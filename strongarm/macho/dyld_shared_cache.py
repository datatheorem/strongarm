from ctypes import c_uint32, sizeof
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type, TypeVar

from _ctypes import Structure

from strongarm.logger import strongarm_logger
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import (
    DyldSharedCacheHeader,
    DyldSharedCacheImageInfo,
    DyldSharedFileMapping,
    MachArch,
    StaticFilePointer,
    VirtualMemoryPointer,
    VMProtFlags,
)

logger = strongarm_logger.getChild(__file__)

_StructureT = TypeVar("_StructureT", bound=Structure)


class DyldSharedCacheParser:
    """Top-level mechanism for parsing a dyld_shared_cache

    Useful links:
        https://opensource.apple.com/source/dyld/dyld-195.6/launch-cache/dsc_iterator.cpp.auto.html
        https://opensource.apple.com/source/dyld/dyld-655.1.1/launch-cache/dyld_cache_format.h.auto.html
    """

    # TODO(PT): Eventually, we could have a generic file-loader which shares some logic of MachoParser/DSCParser

    _DSC_MAGIC = [MachArch.DYLD_SHARED_CACHE_MAGIC]

    def __init__(self, path: Path) -> None:
        self.path = path

        # DSC's are split into 3 "mappings", or segments:
        # Mapping 0 is the executable segment. __TEXT of embedded binaries is placed here
        # Mapping 1 is the writable segment. __DATA/writable data of embedded binaries is placed here
        # Mapping 2 is the readonly segment. __LINKEDIT data (such as symbol tables) is placed here
        # This attribute stores the parsed mapping structures
        self.segment_mappings: List[DyldSharedFileMapping] = []

        # DSC's store a number of system dylibs.
        # This attribute stores the path of an embedded dylib to the virtual mapping of its __TEXT segment
        # In other words, the value for each path is a tuple of:
        # - The VM pointer to the image's Mach-O header
        # - The VM pointer to the end-address of the Mach-O's __TEXT segment
        self.embedded_binary_info: Dict[Path, Tuple[VirtualMemoryPointer, VirtualMemoryPointer]] = {}

        self._parse()

    @property
    def file_magic(self) -> int:
        """Read file magic."""
        return c_uint32.from_buffer(bytearray(self.get_bytes(StaticFilePointer(0), sizeof(c_uint32)))).value

    def get_bytes(self, offset: StaticFilePointer, size: int) -> bytes:
        """Read a region of bytes from the input file
        Args:
            offset: Offset within file to begin reading from
            size: Maximum number of bytes to read
        Returns:
            Byte list representing contents of file at provided address
        """
        with open(str(self.path), "rb") as binary_file:
            binary_file.seek(offset)
            return binary_file.read(size)

    def read_struct(self, file_offset: StaticFilePointer, struct_type: Type[_StructureT]) -> _StructureT:
        """Given a file offset, return the structure it describes
        Args:
            file_offset: Address from where to read the bytes
            struct_type: Structure subclass
        Returns:
            struct_type loaded from the pointed address
        """
        data = bytearray(self.get_bytes(file_offset, sizeof(struct_type)))
        return struct_type.from_buffer(data)  # type: ignore

    def _read_static_c_string(self, start_address: StaticFilePointer) -> Optional[str]:
        """Return a string containing the bytes from start_address up to the next NULL character
        This method will return None if the specified address does not point to a UTF-8 encoded string
        """
        max_len = 16
        symbol_name_characters = []
        found_null_terminator = False

        while not found_null_terminator:
            name_bytes = self.get_bytes(start_address, max_len)
            # search for null terminator in this content
            for ch in name_bytes:
                if ch == 0x00:
                    found_null_terminator = True
                    break
                symbol_name_characters.append(ch)

            # do we need to keep searching for the end of the symbol name?
            if not found_null_terminator:
                # since we read [start_address:start_address + max_len], trim that from search space
                start_address += max_len
                # double search space for next iteration
                max_len *= 2
            else:
                # read full string!
                try:
                    symbol_name = bytearray(symbol_name_characters).decode("UTF-8")
                    return symbol_name
                except UnicodeDecodeError:
                    # if decoding the string failed, we may have been passed an address which does not actually
                    # point to a string
                    return None
        return None

    def _parse(self) -> None:
        # Read the shared-cache header
        self.header = self.read_struct(StaticFilePointer(0), DyldSharedCacheHeader)

        logger.debug(f"Cache magic: {self.header.magic.decode()}")
        logger.debug(f"First mapping: {hex(self.header.mappingOffset)}")
        logger.debug(f"Mapping count: {self.header.mappingCount}")
        logger.debug(f"First image: {hex(self.header.imagesOffset)}")
        logger.debug(f"Image count: {self.header.imagesCount}")
        logger.debug(f"Memory base: {hex(self.header.dyldBaseAddress)}")
        logger.debug(f"Codesign base: {hex(self.header.codeSignOffset)}")

        self._parse_dsc_mappings()
        self._parse_embedded_binaries()

    def _parse_dsc_mappings(self) -> None:
        """Populates self.segment_translations based on the mappings reported by the DSC header."""
        # We expect exactly: an executable mapping, a writable mapping, a readonly mapping
        # Verify this expectation
        assert self.header.mappingCount == 3
        expected_vm_protections = [
            VMProtFlags.VM_PROT_READ | VMProtFlags.VM_PROT_EXECUTE,
            VMProtFlags.VM_PROT_READ | VMProtFlags.VM_PROT_WRITE,
            VMProtFlags.VM_PROT_READ,
        ]

        # Parse the DSC mappings
        mapping_off = self.header.mappingOffset
        for mapping_idx in range(self.header.mappingCount):
            mapping_struct = self.read_struct(StaticFilePointer(mapping_off), DyldSharedFileMapping)
            mapping_off += sizeof(DyldSharedCacheImageInfo)

            virt_addr = VirtualMemoryPointer(mapping_struct.address)
            virt_end = virt_addr + mapping_struct.size

            static_addr = StaticFilePointer(mapping_struct.file_offset)
            prot = mapping_struct.max_prot

            logger.debug(f"Mapping [{mapping_idx}]: [{virt_addr} - {virt_end}] @ {static_addr}, prot = {prot}")

            # Verify the permissions of this mapping are as we expect
            assert prot == expected_vm_protections[mapping_idx], f"{hex(prot)} {expected_vm_protections[mapping_idx]}"

            self.segment_mappings.append(mapping_struct)

    def _parse_embedded_binaries(self) -> None:
        """Populates self.embedded_binary_info based on the images reported by the DSC header."""
        # Parse the embedded binaries within the DSC
        image_off = self.header.imagesOffset
        for image_idx in range(self.header.imagesCount):
            image_struct = self.read_struct(StaticFilePointer(image_off), DyldSharedCacheImageInfo)
            image_off += sizeof(DyldSharedCacheImageInfo)

            # Example: /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
            embedded_binary_path_str = self._read_static_c_string(image_struct.pathFileOffset)
            if not embedded_binary_path_str:
                file_offset = image_off - sizeof(DyldSharedCacheImageInfo)
                raise ValueError(f"Failed to read an image name for image struct @ {hex(file_offset)}")
            embedded_binary_path = Path(embedded_binary_path_str)

            vm_addr = VirtualMemoryPointer(image_struct.address)
            # To calculate the size of this image, we need to look at the next image's address
            # Except for the last image, which doesn't have an image after it
            if image_idx == self.header.imagesCount - 1:
                mapping_end = VirtualMemoryPointer(self.segment_mappings[0].address + self.segment_mappings[0].size)
                image_size = mapping_end - vm_addr
            else:
                next_image = self.read_struct(StaticFilePointer(image_off), DyldSharedFileMapping)
                image_size = next_image.address - image_struct.address

            vm_end = vm_addr + image_size
            self.embedded_binary_info[Path(embedded_binary_path)] = (vm_addr, vm_end)

    def translate_virtual_address_to_static(self, vm_addr: VirtualMemoryPointer) -> StaticFilePointer:
        """Given a pointer within the DSC's virtual address mappings, return the file pointer to the same data."""
        # Find the mapping which contains the provided address
        for mapping in self.segment_mappings:
            if mapping.address <= vm_addr < mapping.address + mapping.size:
                offset_into_segment = vm_addr - mapping.address
                return StaticFilePointer(mapping.file_offset + offset_into_segment)
        raise ValueError(f"Could not find address within DSC address space: {vm_addr}")

    def get_embedded_binary(self, binary_path: Path) -> "DyldSharedCacheBinary":
        """Given a path to a binary embedded in the DSC, retrieve & parse the embedded binary."""
        if binary_path not in self.embedded_binary_info:
            raise ValueError(f"DSC does not contain {binary_path}")

        text_vm_start, text_vm_end = self.embedded_binary_info[binary_path]
        text_size = text_vm_end - text_vm_start
        logger.debug(f"Parsing DSC image {binary_path} @ [{text_vm_start}, {text_vm_end}]")

        static_addr = self.translate_virtual_address_to_static(text_vm_start)
        image_bytes = self.get_bytes(static_addr, text_size)

        return DyldSharedCacheBinary(self, binary_path, static_addr, image_bytes)

    def image_for_text_address(self, address: VirtualMemoryPointer) -> Path:
        """Given a virtual memory address of __TEXT content, return the embedded image which contains it."""
        for path, text_region in self.embedded_binary_info.items():
            text_vm_start, text_vm_end = text_region
            if text_vm_start <= address < text_vm_end:
                return path
        raise ValueError(f"No embedded __TEXT segment contains {address}")


class DyldSharedCacheBinary(MachoBinary):
    """A special Mach-O binary which exists within a dyld_shared_cache.
    DSC binaries are different from Mach-O binaries in that its segments are dispersed across the DSC file.
    Its __TEXT is in DSC.segment_mappings[0]. This means that all the header-structures parsed by the MachoBinary
    intializer are within the __TEXT buffer.
    However, these structures may point to things in DSC.segment_mappings[1] or DSC.segment_mappings[2].
    For example, a symtab command of a DSC binary will contain pointers to __LINKEDIT data within the DSC's __LINKEDIT.
    Thus, these binaries are supported like so:
    - The DSC binary retains a reference to the global DSC
    - When the DSC binary is initialized, MachoBinary only reads the __TEXT segment bytes
    - When get_bytes() is called, it checks whether the address is within __TEXT.
        If not, it will read the data from the global DSC, with an optional flag to disable the translation.
        The translation must be disabled for a few reads, such as symbol-table parsing, as the DSC has pre-
        translated these values.
    """

    def __init__(
        self, dsc_parser: "DyldSharedCacheParser", path: Path, file_offset: StaticFilePointer, binary_data: bytes
    ) -> None:
        self.dyld_shared_cache_parser = dsc_parser
        self.dyld_shared_cache_file_offset = file_offset
        super().__init__(path, binary_data)

    def file_offset_for_virtual_address(self, virtual_address: VirtualMemoryPointer) -> StaticFilePointer:
        # Translate into the global DSC file
        return self.dyld_shared_cache_parser.translate_virtual_address_to_static(virtual_address)

    def get_bytes(self, offset: StaticFilePointer, size: int, _translate_addr_to_file: bool = True) -> bytearray:
        # There are two possibilities: The requested data is "binary-local", meaning it's within the __TEXT buffer
        # backing this object. Or, the requested data is somewhere within the global DSC.
        # It would be clear which is the case from the calling context. For example, if the pointer comes from
        # a symbol table, it's probably in the DSC-global __LINKEDIT mapping. In contrast, if the pointer represents
        # the bytecode for some function, it's probably in the __TEXT mapping. We don't want to provide this context
        # from every get_bytes caller, so try to determine what data is being requested here.
        # If offset+size refers to an address outside the local image, translate and read from the global DSC.
        # Otherwise, don't translate and read directly from the global DSC.
        if offset + size > self.dyld_shared_cache_file_offset + len(self._cached_binary):
            logger.debug(f"Reading from addr outside __TEXT: {offset}")
            # This address is outside the binary's buffer. If translation was disabled, an assumption has been violated
            assert _translate_addr_to_file, f"Must translate addr outside __TEXT: {offset}"

        else:
            if _translate_addr_to_file:
                offset += self.dyld_shared_cache_file_offset
            else:
                logger.debug(f"Translation explicitly disabled, direct read of {offset}")

        return bytearray(self.dyld_shared_cache_parser.get_bytes(offset, size))
