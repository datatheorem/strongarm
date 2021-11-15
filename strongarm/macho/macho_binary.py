import math
from ctypes import c_uint32, c_uint64, sizeof
from distutils.version import LooseVersion
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple, Type, TypeVar

from _ctypes import Structure

from strongarm.logger import strongarm_logger
from strongarm.macho.arch_independent_structs import (
    ArchIndependentStructure,
    CFStringStruct,
    DylibCommandStruct,
    MachoBuildToolVersionStruct,
    MachoBuildVersionCommandStruct,
    MachoDyldInfoCommandStruct,
    MachoDysymtabCommandStruct,
    MachoEncryptionInfoStruct,
    MachoHeaderStruct,
    MachoLinkeditDataCommandStruct,
    MachoLoadCommandStruct,
    MachoNlistStruct,
    MachoSectionRawStruct,
    MachoSegmentCommandStruct,
    MachoSymtabCommandStruct,
)
from strongarm.macho.macho_definitions import (
    CPU_TYPE,
    HEADER_FLAGS,
    DylibCommand,
    DylibStruct,
    LcStrUnion,
    MachArch,
    MachoBuildVersionPlatform,
    MachoFileType,
    StaticFilePointer,
    VirtualMemoryPointer,
)
from strongarm.macho.macho_load_commands import MachoLoadCommands

if TYPE_CHECKING:
    from strongarm.macho.codesign import CodesignParser

logger = strongarm_logger.getChild(__file__)

AIS = TypeVar("AIS", bound=ArchIndependentStructure)


class BinaryEncryptedError(Exception):
    """Raised when the binary is encrypted."""


class LoadCommandMissingError(Exception):
    """Raised when the binary is missing a load command."""


class NoEmptySpaceForLoadCommandError(Exception):
    """Raised when we fail to insert a load command because there's not enough empty space left in the Mach-O header."""


class InvalidAddressError(Exception):
    """Raised when a client asks for bytes at an address outside the binary."""


class MachoSegment:
    def __init__(self, segment_command: MachoSegmentCommandStruct) -> None:
        self.cmd = segment_command

        self.name = segment_command.segname.decode()
        self.sizeof = segment_command.sizeof

        self.vmaddr = segment_command.vmaddr
        self.vmsize = segment_command.vmsize
        self.vm_end_address = self.vmaddr + self.vmsize

        self.offset = segment_command.fileoff
        self.size = segment_command.filesize
        self.end_address = self.offset + self.size

        self.section_count = segment_command.nsects
        self.sections: List["MachoSection"] = []

        self.maxprot = segment_command.maxprot
        self.initprot = segment_command.initprot
        self.flags = segment_command.flags

    def __repr__(self) -> str:
        virtual_loc = f"[0x{self.vmaddr:011x} - 0x{self.vm_end_address:011x}]"
        file_loc = f"[0x{self.offset:011x} - 0x{self.end_address:011x}]"
        return f"<MachoSegment {virtual_loc} (file {file_loc}) {self.name} ({self.section_count} sections)>"


class MachoSection:
    def __init__(self, section_command: MachoSectionRawStruct, segment: MachoSegment) -> None:
        self.cmd = section_command
        self.segment = segment

        # ignore these types due to dynamic attributes of associated types
        self.name = section_command.sectname.decode()
        self.segment_name = section_command.segname.decode()
        self.address = section_command.addr
        self.size = section_command.size
        self.end_address = self.address + self.size
        self.offset = section_command.offset

        self.align = section_command.align
        self.reloff = section_command.reloff
        self.nreloc = section_command.nreloc
        self.flags = section_command.flags

    def __repr__(self) -> str:
        virtual_loc = f"[0x{self.address:011x} - 0x{self.end_address:011x}]"
        return f'<MachoSection {virtual_loc} "{self.name}" ("{self.segment_name}")>'


class MachoBinary:
    _MAG_64 = [MachArch.MH_MAGIC_64, MachArch.MH_CIGAM_64]
    _MAG_32 = [MachArch.MH_MAGIC, MachArch.MH_CIGAM]
    _MAG_BIG_ENDIAN = [MachArch.MH_CIGAM, MachArch.MH_CIGAM_64]
    SUPPORTED_MAG = _MAG_64 + _MAG_32
    BYTES_PER_INSTRUCTION = 4

    def __init__(self, path: Path, binary_data: bytes, file_offset: Optional[StaticFilePointer] = None) -> None:
        """Parse the bytes representing a Mach-O file."""
        from .codesign.codesign_parser import CodesignParser

        self._cached_binary = binary_data

        self.path = path
        self.is_64bit: bool = False
        self.is_swap: bool = False
        self.slice_filesize = len(binary_data)
        self._load_commands_end_addr = 0
        self.file_offset = file_offset or StaticFilePointer(0x0)

        # Mach-O header data
        self.cpu_type: CPU_TYPE = CPU_TYPE.UNKNOWN  # Overwritten later in the parse
        self._header: Optional[MachoHeaderStruct] = None
        self.header_flags: List[int] = []
        self.file_type: MachoFileType = MachoFileType.MH_EXECUTE  # Overwritten later in the parse
        self._virtual_base: Optional[VirtualMemoryPointer] = None

        # Segment and section commands from Mach-O header
        self.segments: List[MachoSegment] = []
        self.sections: List[MachoSection] = []
        # Interesting Mach-O sections
        self._dysymtab: Optional[MachoDysymtabCommandStruct] = None
        self._symtab: Optional[MachoSymtabCommandStruct] = None
        self._encryption_info: Optional[MachoEncryptionInfoStruct] = None
        self._dyld_info: Optional[MachoDyldInfoCommandStruct] = None
        self._dyld_export_trie: Optional[MachoLinkeditDataCommandStruct] = None
        self._dyld_chained_fixups: Optional[MachoLinkeditDataCommandStruct] = None
        self.load_dylib_commands: List[DylibCommandStruct] = []
        self._code_signature_cmd: Optional[MachoLinkeditDataCommandStruct] = None
        self._function_starts_cmd: Optional[MachoLinkeditDataCommandStruct] = None
        self._functions_list: Optional[Set[VirtualMemoryPointer]] = None
        self._id_dylib_cmd: Optional[DylibCommandStruct] = None
        self._build_version_cmd: Optional[MachoBuildVersionCommandStruct] = None
        self._build_tool_versions: Optional[List[MachoBuildToolVersionStruct]] = None

        self.__codesign_parser: Optional[CodesignParser] = None
        self.__minimum_deployment_target: Optional[LooseVersion] = None

        # This kicks off the parse of the binary
        if not self.parse():
            raise RuntimeError("Failed to parse Mach-O")

        self.platform_word_type = c_uint64 if self.is_64bit else c_uint32

        self._symtab_contents: Optional[List[MachoNlistStruct]] = None
        logger.debug(self, f"parsed symtab, len = {len(self.symtab_contents)}")

        from .dyld_info_parser import DyldBoundSymbol, DyldInfoParser

        self.dyld_bound_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}
        self.dyld_rebased_pointers: Dict[VirtualMemoryPointer, VirtualMemoryPointer] = {}

        if self._dyld_chained_fixups:
            rebases, binds = DyldInfoParser.parse_chained_fixups(self)  # type: ignore
            self.dyld_rebased_pointers, self.dyld_bound_symbols = rebases, binds
        else:
            self.dyld_bound_symbols = DyldInfoParser.parse_dyld_info(self)

    def __repr__(self) -> str:
        return f"<MachoBinary binary={self.path}>"

    def parse(self) -> bool:
        """Attempt to parse the provided file info as a Mach-O slice

        Returns:
            True if the file data represents a valid & supported Mach-O which was successfully parsed.
            False otherwise.

        """
        # logger.debug(self, f"parsing Mach-O slice @ {hex(int(self._offset_within_fat))} in {self.path}")

        # Preliminary Mach-O parsing
        if not self.verify_magic():
            logger.debug(self, f"unsupported magic {hex(self.slice_magic)}")
            return False

        self.is_swap = self.should_swap_bytes()
        # Big endian binaries are currently unsupported
        if self.is_swap:
            raise NotImplementedError("Big-endian binaries are unsupported")

        self.is_64bit = self.magic_is_64()

        self.parse_header()

        logger.debug(self, f"header parsed. non-native endianness? {self.is_swap}. 64-bit? {self.is_64bit}")
        return True

    @property
    def slice_magic(self) -> int:
        """Read magic number identifier from this Mach-O slice."""
        return self.read_word(0, virtual=False, word_type=c_uint32)

    def verify_magic(self) -> bool:
        """Ensure magic at beginning of Mach-O slice indicates a supported format

        Returns:
            True if the magic represents a supported file format, False if the magic represents an unsupported format

        """
        return self.slice_magic in MachoBinary.SUPPORTED_MAG

    def magic_is_64(self) -> bool:
        """Convenience method to check if our magic corresponds to a 64-bit slice

        Returns:
            True if self.slice_magic corresponds to a 64 bit MachO slice, False otherwise

        """
        return self.slice_magic in MachoBinary._MAG_64

    def parse_header(self) -> None:
        """Read all relevant info from a Mach-O header which does not require cross-referencing.
        Specifically, this method parses the Mach-O header & header flags, CPU target,
        and all segment and section commands.
        """
        self._header = self.read_struct(0, MachoHeaderStruct)

        if self.header.cputype == MachArch.MH_CPU_TYPE_ARM:  # type: ignore
            self.cpu_type = CPU_TYPE.ARMV7
        elif self.header.cputype == MachArch.MH_CPU_TYPE_ARM64:  # type: ignore
            self.cpu_type = CPU_TYPE.ARM64
        else:
            self.cpu_type = CPU_TYPE.UNKNOWN

        self._parse_header_flags()
        self.file_type = MachoFileType(self.header.filetype)

        # load commands begin directly after Mach O header, so the offset is the size of the header
        load_commands_off = self.header.sizeof

        self._load_commands_end_addr = load_commands_off + self.header.sizeofcmds  # type: ignore
        self._parse_load_commands(load_commands_off, self.header.ncmds)  # type: ignore

    def _parse_header_flags(self) -> None:
        """Interpret binary's header bitset and populate self.header_flags."""
        self.header_flags = []

        flags_bitset = self.header.flags
        for mask in [x.value for x in HEADER_FLAGS]:
            # is this mask set in the binary's flags?
            if (flags_bitset & mask) == mask:
                # mask is present in bitset, add to list of included flags
                self.header_flags.append(mask)

    def _parse_load_commands(self, offset: StaticFilePointer, ncmds: int) -> None:
        """Parse Mach-O segment commands beginning at a given slice offset

        Args:
            offset: Slice offset to first segment command
            ncmds: Number of load commands to parse, as declared by the header's ncmds field
        """
        self.load_dylib_commands = []

        for i in range(ncmds):
            load_command = self.read_struct(offset, MachoLoadCommandStruct)

            if load_command.cmd in [MachoLoadCommands.LC_SEGMENT, MachoLoadCommands.LC_SEGMENT_64]:
                segment_command = self.read_struct(offset, MachoSegmentCommandStruct)
                # TODO(PT) handle byte swap of segment if necessary
                segment = MachoSegment(segment_command)
                self.segments.append(segment)
                self._parse_sections_for_segment(segment, offset)

            # some commands have their own structure that we interpret separately from a normal load command
            # if we want to interpret more commands in the future, this is the place to do it
            elif load_command.cmd in [MachoLoadCommands.LC_ENCRYPTION_INFO, MachoLoadCommands.LC_ENCRYPTION_INFO_64]:
                self._encryption_info = self.read_struct(offset, MachoEncryptionInfoStruct)

            elif load_command.cmd == MachoLoadCommands.LC_SYMTAB:
                self._symtab = self.read_struct(offset, MachoSymtabCommandStruct)

            elif load_command.cmd == MachoLoadCommands.LC_DYSYMTAB:
                self._dysymtab = self.read_struct(offset, MachoDysymtabCommandStruct)

            elif load_command.cmd in [MachoLoadCommands.LC_DYLD_INFO, MachoLoadCommands.LC_DYLD_INFO_ONLY]:
                self._dyld_info = self.read_struct(offset, MachoDyldInfoCommandStruct)

            elif load_command.cmd in [MachoLoadCommands.LC_DYLD_EXPORTS_TRIE]:
                self._dyld_export_trie = self.read_struct(offset, MachoLinkeditDataCommandStruct)

            elif load_command.cmd in [MachoLoadCommands.LC_DYLD_CHAINED_FIXUPS]:
                self._dyld_chained_fixups = self.read_struct(offset, MachoLinkeditDataCommandStruct)

            elif load_command.cmd in [MachoLoadCommands.LC_LOAD_DYLIB, MachoLoadCommands.LC_LOAD_WEAK_DYLIB]:
                dylib_load_command = self.read_struct(offset, DylibCommandStruct)
                self.load_dylib_commands.append(dylib_load_command)

            elif load_command.cmd == MachoLoadCommands.LC_CODE_SIGNATURE:
                self._code_signature_cmd = self.read_struct(offset, MachoLinkeditDataCommandStruct)

            elif load_command.cmd == MachoLoadCommands.LC_FUNCTION_STARTS:
                self._function_starts_cmd = self.read_struct(offset, MachoLinkeditDataCommandStruct)

            elif load_command.cmd == MachoLoadCommands.LC_ID_DYLIB:
                self._id_dylib_cmd = self.read_struct(offset, DylibCommandStruct)
                # This load command should only be present for dylibs. Validate this assumption
                assert self.file_type == MachoFileType.MH_DYLIB

            elif load_command.cmd == MachoLoadCommands.LC_BUILD_VERSION:
                self._build_version_cmd = self.read_struct(offset, MachoBuildVersionCommandStruct)
                # Parse the build tool versions following this structure
                build_tool_offset = offset + self._build_version_cmd.sizeof
                self._build_tool_versions = []
                for _ in range(self._build_version_cmd.ntools):
                    build_tool_version = self.read_struct(build_tool_offset, MachoBuildToolVersionStruct)
                    self._build_tool_versions.append(build_tool_version)

            # move to next load command in header
            offset += load_command.cmdsize

    def read_struct(self, binary_offset: int, struct_type: Type[AIS], virtual: bool = False) -> AIS:
        """Given an binary offset, return the structure it describes.

        Params:
            binary_offset: Address from where to read the bytes.
            struct_type: ArchIndependentStructure subclass.
            virtual: Whether the address should be slid (virtual) or not.
        Returns:
            ArchIndependentStructure loaded from the pointed address.
        """
        backing_layout = struct_type.get_backing_data_layout(self.is_64bit, self.get_minimum_deployment_target())
        data = self.get_contents_from_address(address=binary_offset, size=sizeof(backing_layout), is_virtual=virtual)
        return struct_type(binary_offset, data, backing_layout)

    def read_struct_with_rebased_pointers(
        self, binary_offset: int, struct_type: Type[AIS], virtual: bool = False
    ) -> AIS:
        """Read a static binary structure that may contain rebased pointers.
        For each uint64_t within the structure, check if we know that this pointer should be rebased.
        If so, the static data here may be a packed chained fixup pointer, rather than a pointer we can follow.
        In this case, update the pointer to contain the value to be rebased, so that the pointer can be followed.
        """
        backing_layout = struct_type.get_backing_data_layout(self.is_64bit, self.get_minimum_deployment_target())
        data = self.get_contents_from_address(address=binary_offset, size=sizeof(backing_layout), is_virtual=virtual)
        s = struct_type(binary_offset, data, backing_layout)

        # Check each c_uint64/c_ulong to see if we know about a rebase for it. If so, apply it
        base_virt_offset = binary_offset
        if not virtual:
            base_virt_offset += self.get_virtual_base()
        for field_name, field_type, *_ in backing_layout._fields_:
            field_offset = getattr(getattr(backing_layout, field_name), "offset")
            field_address = base_virt_offset + field_offset
            if field_type == c_uint64 and field_address in self.dyld_rebased_pointers:
                logger.debug(
                    f"Setting rebased pointer within {struct_type}+{field_offset} -> "
                    f"{self.dyld_rebased_pointers[field_address]} at {field_address}"
                )
                setattr(s, field_name, self.dyld_rebased_pointers[field_address])

        return s

    def section_name_for_address(self, virt_addr: VirtualMemoryPointer) -> Optional[str]:
        """Given an address in the virtual address space, return the name of the section which contains it."""
        section = self.section_for_address(virt_addr)
        if not section:
            return None
        return section.name

    def section_for_address(self, virt_addr: VirtualMemoryPointer) -> Optional[MachoSection]:
        """Given an address in the virtual address space, return the section which contains it."""
        # invalid address?
        if virt_addr < self.get_virtual_base():
            return None

        # if the address given is past the last declared section, translate based on the last section
        # so, we need to keep track of the last seen section
        max_section = next(iter(self.sections))

        for idx, section in enumerate(self.sections):
            # update highest section
            if section.address > max_section.address:
                max_section = section

            if section.address <= virt_addr < section.end_address:
                return section
        # we looked through all sections and didn't find one explicitly containing this address
        # guess by using the highest-addressed section we've seen
        return max_section

    def segment_for_index(self, segment_index: int) -> MachoSegment:
        if 0 <= segment_index < len(self.segments):
            # PT: Segments are guaranteed to be sorted in the order they appear in the Mach-O header
            return self.segments[segment_index]
        else:
            raise ValueError(f"segment_index ({segment_index}) out of bounds ({len(self.segments)}")

    def segment_with_name(self, desired_segment_name: str) -> Optional[MachoSegment]:
        """Returns the segment with the provided name. Returns None if there's no such segment in the binary."""
        # TODO(PT): add unit test for this method
        return next((s for s in self.segments if s.name == desired_segment_name), None)

    def section_with_name(self, desired_section_name: str, parent_segment_name: str) -> Optional[MachoSection]:
        """Retrieve the section with the provided name which is contained within the provided segment.
        Returns None if no such section exists.
        """
        segment = self.segment_with_name(parent_segment_name)
        if segment:
            return next((s for s in segment.sections if s.name == desired_section_name), None)
        return None

    def _parse_sections_for_segment(self, segment: MachoSegment, segment_offset: StaticFilePointer) -> None:
        """Parse all sections contained within a Mach-O segment, and add them to our list of sections

        Args:
            segment: The segment command whose sections should be read
            segment_offset: The offset within the file that the segment command is located at
        """
        if not segment.section_count:
            return

        # The first section of this segment begins directly after the segment
        section_offset = segment_offset + segment.sizeof
        for i in range(segment.section_count):
            # Read section header from file
            # TODO(PT): handle byte swap of segment
            section_command = self.read_struct(section_offset, MachoSectionRawStruct)
            # Encapsulate header and content into one object, and store that
            section = MachoSection(section_command, segment)
            segment.sections.append(section)
            # Add to list of sections within the Mach-O
            self.sections.append(section)

            # Iterate to next section in list
            section_offset += section_command.sizeof

    def get_virtual_base(self) -> VirtualMemoryPointer:
        """Retrieve the first virtual address of the Mach-O slice

        Returns:
            int containing the virtual memory space address that the Mach-O slice requests to begin at

        """
        if not self._virtual_base:
            text_seg = self.segment_with_name("__TEXT")
            if not text_seg:
                raise RuntimeError("Could not find virtual base because binary has no __TEXT segment.")
            self._virtual_base = VirtualMemoryPointer(text_seg.vmaddr)

        return self._virtual_base

    def get_file_offset(self) -> StaticFilePointer:
        """Retrieve the offset within the file of this Mach-O slice."""
        return self.file_offset

    def get_bytes(self, offset: StaticFilePointer, size: int, _translate_addr_to_file: bool = False) -> bytearray:
        """Retrieve bytes from Mach-O slice, taking into account that the slice could be at an offset within a FAT

        Args:
            offset: index from beginning of slice to retrieve data from
            size: maximum number of bytes to read
            _translate_addr_to_file: Internal option to support parsing DYLD shared cache binaries.
                Images within the shared cache store some of their data in a separate part of the cache from their code.
                This option tells DYLD cache binaries to translate the offset into the global cache file.

        Returns:
            string containing byte content of mach-o slice at an offset from the start of the slice

        """
        if offset > 0x100000000:
            raise InvalidAddressError(
                f"get_bytes() offset {hex(offset)} looks like a virtual address."
                " Did you mean to use get_content_from_virtual_address?"
            )
        if offset < 0:
            raise InvalidAddressError(f"get_bytes() passed negative offset: {hex(offset)}")
        if _translate_addr_to_file:
            raise ValueError("_translate_addr_to_file may only be used with dyld_shared_cache binaries")

        # safeguard against reading from an encrypted segment of the binary
        if self.is_range_encrypted(offset, size):
            encryption_range_start = int(self.encryption_info.cryptoff)
            encryption_range_end = encryption_range_start + int(self.encryption_info.cryptsize)
            raise BinaryEncryptedError(
                f"Cannot read encrypted range [{hex(encryption_range_start)} - {hex(encryption_range_end)}]"
            )

        return bytearray(self._cached_binary[offset : offset + size])

    def should_swap_bytes(self) -> bool:
        """Check whether self.slice_magic refers to a big-endian Mach-O binary

        Returns:
            True if self.slice_magic indicates a big endian Mach-O, False otherwise

        """
        return self.slice_magic in MachoBinary._MAG_BIG_ENDIAN

    def get_raw_string_table(self) -> List[int]:
        """Read string table from binary, as described by LC_SYMTAB. Each strtab entry is terminated
        by a NULL character.

        Returns:
            Raw, packed array of characters containing binary's string table data

        """
        string_table_data = self.get_bytes(self.symtab.stroff, self.symtab.strsize)
        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(string_table_data)
        return string_table

    @property
    def symtab_contents(self) -> List[MachoNlistStruct]:
        if self._symtab_contents is None:
            self._symtab_contents = self._parse_symtab_contents()
            logger.debug(self, f"parsed symtab, len = {len(self.symtab_contents)}")
        return self._symtab_contents

    def _parse_symtab_contents(self) -> List[MachoNlistStruct]:
        """Parse symbol table containing list of Nlist64's

        Returns:
            Array of Nlist64's representing binary's symbol table
        """
        logger.debug(self, f"parsing {self.symtab.nsyms} symtab entries")

        symtab = []
        # start reading from symoff and increment by one Nlist64 each iteration
        symoff = self.symtab.symoff
        for i in range(self.symtab.nsyms):
            nlist = self.read_struct(symoff, MachoNlistStruct)
            symtab.append(nlist)
            # go to next Nlist in file
            symoff += nlist.sizeof

        return symtab

    def get_indirect_symbol_table(self) -> List[int]:
        indirect_symtab = []
        # dysymtab has fields that tell us the file offset of the indirect symbol table, as well as the number
        # of indirect symbols present in the mach-o
        indirect_symtab_off = self.dysymtab.indirectsymoff

        # indirect symtab is an array of uint32's
        for i in range(self.dysymtab.nindirectsyms):
            indirect_symtab_entry = self.read_word(indirect_symtab_off, virtual=False, word_type=c_uint32)
            indirect_symtab.append(int(indirect_symtab_entry))
            # traverse to next pointer
            indirect_symtab_off += sizeof(c_uint32)
        return indirect_symtab

    def file_offset_for_virtual_address(self, virtual_address: VirtualMemoryPointer) -> StaticFilePointer:
        # if this address is within the initial Mach-O load commands, it must be handled seperately
        # this unslid virtual address is just a 'best guess' of the physical file address, and it'll be the correct
        # address if the virtual address was within the initial load commands
        # if the virtual address was in the section contents, however, we must use another method to translate addresses
        unslid_virtual_address = virtual_address - self.get_virtual_base()
        if unslid_virtual_address < self._load_commands_end_addr:
            return StaticFilePointer(unslid_virtual_address)

        section_for_address = self.section_for_address(virtual_address)
        if not section_for_address:
            raise RuntimeError(f"Could not map virtual address {hex(int(virtual_address))} to a section!")

        # the virtual address is contained within a section's contents
        # use this formula to convert a virtual address within a section to the file offset:
        # https://reverseengineering.stackexchange.com/questions/8177/convert-mach-o-vm-address-to-file-offset
        binary_address = (virtual_address - section_for_address.address) + section_for_address.offset
        return StaticFilePointer(binary_address)

    def get_content_from_virtual_address(self, virtual_address: VirtualMemoryPointer, size: int) -> bytearray:
        binary_address = self.file_offset_for_virtual_address(virtual_address)
        return self.get_bytes(binary_address, size)

    def get_contents_from_address(self, address: int, size: int, is_virtual: bool = False) -> bytearray:
        """Get a bytesarray from a specified address, size and virtualness
        TODO(FS): change all methods that use addresses as ints to the VirtualAddress/StaticAddress class pair to better
         express intent
        """
        if is_virtual:
            return self.get_content_from_virtual_address(VirtualMemoryPointer(address), size)
        else:
            return self.get_bytes(StaticFilePointer(address), size)

    def get_full_string_from_start_address(self, start_address: int, virtual: bool = True) -> Optional[str]:
        """Return a string containing the bytes from start_address up to the next NULL character
        This method will return None if the specified address does not point to a UTF-8 encoded string
        """
        max_len = 16
        symbol_name_characters = []
        found_null_terminator = False

        while not found_null_terminator:
            if virtual:
                name_bytes = self.get_content_from_virtual_address(VirtualMemoryPointer(start_address), max_len)
            else:
                name_bytes = self.get_bytes(StaticFilePointer(start_address), max_len)
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
                    symbol_name = bytearray(symbol_name_characters).decode()
                    return symbol_name
                except UnicodeDecodeError:
                    # if decoding the string failed, we may have been passed an address which does not actually
                    # point to a string
                    return None
        return None

    def read_string_at_address(self, address: VirtualMemoryPointer) -> Optional[str]:
        """Read a string embedded in the binary at address
        This method will automatically parse a CFString and return the string literal if address points to one
        """
        section_name = self.section_name_for_address(address)
        # no section found?
        if not section_name:
            return None
        # some sections will never contain a string literal and can cause errors if we try to read a string from them
        if section_name in ["__bss", "__objc_selrefs", "__objc_classrefs"]:
            return None
        # special case if this is a __cfstring entry
        if section_name == "__cfstring":
            # read bytes into CFString struct
            cfstring_ent = self.read_struct(address, CFStringStruct, virtual=True)
            # patch address to read string from to be the string literal address of this CFString
            address = cfstring_ent.literal
        return self.get_full_string_from_start_address(address)

    def is_encrypted(self) -> bool:
        """Returns True if the binary has an encrypted segment, False otherwise."""
        if not self._encryption_info:
            return False
        return self.encryption_info.cryptid != 0

    def is_range_encrypted(self, offset: StaticFilePointer, size: int) -> bool:
        """Returns whether the provided address range overlaps with the encrypted section of the binary."""
        if not self.is_encrypted():
            return False

        # if 2 ranges overlap, the end address of the first range will be greater than the start of the second, and
        # the end address of the second will be greater than the start of the first
        range1 = (offset, offset + size)
        range2 = (self.encryption_info.cryptoff, self.encryption_info.cryptoff + self.encryption_info.cryptsize)
        return range1[1] >= range2[0] and range2[1] >= range1[0]

    def dylib_for_library_ordinal(self, library_ordinal: int) -> Optional[DylibCommandStruct]:
        """Retrieve the library information for the 'library ordinal' value, or None if no entry exists there.
        Library ordinals are 1-indexed.

        https://opensource.apple.com/source/cctools/cctools-795/include/mach-o/loader.h
        """
        idx = library_ordinal - 1
        # library ordinals are 1-indexed
        # if the input is invalid, return None
        if library_ordinal < 1 or idx >= len(self.load_dylib_commands):
            return None
        return self.load_dylib_commands[idx]

    def dylib_name_for_library_ordinal(self, library_ordinal: int) -> str:
        """Read the name of the dynamic library by its library ordinal."""
        source_dylib = self.dylib_for_library_ordinal(library_ordinal)
        if source_dylib:
            source_name_addr = source_dylib.binary_offset + source_dylib.dylib.name.offset + self.get_virtual_base()
            source_name = self.get_full_string_from_start_address(source_name_addr)
            if not source_name:
                source_name = "<unknown dylib>"
        else:
            # we have encountered binaries where the n_desc indicates a nonexistent library ordinal
            # Netflix.app/frameworks/widevine_cdm_sdk_oemcrypto_release.framework/widevine_cdm_sdk_oemcrypto_release
            # indicates an ordinal 254, when the binary only actually has 8 LC_LOAD_DYLIB commands.
            # if we encounter a buggy binary like this, just use a placeholder name
            source_name = "<unknown dylib>"
        return source_name

    def read_pointer_section(self, section_name: str) -> Dict[VirtualMemoryPointer, VirtualMemoryPointer]:
        """Read all the pointers in a section

        It is the caller's responsibility to only call this with a `section_name` which indicates a section which should
        only contain a pointer list.

        The return value is two lists of pointers.
        The first List contains the virtual addresses of each entry in the section.
        The second List contains the pointer values contained at each of these addresses.

        The indexes of these two lists are matched up; that is, list1[0] is the virtual address of the first pointer
        in the requested section, and list2[0] is the pointer value contained at that address.
        """
        # PT: Assume a pointer-list-section will always be in __DATA or __DATA_CONST. True as far as I know.
        for segment in ["__DATA", "__DATA_CONST"]:
            section = self.section_with_name(section_name, segment)
            if section:
                break
        else:
            # Couldn't find the desired section
            return {}

        address_to_pointer_map: Dict[VirtualMemoryPointer, VirtualMemoryPointer] = {}

        section_base = section.address
        section_data = self.get_bytes(section.offset, section.size)

        binary_word = self.platform_word_type
        pointer_count = int(len(section_data) / sizeof(binary_word))
        pointer_off = 0

        for i in range(pointer_count):
            # convert section offset of entry to absolute virtual address
            ptr_location = VirtualMemoryPointer(section_base + pointer_off)

            if ptr_location in self.dyld_rebased_pointers:
                ptr_value = self.dyld_rebased_pointers[ptr_location]
                logger.debug(f"Pointer is rebased: {ptr_location} -> {ptr_value}")
            else:
                data_end = pointer_off + sizeof(binary_word)
                ptr_value = VirtualMemoryPointer(
                    binary_word.from_buffer(bytearray(section_data[pointer_off:data_end])).value
                )
                logger.debug(f"Pointer was not in the rebase list: {ptr_location} -> {ptr_value}")

            address_to_pointer_map[ptr_location] = VirtualMemoryPointer(ptr_value)

            pointer_off += sizeof(binary_word)

        return address_to_pointer_map

    def read_word(self, address: int, virtual: bool = True, word_type: Any = None) -> int:
        """Attempt to read a word from the binary at a virtual address."""
        if not word_type:
            word_type = self.platform_word_type

        if virtual:
            file_bytes = self.get_content_from_virtual_address(VirtualMemoryPointer(address), sizeof(word_type))
        else:
            file_bytes = self.get_bytes(StaticFilePointer(address), sizeof(word_type))

        if not file_bytes:
            raise InvalidAddressError(f"Could not read word at address {hex(address)}")

        return word_type.from_buffer(bytearray(file_bytes)).value

    def read_rebased_pointer(self, address: VirtualMemoryPointer) -> VirtualMemoryPointer:
        """Attempt to read a rebased pointer from the binary at a virtual address.
        The pointer is assumed to be the platform word size.
        """
        if address not in self.dyld_rebased_pointers:
            # This may be a pre-iOS 15 binary for which we don't record rebases
            return VirtualMemoryPointer(self.read_word(address, virtual=True, word_type=self.platform_word_type))

        return self.dyld_rebased_pointers[address]

    @property
    def header(self) -> MachoHeaderStruct:
        if self._header:
            return self._header
        else:
            raise LoadCommandMissingError()

    @property
    def dysymtab(self) -> MachoDysymtabCommandStruct:
        if self._dysymtab:
            return self._dysymtab
        else:
            raise LoadCommandMissingError()

    @property
    def symtab(self) -> MachoSymtabCommandStruct:
        if self._symtab:
            return self._symtab
        else:
            raise LoadCommandMissingError()

    @property
    def encryption_info(self) -> MachoEncryptionInfoStruct:
        if self._encryption_info:
            return self._encryption_info
        else:
            raise LoadCommandMissingError()

    @property
    def dyld_info(self) -> MachoDyldInfoCommandStruct:
        if self._dyld_info:
            return self._dyld_info
        else:
            raise LoadCommandMissingError()

    @property
    def code_signature_cmd(self) -> Optional[MachoLinkeditDataCommandStruct]:
        return self._code_signature_cmd

    @property
    def _codesign_parser(self) -> "CodesignParser":
        if not self.__codesign_parser:
            from strongarm.macho.codesign import CodesignParser

            self.__codesign_parser = CodesignParser(self)
        return self.__codesign_parser

    def get_entitlements(self) -> Optional[bytearray]:
        """Read the entitlements the binary was signed with."""
        return self._codesign_parser.entitlements

    def get_signing_identity(self) -> Optional[str]:
        """Read the bundle ID the binary was signed as."""
        return self._codesign_parser.signing_identifier

    def get_team_id(self) -> Optional[str]:
        """Read the team ID the binary was signed with."""
        return self._codesign_parser.signing_team_id

    def write_bytes(self, data: bytes, address: int, virtual: bool = False) -> "MachoBinary":
        """Overwrite the data in the current binary with the provided data, returning a new modified binary.
        Note: This will invalidate the binary's code signature, if present.
        """
        # Ensure there is valid data in this address region by trying to read from it
        self.get_contents_from_address(address, len(data), virtual)

        # If the above did not throw an exception, the provided address range is valid.
        file_offset = address
        if virtual:
            file_offset = self.file_offset_for_virtual_address(VirtualMemoryPointer(address))

        # Create a new binary with the overwritten data
        new_binary_data = bytearray(len(self._cached_binary))
        new_binary_data[:] = self._cached_binary
        new_binary_data[file_offset : file_offset + len(data)] = data

        return MachoBinary(self.path, new_binary_data)

    def write_struct(self, struct: Structure, address: int, virtual: bool = False) -> "MachoBinary":
        """Serialize and write the provided structure the Mach-O slice, returning a new modified binary.
        Note: This will invalidate the binary's code signature, if present.
        TODO(PT): Deprecate and move to MachoBinaryWriter
        """
        # Write the structure bytes to the binary
        # TODO(PT): byte order?
        return self.write_bytes(bytes(struct), address, virtual)

    def insert_load_dylib_cmd(self, dylib_path: str) -> "MachoBinary":
        """Add a load command of the provided dylib path to the Mach-O header, returning a modified binary.
        This will increase mh_header->ncmds by 1, and mh_header->sizeofcmds by the size of the new load command,
        including the pathname.
        Raises NoEmptySpaceForLoadCommandError() if there's not enough space in the Mach-O header to add a new command.
        Note: This will invalidate the binary's code signature, if present.
        TODO(PT): Deprecate and move to MachoBinaryWriter
        """
        if not self.is_64bit:
            raise RuntimeError("Inserting load commands is only support on 64-bit binaries")
        if self.is_swap:
            raise RuntimeError("Unsupported endianness")

        load_cmd = DylibCommand()
        load_cmd.cmd = MachoLoadCommands.LC_LOAD_DYLIB
        sizeof_dylib_struct = sizeof(DylibStruct())
        sizeof_load_cmd = sizeof(load_cmd)
        # XXX(PT): The size of the command should be 0x20 + max(len(dylib_path), 0x20). Found experimentally.
        dylib_path_bytes = bytes(dylib_path, "utf8")
        load_cmd.cmdsize = sizeof_load_cmd + max(len(dylib_path_bytes), 0x20)
        # Align the size on an 8-byte boundary
        if load_cmd.cmdsize % 8:
            load_cmd.cmdsize = (load_cmd.cmdsize + 8) & ~(8 - 1)

        load_cmd.dylib = DylibStruct()
        dylib_name = LcStrUnion()
        # The name starts after the size of the LC_LOAD_DYLIB struct, which is 0x18 bytes
        dylib_name.offset = sizeof_dylib_struct
        load_cmd.dylib.name = dylib_name
        load_cmd.dylib.timestamp = 0x0
        load_cmd.dylib.current_version = 0x0
        load_cmd.dylib.compatibility_version = 0x0

        # TODO(PT): It'd be nice to get a modified MachoBinary with a context manager.
        # This way, all the modifications can be performed on the same binary, without creating a copy
        # for each change.
        # TODO(PT): Alternatively, assignments like `self.header.ncmds += 1` should update the backing binary.
        # This would also make binary modifications easier.

        # Check that there is enough emtpy space before the start of __text to insert a load command
        load_commands_end = self.header.sizeof + self.header.sizeofcmds
        string_end = load_commands_end + load_cmd.cmdsize
        text_section = self.section_with_name("__text", "__TEXT")
        if text_section and string_end >= text_section.offset:
            raise NoEmptySpaceForLoadCommandError()

        # Add the load command to the end of the Mach-O header
        modified_binary = self.write_struct(load_cmd, load_commands_end)
        # Write the dylib path directly after the load cmd
        modified_binary = modified_binary.write_bytes(dylib_path_bytes, load_commands_end + sizeof_dylib_struct)

        # Increase mh_header->ncmds by 1
        bumped_ncmds = self.header.ncmds + 1
        # This field is a 32-bit little-endian encoded int
        bumped_ncmds_bytes = bumped_ncmds.to_bytes(4, "little")
        # The ncmds field is located at the binary head, plus the offset of the field into the mh_header structure
        ncmds_address = MachoHeaderStruct._64_BIT_STRUCT.ncmds.offset
        modified_binary = modified_binary.write_bytes(bumped_ncmds_bytes, ncmds_address)

        # Increase mh_header->sizeofcmds by the size of the new load command
        bumped_sizeofcmds = self.header.sizeofcmds + load_cmd.cmdsize
        # This field is a 32-bit little-endian encoded int
        bumped_sizeofcmds_bytes = bumped_sizeofcmds.to_bytes(4, "little")
        # The sizeofcmds field is located at the binary head, plus the offset of the field into the mh_header structure
        sizeofcmds_address = MachoHeaderStruct._64_BIT_STRUCT.sizeofcmds.offset
        modified_binary = modified_binary.write_bytes(bumped_sizeofcmds_bytes, sizeofcmds_address)

        # All done
        return modified_binary

    def write_binary(self, path: Path) -> None:
        """Write the in-memory Mach-O slice to the provided path.
        TODO(PT): Deprecate and move to MachoBinaryWriter
        """
        # Pass 'x' so the call will throw an exception if the path already exists
        with open(path, "xb") as out_file:
            out_file.write(self._cached_binary)

    @staticmethod
    def write_fat(slices: List["MachoBinary"], path: Path) -> None:
        """Write a list of Mach-O slices into a FAT file at the provided path.
        TODO(PT): Deprecate and move to MachoBinaryWriter
        """
        from strongarm.macho.macho_definitions import MachArch, MachoFatArch, MachoFatHeader

        if any(x.is_swap for x in slices):
            raise RuntimeError("Unsupported endianness")

        # Write the FAT header
        fat_header = MachoFatHeader()
        fat_header.magic = MachArch.FAT_MAGIC.value
        fat_header.nfat_arch = len(slices)
        file_data = bytearray(bytes(fat_header))

        # Write a fat-arch structure for each binary slice
        arch_to_binaries: List[Tuple[MachoFatArch, "MachoBinary"]] = []
        page_size = 0x4000
        for binary in slices:
            arch = MachoFatArch()
            arch.cputype = binary.header.cputype
            arch.cpusubtype = binary.header.cpusubtype
            arch.size = len(binary._cached_binary)
            # Experimentally, in a FAT with an armv7 and arm64 slice, the align for both arch's was log2(0x4000)
            arch.align = int(math.log2(page_size))
            arch_to_binaries.append((arch, binary))

        # Figure out where to place each binary in the file
        speculative_data_end = len(file_data) + (sizeof(MachoFatArch) * len(arch_to_binaries))
        for arch, binary in arch_to_binaries:
            # Find the nearest page boundary
            speculative_data_end = (speculative_data_end + page_size) & ~(page_size - 1)
            # Assign this file offset to the slice
            arch.offset = speculative_data_end
            # Add the size of the binary to the data-size marker
            speculative_data_end += arch.size
            # Write this arch entry to the file data
            file_data += bytearray(bytes(arch))

        # Change the endianess of the FAT header from big to little
        # The FAT header is a list of 32-bit ints
        for idx in range(len(file_data))[::4]:
            # Reverse the bytes of this int
            file_data[idx : idx + 4] = bytearray(reversed(file_data[idx : idx + 4]))

        # We now know the final file size, and where each slice should be placed
        # Zero-fill the rest of the file, and copy in each slice
        # Page-align the file-end
        speculative_data_end = (speculative_data_end + page_size) & ~(page_size - 1)
        file_data += bytearray(speculative_data_end - len(file_data))
        for arch, binary in arch_to_binaries:
            file_data[arch.offset : arch.offset + arch.size] = binary._cached_binary

        # The output file has been constructed. Write it to disk
        # Pass 'x' so the call will throw an exception if the path already exists
        with open(path, "xb") as out_file:
            out_file.write(file_data)

    def get_functions(self) -> Set[VirtualMemoryPointer]:
        """Get a list of the function entry points defined in LC_FUNCTION_STARTS. This includes objective-c methods.

        Returns: A list of VirtualMemoryPointers corresponding to each function's entry point.
        """
        # TODO(PT): move read_uleb somewhere else
        from .dyld_info_parser import DyldInfoParser

        if self._functions_list:
            return self._functions_list

        # Cannot do anything without LC_FUNCTIONS_START
        if not self._function_starts_cmd:
            return set()

        functions_list = set()

        fs_start = self._function_starts_cmd.dataoff
        fs_size = self._function_starts_cmd.datasize
        fs_uleb = self.get_contents_from_address(fs_start, fs_size)

        address = int(self.get_virtual_base())

        idx = 0
        while idx < fs_size:
            address_delta, idx = DyldInfoParser.read_uleb(fs_uleb, idx)

            address += address_delta
            func_entry = VirtualMemoryPointer(address)
            functions_list.add(func_entry)

        self._functions_list = functions_list
        return self._functions_list

    def get_constructor_functions(self) -> List[VirtualMemoryPointer]:
        """Get a list of the function entry points defined in __mod_init_func. This includes C constructors.

        Returns: A list of VirtualMemoryPointers corresponding to each function's entry point.
        """
        return list(self.read_pointer_section("__mod_init_func").values())

    def get_destructor_functions(self) -> List[VirtualMemoryPointer]:
        """Get a list of the function entry points defined in __mod_term_func. This includes C destructors.

        Returns: A list of VirtualMemoryPointers corresponding to each function's entry point.
        """
        return list(self.read_pointer_section("__mod_term_func").values())

    def dylib_id(self) -> Optional[str]:
        """If the binary contains an LC_ID_DYLIB load command, return the pathname which the binary represents."""
        if not self._id_dylib_cmd:
            return None

        dylib_name_addr = (
            self._id_dylib_cmd.binary_offset + self._id_dylib_cmd.dylib.name.offset + self.get_virtual_base()
        )
        dylib_name = self.get_full_string_from_start_address(dylib_name_addr)
        if not dylib_name:
            dylib_name = "<unknown dylib>"
        return dylib_name

    def get_minimum_deployment_target(self) -> Optional[LooseVersion]:
        if not self.__minimum_deployment_target:
            if self._build_version_cmd:
                # X.Y.Z is encoded in nibbles xxxx.yy.zz
                encoded_min_target = self._build_version_cmd.minos
                patch = (encoded_min_target >> (8 * 0)) & 0xFF
                minor = (encoded_min_target >> (8 * 1)) & 0xFF
                major = (encoded_min_target >> (8 * 2)) & 0xFFFF
                self.__minimum_deployment_target = LooseVersion(f"{major}.{minor}.{patch}")
        return self.__minimum_deployment_target

    def get_build_version_platform(self) -> Optional[MachoBuildVersionPlatform]:
        if not self._build_version_cmd:
            return None
        return MachoBuildVersionPlatform(self._build_version_cmd.platform)

    def get_build_tool_versions(self) -> Optional[List[MachoBuildToolVersionStruct]]:
        return self._build_tool_versions
