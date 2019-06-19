from typing import List, Dict, Tuple, Any, Type, Optional, TypeVar
from typing import TYPE_CHECKING

from ctypes import c_uint64, c_uint32, sizeof

from strongarm.debug_util import DebugUtil

from strongarm.macho.macho_definitions import (
    CPU_TYPE,
    MachArch,
    HEADER_FLAGS,
    MachoFileType,
    FILE_HEAD_PTR,
    StaticFilePointer,
    VirtualMemoryPointer
)
from strongarm.macho.arch_independent_structs import (
    ArchIndependentStructure,
    MachoHeaderStruct,
    MachoSegmentCommandStruct,
    MachoSectionRawStruct,
    MachoEncryptionInfoStruct,
    MachoNlistStruct,
    CFStringStruct,
    DylibCommandStruct,
    MachoLoadCommandStruct,
    MachoSymtabCommandStruct,
    MachoDysymtabCommandStruct,
    MachoDyldInfoCommandStruct,
    MachoLinkeditDataCommandStruct,
)
from strongarm.macho.macho_load_commands import MachoLoadCommands

if TYPE_CHECKING:
    from strongarm.macho.codesign import CodesignParser

AIS = TypeVar("AIS", bound=ArchIndependentStructure)


class BinaryEncryptedError(Exception):
    pass


class LoadCommandMissingError(Exception):
    pass


class InvalidAddressError(Exception):
    """Raised when a client asks for bytes at an address outside the binary
    """


class MachoSection:
    def __init__(self, binary: 'MachoBinary', section_command: MachoSectionRawStruct) -> None:
        self.cmd = section_command
        # ignore these types due to dynamic attributes of associated types
        self.content = binary.get_bytes(section_command.offset, section_command.size)
        self.name = section_command.sectname
        self.address = section_command.addr
        self.offset = section_command.offset
        self.end_address = self.address + section_command.size


class MachoBinary:
    _MAG_64 = [
        MachArch.MH_MAGIC_64,
        MachArch.MH_CIGAM_64
    ]
    _MAG_32 = [
        MachArch.MH_MAGIC,
        MachArch.MH_CIGAM,
    ]
    _MAG_BIG_ENDIAN = [
        MachArch.MH_CIGAM,
        MachArch.MH_CIGAM_64,
    ]
    SUPPORTED_MAG = _MAG_64 + _MAG_32
    BYTES_PER_INSTRUCTION = 4

    def __init__(self, filename: bytes, offset_within_fat: StaticFilePointer = FILE_HEAD_PTR) -> None:
        from .codesign.codesign_parser import CodesignParser
        # info about this Mach-O's file representation
        self.filename = filename
        self._offset_within_fat = offset_within_fat

        # generic Mach-O header info
        self.is_64bit: bool = False
        self.is_swap: bool = False
        self.cpu_type: CPU_TYPE = CPU_TYPE.UNKNOWN
        self._load_commands_end_addr = 0

        # Mach-O header data
        self._header: Optional[MachoHeaderStruct] = None
        self.header_flags: List[int] = []
        self.file_type: MachoFileType = MachoFileType.MH_EXECUTE

        # segment and section commands from Mach-O header
        self.segments: List[MachoSegmentCommandStruct] = []
        self.sections: List[MachoSection] = []
        # also store specific interesting sections which are useful to us
        self._dysymtab: Optional[MachoDysymtabCommandStruct] = None
        self._symtab: Optional[MachoSymtabCommandStruct] = None
        self._encryption_info: Optional[MachoEncryptionInfoStruct] = None
        self._dyld_info: Optional[MachoDyldInfoCommandStruct] = None
        self.load_dylib_commands: List[DylibCommandStruct] = []
        self._code_signature_cmd: Optional[MachoLinkeditDataCommandStruct] = None

        self.__codesign_parser: Optional[CodesignParser] = None

        # cache to save work on calls to get_bytes()
        with open(self.filename, 'rb') as f:
            # TODO(PT): this should only read to the end of our FAT slice!
            self._cached_binary = f.read()[offset_within_fat:]

        # kickoff for parsing this slice
        if not self.parse():
            raise RuntimeError('Failed to parse Mach-O')

        self.platform_word_type = c_uint64 if self.is_64bit else c_uint32
        self.symtab_contents = self._get_symtab_contents()
        DebugUtil.log(self, f"parsed symtab, len = {len(self.symtab_contents)}")

        # Internal use
        self._last_segment_command: Optional[MachoSegmentCommandStruct] = None

    def parse(self) -> bool:
        """Attempt to parse the provided file info as a Mach-O slice

        Returns:
            True if the file data represents a valid & supported Mach-O which was successfully parsed.
            False otherwise.

        """
        DebugUtil.log(self, f'parsing Mach-O slice @ {hex(int(self._offset_within_fat))} in {self.filename.decode()}')

        # preliminary Mach-O parsing
        if not self.verify_magic():
            DebugUtil.log(self, f'unsupported magic {hex(self.slice_magic)}')
            return False
        self.is_swap = self.should_swap_bytes()
        self.is_64bit = self.magic_is_64()

        self.parse_header()

        DebugUtil.log(self, f'header parsed. non-native endianness? {self.is_swap}. 64-bit? {self.is_64bit}')
        return True

    @property
    def slice_magic(self) -> int:
        """Read magic number identifier from this Mach-O slice
        """
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

        self._load_commands_end_addr = load_commands_off + self.header.sizeofcmds   # type: ignore
        self._parse_segment_commands(load_commands_off, self.header.ncmds)  # type: ignore

    def _parse_header_flags(self) -> None:
        """Interpret binary's header bitset and populate self.header_flags
        """
        self.header_flags = []

        flags_bitset = self.header.flags
        for mask in [x.value for x in HEADER_FLAGS]:
            # is this mask set in the binary's flags?
            if (flags_bitset & mask) == mask:
                # mask is present in bitset, add to list of included flags
                self.header_flags.append(mask)

    def _parse_segment_commands(self, offset: StaticFilePointer, segment_count: int) -> None:
        """Parse Mach-O segment commands beginning at a given slice offset

        Args:
            offset: Slice offset to first segment command
            segment_count: Number of segments to parse, as declared by the header's ncmds field

        """
        self.load_dylib_commands = []

        for i in range(segment_count):
            load_command = self.read_struct(offset, MachoLoadCommandStruct)

            if load_command.cmd in [MachoLoadCommands.LC_SEGMENT,
                                    MachoLoadCommands.LC_SEGMENT_64]:

                segment = self.read_struct(offset, MachoSegmentCommandStruct)
                # TODO(pt) handle byte swap of segment if necessary
                self.segments.append(segment)
                self._parse_sections_for_segment(segment, offset)
                self._last_segment_command = segment

            # some commands have their own structure that we interpret separately from a normal load command
            # if we want to interpret more commands in the future, this is the place to do it
            elif load_command.cmd in [MachoLoadCommands.LC_ENCRYPTION_INFO,
                                      MachoLoadCommands.LC_ENCRYPTION_INFO_64]:
                self._encryption_info = self.read_struct(offset, MachoEncryptionInfoStruct)

            elif load_command.cmd == MachoLoadCommands.LC_SYMTAB:
                self._symtab = self.read_struct(offset, MachoSymtabCommandStruct)

            elif load_command.cmd == MachoLoadCommands.LC_DYSYMTAB:
                self._dysymtab = self.read_struct(offset, MachoDysymtabCommandStruct)

            elif load_command.cmd in [MachoLoadCommands.LC_DYLD_INFO, MachoLoadCommands.LC_DYLD_INFO_ONLY]:
                self._dyld_info = self.read_struct(offset, MachoDyldInfoCommandStruct)

            elif load_command.cmd in [MachoLoadCommands.LC_LOAD_DYLIB, MachoLoadCommands.LC_LOAD_WEAK_DYLIB]:
                dylib_load_command = self.read_struct(offset, DylibCommandStruct)
                self.load_dylib_commands.append(dylib_load_command)

            elif load_command.cmd == MachoLoadCommands.LC_CODE_SIGNATURE:
                self._code_signature_cmd = self.read_struct(offset, MachoLinkeditDataCommandStruct)

            # move to next load command in header
            offset += load_command.cmdsize

    def read_struct(self,
                    binary_offset: int,
                    struct_type: Type[AIS],
                    virtual: bool = False) -> AIS:
        """Given an binary offset, return the structure ot describes.

        Params:
            binary_offset: Address from where to read the bytes.
            struct_type: ArchIndependentStructure subclass.
            virtual: Whether the address should be slid (virtual) or not.

        Returns:
            ArchIndependentStructure loaded from the pointed address.
        """

        size = struct_type.struct_size(self.is_64bit)
        data = self.get_contents_from_address(address=binary_offset, size=size, is_virtual=virtual)
        return struct_type(binary_offset, data, self.is_64bit)

    def write_struct(self, address: int, struct: ArchIndependentStructure) -> None:
        pass

    def section_name_for_address(self, virt_addr: VirtualMemoryPointer) -> Optional[str]:
        """Given an address in the virtual address space, return the name of the section which contains it.
        """
        section = self.section_for_address(virt_addr)
        if not section:
            return None
        return section.name.decode('UTF8')

    def section_for_address(self, virt_addr: VirtualMemoryPointer) -> Optional[MachoSection]:
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

    def segment_for_index(self, segment_index: int) -> MachoSegmentCommandStruct:
        if segment_index < 0 or segment_index >= len(self.segments):
            raise ValueError(f"segment_index ({segment_index}) out of bounds ({len(self.segments)}")
        # PT: Segments are guaranteed to be sorted in the order they appear in the Mach-O header
        return self.segments[segment_index]

    def segment_with_name(self, desired_segment_name: str) -> Optional[MachoSegmentCommandStruct]:
        # TODO(PT): add unit test for this method
        for segment_cmd in self.segments:
            segment_name = segment_cmd.segname.decode()
            if segment_name == desired_segment_name:
                return segment_cmd
        return None

    def section_with_name(self, desired_section_name: str, parent_segment_name: str) -> Optional[MachoSection]:
        # Sanity-check that a valid segment was provided
        if not self.segment_with_name(parent_segment_name):
            raise RuntimeError(f'No such segment: {parent_segment_name}')

        # TODO(PT): add unit test for this method
        for section in self.sections:
            section_name = section.name.decode()
            if section_name == desired_section_name:
                if section.cmd.segname.decode() != parent_segment_name:
                    print(f'skipping {section_name} because its not in correct segment')
                    continue
                return section
        return None

    def _parse_sections_for_segment(self,
                                    segment: MachoSegmentCommandStruct,
                                    segment_offset: StaticFilePointer) -> None:
        """Parse all sections contained within a Mach-O segment, and add them to our list of sections

        Args:
            segment: The segment command whose sections should be read
            segment_offset: The offset within the file that the segment command is located at
        """
        if not segment.nsects:
            return

        # The first section of this segment begins directly after the segment
        section_offset = segment_offset + segment.sizeof
        for i in range(segment.nsects):
            # Read section header from file
            # TODO(PT): handle byte swap of segment
            section_command = self.read_struct(section_offset, MachoSectionRawStruct)
            # Encapsulate header and content into one object, and store that
            section = MachoSection(self, section_command)
            # Add to list of sections within the Mach-O
            self.sections.append(section)

            # Iterate to next section in list
            section_offset += section_command.sizeof

    def get_virtual_base(self) -> VirtualMemoryPointer:
        """Retrieve the first virtual address of the Mach-O slice

        Returns:
            int containing the virtual memory space address that the Mach-O slice requests to begin at

        """
        # TODO(PT): Perhaps this should be cached. Finding the segment by name is now O(n) on segment count
        text_seg = self.segment_with_name('__TEXT')
        if not text_seg:
            raise RuntimeError(f'Could not find virtual base because binary has no __TEXT segment.')
        return VirtualMemoryPointer(text_seg.vmaddr)

    def get_bytes(self, offset: StaticFilePointer, size: int) -> bytearray:
        """Retrieve bytes from Mach-O slice, taking into account that the slice could be at an offset within a FAT

        Args:
            offset: index from beginning of slice to retrieve data from
            size: maximum number of bytes to read

        Returns:
            string containing byte content of mach-o slice at an offset from the start of the slice

        """
        if offset > 0x100000000:
            raise InvalidAddressError(f'get_bytes() offset {hex(offset)} looks like a virtual address.'
                                      f' Did you mean to use get_content_from_virtual_address?')

        # safeguard against reading from an encrypted segment of the binary
        if self.is_range_encrypted(offset, size):
            raise BinaryEncryptedError(f'Cannot read encrypted'
                                       f' range [{hex(int(self.encryption_info.cryptoff))}'
                                       f' to {hex(int(self.encryption_info.cryptsize))}]')

        return bytearray(self._cached_binary[offset:offset+size])

    def should_swap_bytes(self) -> bool:
        """Check whether self.slice_magic refers to a big-endian Mach-O binary

        Returns:
            True if self.slice_magic indicates a big endian Mach-O, False otherwise

        """
        # TODO(pt): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
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

    def _get_symtab_contents(self) -> List[MachoNlistStruct]:
        """Parse symbol table containing list of Nlist64's

        Returns:
            Array of Nlist64's representing binary's symbol table

        """
        DebugUtil.log(self, f'parsing {self.symtab.nsyms} symtab entries')

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
            raise RuntimeError(f'Could not map virtual address {hex(int(virtual_address))} to a section!')

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
         express intent and facilitate the implementation by using @singledispatch
         (https://docs.python.org/3/library/functools.html?highlight=singledispatch#functools.singledispatch)
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
                    symbol_name = bytearray(symbol_name_characters).decode('UTF-8')
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
        # special case if this is a __cfstring entry
        if section_name == '__cfstring':
            # read bytes into CFString struct
            cfstring_ent = self.read_struct(address, CFStringStruct, virtual=True)
            # patch address to read string from to be the string literal address of this CFString
            address = cfstring_ent.literal
        return self.get_full_string_from_start_address(address)

    def is_encrypted(self) -> bool:
        """Returns True if the binary has an encrypted segment, False otherwise
        """
        if not self._encryption_info:
            return False
        return self.encryption_info.cryptid != 0

    def is_range_encrypted(self, offset: StaticFilePointer, size: int) -> bool:
        """Returns whether the provided address range overlaps with the encrypted section of the binary.
        """
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
        """Read the name of the dynamic library by its library ordinal
        """
        source_dylib = self.dylib_for_library_ordinal(library_ordinal)
        if source_dylib:
            source_name_addr = source_dylib.binary_offset + \
                               source_dylib.dylib.name.offset + \
                               self.get_virtual_base()
            source_name = self.get_full_string_from_start_address(source_name_addr)
            if not source_name:
                source_name = '<unknown dylib>'
        else:
            # we have encountered binaries where the n_desc indicates a nonexistent library ordinal
            # Netflix.app/frameworks/widevine_cdm_sdk_oemcrypto_release.framework/widevine_cdm_sdk_oemcrypto_release
            # indicates an ordinal 254, when the binary only actually has 8 LC_LOAD_DYLIB commands.
            # if we encounter a buggy binary like this, just use a placeholder name
            source_name = '<unknown dylib>'
        return source_name

    def read_pointer_section(self, section_name: str) -> Tuple[List[VirtualMemoryPointer], List[VirtualMemoryPointer]]:
        """Read all the pointers in a section

        It is the caller's responsibility to only call this with a `section_name` which indicates a section which should
        only contain a pointer list.

        The return value is two lists of pointers.
        The first List contains the virtual addresses of each entry in the section.
        The second List contains the pointer values contained at each of these addresses.

        The indexes of these two lists are matched up; that is, list1[0] is the virtual address of the first pointer
        in the requested section, and list2[0] is the pointer value contained at that address.
        """
        locations: List[VirtualMemoryPointer] = []
        entries: List[VirtualMemoryPointer] = []

        # PT: Assume a pointer-list-section will always be in the __DATA segment. True as far as I know.
        section = self.section_with_name(section_name, '__DATA')
        if not section:
            return locations, entries

        section_base = section.address
        section_data = section.content

        binary_word = self.platform_word_type
        pointer_count = int(len(section_data) / sizeof(binary_word))
        pointer_off = 0

        for i in range(pointer_count):
            # convert section offset of entry to absolute virtual address
            locations.append(VirtualMemoryPointer(section_base + pointer_off))

            data_end = pointer_off + sizeof(binary_word)
            val = binary_word.from_buffer(bytearray(section_data[pointer_off:data_end])).value
            entries.append(VirtualMemoryPointer(val))

            pointer_off += sizeof(binary_word)

        return locations, entries

    def read_word(self,
                  address: int,
                  virtual: bool = True,
                  word_type: Any = None) -> int:
        """Attempt to read a word from the binary at a virtual address. Returns None if the address is invalid.
        """
        if not word_type:
            word_type = self.platform_word_type

        if virtual:
            file_bytes = self.get_content_from_virtual_address(VirtualMemoryPointer(address), sizeof(word_type))
        else:
            file_bytes = self.get_bytes(StaticFilePointer(address), sizeof(word_type))

        if not file_bytes:
            raise ValueError(f"Could not read word at address 0x{hex(address)}")

        return word_type.from_buffer(bytearray(file_bytes)).value

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
    def _codesign_parser(self) -> 'CodesignParser':
        if not self.__codesign_parser:
            from strongarm.macho.codesign import CodesignParser
            self.__codesign_parser = CodesignParser(self)
        return self.__codesign_parser

    def get_entitlements(self) -> Optional[bytearray]:
        """Read the entitlements the binary was signed with.
        """
        return self._codesign_parser.entitlements

    def get_signing_identity(self) -> Optional[str]:
        """Read the bundle ID the binary was signed as.
        """
        return self._codesign_parser.signing_identifier

    def get_team_id(self) -> Optional[str]:
        """Read the team ID the binary was signed with.
        """
        return self._codesign_parser.signing_team_id
