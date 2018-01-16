# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from typing import List, Text, Optional

from strongarm.debug_util import DebugUtil

from strongarm.macho.macho_definitions import MachArch, CPU_TYPE, HEADER_FLAGS
from strongarm.macho.macho_load_commands import MachoLoadCommands
from strongarm.macho.arch_independent_structs import \
    MachoHeaderStruct, \
    MachoSegmentCommandStruct, \
    MachoSectionRawStruct, \
    MachoEncryptionInfoStruct, \
    MachoNlistStruct, \
    CFStringStruct, \
    DylibCommandStruct, \
    MachoLoadCommandStruct, \
    MachoSymtabCommandStruct, \
    MachoDysymtabCommandStruct

from ctypes import c_uint64, c_uint32, sizeof
import io


class BinaryEncryptedError(Exception):
    pass


class MachoSection(object):
    def __init__(self, binary, section_command):
        # type: (MachoBinary, MachoSectionRawStruct) -> None
        self.cmd = section_command
        self.content = binary.get_bytes(section_command.offset, section_command.size)
        self.name = section_command.sectname
        self.address = section_command.addr
        self.offset = section_command.offset
        self.end_address = self.address + section_command.size


class MachoBinary(object):
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

    def __init__(self, filename, offset_within_fat=0):
        # type: (Text, int) -> None
        # info about this Mach-O's file representation
        self.filename = filename
        self._offset_within_fat = offset_within_fat

        # generic Mach-O header info
        self.is_64bit = None
        self.is_swap = None
        self.cpu_type = None
        self._load_commands_end_addr = None

        # Mach-O header data
        self.header = None
        self.header_flags = None

        # segment and section commands from Mach-O header
        self.segment_commands = None
        self.sections = None
        # also store specific interesting sections which are useful to us
        self.dysymtab = None
        self.symtab = None
        self.encryption_info = None
        self.load_dylib_commands = None

        # cache to save work on calls to get_bytes()
        with open(self.filename, 'rb') as f:
            self._cached_binary = f.read()[offset_within_fat:]

        # kickoff for parsing this slice
        if not self.parse():
            raise RuntimeError('Failed to parse Mach-O')

        self.platform_word_type = c_uint64 if self.is_64bit else c_uint32
        self.symtab_contents = self._get_symtab_contents()
        DebugUtil.log(self, "parsed symtab, len = {}".format(len(self.symtab_contents)))

    def parse(self):
        # type: () -> bool
        """Attempt to parse the provided file info as a Mach-O slice

        Returns:
            True if the file data represents a valid & supported Mach-O which was successfully parsed.
            False otherwise.

        """
        DebugUtil.log(self, 'parsing Mach-O slice @ {} in {}'.format(
            hex(int(self._offset_within_fat)),
            self.filename.decode('utf-8')
        ))

        # preliminary Mach-O parsing
        if not self.verify_magic():
            DebugUtil.log(self, 'unsupported magic {}'.format(hex(int(self.slice_magic))))
            return False
        self.is_swap = self.should_swap_bytes()
        self.is_64bit = self.magic_is_64()

        self.parse_header()

        DebugUtil.log(self, 'header parsed. non-native endianness? {}. 64-bit? {}'.format(self.is_swap, self.is_64bit))
        return True

    @property
    def slice_magic(self):
        # type: () -> None
        """Read magic number identifier from this Mach-O slice
        """
        return c_uint32.from_buffer(bytearray(self.get_bytes(0, sizeof(c_uint32)))).value

    def verify_magic(self):
        # type: () -> bool
        """Ensure magic at beginning of Mach-O slice indicates a supported format

        Returns:
            True if the magic represents a supported file format, False if the magic represents an unsupported format

        """
        return self.slice_magic in MachoBinary.SUPPORTED_MAG

    def magic_is_64(self):
        # type: () -> bool
        """Convenience method to check if our magic corresponds to a 64-bit slice

        Returns:
            True if self.slice_magic corresponds to a 64 bit MachO slice, False otherwise

        """
        return self.slice_magic in MachoBinary._MAG_64

    def parse_header(self):
        # type: () -> None
        """Read all relevant info from a Mach-O header which does not require cross-referencing.
        Specifically, this method parses the Mach-O header & header flags, CPU target,
        and all segment and section commands.
        """
        self.header = MachoHeaderStruct(self, 0)

        if self.header.cputype == MachArch.MH_CPU_TYPE_ARM:
            self.cpu_type = CPU_TYPE.ARMV7
        elif self.header.cputype == MachArch.MH_CPU_TYPE_ARM64:
            self.cpu_type = CPU_TYPE.ARM64
        else:
            self.cpu_type = CPU_TYPE.UNKNOWN

        self._parse_header_flags()

        # load commands begin directly after Mach O header, so the offset is the size of the header
        load_commands_off = self.header.sizeof

        self._load_commands_end_addr = load_commands_off + self.header.sizeofcmds
        self._parse_segment_commands(load_commands_off, self.header.ncmds)

    def _parse_header_flags(self):
        # type: () -> None
        """Interpret binary's header bitset and populate self.header_flags
        """
        self.header_flags = []

        flags_bitset = self.header.flags
        for mask in [x.value for x in HEADER_FLAGS]:
            # is this mask set in the binary's flags?
            if (flags_bitset & mask) == mask:
                # mask is present in bitset, add to list of included flags
                self.header_flags.append(mask)

    def _parse_segment_commands(self, offset, segment_count):
        # type: (int) -> None
        """Parse Mach-O segment commands beginning at a given slice offset

        Args:
            offset: Slice offset to first segment command
            segment_count: Number of segments to parse, as declared by the header's ncmds field

        """
        self.segment_commands = {}
        self.sections = {}
        self.load_dylib_commands = []

        for i in range(segment_count):
            load_command = MachoLoadCommandStruct(self, offset)

            if load_command.cmd in [MachoLoadCommands.LC_SEGMENT,
                                    MachoLoadCommands.LC_SEGMENT_64]:
                segment = MachoSegmentCommandStruct(self, offset)
                # TODO(pt) handle byte swap of segment if necessary
                self.segment_commands[segment.segname.decode('UTF8')] = segment
                self._parse_sections_for_segment(segment, offset)

            # some commands have their own structure that we interpret separately from a normal load command
            # if we want to interpret more commands in the future, this is the place to do it
            elif load_command.cmd in [MachoLoadCommands.LC_ENCRYPTION_INFO,
                                      MachoLoadCommands.LC_ENCRYPTION_INFO_64]:
                self.encryption_info = MachoEncryptionInfoStruct(self, offset)
            elif load_command.cmd == MachoLoadCommands.LC_SYMTAB:
                self.symtab = MachoSymtabCommandStruct(self, offset)
            elif load_command.cmd == MachoLoadCommands.LC_DYSYMTAB:
                self.dysymtab = MachoDysymtabCommandStruct(self, offset)
            elif load_command.cmd in [MachoLoadCommands.LC_LOAD_DYLIB, MachoLoadCommands.LC_LOAD_WEAK_DYLIB]:
                dylib_load_command = DylibCommandStruct(self, offset)
                dylib_load_command.fileoff = offset
                self.load_dylib_commands.append(dylib_load_command)

            # move to next load command in header
            offset += load_command.cmdsize

    def section_name_for_address(self, virt_addr):
        # type: (int) -> Optional[Text]
        """Given an address in the virtual address space, return the name of the section which contains it.
        """
        return self.section_for_address(virt_addr).name.decode('UTF8')

    def section_for_address(self, virt_addr):
        # type: (int) -> Optional[MachoSection]
        import six
        # invalid address?
        if virt_addr < self.get_virtual_base():
            return None

        # if the address given is past the last declared section, translate based on the last section
        # so, we need to keep track of the last seen section
        max_section = six.next(six.itervalues(self.sections))

        for section_name in self.sections:
            section = self.sections[section_name]
            # update highest section
            if section.address > max_section.address:
                max_section = section

            if section.address <= virt_addr < section.end_address:
                return self.sections[section_name]
        # we looked through all sections and didn't find one explicitly containing this address
        # guess by using the highest-addressed section we've seen
        return max_section

    def _parse_sections_for_segment(self, segment, segment_offset):
        # type: (MachoSegmentCommandStruct, int) -> None
        """Parse all sections contained within a Mach-O segment, and add them to our list of sections

        Args:
            segment: The segment command whose sections should be read
            segment_offset: The offset within the file that the segment command is located at
        """
        if not segment.nsects:
            return

        # the first section of this segment begins directly after the segment
        section_offset = segment_offset + segment.sizeof
        for i in range(segment.nsects):
            # read section header from file
            # TODO(PT): handle byte swap of segment
            section_command = MachoSectionRawStruct(self, section_offset)
            # encapsulate header and content into one object, and store that
            section = MachoSection(self, section_command)
            # add to map with the key being the name of the section
            self.sections[section_command.sectname.decode('UTF8')] = section

            # go to next section in list
            section_offset += section_command.sizeof

    def get_virtual_base(self):
        # type: () -> int
        """Retrieve the first virtual address of the Mach-O slice

        Returns:
            int containing the virtual memory space address that the Mach-O slice requests to begin at

        """
        text_seg = self.segment_commands['__TEXT']
        return text_seg.vmaddr

    def get_bytes(self, offset, size):
        # type: (int, int) -> bytearray
        """Retrieve bytes from Mach-O slice, taking into account that the slice could be at an offset within a FAT

        Args:
            offset: index from beginning of slice to retrieve data from
            size: maximum number of bytes to read

        Returns:
            string containing byte content of mach-o slice at an offset from the start of the slice

        """
        if offset > 0x100000000:
            raise RuntimeError('get_bytes() offset {} looks like a virtual address. Did you mean to use '
                               'get_content_from_virtual_address?'.format(hex(offset)))

        # safeguard against reading from an encrypted segment of the binary
        if self.is_range_encrypted(offset, size):
            raise BinaryEncryptedError('Cannot read encrypted range [{} to {}]'.format(
                hex(int(self.encryption_info.cryptoff)),
                hex(int(self.encryption_info.cryptsize))
            ))

        return bytearray(self._cached_binary[offset:offset+size])

    def should_swap_bytes(self):
        # type: () -> bool
        """Check whether self.slice_magic refers to a big-endian Mach-O binary

        Returns:
            True if self.slice_magic indicates a big endian Mach-O, False otherwise

        """
        # TODO(pt): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
        return self.slice_magic in MachoBinary._MAG_BIG_ENDIAN

    def get_raw_string_table(self):
        # type: () -> List[int]
        """Read string table from binary, as described by LC_SYMTAB. Each strtab entry is terminated
        by a NULL character.

        Returns:
            Raw, packed array of characters containing binary's string table data

        """
        string_table_data = self.get_bytes(self.symtab.stroff, self.symtab.strsize)
        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(string_table_data)
        return string_table

    def _get_symtab_contents(self):
        # type: () -> List[MachoNlistStruct]
        """Parse symbol table containing list of Nlist64's

        Returns:
            Array of Nlist64's representing binary's symbol table

        """
        DebugUtil.log(self, 'parsing {} symtab entries'.format(self.symtab.nsyms))

        symtab = []
        # start reading from symoff and increment by one Nlist64 each iteration
        symoff = self.symtab.symoff
        for i in range(self.symtab.nsyms):
            nlist = MachoNlistStruct(self, symoff)
            symtab.append(nlist)
            # go to next Nlist in file
            symoff += nlist.sizeof

        return symtab

    def get_indirect_symbol_table(self):
        # type: () -> List[c_uint32]
        indirect_symtab = []
        # dysymtab has fields that tell us the file offset of the indirect symbol table, as well as the number
        # of indirect symbols present in the mach-o
        indirect_symtab_off = self.dysymtab.indirectsymoff

        # indirect symtab is an array of uint32's
        for i in range(self.dysymtab.nindirectsyms):
            indirect_symtab_bytes = self.get_bytes(indirect_symtab_off, sizeof(c_uint32))
            indirect_symtab_entry = c_uint32.from_buffer(bytearray(indirect_symtab_bytes))
            indirect_symtab.append(int(indirect_symtab_entry.value))
            # traverse to next pointer
            indirect_symtab_off += sizeof(c_uint32)
        return indirect_symtab

    def file_offset_for_virtual_address(self, virtual_address):
        # type: (int) -> int
        # if this address is within the initial Mach-O load commands, it must be handled seperately
        # this unslid virtual address is just a 'best guess' of the physical file address, and it'll be the correct
        # address if the virtual address was within the initial load commands
        # if the virtual address was in the section contents, however, we must use another method to translate addresses
        unslid_virtual_address = virtual_address - self.get_virtual_base()
        if unslid_virtual_address < self._load_commands_end_addr:
            return unslid_virtual_address

        section_for_address = self.section_for_address(virtual_address)
        if not section_for_address:
            raise RuntimeError('Couldn\'t map virtual address {} to a section!'.format(hex(int(virtual_address))))

        # the virtual address is contained within a section's contents
        # use this formula to convert a virtual address within a section to the file offset:
        # https://reverseengineering.stackexchange.com/questions/8177/convert-mach-o-vm-address-to-file-offset
        binary_address = (virtual_address - section_for_address.address) + section_for_address.offset
        return binary_address

    def get_content_from_virtual_address(self, virtual_address, size):
        # type: (int, int) -> bytearray
        binary_address = self.file_offset_for_virtual_address(virtual_address)
        return self.get_bytes(binary_address, size)

    def get_full_string_from_start_address(self, start_address, virtual=True):
        # type: (int) -> Optional[Text]
        """Return a string containing the bytes from start_address up to the next NULL character
        This method will return None if the specified address does not point to a UTF-8 encoded string
        """
        max_len = 16
        symbol_name_characters = []
        found_null_terminator = False

        while not found_null_terminator:
            if virtual:
                name_bytes = self.get_content_from_virtual_address(virtual_address=start_address, size=max_len)
            else:
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
                    symbol_name = bytearray(symbol_name_characters).decode('UTF-8')
                    return symbol_name
                except UnicodeDecodeError:
                    # if decoding the string failed, we may have been passed an address which does not actually
                    # point to a string
                    return None

    def read_string_at_address(self, address):
        # type: (int) -> Optional[Text]
        """Read a string embedded in the binary at address
        This method will automatically parse a CFString and return the string literal if address points to one
        """
        section_name = self.section_name_for_address(address)
        # special case if this is a __cfstring entry
        if section_name == '__cfstring':
            # read bytes into CFString struct
            cfstring_ent = CFStringStruct(self, address, virtual=True)
            # patch address to read string from to be the string literal address of this CFString
            address = cfstring_ent.literal
        return self.get_full_string_from_start_address(address)

    def is_encrypted(self):
        # type: () -> bool
        """Returns True if the binary has an encrypted segment, False otherwise
        """
        if not self.encryption_info:
            return False
        return self.encryption_info.cryptid != 0

    def is_range_encrypted(self, offset, size):
        # type: (int, int) -> bool
        """Returns whether the provided address range overlaps with the encrypted section of the binary.
        """
        if not self.encryption_info:
            return False
        # if cryptid is 0, binary is not encrypted
        if not self.encryption_info.cryptid:
            return False

        # if 2 ranges overlap, the end address of the first range will be greater than the start of the second, and
        # the end address of the second will be greater than the start of the first
        range1 = (offset, offset + size)
        range2 = (self.encryption_info.cryptoff, self.encryption_info.cryptoff + self.encryption_info.cryptsize)
        return range1[1] >= range2[0] and range2[1] >= range1[0]

