from macho_definitions import *
import macho_load_commands
from decorators import memoized


class MachoStringTableEntry(object):
    def __init__(self, start_idx, length):
        self.start_idx = start_idx
        self.length = length


class MachoBinary(object):
    def __init__(self, fat_file, offset_within_fat=0):
        # type: (file, int) -> MachoBinary
        self._file = fat_file
        self.offset_within_fat = offset_within_fat

        self.is_64bit = False
        self.load_commands_offset = 0
        self._num_commands = 0
        self.cpu_type = CPU_TYPE.UNKNOWN
        self.magic = 0
        self.is_swap = False

        self.header = None
        self.segments = {}
        self.sections = {}
        self.dysymtab = None
        self.symtab = None
        self.encryption_info = None
        self.imported_functions = None
        self.classlist = None
        self.header_flags = []

        self.parse()

    def parse(self):
        # type: () -> None
        """
        Attempt to parse the provided file contents as a MachO slice
        This method may throw an exception if the provided data does not represent a valid or supported
        Mach-O slice.
        """
        if not self.check_magic():
            return
        self.is_swap = self.should_swap_bytes()
        self.is_64bit = self.magic_is_64()
        self.parse_header()
        self.imported_functions = self.parse_imported_symbols()
        self.parse_classlist()

    def check_magic(self):
        # type: () -> bool
        """
        Ensure magic at provided offset within provided file represents a valid and supported Mach-O slice
        Sets up byte swapping if host and slice differ in endianness
        This method will throw an exception if the magic is invalid or unsupported
        Returns:
            True if the magic represents a supported file format
        """
        self.magic = c_uint32.from_buffer(bytearray(self.get_bytes(0, sizeof(c_uint32)))).value
        valid_mag = [
            MachArch.MH_MAGIC_64,
            MachArch.MH_CIGAM_64
        ]
        mag32 = [
            MachArch.MH_MAGIC,
            MachArch.MH_CIGAM,
        ]
        self.is_swap = self.should_swap_bytes()

        if self.magic in mag32:
            raise RuntimeError('32-bit Mach-O slices not supported')
        if self.magic not in valid_mag:
            raise RuntimeError('Macho slice @ {} had invalid magic {}'.format(
                hex(int(self.offset_within_fat)),
                hex(int(self.magic))
            ))
        return True

    def magic_is_64(self):
        # type: () -> bool
        """
        Convenience method to check if our magic corresponds to a 64-bit slice
        Returns:
            True if self.magic corresponds to a 64 bit MachO slice, False otherwise
        """
        return self.magic == MachArch.MH_MAGIC_64 or self.magic == MachArch.MH_CIGAM_64

    def parse_header(self):
        # type: () -> None
        """
        Parse all info from a Mach-O header.
        This method will also parse all segment and section commands.
        """
        header_bytes = self.get_bytes(0, sizeof(MachoHeader64))
        self.header = MachoHeader64.from_buffer(bytearray(header_bytes))

        if self.header.cputype == MachArch.MH_CPU_TYPE_ARM:
            self.cpu_type = CPU_TYPE.ARMV7
        elif self.header.cputype == MachArch.MH_CPU_TYPE_ARM64:
            self.cpu_type = CPU_TYPE.ARM64
        else:
            self.cpu_type = CPU_TYPE.UNKNOWN

        self.parse_header_flags()

        self._num_commands = self.header.ncmds
        # load commands begin directly after Mach O header
        self.load_commands_offset = sizeof(MachoHeader64)
        self.parse_segment_commands(self.load_commands_offset)

    def parse_header_flags(self):
        # type: () -> None
        """
        Interpret binary's header bitset and populate self.header_flags
        """
        flags_bitset = self.header.flags
        # get all fields from HEADER_FLAGS
        # we get class members by getting all fields of the class,
        # and filtering out private names, and methods
        flags_as_dict = HEADER_FLAGS.__dict__
        possible_flags = {key:value for key, value in flags_as_dict.items() \
                          if not key.startswith('__') and not callable(key)}
        for name in possible_flags:
            mask = flags_as_dict[name]
            # is this mask set in the binary's flags?
            if (flags_bitset & mask) == mask:
                # mask is present in bitset
                self.header_flags.append(mask)

    def parse_segment_commands(self, offset):
        # type: (int) -> None
        """
        Parse Mach-O segment commands beginning at a given slice offset
        Args:
            offset: Slice offset to first segment command
        """
        for i in range(self._num_commands):
            load_command_bytes = self.get_bytes(offset, sizeof(MachOLoadCommand))
            load_command = MachOLoadCommand.from_buffer(bytearray(load_command_bytes))
            # TODO(pt) handle byte swap of load_command
            if load_command.cmd == MachoLoadCommands.LC_SEGMENT:
                # 32 bit segments unsupported!
                continue

            # some commands have their own structure that we interpret seperately from a normal load command
            # if we want to interpret more commands in the future, this is the place to do it
            if load_command.cmd == MachoLoadCommands.LC_SYMTAB:
                symtab_bytes = self.get_bytes(offset, sizeof(MachoSymtabCommand))
                self.symtab = MachoSymtabCommand.from_buffer(bytearray(symtab_bytes))

            elif load_command.cmd == MachoLoadCommands.LC_DYSYMTAB:
                dysymtab_bytes = self.get_bytes(offset, sizeof(MachoDysymtabCommand))
                self.dysymtab = MachoDysymtabCommand.from_buffer(bytearray(dysymtab_bytes))

            elif load_command.cmd == MachoLoadCommands.LC_ENCRYPTION_INFO_64:
                encryption_info_bytes = self.get_bytes(offset, sizeof(MachoEncryptionInfo64Command))
                self.encryption_info = MachoEncryptionInfo64Command.from_buffer(bytearray(encryption_info_bytes))

            elif load_command.cmd == MachoLoadCommands.LC_SEGMENT_64:
                segment_bytes = self.get_bytes(offset, sizeof(MachoSegmentCommand64))
                segment = MachoSegmentCommand64.from_buffer(bytearray(segment_bytes))
                # TODO(pt) handle byte swap of segment
                self.segments[segment.segname] = segment
                self.parse_sections(segment, offset)

            # move to next load command in header
            offset += load_command.cmdsize

    def parse_sections(self, segment, segment_offset):
        # type: (MachoSegmentCommand64, int) -> None
        """
        Parse all sections contained within a Mach-O segment,
        and add them to our map of sections
        Args:
            segment: The segment command whose sections should be read
            segment_offset: The offset within the file that the segment command is located at
        """
        if not segment.nsects:
            return

        # the first section of this segment begins directly after the segment
        section_offset = segment_offset + sizeof(MachoSegmentCommand64)
        section_size = sizeof(MachoSection64)

        for i in range(segment.nsects):
            section_bytes = self.get_bytes(section_offset, sizeof(MachoSection64))
            section = MachoSection64.from_buffer(bytearray(section_bytes))
            # TODO(pt) handle byte swap of segment
            # add to our section with the section name as the key
            self.sections[section.sectname] = section

            section_offset += section_size

    def get_section_with_name(self, name):
        # type: (str) -> Optional[MachoSection64]
        """
        Convenience method to retrieve a section with a given name from map
        Args:
            name: The name of the section to find
        Returns:
            The MachoSection64 command if it is found, None otherwise
        """
        if name in self.sections:
            return self.sections[name]
        return None

    def get_section_content(self, section):
        # type: (MachoSection64) -> bytearray
        """
        Convenience method to retrieve slice content associated with a section command
        Args:
            section: The section command whose corresponding content should be found
        Returns:
            bytearray containing the file contents associated with the section command
        """
        return bytearray(self.get_bytes(section.offset, section.size))

    def get_virtual_base(self):
        # type: () -> int
        """
        Retrieve the first virtual address of the Mach-O slice
        Returns:
            int containing the virtual memory space address that the Mach-O slice requests to begin at
        """
        text_seg = self.segments['__TEXT']
        return text_seg.vmaddr

    def get_bytes(self, offset, size):
        # type: (int, int) -> str
        """
        Retrieve bytes from Mach-O slice, taking into account that the slice could be at an offset within a FAT
        Args:
            offset: index from beginning of slice to retrieve data from
            size: maximum number of bytes to read

        Returns:
            string containing byte content of mach-o slice at an offset from the start of the slice
        """
        # ensure file is open
        self._file = open(self._file.name)
        # account for the fact that this Macho slice is not necessarily the start of the file!
        # add slide to our macho slice to file seek
        self._file.seek(offset + self.offset_within_fat)
        content = self._file.read(size)

        # now that we've read our data, close file again
        self._file.close()
        return content

    def should_swap_bytes(self):
        # type: () -> bool
        """
        Check whether self.magic refers to a big-endian Mach-O binary
        Returns:
            True if self.magic indicates a big endian Mach-O, False otherwise
        """
        # TODO(pt): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
        big_endian = [MachArch.MH_CIGAM,
                      MachArch.MH_CIGAM_64,
                      ]
        return self.magic in big_endian

    def get_raw_string_table(self):
        # type: () -> List[int]
        """
        Read string table from binary, as described by LC_SYMTAB. Each strtab entry is terminated
        by a NULL character.
        Returns:
            Raw, packed array of characters containing binary's string table data
        """
        string_table_data = self.get_bytes(self.symtab.stroff, self.symtab.strsize)
        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(string_table_data)
        return string_table

    @memoized
    def get_symtab_contents(self):
        # type: () -> List[MachoNlist64]
        """
        Parse symbol table containing list of Nlist64's
        Returns:
            Array of Nlist64's representing binary's symbol table
        """
        symtab = []
        # start reading from symoff and increment by one Nlist64 each iteration
        symoff = self.symtab.symoff
        for i in range(self.symtab.nsyms):
            nlist_data = self.get_bytes(symoff, sizeof(MachoNlist64))
            nlist = MachoNlist64.from_buffer(bytearray(nlist_data))
            symtab.append(nlist)
            # go to next Nlist in file
            symoff += sizeof(MachoNlist64)

        return symtab

    @memoized
    def string_table_index_info_table(self):
        # preprocess string table to ensure loops run in O(n) instead of O(n^2)
        # maintain an array of MachoStringTableEntry's which is the same size as the string table array.
        # so for each index in the string table's array of characters,
        # have an entry in another table which contains a copy of a MachoStringTableEntry describing the string
        # corresponding to that string table entry
        # this way, we can find the symbol name for a given string table index without having to search for a null-
        # character inside another loop.
        string_table_index_info_table = []
        current_str_start_idx = 0
        strtab = self.get_raw_string_table()
        for idx, ch in enumerate(strtab):
            if ch == '\x00':
                length = idx - current_str_start_idx

                # record in list
                ent = (current_str_start_idx, length)
                # max to ensure there's at least 1 entry in list, even if this string entry is just a null char
                # also, add 1 entry for null character
                count_to_include = max(1, length + 1)
                for j in range(count_to_include):
                    string_table_index_info_table.append(ent)

                # move to starting index of next string
                current_str_start_idx = idx + 1
        return string_table_index_info_table

    def parse_imported_symbols(self):
        # type: () -> List[Text]
        """
        Convert packed string table into a list of NULL-terminated strings
        Returns:
            List of strings representing symbols in binary's string table
        """
        strtab = self.get_raw_string_table()
        symtab = self.get_symtab_contents()
        string_table_indexes = self.string_table_index_info_table()
        symbols = []
        for sym in symtab:
            strtab_idx = sym.n_un.n_strx

            # string table is an array of characters
            # these characters represent symbol names,
            # with a null character delimiting each symbol name
            # find the string corresponding to this index
            # use string index table to avoid any array searching within this loop
            start_idx, length = string_table_indexes[strtab_idx]
            end_idx = start_idx + length
            symbol_str_characters = strtab[start_idx:end_idx:]
            symbol_str = ''.join(symbol_str_characters)

            symbols.append(symbol_str)
        return symbols

    def get_external_sym_pointers(self):
        # type: () -> List[int]
        """
        Parse lazy symbol section into a list of pointers
        The lazy symbol section contains dummy pointers to known locations, which dyld_stub_binder will
        rewrite into their real runtime addresses when the dylibs are loaded.
        * IMPORTANT *
        This method actually records the _virtual address where the destination pointer is recorded_, not the value
        of the garbage pointer.
        This is because the actual content of these pointers is useless until runtime (since they point to nonexistent
        data), but their ordering in the lazy symbol table is the same as described in other symbol tables, so
        we need the index
        Returns:
            A list of pointers containing the virtual addresses of each pointer in this section
        """
        section = self.get_section_with_name('__la_symbol_ptr')
        # __la_symbol_ptr is just an array of pointers
        # the number of pointers is the size, in bytes, of the section, divided by a 64b pointer size
        sym_ptr_count = section.size / sizeof(c_void_p)

        section_pointers = []
        # this section's data starts at the file offset field
        section_data_ptr = section.offset

        # read every pointer in the table
        for i in range(sym_ptr_count):
            # this addr is the address in the file of this data, plus the slide that the file has requested,
            # to result in the final address that would be referenced elsewhere in this Mach-O
            section_pointers.append(self.get_virtual_base() +  section_data_ptr)
            # go to next pointer in list
            section_data_ptr += sizeof(c_void_p)
        return section_pointers

    def get_indirect_symbol_table(self):
        # type: () -> List[c_uint32_t]
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

    def get_content_from_virtual_address(self, virtual_address, size):
        binary_address = virtual_address - self.get_virtual_base()
        return self.get_bytes(binary_address, size)

    def parse_selrefs(self):
        methname_header = self.get_section_with_name('__objc_methname')
        selref_header = self.get_section_with_name('__objc_selrefs')

        print('methname header {}'.format(methname_header))
        print('selref header {}'.format(selref_header))

        methname = self.get_section_content(methname_header)
        selref = self.get_section_content(selref_header)
        print('len methname content {}'.format(hex(len(methname))))
        print('len selref content {}'.format(hex(len(selref))))

        # methname section data is essentially a packed character array of selector names
        # the order of selector string literals within this array is the same as the order of selrefs
        # in the __objc_selrefs section
        # thus, we can map __objc_methname string literals directly to pointers in __objc_selrefs,
        # because the order in each is the same

        # read methname into list of full strings
        selector_names = []
        str_start_idx = 0
        for idx, ch in enumerate(methname):
            if chr(ch) == '\x00':
                # end of this string
                # read entire string into selector_names
                sel_name = str(methname[str_start_idx:idx])
                selector_names.append(sel_name)
                # next string will start at the byte after this one
                str_start_idx = idx + 1

        # read selref into list of pointers
        selrefs_size = selref_header.size / sizeof(c_uint64)
        selref_ptrs = []
        selref_off = 0
        for i in range(selrefs_size):
            selref_entry_end = selref_off + sizeof(c_uint64)
            selref_entry = c_uint64.from_buffer(bytearray(selref[selref_off:selref_entry_end])).value
            selref_ptrs.append(selref_entry)
            selref_off += sizeof(c_uint64)

        self.selref_map = {}
        for name, ptr in zip(selector_names, selref_ptrs):
            self.selref_map[ptr] = name
        for k,v in self.selref_map.iteritems():
            print('{}: {}'.format(
                hex(int(k)),
                v,
            ))
        return self.selref_map

    def crossref_classlist(self):
        classlist_entries = []
        for idx, ent in enumerate(self.classlist):
            file_ptr = ent - self.get_virtual_base()
            raw_struct_data = self.get_bytes(file_ptr, sizeof(ObjcClass))
            class_entry = ObjcClass.from_buffer(bytearray(raw_struct_data))
            classlist_entries.append(class_entry)
#            print('ObjcClass metaclass {} super {} cache {} vtable {} data {}'.format(
#                hex((class_entry.metaclass)),
#                hex((class_entry.superclass)),
#                hex((class_entry.cache)),
#                hex((class_entry.vtable)),
#                hex((class_entry.data)),
#            ))
        self.parse_classlist_entries(classlist_entries)

    def parse_classlist_entries(self, classlist_entries):
        # type: (List[ObjcClass]) -> None
        objc_data_entries = []
        for i, class_ent in enumerate(classlist_entries):
            data_file_ptr = class_ent.data - self.get_virtual_base()
            raw_struct_data = self.get_bytes(data_file_ptr, sizeof(ObjcData))
            data_entry = ObjcData.from_buffer(bytearray(raw_struct_data))
            objc_data_entries.append(data_entry)
        self.parse_objc_data_entries(objc_data_entries)

    def parse_objc_data_entries(self, objc_data_entries):
        # type: (List[ObjcData]) -> None
        for ent in objc_data_entries:
            methlist_file_ptr = ent.base_methods - self.get_virtual_base()
            raw_struct_data = self.get_bytes(methlist_file_ptr, sizeof(ObjcMethodList))
            methlist = ObjcMethodList.from_buffer(bytearray(raw_struct_data))

            # parse every entry in method list
            method_entry_off = methlist_file_ptr + sizeof(ObjcMethodList)
            for i in range(methlist.methcount):
                raw_struct_data = self.get_bytes(method_entry_off, sizeof(ObjcMethod))
                method_ent = ObjcMethod.from_buffer(bytearray(raw_struct_data))
                print('got method entry w sel {} imp {}'.format(hex(int(method_ent.name)), hex(int(method_ent.implementation))))
                method_entry_off += sizeof(ObjcMethod)

    def parse_classlist(self):
        classlist_cmd = self.get_section_with_name('__objc_classlist')
        classlist_data = self.get_section_content(classlist_cmd)
        classlist_size = len(classlist_data) / sizeof(c_uint64)
        classlist_off = 0
        classlist = []
        for i in range(classlist_size):
            data_end = classlist_off + sizeof(c_uint64)
            val = c_uint64.from_buffer(classlist_data[classlist_off:data_end]).value
            classlist.append(val)
            classlist_off += sizeof(c_uint64)

        self.classlist = classlist
        self.crossref_classlist()
        return classlist

