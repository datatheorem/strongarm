from ctypes import c_uint64, sizeof, c_void_p

from capstone import *
from typing import Text, List, Dict, Optional

from strongarm.debug_util import DebugUtil
from strongarm.decorators import memoized
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.macho_definitions import ObjcClass, ObjcMethod, ObjcMethodList, ObjcData
from macho_string_table_helper import MachoStringTableHelper


class MachoAnalyzer(object):
    # keep map of active MachoAnalyzer instances
    # each MachoAnalyzer operates on a single MachoBinary which will never change in the lifecycle of the analyzer
    # also, some MachoAnalyzer operations are expensive, but they only have to be done once per instance
    # so, we only keep one analyzer for each MachoBinary
    active_analyzer_map = {}

    def __init__(self, bin):
        # type: (MachoBinary) -> None
        self.binary = bin
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        self._selrefs = None
        self.selector_names_to_imps = None
        self._selector_name_pointers_to_imps = None

        self._contains_objc = False

        self.crossref_helper = MachoStringTableHelper(bin)
        self.imported_symbols = self.crossref_helper.imported_symbols
        self.exported_symbols = self.crossref_helper.exported_symbols

        self.imp_stubs = MachoImpStubsParser(bin, self.cs).imp_stubs

        self.parse_static_objc_runtime_info()

        if self._contains_objc:
            self._create_selref_to_name_map()

        # done setting up, store this analyzer in class cache
        MachoAnalyzer.active_analyzer_map[bin] = self

    @classmethod
    def get_analyzer(cls, bin):
        # type: (MachoBinary) -> MachoAnalyzer
        """Get a cached analyzer for a given MachoBinary
        """
        if bin in cls.active_analyzer_map:
            # use cached analyzer for this binary
            return cls.active_analyzer_map[bin]
        return MachoAnalyzer(bin)

    @memoized
    def _parse_la_symbol_ptr_list(self):
        # type: () -> List[int]
        """Parse lazy symbol section into a list of pointers
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
        section_pointers = []
        if '__la_symbol_ptr' not in self.binary.sections:
            return section_pointers

        lazy_sym_section = self.binary.sections['__la_symbol_ptr']
        # __la_symbol_ptr is just an array of pointers
        # the number of pointers is the size, in bytes, of the section, divided by a 64b pointer size
        sym_ptr_count = lazy_sym_section.cmd.size / sizeof(c_void_p)

        # this section's data starts at the file offset field
        section_data_ptr = lazy_sym_section.cmd.offset

        virt_base = self.binary.get_virtual_base()
        # read every pointer in the table
        for i in range(sym_ptr_count):
            # this addr is the address in the file of this data, plus the slide that the file has requested,
            # to result in the final address that would be referenced elsewhere in this Mach-O
            section_pointers.append(virt_base + section_data_ptr)
            # go to next pointer in list
            section_data_ptr += sizeof(c_void_p)
        return section_pointers

    @property
    @memoized
    def _la_symbol_ptr_to_symbol_name_map(self):
        # type: () -> Dict[int, Text]
        """Cross-reference Mach-O sections to produce __la_symbol_ptr pointers -> external symbol name map.
        
        This map will only contain entries for symbols that are defined outside the main binary.
        This method cross references data in __la_symbol_ptr, the indirect symbol table

        The map created by this method DOES NOT correspond to the addresses used by branch destinations.
        Branch destinations will actually point to entries in __imp_stubs. This is a helper function for a method
        to map __imp_stubs entries to symbol names

        Returns:
            Map of __la_symbol_ptr pointers to the strings corresponding to the name of each symbol
        """
        imported_symbol_map = {}
        if '__la_symbol_ptr' not in self.binary.sections:
            return imported_symbol_map

        # the reserved1 field of the lazy symbol section header holds the starting index of this table's entries,
        # within the indirect symbol table
        # so, for any address in the lazy symbol, its translated address into the indirect symbol table is:
        # lazy_sym_section.reserved1 + index
        lazy_sym_offset_within_indirect_symtab = self.binary.sections['__la_symbol_ptr'].cmd.reserved1
        # this list contains the contents of __la_symbol_ptr
        external_symtab = self._parse_la_symbol_ptr_list()

        # indirect symbol table is a list of indexes into larger symbol table
        indirect_symtab = self.binary.get_indirect_symbol_table()

        symtab = self.binary.symtab_contents

        for (index, symbol_ptr) in enumerate(external_symtab):
            # as above, for an index idx in __la_symbol_ptr, the corresponding entry within the symbol table (from which
            # we can get the string name of this symbol) is given by the value in the indirect symbol table at index:
            # la_symbol_ptr_command.reserved1 + idx
            offset = indirect_symtab[lazy_sym_offset_within_indirect_symtab + index]
            sym = symtab[offset]

            # we now have the Nlist64 symbol for the __la_symbol_ptr entry
            # the starting index of the string within the string table for this symbol is given by the n_strx field
            strtab_idx = sym.n_un.n_strx

            symbol_name = self.crossref_helper.string_table_entry_for_strtab_index(strtab_idx).full_string
            # record this mapping of address to symbol name
            imported_symbol_map[symbol_ptr] = symbol_name
        return imported_symbol_map

    @property
    @memoized
    def external_branch_destinations_to_symbol_names(self):
        # type: () -> Dict[int, Text]
        """Return a Dict of addresses to the external symbols they correspond to
        """
        symbol_name_map = {}
        stubs = self.imp_stubs
        la_sym_ptr_name_map = self._la_symbol_ptr_to_symbol_name_map

        for stub in stubs:
            symbol_name = la_sym_ptr_name_map[stub.destination]
            symbol_name_map[stub.address] = symbol_name
        return symbol_name_map

    @property
    @memoized
    def external_symbol_names_to_branch_destinations(self):
        # type: () -> Dict[Text, int]
        """Return a Dict of external symbol names to the addresses they'll be called at
        """
        call_address_map = {}
        for key, value in self.external_branch_destinations_to_symbol_names.iteritems():
            call_address_map[value] = key
        return call_address_map

    def symbol_name_for_branch_destination(self, branch_address):
        # type: (int) -> Text
        """Get the associated symbol name for a given branch destination
        """
        if branch_address in self.external_branch_destinations_to_symbol_names:
            return self.external_branch_destinations_to_symbol_names[branch_address]
        raise RuntimeError('Unknown branch destination {}. Is this a local branch?'.format(
            hex(branch_address)
        ))

    def _find_function_boundary(self, start_address, size):
        # type: (int, int) -> int
        """Helper function to search for a function boundary within a given block of executable code

        This function searches from start_address up to start_address + size looking for a set of
        instructions resembling a function boundary. If a function boundary is identified its address will be returned,
        or else 0 will be returned if no boundary was found.
        """

        # get executable code in requested region
        func_str = self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size)

        # transform func_str into list of CsInstr
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]

        # this will be set to an address if we find one,
        # or will stay 0. If it remains 0 we know we didn't find the end of the function
        end_address = 0
        # flag to be used when we encounter an unconditional branch
        # if we encounter an unconditional branch and recently loaded the link register with a stored value,
        # it is exceedingly likely that the unconditional branch serves as the last statement in the function,
        # as after the branch the link register will contain whatever it was after loading it from the stack here,
        # and execution will jump back to the caller of this function
        next_branch_is_return = False
        # if a function makes no other calls to other subroutines
        # (and thus never modifies the link register),
        # then it's possible for the last instruction to be an unconditional branch,
        # without first loading the link register from the stack
        # this tracks whether the link register has been modified in the code block
        # if it has, then we know we can only be at the end of function if we've seen a
        # ldp ..., x30, ...
        has_modified_lr = False

        # traverse instructions, looking for signs of end-of-function
        for instr in instructions:
            # ret mnemonic is sure sign we've found end of the function!
            if instr.mnemonic == 'ret':
                end_address = instr.address
                break

            # slightly less strong heuristic
            # in the uncommon case that a function ends in a branch,
            # it *must* have moved something sane into the link register,
            # or else the program would jump to an unreasonable place after the branch.
            # The sole exception to this rule is if a function never modifies the link
            # register in the first place, which is tracked by has_modified_lr.
            # we could possibly strengthen the has_modified_lr check by also checking for this pattern:
            # in the prologue, stp ..., x30, [sp, #0x...]
            # then a corresponding ldp ..., x30, [sp, #0x...]
            elif instr.mnemonic == 'ldp':
                # are we restoring a value into link register?
                load_dst_1 = instr.reg_name(instr.operands[0].value.reg)
                load_dst_2 = instr.reg_name(instr.operands[1].value.reg)
                # link register on ARM64 is x30
                link_register = 'x30'
                if load_dst_1 == link_register or load_dst_2 == link_register:
                    next_branch_is_return = True

            # branch with link inherently modifies the link register,
            # which means the function *must* have stored link register at some point,
            # which means we can later use an ldp ..., x30 as a heuristic for function epilogue
            elif instr.mnemonic == 'bl':
                has_modified_lr = True
            elif instr.mnemonic == 'b':
                if next_branch_is_return or not has_modified_lr:
                    end_address = instr.address
                    break

        # long to int
        end_address = int(end_address)
        return end_address

    def get_function_address_range(self, function_address):
        """Retrieve the address range of executable function beginning at function_address

        The return value will be a tuple containing the start and end addresses of executable code belonging
        to the function starting at address function_address
        """

        # get_content_from_virtual_address wants a size for how much data to grab,
        # but we don't actually know how big the function is!
        # start off by grabbing 256 bytes, and keep doubling search area until we encounter the
        # function boundary.
        end_address = 0
        search_size = 0x100
        while not end_address:
            end_address = self._find_function_boundary(function_address, search_size)
            # double search space
            search_size *= 2

        return function_address, end_address

    def get_function_instructions(self, start_address):
        # type: (int) -> List[CsInsn]
        """Get a list of disassembled instructions for the function beginning at start_address
        """
        _, end_address = self.get_function_address_range(start_address)
        if not end_address:
            raise RuntimeError('Couldn\'t parse function @ {}'.format(start_address))
        function_size = end_address - start_address

        func_str = self.binary.get_bytes(start_address - self.binary.get_virtual_base(), function_size)
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        return instructions

    def _get_classlist_entries(self):
        # type: () -> List[int]
        """Read pointers in __objc_classlist into list
        """
        classlist_entries = []
        if '__objc_classlist' not in self.binary.sections:
            return classlist_entries

        classlist_data = self.binary.sections['__objc_classlist'].content
        classlist_size = len(classlist_data) / sizeof(c_uint64)

        classlist_off = 0
        for i in range(classlist_size):
            data_end = classlist_off + sizeof(c_uint64)
            val = c_uint64.from_buffer(bytearray(classlist_data[classlist_off:data_end])).value
            classlist_entries.append(val)
            classlist_off += sizeof(c_uint64)
        return classlist_entries

    def _get_objc_class_from_classlist_pointer(self, entry_location):
        # type: (int) -> ObjcClass
        """Read a struct __objc_class from the virtual address of the pointer
        Typically, this pointer will come from an entry in __objc_classlist
        """
        file_ptr = entry_location - self.binary.get_virtual_base()
        raw_struct_data = self.binary.get_bytes(file_ptr, sizeof(ObjcClass))
        class_entry = ObjcClass.from_buffer(bytearray(raw_struct_data))

        # sanitize class_entry
        # it seems for Swift classes,
        # the compiler will add 1 to the data field
        # TODO(pt) detecting this can be a heuristic for finding Swift classes!
        # mod data field to a byte size
        overlap = class_entry.data % 0x8
        class_entry.data -= overlap
        return class_entry

    def _get_objc_data_from_objc_class(self, objc_class):
        # type: (ObjcClass) -> Optional[ObjcData]
        """Read a struct __objc_data from a provided struct __objc_class
        If the struct __objc_class describe invalid or no corresponding data, None will be returned.
        """
        data_file_ptr = objc_class.data - self.binary.get_virtual_base()
        raw_struct_data = self.binary.get_bytes(data_file_ptr, sizeof(ObjcData))
        data_entry = ObjcData.from_buffer(bytearray(raw_struct_data))
        # ensure this is a valid entry
        if data_entry.name < self.binary.get_virtual_base():
            DebugUtil.log(self, 'caught ObjcData struct with invalid fields at {}'.format(
                hex(int(data_file_ptr + self.binary.get_virtual_base()))
            ))
            return None
        return data_entry

    def parse_static_objc_runtime_info(self):
        # type: () -> None
        """Read Objective-C class data in __objc_classlist, __objc_data to get classes and selectors in binary
        """
        classlist_pointers = self._get_classlist_entries()
        # if the classlist had no entries, there's no Objective-C data in this binary
        # in this case, the binary must be implemented purely in C or Swift
        if not len(classlist_pointers):
            self._contains_objc = False
            return
        self._contains_objc = True

        # read actual list of ObjcClass structs from list of pointers
        objc_classes = []
        for class_ptr in classlist_pointers:
            objc_classes.append(self._get_objc_class_from_classlist_pointer(class_ptr))

        # TODO(PT): use ObjcClass objects in objc_classes to create list of classes in binary
        # we could even make a list of all selectors for a given class
        # and, when requesting an IMP for a selector, we could request the class too (for SEL collisions)

        # read data for each class
        objc_data_entries = []
        for class_ent in objc_classes:
            objc_data_entries.append(self._get_objc_data_from_objc_class(class_ent))
        self._parse_objc_data_entries(objc_data_entries)

    def _get_methlist_from_objc_data(self, data_struct):
        # type: (ObjcData) -> Optional[(ObjcMethodList, int)]
        """Return the ObjcMethodList and file offset described by the provided ObjcData struct
        Some __objc_data entries will describe classes that have no methods implemented. In this case, the method
        list will not exist, and this method will return None.
        If the method list does exist, a tuple of the ObjcMethodList and the file offset where the entry is located
        will be returned

        Args:
            data_struct: The struct __objc_data whose method list entry should be read

        Returns:
            A tuple of the data's ObjcMethodList and the file pointer to this method list structure.
            If the data has no methods, None will be returned.
        """
        # does this data entry describe any methods?
        if data_struct.base_methods == 0:
            return None

        methlist_file_ptr = data_struct.base_methods - self.binary.get_virtual_base()
        raw_struct_data = self.binary.get_bytes(methlist_file_ptr, sizeof(ObjcMethodList))
        methlist = ObjcMethodList.from_buffer(bytearray(raw_struct_data))
        return (methlist, methlist_file_ptr)

    def _get_full_string_from_start_address(self, start_address):
        # type: (int) -> Text
        """Return a string containing the bytes from start_address up to the next NULL character
        """
        max_len = 128
        symbol_name_characters = []
        found_null_terminator = False

        while not found_null_terminator:
            name_len = 0
            name_bytes = self.binary.get_content_from_virtual_address(virtual_address=start_address, size=max_len)
            # search for null terminator in this content
            for ch in name_bytes:
                if ch == '\x00':
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
                symbol_name = ''.join(symbol_name_characters)
                return symbol_name

    def _get_sel_name_imp_pairs_from_methlist(self, methlist, methlist_file_ptr):
        # type: (ObjcMethodList, int) -> List[(Text, int, int)]
        """Given a method list, return a List of tuples of selector name, selref, and IMP address for each method
        """
        methods_data = []
        # parse every entry in method list
        # the first entry appears directly after the ObjcMethodList structure
        method_entry_off = methlist_file_ptr + sizeof(ObjcMethodList)
        for i in range(methlist.methcount):
            raw_struct_data = self.binary.get_bytes(method_entry_off, sizeof(ObjcMethod))
            method_ent = ObjcMethod.from_buffer(bytearray(raw_struct_data))

            # TODO(PT): preprocess __objc_methname so we don't have to search for null byte for every string here
            symbol_name = self._get_full_string_from_start_address(method_ent.name)
            methods_data.append((symbol_name, method_ent.name, method_ent.implementation))

            method_entry_off += sizeof(ObjcMethod)
        return methods_data

    def _parse_objc_data_entries(self, objc_data_entries):
        # type: (List[ObjcData]) -> None
        """For each ObjcData, find the selector name, selref, and IMP address, and record in instance maps
        """

        self.selector_names_to_imps = {}
        self._selector_name_pointers_to_imps = {}

        for ent in objc_data_entries:
            methlist_info = self._get_methlist_from_objc_data(ent)
            if not methlist_info:
                continue
            methlist = methlist_info[0]
            methlist_file_ptr = methlist_info[1]

            methods_in_methlist = self._get_sel_name_imp_pairs_from_methlist(methlist, methlist_file_ptr)
            for selector_name, selref, imp in methods_in_methlist:
                self._selector_name_pointers_to_imps[selref] = imp

                # if this is the first instance of this selector name we've seen,
                # map it to an array just containing the IMP address
                if selector_name not in self.selector_names_to_imps:
                    self.selector_names_to_imps[selector_name] = [imp]
                # if we've already recorded an IMP for this sel name, just add the new one to the list
                else:
                    self.selector_names_to_imps[selector_name].append(imp)

    def _create_selref_to_name_map(self):
        self._selrefs = {}
        self._selref_ptr_to_imp_map = {}

        if '__objc_selrefs' not in self.binary.sections:
            return

        selref_sect = self.binary.sections['__objc_selrefs']
        entry_count = selref_sect.cmd.size / sizeof(c_uint64)

        for i in range(entry_count):
            content_off = i * sizeof(c_uint64)
            selref_val_data = selref_sect.content[content_off:content_off + sizeof(c_uint64)]
            selref_val = c_uint64.from_buffer(bytearray(selref_val_data)).value
            virt_location = content_off + selref_sect.cmd.addr
            self._selrefs[virt_location] = selref_val

        # we now have an array of tuples of (selref ptr, string literal ptr)
        # self._selector_name_pointers_to_imps contains a map of {string literal ptr, IMP}
        # create mapping from selref ptr to IMP
        for selref_ptr, string_ptr in self._selrefs.items():
            try:
                imp_ptr = self._selector_name_pointers_to_imps[string_ptr]
            except KeyError as e:
                # if this selref had no IMP, it must be a selector for a method defined outside this binary
                # we don't mind, just continue
                continue
            self._selref_ptr_to_imp_map[selref_ptr] = imp_ptr

    def imp_for_selref(self, selref_ptr):
        if not selref_ptr:
            return None
        try:
            return self._selref_ptr_to_imp_map[selref_ptr]
        except KeyError as e:
            # if we have a selector reference entry for this pointer but no IMP,
            # it must be a selector for a class defined outside this binary
            if selref_ptr in self._selrefs:
                return None
            # if we had no record of this selref, it's an invalid pointer and an exception should be raised
            raise RuntimeError('invalid selector reference pointer {}'.format(hex(int(selref_ptr))))

    def get_method_imp_addresses(self, selector):
        # type: (Text) -> List[int]
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        if not self.selector_names_to_imps:
            return []
        if selector not in self.selector_names_to_imps:
            return []
        return self.selector_names_to_imps[selector]

    def get_method_address_ranges(self, selector):
        # type: (Text) -> List[(int, int)]
        """Retrieve a list of addresses where the provided SEL is implemented

        If no implementations exist for the provided selector, an empty list will be returned.
        If implementations exist, the list will contain tuples in the form: (IMP start address, IMP end address)
        """
        ranges_list = []
        start_addresses = self.get_method_imp_addresses(selector)
        if not start_addresses:
            # get_method_imp_address failed, selector might not exist
            # return empty list
            return ranges_list

        for idx, start_address in enumerate(start_addresses):
            end_address = self.get_function_address_range(start_address)
            # get_content_from_virtual_address wants a size for how much data to grab,
            # but we don't actually know how big the function is!
            # start off by grabbing 256 bytes, and keep doubling search area until we encounter the
            # function boundary.
            end_address = 0
            search_size = 0x100
            while not end_address:
                end_address = self._find_function_boundary(start_address, search_size)
                # double search space
                search_size *= 2

            ranges_list.append((start_address, end_address))
        return ranges_list

    def get_implementations(self, selector):
        # type: (Text) -> List[List[CsInsn]]
        """Retrieve a list of the disassembled function data for every implementation of a provided selector
        Args:
            selector: The selector name who's implementations should be found

        Returns:
            A list of lists containing CsInsn objects. Each entry in the outer list represents an implementation of
            the selector, suitable for being passed to an ObjcFunctionAnalyzer constructor
        """
        implementations = []
        imp_addresses = self.get_method_address_ranges(selector)
        for imp_start, imp_end in imp_addresses:
            imp_size = imp_end - imp_start
            imp_data = self.binary.get_content_from_virtual_address(virtual_address=imp_start, size=imp_size)
            imp_instructions = [instr for instr in self.cs.disasm(imp_data, imp_start)]
            implementations.append(imp_instructions)
        return implementations
