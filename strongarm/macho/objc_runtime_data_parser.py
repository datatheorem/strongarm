# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from typing import List, Optional, Text, Dict, Tuple, AnyStr
from ctypes import sizeof
import logging

from strongarm.macho.arch_independent_structs import \
    ObjcClassRawStruct, \
    ObjcDataRawStruct, \
    ObjcMethodStruct, \
    ObjcMethodListStruct, \
    DylibCommandStruct
from strongarm.debug_util import DebugUtil
from strongarm.macho.macho_binary import MachoBinary


class ObjcClass(object):
    __slots__ = ['name', 'selectors']

    def __init__(self, name, selectors):
        # type: (Text, List[ObjcSelector]) -> None
        self.name = name
        self.selectors = selectors


class ObjcSelector(object):
    __slots__ = ['name', 'selref', 'implementation', 'is_external_definition']

    def __init__(self, name, selref, implementation):
        # type: (Text, ObjcSelref, Optional[int]) -> None
        self.name = name
        self.selref = selref
        self.implementation = implementation

        self.is_external_definition = (not self.implementation)

    def __str__(self):  # type: ignore
        imp_addr = 'NaN'
        if self.implementation:
            imp_addr = hex(int(self.implementation))
        return '<@selector({}) at {}>'.format(self.name, imp_addr)
    __repr__ = __str__


class ObjcSelref(object):
    __slots__ = ['source_address', 'destination_address', 'selector_literal']

    def __init__(self, source_address, destination_address, selector_literal):
        # type: (int, int, Text) -> None
        self.source_address = source_address
        self.destination_address = destination_address
        self.selector_literal = selector_literal


class ObjcDataEntryParser(object):
    """Class encapsulating logic to retrieve a list of selectors from a struct __objc_data
    """

    def __init__(self, binary, selref_list, objc_data_raw_struct):
        # type: (MachoBinary, List[ObjcSelref], ObjcDataRawStruct) -> None
        self._binary = binary
        self._selrefs = selref_list
        self._objc_data_raw_struct = objc_data_raw_struct

        # make map of selref pointers to the ObjcSelref objects
        # this is so we can find the selref object for a selref pointer in constant time when
        # parsing objc selectors in _get_selectors_from_methlist()
        self._selref_pointer_map = {}   # type: Dict[int, ObjcSelref]
        for selref in self._selrefs:
            self._selref_pointer_map[selref.destination_address] = selref

    def get_selectors(self):
        # type: () -> List[ObjcSelector]
        """Parse every ObjcSelector described by the struct __objc_data
        """
        methlist_info = self._get_methlist()
        if not methlist_info:
            return []
        methlist = methlist_info[0]
        methlist_file_ptr = methlist_info[1]

        return self._get_selectors_from_methlist(methlist, methlist_file_ptr)

    def get_selref_for_objc_method(self, objc_method):
        # type: (ObjcMethodStruct) -> Optional[ObjcSelref]
        """Retrieve the selref whose destination address points to the name field of the provided ObjcMethodStruct
        """
        name_ptr = objc_method.name
        if name_ptr not in self._selref_pointer_map:
            return None
        return self._selref_pointer_map[name_ptr]

    def _get_selectors_from_methlist(self, methlist, methlist_file_ptr):
        # type: (ObjcMethodListStruct, int) -> List[ObjcSelector]
        """Given a method list, return a List of ObjcSelectors encapsulating each method
        """
        selectors = []
        # parse every entry in method list
        # the first entry appears directly after the ObjcMethodListStruct
        method_entry_off = methlist_file_ptr + methlist.sizeof
        for i in range(methlist.methcount):
            method_ent = ObjcMethodStruct(self._binary, method_entry_off)
            # byte-align IMP
            method_ent.implementation &= ~0x3

            symbol_name = self._binary.get_full_string_from_start_address(method_ent.name)
            selref = self.get_selref_for_objc_method(method_ent)

            selector = ObjcSelector(symbol_name, selref, method_ent.implementation)
            selectors.append(selector)

            method_entry_off += method_ent.sizeof
        return selectors

    def _get_methlist(self):
        # type: () -> Optional[Tuple[ObjcMethodListStruct, int]]
        """Return the ObjcMethodList and file offset described by the ObjcDataRawStruct
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
        # does the data entry describe any methods?
        if self._objc_data_raw_struct.base_methods == 0:
            return None

        methlist_file_ptr = self._binary.file_offset_for_virtual_address(self._objc_data_raw_struct.base_methods)
        methlist = ObjcMethodListStruct(self._binary, methlist_file_ptr)
        return (methlist, methlist_file_ptr)


class ObjcRuntimeDataParser(object):
    def __init__(self, binary):
        # type: (MachoBinary) -> None
        self.binary = binary
        DebugUtil.log(self, 'Parsing ObjC runtime info... (this may take a while)')
        DebugUtil.log(self, 'Step 1: Parsing selrefs...')
        self._selrefs = self._parse_selrefs()
        DebugUtil.log(self, 'Step 2: Parsing classes...')
        self.classes = self._parse_static_objc_runtime_info()

        DebugUtil.log(self, 'Step 3: Resolving symbol name to source dylib map...')
        self._sym_to_dylib_path = self._parse_linked_dylib_symbols()

    def _parse_linked_dylib_symbols(self):
        # type: () -> Dict[Text, Text]
        syms_to_dylib_path = {}

        symtab = self.binary.symtab
        symtab_contents = self.binary.symtab_contents
        dysymtab = self.binary.dysymtab
        for undef_sym_idx in range(dysymtab.nundefsym):
            symtab_idx = dysymtab.iundefsym + undef_sym_idx
            sym = symtab_contents[symtab_idx]

            strtab_idx = sym.n_un.n_strx
            string_file_address = symtab.stroff + strtab_idx
            symbol_name = self.binary.get_full_string_from_start_address(string_file_address, virtual=False)

            library_ordinal = self._library_ordinal_from_n_desc(sym.n_desc)
            source_dylib = self._dylib_from_library_ordinal(library_ordinal)
            if source_dylib:
                source_name_addr = source_dylib.fileoff + \
                                   source_dylib.dylib.name.offset + \
                                   self.binary.get_virtual_base()
                source_name = self.binary.get_full_string_from_start_address(source_name_addr)
            else:
                # we have encountered binaries where the n_desc indicates a nonexistent library ordinal
                # Netflix.app/frameworks/widevine_cdm_sdk_oemcrypto_release.framework/widevine_cdm_sdk_oemcrypto_release
                # indicates an ordinal 254, when the binary only actually has 8 LC_LOAD_DYLIB commands.
                # if we encounter a buggy binary like this, just use a placeholder name
                source_name = '<unknown dylib>'

            syms_to_dylib_path[symbol_name] = source_name
        return syms_to_dylib_path

    def path_for_external_symbol(self, symbol):
        # type: (Text) -> Optional[Text]
        if symbol in self._sym_to_dylib_path:
            return self._sym_to_dylib_path[symbol]
        return None

    @staticmethod
    def _library_ordinal_from_n_desc(n_desc):
        # type: (int) -> int
        return (n_desc >> 8) & 0xff

    def _dylib_from_library_ordinal(self, ordinal):
        # type: (int) -> Optional[DylibCommandStruct]
        # ordinals start from 1, so translate to an array index
        ordinal_idx = ordinal - 1
        if ordinal_idx >= len(self.binary.load_dylib_commands):
            return None
        return self.binary.load_dylib_commands[ordinal_idx]

    def log_long_parse(self, selref_count):
        # type: (int) -> None
        if selref_count < 1000:
            return
        # found through observation
        seconds_per_selref_estimate = 0.0015
        seconds_estimate = selref_count * seconds_per_selref_estimate
        minutes_estimate = seconds_estimate / 60.0
        if minutes_estimate < 0.5:
            return
        logging.warning('strongarm: Large ObjC info section! Estimate: {} minutes'.format(minutes_estimate))

    def _parse_selrefs(self):
        # type: () -> List[ObjcSelref]
        selrefs = []    # type: List[ObjcSelref]
        if '__objc_selrefs' not in self.binary.sections:
            return selrefs

        selref_sect = self.binary.sections['__objc_selrefs']

        binary_word = self.binary.platform_word_type
        entry_count = int(selref_sect.cmd.size / sizeof(binary_word))
        self.log_long_parse(entry_count)
        for i in range(entry_count):
            selref_addr = selref_sect.address + (i * sizeof(binary_word))
            selref_val_bytes = self.binary.get_content_from_virtual_address(selref_addr, sizeof(binary_word))
            selref_val = binary_word.from_buffer(selref_val_bytes).value

            # read selector string literal from selref pointer
            selref_contents = self.binary.get_full_string_from_start_address(selref_val)
            selrefs.append(ObjcSelref(selref_addr, selref_val, selref_contents))
        return selrefs

    def selector_for_selref(self, selref_addr):
        # type: (int) -> Optional[ObjcSelector]
        for objc_class in self.classes:
            for sel in objc_class.selectors:
                if not sel.selref:
                    continue
                if sel.selref.source_address == selref_addr:
                    return sel
        # selref wasn't referenced in classes implemented within the binary
        # make sure it's a valid selref
        selref = [x for x in self._selrefs if x.source_address == selref_addr]
        if not len(selref):
            return None
        _selref = selref[0]

        # therefore, the _selref must refer to a selector which is defined outside this binary
        # this is fine, just construct an ObjcSelector with what we know
        sel = ObjcSelector(_selref.selector_literal, _selref, None)
        return sel

    def get_method_imp_addresses(self, selector):
        # type: (Text) -> List[int]
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        imp_addresses = []
        for objc_class in self.classes:
            for objc_sel in objc_class.selectors:
                if objc_sel.name == selector:
                    imp_addresses.append(objc_sel.implementation)
        return imp_addresses

    def _parse_objc_classes(self):
        # type: () -> List[ObjcClass]
        """Read Objective-C class data in __objc_classlist, __objc_data to get classes and selectors in binary
        """
        DebugUtil.log(self, 'Cross-referencing __objc_classlist, __objc_class, and __objc_data entries...')
        parsed_objc_classes = []
        classlist_pointers = self._get_classlist_pointers()
        for ptr in classlist_pointers:
            objc_class = self._get_objc_class_from_classlist_pointer(ptr)
            if objc_class:
                objc_data_struct = self._get_objc_data_from_objc_class(objc_class)
                if objc_data_struct:
                    # read information from each struct __objc_data
                    parsed_objc_classes.append(self._parse_objc_data_entry(objc_data_struct))
        return parsed_objc_classes

    def _parse_objc_categories(self):
        # type: () -> List[ObjcCategory]
        DebugUtil.log(self, 'Cross referencing objc_catlist, __objc_category, and __objc_data entries...')
        pass
    def _parse_static_objc_runtime_info(self):
        # type: () -> List[ObjcClass]
        """Parse classes referenced by __objc_classlist and categories referenced by __objc_catlist
        """
        classes = []
        classes += self._parse_objc_classes()
        classes += self._parse_objc_categories()
        return classes

    def _parse_objc_data_entry(self, objc_data_raw):
        # type: (ObjcDataRawStruct) -> ObjcClass
        data_parser = ObjcDataEntryParser(self.binary, self._selrefs, objc_data_raw)

        name = self.binary.get_full_string_from_start_address(objc_data_raw.name)
        selectors = data_parser.get_selectors()
        return ObjcClass(name, selectors)

    def _read_pointer_section(self, section_name):
        # type: (Text) -> List[int]
        """Read all the pointers in a section

        It is the caller's responsibility to only call this with a `section_name` which indicates a section which should
        only contain a pointer list.
        """
        entries = []  # type: List[int]
        if section_name not in self.binary.sections:
            return entries

        section_data = self.binary.sections[section_name].content
        binary_word = self.binary.platform_word_type
        pointer_count = int(len(section_data) / sizeof(binary_word))

        pointer_off = 0
        for i in range(pointer_count):
            data_end = pointer_off + sizeof(binary_word)
            val = binary_word.from_buffer(bytearray(section_data[pointer_off:data_end])).value
            entries.append(val)
            pointer_off += sizeof(binary_word)
        return entries

    def _get_catlist_pointers(self):
        # type: () -> List[int]
        """Read pointers in __objc_catlist into list
        """
        return self._read_pointer_section('__objc_catlist')

    def _get_classlist_pointers(self):
        # type: () -> List[int]
        """Read pointers in __objc_classlist into list
        """
        return self._read_pointer_section('__objc_classlist')

    def _get_objc_class_from_classlist_pointer(self, entry_location):
        # type: (int) -> ObjcClassRawStruct
        """Read a struct __objc_class from the virtual address of the pointer
        Typically, this pointer will come from an entry in __objc_classlist
        """
        class_entry = ObjcClassRawStruct(self.binary, entry_location, virtual=True)

        # sanitize class_entry
        # the least significant 2 bits are used for flags
        # flag 0x1 indicates a Swift class
        # mod data pointer to ignore flags!
        class_entry.data &= ~0x3
        return class_entry

    def _get_objc_data_from_objc_class(self, objc_class):
        # type: (ObjcClassRawStruct) -> Optional[ObjcDataRawStruct]
        """Read a struct __objc_data from a provided struct __objc_class
        If the struct __objc_class describe invalid or no corresponding data, None will be returned.
        """
        data_entry = ObjcDataRawStruct(self.binary, objc_class.data, virtual=True)
        # ensure this is a valid entry
        if data_entry.name < self.binary.get_virtual_base():
            # TODO(PT): sometimes we'll get addresses passed to this method that are actually struct __objc_method
            # entries, rather than struct __objc_data entries. Investigate why this is.
            # This was observed on a 32bit binary, Esquire2
            DebugUtil.log(self, 'caught ObjcDataRaw struct with invalid fields at {}. data->name = {}'.format(
                hex(int(objc_class.data)),
                hex(data_entry.name)
            ))
            return None
        return data_entry

