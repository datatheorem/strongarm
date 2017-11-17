from typing import List, Optional, Text
from ctypes import sizeof, c_uint64

from strongarm.macho.macho_definitions import ObjcClassRaw, ObjcDataRaw, ObjcMethodList, ObjcMethod
from strongarm.debug_util import DebugUtil
from strongarm.macho.macho_binary import MachoBinary


class ObjcClass(object):
    def __init__(self, name, selectors):
        # type: (Text, List[ObjcSelector]) -> None
        self.name = name
        self.selectors = selectors


class ObjcSelector(object):
    def __init__(self, name, selref, signature, implementation):
        # type: (Text, int, Text, int) -> None
        self.name = name
        self.selref = selref
        self.signature = signature
        self.implementation = implementation

    def __str__(self):
        return '<@selector({}) at {}>'.format(self.name, hex(int(self.implementation)))
    __repr__ = __str__


class ObjcDataEntryParser(object):
    """Class encapsulating logic to retrieve a list of selectors from an __objc_data struct
    """

    def __init__(self, binary, objc_data_raw_struct):
        # type: (MachoBinary, ObjcDataRaw) -> None
        self._binary = binary
        self._objc_data_raw_struct = objc_data_raw_struct

    def get_selectors(self):
        """Parse every ObjcSelector described by the struct __objc_data
        """
        methlist_info = self._get_methlist()
        if not methlist_info:
            return
        methlist = methlist_info[0]
        methlist_file_ptr = methlist_info[1]

        return self._get_selectors_from_methlist(methlist, methlist_file_ptr)

    def _get_selectors_from_methlist(self, methlist, methlist_file_ptr):
        # type: (ObjcMethodList, int) -> List[ObjcSelector]
        """Given a method list, return a List of ObjcSelectors encapsulating each method
        """
        selectors = []
        # parse every entry in method list
        # the first entry appears directly after the ObjcMethodList structure
        method_entry_off = methlist_file_ptr + sizeof(ObjcMethodList)
        for i in range(methlist.methcount):
            raw_struct_data = self._binary.get_bytes(method_entry_off, sizeof(ObjcMethod))
            method_ent = ObjcMethod.from_buffer(bytearray(raw_struct_data))

            # TODO(PT): preprocess __objc_methname so we don't have to search for null byte for every string here
            symbol_name = self._binary.get_full_string_from_start_address(method_ent.name)
            signature = self._binary.get_full_string_from_start_address(method_ent.signature)

            selector = ObjcSelector(symbol_name, method_ent.name, signature, method_ent.implementation)
            selectors.append(selector)

            method_entry_off += sizeof(ObjcMethod)
        return selectors

    def _get_methlist(self):
        # type: () -> Optional[(ObjcMethodList, int)]
        """Return the ObjcMethodList and file offset described by the ObjcDataRaw struct
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

        methlist_file_ptr = self._objc_data_raw_struct.base_methods - self._binary.get_virtual_base()
        raw_struct_data = self._binary.get_bytes(methlist_file_ptr, sizeof(ObjcMethodList))
        methlist = ObjcMethodList.from_buffer(bytearray(raw_struct_data))
        return (methlist, methlist_file_ptr)


class ObjcRuntimeDataParser(object):
    def __init__(self, binary):
        self.binary = binary
        self.classes = self._parse_static_objc_runtime_info()

    def imp_for_selref(self, selref):
        # type: (int) -> Optional[int]
        for objc_class in self.classes:
            for sel in objc_class.selectors:
                print('got selref {}'.format(hex(int(sel.selref))))
                if sel.selref == selref:
                    return sel.implementation
        return None

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

    def _parse_static_objc_runtime_info(self):
        # type: () -> List[ObjcClass]
        """Read Objective-C class data in __objc_classlist, __objc_data to get classes and selectors in binary
        """
        objc_classes = []
        classlist_pointers = self._get_classlist_pointers()
        # if the classlist had no entries, there's no Objective-C data in this binary
        # in this case, the binary must be implemented purely in C or Swift
        if not len(classlist_pointers):
            return objc_classes

        # read actual list of ObjcClassRaw structs from list of pointers
        raw_objc_classes = []
        for class_ptr in classlist_pointers:
            raw_objc_classes.append(self._get_objc_class_from_classlist_pointer(class_ptr))

        # TODO(PT): use ObjcClassRaw objects in objc_classes to create list of classes in binary
        # we could even make a list of all selectors for a given class
        # and, when requesting an IMP for a selector, we could request the class too (for SEL collisions)

        # read data for each class
        objc_data_entries = []
        for class_ent in raw_objc_classes:
            objc_data_entries.append(self._get_objc_data_from_objc_class(class_ent))

        # read information from each struct __objc_data
        for objc_data in objc_data_entries:
            objc_classes.append(self._parse_objc_data_entry(objc_data))
        return objc_classes

    def _parse_objc_data_entry(self, objc_data_raw):
        # type: (ObjcDataRaw) -> ObjcClass
        data_parser = ObjcDataEntryParser(self.binary, objc_data_raw)
        selectors = data_parser.get_selectors()

        name = self.binary.get_full_string_from_start_address(objc_data_raw.name)

        print('{} selectors {}'.format(name, selectors))
        return ObjcClass(name, selectors)

    def _get_classlist_pointers(self):
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
        # type: (int) -> ObjcClassRaw
        """Read a struct __objc_class from the virtual address of the pointer
        Typically, this pointer will come from an entry in __objc_classlist
        """
        file_ptr = entry_location - self.binary.get_virtual_base()
        raw_struct_data = self.binary.get_bytes(file_ptr, sizeof(ObjcClassRaw))
        class_entry = ObjcClassRaw.from_buffer(bytearray(raw_struct_data))

        # sanitize class_entry
        # it seems for Swift classes,
        # the compiler will add 1 to the data field
        # TODO(pt) detecting this can be a heuristic for finding Swift classes!
        # mod data field to a byte size
        overlap = class_entry.data % 0x8
        class_entry.data -= overlap
        return class_entry

    def _get_objc_data_from_objc_class(self, objc_class):
        # type: (ObjcClassRaw) -> Optional[ObjcDataRaw]
        """Read a struct __objc_data from a provided struct __objc_class
        If the struct __objc_class describe invalid or no corresponding data, None will be returned.
        """
        data_file_ptr = objc_class.data - self.binary.get_virtual_base()
        raw_struct_data = self.binary.get_bytes(data_file_ptr, sizeof(ObjcDataRaw))
        data_entry = ObjcDataRaw.from_buffer(bytearray(raw_struct_data))
        # ensure this is a valid entry
        if data_entry.name < self.binary.get_virtual_base():
            DebugUtil.log(self, 'caught ObjcDataRaw struct with invalid fields at {}'.format(
                hex(int(data_file_ptr + self.binary.get_virtual_base()))
            ))
            return None
        return data_entry

