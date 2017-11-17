from typing import List, Optional, Text
from ctypes import sizeof, c_uint64

from strongarm.macho.macho_definitions import ObjcClassRaw, ObjcDataRaw, ObjcMethodList, ObjcMethod
from strongarm.debug_util import DebugUtil


class ObjcClass(object):
    def __init__(self, raw_objc_class_struct):
        self.raw_objc_class_struct = raw_objc_class_struct
        self.name = None


class ObjcData(object):
    def __init__(self, raw_objc_data_struct):
        self.raw_objc_data_struct = raw_objc_data_struct


class ObjcRuntimeDataParser(object):
    def __init__(self, binary):
        self.binary = binary
        self.parse_static_objc_runtime_info()

    def parse_static_objc_runtime_info(self):
        # type: () -> None
        """Read Objective-C class data in __objc_classlist, __objc_data to get classes and selectors in binary
        """
        classlist_pointers = self._get_classlist_pointers()
        # if the classlist had no entries, there's no Objective-C data in this binary
        # in this case, the binary must be implemented purely in C or Swift
        if not len(classlist_pointers):
            return

        # read actual list of ObjcClassRaw structs from list of pointers
        objc_classes = []
        for class_ptr in classlist_pointers:
            objc_classes.append(self._get_objc_class_from_classlist_pointer(class_ptr))

        # TODO(PT): use ObjcClassRaw objects in objc_classes to create list of classes in binary
        # we could even make a list of all selectors for a given class
        # and, when requesting an IMP for a selector, we could request the class too (for SEL collisions)

        # read data for each class
        objc_data_entries = []
        for class_ent in objc_classes:
            objc_data_entries.append(self._get_objc_data_from_objc_class(class_ent))

        # for each ObjcClassRaw/ObjcDataRaw pair, parse details about the class implementation
        for objc_class, objc_data in zip(objc_classes, objc_data_entries):
            self.parse_class_data_pair(objc_class, objc_data)
            #self._parse_objc_data_entries(objc_data_entries)
        import sys
        sys.exit(0)

    def parse_class_data_pair(self, objc_class_raw, objc_data_raw):
        # type: (ObjcClassRaw, ObjcDataRaw) -> None
        objc_class = ObjcClass(objc_class_raw)
        name = self.binary.get_full_string_from_start_address(objc_data_raw.name)
        objc_class.name = name
        print('found class with name {}'.format(name))

    def _parse_objc_data_entries(self, objc_data_entries):
        # type: (List[ObjcDataRaw]) -> None
        """For each ObjcDataRaw, find the selector name, selref, and IMP address, and record in instance maps
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


    def _get_methlist_from_objc_data(self, data_struct):
        # type: (ObjcDataRaw) -> Optional[(ObjcMethodList, int)]
        """Return the ObjcMethodList and file offset described by the provided ObjcDataRaw struct
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
            symbol_name = self.binary._get_full_string_from_start_address(method_ent.name)
            methods_data.append((symbol_name, method_ent.name, method_ent.implementation))

            method_entry_off += sizeof(ObjcMethod)
        return methods_data

