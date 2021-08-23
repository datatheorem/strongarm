import logging
from ctypes import c_uint32, c_uint64, sizeof
from typing import Dict, List, Optional

from more_itertools import first_true

from strongarm.macho.arch_independent_structs import (
    ArchIndependentStructure,
    ObjcCategoryRawStruct,
    ObjcClassRawStruct,
    ObjcDataRawStruct,
    ObjcIvarListStruct,
    ObjcIvarStruct,
    ObjcMethodListStruct,
    ObjcMethodStruct,
    ObjcProtocolListStruct,
    ObjcProtocolRawStruct,
)
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import VirtualMemoryPointer


class ObjcSelref:
    __slots__ = ["source_address", "destination_address", "selector_literal"]

    def __init__(
        self, source_address: VirtualMemoryPointer, destination_address: VirtualMemoryPointer, selector_literal: str
    ) -> None:
        self.source_address = source_address
        self.destination_address = destination_address
        self.selector_literal = selector_literal

    def __repr__(self) -> str:
        return (
            f"<ObjcSelref source=0x{self.source_address:x} dest=0x{self.destination_address:x}"
            f" sel={self.selector_literal}>"
        )


class ObjcSelector:
    __slots__ = ["name", "selref", "implementation", "is_external_definition"]

    def __init__(self, name: str, selref: Optional[ObjcSelref], implementation: Optional[VirtualMemoryPointer]) -> None:
        self.name = name
        self.selref = selref
        self.implementation = implementation

        self.is_external_definition = not self.implementation

    def __str__(self) -> str:
        imp_addr = "NaN"
        if self.implementation:
            imp_addr = hex(int(self.implementation))
        return f"<@selector({self.name}) at {imp_addr}>"

    __repr__ = __str__


class ObjcIvar:
    __slots__ = ["name", "class_name", "field_offset", "field_offset_addr"]

    def __init__(self, name: str, class_name: str, offset: int, field_offset_addr: VirtualMemoryPointer):
        self.name = name
        self.class_name = class_name
        self.field_offset = offset
        self.field_offset_addr = field_offset_addr

    def __str__(self) -> str:
        return f"<@ivar {self.class_name}* {self.name}, off @ {self.field_offset}>"

    __repr__ = __str__


class ObjcClass:
    __slots__ = ["raw_struct", "name", "selectors", "ivars", "protocols", "super_classref", "superclass_name"]

    def __init__(
        self,
        raw_struct: ArchIndependentStructure,
        name: str,
        selectors: List[ObjcSelector],
        ivars: List[ObjcIvar] = None,
        protocols: List["ObjcProtocol"] = None,
        super_classref: Optional[VirtualMemoryPointer] = None,
        superclass_name: Optional[str] = None,
    ) -> None:
        self.name = name
        self.selectors = selectors
        self.raw_struct = raw_struct
        self.ivars = ivars if ivars else []
        self.protocols = protocols if protocols else []
        self.super_classref = super_classref
        self.superclass_name = superclass_name

    def __str__(self) -> str:
        return f"ObjcClass({self.name} : {self.superclass_name})"

    def __repr__(self) -> str:
        return (
            f"<@class {self.name} : {self.superclass_name}"
            f" sel_count={len(self.selectors)} ivar_count={len(self.ivars)} protocol_count={len(self.protocols)}>"
        )


class ObjcProtocol(ObjcClass):
    pass


class ObjcCategory(ObjcClass):
    __slots__ = ["raw_struct", "name", "base_class", "category_name", "selectors", "ivars", "protocols"]

    def __init__(
        self,
        raw_struct: ObjcCategoryRawStruct,
        base_class: str,
        category_name: str,
        selectors: List[ObjcSelector],
        ivars: List[ObjcIvar] = None,
        protocols: List[ObjcProtocol] = None,
    ) -> None:
        self.base_class = base_class
        self.category_name = category_name

        # ObjcCategory.name includes the base class + the cat-name
        # That way, callers don't need to check the ObjcClass instance type to get the 'right' value
        full_name = f"{base_class} ({category_name})"
        super().__init__(raw_struct, full_name, selectors, ivars, protocols)

    def __str__(self) -> str:
        return f"ObjcCategory({self.base_class} ({self.category_name}))"

    def __repr__(self) -> str:
        return (
            f"<@class {self.base_class} ({self.category_name})"
            f" sel_count={len(self.selectors)} ivar_count={len(self.ivars)} protocol_count={len(self.protocols)}>"
        )


class ObjcRuntimeDataParser:
    def __init__(self, binary: MachoBinary) -> None:
        self.binary = binary
        logging.debug(f"Parsing ObjC runtime info of {self.binary}...")

        logging.debug("Step 1: Parsing selrefs...")
        self._selref_ptr_to_selector_map: Dict[VirtualMemoryPointer, ObjcSelector] = {}
        self._selector_literal_ptr_to_selref_map: Dict[VirtualMemoryPointer, ObjcSelref] = {}
        # This populates self._selector_literal_ptr_to_selref_map and self._selref_ptr_to_selector_map
        self._parse_selrefs()

        logging.debug("Step 2: Parsing classes, categories, and protocols...")
        self._classrefs_to_objc_classes: Dict[VirtualMemoryPointer, ObjcClass] = {}
        # This populates self._classrefs_to_objc_classes
        self.classes = self._parse_class_and_category_info()
        self.protocols = self._parse_global_protocol_info()

        logging.debug("Step 3: Resolving symbol name to source dylib map...")
        self._sym_to_dylib_path = self._parse_linked_dylib_symbols()

    def _parse_linked_dylib_symbols(self) -> Dict[str, str]:
        syms_to_dylib_path = {}

        symtab = self.binary.symtab
        symtab_contents = self.binary.symtab_contents
        dysymtab = self.binary.dysymtab
        visited_addresses = set()
        for undef_sym_idx in range(dysymtab.nundefsym):
            symtab_idx = dysymtab.iundefsym + undef_sym_idx
            sym = symtab_contents[symtab_idx]

            strtab_idx = sym.n_un.n_strx
            string_file_address = symtab.stroff + strtab_idx

            # Some binaries contain a symtab such that all the calculated string address are the same. This check
            # prevents spamming the logs with errors about the same symbol
            # TODO(FS): Task tracking this issue SCAN-2744
            if string_file_address in visited_addresses:
                continue
            visited_addresses.add(string_file_address)

            symbol_name = self.binary.get_full_string_from_start_address(string_file_address, virtual=False)
            if not symbol_name:
                logging.error(f"Could not get symbol name at address {hex(string_file_address)}")
                continue

            library_ordinal = self._library_ordinal_from_n_desc(sym.n_desc)
            source_name = self.binary.dylib_name_for_library_ordinal(library_ordinal)

            syms_to_dylib_path[symbol_name] = source_name
        return syms_to_dylib_path

    def path_for_external_symbol(self, symbol: str) -> Optional[str]:
        if symbol in self._sym_to_dylib_path:
            return self._sym_to_dylib_path[symbol]
        return None

    @staticmethod
    def _library_ordinal_from_n_desc(n_desc: int) -> int:
        return (n_desc >> 8) & 0xFF

    def _parse_selrefs(self) -> None:
        """Parse the binary's selref list, and store the data.

        This method populates self._selector_literal_ptr_to_selref_map.
        It also *PARTLY* populates self._selref_ptr_to_selector_map. All selrefs keys will have an ObjcSelector
        value, but none of the ObjcSelector objects will have their `implementation` field filled, because
        at this point in the parse we do not yet know the implementations of each selector. ObjcSelectors which we
        later find an implementation for are updated in self.read_selectors_from_methlist_ptr"""
        selref_pointers, selector_literal_pointers = self.binary.read_pointer_section("__objc_selrefs")
        # sanity check
        if len(selref_pointers) != len(selector_literal_pointers):
            raise RuntimeError("read invalid data from __objc_selrefs")

        for selref_ptr, selector_literal_ptr in zip(selref_pointers, selector_literal_pointers):
            # read selector string literal from selref pointer
            selector_string = self.binary.get_full_string_from_start_address(selector_literal_ptr)
            if not selector_string:
                continue  # but all selectors should have a name
            wrapped_selref = ObjcSelref(selref_ptr, selector_literal_ptr, selector_string)

            # map the selector string pointer to the ObjcSelref
            self._selector_literal_ptr_to_selref_map[selector_literal_ptr] = wrapped_selref
            # add second mapping in selref list
            # we don't know the implementation address yet but it will be updated when we parse method lists
            self._selref_ptr_to_selector_map[selref_ptr] = ObjcSelector(selector_string, wrapped_selref, None)

    def selector_for_selref(self, selref_addr: VirtualMemoryPointer) -> Optional[ObjcSelector]:
        selector = self._selref_ptr_to_selector_map.get(selref_addr)
        if selector is not None:
            return selector

        # selref wasn't referenced in classes implemented within the binary
        # make sure it's a valid selref
        selrefs = self._selector_literal_ptr_to_selref_map.values()
        selref = first_true(iter(selrefs), pred=lambda x: x.source_address == selref_addr, default=None)

        if selref is not None:
            # Therefore, the selref must refer to a selector which is defined outside this binary
            # this is fine, just construct an ObjcSelector with what we know
            return ObjcSelector(selref.selector_literal, selref, None)

        else:
            return None

    def selector_for_selector_literal(self, literal_addr: VirtualMemoryPointer) -> Optional[ObjcSelector]:
        selector_literal = self._selector_literal_ptr_to_selref_map.get(literal_addr)
        if selector_literal is not None:
            return self.selector_for_selref(selector_literal.source_address)
        else:
            return None

    def selrefs_to_selectors(self) -> Dict[VirtualMemoryPointer, ObjcSelector]:
        return self._selref_ptr_to_selector_map

    def selref_for_selector_name(self, selector_name: str) -> Optional[VirtualMemoryPointer]:
        return next(
            (selref for selref, selector in self._selref_ptr_to_selector_map.items() if selector.name == selector_name),
            None,
        )

    def get_method_imp_addresses(self, selector: str) -> List[VirtualMemoryPointer]:
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        return [
            objc_sel.implementation
            for objc_class in self.classes
            for objc_sel in objc_class.selectors
            if objc_sel.name == selector and objc_sel.implementation
        ]

    def objc_class_for_classlist_pointer(self, classlist_ptr: VirtualMemoryPointer) -> Optional[ObjcClass]:
        return self._classrefs_to_objc_classes.get(classlist_ptr)

    def _parse_objc_classes(self) -> List[ObjcClass]:
        """Read Objective-C class data in __objc_classlist, __objc_data to get classes and selectors in binary
        """
        logging.debug("Cross-referencing __objc_classlist, __objc_class, and __objc_data entries...")
        parsed_objc_classes = []
        classlist_pointers = self._get_classlist_pointers()
        for ptr in classlist_pointers:
            objc_class = self._get_objc_class_from_classlist_pointer(ptr)
            if objc_class:
                parsed_class = None
                # parse the instance method list
                objc_data_struct = self._get_objc_data_from_objc_class(objc_class)
                if objc_data_struct:
                    # the class's associated struct __objc_data contains the method list
                    parsed_class = self._parse_objc_data_entry(objc_class, objc_data_struct)

                # parse the metaclass if it exists
                # the class stores instance methods and the metaclass's method list contains class methods
                # the metaclass has the same name as the actual class
                metaclass = self._get_objc_class_from_classlist_pointer(VirtualMemoryPointer(objc_class.metaclass))
                if metaclass:
                    objc_data_struct = self._get_objc_data_from_objc_class(metaclass)
                    if objc_data_struct:
                        parsed_metaclass = self._parse_objc_data_entry(objc_class, objc_data_struct)
                        if parsed_class:
                            # add in selectors from the metaclass to the real class
                            parsed_class.selectors += parsed_metaclass.selectors
                        else:
                            # no base class found, set the base class to the metaclass
                            parsed_class = parsed_metaclass

                # sanity check
                # ensure we either found a class or metaclass
                if not parsed_class:
                    raise RuntimeError(f"Failed to parse classref {hex(ptr)}")
                parsed_objc_classes.append(parsed_class)
                self._classrefs_to_objc_classes[ptr] = parsed_class

        return parsed_objc_classes

    def _parse_objc_categories(self) -> List[ObjcCategory]:
        logging.debug("Cross referencing __objc_catlist, __objc_category, and __objc_data entries...")
        parsed_categories = []
        category_pointers = self._get_catlist_pointers()
        for ptr in category_pointers:
            objc_category_struct = self._get_objc_category_from_catlist_pointer(ptr)
            if objc_category_struct:
                parsed_category = self._parse_objc_category_entry(objc_category_struct)
                parsed_categories.append(parsed_category)
        return parsed_categories

    def _parse_class_and_category_info(self) -> List[ObjcClass]:
        """Parse classes and categories referenced by __objc_classlist and __objc_catlist
        """
        classes: List[ObjcClass] = []
        classes += self._parse_objc_classes()
        classes += self._parse_objc_categories()
        # Link superclass methods into their subclasses
        self._add_superclass_methods_to_subclasses()
        # Link superclasses of classes and base-classes of categories
        self._add_superclass_or_base_class_name_to_classes(classes)
        return classes

    def _add_superclass_methods_to_subclasses(self) -> None:
        for classlist_ptr, objc_class in self._classrefs_to_objc_classes.items():
            super_classref = objc_class.super_classref
            if not super_classref:
                continue
            superclass = self.objc_class_for_classlist_pointer(super_classref)
            if not superclass:
                continue
            objc_class.ivars += superclass.ivars
            objc_class.selectors += superclass.selectors
            objc_class.protocols += superclass.protocols

    def _add_superclass_or_base_class_name_to_classes(self, classes: List[ObjcClass]) -> None:
        """Iterate each ObjC class/category, and backfill its superclass/base_class name, respectively.

        Linking super/base_classes needs two data-sources, depending on whether the super/base_class is imported or not:
        - To retrieve the class names of imported super/base classes, this needs the map of bound dyld symbols
        - To retrieve the class names of locally implemented classes, this needs the full list of ObjcClasses
        """
        # For efficiency, build a map of (struct address -> class name)
        addr_to_class_names = {x.raw_struct.binary_offset: x.name for x in classes}

        for objc_class_or_category in classes:
            raw_struct = objc_class_or_category.raw_struct
            # This method uses the fact that `struct __objc_data.superclass` and `struct __objc_category.base_class`
            # have the same memory layout, being placed one 64-bit word after the start of the structure.
            base_class_field_addr = VirtualMemoryPointer(raw_struct.binary_offset + sizeof(c_uint64))

            # If the base class is an imported classref, the imported classref will be bound to its runtime load address
            # by dyld. Look up whether we have an import-binding for the `base_class` field of this structure.
            if base_class_field_addr in self.binary.dyld_bound_symbols:
                imported_base_class_sym = self.binary.dyld_bound_symbols[base_class_field_addr]
                base_class_name = imported_base_class_sym.name

            else:
                dereferenced_classref = VirtualMemoryPointer(self.binary.read_word(base_class_field_addr))
                # The base class is implemented in this binary, and we should have a corresponding ObjcClass object.
                if dereferenced_classref in addr_to_class_names:
                    base_class_name = addr_to_class_names[dereferenced_classref]
                else:
                    logging.error(
                        f"Failed to find a corresponding ObjC class for ref {dereferenced_classref} from "
                        f"{objc_class_or_category}"
                    )
                    base_class_name = "$_Unknown_Class"

            if isinstance(objc_class_or_category, ObjcCategory):
                objc_class_or_category.base_class = base_class_name
                # Update the name attribute to hold the parsed category name
                objc_class_or_category.name = f"{base_class_name} ({objc_class_or_category.category_name})"
            else:
                objc_class_or_category.superclass_name = base_class_name

    def _parse_global_protocol_info(self) -> List[ObjcProtocol]:
        """Parse protocols which code in the app conforms to, referenced by __objc_protolist
        """
        logging.debug("Cross referencing __objc_protolist, __objc_protocol, and __objc_data entries...")
        protocol_pointers = self._get_protolist_pointers()
        return self._parse_protocol_ptr_list(protocol_pointers)

    def read_ivars_from_ivarlist_ptr(self, ivarlist_ptr: VirtualMemoryPointer) -> List[ObjcIvar]:
        """Given the virtual address of an ivar list, return a List of each encoded ObjcIvar
        """
        ivarlist = self.binary.read_struct(ivarlist_ptr, ObjcIvarListStruct, virtual=True)
        ivars: List[ObjcIvar] = []
        # Parse each ivar struct which follows the ivarlist
        ivar_struct_ptr = ivarlist_ptr + ivarlist.sizeof
        for _ in range(ivarlist.count):
            ivar_struct = self.binary.read_struct_with_rebased_pointers(ivar_struct_ptr, ObjcIvarStruct, virtual=True)

            ivar_name = self.binary.get_full_string_from_start_address(ivar_struct.name)
            class_name = self.binary.get_full_string_from_start_address(ivar_struct.type)
            field_offset = self.binary.read_word(ivar_struct.offset_ptr, word_type=c_uint32)
            field_offset_addr = ivar_struct.offset_ptr

            # class_name and field_offset can be falsey ('' and 0), so don't include them in this sanity check
            if not ivar_name:
                raise ValueError(f"Failed to read ivar data for ivar entry @ {hex(ivar_struct_ptr)}")

            ivar = ObjcIvar(ivar_name, class_name, field_offset, field_offset_addr)  # type: ignore
            ivars.append(ivar)

            ivar_struct_ptr += ivar_struct.sizeof
        return ivars

    def read_selectors_from_methlist_ptr(self, methlist_ptr: VirtualMemoryPointer) -> List[ObjcSelector]:
        """Given the virtual address of a method list, return a List of ObjcSelectors encapsulating each method
        """
        methlist = self.binary.read_struct(methlist_ptr, ObjcMethodListStruct, virtual=True)
        selectors: List[ObjcSelector] = []
        # parse every entry in method list
        # the first entry appears directly after the ObjcMethodListStruct
        method_entry_off = methlist_ptr + methlist.sizeof
        for i in range(methlist.methcount):
            method_ent = ObjcMethodStruct.read_method_struct(
                self.binary, method_entry_off, methlist_flags=methlist.flags
            )
            # Byte-align IMP, as the lower bits are used for flags
            method_ent.implementation &= ~0x3  # type: ignore

            symbol_name = self.binary.get_full_string_from_start_address(method_ent.name)
            if not symbol_name:
                raise ValueError(f"Could not get symbol name for {method_ent.name}")
            # attempt to find corresponding selref
            selref = self._selector_literal_ptr_to_selref_map.get(method_ent.name)

            selector = ObjcSelector(symbol_name, selref, VirtualMemoryPointer(method_ent.implementation))
            selectors.append(selector)

            # save this selector in the selref pointer -> selector map
            if selref:
                # if this selector is already in the map, check if we now know the implementation address
                # we could have parsed the selector literal/selref pair in _parse_selrefs() but not have known the
                # implementation, but do now. It's also possible the selref is an external method, and thus will not
                # have a local implementation.
                most_specific_selector = selector
                if selref.source_address in self._selref_ptr_to_selector_map:
                    previously_parsed_selector = self._selref_ptr_to_selector_map[selref.source_address]
                    # Did we already parse this same selector but with more specific information?
                    # (Say, if we parse an ObjC class implementing a protocol before parsing the protocol itself)
                    if previously_parsed_selector.implementation:
                        # Make sure we keep the most specific selector we've seen
                        most_specific_selector = previously_parsed_selector
                self._selref_ptr_to_selector_map[selref.source_address] = most_specific_selector

            method_entry_off += method_ent.sizeof
        return selectors

    def _parse_objc_protocol_entry(self, objc_protocol_struct: ObjcProtocolRawStruct) -> ObjcProtocol:
        symbol_name = self.binary.get_full_string_from_start_address(objc_protocol_struct.name)
        if not symbol_name:
            raise ValueError(f"Could not get symbol name for {objc_protocol_struct.name}")

        selectors: List[ObjcSelector] = []
        if objc_protocol_struct.required_instance_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_protocol_struct.required_instance_methods)
        if objc_protocol_struct.required_class_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_protocol_struct.required_class_methods)
        if objc_protocol_struct.optional_instance_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_protocol_struct.optional_instance_methods)
        if objc_protocol_struct.optional_class_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_protocol_struct.optional_class_methods)

        return ObjcProtocol(objc_protocol_struct, symbol_name, selectors)

    def _parse_objc_category_entry(self, objc_category_struct: ObjcCategoryRawStruct) -> ObjcCategory:
        # TODO(PT): Add in the methods of the base class to the ObjcCategory
        symbol_name = self.binary.get_full_string_from_start_address(objc_category_struct.name)
        if not symbol_name:
            raise ValueError(f"Could not get symbol name for {objc_category_struct.name}")

        selectors: List[ObjcSelector] = []
        protocols: List[ObjcProtocol] = []

        # The class-name will be overwritten later in the parse. See self._add_superclass_or_base_class_name_to_classes
        placeholder_class_name = (
            f"<Base class of {symbol_name} category @ {objc_category_struct.binary_offset} will be populated later>"
        )

        # if the class implements no methods, the pointer to method list will be the null pointer
        # TODO(PT): we could add some flag to keep track of whether a given sel is an instance or class method
        if objc_category_struct.instance_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_category_struct.instance_methods)
        if objc_category_struct.class_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_category_struct.class_methods)
        if objc_category_struct.base_protocols:
            # TODO(PT): perhaps these should be combined into one call
            protocol_pointers = self._protolist_ptr_to_protocol_ptr_list(objc_category_struct.base_protocols)
            protocols += self._parse_protocol_ptr_list(protocol_pointers)

        return ObjcCategory(objc_category_struct, placeholder_class_name, symbol_name, selectors, protocols=protocols)

    def _parse_objc_data_entry(
        self, objc_class_struct: ObjcClassRawStruct, objc_data_struct: ObjcDataRawStruct
    ) -> ObjcClass:
        symbol_name = self.binary.get_full_string_from_start_address(objc_data_struct.name)
        if not symbol_name:
            raise ValueError(f"Could not get symbol name for {hex(objc_data_struct.name)}")

        selectors: List[ObjcSelector] = []
        protocols: List[ObjcProtocol] = []
        ivars: List[ObjcIvar] = []
        # if the class implements no methods, base_methods will be the null pointer
        if objc_data_struct.base_methods:
            selectors += self.read_selectors_from_methlist_ptr(objc_data_struct.base_methods)
        # if the class doesn't conform to any protocols, base_protocols will be null
        if objc_data_struct.base_protocols:
            protocol_pointer_list = self._protolist_ptr_to_protocol_ptr_list(objc_data_struct.base_protocols)
            protocols += self._parse_protocol_ptr_list(protocol_pointer_list)
        # Parse ivar list
        if objc_data_struct.ivars:
            ivars += self.read_ivars_from_ivarlist_ptr(objc_data_struct.ivars)

        return ObjcClass(objc_class_struct, symbol_name, selectors, ivars, protocols, objc_class_struct.superclass)

    def _protolist_ptr_to_protocol_ptr_list(self, protolist_ptr: VirtualMemoryPointer) -> List[VirtualMemoryPointer]:
        """Accepts the virtual address of an ObjcProtocolListStruct, and returns List of protocol pointers it refers to.
        """
        protolist = self.binary.read_struct(protolist_ptr, ObjcProtocolListStruct, virtual=True)
        protocol_pointers: List[VirtualMemoryPointer] = []
        # pointers start directly after the 'count' field
        addr = VirtualMemoryPointer(protolist.binary_offset + protolist.sizeof)
        for i in range(protolist.count):
            # This pointer may be rebased
            pointer = self.binary.read_rebased_pointer(addr)
            protocol_pointers.append(VirtualMemoryPointer(pointer))
            # step to next protocol pointer in list
            addr += sizeof(self.binary.platform_word_type)
        return protocol_pointers

    def _parse_protocol_ptr_list(self, protocol_ptrs: List[VirtualMemoryPointer]) -> List[ObjcProtocol]:
        protocols = []
        for protocol_ptr in protocol_ptrs:
            objc_protocol_struct = self._get_objc_protocol_from_pointer(protocol_ptr)
            if objc_protocol_struct:
                parsed_protocol = self._parse_objc_protocol_entry(objc_protocol_struct)
                protocols.append(parsed_protocol)
        return protocols

    def _get_catlist_pointers(self) -> List[VirtualMemoryPointer]:
        """Read pointers in __objc_catlist into list
        """
        _, catlist_pointers = self.binary.read_pointer_section("__objc_catlist")
        return catlist_pointers

    def _get_protolist_pointers(self) -> List[VirtualMemoryPointer]:
        """Read pointers in __objc_protolist into list
        """
        _, protolist_pointers = self.binary.read_pointer_section("__objc_protolist")
        return protolist_pointers

    def _get_classlist_pointers(self) -> List[VirtualMemoryPointer]:
        """Read pointers in __objc_classlist into list
        """
        _, classlist_pointers = self.binary.read_pointer_section("__objc_classlist")
        return classlist_pointers

    def _get_objc_category_from_catlist_pointer(
        self, category_struct_pointer: VirtualMemoryPointer
    ) -> ObjcCategoryRawStruct:
        """Read a struct __objc_category from the location indicated by the provided __objc_catlist pointer
        """
        category_entry = self.binary.read_struct_with_rebased_pointers(
            category_struct_pointer, ObjcCategoryRawStruct, virtual=True
        )
        return category_entry

    def _get_objc_protocol_from_pointer(self, protocol_struct_pointer: VirtualMemoryPointer) -> ObjcProtocolRawStruct:
        """Read a struct __objc_protocol from the location indicated by the provided struct objc_protocol_list pointer
        """
        protocol_entry = self.binary.read_struct_with_rebased_pointers(
            protocol_struct_pointer, ObjcProtocolRawStruct, virtual=True
        )
        return protocol_entry

    def _get_objc_class_from_classlist_pointer(self, class_struct_pointer: VirtualMemoryPointer) -> ObjcClassRawStruct:
        """Read a struct __objc_class from the location indicated by the __objc_classlist pointer
        """
        class_entry = self.binary.read_struct_with_rebased_pointers(
            class_struct_pointer, ObjcClassRawStruct, virtual=True
        )

        # sanitize class_entry
        # the least significant 2 bits are used for flags
        # flag 0x1 indicates a Swift class
        # mod data pointer to ignore flags!
        class_entry.data &= ~0x3  # type: ignore
        return class_entry

    def _get_objc_data_from_objc_class(self, objc_class: ObjcClassRawStruct) -> Optional[ObjcDataRawStruct]:
        """Read a struct __objc_data from a provided struct __objc_class
        If the struct __objc_class describe invalid or no corresponding data, None will be returned.
        """
        data_entry = self.binary.read_struct_with_rebased_pointers(objc_class.data, ObjcDataRawStruct, virtual=True)
        # ensure this is a valid entry
        if data_entry.name < self.binary.get_virtual_base():
            # TODO(PT): sometimes we'll get addresses passed to this method that are actually struct __objc_method
            # entries, rather than struct __objc_data entries. Investigate why this is.
            # This was observed on a 32bit binary, Esquire2
            logging.debug(
                f"caught ObjcDataRaw struct with invalid fields at {hex(int(objc_class.data))}."
                f" data->name = {hex(data_entry.name)}"
            )
            return None
        return data_entry
