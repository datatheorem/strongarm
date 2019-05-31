import logging
from typing import TYPE_CHECKING
from typing import List, Dict, Optional, Set
from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM

from ctypes import sizeof

from strongarm import DebugUtil
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.macho_definitions import VirtualMemoryPointer
from strongarm.macho.dyld_info_parser import DyldInfoParser, DyldBoundSymbol
from strongarm.macho.macho_string_table_helper import MachoStringTableHelper
from strongarm.macho.arch_independent_structs import CFStringStruct, CFString32, CFString64

from strongarm.macho.objc_runtime_data_parser import (
    ObjcClass,
    ObjcProtocol,
    ObjcSelector,
    ObjcCategory,
    ObjcRuntimeDataParser,
)


if TYPE_CHECKING:
    from strongarm.objc import ObjcFunctionAnalyzer, ObjcMethodInfo  # type: ignore


class MachoAnalyzer:
    # keep map of binary -> analyzers as these do expensive one-time cross-referencing operations
    # XXX(PT): references to these will live to the end of the process, or until clear_cache() is called.
    _ACTIVE_ANALYZER_MAP: Dict[MachoBinary, 'MachoAnalyzer'] = {}

    def __init__(self, binary: MachoBinary) -> None:
        self.binary = binary
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        # Worker to parse dyld bytecode stream and extract dyld stub addresses to the DyldBoundSymbol they represent
        self._dyld_info_parser: DyldInfoParser = None
        # Each __stubs function calls a single dyld stub address, which has a corresponding DyldBoundSymbol.
        # Map of each __stub function to the associated name of the DyldBoundSymbol
        self._imported_symbol_addresses_to_names: Dict[VirtualMemoryPointer, str] = None

        self.crossref_helper = MachoStringTableHelper(binary)
        self.imported_symbols = self.crossref_helper.imported_symbols
        self.exported_symbols = self.crossref_helper.exported_symbols

        self.imp_stubs = MachoImpStubsParser(binary, self.cs).imp_stubs
        self._objc_helper: ObjcRuntimeDataParser = None
        self._objc_method_list: List[ObjcMethodInfo] = None

        self._cached_function_boundaries: Dict[int, int] = {}

        # done setting up, store this analyzer in class cache
        MachoAnalyzer._ACTIVE_ANALYZER_MAP[binary] = self

    @classmethod
    def clear_cache(cls):
        """Delete cached MachoAnalyzer's
        This can be used when you are finished analyzing a binary set and don't want to retain the cached data in memory
        """
        cls._ACTIVE_ANALYZER_MAP = {}

    @property
    def objc_helper(self) -> ObjcRuntimeDataParser:
        if not self._objc_helper:
            self._objc_helper = ObjcRuntimeDataParser(self.binary)
        return self._objc_helper

    @classmethod
    def get_analyzer(cls, bin: MachoBinary) -> 'MachoAnalyzer':
        """Get a cached analyzer for a given MachoBinary
        """
        if bin in cls._ACTIVE_ANALYZER_MAP:
            # use cached analyzer for this binary
            return cls._ACTIVE_ANALYZER_MAP[bin]
        return MachoAnalyzer(bin)

    def objc_classes(self) -> List[ObjcClass]:
        """Return the List of classes and categories implemented within the binary
        """
        return self.objc_helper.classes

    def objc_categories(self) -> List[ObjcCategory]:
        """Return the List of categories implemented within the app
        """
        all_classes = self.objc_classes()
        categories: List[ObjcCategory] = [c for c in all_classes if type(c) == ObjcCategory]
        return categories

    def get_conformed_protocols(self) -> List[ObjcProtocol]:
        """Return the List of protocols to which code within the binary conforms
        """
        return self.objc_helper.protocols

    @property
    def dyld_info_parser(self) -> DyldInfoParser:
        if self._dyld_info_parser:
            return self._dyld_info_parser
        self._dyld_info_parser = DyldInfoParser(self.binary)
        return self._dyld_info_parser

    @property
    def dyld_bound_symbols(self) -> Dict[VirtualMemoryPointer, DyldBoundSymbol]:
        """Return a Dict of each imported dyld stub to the corresponding symbol to be bound at runtime.
        """
        return self.dyld_info_parser.dyld_stubs_to_symbols

    @property
    def imp_stubs_to_symbol_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of callable implementation stubs to the names of the imported symbols they correspond to.
        """
        if self._imported_symbol_addresses_to_names:
            return self._imported_symbol_addresses_to_names

        symbol_name_map = {}
        stubs = self.imp_stubs
        stub_map = self.dyld_bound_symbols

        unnamed_stub_count = 0
        for stub in stubs:
            if stub.destination in stub_map:
                symbol_name = stub_map[stub.destination].name
                symbol_name_map[stub.address] = symbol_name
            else:
                # add in stub which is not backed by a named symbol
                # a stub contained in the __stubs section that was not backed by a named symbol was first
                # encountered in com.intuit.mobilebanking01132.app/PlugIns/CMA Balance Widget.appex/CMA Balance Widget
                name = f'unnamed_stub_{unnamed_stub_count}'
                unnamed_stub_count += 1
                symbol_name_map[stub.destination] = name

        self._imported_symbol_addresses_to_names = symbol_name_map
        return symbol_name_map
    
    @property
    def imported_symbols_to_symbol_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of imported symbol pointers to their names.
        These symbols are not necessarily callable, but may rather be imported classes, for example.
        Inverse of MachoAnalyzer.imported_symbol_names_to_pointers()
        """
        return {addr: x.name for addr, x in self.dyld_bound_symbols.items()}

    @property
    def imported_symbol_names_to_pointers(self) -> Dict[str, VirtualMemoryPointer]:
        """Return a Dict of imported symbol names to their pointers.
        These symbols are not necessarily callable.
        Inverse of MachoAnalyzer.imported_symbol_names_to_pointers()
        """
        return {x.name: addr for addr, x in self.dyld_bound_symbols.items()}

    def symbol_name_for_branch_destination(self, branch_address: VirtualMemoryPointer) -> str:
        """Get the associated symbol name for a given branch destination
        """
        if branch_address in self.imp_stubs_to_symbol_names:
            return self.imp_stubs_to_symbol_names[branch_address]
        raise RuntimeError('Unknown branch destination {}. Is this a local branch?'.format(
            hex(branch_address)
        ))

    def _disassemble_region(self, start_address: VirtualMemoryPointer, size: int) -> List[CsInsn]:
        """Disassemble the executable code in a given region into a list of CsInsn objects
        """
        func_str = bytes(self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size))
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        return instructions

    def get_function_instructions(self, start_address: VirtualMemoryPointer) -> List[CsInsn]:
        """Get a list of disassembled instructions for the function beginning at start_address
        """
        from strongarm.objc.dataflow import determine_function_boundary

        if start_address in self._cached_function_boundaries:
            end_address = self._cached_function_boundaries[start_address]
        else:
            # limit functions to 8kb
            max_function_size = 0x2000
            binary_data = bytes(self.binary.get_content_from_virtual_address(start_address, max_function_size))
            # not in cache. calculate function boundary, then cache it
            # add 1 instruction size to the end address so the last instruction is included in the function scope
            end_address = determine_function_boundary(binary_data, start_address) + MachoBinary.BYTES_PER_INSTRUCTION
            self._cached_function_boundaries[start_address] = end_address

        instructions = self._disassemble_region(start_address, end_address - start_address)
        return instructions

    def imp_for_selref(self, selref_ptr: VirtualMemoryPointer) -> Optional[VirtualMemoryPointer]:
        selector = self.objc_helper.selector_for_selref(selref_ptr)
        if not selector:
            return None
        return selector.implementation

    def selector_for_selref(self, selref_ptr: VirtualMemoryPointer) -> Optional[ObjcSelector]:
        return self.objc_helper.selector_for_selref(selref_ptr)

    def get_method_imp_addresses(self, selector: str) -> List[VirtualMemoryPointer]:
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        return self.objc_helper.get_method_imp_addresses(selector)

    if TYPE_CHECKING:   # noqa
        from strongarm.objc import ObjcFunctionAnalyzer # type: ignore
        from strongarm.objc import CodeSearch, CodeSearchResult # type: ignore

    def get_imps_for_sel(self, selector: str) -> List['ObjcFunctionAnalyzer']:
        """Retrieve a list of the disassembled function data for every implementation of a provided selector
        Args:
            selector: The selector name who's implementations should be found

        Returns:
            A list of ObjcFunctionAnalyzers corresponding to each found implementation of the provided selector.
        """
        from strongarm.objc import ObjcFunctionAnalyzer # type: ignore

        implementation_analyzers = []
        imp_addresses = self.get_method_imp_addresses(selector)
        for imp_start in imp_addresses:
            imp_instructions = self.get_function_instructions(imp_start)
            function_analyzer = ObjcFunctionAnalyzer(self.binary, imp_instructions)
            implementation_analyzers.append(function_analyzer)
        return implementation_analyzers

    def get_objc_methods(self) -> List['ObjcMethodInfo']:
        """Get a List of ObjcMethodInfo's representing all ObjC methods implemented in the Mach-O.
        """
        from strongarm.objc import ObjcMethodInfo   # type: ignore
        if self._objc_method_list:
            return self._objc_method_list
        method_list = []
        for objc_class in self.objc_classes():
            for objc_sel in objc_class.selectors:
                imp_addr = objc_sel.implementation

                info = ObjcMethodInfo(objc_class, objc_sel, imp_addr)
                method_list.append(info)
        self._objc_method_list = method_list
        return self._objc_method_list

    def search_code(self, code_search: 'CodeSearch') -> List['CodeSearchResult']:
        """Given a CodeSearch object describing rules for matching code, return a List of CodeSearchResult's
        encapsulating instructions which match the described set of conditions.

        The search space of this method includes all known functions within the binary.
        """
        from strongarm.objc import CodeSearchResult # type: ignore
        from strongarm.objc import ObjcFunctionAnalyzer # type: ignore

        DebugUtil.log(self, 'Performing code search on binary with search description:\n{}'.format(
            code_search
        ))

        search_results: List[CodeSearchResult] = []
        entry_point_list = self.get_objc_methods()
        for i, method_info in enumerate(entry_point_list):
            DebugUtil.log(
                self,
                f'search_code: {hex(method_info.imp_addr)} -[{method_info.objc_class.name} {method_info.objc_sel.name}]'
            )
            try:
                function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.binary, method_info)
                search_results += function_analyzer.search_code(code_search)
            except RuntimeError:
                continue

            checkpoint_index = len(entry_point_list) // 10
            if checkpoint_index and i % checkpoint_index == 0:
                percent_complete = int((i / len(entry_point_list) + 0.01) * 100)
                logging.info(f'binary code search {percent_complete}% complete')
        return search_results

    def class_name_for_class_pointer(self, classref: VirtualMemoryPointer) -> Optional[str]:
        """Given a classref, return the name of the class.
        This method will handle classes implemented within the binary and imported classes.
        """
        if classref in self.imported_symbols_to_symbol_names:
            # imported class
            return self.imported_symbols_to_symbol_names[classref]

        # otherwise, the class is implemented within a binary and we have an ObjcClass for it
        class_location = self.binary.read_word(classref)
        if not class_location:
            # invalid pointer
            return None

        local_class = [x for x in self.objc_classes() if x.raw_struct.binary_offset == class_location]
        if len(local_class):
            return local_class[0].name

        # invalid classref
        return None

    def classref_for_class_name(self, class_name: str) -> Optional[VirtualMemoryPointer]:
        """Given a class name, try to find a classref for it.
        """
        classrefs = [addr for addr, name in self.imported_symbols_to_symbol_names.items() if name == class_name]
        if len(classrefs):
            return classrefs[0]

        # TODO(PT): this is expensive! We should do one analysis step of __objc_classrefs and create a map.
        classref_locations, classref_destinations = self.binary.read_pointer_section('__objc_classrefs')

        # is it a local class?
        class_location = [x.raw_struct.binary_offset for x in self.objc_classes() if x.name == class_name]
        if not len(class_location):
            # unknown class name
            return None
        class_location = class_location[0]

        if class_location not in classref_destinations:
            # unknown class name
            return None

        classref_index = classref_destinations.index(class_location)
        return classref_locations[classref_index]

    def selref_for_selector_name(self, selector_name: str) -> Optional[VirtualMemoryPointer]:
        return self.objc_helper.selref_for_selector_name(selector_name)

    def strings(self) -> Set[str]:
        """Return the list of strings in the binary's __cstring section.
        """
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        # This method should cache its result.
        if '__cstring' not in self.binary.sections:
            return set()

        strings_section = self.binary.sections['__cstring']
        strings_content = strings_section.content

        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(strings_content)
        transformed_strings = MachoStringTableHelper.transform_string_section(string_table)
        return set((x.full_string for x in transformed_strings.values()))

    def _stringref_for_cstring(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref in __cstrings for a provided C string.
        If the string is not present in the __cstrings section, this method returns None.
        """
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        if '__cstring' not in self.binary.sections:
            return None
        strings_section = self.binary.sections['__cstring']

        strings_base = strings_section.address
        strings_content = self.binary.sections['__cstring'].content

        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(strings_content)
        transformed_strings = MachoStringTableHelper.transform_string_section(string_table)
        for idx, entry in transformed_strings.items():
            print(f'{hex(strings_base+idx)}: {entry.full_string}')
            if entry.full_string == string:
                # found the string we're looking for
                # the address is the base of __cstring plus the index of the entry
                stringref_address = strings_base + idx
                return stringref_address

        # didn't find the string the user requested
        return None

    def _stringref_for_cfstring(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref in __cfstrings for a provided Objective-C string literal.
        If the string is not present in the __cfstrings section, this method returns None.
        """
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        if '__cfstring' not in self.binary.sections:
            return None

        sizeof_cfstring = sizeof(CFString64) if self.binary.is_64bit else sizeof(CFString32)
        cfstrings_section = self.binary.sections['__cfstring']
        cfstrings_base = cfstrings_section.address

        cfstrings_count = int((cfstrings_section.end_address - cfstrings_section.address) / sizeof_cfstring)
        for i in range(cfstrings_count):
            cfstring_addr = cfstrings_base + (i * sizeof_cfstring)
            cfstring = CFStringStruct(self.binary, cfstring_addr, virtual=True)

            # check if this is the string the user requested
            string_address = cfstring.literal
            if self.binary.read_string_at_address(string_address) == string:
                return VirtualMemoryPointer(cfstring_addr)

        return None

    def stringref_for_string(self, string: str) -> Optional[int]:
        """Try to find the stringref for a provided string.
        If the string is not present in the binary, this method returns None.

        If you are looking for a C string, pass the string with no additional formatting.
        If you are looking for an Objective-C string literal (CFStringRef), enclose your string in @"".
        """
        is_cfstring = False
        if string.startswith('@"'):
            if not string.endswith('"'):
                raise RuntimeError(f'incorrectly formatted ObjC string literal {string}')

            is_cfstring = True
            # trim the @" prefix and the " suffix
            string = string[2:-1]

        if is_cfstring:
            return self._stringref_for_cfstring(string)
        return self._stringref_for_cstring(string)
