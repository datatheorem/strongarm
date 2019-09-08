import logging
from pathlib import Path
from ctypes import sizeof
from collections import defaultdict

from typing import TYPE_CHECKING
from typing import Set, List, Dict, Optional, Callable
from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM

from strongarm.macho.macho_definitions import VirtualMemoryPointer
from strongarm.macho.arch_independent_structs import CFStringStruct, CFString32, CFString64
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.macho_binary import MachoBinary, InvalidAddressError
from strongarm.macho.dyld_info_parser import DyldInfoParser, DyldBoundSymbol
from strongarm.macho.macho_string_table_helper import MachoStringTableHelper
from strongarm.macho.progress_bar import ConsoleProgressBar

from strongarm.macho.objc_runtime_data_parser import (
    ObjcClass,
    ObjcCategory,
    ObjcProtocol,
    ObjcSelector,
    ObjcRuntimeDataParser,
)

if TYPE_CHECKING:
    from strongarm.objc import (
        ObjcFunctionAnalyzer, ObjcMethodInfo,
        CodeSearch, CodeSearchResult
    )


# Callback invoked when the results for a previously queued CodeSearch have been found.
# This will be dispatched some time after MachoAnalyzer.search_all_code() is called
CodeSearchCallback = Callable[['MachoAnalyzer', 'CodeSearch', List['CodeSearchResult']], None]


class DisassemblyFailedError(Exception):
    """Raised when Capstone fails to disassemble a bytecode sequence.
    """


class MachoAnalyzer:
    # This class does expensive one-time cross-referencing operations
    # Therefore, we want only one instance to exist for any MachoBinary
    # Thus, the preferred interface for getting an instance of this class is MachoAnalyzer.get_analyzer(binary),
    # which utilizes this cache
    # XXX(PT): These references live to process termination, or until clear_cache() is called
    _ANALYZER_CACHE: Dict[MachoBinary, 'MachoAnalyzer'] = {}

    def __init__(self, binary: MachoBinary) -> None:
        from strongarm.objc import CodeSearch

        self.binary = binary
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        # Worker to parse dyld bytecode stream and extract dyld stub addresses to the DyldBoundSymbol they represent
        self._dyld_info_parser: Optional[DyldInfoParser] = None
        # Each __stubs function calls a single dyld stub address, which has a corresponding DyldBoundSymbol.
        # Map of each __stub function to the associated name of the DyldBoundSymbol
        self._imported_symbol_addresses_to_names: Dict[VirtualMemoryPointer, str] = {}

        self.crossref_helper = MachoStringTableHelper(binary)
        self.imported_symbols = self.crossref_helper.imported_symbols
        self.exported_symbols = self.crossref_helper.exported_symbols

        self.imp_stubs = MachoImpStubsParser(binary, self.cs).imp_stubs
        self._objc_helper: Optional[ObjcRuntimeDataParser] = None
        self._objc_method_list: List[ObjcMethodInfo] = []
        self._functions_list: Optional[List[VirtualMemoryPointer]] = None

        self._cached_function_boundaries: Dict[int, int] = {}

        # For efficiency, API clients submit several CodeSearch's to be performed in a batch, instead of sequentially.
        # Iterating the binary's code is an expensive operation, and this allows us to do it just once.
        # This map is where we store the CodeSearch's that are waiting to be executed, and the
        # callbacks which should be invoked once results are found.
        self._queued_code_searches: Dict['CodeSearch', CodeSearchCallback] = {}

        # done setting up, store this analyzer in class cache
        MachoAnalyzer._ANALYZER_CACHE[binary] = self

    @classmethod
    def clear_cache(cls) -> None:
        """Delete cached MachoAnalyzer's
        This can be used when you are finished analyzing a binary set and don't want to retain the cached data in memory
        """
        cls._ANALYZER_CACHE.clear()

    @property
    def objc_helper(self) -> ObjcRuntimeDataParser:
        if not self._objc_helper:
            self._objc_helper = ObjcRuntimeDataParser(self.binary)
        return self._objc_helper

    @classmethod
    def get_analyzer(cls, binary: MachoBinary) -> 'MachoAnalyzer':
        """Get a cached analyzer for a given MachoBinary
        """
        if binary in cls._ANALYZER_CACHE:
            # There exists a MachoAnalyzer for this binary - use it instead of making a new one
            return cls._ANALYZER_CACHE[binary]
        return MachoAnalyzer(binary)

    def objc_classes(self) -> List[ObjcClass]:
        """Return the List of classes and categories implemented within the binary
        """
        return self.objc_helper.classes

    def objc_categories(self) -> List[ObjcCategory]:
        """Return the List of categories implemented within the app
        """
        all_classes = self.objc_classes()
        categories: List[ObjcCategory] = [c for c in all_classes if isinstance(c, ObjcCategory)]
        return categories

    def get_conformed_protocols(self) -> List[ObjcProtocol]:
        """Return the List of protocols to which code within the binary conforms
        """
        return self.objc_helper.protocols

    @property
    def dyld_info_parser(self) -> DyldInfoParser:
        if not self._dyld_info_parser:
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
        raise RuntimeError(f'Unknown branch destination {hex(branch_address)}. Is this a local branch?')

    def _disassemble_region(self, start_address: VirtualMemoryPointer, size: int) -> List[CsInsn]:
        """Disassemble the executable code in a given region into a list of CsInsn objects
        """
        func_str = bytes(self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size))
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        if not len(instructions):
            raise DisassemblyFailedError(f'Failed to disassemble code at {hex(start_address)}:{hex(size)}')
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

    def get_imps_for_sel(self, selector: str) -> List['ObjcFunctionAnalyzer']:
        """Retrieve a list of the disassembled function data for every implementation of a provided selector
        Args:
            selector: The selector name who's implementations should be found

        Returns:
            A list of ObjcFunctionAnalyzers corresponding to each found implementation of the provided selector.
        """
        from strongarm.objc import ObjcFunctionAnalyzer     # type: ignore

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

    def get_functions(self) -> List[VirtualMemoryPointer]:
        """Get a list of the function entry points defined in LC_FUNCTION_STARTS. This includes objective-c methods.
        
        Returns: A list of VirtualMemoryPointers corresponding to each function's entry point.
        """
        if self._functions_list:
            return self._functions_list

        # Cannot do anything without LC_FUNCTIONS_START
        if not self.binary._function_starts_cmd:
            return []
        
        functions_list = []

        fs_start = self.binary._function_starts_cmd.dataoff
        fs_size = self.binary._function_starts_cmd.datasize
        fs_uleb = self.binary.get_contents_from_address(fs_start, fs_size)
        
        address = int(self.binary.get_virtual_base())

        idx = 0
        while idx < fs_size:
            address_delta, idx = self.dyld_info_parser.read_uleb(fs_uleb, idx)

            address += address_delta
            func_entry = VirtualMemoryPointer(address)
            functions_list.append(func_entry)

        self._functions_list = functions_list
        return self._functions_list
        
    def queue_code_search(self, code_search: 'CodeSearch', callback: CodeSearchCallback) -> None:
        """Enqueue a CodeSearch. It will be ran when `search_all_code` runs. `callback` will then be invoked.
        The search space is all known Objective-C entry points within the binary.

        A CodeSearch describes criteria for matching code. A CodeSearchResult encapsulates a CPU instruction and its
        containing source function which matches the criteria of the search.

        Once the CodeSearch has been run over the binary, the `callback` will be invoked, passing the relevant
        info about the discovered code.
        """
        binary_name = Path(self.binary.filename.decode()).name
        logging.info(f'{binary_name} enqueuing CodeSearch {code_search}. Will invoke {callback}')
        self._queued_code_searches[code_search] = callback

    def search_all_code(self) -> None:
        """Iterate every function in the binary, and run each pending CodeSearch over them.
        The search space is all known Objective-C entry points within the binary.

        A CodeSearch describes criteria for matching code. A CodeSearchResult encapsulates a CPU instruction and its
        containing source function which matches the criteria of the search.

        For each search which is executed, this method will invoke the CodeSearchCallback provided when the search
        was requested, with the List of CodeSearchResult's which were found.
        """
        from strongarm.objc import CodeSearch, CodeSearchResult     # type: ignore
        from strongarm.objc import ObjcFunctionAnalyzer     # type: ignore

        # If there are no queued code searches, we have nothing to do
        if not len(self._queued_code_searches):
            return

        binary_name = Path(self.binary.filename.decode()).name
        logging.info(f'Running {len(self._queued_code_searches.keys())} code searches on {binary_name}')

        entry_point_list = self.get_functions()
        search_results: Dict['CodeSearch', List[CodeSearchResult]] = defaultdict(list)

        # Searching all code can be a time-consumptive operation. Provide UI feedback on the progress.
        # This displays a progress bar to stdout. The progress bar will be erased when the context manager exits.
        code_size = self.binary.slice_filesize / 1024 / 1024
        with ConsoleProgressBar(prefix=f'CodeSearch {int(code_size)}mb') as progress_bar:

            # Build analyzers for function entry points.
            for i, entry_address in enumerate(entry_point_list):
                try:
                    # Try to find an objcmethodinfo with matching address
                    matched_method_info = None
                    for method_info in self.get_objc_methods():
                        if method_info.imp_addr == entry_address:
                            matched_method_info = method_info
                            break
                    if matched_method_info:
                        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.binary, matched_method_info)
                    else:
                        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(self.binary, entry_address)
                except DisassemblyFailedError as e:
                    logging.error(f'Failed to disassemble function {hex(entry_address)}: {str(e)}')
                    continue
                
                # Run every code search on this function and record their respective results
                for code_search, callback in self._queued_code_searches.items():
                    search_results[code_search] += function_analyzer.search_code(code_search)

                progress_bar.set_progress(i / len(entry_point_list))

        # Invoke every callback with their respective search results
        for search, results in search_results.items():
            callback = self._queued_code_searches[search]
            callback(self, search, results)

        # We've completed all of the waiting code searches. Drain the queue
        self._queued_code_searches.clear()

    def class_name_for_class_pointer(self, classref: VirtualMemoryPointer) -> Optional[str]:
        """Given a classref, return the name of the class.
        This method will handle classes implemented within the binary and imported classes.
        """
        if classref in self.imported_symbols_to_symbol_names:
            # imported class
            return self.imported_symbols_to_symbol_names[classref]

        # otherwise, the class is implemented within a binary and we have an ObjcClass for it
        try:
            class_location = self.binary.read_word(classref)
        except InvalidAddressError:
            # invalid classref
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
        class_locations = [x.raw_struct.binary_offset for x in self.objc_classes() if x.name == class_name]
        if not len(class_locations):
            # unknown class name
            return None
        class_location = VirtualMemoryPointer(class_locations[0])

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
        strings_section = self.binary.section_with_name('__cstring', '__TEXT')
        if not strings_section:
            return set()

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
        strings_section = self.binary.section_with_name('__cstring', '__TEXT')
        if not strings_section:
            return None

        strings_base = strings_section.address
        strings_content = strings_section.content

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
        cfstrings_section = self.binary.section_with_name('__cfstring', '__DATA')
        if not cfstrings_section:
            return None

        sizeof_cfstring = sizeof(CFString64) if self.binary.is_64bit else sizeof(CFString32)
        cfstrings_base = cfstrings_section.address

        cfstrings_count = int((cfstrings_section.end_address - cfstrings_section.address) / sizeof_cfstring)
        for i in range(cfstrings_count):
            cfstring_addr = cfstrings_base + (i * sizeof_cfstring)
            cfstring = self.binary.read_struct(cfstring_addr, CFStringStruct, virtual=True)

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
