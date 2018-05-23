# -*- coding: utf-8 -*-
from ctypes import sizeof
from typing import TYPE_CHECKING
from typing import Text, List, Dict, Optional, Tuple
from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM

from strongarm import DebugUtil
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.dyld_info_parser import DyldInfoParser, DyldBoundSymbol
from strongarm.macho.macho_string_table_helper import MachoStringTableHelper
from strongarm.macho.objc_runtime_data_parser import \
    ObjcRuntimeDataParser, \
    ObjcSelector, \
    ObjcClass, \
    ObjcCategory, \
    ObjcProtocol


if TYPE_CHECKING:
    from strongarm.objc import ObjcFunctionAnalyzer, ObjcMethodInfo  # type: ignore


class MachoAnalyzer(object):
    _BYTES_IN_INSTRUCTION = 4

    # keep map of active MachoAnalyzer instances
    # each MachoAnalyzer operates on a single MachoBinary which will never change in the lifecycle of the analyzer
    # also, some MachoAnalyzer operations are expensive, but they only have to be done once per instance
    # so, we only keep one analyzer for each MachoBinary
    active_analyzer_map = {}    # type: Dict[MachoBinary, MachoAnalyzer]

    def __init__(self, bin):
        # type: (MachoBinary) -> None
        self.binary = bin
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        # Worker to parse dyld bytecode stream and extract dyld stub addresses to the DyldBoundSymbol they represent
        self._dyld_info_parser: DyldInfoParser = None
        # Each __stubs function calls a single dyld stub address, which has a corresponding DyldBoundSymbol.
        # Map of each __stub function to the associated name of the DyldBoundSymbol
        self._imported_symbol_addresses_to_names: Dict[int, str] = None

        self.crossref_helper = MachoStringTableHelper(bin)
        self.imported_symbols = self.crossref_helper.imported_symbols
        self.exported_symbols = self.crossref_helper.exported_symbols

        self.imp_stubs = MachoImpStubsParser(bin, self.cs).imp_stubs
        self._objc_helper = None    # type: ObjcRuntimeDataParser
        self._objc_method_list = None   # type: List[ObjcMethodInfo]

        self._cached_function_boundaries = {}   # type: Dict[int, int]

        # done setting up, store this analyzer in class cache
        MachoAnalyzer.active_analyzer_map[bin] = self

    @classmethod
    def clear_cache(cls):
        """Delete cached MachoAnalyzer's
        This can be used when you are finished analyzing a binary set and don't want to retain the cached data in memory
        """
        cls.active_analyzer_map = {}

    @property
    def objc_helper(self):
        # type: () -> ObjcRuntimeDataParser
        if not self._objc_helper:
            self._objc_helper = ObjcRuntimeDataParser(self.binary)
        return self._objc_helper

    @classmethod
    def get_analyzer(cls, bin):
        # type: (MachoBinary) -> MachoAnalyzer
        """Get a cached analyzer for a given MachoBinary
        """
        if bin in cls.active_analyzer_map:
            # use cached analyzer for this binary
            return cls.active_analyzer_map[bin]
        return MachoAnalyzer(bin)

    def objc_classes(self):
        """Return the List of classes and categories implemented within the binary
        """
        # type: () -> List[ObjcClass]
        return self.objc_helper.classes

    def objc_categories(self):
        """Return the List of categories implemented within the app
        """
        all_classes = self.objc_classes()
        categories = [c for c in all_classes if type(c) == ObjcCategory]
        return categories

    def get_conformed_protocols(self):
        """Return the List of protocols to which code within the binary conforms
        """
        # type: () -> List[ObjcProtocol]
        return self.objc_helper.protocols

    @property
    def dyld_info_parser(self) -> DyldInfoParser:
        if self._dyld_info_parser:
            return self._dyld_info_parser
        self._dyld_info_parser = DyldInfoParser(self.binary)
        return self._dyld_info_parser

    @property
    def dyld_bound_symbols(self) -> Dict[int, DyldBoundSymbol]:
        """Return a Dict of each imported dyld stub to the corresponding symbol to be bound at runtime.
        """
        return self.dyld_info_parser.dyld_stubs_to_symbols

    @property
    def imp_stubs_to_symbol_names(self):
        # type: () -> Dict[int, Text]
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
                name = 'unnamed_stub_{}'.format(unnamed_stub_count)
                unnamed_stub_count += 1
                symbol_name_map[stub.destination] = name

        self._imported_symbol_addresses_to_names = symbol_name_map
        return symbol_name_map

    @property
    def imported_symbols_to_symbol_names(self) -> Dict[int, str]:
        """Return a Dict of imported symbol pointers to their names.
        These symbols are not necessarily callable, but may rather be imported classes, for example.
        """
        return {addr: x.name for addr, x in self.dyld_bound_symbols.items()}

    def symbol_name_for_branch_destination(self, branch_address):
        # type: (int) -> Text
        """Get the associated symbol name for a given branch destination
        """
        if branch_address in self.imp_stubs_to_symbol_names:
            return self.imp_stubs_to_symbol_names[branch_address]
        raise RuntimeError('Unknown branch destination {}. Is this a local branch?'.format(
            hex(branch_address)
        ))

    def _disassemble_region(self, start_address, size):
        # type: (int, int) -> List[CsInsn]
        """Disassemble the executable code in a given region into a list of CsInsn objects
        """
        func_str = bytes(self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size))
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        return instructions

    def _find_function_boundary(self, start_address, size, instructions):
        # type: (int, int, List[CsInsn]) -> Tuple[List[CsInsn], int]
        """Helper function to search for a function boundary within a given block of executable code

        This function searches from start_address up to start_address + size looking for a set of
        instructions resembling a function boundary. If a function boundary is identified its address will be returned,
        or else 0 will be returned if no boundary was found.

        Args:
            start_address: The entry point of the function to be analyzed
            size: The maximum size (in bytes) that this function will search for a function exit
            instructions: An empty list, or a list of instructions within the analyzed function that have already
                been disassembled, and will not be disassembled again. Also, this function will only start searching
                from after the last instruction in this list.

        Returns:
            A tuple of a list of disassembled instructions, and an int. If the end-of-function was not found
            within the specified search space, the list will contain all the diassembled instructions from
            [start_address to start_address + size], and the int will be 0 to indicate failure. Otherwise,
            the end-of-function was successfully found, and the list will contain all the instructions within the
            function, and the int will be the end address of the function.
        """

        # we need to keep track of the first instruction we should analyze, so this function doesn't have to keep
        # analyzing the same instructions over and over when the search space increases.
        # if the passed instructions are the empty list (meaning this is the first attempt at finding this function
        # boundary), then we start searching at the first instruction
        if not len(instructions):
            # get executable code in requested region
            next_instr_addr = start_address
            instructions = self._disassemble_region(start_address, size)
        else:
            # append to instructions
            # figure out the last disasm'd instruction
            last_disassembled_instruction_addr = instructions[-1].address
            disassembled_range = last_disassembled_instruction_addr - instructions[0].address

            # we should start searching at the instruction after the last one we previously looked at
            next_instr_addr = last_disassembled_instruction_addr + self._BYTES_IN_INSTRUCTION
            # get executable code of remainder
            remainder_bytes = size - disassembled_range
            instructions += self._disassemble_region(next_instr_addr, remainder_bytes)

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

        # convert next_instr_addr to an index within instructions array
        # this is the difference between next_instr_addr and the address of the entry point, divided by the
        # byte count in an instruction
        first_instr_to_analyze_idx = (next_instr_addr - start_address) / self._BYTES_IN_INSTRUCTION
        first_instr_to_analyze_idx = int(first_instr_to_analyze_idx)
        # traverse instructions, looking for signs of end-of-function
        for instr in instructions[first_instr_to_analyze_idx:]:
            mnemonic = instr.mnemonic
            # ret mnemonic is sure sign we've found end of the function!
            if mnemonic == 'ret':
                end_address = instr.address
                break

            # slightly less strong heuristic
            # in the uncommon case that a function ends in a branch,
            # it *must* have moved something sane into the link register,
            # or else the program would jump to an unreasonable place after the branch.
            # The sole exception to this rule is if a function never modifies the link
            # register in the first place, which is tracked by has_modified_lr.
            # (branching to another function would entail modifying the link register, so this is another way of
            # saying the function is entirely local)
            # we could possibly strengthen the has_modified_lr check by also checking for this pattern:
            # in the prologue, stp ..., x30, [sp, #0x...]
            # then a corresponding ldp ..., x30, [sp, #0x...]
            elif mnemonic == 'ldp':
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
            elif mnemonic in ['bl', 'blx']:
                has_modified_lr = True
            # unconditional branch instruction
            # this could be a local branch, or it could be the last statement in the function
            # we detect which based on the flags set previously while iterating the code
            elif mnemonic == 'b':
                if next_branch_is_return or not has_modified_lr:
                    end_address = instr.address
                    break

        # long to int
        end_address = int(end_address)

        # if we found the end address of the function, trim the instructions list up to the last instruction in the
        # function
        # otherwise, the instructions list will remain the full list of instructions from the start of the function
        # up to the requested search size
        if end_address:
            # trim instructions up to the instruction at end_address
            last_instruction_idx = int((end_address - start_address) / 4)
            instructions = instructions[:last_instruction_idx+1:]
        return instructions, end_address

    def _find_function_code(self, function_address):
        # type: (int) -> Tuple[List[CsInsn], int, int]
        """Determine the boundary of a function with a known start address, and disassemble the code

        The return value will be a tuple of a List of instructions in the function, the start address, and the end
        address.
        """
        # get_content_from_virtual_address wants a size for how much data to grab,
        # but we don't actually know how big the function is!
        # start off by grabbing a small amount of bytes, and keep doubling search area until function boundary is hit
        end_address = 0
        search_size = 0x80
        instructions = []   # type: List[CsInsn]
        while not end_address:
            # place upper limit on search space
            # limit to 32kb of code in a single function
            if search_size == 0x10000:
                raise RuntimeError("Couldn't detect end-of-function within {} bytes for function starting at {}".format(
                    hex(int(search_size/2)),
                    hex(function_address)
                ))
            if search_size >= 0x2000:
                DebugUtil.log(self, 'WARNING: Analyzing large function at {} (search space == {} bytes)'.format(
                    hex(function_address),
                    hex(search_size)
                ))

            instructions, end_address = self._find_function_boundary(function_address, search_size, instructions)
            # double search space
            search_size *= 2
        return instructions, function_address, end_address

    def get_function_instructions(self, start_address):
        # type: (int) -> List[CsInsn]
        """Get a list of disassembled instructions for the function beginning at start_address
        """
        if start_address in self._cached_function_boundaries:
            end_address = self._cached_function_boundaries[start_address]
            instructions = self._disassemble_region(start_address, end_address - start_address)
        else:
            # not in cache. calculate function boundary, then cache it
            instructions, _, end_address = self._find_function_code(start_address)
            self._cached_function_boundaries[start_address] = end_address
        if not end_address:
            raise RuntimeError('Couldn\'t parse function @ {}'.format(start_address))
        return instructions

    def imp_for_selref(self, selref_ptr):
        # type: (int) -> Optional[int]
        selector = self.objc_helper.selector_for_selref(selref_ptr)
        if not selector:
            return None
        return selector.implementation

    def selector_for_selref(self, selref_ptr):
        # type: (int) -> Optional[ObjcSelector]
        return self.objc_helper.selector_for_selref(selref_ptr)

    def get_method_imp_addresses(self, selector):
        # type: (Text) -> List[int]
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        return self.objc_helper.get_method_imp_addresses(selector)

    if TYPE_CHECKING:   # noqa
        from strongarm.objc import ObjcFunctionAnalyzer # type: ignore
        from strongarm.objc import CodeSearch, CodeSearchResult # type: ignore

    def get_imps_for_sel(self, selector):
        # type: (Text) -> List[ObjcFunctionAnalyzer]
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

    def get_objc_methods(self):
        # type: () -> List[ObjcMethodInfo]
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

    def search_code(self, code_search):
        # type: (CodeSearch) -> List[CodeSearchResult]
        """Given a CodeSearch object describing rules for matching code, return a List of CodeSearchResult's
        encapsulating instructions which match the described set of conditions.

        The search space of this method includes all known functions within the binary.
        """
        from strongarm.objc import CodeSearch, CodeSearchResult # type: ignore
        from strongarm.objc import ObjcFunctionAnalyzer # type: ignore

        DebugUtil.log(self, 'Performing code search on binary with search description:\n{}'.format(
            code_search
        ))

        search_results = [] # type: List[CodeSearchResult]
        entry_point_list = self.get_objc_methods()
        for method_info in entry_point_list:
            try:
                function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.binary, method_info)
                search_results += function_analyzer.search_code(code_search)
            except RuntimeError:
                continue
        return search_results
