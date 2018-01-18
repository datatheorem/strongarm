# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from ctypes import sizeof, c_void_p

from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM
from typing import Text, List, Dict, Optional, Tuple
from typing import TYPE_CHECKING

from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.macho_string_table_helper import MachoStringTableHelper
from strongarm.macho.objc_runtime_data_parser import ObjcRuntimeDataParser, ObjcSelector, ObjcClass
from strongarm import DebugUtil


if TYPE_CHECKING:
    from strongarm.objc import ObjcFunctionAnalyzer, ObjcMethodInfo # type: ignore


class MachoAnalyzer(object):
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

        # data cached by various methods
        self._lazy_symbol_entry_pointers = None # type: List[int]
        self._imported_symbol_map = None    # type: Dict[int, Text]
        self._external_branch_destinations_to_symbol_names = None   # type: Dict[int, Text]
        self._external_symbol_names_to_branch_destinations = None   # type: Dict[Text, int]

        self.crossref_helper = MachoStringTableHelper(bin)
        self.imported_symbols = self.crossref_helper.imported_symbols
        self.exported_symbols = self.crossref_helper.exported_symbols

        self.imp_stubs = MachoImpStubsParser(bin, self.cs).imp_stubs
        self._objc_helper = None    # type: ObjcRuntimeDataParser
        self._objc_method_list = None   # type: List[ObjcMethodInfo]

        self._cached_function_instructions = {} # type: Dict[int, List[CsInsn]]

        # done setting up, store this analyzer in class cache
        MachoAnalyzer.active_analyzer_map[bin] = self

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
        # type: () -> List[ObjcClass]
        return self.objc_helper.classes

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
        if self._lazy_symbol_entry_pointers:
            return self._lazy_symbol_entry_pointers

        section_pointers = []   # type: List[int]
        if '__la_symbol_ptr' not in self.binary.sections:
            return section_pointers

        lazy_sym_section = self.binary.sections['__la_symbol_ptr']
        # __la_symbol_ptr is just an array of pointers
        # the number of pointers is the size, in bytes, of the section, divided by a 64b pointer size
        sym_ptr_count = int(lazy_sym_section.cmd.size / sizeof(c_void_p))

        # this section's data starts at the file offset field
        section_data_ptr = lazy_sym_section.cmd.addr
        # read every pointer in the table
        for i in range(sym_ptr_count):
            # this addr is the address in the file of this data, plus the slide that the file has requested,
            # to result in the final address that would be referenced elsewhere in this Mach-O
            section_pointers.append(section_data_ptr)
            # go to next pointer in list
            section_data_ptr += sizeof(c_void_p)

        self._lazy_symbol_entry_pointers = section_pointers
        return section_pointers

    @property
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
        if self._imported_symbol_map:
            return self._imported_symbol_map

        imported_symbol_map = {}    # type: Dict[int, Text]
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

            # T1Twitter.framework has several thousand symtab entries whose offset is 0xc00000000
            # I don't know why these are in the symbol table but they clearly don't point to real data
            # if an offset points to a bad index, let's just ignore it
            if offset >= len(symtab):
                continue

            sym = symtab[offset]

            # we now have the Nlist64 symbol for the __la_symbol_ptr entry
            # the starting index of the string within the string table for this symbol is given by the n_strx field
            strtab_idx = sym.n_un.n_strx

            symbol_name = self.crossref_helper.string_table_entry_for_strtab_index(strtab_idx).full_string
            # record this mapping of address to symbol name
            imported_symbol_map[symbol_ptr] = symbol_name

        self._imported_symbol_map = imported_symbol_map
        return imported_symbol_map

    @property
    def external_branch_destinations_to_symbol_names(self):
        # type: () -> Dict[int, Text]
        """Return a Dict of addresses to the external symbols they correspond to
        """
        if self._external_branch_destinations_to_symbol_names:
            return self._external_branch_destinations_to_symbol_names

        symbol_name_map = {}
        stubs = self.imp_stubs
        la_sym_ptr_name_map = self._la_symbol_ptr_to_symbol_name_map

        for stub in stubs:
            symbol_name = la_sym_ptr_name_map[stub.destination]
            symbol_name_map[stub.address] = symbol_name

        self._external_branch_destinations_to_symbol_names = symbol_name_map
        return symbol_name_map

    @property
    def external_symbol_names_to_branch_destinations(self):
        # type: () -> Dict[Text, int]
        """Return a Dict of external symbol names to the addresses they'll be called at
        """
        if self._external_symbol_names_to_branch_destinations:
            return self._external_symbol_names_to_branch_destinations

        call_address_map = {}
        for key in self.external_branch_destinations_to_symbol_names:
            value = self.external_branch_destinations_to_symbol_names[key]
            call_address_map[value] = key

        self._external_symbol_names_to_branch_destinations = call_address_map
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

    def _find_function_boundary(self, start_address, size, instructions):
        # type: (int, int, List[CsInsn]) -> Tuple[List[CsInsn], int]
        """Helper function to search for a function boundary within a given block of executable code

        This function searches from start_address up to start_address + size looking for a set of
        instructions resembling a function boundary. If a function boundary is identified its address will be returned,
        or else 0 will be returned if no boundary was found.
        """

        # transform func_str into list of CsInstr
        if not len(instructions):
            # get executable code in requested region
            func_str = bytes(self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size))
            instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        else:
            # append to instructions
            # figure out the last disasm'd instruction
            last_disassembled_instruction_addr = instructions[-1].address
            disassembled_range = last_disassembled_instruction_addr - instructions[0].address

            # get executable code of remainder
            next_instr_addr = last_disassembled_instruction_addr + 4
            remainder_bytes = size - disassembled_range
            func_str = bytes(self.binary.get_content_from_virtual_address(
                virtual_address=next_instr_addr,
                size=remainder_bytes
            ))
            instructions += [instr for instr in self.cs.disasm(func_str, next_instr_addr)]

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
            elif mnemonic == 'b':
                if next_branch_is_return or not has_modified_lr:
                    end_address = instr.address
                    break

        # long to int
        end_address = int(end_address)
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
        if start_address in self._cached_function_instructions:
            return self._cached_function_instructions[start_address]

        instructions, _, end_address = self._find_function_code(start_address)
        if not end_address:
            raise RuntimeError('Couldn\'t parse function @ {}'.format(start_address))
        self._cached_function_instructions[start_address] = instructions
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
        # type: () -> List[ObjcFunctionAnalyzer]
        """Get a List of ObjcFunctionAnalyzers representing all ObjC methods implemented in the Mach-O.
        """
        from strongarm.objc import ObjcFunctionAnalyzer, ObjcMethodInfo # type: ignore
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
