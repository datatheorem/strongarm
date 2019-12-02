import functools
from typing import List, Tuple, Optional
from subprocess import check_output

from capstone import CsInsn

from strongarm.debug_util import DebugUtil
from strongarm.macho import MachoBinary, VirtualMemoryPointer

from .objc_instruction import (
    ObjcInstruction,
    ObjcBranchInstruction,
    ObjcUnconditionalBranchInstruction
)
from .objc_query import (
    CodeSearch,
    CodeSearchResult
)

from .register_contents import RegisterContents, RegisterContentsType
from .dataflow import get_register_contents_at_instruction_fast


def _is_mangled_cpp_symbol(symbol_name: str) -> bool:
    """Return whether a symbol name appears to be a mangled C++ symbol.
    """
    return any(symbol_name.startswith(prefix) for prefix in ['_Z', '__Z', '___Z'])


def _demangle_cpp_symbol(cpp_symbol: str) -> str:
    """Call into c++filt to demangle the provided mangled C++ symbol name.
    """
    if not _is_mangled_cpp_symbol(cpp_symbol):
        return cpp_symbol

    original_symbol = cpp_symbol

    # Linux's c++filt doesn't like the clang-specific "_block_invoke" which is tacked onto ObjC++ blocks.
    # Trim this off and add it back after demangling the symbol
    is_block = False
    block_index = ''
    if '_block_invoke' in cpp_symbol:
        is_block = True
        cpp_symbol, block_index_str = cpp_symbol.split('_block_invoke')
        # Some blocks have an index
        if block_index_str.isnumeric():
            block_index = f' {int(block_index_str)}'

    # XXX(PT): We observe that c++filt doesn't work if there are too many leading underscores
    # Try demangling multiple times, trimming a leading underscore each time until success (up to 3 times)
    for _ in range(3):
        # If demangling fails, allow the exception to propagate up. This can alert us to scanner issues.
        demangled_symbol = check_output(f'c++filt -_ {cpp_symbol}', shell=True).decode().strip()
        # Was the symbol demangled?
        if demangled_symbol != cpp_symbol:
            if is_block:
                demangled_symbol = f'block{block_index} in {demangled_symbol}'
            return demangled_symbol
        else:
            # Trim an underscore and try again if possible
            if not cpp_symbol.startswith('_'):
                break
            cpp_symbol = cpp_symbol[1:]

    # Failed to demangle, return the original symbol name
    return original_symbol


class ObjcMethodInfo:
    from strongarm.macho import ObjcClass, ObjcSelector
    __slots__ = ['objc_class', 'objc_sel', 'imp_addr']

    def __init__(self, objc_class: 'ObjcClass', objc_sel: 'ObjcSelector', imp: Optional[VirtualMemoryPointer]) -> None:
        self.objc_class = objc_class
        self.objc_sel = objc_sel
        self.imp_addr = imp

    def __repr__(self) -> str:
        return f'-[{self.objc_class.name} {self.objc_sel.name}]'


class BasicBlock:
    def __init__(self, start_address: VirtualMemoryPointer, end_address: VirtualMemoryPointer) -> None:
        """Represents a basic-block of assembly code.

        A 'basic block' is a unit of assembly code with no branching except for the last instruction.
        In other words, it is the smallest unit of callable code - a subroutine.
        There is a single entry point, and single exit point.

        The start and end addresses are inclusive.
        """
        self.start_address = start_address
        self.end_address = end_address


class ObjcFunctionAnalyzer:
    """Provides utility functions for introspecting on a set of instructions which represent a function body.
    As Objective-C is a strict superset of C, ObjcFunctionAnalyzer can also be used on pure C functions.
    """

    def __init__(self, binary: MachoBinary, instructions: List[CsInsn], method_info: ObjcMethodInfo = None) -> None:
        from strongarm.macho import MachoAnalyzer
        try:
            self.start_address = VirtualMemoryPointer(instructions[0].address)
            last_instruction = instructions[len(instructions) - 1]
            self.end_address = VirtualMemoryPointer(last_instruction.address)
        except IndexError:
            # this method must have just been a stub with no real instructions!
            self.start_address = VirtualMemoryPointer(0)
            self.end_address = VirtualMemoryPointer(0)

        self.binary = binary
        self.macho_analyzer = MachoAnalyzer.get_analyzer(binary)
        self.instructions = instructions
        self.method_info = method_info

        self._call_targets: Optional[List[ObjcBranchInstruction]] = None

        # Find basic-block-boundaries upfront
        self.basic_blocks = self._find_basic_blocks()

    def _get_instruction_index_of_address(self, address: VirtualMemoryPointer) -> Optional[int]:
        """Return the index of an instruction with a provided address within the internal list of instructions
        """
        base_address = self.start_address
        offset = address - base_address
        index = int(offset / MachoBinary.BYTES_PER_INSTRUCTION)
        if 0 <= index < len(self.instructions):
            return index
        return None

    def get_instruction_at_index(self, index: int) -> Optional[CsInsn]:
        """Get the instruction at a given index within the function's code, wrapping in ObjcInstruction
        """
        if 0 <= index < len(self.instructions):
            return self.instructions[index]
        return None

    def get_instruction_at_address(self, address: VirtualMemoryPointer) -> Optional[CsInsn]:
        """Get the Instruction within the analyzed function at a provided address.
        The return will be wrapped in an ObjcInstruction.
        This method will return None if the address is not contained within the analyzed function.
        """
        index = self._get_instruction_index_of_address(address)
        if index is None:
            return None
        return self.get_instruction_at_index(index)

    def debug_print(self, idx: int, output: str) -> None:
        """Helper function to pretty-print debug logs

        Args:
            idx: instruction offset within function the message references
            output: string to output to debug log
        """
        if not len(self.instructions):
            DebugUtil.log(self, f'func(stub) {output}')
        else:
            func_base = self.start_address
            instruction_address = func_base + (idx * MachoBinary.BYTES_PER_INSTRUCTION)
            DebugUtil.log(self, f'func({hex(int(instruction_address))}) {output}')

    def get_symbol_name(self) -> str:
        """Return a objective-c class/method, c function, or sub_address-style string representing the name of
            this block of code.
        """
        if self.method_info:
            return f'-[{self.method_info.objc_class.name} {self.method_info.objc_sel.name}]'
        else:
            # Not an Objective-C method. Try to find a symbol name that matches the address
            strtbl_sym_name = self.macho_analyzer.crossref_helper.get_symbol_name_for_address(
                VirtualMemoryPointer(self.start_address)
            )

            if strtbl_sym_name:
                # Demangle C++ symbols when applicable
                if _is_mangled_cpp_symbol(strtbl_sym_name):
                    strtbl_sym_name = _demangle_cpp_symbol(strtbl_sym_name)

                return strtbl_sym_name

        # Fallback
        # We don't want to format the procedure as sub_<address>, because we use the output of this method to
        # report code locations, and the address of the same procedure might change between subsequent binary builds.
        return '_unsymbolicated_function'

    @classmethod
    def get_function_analyzer(cls, binary: MachoBinary, start_address: VirtualMemoryPointer) -> 'ObjcFunctionAnalyzer':
        """Get the shared analyzer for the function at start_address in the binary.

        This method uses a cached MachoAnalyzer if available, which is more efficient than analyzing the
        same binary over and over. Therefore, this method should be used when an ObjcFunctionAnalyzer is needed,
        instead of constructing it yourself.

        Args:
            binary: The MachoBinary containing a function at start_address
            start_address: The entry point address for the function to be analyzed

        Returns:
            An ObjcFunctionAnalyzer suitable for introspecting a block of code.
        """
        from strongarm.macho.macho_analyzer import MachoAnalyzer
        analyzer = MachoAnalyzer.get_analyzer(binary)
        instructions = analyzer.get_function_instructions(start_address)
        return ObjcFunctionAnalyzer(binary, instructions)

    @classmethod
    def get_function_analyzer_for_method(cls,
                                         binary: MachoBinary,
                                         method_info: ObjcMethodInfo) -> 'ObjcFunctionAnalyzer':
        """Get the shared analyzer describing an Objective-C method within the Mach-O binary
        This method performs the same caching as get_function_analyzer()

        Args:
            binary: The MachoBinary containing a function at method_info.imp_addr
            method_info: The ObjcMethodInfo describing the IMP to be analyzed

        Returns:
            An ObjcFunctionAnalyzer suitable for introspecting the provided method

        Raises:
            ValueError: Could not get function instructions for the provided method
        """
        # TODO(PT): it seems like this & related methods should be moved to MachoAnalyzer
        if not method_info.imp_addr:
            raise ValueError(f'Could not get method implementation address for {method_info}')

        from strongarm.macho.macho_analyzer import MachoAnalyzer
        analyzer = MachoAnalyzer.get_analyzer(binary)
        instructions = analyzer.get_function_instructions(method_info.imp_addr)
        return ObjcFunctionAnalyzer(binary, instructions, method_info=method_info)

    @classmethod
    def get_function_analyzer_for_signature(cls,
                                            binary: MachoBinary,
                                            class_name: str,
                                            sel_name: str) -> 'ObjcFunctionAnalyzer':
        from strongarm.macho.macho_analyzer import MachoAnalyzer
        analyzer = MachoAnalyzer.get_analyzer(binary)
        for objc_cls in analyzer.objc_classes():
            if objc_cls.name == class_name:
                for sel in objc_cls.selectors:
                    if sel.name == sel_name:
                        # XXX(PT): where are the method info's normally stored? Can we grab it from there?
                        method_info = ObjcMethodInfo(objc_cls, sel, sel.implementation)
                        return ObjcFunctionAnalyzer.get_function_analyzer_for_method(binary, method_info)
        raise RuntimeError(f'No found function analyzer for -[{class_name} {sel_name}]')

    @property
    def call_targets(self) -> List[ObjcBranchInstruction]:
        """Return the List of all branch instructions within the source function.
        """
        # Use cached list if available
        if self._call_targets is not None:
            return self._call_targets

        # Extract the list of branch instructions in the function
        branches_in_function: List[ObjcBranchInstruction] = []
        for idx, instr in enumerate(self.instructions):
            if ObjcBranchInstruction.is_branch_instruction(instr):
                branches_in_function.append(ObjcBranchInstruction.parse_instruction(
                    self, 
                    instr,
                    container_function_boundary=(self.start_address, self.end_address)
                ))

        self._call_targets = branches_in_function
        return self._call_targets

    @property
    def function_call_targets(self) -> List['ObjcFunctionAnalyzer']:
        """Find List of function analyzers representing functions reachable from the source function.

        This excludes other branch destinations, such as objc_msgSend calls to methods implemented outside this
        binary, or local branching within the source function.
        """
        call_targets = []
        for target in self.call_targets:
            # don't try to follow calls to functions defined outside this binary
            if target.is_external_c_call and not target.is_msgSend_call:
                continue
            # don't try to follow path if it's an internal branch (i.e. control flow within this function)
            # any internal branching will eventually be covered by call_targets,
            # so there's no need to follow twice
            if self.is_local_branch(target):
                continue
            # might be objc_msgSend to object of class defined outside binary
            if target.is_external_objc_call:
                continue
            call_targets.append(ObjcFunctionAnalyzer.get_function_analyzer(self.binary, target.destination_address))
        return call_targets

    def search_code(self, code_search: CodeSearch) -> List[CodeSearchResult]:
        """Given a CodeSearch object describing rules for matching code, return a List of CodeSearchResult's
        encapsulating instructions which match the described set of conditions.
        """
        from .objc_query import CodeSearchResult

        search_results: List[CodeSearchResult] = []
        for instruction in self.instructions:
            result = code_search.satisfied(self, instruction)
            if result:
                search_results.append(result)
        return search_results

    def get_local_branches(self) -> List[ObjcBranchInstruction]:
        """Return all instructions in the analyzed function representing a branch to a destination within the function
        """
        local_branches = []
        for target in self.call_targets:
            # find the address of this branch instruction within the function
            if self.is_local_branch(target):
                local_branches.append(target)
        return local_branches

    def search_call_graph(self, code_search: CodeSearch) -> List[CodeSearchResult]:
        """Search the entire executable code graph beginning from this function analyzer for a query.

        Given a CodeSearch object describing rules for matching code, return a List of CodeSearchResult's
        encapsulating instructions which match the described set of conditions.

        The search space of this method is all functions which are reachable from any code path from the source function
        analyzer.
        """
        functions_to_search = [self]
        reachable_functions = self.function_call_targets
        while len(reachable_functions) > 0:
            function_analyzer = reachable_functions[0]
            reachable_functions.remove(function_analyzer)
            functions_to_search.append(function_analyzer)
            reachable_functions += function_analyzer.function_call_targets

        search_results: List[CodeSearchResult] = []
        for func in functions_to_search:
            subsearch = func.search_code(code_search)
            search_results += subsearch
        return search_results

    @classmethod
    def format_instruction(cls, instr: CsInsn) -> str:
        """Stringify a CsInsn for printing
        Args:
            instr: Instruction to create formatted string representation for
        Returns:
            Formatted string representing instruction
        """
        return f'{hex(int(instr.address))}:\t{instr.mnemonic}\t{instr.op_str}'

    def is_local_branch(self, branch_instruction: ObjcBranchInstruction) -> bool:
        # if there's no destination address, the destination is outside the binary, and it couldn't possible be local
        if not branch_instruction.destination_address:
            return False
        return self.start_address <= branch_instruction.destination_address <= self.end_address

    def get_objc_selref(self, msgsend_instr: ObjcUnconditionalBranchInstruction) -> VirtualMemoryPointer:
        """Returns the selref pointer at an _objc_msgSend call site.
        When _objc_msgSend is called, x1 contains the selref being messaged.
        The caller is responsible for ensuring this is called at an _objc_msgSend call site.
        """
        if msgsend_instr.raw_instr.mnemonic not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError('get_objc_selref() called on non-branch instruction')

        # at an _objc_msgSend call site, the selref is in x1
        contents = self.get_register_contents_at_instruction('x1', msgsend_instr)
        if contents.type != RegisterContentsType.IMMEDIATE:
            raise RuntimeError(f'could not determine selref ptr, origates in function arg (type {contents.type.name})')
        return VirtualMemoryPointer(contents.value)

    @functools.lru_cache(maxsize=100)
    def get_register_contents_at_instruction(self, register: str, instruction: ObjcInstruction) -> RegisterContents:
        # If basic-block analysis has been done, reduce the dataflow analysis space to the instruction's basic-block
        # Otherwise, use the entire source function as the search space
        for bb in self.basic_blocks:
            if bb.start_address <= instruction.address < bb.end_address:
                # Found the basic block containing the instruction; reduce dataflow analysis space to its head
                dataflow_space_start = bb.start_address
                break
        else:
            # We are in the process of computing basic blocks, so we can't query them. Use the whole function for DFA
            dataflow_space_start = self.start_address

        return get_register_contents_at_instruction_fast(register, self, instruction, dataflow_space_start)

    def _find_basic_blocks(self) -> List['BasicBlock']:
        """Locate the basic-block-boundaries within the source function.
        A 'basic block' is a unit of assembly code with no branching except for the last instruction.
        In other words, it is the smallest unit of callable code - a subroutine.
        There is a single entry point, and single exit point.

        Returns a List of objects encapsulating the basic block boundaries.
        """
        # First basic block begins at the first instruction in the function
        basic_block_start_indexes = [0]
        # Last basic block ends at the last instruction in the function
        basic_block_end_indexes = [len(self.instructions) - 1]

        # Iterate all of the internal-branching within the function to record the basic blocks
        for instr in self.instructions:
            # Ensure we're looking at a branch instruction and pull out the destination address
            if instr.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
                destination_address = instr.operands[0].value.imm
            elif instr.mnemonic in ['cbz', 'cbnz']:
                destination_address = instr.operands[1].value.imm
            elif instr.mnemonic in ['tbz', 'tbnz']:
                destination_address = instr.operands[2].value.imm
            else:
                # Not a branch instruction
                continue

            # Is it a branch to a local label within the function?
            if self.start_address <= destination_address < self.end_address:
                branch_idx = self._get_instruction_index_of_address(instr.address)
                branch_destination_idx = self._get_instruction_index_of_address(destination_address)
                if not branch_idx or not branch_destination_idx:
                    # We somehow were given a branch that isn't function-local - move on
                    DebugUtil.log(self, f'Consistency check failed: {instr.address} is not a local branch of {self}')
                    continue

                # A basic block ends at this branch
                basic_block_end_indexes.append(branch_idx)
                # A different basic block begins just after this branch
                basic_block_start_indexes.append(branch_idx + 1)

                # A basic block begins at the branch destination
                basic_block_start_indexes.append(branch_destination_idx)
                # A basic block ends just before the branch destination
                basic_block_end_indexes.append(branch_destination_idx - 1)

        # Sort arrays of basic block start/end addresses so we can zip them together into basic block ranges
        # Also, remove duplicate entries
        basic_block_start_indexes = sorted(set(basic_block_start_indexes))
        basic_block_end_indexes = sorted(set(basic_block_end_indexes))
        basic_block_indexes = list(zip(basic_block_start_indexes, basic_block_end_indexes))

        # Convert to ObjcBasicBlockLocation objects
        basic_blocks = []
        for start_idx, end_idx in basic_block_indexes:
            start_address = self.start_address + (start_idx * MachoBinary.BYTES_PER_INSTRUCTION)
            end_address = self.start_address + (end_idx * MachoBinary.BYTES_PER_INSTRUCTION)
            bb = BasicBlock(start_address, end_address)
            basic_blocks.append(bb)

        return basic_blocks

    def __repr__(self) -> str:
        return f'({self.get_symbol_name()} @ {self.start_address})'
