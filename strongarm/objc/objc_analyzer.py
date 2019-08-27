import functools
from typing import List, Optional

from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM
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


class ObjcMethodInfo:
    from strongarm.macho import ObjcClass, ObjcSelector
    __slots__ = ['objc_class', 'objc_sel', 'imp_addr']

    def __init__(self, objc_class: 'ObjcClass', objc_sel: 'ObjcSelector', imp: Optional[VirtualMemoryPointer]) -> None:
        self.objc_class = objc_class
        self.objc_sel = objc_sel
        self.imp_addr = imp

    def __repr__(self) -> str:
        return f'-[{self.objc_class.name} {self.objc_sel.name}]'


class ObjcBasicBlock:
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
            self.start_address = instructions[0].address
            last_instruction = instructions[len(instructions) - 1]
            self.end_address = last_instruction.address
        except IndexError:
            # this method must have just been a stub with no real instructions!
            self.start_address = 0
            self.end_address = 0
            pass

        self.binary = binary
        self.macho_analyzer = MachoAnalyzer.get_analyzer(binary)
        self.instructions = instructions
        self.method_info = method_info

        self._call_targets: Optional[List[CsInsn]] = None

        # Find basic-block-boundaries upfront
        # This will eventually invoke code which accesses `self.basic_blocks` in get_register_contents_for_instruction,
        # so create the attribute before starting.
        self.basic_blocks: List[ObjcBasicBlock] = []
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
        """Find a List of all branch destinations reachable from the source function

        Returns:
            A list of objects encapsulating info about the branch destinations from self.instructions
        """
        # use cached list if available
        if self._call_targets is not None:
            return self._call_targets

        targets = []
        # keep track of the index of the last branch destination we saw
        last_branch_idx = 0

        while True:
            # grab the next branch in front of the last one we visited
            next_branch_idx = self.next_branch_idx_after_instr_idx(last_branch_idx)
            if not next_branch_idx:
                # parsed every branch in this function
                break

            next_branch = ObjcBranchInstruction.parse_instruction(self, self.instructions[next_branch_idx])
            targets.append(next_branch)
            # record that we checked this branch
            # add 1 to last branch so on the next loop iteration,
            # we start searching for branches following this instruction which is known to have a branch
            last_branch_idx = next_branch_idx + 1

        self._call_targets = targets
        return targets

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

    def next_branch_idx_after_instr_idx(self, start_index: int) -> Optional[int]:
        """Returns the index of the next branch instruction in the source function, starting from the specified index.
        """
        for idx, instr in enumerate(self.instructions[start_index::]):
            if ObjcBranchInstruction.is_branch_instruction(instr):
                # found next branch!
                return start_index + idx
        return None

    def is_local_branch(self, branch_instruction: ObjcBranchInstruction) -> bool:
        # if there's no destination address, the destination is outside the binary, and it couldn't possible be local
        if not branch_instruction.destination_address:
            return False
        return self.start_address <= branch_instruction.destination_address <= self.end_address

    def get_selref_ptr(self, msgsend_instr: ObjcUnconditionalBranchInstruction) -> VirtualMemoryPointer:
        """Retrieve contents of x1 register when control is at provided instruction

        Args:
              msgsend_instr: Instruction at which data in x1 should be found

        Returns:
              Data stored in x1 at execution of msgsend_instr

        Raises:
            ValueError: - get_selref_ptr() called on non-branch instruction
                        - wrong type passed to get_selref_ptr()
                        - instruction index not found for address
        """
        if msgsend_instr.raw_instr.mnemonic not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError('get_selref_ptr() called on non-branch instruction')
        if not isinstance(msgsend_instr, ObjcInstruction):
            raise ValueError('wrong type passed to get_selref_ptr()')

        # try fast path to identify selref
        msgsend_idx = self._get_instruction_index_of_address(msgsend_instr.address)
        if not msgsend_idx:
            raise ValueError(f'instruction index not found for address {msgsend_instr.address}')

        search_space_start_idx = msgsend_idx - 3
        search_space_start_idx = max(0, search_space_start_idx)
        adrp_ptr = None
        ldr_val = None
        for instr in self.instructions[search_space_start_idx:msgsend_idx]:
            if instr.mnemonic == 'adrp':
                adrp_ptr = instr.operands[1].value.imm
            elif instr.mnemonic == 'ldr':
                src = instr.operands[1]
                if src.type == ARM64_OP_IMM:
                    ldr_val = src.value.imm
                    break
                elif src.type == ARM64_OP_MEM:
                    ldr_val = src.value.mem.disp
                    break

        if adrp_ptr and ldr_val:
            selref_ptr = adrp_ptr + ldr_val
            return selref_ptr

        # retrieve whatever data is in x1 at this msgSend call
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

    def _find_basic_blocks(self) -> List['ObjcBasicBlock']:
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
        for branch in self.get_local_branches():
            branch_idx = self._get_instruction_index_of_address(branch.address)
            branch_destination_idx = self._get_instruction_index_of_address(branch.destination_address)
            if not branch_idx or not branch_destination_idx:
                # We somehow were given a branch that isn't function-local - move on
                DebugUtil.debug(self, f'Consistency check failed: {branch.address} is not a local branch of {self}')
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
            bb = ObjcBasicBlock(VirtualMemoryPointer(self.start_address), start_address, end_address)
            basic_blocks.append(bb)

        return basic_blocks
