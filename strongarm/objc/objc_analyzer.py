# -*- coding: utf-8 -*-
import functools
from typing import List, Optional, Tuple

from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from capstone import CsInsn

from strongarm.debug_util import DebugUtil
from strongarm.macho import MachoBinary

from .objc_instruction import \
    ObjcInstruction, \
    ObjcBranchInstruction, \
    ObjcUnconditionalBranchInstruction
from .objc_query import \
    CodeSearch, \
    CodeSearchResult, \
    CodeSearchTermInstructionIndex
from .register_contents import RegisterContents, RegisterContentsType
from .dataflow import get_register_contents_at_instruction_fast


class ObjcMethodInfo:
    from strongarm.macho import ObjcClass, ObjcSelector
    __slots__ = ['objc_class', 'objc_sel', 'imp_addr']

    def __init__(self, objc_class: 'ObjcClass', objc_sel: 'ObjcSelector', imp: int) -> None:
        self.objc_class = objc_class
        self.objc_sel = objc_sel
        self.imp_addr = imp


class ObjcFunctionAnalyzer(object):
    """Provides utility functions for introspecting on a set of instructions which represent a function body.
    As Objective-C is a strict superset of C, ObjcFunctionAnalyzer can also be used on pure C functions.
    """

    def __init__(self, binary: MachoBinary, instructions: List[CsInsn], method_info=None):
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

        self._call_targets: List[ObjcBranchInstruction] = None

    def _get_instruction_index_of_address(self, address: int) -> Optional[int]:
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

    def get_instruction_at_address(self, address: int) -> Optional[CsInsn]:
        """Get the Instruction within the analyzed function at a provided address.
        The return will be wrapped in an ObjcInstruction.
        This method will return None if the address is not contained within the analyzed function.
        """
        index = self._get_instruction_index_of_address(address)
        return self.get_instruction_at_index(index)

    def debug_print(self, idx: int, output: str) -> None:
        """Helper function to pretty-print debug logs

        Args:
            idx: instruction offset within function the message references
            output: string to output to debug log
        """
        if not len(self.instructions):
            DebugUtil.log(self, 'func(stub) {}'.format(
                output
            ))
        else:
            func_base = self.start_address
            instruction_address = func_base + (idx * MachoBinary.BYTES_PER_INSTRUCTION)
            DebugUtil.log(self, 'func({}) {}'.format(
                hex(int(instruction_address)),
                output
            ))

    @classmethod
    def get_function_analyzer(cls, binary: MachoBinary, start_address: int) -> 'ObjcFunctionAnalyzer':
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
        """
        from strongarm.macho.macho_analyzer import MachoAnalyzer
        analyzer = MachoAnalyzer.get_analyzer(binary)
        instructions = analyzer.get_function_instructions(method_info.imp_addr)
        return ObjcFunctionAnalyzer(binary, instructions, method_info=method_info)

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
            # TODO(PT): this should use a mnemonic and instruction index search predicate
            next_branch = self.next_branch_after_instruction_index(last_branch_idx)
            if not next_branch:
                # parsed every branch in this function
                break

            targets.append(next_branch)
            # record that we checked this branch
            last_branch_idx = self.instructions.index(next_branch.raw_instr)
            # add 1 to last branch so on the next loop iteration,
            # we start searching for branches following this instruction which is known to have a branch
            last_branch_idx += 1

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
        minimum_index = 0
        maximum_index = len(self.instructions)
        step = 1

        search_results: List[CodeSearchResult] = []
        for instruction in self.instructions[minimum_index:maximum_index:step]:
            for search_term in code_search.search_terms:
                result = search_term.satisfied(self, instruction)
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
        return "{addr}:\t{mnemonic}\t{ops}".format(addr=hex(int(instr.address)),
                                                   mnemonic=instr.mnemonic,
                                                   ops=instr.op_str)

    # TODO(PT): this should return the branch and the instruction index for caller convenience
    def next_branch_after_instruction_index(self, start_index: int) -> Optional[ObjcBranchInstruction]:
        for idx, instr in enumerate(self.instructions[start_index::]):
            if ObjcBranchInstruction.is_branch_instruction(instr):
                # found next branch!
                # wrap in ObjcBranchInstruction object
                branch_instr = ObjcBranchInstruction.parse_instruction(self, instr)

                # were we able to resolve the destination of this call?
                # some objc_msgSend calls are too difficult to be parsed, for example if they depend on addresses
                # in the stack. detect this fail case
                if branch_instr.is_msgSend_call and not branch_instr.destination_address:
                    instr_idx = start_index + idx
                    self.debug_print(instr_idx, 'bl <objc_msgSend> target cannot be determined statically')

                return ObjcBranchInstruction.parse_instruction(self, instr)
        return None

    def is_local_branch(self, branch_instruction: ObjcBranchInstruction) -> bool:
        # if there's no destination address, the destination is outside the binary, and it couldn't possible be local
        if not branch_instruction.destination_address:
            return False
        return self.start_address <= branch_instruction.destination_address <= self.end_address

    def get_selref_ptr(self, msgsend_instr: ObjcUnconditionalBranchInstruction) -> int:
        """Retrieve contents of x1 register when control is at provided instruction

        Args:
              msgsend_instr: Instruction at which data in x1 should be found

        Returns:
              Data stored in x1 at execution of msgsend_instr

        """
        if msgsend_instr.raw_instr.mnemonic not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError('get_selref_ptr() called on non-branch instruction')
        if not isinstance(msgsend_instr, ObjcInstruction):
            raise ValueError('wrong type passed to get_selref_ptr()')

        # try fast path to identify selref
        msgsend_idx = self._get_instruction_index_of_address(msgsend_instr.address)
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
            raise RuntimeError('couldn\'t determine selref ptr, origates in function arg (type {})'.format(
                contents.type.name
            ))
        return contents.value

    @functools.lru_cache(maxsize=100)
    def get_register_contents_at_instruction(self, register: str, instruction: ObjcInstruction) -> RegisterContents:
        return get_register_contents_at_instruction_fast(register, self, instruction)


class ObjcBlockAnalyzer(ObjcFunctionAnalyzer):
    # XXX(PT): This class is very old and outdated.
    def __init__(self, binary: MachoBinary, instructions: List[CsInsn], initial_block_reg: str) -> None:
        ObjcFunctionAnalyzer.__init__(self, binary, instructions)

        self.initial_block_reg = initial_block_reg
        self.block_arg_index = int(self.trimmed_register_name(self.initial_block_reg))
        self.invoke_instruction, self.invocation_instruction_index = self.find_block_invoke()

    @staticmethod
    def trimmed_register_name(reg_name: str) -> str:
        """Remove 'x', 'r', or 'w' from general purpose register name
        This is so the register strings 'x22' and 'w22', which are two slices of the same register,
        map to the same register.

        Returns non-GP registers, such as 'sp', as-is.
        Returns NEON registers ('s' 32b registers, 'd' 64b registers, and 'q' 128b registers) as-is.

        Args:
              reg_name: Full register name to trim

        Returns:
              Register name with trimmed size prefix, or unmodified name if not a GP register
        """
        if reg_name[0] in ['x', 'w', 'r']:
            return reg_name[1::]
        return reg_name

    def find_block_invoke(self) -> Tuple[ObjcInstruction, int]:
        """Find instruction where the targeted Block->invoke is loaded into

        Returns:
             Tuple of register containing target Block->invoke, and the index this instruction was found at
        """
        from .objc_query import CodeSearchTermInstructionMnemonic, CodeSearchTermInstructionOperand
        block_invoke_search = CodeSearch([
            CodeSearchTermInstructionMnemonic(self.binary, allow_mnemonics=['blr']),
            CodeSearchTermInstructionOperand(self.binary, operand_index=0, operand_type=ARM64_OP_REG)
        ])
        for search_result in self.search_code(block_invoke_search):
            # in the past, find_block_invoke would find a block load from an instruction like:
            # ldr x8, [<block containing reg>, 0x10]
            # then, we look for a block invoke instruction:
            # blr x8
            # Now, we just look for a blr to a register that has a dependency on the data originally in the register
            # containing the block pointer.
            # this is very likely to work more or less all the time.
            # TODO(PT): CodeSearchTermDataDependency?
            found_branch_instruction = search_result.found_instruction
            contents = self.get_register_contents_at_instruction(self.initial_block_reg, found_branch_instruction)

            trimmed_block_argument_reg = int(self.trimmed_register_name(self.initial_block_reg))
            if contents.type != RegisterContentsType.FUNCTION_ARG:
                # not what we're looking for; branch destination didn't come from function arg
                continue
            if contents.value != trimmed_block_argument_reg:
                # not what we're looking for; branch destination is sourced from the wrong register
                continue
            return found_branch_instruction, self.instructions.index(found_branch_instruction.raw_instr)
        raise RuntimeError('never found block invoke')
