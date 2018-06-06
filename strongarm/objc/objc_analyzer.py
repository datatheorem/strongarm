# -*- coding: utf-8 -*-

from enum import Enum
from typing import Text, List, Optional, Dict, Tuple

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


class ObjcMethodInfo(object):
    __slots__ = ['objc_class', 'objc_sel', 'imp_addr']

    def __init__(self, objc_class, objc_sel, imp):
        # type: (ObjcClass, ObjcSelector, int) -> None
        from strongarm.macho import ObjcClass, ObjcSelector
        self.objc_class = objc_class
        self.objc_sel = objc_sel
        self.imp_addr = imp


class RegisterContentsType(Enum):
    FUNCTION_ARG = 0
    IMMEDIATE = 1
    UNKNOWN = 2


class RegisterContents(object):

    def __init__(self, value_type, value):
        # type: (RegisterContentsType, int) -> None
        self.type = value_type
        self.value = value


class ObjcFunctionAnalyzer(object):
    """Provides utility functions for introspecting on a set of instructions which represent a function body.
    As Objective-C is a strict superset of C, ObjcFunctionAnalyzer can also be used on pure C functions.
    """

    def __init__(self, binary, instructions, method_info=None):
        # type: (MachoBinary, List[CsInsn], ObjcMethodInfo) -> None
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

        self._call_targets = None   # type: List[ObjcBranchInstruction]

    def _get_instruction_index_of_address(self, address):
        # type: (int) -> Optional[int]
        """Return the index of an instruction with a provided address within the internal list of instructions
        """
        base_address = self.start_address
        offset = address - base_address
        index = int(offset / MachoBinary.BYTES_PER_INSTRUCTION)
        if 0 <= index < len(self.instructions):
            return index
        return None

    def get_instruction_at_index(self, index):
        # type: (int) -> Optional[CsInsn]
        """Get the instruction at a given index within the function's code, wrapping in ObjcInstruction
        """
        if 0 <= index < len(self.instructions):
            return self.instructions[index]
        return None

    def get_instruction_at_address(self, address):
        # type: (int) -> Optional[CsInsn]
        """Get the Instruction within the analyzed function at a provided address.
        The return will be wrapped in an ObjcInstruction.
        This method will return None if the address is not contained within the analyzed function.
        """
        index = self._get_instruction_index_of_address(address)
        return self.get_instruction_at_index(index)

    def debug_print(self, idx, output):
        # type: (int, Text) -> None
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
    def get_function_analyzer(cls, binary, start_address):
        # type: (MachoBinary, int) -> ObjcFunctionAnalyzer
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
    def get_function_analyzer_for_method(cls, binary, method_info):
        # type: (MachoBinary, ObjcMethodInfo) -> ObjcFunctionAnalyzer
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
    def call_targets(self):
        # type: () -> List[ObjcBranchInstruction]
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
    def function_call_targets(self):
        # type: () -> List[ObjcFunctionAnalyzer]
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

    def search_code(self, code_search):
        # type: (CodeSearch) -> List[CodeSearchResult]
        """Given a CodeSearch object describing rules for matching code, return a List of CodeSearchResult's
        encapsulating instructions which match the described set of conditions.
        """
        from .objc_query import CodeSearch, CodeSearchResult
        minimum_index = 0
        maximum_index = len(self.instructions)
        step = 1

        search_results: List[CodeSearchResult] = []
        for instruction in self.instructions[minimum_index:maximum_index:step]:
            for search_term in code_search.search_terms:
                if isinstance(search_term, CodeSearchTermInstructionIndex):
                    # this term is where minimum_index, maximum_index, step, comes from, along w/ search_backwards flag
                    raise NotImplementedError()

                result = search_term.satisfied(self, instruction)
                if result:
                    search_results.append(result)
        return search_results

    def get_local_branches(self):
        # type: () -> List[ObjcBranchInstruction]
        """Return all instructions in the analyzed function representing a branch to a destination within the function
        """
        local_branches = []
        for target in self.call_targets:
            # find the address of this branch instruction within the function
            if self.is_local_branch(target):
                local_branches.append(target)
        return local_branches

    def search_call_graph(self, code_search):
        # type: (CodeSearch) -> List[CodeSearchResult]
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

        search_results = [] # type: List[CodeSearchResult]
        for func in functions_to_search:
            subsearch = func.search_code(code_search)
            search_results += subsearch
        return search_results

    @classmethod
    def format_instruction(cls, instr):
        # type: (CsInsn) -> Text
        """Stringify a CsInsn for printing
        Args:
            instr: Instruction to create formatted string representation for
        Returns:
            Formatted string representing instruction
        """
        return "{addr}:\t{mnemonic}\t{ops}".format(addr=hex(int(instr.address)),
                                                   mnemonic=instr.mnemonic,
                                                   ops=instr.op_str)

    def track_reg(self, reg):
        # type: (Text) -> List[Text]
        """
        Track the flow of data starting in a register through a list of instructions
        Args:
            reg: Register containing initial location of data
        Returns:
            List containing all registers which contain data originally in reg
        """
        # list containing all registers which hold the same value as initial argument reg
        regs_holding_value = [reg]
        for instr in self.instructions:
            # TODO(pt) track other versions of move w/ suffix e.g. movz
            # do instructions like movz only operate on literals? we only care about reg to reg
            if instr.mnemonic == 'mov':
                if len(instr.operands) != 2:
                    raise RuntimeError('Encountered mov with more than 2 operands! {}'.format(
                        self.format_instruction(instr)
                    ))
                # in mov instruction, operands[0] is dst and operands[1] is src
                src = instr.reg_name(instr.operands[1].value.reg)
                dst = instr.reg_name(instr.operands[0].value.reg)

                # check if we're copying tracked value to another register
                if src in regs_holding_value and dst not in regs_holding_value:
                    # add destination register to list of registers containing value to track
                    regs_holding_value.append(dst)
                # check if we're copying something new into a register previously containing tracked value
                elif dst in regs_holding_value and src not in regs_holding_value:
                    # register being overwrote -- no longer contains tracked value, so remove from list
                    regs_holding_value.remove(dst)
        return regs_holding_value

    # TODO(PT): this should return the branch and the instruction index for caller convenience
    def next_branch_after_instruction_index(self, start_index):
        # type: (int) -> Optional[ObjcBranchInstruction]

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

    def is_local_branch(self, branch_instruction):
        # type: (ObjcBranchInstruction) -> bool
        # if there's no destination address, the destination is outside the binary, and it couldn't possible be local
        if not branch_instruction.destination_address:
            return False
        return self.start_address <= branch_instruction.destination_address <= self.end_address

    def get_selref_ptr(self, msgsend_instr):
        # type: (ObjcUnconditionalBranchInstruction) -> int
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

    def get_register_contents_at_instruction(self, register: str, instruction: ObjcInstruction) -> RegisterContents:
        from strongarm.objc.dataflow import dataflow
        return dataflow.get_register_contents_at_instruction_fast(register, self, instruction)

    def get_register_contents_at_instruction2(self, register: str, instruction: ObjcInstruction) -> RegisterContents:
        """Analyze instructions backwards from `instruction` to find the data in `register`
        This function will read all instructions until it gathers all data and assignments necessary to determine
        value of the desired register.

        For example, if we have a function like the following:
        15  | adrp x8, #0x1011bc000
        16  | ldr x22, [x8, #0x378]
        ... | ...
        130 | mov x1, x22
        131 | bl objc_msgSend <-- ObjcFunctionAnalyzer.get_register_contents_at_instruction('x1', 131) = 0x1011bc378

        Args:
            register: string containing name of register whose data should be determined
            instruction: the instruction marking the execution point where the register value should be determined

        Returns:
            A RegisterContents instance encapsulating information about the contents of the specified register at the
            specified point of execution
        """
        desired_reg = register
        target_addr = instruction.address
        start_index = self._get_instruction_index_of_address(target_addr)

        # TODO(PT): write CsInsn instructions by hand to make this function easy to test w/ different scenarios
        # List of registers whose values we need to find
        # initially, we need to find the value of whatever the user requested
        unknown_regs = [self.trimmed_register_name(desired_reg)]
        # map of name -> value for registers whose values have been resolved to an immediate
        determined_values = {}
        # map of name -> (name, value). key is register needing to be resolved,
        # value is tuple containing (register containing source value, signed offset from source register)
        needed_links = {}
        # helper to handle instructions that this method doesn't totally parse
        # when we detect an instruction like add x0, x0, #0xf60, instead of trying to handle it we just keep track of
        # the #0xf60 and add it to the final value of x0 at the end of the operation
        extra_offset = 0

        # some instructions will have the same format as register transformations,
        # but are actually unrelated to what we're looking for
        # for example, str x1, [sp, #0x38] would be identified by this function as moving something from sp into
        # x1, but with that particular instruction it's the other way around: x1 is being stored somewhere offset
        # from sp.
        # to avoid this bug, we need to exclude some instructions from being looked at by this method.
        excluded_instructions = [
            'str',
        ]
        # let's also skip any branch instruction, because they won't be necessary for determining a register value
        excluded_instructions += ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS

        # find data starting backwards from start_index
        # TODO(PT): instead of blindly going through instructions backwards,
        # only follow possible code paths split into basic blocks from ObjcBasicBlock
        for instr in self.instructions[start_index::-1]:
            # still looking for anything?
            if len(unknown_regs) == 0:
                # found everything we need
                break

            # skip instructions we want to ignore
            if instr.mnemonic in excluded_instructions:
                continue

            # we only care about instructions that could be moving data between registers
            # therefore, the minimum number of operands an instruction we're interested in could have is 2
            operands = instr.operands
            if len(operands) < 2:
                continue

            # ignore instructions accessing vector registers
            if ObjcInstruction.instruction_uses_vector_registers(instr):
                continue

            dst = operands[0]
            src = operands[1]

            # we're only interested in instructions whose destination is a register
            if dst.type != ARM64_OP_REG:
                continue

            dst_reg_name = self.trimmed_register_name(instr.reg_name(dst.value.reg))

            # is this register needed for us to determine the value of the requested register?
            if dst_reg_name not in unknown_regs:
                continue

            # src might not actually be the first operand
            # this could be an instruction like 'orr', whose invocation might look like this:
            # orr x1, wzr, #0x2
            # here, wzr is used as a 'trick' and the real source is the third operand
            # try to detect this pattern
            # zr indicates zero-register
            if len(operands) > 2:
                src2 = operands[2]
                if src.type == ARM64_OP_REG:
                    src_reg_name = self.trimmed_register_name(instr.reg_name(src.value.reg))
                    if src_reg_name == 'zr':
                        # skip over zero register and set source to third operand
                        src = operands[2]
                    # we might see an instruction like add x0, x0, #0xf60
                    # in this case, x0 is both the source and dest, but for our purposes it's the dest
                    # TODO(PT): handle instructions with 2 source operands (like add)
                    elif src2.type == ARM64_OP_IMM:
                        # ensure we're handling an instruction where the first 2 registers are the same
                        # we don't know how to handle the case where they're different registers
                        if dst_reg_name != src_reg_name:
                            return RegisterContents(RegisterContentsType.UNKNOWN, 0)
                        extra_offset += src2.value.imm
                        continue

            if src.type == ARM64_OP_IMM:
                # we now know the immediate value in dst_reg_name
                # remove it from unknown list
                unknown_regs.remove(dst_reg_name)
                # add it to known list, along with its value
                determined_values[dst_reg_name] = src.value.imm
            elif src.type == ARM64_OP_REG:
                # we now need the value of src before dst can be determined
                # move dst from list of unknown registers to list of registers waiting for another value
                unknown_regs.remove(dst_reg_name)
                src_reg_name = self.trimmed_register_name(instr.reg_name(src.value.reg))

                # do we already know the exact value of the source?
                if src_reg_name in determined_values:
                    # value of dst will just be whatever src contains
                    dst_value = determined_values[src_reg_name]
                    determined_values[dst_reg_name] = dst_value
                # is the source the zero register?
                elif src_reg_name == 'zr':
                    # value of dst will be 0
                    dst_value = 0
                    determined_values[dst_reg_name] = dst_value
                else:
                    # we'll need to resolve src before we can know dst,
                    # add dst -> src to links list
                    needed_links[dst_reg_name] = src_reg_name, 0
                    # and add src to registers to search for
                    unknown_regs.append(src_reg_name)
            elif src.type == ARM64_OP_MEM:
                # an instruction with an operand of type ARM64_OP_MEM might look like:
                # ldr x1, [x3, #0x1000]
                # here, the bracketed portion is accessible through src.mem, which has a reg base and imm disp property
                src_reg_name = self.trimmed_register_name(instr.reg_name(src.mem.base))
                # dst is being assigned to the value of another register, plus a signed offset
                unknown_regs.remove(dst_reg_name)
                if src_reg_name in determined_values:
                    # we know dst value is value in src plus an offset,
                    # and we know what's in source
                    # we now know the value of dst
                    dst_value = determined_values[src_reg_name] + src.mem.disp
                    determined_values[dst_reg_name] = dst_value
                else:
                    # we must find src's value to resolve dst
                    unknown_regs.append(src_reg_name)
                    # add dst -> src + offset to links list
                    needed_links[dst_reg_name] = src_reg_name, src.mem.disp

        # if any of the data dependencies for our desired register uses the stack pointer,
        # there's no way we can resolve the value.
        stack_pointer_reg = 'sp'
        if stack_pointer_reg in needed_links or stack_pointer_reg in unknown_regs:
            # DebugUtil.log(self, f'{hex(int(target_addr))}: {desired_reg} = stack dependent')
            return RegisterContents(RegisterContentsType.UNKNOWN, 0)

        # once we've broken out of the above loop, we should have all the values we need to compute the
        # final value of the desired register.

        # if we broke out of the above loop and there is still content in unknown_regs,
        # the desired value must have been an argument to the function
        if len(unknown_regs):
            # if the above assumption is correct, there should only be 1 reg in unknown_regs
            if len(unknown_regs) > 1:
                DebugUtil.log(self, 'Exited loop with unknown list! instr 0 {} idx {} unknown {} links {} known {}'.format(
                    hex(int(self.start_address)),
                    start_index,
                    unknown_regs,
                    needed_links,
                    determined_values,
                ))
                raise RuntimeError('Data-flow loop exited before all unknowns were marked {}'.format(unknown_regs))

            arg_index = int(unknown_regs[0])

            # DebugUtil.log(self, f'{hex(int(target_addr))}: {desired_reg} = function arg #{arg_index}')
            return RegisterContents(RegisterContentsType.FUNCTION_ARG, arg_index)

        # for every register in the waiting list,
        # cross reference all its dependent variables to calculate the final value
        final_register_value = self._resolve_register_value_from_data_links(
            desired_reg,
            needed_links,
            determined_values
        )
        # handle residual
        final_register_value += extra_offset

        # DebugUtil.log(self, f'{hex(int(target_addr))}: {desired_reg} = {hex(final_register_value)}')
        return RegisterContents(RegisterContentsType.IMMEDIATE, final_register_value)

    def _resolve_register_value_from_data_links(self, desired_reg, links, resolved_registers):
        # type: (Text, Dict[Text, Tuple[Text, int]], Dict[Text, int]) -> int
        """Resolve data dependencies for each register to find final value of desired_reg
        This method will throw an Exception if the arguments cannot be resolved.

        Args:
              desired_reg: string containing name of register whose value should be determined
              links: mapping of register data dependencies. For example, x1's value might be x22's value plus an
                  offset of 0x300, so links['x1'] = ('x22', 0x300)
              resolved_registers: mapping of registers whose final value is already known

        Returns:
            The final value contained in desired_reg after resolving all data dependencies
        """

        if len(resolved_registers) == 0:
            raise RuntimeError('need at least one known value to resolve data dependencies')

        desired_reg = self.trimmed_register_name(desired_reg)
        if desired_reg not in links and desired_reg not in resolved_registers:
            raise RuntimeError('invalid data set? desired_reg {} can\'t be determined from '
                               'links {}, resolved_registers {}'.format(desired_reg,
                                                                        links,
                                                                        resolved_registers))

        # do we know the value of this register?
        if desired_reg in resolved_registers:
            # desired_reg is a known immediate
            return resolved_registers[desired_reg]

        # 'desired_reg' is the value of 'source_reg', plus 'offset'
        # to determine value in desired_reg,
        # we must find the value of source_reg, and then apply the offset
        source_reg, offset = links[desired_reg]

        # resolve source reg value, then add offset
        source_reg_val = self._resolve_register_value_from_data_links(source_reg, links, resolved_registers)
        desired_reg_val = source_reg_val + offset

        # this link has been resolved! remove from links list
        links.pop(desired_reg)
        # add to list of known values
        resolved_registers[desired_reg] = desired_reg_val

        # successfully resolved the value!
        return desired_reg_val


class ObjcBlockAnalyzer(ObjcFunctionAnalyzer):

    def __init__(self, binary, instructions, initial_block_reg):
        # type: (MachoBinary, List[CsInsn], Text) -> None
        ObjcFunctionAnalyzer.__init__(self, binary, instructions)

        self.initial_block_reg = initial_block_reg
        self.block_arg_index = int(self.trimmed_register_name(self.initial_block_reg))
        self.invoke_instruction, self.invocation_instruction_index = self.find_block_invoke()

    def find_block_invoke(self):
        # type: () -> Tuple[ObjcInstruction, int]
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
