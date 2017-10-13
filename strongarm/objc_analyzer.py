from capstone.arm64 import *
from typing import *
from objc_instruction import *
from macho_binary import MachoBinary
from debug_util import DebugUtil


class ObjcFunctionAnalyzer(object):
    def __init__(self, binary, instructions):
        # type: (MachoBinary, List[CsInsn]) -> None
        try:
            self.start_address = instructions[0].address
            last_idx = len(instructions) - 1
            self.end_address = instructions[last_idx].address
        except IndexError as e:
            raise RuntimeError('ObjcFunctionAnalyzer was passed invalid instructions')

        self.binary = binary
        self.analyzer = MachoAnalyzer.get_analyzer(binary)
        self._instructions = instructions
        self.__call_targets = None

    def debug_print(self, idx, output):
        DebugUtil.log(self, 'func({} + {}) {}'.format(
            hex(int(self._instructions[0].address)),
            hex(idx),
            output
        ))

    @classmethod
    def get_function_analyzer(cls, binary, start_address):
        analyzer = MachoAnalyzer.get_analyzer(binary)
        instructions = analyzer.get_function_instructions(start_address)
        return ObjcFunctionAnalyzer(binary, instructions)

    @property
    def call_targets(self):
        if self.__call_targets is not None:
            return self.__call_targets
        targets = []

        last_branch_idx = 0
        while True:
            next_branch = self.next_branch(last_branch_idx)
            if not next_branch:
                # parsed every branch in this function
                break
            targets.append(next_branch)
            # record that we checked this branch
            last_branch_idx = self._instructions.index(next_branch.raw_instr)
            # add 1 to last branch so on the next loop iteration,
            # we start searching for branches following this instruction which is known to have a branch
            last_branch_idx += 1

        self.__call_targets = targets
        return targets

    def can_execute_call(self, call_address):
        self.debug_print(0, 'recursively searching for invocation of {}'.format(hex(int(call_address))))
        for target in self.call_targets:
            instr_idx = self._instructions.index(target.raw_instr)

            # is this a direct call?
            if target.destination_address == call_address:
                self.debug_print(instr_idx, 'found call to {} at {}'.format(
                    hex(int(call_address)),
                    hex(int(target.address))
                ))
                return True
            # don't try to follow this path if it's an external symbol and not an objc_msgSend call
            if target.is_external_c_call and not target.is_msgSend_call:
                self.debug_print(instr_idx, '{}(...)'.format(
                    target.symbol
                ))
                continue
            # don't try to follow path if it's an internal branch (i.e. control flow within this function)
            # any internal branching will eventually be covered by call_targets,
            # so there's no need to follow twice
            if self.is_local_branch(target):
                self.debug_print(instr_idx, 'local goto -> {}'.format(hex(int(target.destination_address))))
                continue

            # might be objc_msgSend to object of class defined outside binary
            if target.is_external_objc_call:
                self.debug_print(instr_idx, 'objc_msgSend(...) to external class, selref at {}'.format(
                    hex(int(target.selref))
                ))
                continue

            # in debug log, print whether this is a function call or objc_msgSend call
            call_convention = 'objc_msgSend(id, ' if target.is_msgSend_call else 'func('
            self.debug_print(instr_idx, '{}{})'.format(
                call_convention,
                hex(int(target.destination_address)),
            ))

            # recursively check if this destination can call target address
            child_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(self.binary, target.destination_address)
            if child_analyzer.can_execute_call(call_address):
                self.debug_print(instr_idx, 'found call to {} in child code path'.format(
                    hex(int(call_address))
                ))
                return True
        # no code paths reach desired call
        self.debug_print(len(self._instructions), 'no code paths reach {}'.format(
            hex(int(call_address))
        ))
        return False

    @classmethod
    def format_instruction(cls, instr):
        # type: (CsInsn) -> Text
        """Stringify a CsInsn for printing
        :param instr: Instruction to create formatted string representation for
        :return: Formatted string representing instruction
        """
        return "{addr}:\t{mnemonic}\t{ops}".format(addr=hex(int(instr.address)),
                                                   mnemonic=instr.mnemonic,
                                                   ops=instr.op_str)

    def track_reg(self, reg):
        # type: (Text) -> List[Text]
        """
        Track the flow of data starting in a register through a list of instructions
        :param reg: Register containing initial location of data
        :return: List containing all registers which contain data originally in reg
        """
        # list containing all registers which hold the same value as initial argument reg
        regs_holding_value = [reg]
        for instr in self._instructions:
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

    def next_blr_to_reg(self, reg, start_index):
        # type: (Text, int) -> CsInsn
        """
        Search for the next 'blr' instruction to a target register, starting from the instruction at start_index
        :param reg: Register whose 'branch to' instruction should be found
        :param start_index: Instruction index to begin search at
        :return: Index of next 'blr' instruction to reg
        """
        index = start_index
        for instr in self._instructions[start_index::]:
            if instr.mnemonic == 'blr':
                dst = instr.operands[0]
                if instr.reg_name(dst.value.reg) == reg:
                    return instr
            index += 1
        return None

    def next_branch(self, start_index):
        branch_mnemonics = ['b',
                            'bl',
                            'bx',
                            'blx',
                            'bxj',
                            ]
        for instr in self._instructions[start_index::]:
            if instr.mnemonic in branch_mnemonics:
                # found next branch!
                # wrap in ObjcBranchInstr object
                branch_instr = ObjcBranchInstr(self.binary, instr)

                # if this is an objc_msgSend target, patch destination_address to be the address of the targeted IMP
                # note! this means destination_address is *not* the actual destination address of the instruction
                # the *real* destination will be a stub function corresponding to __objc_msgSend, but
                # knowledge of this is largely useless, and the much more valuable piece of information is which function
                # the selector passed to objc_msgSend corresponds to.
                # therefore, replace the 'real' destination address with the requested IMP
                if branch_instr.is_msgSend_call:
                    selref = self.get_selref(branch_instr.raw_instr)
                    # attempt to get an IMP for this selref
                    try:
                        sel_imp = self.analyzer.imp_for_selref(selref)
                    except RuntimeError as e:
                        # if imp_for_selref threw an exception,
                        # then the only explanation is that we read the selref incorrectly
                        # in the assembly of the problematic IMP, this could be the pattern:
                        # adrp x8, #0x1011bc000
                        # ldr x22, [x8, #0x370] <-- this is where our selref gets loaded, into x22
                        # ...
                        # adrp       x8, #0x1011d2000
                        # ldr        x24, [x8, #0xf48] <-- unrelated load we don't care about
                        # mov x1, x22
                        # bl <objc_msgSend>
                        # in the above example, get_selref would have incorrectly caught the _second_ ldr, which
                        # loads something unrelated, instead of the _first_ which contains the correct selref,
                        # since get_selref only searches backwards from objc_msgSend to the first ldr.
                        # TODO(PT): do more rigorous register data flow analysis to fix this bug
                        self.debug_print(0, 'Stronger dataflow analysis required to follow '
                                         'objc_msgSend call at {}'.format(
                            hex(int(branch_instr.raw_instr.address))
                        ))
                        sel_imp = None

                    # if we couldn't find an IMP for this selref,
                    # it is defined in a class outside this binary
                    if not sel_imp:
                        branch_instr.is_external_objc_call = True

                    branch_instr.selref = selref
                    branch_instr.destination_address = sel_imp

                return branch_instr
        return None

    def is_local_branch(self, branch_instruction):
        return self.start_address <= branch_instruction.destination_address <= self.end_address

    def get_selref(self, msgsend_instr):
        # search backwards from objc_msgSend call to SEL load
        msgsend_index = self._instructions.index(msgsend_instr)
        for idx, instr in enumerate(self._instructions[msgsend_index::-1]):
            if instr.mnemonic == 'adrp':
                # this instruction loads the virtual page which this selref is contained in
                # addr is operand 2: adrp x8, 0xdeadbeef
                page = instr.operands[1].value.imm

                # instr after this should be ldr into x1
                # AdobeAcrobat has this in one objc_msgSend invocation:
                # adrp       x21, #0x1011b1000
                # movz       x24, #0x0
                # ldr        x28, [x21, #0xf18]
                # the movz in the middle is unfortunate as it causes the 'unknown pattern' exception to be raised,
                # since we expect an ldr directly after an adrp
                # As a temporary workaround until better data flow analysis is implemented,
                # check the next 2 instructions after adrp
                for i in range(2):
                    function_index = msgsend_index - idx
                    instr2 = self._instructions[function_index + 1 + i]
                    if instr2.mnemonic != 'ldr':
                        continue
                    slide_op = instr2.operands[1]

                    if instr2.mnemonic != 'ldr' or slide_op.type != ARM64_OP_MEM:
                        raise RuntimeError('encountered unknown pattern @ {} while looking for selref'.format(
                            hex(int(instr2.address))
                        ))

                    pageoff = instr2.operands[1].mem.disp
                    selref_ptr_addr = page + pageoff
                    return selref_ptr_addr
                raise RuntimeError('encountered unknown pattern @ {} while looking for selref'.format(
                    hex(int(instr.address))
                ))



class ObjcBlockAnalyzer(ObjcFunctionAnalyzer):
    def __init__(self, binary, instructions, initial_block_reg):
        ObjcFunctionAnalyzer.__init__(self, binary, instructions)

        self.registers_containing_block = self.track_reg(initial_block_reg)
        self.load_reg, self.load_index = self.find_block_load()
        self.invoke_instr = self.find_block_invoke()

    def find_block_load(self):
        """
        Find instruction where Block->invoke is loaded into
        :return: Tuple of register containing Block->invoke, and the index this instruction was found at
        """
        index = 0
        for instr in self._instructions:
            if instr.mnemonic == 'ldr':
                if len(instr.operands) != 2:
                    raise RuntimeError('Encountered ldr with more than 2 operands! {}'.format(
                        self.format_instruction(instr)
                    ))
                # we're looking for an instruction in the format:
                # ldr <reg> [<reg_containing_block>, #0x10]
                # block->invoke is always 0x10 from start of block
                # so if we see the above then we know we're loading the block's executable start addr
                dst = instr.operands[0]
                src = instr.operands[1]
                if src.type == ARM64_OP_MEM:
                    if instr.reg_name(src.mem.base) in self.registers_containing_block and src.mem.disp == 0x10:
                        # found load of block's invoke addr!
                        return instr.reg_name(dst.value.reg), index
            index += 1

    def find_block_invoke(self):
        # type: () -> CsInsn
        return self.next_blr_to_reg(self.load_reg, self.load_index)

    def get_block_arg(self, arg_index):
        # type: (int) -> int
        """
        Starting from the index where a function is called, search backwards for the assigning of
        a register corresponding to function argument at index arg_index
        Currently this function will only detect arguments who are assigned to an immediate value
        :param arg_index: Positional argument index (0 for first argument, 1 for second, etc.)
        :return: Index of instruction where argument is assigned
        """
        desired_register = u'x{}'.format(arg_index)

        invoke_index = self._instructions.index(self.invoke_instr)
        for instr in self._instructions[invoke_index::-1]:
            if instr.mnemonic == 'movz' or instr.mnemonic == 'mov':
                # arg1 will be stored in x1
                dst = instr.operands[0]
                src = instr.operands[1]
                if instr.reg_name(dst.value.reg) == desired_register:
                    # return immediate value if source is not a register
                    if instr.mnemonic == 'movz':
                        return src.value.imm
                    # source is a register, return register name
                    return instr.reg_name(src.value.reg)
