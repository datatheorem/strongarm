from capstone import *
from capstone.arm64 import *
from typing import *
from objc_instruction import *
from macho_binary import MachoBinary


class ObjcFunctionAnalyzer(object):
    def __init__(self, binary, instructions):
        # type: (MachoBinary, List[CsInsn]) -> ObjcFunctionAnalyzer
        self.binary = binary
        self._instructions = instructions

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
                return branch_instr
        return None


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
                    # source is a register, return reg name
                    return instr.reg_name(src.value.reg)
