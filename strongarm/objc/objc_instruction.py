from capstone import *

from strongarm.macho.macho_analyzer import MachoAnalyzer
import objc_analyzer


class ObjcInstruction(object):
    def __init__(self, instruction):
        # type: (CsInsn) -> None
        self.raw_instr = instruction
        self.address = self.raw_instr.address

        self.is_msgSend_call = False
        self.symbol = None


class ObjcBranchInstruction(ObjcInstruction):
    def __init__(self, instruction, destination_address):
        # type: (CsInsn, int) -> None
        super(ObjcBranchInstruction, self).__init__(instruction)

        self.destination_address = destination_address

        self.symbol = None
        self.selref = None

        self.is_external_c_call = None
        self.is_external_objc_call = None

    @classmethod
    def parse_instruction(cls, function_analyzer, instruction):
        # type: (objc_analyzer.ObjcFunctionAnalyzer, CsInsn) -> ObjcBranchInstruction
        # use appropriate subclass
        if instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            instr = ObjcUnconditionalBranchInstruction(function_analyzer, instruction)
        elif instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            instr = ObjcConditionalBranchInstruction(function_analyzer, instruction)
        else:
            raise ValueError('Unknown branch mnemonic {}'.format(instruction.mnemonic))

        instr.is_local_branch = function_analyzer.is_local_branch(instr)
        return instr

    @classmethod
    def is_branch_instruction(cls, instruction):
        return instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS \
               or instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS


class ObjcUnconditionalBranchInstruction(ObjcBranchInstruction):
    UNCONDITIONAL_BRANCH_MNEMONICS = ['b',
                                      'bl',
                                      'bx',
                                      'blx',
                                      'bxj',
                                      ]

    def __init__(self, function_analyzer, instruction):
        # type: (objc_analyzer.ObjcFunctionAnalyzer, CsInsn) -> None

        if instruction.mnemonic not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError('ObjcUnconditionalBranchInstruction instantiated with invalid mnemonic {}'.format(
                instruction.mnemonic
            ))
        # an unconditional branch has the destination as the only operand
        ObjcBranchInstruction.__init__(self, instruction, instruction.operands[0].value.imm)

        macho_analyzer = MachoAnalyzer.get_analyzer(function_analyzer.binary)
        external_c_sym_map = macho_analyzer.external_branch_destinations_to_symbol_names
        if self.destination_address in external_c_sym_map:
            self.symbol = external_c_sym_map[self.destination_address]
            if self.symbol == '_objc_msgSend':
                self.is_msgSend_call = True

        self.is_external_c_call = self.symbol is not None


class ObjcConditionalBranchInstruction(ObjcBranchInstruction):
    CONDITIONAL_BRANCH_MNEMONICS = ['cbz',
                                    'cbnz',
                                    ]

    def __init__(self, function_analyzer, instruction):
        # type: (objc_analyzer.ObjcFunctionAnalyzer, CsInsn) -> None
        if instruction.mnemonic not in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError('ObjcConditionalBranchInstruction instantiated with invalid mnemonic {}'.format(
                instruction.mnemonic
            ))
        # a conditional branch will hold the destination address in its second operand
        ObjcBranchInstruction.__init__(self, instruction, instruction.operands[1].value.imm)
