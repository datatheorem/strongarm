from capstone import *

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_binary import MachoBinary


class ObjcInstruction(object):
    def __init__(self, instruction):
        # type: (CsInsn) -> None
        self.raw_instr = instruction
        self.address = self.raw_instr.address

        self.is_msgSend_call = False
        self.destination_address = None
        self.symbol = None


class ObjcBranchInstruction(ObjcInstruction):
    def __init__(self, instruction):
        # type: (CsInsn) -> None
        super(ObjcBranchInstruction, self).__init__(instruction)

        self.destination_address = self.raw_instr.operands[0].value.imm

        self.symbol = None
        self.is_external_c_call = False

        self.selref = None
        self.is_external_objc_call = False

    @classmethod
    def parse_instruction(cls, binary, instruction):
        # type: (MachoBinary, CsInsn) -> ObjcBranchInstruction
        analyzer = MachoAnalyzer.get_analyzer(binary)
        instr = ObjcBranchInstruction(instruction)

        instr.destination_address = instr.raw_instr.operands[0].value.imm
        external_c_sym_map = analyzer.external_branch_destinations_to_symbol_names

        if instr.destination_address in external_c_sym_map:
            instr.symbol = external_c_sym_map[instr.destination_address]
            if instr.symbol == '_objc_msgSend':
                instr.is_msgSend_call = True

        instr.is_external_c_call = instr.symbol is not None
        return instr
