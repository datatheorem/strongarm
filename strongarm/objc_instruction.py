from capstone import *
from macho_binary import MachoBinary
from macho_analyzer import MachoAnalyzer


class ObjcInstr(object):
    def __init__(self, binary, instruction):
        # type: (MachoBinary, CsInsn) -> ObjcInstr
        self.binary = binary
        self.raw_instr = instruction
        self.address = self.raw_instr.address
        self.analyzer = MachoAnalyzer.get_analyzer(binary)


class ObjcBranchInstr(ObjcInstr):
    def __init__(self, binary, instruction):
        # type: (MachoBinary, CsInsn) -> ObjcBranchInstr
        super(ObjcBranchInstr, self).__init__(binary, instruction)

        self.destination_address = self.raw_instr.operands[0].value.imm
        external_c_sym_map = self.analyzer.address_to_symbol_name_map

        self.symbol = None
        if self.destination_address in external_c_sym_map:
            self.symbol = external_c_sym_map[self.destination_address]

        self.is_external_call = self.symbol is not None
