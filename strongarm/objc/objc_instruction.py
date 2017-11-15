from capstone import CsInsn

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
        """Read a branch instruction and encapsulate it in the appropriate ObjcBranchInstruction subclass
        """
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
        # type: (CsInsn) -> bool
        """Returns True if the CsInsn represents a branch instruction, False otherwise
        """
        return instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS \
               or instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS


class ObjcUnconditionalBranchInstruction(ObjcBranchInstruction):
    UNCONDITIONAL_BRANCH_MNEMONICS = ['b',
                                      'bl',
                                      'bx',
                                      'blx',
                                      'bxj',
                                      'b.eq', # TODO(PT): these b-suffix are not strictly unconditional branches, but
                                              # they're functionally unconditional for what we care about
                                      'b.ne',
                                      'b.lt',
                                      'b.gt'
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
                self._patch_msgSend_destination(function_analyzer)

        self.is_external_c_call = self.symbol is not None

    def _patch_msgSend_destination(self, function_analyzer):
        # type: (objc_analyzer.ObjcFunctionAnalyzer) -> None
        # validate instruction
        if not self.is_msgSend_call or \
           self.raw_instr.mnemonic != 'bl' or \
           self.symbol != '_objc_msgSend':
            print('self.is_msgSend_call {} self.raw_instr.mnemonic {} self.symbol {}'.format(
                self.is_msgSend_call,
                self.raw_instr.mnemonic,
                self.symbol,
            ))
            raise ValueError('cannot parse objc_msgSend destination on non-msgSend instruction {}'.format(function_analyzer.format_instruction(self.raw_instr)))
        # if this is an objc_msgSend target, patch destination_address to be the address of the targeted IMP
        # note! this means destination_address is *not* the actual destination address of the instruction
        # the *real* destination will be a stub function corresponding to _objc_msgSend, but
        # knowledge of this is largely useless, and the much more valuable piece of information is
        # which function the selector passed to objc_msgSend corresponds to.
        # therefore, replace the 'real' destination address with the requested IMP
        selref = None
        # attempt to get an IMP for this selref
        try:
            selref = function_analyzer.get_selref(self.raw_instr)
            sel_imp = function_analyzer.macho_analyzer.imp_for_selref(selref)
        except RuntimeError as e:
            # if this raised an exception, we couldn't find an IMP for this SEL name, which means
            # the SEL is not implemented within this binary
            sel_imp = None

        # if we couldn't find an IMP for this selref,
        # it is defined in a class outside this binary
        if not sel_imp:
            self.is_external_objc_call = True

        self.selref = selref
        self.destination_address = sel_imp


class ObjcConditionalBranchInstruction(ObjcBranchInstruction):
    SINGLE_OP_MNEMONICS = ['cbz',
                           'cbnz',
                           ]
    DOUBLE_OP_MNEMONICS = ['tbnz',
                           ]
    CONDITIONAL_BRANCH_MNEMONICS = SINGLE_OP_MNEMONICS + DOUBLE_OP_MNEMONICS

    def __init__(self, function_analyzer, instruction):
        # type: (objc_analyzer.ObjcFunctionAnalyzer, CsInsn) -> None
        if instruction.mnemonic not in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError('ObjcConditionalBranchInstruction instantiated with invalid mnemonic {}'.format(
                instruction.mnemonic
            ))

        # a conditional branch will either hold the destination in first or second operand, depending on mnemonic
        dest_op_idx = 1
        if instruction.mnemonic in ObjcConditionalBranchInstruction.SINGLE_OP_MNEMONICS:
            dest_op_idx = 1
        elif instruction.mnemonic in ObjcConditionalBranchInstruction.DOUBLE_OP_MNEMONICS:
            dest_op_idx = 2
        else:
            raise ValueError('Unknown conditional mnemonic {}'.format(instruction.mnemonic))

        ObjcBranchInstruction.__init__(self, instruction, instruction.operands[dest_op_idx].value.imm)
