from typing import Optional, Union
from typing import TYPE_CHECKING

from capstone import CsInsn
from capstone.arm64 import Arm64Op, ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

from strongarm.macho.macho_definitions import VirtualMemoryPointer
from strongarm.macho.objc_runtime_data_parser import ObjcSelref, ObjcSelector
from strongarm.macho.macho_analyzer import MachoAnalyzer

if TYPE_CHECKING:
    from .objc_analyzer import ObjcFunctionAnalyzer


class ObjcInstruction:
    VECTOR_REGISTER_PREFIXES = ['d', 's', 'v']

    def __init__(self, instruction: CsInsn) -> None:
        self.raw_instr = instruction
        self.address = VirtualMemoryPointer(self.raw_instr.address)

        self.is_msgSend_call: bool = False
        self.symbol: Optional[str] = None

    @classmethod
    def is_vector_register(cls, reg_name: str) -> bool:
        """Returns True if the register refers to a vector register; False otherwise.
        """
        for vector_prefix in ObjcInstruction.VECTOR_REGISTER_PREFIXES:
            if vector_prefix in reg_name:
                return True
        return False

    @classmethod
    def _operand_uses_vector_registers(cls, instruction: CsInsn, operand: Arm64Op) -> bool:
        if operand.type == ARM64_OP_IMM:
            return False

        if operand.type == ARM64_OP_REG:
            reg_name = instruction.reg_name(operand.value.reg)
        elif operand.type == ARM64_OP_MEM:
            reg_name = instruction.reg_name(operand.mem.base)
        else:
            raise RuntimeError(f'unknown operand type {operand.type} in instr at {instruction.address}')
        return ObjcInstruction.is_vector_register(reg_name)

    @classmethod
    def instruction_uses_vector_registers(cls, instruction: CsInsn) -> bool:
        """Returns True if the instruction accesses vector registers.
        False if the instruction only uses general-purpose registers.
        """
        for op in instruction.operands:
            if ObjcInstruction._operand_uses_vector_registers(instruction, op):
                return True
        return False

    @classmethod
    def parse_instruction(cls, function_analyzer: 'ObjcFunctionAnalyzer', instruction: CsInsn) -> 'ObjcInstruction':
        """Read an instruction and encapsulate it in the appropriate ObjcInstruction subclass
        """
        if ObjcBranchInstruction.is_branch_instruction(instruction):
            return ObjcBranchInstruction.parse_instruction(function_analyzer, instruction)
        return ObjcInstruction(instruction)


class ObjcBranchInstruction(ObjcInstruction):
    def __init__(self, instruction: CsInsn, destination_address: VirtualMemoryPointer) -> None:
        super(ObjcBranchInstruction, self).__init__(instruction)

        self.destination_address = destination_address

        self.selref: Optional[ObjcSelref] = None
        self.selector: Optional[ObjcSelector] = None

        self.is_external_c_call: bool = False
        self.is_external_objc_call: bool = False

        self.is_local_branch: bool = False

    @classmethod
    def parse_instruction(cls,
                          function_analyzer: 'ObjcFunctionAnalyzer',
                          instruction: CsInsn) -> Union['ObjcUnconditionalBranchInstruction',
                                                        'ObjcConditionalBranchInstruction']:
        """Read a branch instruction and encapsulate it in the appropriate ObjcBranchInstruction subclass
        """
        # use appropriate subclass
        if instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            uncond_instr = ObjcUnconditionalBranchInstruction(function_analyzer, instruction)
            uncond_instr.is_local_branch = function_analyzer.is_local_branch(uncond_instr)
            return uncond_instr

        elif instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            cond_instr = ObjcConditionalBranchInstruction(function_analyzer, instruction)
            cond_instr.is_local_branch = function_analyzer.is_local_branch(cond_instr)
            return cond_instr

        else:
            raise ValueError(f'Unknown branch mnemonic {instruction.mnemonic}')

    @classmethod
    def is_branch_instruction(cls, instruction: CsInsn) -> bool:
        """Returns True if the CsInsn represents a branch instruction, False otherwise
        """
        # TODO(FS): Merge subclasses into ObjcBranchInstruction and provide contextual information about each variant
        return instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS or \
               instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS


class ObjcUnconditionalBranchInstruction(ObjcBranchInstruction):
    UNCONDITIONAL_BRANCH_MNEMONICS = ['b',
                                      'bl',
                                      'bx',
                                      'blx',
                                      'bxj',
                                      'b.eq',  # TODO(PT): these b-suffix are not strictly unconditional branches, but
                                               # they're functionally unconditional for what we care about
                                      'b.ne',
                                      'b.lt',
                                      'b.gt'
                                      ]
    OBJC_MSGSEND_FUNCTIONS = ['_objc_msgSend', '_objc_msgSendSuper2']

    def __init__(self, function_analyzer: 'ObjcFunctionAnalyzer', instruction: CsInsn) -> None:
        if instruction.mnemonic not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError(f'ObjcUnconditionalBranchInstruction instantiated with'
                             f' invalid mnemonic {instruction.mnemonic}')
        # an unconditional branch has the destination as the only operand
        super().__init__(instruction, VirtualMemoryPointer(instruction.operands[0].value.imm))

        self.selref: Optional[ObjcSelref] = None
        self.selector: Optional[ObjcSelector] = None

        macho_analyzer = MachoAnalyzer.get_analyzer(function_analyzer.binary)
        external_c_sym_map = macho_analyzer.imp_stubs_to_symbol_names
        if self.destination_address in external_c_sym_map:
            self.symbol = external_c_sym_map[self.destination_address]  # type: ignore
            if self.symbol in self.OBJC_MSGSEND_FUNCTIONS:
                self.is_msgSend_call = True
                self._patch_msgSend_destination(function_analyzer)
            else:
                self.is_msgSend_call = False

        self.is_external_c_call = self.symbol is not None

    def _patch_msgSend_destination(self, function_analyzer: 'ObjcFunctionAnalyzer') -> None:
        # validate instruction
        if not self.is_msgSend_call or \
           self.raw_instr.mnemonic not in ['bl', 'b'] or \
           self.symbol not in self.OBJC_MSGSEND_FUNCTIONS:
            raise ValueError(f'cannot parse objc_msgSend destination on non-msgSend instruction'
                             f' {function_analyzer.format_instruction(self.raw_instr)}')
        # if this is an objc_msgSend target, patch destination_address to be the address of the targeted IMP
        # note! this means destination_address is *not* the actual destination address of the instruction
        # the *real* destination will be a stub function corresponding to _objc_msgSend, but
        # knowledge of this is largely useless, and the much more valuable piece of information is
        # which function the selector passed to objc_msgSend corresponds to.
        # therefore, replace the 'real' destination address with the requested IMP
        try:
            selref_ptr = function_analyzer.get_objc_selref(self)
            selector = function_analyzer.macho_analyzer.selector_for_selref(selref_ptr)
            if not selector:
                raise RuntimeError(f'Couldn\'t get sel for selref ptr {selref_ptr}')
            # if we couldn't find an IMP for this selref,
            # it is defined in a class outside this binary
            self.is_external_objc_call = selector.is_external_definition

            self.destination_address = selector.implementation if selector.implementation else VirtualMemoryPointer(0)
            self.selref = selector.selref
            self.selector = selector
        except RuntimeError as e:
            # GammaRayTestBad @ 0x10007ed10 causes get_objc_selref() to fail.
            # This is because x1 has a data dependency on x20.
            # At the beginning of the function, there's a basic block to return early if imageView is nil.
            # This basic block includes a stack unwind, which tricks get_register_contents_at_instruction() into
            # thinking that there's a data dependency on x0, which there *isn't*
            # Nonetheless, this causes get_objc_selref() to fail.
            # As a workaround, let's assign all the above fields to 'not found' values if this bug is hit
            self.is_external_objc_call = True
            self.destination_address = VirtualMemoryPointer(0)


class ObjcConditionalBranchInstruction(ObjcBranchInstruction):
    SINGLE_OP_MNEMONICS = ['cbz',
                           'cbnz',
                           ]
    DOUBLE_OP_MNEMONICS = ['tbnz',
                           ]
    CONDITIONAL_BRANCH_MNEMONICS = SINGLE_OP_MNEMONICS + DOUBLE_OP_MNEMONICS

    def __init__(self, function_analyzer: 'ObjcFunctionAnalyzer', instruction: CsInsn) -> None:
        if instruction.mnemonic not in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError(f'ObjcConditionalBranchInstruction instantiated with'
                             f' invalid mnemonic {instruction.mnemonic}')

        # a conditional branch will either hold the destination in first or second operand, depending on mnemonic
        if instruction.mnemonic in ObjcConditionalBranchInstruction.SINGLE_OP_MNEMONICS:
            dest_op_idx = 1
        elif instruction.mnemonic in ObjcConditionalBranchInstruction.DOUBLE_OP_MNEMONICS:
            dest_op_idx = 2
        else:
            raise ValueError(f'Unknown conditional mnemonic {instruction.mnemonic}')

        ObjcBranchInstruction.__init__(
            self,
            instruction,
            VirtualMemoryPointer(instruction.operands[dest_op_idx].value.imm)
        )
