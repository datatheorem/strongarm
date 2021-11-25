from typing import TYPE_CHECKING, Optional, Tuple, Union

from capstone import CsInsn
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG, Arm64Op

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_definitions import VirtualMemoryPointer
from strongarm.macho.objc_runtime_data_parser import ObjcSelector, ObjcSelref

if TYPE_CHECKING:
    from .objc_analyzer import ObjcFunctionAnalyzer


class ObjcInstruction:
    VECTOR_REGISTER_PREFIXES = ["d", "s", "v"]

    def __init__(self, instruction: CsInsn) -> None:
        self.raw_instr = instruction
        self.address = VirtualMemoryPointer(self.raw_instr.address)

        self.is_msgSend_call: bool = False
        self.symbol: Optional[str] = None

    def __repr__(self) -> str:
        return f"<ObjcInstruction {self.symbol} at 0x{self.address:x}>"

    @classmethod
    def is_vector_register(cls, reg_name: str) -> bool:
        """Returns True if the register refers to a vector register; False otherwise."""
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
            raise RuntimeError(f"unknown operand type {operand.type} in instr at {instruction.address}")
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
    def parse_instruction(
        cls, function_analyzer: "ObjcFunctionAnalyzer", instruction: CsInsn
    ) -> Union["ObjcInstruction", "ObjcUnconditionalBranchInstruction", "ObjcConditionalBranchInstruction"]:
        """Read an instruction and encapsulate it in the appropriate ObjcInstruction subclass."""
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

    @classmethod
    def parse_instruction(
        cls,
        function_analyzer: "ObjcFunctionAnalyzer",
        instruction: CsInsn,
        patch_msgSend_destination: bool = True,
        container_function_boundary: Tuple[VirtualMemoryPointer, VirtualMemoryPointer] = None,
    ) -> Union["ObjcUnconditionalBranchInstruction", "ObjcConditionalBranchInstruction"]:
        """Read a branch instruction and encapsulate it in the appropriate ObjcBranchInstruction subclass."""
        # use appropriate subclass
        if instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            uncond_instr = ObjcUnconditionalBranchInstruction(
                function_analyzer, instruction, patch_msgSend_destination, container_function_boundary
            )
            return uncond_instr

        elif instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            cond_instr = ObjcConditionalBranchInstruction(function_analyzer, instruction)
            return cond_instr

        else:
            raise ValueError(f"Unknown branch mnemonic {instruction.mnemonic}")

    @classmethod
    def is_branch_instruction(cls, instruction: CsInsn) -> bool:
        """Returns True if the CsInsn represents a branch instruction, False otherwise."""
        # TODO(FS): Merge subclasses into ObjcBranchInstruction and provide contextual information about each variant
        return (
            instruction.mnemonic in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS
            or instruction.mnemonic in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS
        )


class ObjcUnconditionalBranchInstruction(ObjcBranchInstruction):
    UNCONDITIONAL_BRANCH_MNEMONICS = [
        "b",
        "bl",
        "bx",
        "blx",
        "bxj",
        "b.eq",  # TODO(PT): these b-suffix are not strictly unconditional branches, but
        # they're functionally unconditional for what we care about
        "b.ne",
        "b.ge",
        "b.le",
        "b.gt",
        "b.lt",
        "b.hi",
        "b.lo",
    ]
    OBJC_MSGSEND_FUNCTIONS = ["_objc_msgSend", "_objc_msgSendSuper2"]

    def __init__(
        self,
        function_analyzer: "ObjcFunctionAnalyzer",
        instruction: CsInsn,
        patch_msgSend_destination: bool = True,
        container_function_boundary: Tuple[VirtualMemoryPointer, VirtualMemoryPointer] = None,
    ) -> None:
        if instruction.mnemonic not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError(
                f"ObjcUnconditionalBranchInstruction instantiated with" f" invalid mnemonic {instruction.mnemonic}"
            )
        # an unconditional branch has the destination as the only operand
        super().__init__(instruction, VirtualMemoryPointer(instruction.operands[0].value.imm))

        self.selref: Optional[ObjcSelref] = None
        self.selector: Optional[ObjcSelector] = None

        analyzer = MachoAnalyzer.get_analyzer(function_analyzer.binary)

        if container_function_boundary:
            if self.destination_address >= container_function_boundary[0]:
                if self.destination_address < container_function_boundary[1]:
                    # Local basic-block branch within a function
                    # print(f'{self.destination_address} local branch fast path')
                    self.symbol = None
                    self.is_external_c_call = False
                    self.is_msgSend_call = False
                    return

        called_sym = analyzer.callable_symbol_for_address(self.destination_address)
        if not called_sym:
            # Branch to an anonymous destination
            # Might be a basic block within a function or some other label
            # logger.debug(f'No symbol for branch destination {hex(self.destination_address)}')
            self.is_external_c_call = False
            self.is_msgSend_call = False
            self.symbol = None
            return

        self.symbol = called_sym.symbol_name
        self.is_external_c_call = called_sym.is_imported

        if called_sym.is_imported:
            if called_sym.symbol_name in self.OBJC_MSGSEND_FUNCTIONS:
                self.is_msgSend_call = True
                self.is_external_c_call = False
                if patch_msgSend_destination:
                    self._patch_msgSend_destination(function_analyzer)
            else:
                self.is_msgSend_call = False
        else:
            self.is_msgSend_call = False

    def _patch_msgSend_destination(self, function_analyzer: "ObjcFunctionAnalyzer") -> None:
        # validate instruction
        if (
            not self.is_msgSend_call
            or self.raw_instr.mnemonic not in ["bl", "b"]
            or self.symbol not in self.OBJC_MSGSEND_FUNCTIONS
        ):
            raise ValueError(
                f"cannot parse objc_msgSend destination on non-msgSend instruction"
                f" {function_analyzer.format_instruction(self.raw_instr)}"
            )
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
                raise RuntimeError(f"Couldn't get sel for selref ptr {selref_ptr}")
            # if we couldn't find an IMP for this selref,
            # it is defined in a class outside this binary
            self.is_external_objc_call = selector.is_external_definition

            # Only patch destination_address if the implementation is in this binary.
            # Otherwise, destination_address will continue to point to __imp_stubs_objc_msgSend
            if selector.implementation:
                self.destination_address = selector.implementation
            self.selref = selector.selref
            self.selector = selector
        except RuntimeError:
            # TODO(PT): Should this ever be hit?
            self.is_external_objc_call = True
            self.destination_address = VirtualMemoryPointer(0)


class ObjcConditionalBranchInstruction(ObjcBranchInstruction):
    SINGLE_OP_MNEMONICS = ["cbz", "cbnz"]
    DOUBLE_OP_MNEMONICS = ["tbnz"]
    CONDITIONAL_BRANCH_MNEMONICS = SINGLE_OP_MNEMONICS + DOUBLE_OP_MNEMONICS

    def __init__(self, function_analyzer: "ObjcFunctionAnalyzer", instruction: CsInsn) -> None:
        if instruction.mnemonic not in ObjcConditionalBranchInstruction.CONDITIONAL_BRANCH_MNEMONICS:
            raise ValueError(
                f"ObjcConditionalBranchInstruction instantiated with" f" invalid mnemonic {instruction.mnemonic}"
            )

        # a conditional branch will either hold the destination in first or second operand, depending on mnemonic
        if instruction.mnemonic in ObjcConditionalBranchInstruction.SINGLE_OP_MNEMONICS:
            dest_op_idx = 1
        elif instruction.mnemonic in ObjcConditionalBranchInstruction.DOUBLE_OP_MNEMONICS:
            dest_op_idx = 2
        else:
            raise ValueError(f"Unknown conditional mnemonic {instruction.mnemonic}")

        ObjcBranchInstruction.__init__(
            self, instruction, VirtualMemoryPointer(instruction.operands[dest_op_idx].value.imm)
        )
