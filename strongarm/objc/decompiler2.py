import sys
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import capstone
from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM

from strongarm.macho import (
    VirtualMemoryPointer,

    MachoParser,
    MachoBinary,
    MachoAnalyzer,

    ObjcSelector,
    ObjcClass,
    ObjcClassRawStruct,
)
from strongarm.objc.objc_analyzer import ObjcMethodInfo
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer
from strongarm.objc.objc_instruction import ObjcUnconditionalBranchInstruction


class InstructionIndex(int):
    """An int representing the index of an instruction within a source function.
    """


class WordContents:
    """Base class for data that can be manipulated in code.
    Can be a constant number, a classref, an object, etc.
    """
    pass


class Value(ABC, WordContents):
    @abstractmethod
    def __init__(self, value: Any) -> None:
        self.value = value

    def __repr__(self):
        return f'<VAL {self.value}>'


class ConstantValue(Value):
    def __init__(self, value: int) -> None:
        super().__init__(value)

    def __repr__(self):
        return f'<VAL {hex(self.value)}>'


class StringValue(Value):
    def __init__(self, value: str) -> None:
        super().__init__(value)


class Object(WordContents):
    UNKNOWN_CLASS = '_$_Unknown'

    def __init__(self, class_name: str) -> None:
        self.class_name = class_name

    def __repr__(self):
        return f'<OBJ {self.class_name}>'


class WordStorage:
    """A symbolic representation of a part of the machine which stores a value - can be a register or stack word
    """
    @classmethod
    def get_register(cls, reg_name: str) -> str:
        """Return the symbolic Register for the register name
        """
        return reg_name

    @classmethod
    def get_stack_word(cls, stack_offset: int) -> str:
        """Return the symbolic StackLocation for the given stack offset
        """
        return f'sp+{hex(stack_offset)}'

    def __init__(self, name: str) -> None:
        """
        Args:
            name: The name used for this data location, i.e. "x23" or "sp+0x8"
        """
        self._name = name
        self.contents: Optional[WordContents] = None

    @property
    def name(self):
        return self._name

    def __repr__(self):
        return f'<[{self.name}] = {self.contents}>'
        pass


class MachineState(dict):
    def set_register(self, register_name: str, contents: WordContents) -> None:
        if register_name in self:
            storage = self[register_name]
        else:
            storage = WordStorage(register_name)
            self[register_name] = storage
        storage.contents = contents

    def load_imm(self, reg_name: str, val: int) -> None:
        self[reg_name] = ConstantValue(val)

    def mov_word(self, src_location: str, dst_location: str) -> None:
        src = self[src_location]
        self[dst_location] = src


def is_neon_register(reg_name: str) -> bool:
    """Return whether the register refers to an ARM NEON register, used for SIMD/FP instructions.
    """
    neon_prefixes = ['v', 'd']
    for neon_prefix in neon_prefixes:
        if reg_name.startswith(neon_prefix):
            return True
    return False


class FunctionDecompiler:
    """Decompile a source function up to a target instruction.
    The decompiler works by interpreting assembly and updating a virtual representation of the machine's
    registers and stack frame.

    Note that this only disassembles the function up to the target instruction. The decompile operation will be
    performed again if you request the machine state at a different execution point within the same source function.

    XXX(PT): This does not respect basic blocks at all, and always assumes execution is linear, which is not true.
    Testing will show whether this behavior is good enough.

    XXX(PT): Should we store a function's decompiled state (and state at each execution point?) It'd mean we only
    decompile functions once, but the memory tradeoff could be large as we'd need to store the state at every
    instruction. We probably should not / do not need to do this.

    The decompiler is used within the context of a CodeSearch. We will only decompile a function up to
    an execution point if we are interested in this execution point for some other reason -- particularly, that the
    execution point calls out to some symbol we're interested in. The canonical example is the code calls out to a
    function which takes an object as an argument, and we will decompile the code so we can introspect more on this
    object.
    """
    def __init__(self, function_analyzer: ObjcFunctionAnalyzer, instruction: CsInsn) -> None:
        # XXX(PT): The decompiler always assumes it's operating on an Objective-C method with `method_info` populated
        self._method_info: ObjcMethodInfo = function_analyzer.method_info
        assert self._method_info, f'Decompiler cannot operate on non-ObjC ' \
                                  f'function: {hex(function_analyzer.start_address)}'

        self.function_analyzer = function_analyzer
        self.target_instruction = instruction

        self._machine_state: MachineState[WordStorage, WordContents] = MachineState()
        self._setup_machine_state()

        self._interpret_function_to_target_instruction()

    @staticmethod
    def find_prologue_end(function_analyzer: ObjcFunctionAnalyzer) -> InstructionIndex:
        """Identify the index where the function prologue ends and the real code begins.
        The function prologue is a piece of code present in every function which sets up the stack frame.
        There is also a matching function epilogue.
        """
        prologue_end_idx = -1
        for idx, instr in enumerate(function_analyzer.instructions):
            if instr.mnemonic != 'add':
                continue
            src = instr.operands[1]
            if src.type != ARM64_OP_REG:
                continue
            if instr.reg_name(src.reg) != 'sp':
                continue
            prologue_end_idx = idx + 1
            break

        if prologue_end_idx < 0:
            raise RuntimeError(f'Failed to find end of function prologue')

        return InstructionIndex(prologue_end_idx)

    def _setup_machine_state(self):
        """Populate the machine state that will exist when the function begins.
        Specifically, set the contents of the argument-passing registers.

        In the Objective-C ABI, registers will be laid out like so:
        x0 = self
        x1 = SEL
        x2 = method argument 1
        x3 = method argument 2
        ...
        """
        # Populate x0 (self) with an object of the class which implements the function
        self_object = Object(self._method_info.objc_class.name)
        self._machine_state.set_register('x0', self_object)
        # Populate x1 (SEL) with the selector of the function
        selector = self._method_info.objc_sel
        selector_value = StringValue(selector.name)
        self._machine_state.set_register('x1', selector_value)

        # Populate each of the registers with the selector arguments
        # In Objective-C, it is guaranteed that each colon in the selector will map to one argument
        # XXX(PT): Parsing the signature would tell us more about the arguments:
        # v56@0:8@16{CGRect={CGPoint=dd}{CGSize=dd}}24
        arg_count = selector.name.count(':')
        for sel_arg_idx in range(arg_count):
            # x0 and x1 are used by self and SEL, so real arguments start at idx 2
            func_arg_idx = 2 + sel_arg_idx
            register_name = f'x{func_arg_idx}'
            arg_object = Object(Object.UNKNOWN_CLASS)
            self._machine_state.set_register(register_name, arg_object)

    def _interpret_function_to_target_instruction(self):
        """Interpret the assembly up to the target instruction, updating our virtual machine state as we go.
        """
        print(f'---------------- START DECOMPILE ----------------')
        # assert self.target_instruction.is_msgSend_call

        prologue_end_idx = self.find_prologue_end(self.function_analyzer)
        for idx, instr in enumerate(self.function_analyzer.instructions[prologue_end_idx:]):
            if instr.mnemonic == 'nop':
                continue

            if instr == self.target_instruction:
                print(f'Got target instr')
                return
                raise RuntimeError()

            if instr.mnemonic in ['adr', 'ldr']:
                dst = instr.operands[0]
                assert dst.type == ARM64_OP_REG
                dst_reg = f'{instr.reg_name(dst.reg)}'

                src = instr.operands[1]
                if src.type == ARM64_OP_IMM:
                    self._machine_state.load_imm(dst_reg, src.imm)

            elif instr.mnemonic == 'mov':
                dst = instr.operands[0]
                assert dst.type == ARM64_OP_REG
                dst_reg = f'{instr.reg_name(dst.reg)}'
                src = instr.operands[1]
                assert src.type == ARM64_OP_REG
                src_reg = f'{instr.reg_name(src.reg)}'

                # Ignore NEON registers
                if is_neon_register(dst_reg) or is_neon_register(src_reg):
                    continue

                if dst_reg == src_reg:
                    # no-op
                    continue
                # assert src_reg in self.execution.machine_state.keys(), f'{src_reg} value unknown @ {hex(instr.address)}'
                self._machine_state.mov_word(src_reg, dst_reg)

            elif instr.mnemonic in ['bl', 'b']:
                wrapped_instr = ObjcUnconditionalBranchInstruction.parse_instruction(self.function_analyzer, instr)
                if wrapped_instr.is_msgSend_call:
                    # self.execution.objc_msgSend(wrapped_instr)
                    print(f'objc_msgsend')
                else:
                    # self.execution.function_call(wrapped_instr)
                    print(f'function call')

            elif instr.mnemonic == 'str':
                src_reg = instr.operands[0]
                stack_dest = instr.operands[1]

                assert src_reg.type == ARM64_OP_REG
                assert stack_dest.type == ARM64_OP_MEM

                src_reg_name = instr.reg_name(src_reg.reg)
                # Ignore NEON registers
                if is_neon_register(src_reg_name):
                    continue

                dest_reg = instr.reg_name(stack_dest.mem.base)
                assert dest_reg == 'sp'

                offset = stack_dest.mem.disp
                dest_loc = WordStorage.get_stack_word(offset)

                self._machine_state.mov_word(src_reg_name, dest_loc)

            elif False and instr.mnemonic == 'ldp':
                # Probably epilogue ?
                break

        raise RuntimeError(f'never found target instr?')
        pass

    def print_machine_state(self):
        print(f'------ Machine State ------')
        for key in self._machine_state.keys():
            print(f'{key} = {self._machine_state[key]}')
        print(f'---------------------------')


if __name__ == '__main__':
    capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    capstone.detail = True

    binary_path = '/Users/philliptennen/Documents/DynStaticChecks 2019-05-28 00-26-14/Payload/DynStaticChecks.app/DynStaticChecks'
    binary_path = '/Users/philliptennen/Library/CloudStorage/iCloud Drive/Documents/DataProtectionCheck 2019-05-28 19-40-13/Payload 2/DataProtectionCheck/DataProtectionCheck'
    binary = MachoParser(binary_path).get_arm64_slice()
    analyzer = MachoAnalyzer.get_analyzer(binary)

    function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_signature(binary,
                                                                                 'AppDelegate',
                                                                                 'application:didFinishLaunchingWithOptions:')
    decompiler = FunctionDecompiler(function_analyzer, function_analyzer.get_instruction_at_address(0x00000001000066c4))
    decompiler.print_machine_state()
