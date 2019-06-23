import sys
from enum import Enum
from collections import defaultdict
from typing import Any, Type, Dict, List, Union, Optional

import capstone
from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM, Arm64OpValue

from strongarm.macho import (
    VirtualMemoryPointer,

    MachoParser,
    MachoBinary,
    MachoAnalyzer,

    ObjcSelector,
    ObjcClass,
    ObjcClassRawStruct,
)
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer
from strongarm.objc.objc_instruction import ObjcUnconditionalBranchInstruction

from typing import Any
from abc import ABC, abstractmethod

from strongarm.macho import VirtualMemoryPointer, MachoParser, MachoBinary, MachoAnalyzer
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer, ObjcMethodInfo, ObjcUnconditionalBranchInstruction, ObjcInstruction


class OperandIsNotStorage(Exception):
    pass


class EndOfFunction(Exception):
    """Raised when you try to step() past the end of a source function
    """


class InstructionIndex(int):
    pass


class MemoryContents(ABC):
    @abstractmethod
    def get_value(self, execution: 'Execution' = None) -> Any:
        raise NotImplementedError()

    @abstractmethod
    def format(self, execution: 'Execution' = None) -> str:
        raise NotImplementedError()


class StorageLoad(MemoryContents):
    """A storage space which contains the address of another storage space
    """
    def __init__(self, source: 'VariableStorage') -> None:
        self.source = source

    def get_value(self, execution: 'Execution' = None) -> Any:
        return self.source.contents.get_value(execution)

    def format(self, execution: 'Execution' = None) -> str:
        return f'[pointer to {self.source}]'

    def __repr__(self) -> str:
        return f'[pointer to {self.source}]'


class Object(MemoryContents):
    """A symbolic variable initialized at runtime
    """
    GENERIC_CLASS = 'id'

    def __init__(self, class_name: str = GENERIC_CLASS, selector_name: str = None) -> None:
        self.class_name: Optional[str] = class_name
        self.selector_name: Optional[str] = selector_name

    def get_value(self, execution: 'Execution' = None) -> 'Object':
        return self

    def format(self, execution: 'Execution' = None) -> str:
        return f'[heap instance {self.class_name.lower()}]'

    def __repr__(self):
        return f'[heap instance {self.class_name.lower()}]'


class ConstantValue(MemoryContents):
    """A constant value being stored in a storage space
    """
    def __init__(self, value: int) -> None:
        self.value = value

    def get_value(self, execution: 'Execution' = None) -> int:
        return self.value

    def format(self, execution: 'Execution' = None) -> str:
        return f'[{hex(self.value)}]'

    def __repr__(self) -> str:
        return f'[{hex(self.value)}]'


class UninitializedValue(MemoryContents):
    """The contents of a variable storage space that's never been written to
    """
    def get_value(self, execution: 'Execution' = None) -> str:
        return '[not set]'

    def format(self, execution: 'Execution' = None) -> str:
        return '[not set]'

    def __repr__(self):
        return '[not set]'


class NonLocalValue(MemoryContents):
    """A value which originates outside the function
    """
    def get_value(self, execution: 'Execution' = None) -> str:
        return '[non-local]'

    def format(self, execution: 'Execution' = None) -> str:
        return '[non-local]'

    def __repr__(self) -> str:
        return '[non-local]'


class FunctionArgumentObject(Object):
    def format(self, execution: 'Execution' = None) -> str:
        return f'[function arg {super().format(execution)}]'

    def __repr__(self) -> str:
        return f'[function arg {super().__repr__()}]'


class VariableStorage:
    """A register or stack word
    """
    def __init__(self, name: str) -> None:
        self.name = name
        self.contents: MemoryContents = UninitializedValue()


class NSDictionary(Object):
    CLS_NAME = '_OBJC_CLASS_$_NSDictionary'
    CONSTRUCTOR_SEL = 'dictionaryWithObjects:forKeys:count:'

    def __init__(self, class_name: str, selector_name: str, machine_state: 'Execution') -> None:
        if class_name != self.CLS_NAME or selector_name != self.CONSTRUCTOR_SEL:
            raise RuntimeError(f'Unexpected NSDictionary initializer: -[{class_name} {selector_name}]')
        super().__init__(class_name, selector_name)

        self._construct_from_machine_state(machine_state)

    def _construct_from_machine_state(self, machine_state: 'Execution') -> None:
        objects = machine_state.get_reg_contents('x2')
        keys = machine_state.get_reg_contents('x3')
        count = machine_state.get_reg_contents('x4')
        print(f'\tobjects: {objects} {hex(objects.get_value(machine_state))}')
        print(f'\tkeys:    {keys} {hex(keys.get_value(machine_state))}')
        print(f'\tcount:   {count}')


# PT: Insight. Everything is either a constant value or a set of pointers that ends in a value
# Or heap memory.


class RegisterStorage(VariableStorage):
    def __init__(self, name: str) -> None:
        super().__init__(name)

    @staticmethod
    def get_label(register_name: str) -> str:
        # Turn w2 into x2
        # TODO(PT): do this for all word-size prefixes, or change the approach
        register_name = register_name.replace('w', 'x')
        return register_name

    def __repr__(self):
        return f'/{self.name} = {self.contents}/'


class ZeroRegister(RegisterStorage):
    def __init__(self):
        super().__init__('zr')
        # TODO(PT): add a set_contents where this subclass throws an exception
        self.contents = ConstantValue(0)


class StackStorage(VariableStorage):
    def __init__(self, address: int) -> None:
        self.address: int = address
        super().__init__(self.get_label(address))

    @staticmethod
    def get_label(address: int):
        return f'stack:{hex(address)}'

    def __repr__(self):
        return f'[stack mem @ {hex(self.address)}]'


class Execution:
    """A state-machine representing the processor as it executes a function.
    """
    # Instructions are 4 bytes on ARM64
    INSTRUCTION_SIZE = 4
    # Words are 8 bytes on ARM64
    WORD_SIZE = 8

    # Arbitrary address used as the base of the interpreted program stack
    VIRTUAL_STACK_BASE = VirtualMemoryPointer(0x8ffffffff)

    _ZERO_REGISTER = ZeroRegister()

    def __init__(self, function_analyzer: ObjcFunctionAnalyzer) -> None:
        self.function_analyzer = function_analyzer
        self._variables: Dict[str, Union[RegisterStorage, ZeroRegister, StackStorage]] = {
            self._ZERO_REGISTER.name: self._ZERO_REGISTER,
        }

        # Set the instruction pointer to the start of the function
        self.instruction_pointer_addr: VirtualMemoryPointer = self.function_analyzer.start_address
        # Give the machine a fake stack frame
        # We want to use an address which is unlikely to collide with any of the binary data, so make it high
        self.stack_pointer_addr = self.VIRTUAL_STACK_BASE

        # Set up frame pointer (x29)
        self.set_contents(self.storage_from_reg_name('x29'), NonLocalValue())
        # Set up link register (x30)
        self.set_contents(self.storage_from_reg_name('x30'), NonLocalValue())

        # Set up argument registers (x0-x7)
        # TODO(PT): test machine state on interpreter startup
        # In an Objective-C method call, x0 always contains self
        self_arg = FunctionArgumentObject(class_name=function_analyzer.method_info.objc_class.name)
        self.set_contents(self.storage_from_reg_name('x0'), self_arg)
        # And x1 always contains the selref, but we won't necessarily know this value
        # This is because a selref is only added to _objc_selrefs if the selector is invoked within the binary
        # Thus, make it an unknown value
        self.set_contents(self.storage_from_reg_name('x1'), NonLocalValue())
        # And x2-x7 will contain method arguments
        # TODO(PT): we should be smarter about this by reading the arg count from the selector / signature
        for i in range(2, 8):
            reg_name = f'x{i}'
            object = FunctionArgumentObject()
            self.set_contents(self.storage_from_reg_name(reg_name), FunctionArgumentObject())

        # Set up the callee-saved registers (x19-x28, d8-d15)
        for i in range(19, 29):
            reg_name = f'x{i}'
            self.set_contents(self.storage_from_reg_name(reg_name), NonLocalValue())
        for i in range(8, 16):
            reg_name = f'd{i}'
            self.set_contents(self.storage_from_reg_name(reg_name), NonLocalValue())

        # self.print()

    def storage_from_reg_name(self, name: str) -> RegisterStorage:
        if 'zr' in name:
            return self._variables[self._ZERO_REGISTER.name]

        label = RegisterStorage.get_label(name)
        if label not in self._variables:
            self._variables[label] = RegisterStorage(label)
        storage = self._variables[label]
        assert type(storage) == RegisterStorage, f'Expected register storage for {label}, got {type(storage)}'
        return storage

    def get_reg_contents(self, reg_name: str) -> MemoryContents:
        reg = self.storage_from_reg_name(reg_name)
        return reg.contents

    def storage_from_stack_offset(self, offset: int) -> StackStorage:
        storage_addr = self.stack_pointer_addr - offset
        label = StackStorage.get_label(storage_addr)

        if label not in self._variables:
            self._variables[label] = StackStorage(storage_addr)
        storage = self._variables[label]
        assert type(storage) == StackStorage, f'Expected stack storage for {label}, got {type(storage)}'
        return storage

    def _get_storage_for_operand_at_index(self,
                                          instr: CsInsn,
                                          operand_index: int,
                                          expected_type: Type[VariableStorage]) -> VariableStorage:
        """Read the operand at the specified index from the source instruction, and ensure it is storage space.
        """
        assert len(instr.operands) >= operand_index, f'{hex(instr.address)} has less than {operand_index} operands'
        op = instr.operands[operand_index]
        if op.type == ARM64_OP_REG:
            reg_name = instr.reg_name(op.reg)

            # Capstone treats "sp" as a normal register, but we model it as a stack word (sp+0x0)
            # Deal with this case
            if reg_name == 'sp':
                assert issubclass(StackStorage, expected_type), \
                    f'{hex(instr.address)} Expected a {expected_type}, but op {operand_index} is a {StackStorage}'
                return self.storage_from_stack_offset(0x0)

            # Normal register
            assert issubclass(RegisterStorage, expected_type), \
                f'{(hex(instr.address))} Expected a {expected_type}, but op {operand_index} is a {RegisterStorage}'
            return self.storage_from_reg_name(reg_name)

        elif op.type == ARM64_OP_MEM:
            assert issubclass(StackStorage, expected_type), \
                f'Expected a {expected_type}, but op {operand_index} is a memory load'
            offset = op.mem.disp
            return self.storage_from_stack_offset(offset)

        raise RuntimeError(f'{hex(instr.address)} at op idx {operand_index} has unknown type: {op.type}')

    def op0_storage(self, instr: CsInsn, expected_type: Type[VariableStorage] = VariableStorage) -> VariableStorage:
        return self._get_storage_for_operand_at_index(instr, 0, expected_type)

    def op1_storage(self, instr: CsInsn, expected_type: Type[VariableStorage] = VariableStorage) -> VariableStorage:
        return self._get_storage_for_operand_at_index(instr, 1, expected_type)

    def op2_storage(self, instr: CsInsn, expected_type: Type[VariableStorage] = VariableStorage) -> VariableStorage:
        return self._get_storage_for_operand_at_index(instr, 2, expected_type)

    def storage_is_stack_pointer(self, storage: VariableStorage) -> bool:
        if not issubclass(type(storage), StackStorage):
            return False
        stack_storage: StackStorage = storage
        return stack_storage.address == self.stack_pointer_addr

    def set_imm(self, dest: VariableStorage, immediate: int) -> None:
        val = ConstantValue(immediate)
        dest.contents = val

    def copy_value(self, source: VariableStorage, dest: VariableStorage) -> None:
        dest.contents = source.contents

    def set_contents(self, storage: VariableStorage, value: MemoryContents) -> None:
        storage.contents = value

    def print(self):
        def _format_value(value: MemoryContents) -> str:
            formatted_value = str(value)
            if isinstance(value, int):
                formatted_value = hex(value)
            return formatted_value

        print(f'########### Machine State ###########')
        # Print current sp
        print(f'- sp @ {hex(self.stack_pointer_addr)}')
        # Print registers
        stack_variables = {}
        print(f'- Registers')
        for name, storage in sorted(self._variables.items(), key=lambda t: t[0]):
            if 'stack' in name:
                stack_variables[name] = storage
                continue
            value = _format_value(storage.contents.get_value(self))
            print(f'\t- {name} = {value}')

        print(f'\n- Stack frame')
        for name, storage in sorted(stack_variables.items(), key=lambda t: t[0]):
            stack_offset = self.stack_pointer_addr - storage.address
            if stack_offset < 0:
                relative_loc = f'sp-{hex(abs(stack_offset))}'
            else:
                relative_loc = f'sp+{hex(stack_offset)}'

            value = _format_value(storage.contents.get_value(self))
            print(f'\t- {relative_loc} ({name}) = {value}')
        print(f'####################################')


class FunctionInterpreter:
    def __init__(self, function_analyzer: ObjcFunctionAnalyzer) -> None:
        self.function_analyzer = function_analyzer
        self.execution = Execution(function_analyzer)

    def _find_function_prologue_end(self) -> InstructionIndex:
        prologue_end_idx = -1
        for idx, instr in enumerate(self.function_analyzer.instructions):
            if instr.mnemonic != 'add':
                continue
            try:
                src = self.execution.op1_storage(instr)
                if not self.execution.storage_is_stack_pointer(src):
                    continue
                prologue_end_idx = idx + 1
                break
            except OperandIsNotStorage:
                continue

        if prologue_end_idx < 0:
            raise RuntimeError(f'Failed to find end of function prologue')

        return InstructionIndex(prologue_end_idx)

    def _ldr(self, instr: CsInsn) -> None:
        dest = self.execution.op0_storage(instr)
        source = instr.operands[1]
        if source.type == ARM64_OP_IMM:
            # ldr        x8, #0x100008008
            self.execution.set_imm(dest, source.imm)
            pass
        elif source.type == ARM64_OP_MEM:
            # ldr        x0, [x23, #0xe78]
            if source.value.mem.base != 0:
                source_reg = instr.reg_name(source.value.mem.base)
                reg_offset = source.value.mem.disp
                try:
                    new_value = self.execution.get_reg_contents(source_reg).get_value(self.execution) + reg_offset
                    self.execution.set_imm(dest, new_value)
                except TypeError:
                    print(f'{hex(instr.address)}')
            else:
                raise RuntimeError(f'have to use index? {source.value.mem.index}')
        else:
            print(f'Can\'t handle ldr from {source.type} to register')

    def _adrp(self, instr: CsInsn) -> None:
        dest = self.execution.op0_storage(instr)
        source = instr.operands[1]
        if source.type == ARM64_OP_IMM:
            self.execution.set_imm(dest, source.imm)
        else:
            print(f'Can\'t handle adrp from {source.type} to register')
        pass

    def _mov(self, instr: CsInsn) -> None:
        dest = self.execution.op0_storage(instr)
        source = self.execution.op1_storage(instr)
        if dest == source:
            # no-op
            return
        self.execution.copy_value(source, dest)

    def _str(self, instr: CsInsn) -> None:
        source = self.execution.op0_storage(instr, expected_type=RegisterStorage)
        dest = self.execution.op1_storage(instr, expected_type=StackStorage)
        self.execution.set_contents(dest, source.contents)

    def _stp(self, instr: CsInsn) -> None:
        # stp        d9, d8, [sp, #0x60]
        # stp        x22, x21, [sp, #0xa0]
        # stp        x29, x30, [sp, #0xc0]
        reg1 = self.execution.op0_storage(instr, expected_type=RegisterStorage)
        reg2 = self.execution.op1_storage(instr, expected_type=RegisterStorage)

        dest_memory = instr.operands[2]
        # dest_base_address = self.execution.storage_from_reg_name(dest_memory)
        # TODO(PT): base, offset = self.execution.memory_op_from_instruction()
        assert dest_memory.value.mem.base != 0
        dest_reg = instr.reg_name(dest_memory.value.mem.base)
        assert dest_reg == 'sp'

        offset = dest_memory.value.mem.disp
        dest_storage_word1 = self.execution.storage_from_stack_offset(offset)
        dest_storage_word2 = self.execution.storage_from_stack_offset(offset + Execution.WORD_SIZE)

        self.execution.copy_value(reg1, dest_storage_word1)
        self.execution.copy_value(reg2, dest_storage_word2)

        print(f'store {reg1}, {reg2} -> {dest_storage_word1}, {dest_storage_word2}')

    def _orr(self, instr: CsInsn) -> None:
        # orr        w4, wzr, #0x2
        # Bitwise-or a register and immediate, and store in another register
        dest = self.execution.op0_storage(instr, expected_type=RegisterStorage)
        source = self.execution.op1_storage(instr, expected_type=RegisterStorage)

        imm_op = instr.operands[2]
        assert imm_op.type == ARM64_OP_IMM
        immediate = imm_op.value.imm

        source_value = source.contents.get_value(self.execution)
        assert type(source_value) == int, type(source_value)
        dest_value = source_value | immediate

        self.execution.set_imm(dest, dest_value)

    def _add(self, instr: CsInsn) -> None:
        #  add        x2, sp, #0x48
        dest = self.execution.op0_storage(instr, expected_type=RegisterStorage)
        source = self.execution.op1_storage(instr, expected_type=StackStorage)
        assert self.execution.storage_is_stack_pointer(source)

        stack_offset_op = instr.operands[2]
        assert stack_offset_op.type == ARM64_OP_IMM
        stack_offset = stack_offset_op.value.imm

        new_value = self.execution.stack_pointer_addr + stack_offset
        self.execution.set_imm(dest, new_value)

    def _sub(self, instr: CsInsn) -> None:
        # sub        sp, sp, #0xd0
        dest = self.execution.op0_storage(instr)
        source = self.execution.op1_storage(instr, expected_type=StackStorage)
        assert self.execution.storage_is_stack_pointer(source)

        subtract_value_op = instr.operands[2]
        assert subtract_value_op.type == ARM64_OP_IMM
        subtract_value = subtract_value_op.value.imm

        if self.execution.storage_is_stack_pointer(dest):
            print(f'subtracting stack pointer from itself')
            self.execution.stack_pointer_addr -= subtract_value
        else:
            source_val = source.contents.get_value(self.execution)
            dest_val = source_val - subtract_value
            self.execution.set_imm(dest, dest_val)

    def _branch(self, instr: CsInsn) -> None:
        macho_analyzer = self.function_analyzer.macho_analyzer
        wrapped_instr = ObjcUnconditionalBranchInstruction.parse_instruction(self.function_analyzer, instr)
        if not wrapped_instr.is_msgSend_call:
            # C function call
            # We don't do anything with these for now
            return

        selref = self.execution.get_reg_contents('x1')
        assert type(selref) == ConstantValue
        selector = macho_analyzer.selector_for_selref(selref.get_value(self.execution))
        # print(f'msgSend to @selector({selector_name})')

        receiver: MemoryContents = self.execution.get_reg_contents('x0')
        assert issubclass(type(receiver), MemoryContents), f'receiver was an unexpected class: {type(receiver)}'
        # Are we directly messaging a classref?
        if type(receiver) == ConstantValue:
            class_name = macho_analyzer.class_name_for_class_pointer(receiver.get_value(self.execution))

            # PT: This is the override point for symbolically creating more objects.
            # Let's change this mechanism once out of the prototyping phase
            if class_name == NSDictionary.CLS_NAME and selector.name == NSDictionary.CONSTRUCTOR_SEL:
                return_value = NSDictionary(class_name=class_name,
                                            selector_name=selector.name,
                                            machine_state=self.execution)
            else:
                # Generic object creation
                return_value = Object(class_name=class_name, selector_name=selector.name)
            msg_send_description = f'+[{class_name} {selector.name}]'
        else:
            # Object created by calling a method on another object
            # Type information would be helpful here. At the very least, knowing when a method returns void.
            x0 = self.execution.storage_from_reg_name('x0')
            self.execution.print()
            assert type(receiver) == Object, f'{hex(instr.address)} ObjC receiver is not an Object: {type(x0.contents)}'

            return_value = Object(selector_name=selector.name)
            self.execution.set_contents(x0, return_value)

            msg_send_description = f'-[{receiver.class_name} {selector.name}]'

        self.execution.set_contents(self.execution.storage_from_reg_name('x0'), return_value)
        print(f'{return_value} = {msg_send_description}')

    def run_until_address(self, address: VirtualMemoryPointer) -> None:
        while self.execution.instruction_pointer_addr < address:
            self.step()

    def run_past_address(self, address: VirtualMemoryPointer) -> None:
        self.run_until_address(address)
        self.step()

    def step(self) -> None:
        instr = self.function_analyzer.get_instruction_at_address(self.execution.instruction_pointer_addr)
        self.execution.instruction_pointer_addr += self.execution.INSTRUCTION_SIZE

        print(f'RUN INSTRUCTION:\t\t {self.function_analyzer.format_instruction(instr)}')

        if instr.mnemonic == 'nop':
            return

        # Load memory values
        if instr.mnemonic in ['ldr']:
            self._ldr(instr)
        elif instr.mnemonic == 'adrp':
            self._adrp(instr)
        # Stack storage
        elif instr.mnemonic == 'str':
            self._str(instr)
        elif instr.mnemonic == 'stp':
            self._stp(instr)
        # Moving data
        elif instr.mnemonic == 'mov':
            self._mov(instr)
        # Manipulating registers
        elif instr.mnemonic == 'orr':
            pass
            # self._orr(instr)
        elif instr.mnemonic == 'add':
            self._add(instr)
        elif instr.mnemonic == 'sub':
            self._sub(instr)
        # Branching
        elif instr.mnemonic in ['bl', 'b']:
            self._branch(instr)
        # Other
        elif False and instr.mnemonic == 'ldp':
            # Might be epilogue?
            raise EndOfFunction()

        self.execution.print()


if __name__ == '__main__':
    # capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    # capstone.detail = True

    binary_path = '/Users/philliptennen/Library/CloudStorage/iCloud Drive/Documents/DataProtectionCheck 2019-05-28 19-40-13/Payload 2/DataProtectionCheck/DataProtectionCheck'
    binary = MachoParser(binary_path).get_arm64_slice()
    analyzer = MachoAnalyzer.get_analyzer(binary)

    function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
        binary,
        'AppDelegate',
        'application:didFinishLaunchingWithOptions:')
    target_instr = ObjcUnconditionalBranchInstruction.parse_instruction(
        function_analyzer,
        function_analyzer.get_instruction_at_address(VirtualMemoryPointer(0x0000000100006728))
    )

    interpreter = FunctionInterpreter(function_analyzer, target_instr)
    x5_contents = interpreter.execution.get_reg_contents('x5')
    print(x5_contents)

