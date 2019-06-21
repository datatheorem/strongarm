import sys
from enum import Enum
from collections import defaultdict
from typing import Any, Dict, List, Optional

import capstone
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
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


class BinaryXRefType(Enum):
    STRING = 0
    CLASSREF = 1
    SELREF = 2
    IMPORTED_SYMBOL = 3


class BinaryXRef:
    def __init__(self, binary: MachoBinary, address: VirtualMemoryPointer, xref_type: BinaryXRefType, data) -> None:
        self.binary = binary
        self.address = address
        self.xref_type = xref_type
        self.data = data

    def __repr__(self):
        if self.xref_type == BinaryXRefType.CLASSREF:
            cls: ObjcClass = self.data
            return f'__objc_class_{cls.name}'
        elif self.xref_type == BinaryXRefType.SELREF:
            sel: ObjcSelector = self.data
            return f'__objc_sel_{sel.name}'
        elif self.xref_type == BinaryXRefType.IMPORTED_SYMBOL:
            return f'{self.data}'

        raise RuntimeError(f'No repr for xref type {self.xref_type}')


def objc_class_for_classref(analyzer: MachoAnalyzer, pointer: VirtualMemoryPointer) -> str:
    # TODO(PT): we should construct ObjcClass's for imported classes and add analyzer.class_for_class_pointer.
    # This method should return an ObjcClass.
    return analyzer.class_name_for_class_pointer(pointer)
    if False:
        objc_classes = [cls for cls in analyzer.objc_classes() if cls.raw_struct.binary_offset == pointer]
        if len(objc_classes) != 1:
            raise RuntimeError(f'Didn\'t find sane data for classref ptr {hex(pointer)}')
        return objc_classes[0]


def objc_sel_for_selref(analyzer: MachoAnalyzer, pointer: VirtualMemoryPointer) -> ObjcSelector:
    return analyzer._objc_helper.selector_for_selref(pointer)


def get_xref(function_analyzer: ObjcFunctionAnalyzer, pointer: VirtualMemoryPointer) -> BinaryXRef:
    binary = function_analyzer.binary
    analyzer = MachoAnalyzer.get_analyzer(binary)

    if binary.section_name_for_address(pointer) in ['__cstring', '__cfstring']:
        string = binary.read_string_at_address(pointer)
        return BinaryXRef(binary, pointer, BinaryXRefType.STRING, f'@"{string}"')

    objc_class = objc_class_for_classref(analyzer, pointer)
    if objc_class:
        return BinaryXRef(binary, pointer, BinaryXRefType.CLASSREF, objc_class)

    addresses, values = binary.read_pointer_section('__objc_selrefs')
    if pointer in addresses:
        objc_sel = objc_sel_for_selref(analyzer, VirtualMemoryPointer(pointer))
        return BinaryXRef(binary, pointer, BinaryXRefType.SELREF, objc_sel)

    for sym_name, ptr in analyzer.imported_symbol_names_to_pointers.items():
        if ptr == pointer:
            return BinaryXRef(binary, pointer, BinaryXRefType.IMPORTED_SYMBOL, sym_name)

    raise RuntimeError(f'Could not find XRef for {hex(pointer)}')


class ConstantValue(int):
    pass


class InstructionIndex(int):
    pass


def trimmed_register_name(name: str) -> str:
    gp_prefixes = ['x', 'w', 'r']
    for prefix in gp_prefixes:
        if name[0] == prefix:
            return name[1:]
    return name


def data_loc_for_stack_offset(offset: int) -> str:
    return f'sp+{hex(offset)}'


class MethodCallResult:
    def __init__(self, receiver, selector: str) -> None:
        self.receiver = receiver
        self.selector = selector

    def __repr__(self):
        return f'_objc_msgSend({self.receiver}, {self.selector})'


class FunctionCall:
    pass


class ObjcMethodCall:
    def __init__(self):
        pass


class CodeData:
    pass


class CodeDataPointer(CodeData):
    def __init__(self, value: VirtualMemoryPointer) -> None:
        self.value = value

    def __repr__(self):
        return hex(self.value)


class MethodCallRecord:
    def __init__(self, receiver: CodeData, objc_sel: ObjcSelector):
        self.receiver = receiver
        self.objc_sel = objc_sel


class CodeDataObject(CodeData):
    _GLOBAL_OBJECT_COUNT = 0

    def __init__(self, objc_cls: str, objc_sel: ObjcSelector):
        self.objc_cls = objc_cls
        self.objc_sel = objc_sel

        self.method_call_history = [MethodCallRecord(self, objc_sel)]

        self.object_id = self._GLOBAL_OBJECT_COUNT
        CodeDataObject._GLOBAL_OBJECT_COUNT += 1

    def call(self, objc_sel: ObjcSelector) -> Optional['CodeDataObject']:
        call_record = MethodCallRecord(self, objc_sel)
        self.method_call_history.append(call_record)

        # TODO(PT): How do we get the return value?
        selectors_returning_self = ['alloc', 'init']
        # Catch initWith... as well as init
        for selector in selectors_returning_self:
            if objc_sel.name.startswith(selector):
                return self
        else:
            # Assume the call returns a new object
            new_object = CodeDataObject('_Unknown', objc_sel)
            return new_object

    def var_name(self) -> str:
        cls_name = self.objc_cls.lower()
        if '_objc_class_$_' in cls_name:
            cls_name = cls_name.split('_objc_class_$_')[1]
        if cls_name == '_unknown':
            cls_name = f'{cls_name}{self.object_id}'
        return f'{cls_name}'
        # return f'var_{self.object_id}'

    def call_chain(self) -> str:
        s = f'[{self.objc_cls} '
        for call in self.method_call_history:
            s += f'{call.objc_sel.name}] '
        return s

    def __repr__(self):
        return self.var_name()


class CodeDataNSDictionary(CodeDataObject):
    def __init__(self, objc_cls: str, objc_sel: ObjcSelector):
        super(CodeDataNSDictionary, self).__init__(objc_cls, objc_sel)


class MachineState(dict):
    def __init__(self, *arg, **kw):
        super().__init__(*arg, **kw)
        # Set up special registers
        # XXX(PT): Handled in Execution set up
        # self['xzr'] = CodeDataPointer(VirtualMemoryPointer(0))

    def __getitem__(self, key):
        if key not in self:
            print(f'handling GET for unknown key {key}')
            self[key] = 'UNKNOWN'
        return super().__getitem__(key)


class Execution:
    def __init__(self, binary: MachoBinary, function_analyzer: ObjcFunctionAnalyzer):
        self.binary = binary
        self.function_analyzer = function_analyzer
        self.machine_state: Dict[str, CodeData] = MachineState()

    def set_reg_imm(self, reg_name: str, value: int):
        reg_name = trimmed_register_name(reg_name)
        # print(f'--> {reg_name} = {hex(value)}')
        self.machine_state[reg_name] = CodeDataPointer(VirtualMemoryPointer(value))

    def get_reg_val(self, reg_name: str):
        reg_name = trimmed_register_name(reg_name)
        return self.machine_state[reg_name]

    def set_reg_mem(self, reg_name: str, value: Any):
        reg_name = trimmed_register_name(reg_name)
        # print(f'mem type {type(value)}')
        self.machine_state[reg_name] = value

    def mov_reg(self, src_reg: str, dst_reg: str):
        src_reg = trimmed_register_name(src_reg)
        dst_reg = trimmed_register_name(dst_reg)

        src_value = self.machine_state[src_reg]
        # print(f'--> {dst_reg} = {src_reg} ({src_value})')
        self.machine_state[dst_reg] = src_value

    def process_nsdictionary_constructor(self,
                                         instr: ObjcUnconditionalBranchInstruction,
                                         class_xref: BinaryXRef,
                                         selector_xref: BinaryXRef) -> CodeDataObject:
        assert class_xref.data == '_OBJC_CLASS_$_NSDictionary'
        assert selector_xref.data.name == 'dictionaryWithObjects:forKeys:count:', selector_xref.data
        objc_dict = CodeDataNSDictionary(class_xref.data, selector_xref.data)

        count_wrapped: CodeDataPointer = self.get_reg_val('x2')
        objc_dict.count = count_wrapped.value
        for dict_item_idx in range(objc_dict.count):
            pass
        return objc_dict

    def objc_msgSend(self, instr: ObjcUnconditionalBranchInstruction):
        receiver = self.get_reg_val('x0')
        selector_ptr: CodeDataPointer = self.get_reg_val('x1')
        assert type(selector_ptr) == CodeDataPointer
        selector_xref = get_xref(self.function_analyzer, selector_ptr.value)
        assert selector_xref.xref_type == BinaryXRefType.SELREF

        # Are we directly messaging a classref?
        if type(receiver) == CodeDataPointer:
            receiver: CodeDataPointer = receiver
            class_xref: BinaryXRef = get_xref(self.function_analyzer, receiver.value)

            if class_xref.data == '_OBJC_CLASS_$_NSDictionary' and \
                    selector_xref.data.name == 'dictionaryWithObjects:forKeys:count:':
                obj = self.process_nsdictionary_constructor(instr, class_xref, selector_xref)
                print(f'Created symbolic NSDictionary: {obj}')
            else:
                obj = CodeDataObject(class_xref.data, selector_xref.data)

            self.machine_state['x0'] = obj
            print(f'\t{obj.var_name()} = {obj.call_chain()}')

        # Are we messaging an object?
        elif type(receiver) == CodeDataObject:
            receiver: CodeDataObject = receiver
            return_value = receiver.call(selector_xref.data)
            self.machine_state['x0'] = return_value
            # print(f'--> x0 = [{self.machine_state["x0"]} {selector_xref.data.name}]')
            print(f'\t{return_value.var_name()} = [{receiver.var_name()} {selector_xref.data.name}]')

        else:
            raise RuntimeError(f'unknown receiver type {receiver}')

    def format_nslog_call(self, instr: ObjcUnconditionalBranchInstruction):
        return f'NSLog'
        # Read string passed to NSLog
        x0_val: CodeDataPointer = self.get_reg_val('x0')
        if type(x0_val) != CodeDataPointer:
            raise RuntimeError(f'Non-static string passed to NSLog')

        format_string = self.binary.read_string_at_address(x0_val.value)
        formatted_call = f'_NSLog("{format_string}", '

        # Find arguments being passed in format string
        # Hack - read the % count of the string
        argument_count = format_string.count('%')

        # Add in the arguments to the call
        # NSLog passes its arguments on the stack, and each arg takes up 1 word (8 bytes)
        stack_idx = 0
        for arg in range(argument_count):
            # TODO(PT): come up with a real API for this
            stack_var_name = f'sp+{hex(stack_idx)}'
            var: CodeDataObject = self.get_reg_val(stack_var_name)
            assert type(var) == CodeDataObject, type(var)
            formatted_call += f'{var.var_name()}, '

            stack_idx += 8
        # Remove last ", " from formatted call
        formatted_call = formatted_call[:-2]
        formatted_call += ')'
        return formatted_call

    def function_call(self, instr: ObjcUnconditionalBranchInstruction):
        symbol = instr.symbol

        if symbol == '_NSLog':
            # Format NSLog call
            formatted_function_call = self.format_nslog_call(instr)
        else:
            x0_val = self.get_reg_val('x0')
            x0_desc = str(x0_val)
            formatted_function_call = f'{symbol}({x0_desc})'

        print(f'\tx0 = {formatted_function_call}')

    def print(self):
        print(f"--------- World ------------")
        for reg, value in self.machine_state.items():
            if type(value) == CodeDataPointer:
                desc = value
                try:
                    xref = get_xref(self.function_analyzer, value.value)
                    desc = xref.data
                except:
                    pass
            print(f'{reg}: {desc}')
        print(f"----------------------------")
        sys.exit(0)


def find_prologue_end(function_analyzer: ObjcFunctionAnalyzer) -> InstructionIndex:
    prologue_end_idx = -1
    for idx, instr in enumerate(function_analyzer.instructions):
        if instr.mnemonic != 'add':
            continue
        src = instr.operands[1]
        if src.type != ARM64_OP_REG:
            continue
        if trimmed_register_name(instr.reg_name(src.reg)) != 'sp':
            continue
        prologue_end_idx = idx + 1
        break

    if prologue_end_idx < 0:
        raise RuntimeError(f'Failed to find end of function prologue')

    return InstructionIndex(prologue_end_idx)


def is_stack_pointer(register_name: str) -> bool:
    return trimmed_register_name(register_name) == 'sp'


class MemoryLocation:
    def __init__(self, function_analyzer: ObjcFunctionAnalyzer, address: VirtualMemoryPointer):
        self.function_analyzer = function_analyzer
        self.address = address

    def get_content(self):
        # If it's an XRef, try to provide meaningful data
        # Otherwise, provide the raw binary content
        try:
            xref = get_xref(self.function_analyzer, self.address)
            return str(xref)
        except RuntimeError:
            try:
                return hex(self.function_analyzer.binary.read_word(self.address))
            except TypeError:
                return hex(self.function_analyzer.binary.read_word(self.address, virtual=False))


class FunctionInterpreter:
    def __init__(self, function_analyzer: ObjcFunctionAnalyzer):
        CodeDataObject._GLOBAL_OBJECT_COUNT = 0
        method = function_analyzer.method_info
        self.function_analyzer = function_analyzer
        self.binary = function_analyzer.binary
        self.execution = Execution(self.binary, function_analyzer)

        ###
        code_self = CodeDataObject(method.objc_class.name,
                                   method.objc_sel)
        self.execution.set_reg_mem('x0', code_self)
        self.execution.set_reg_mem('x1', method.objc_sel.name)
        ###

        self.execution.set_reg_mem('x2', 'ARG1')
        self.execution.set_reg_mem('x3', 'ARG2')
        self.execution.set_reg_mem('x4', 'ARG3')
        self.execution.set_reg_mem('x5', 'ARG4')
        # Zero register
        self.execution.set_reg_imm('zr', 0)

    def get_receiver(self, target_instr: ObjcUnconditionalBranchInstruction) -> CodeDataObject:
        """Get the Objective-C object being messaged at instruction. The instruction must be an objc_msgSend.
        """
        print(f'---------------- START DECOMPILE ----------------')
        assert target_instr.is_msgSend_call

        prologue_end_idx = find_prologue_end(self.function_analyzer)
        for idx, instr in enumerate(self.function_analyzer.instructions[prologue_end_idx:]):
            if instr.mnemonic == 'nop':
                continue

            if instr == target_instr.raw_instr:
                print(f'Got target instr')
                data: CodeDataObject = self.execution.get_reg_val('x0')
                # assert type(data) == CodeDataObject
                return data

            if instr.mnemonic in ['adr', 'ldr']:
                dst = instr.operands[0]
                assert dst.type == ARM64_OP_REG
                dst_reg = f'{instr.reg_name(dst.reg)}'

                src = instr.operands[1]
                if src.type == ARM64_OP_IMM:
                    self.execution.set_reg_imm(dst_reg, src.imm)

            elif instr.mnemonic == 'mov':
                dst = instr.operands[0]
                assert dst.type == ARM64_OP_REG
                dst_reg = f'{instr.reg_name(dst.reg)}'
                src = instr.operands[1]
                assert src.type == ARM64_OP_REG
                src_reg = f'{instr.reg_name(src.reg)}'
                if dst_reg == src_reg:
                    # no-op
                    continue

                self.execution.mov_reg(src_reg, dst_reg)

            elif instr.mnemonic in ['bl', 'b']:
                wrapped_instr = ObjcUnconditionalBranchInstruction.parse_instruction(self.function_analyzer, instr)
                if wrapped_instr.is_msgSend_call:
                    self.execution.objc_msgSend(wrapped_instr)
                else:
                    self.execution.function_call(wrapped_instr)

            elif instr.mnemonic == 'str':
                src_reg = instr.operands[0]
                stack_dest = instr.operands[1]

                assert src_reg.type == ARM64_OP_REG
                assert stack_dest.type == ARM64_OP_MEM

                src_reg_name = instr.reg_name(src_reg.reg)
                dest_reg = instr.reg_name(stack_dest.mem.base)
                assert dest_reg == 'sp'

                offset = stack_dest.mem.disp
                dest_loc = data_loc_for_stack_offset(offset)

                self.execution.mov_reg(src_reg_name, dest_loc)

            elif instr.mnemonic == 'orr':
                # orr        w4, wzr, #0x2
                # Bitwise-or a register and immediate, and store in another register
                dst_reg = instr.operands[0]
                src_reg = instr.operands[1]
                imm = instr.operands[2]

                assert dst_reg.type == ARM64_OP_REG
                assert src_reg.type == ARM64_OP_REG
                assert imm.type == ARM64_OP_IMM

                dst_reg_name = instr.reg_name(dst_reg.reg)
                src_reg_name = instr.reg_name(src_reg.reg)

                src_val: CodeDataPointer = self.execution.get_reg_val(src_reg_name)
                print(src_val)
                assert type(src_val) == CodeDataPointer
                dst_val = src_val.value | imm.value.imm
                self.execution.set_reg_imm(dst_reg_name, dst_val)

            elif instr.mnemonic == 'add':
                #  add        x2, sp, #0x48
                dst_reg = instr.operands[0]
                src_reg = instr.operands[1]

                if not is_stack_pointer(src_reg):
                    print(f'Skipping Non-sp add')
                    continue

            elif False and instr.mnemonic == 'ldp':
                # Probably epilogue ?
                break

        raise RuntimeError(f'never found target instr?')


if __name__ == '__main__':
    capstone = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    capstone.detail = True

    binary_path = '/Users/philliptennen/Library/CloudStorage/iCloud Drive/Documents/DataProtectionCheck 2019-05-28 19-40-13/Payload 2/DataProtectionCheck/DataProtectionCheck'
    binary = MachoParser(binary_path).get_arm64_slice()
    analyzer = MachoAnalyzer.get_analyzer(binary)

    function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_signature(binary,
                                                                                 'AppDelegate',
                                                                                 'application:didFinishLaunchingWithOptions:')
    decompiler = FunctionInterpreter(function_analyzer)
    decompiler.get_receiver(
        ObjcUnconditionalBranchInstruction.parse_instruction(
            function_analyzer,
            function_analyzer.get_instruction_at_address(VirtualMemoryPointer(0x00000001000066c4))
        )
    )
    # decompiler.print_machine_state()
