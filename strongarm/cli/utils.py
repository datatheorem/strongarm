# -*- coding: utf-8 -*-

import re
from typing import Text, List

from capstone import CsInsn
from capstone.arm64 import \
    Arm64Op, \
    ARM64_OP_REG, \
    ARM64_OP_IMM, \
    ARM64_OP_MEM

from strongarm.objc import ObjcMethodInfo
from strongarm.macho import \
    MachoParser, \
    MachoAnalyzer, \
    MachoBinary, \
    ObjcCategory, \
    CPU_TYPE
from strongarm.objc import \
    RegisterContentsType, \
    ObjcFunctionAnalyzer, \
    ObjcBranchInstruction, \
    ObjcBasicBlock, \
    ObjcInstruction


def pick_macho_slice(parser: MachoParser) -> MachoBinary:
    """Retrieve a MachoBinary slice from a MachoParser, with a preference for an arm64 slice
    """
    binary_slices = parser.slices

    # Sanity checks
    if not parser or len(binary_slices) == 0:
        raise ValueError('Could not parse {} as a Mach-O or FAT'.format(parser.filename))

    parsed_binary = None
    if len(binary_slices) == 1:
        # only one slice - return that
        parsed_binary = binary_slices[0]
    else:
        # multiple slices - return 64 bit slice if there is one
        for slice in binary_slices:
            parsed_binary = slice
            if parsed_binary.cpu_type == CPU_TYPE.ARM64:
                break
    return parsed_binary


def format_instruction_arg(instruction: CsInsn, arg: Arm64Op) -> Text:
    if arg.type == ARM64_OP_REG:
        return instruction.reg_name(arg.value.reg)
    elif arg.type == ARM64_OP_IMM:
        return hex(arg.value.imm)
    elif arg.type == ARM64_OP_MEM:
        return '[{} #{}]'.format(instruction.reg_name(arg.mem.base), hex(arg.mem.disp))
    raise RuntimeError('unknown arg type {}'.format(arg.type))


def args_from_sel_name(sel: Text) -> List[Text]:
    sel_components = sel.split(':')
    sel_args = ['self', '@selector({})'.format(sel)]
    for component in sel_components:
        if not len(component):
            continue
        # extract the last capitalized word
        split = re.findall('[A-Z][^A-Z]*', component)
        # if no capitalized word, use the full component
        if not len(split):
            split.append(component)
        # lowercase it
        sel_args.append(split[-1].lower())
    return sel_args


def disassemble_method(binary: MachoBinary, method: ObjcMethodInfo) -> Text:
    disassembled_text = []  # type: List[Text]

    # figure out the arguments based on the sel name
    sel_args = args_from_sel_name(method.objc_sel.name)
    signature = '\n\n-[{} {}]('.format(method.objc_class.name, method.objc_sel.name)
    for i, arg in enumerate(sel_args):
        signature += arg
        if i != len(sel_args) - 1:
            signature += ', '
    signature += ');'
    disassembled_text.append(signature)

    function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(binary, method.imp_addr)

    basic_blocks = ObjcBasicBlock.get_basic_blocks(function_analyzer)
    # transform basic blocks into tuples of (basic block start addr, basic block end addr)
    basic_block_boundaries = [[block[0].address, block[-1].address] for block in basic_blocks]
    # flatten basic_block_boundaries into one-dimensional list
    basic_block_boundaries = [x for boundaries in basic_block_boundaries for x in boundaries]
    # remove duplicate boundaries
    basic_block_boundaries = set(basic_block_boundaries)

    for instr in function_analyzer.instructions:
        instruction_string = ''
        # add visual indicator if this is a basic block boundary
        if instr.address in basic_block_boundaries:
            instruction_string += '----------------------------------------------- #\tbasic block boundary\n'

        instruction_string += '\t{}\t\t{}'.format(hex(instr.address), instr.mnemonic)

        # add each arg to the string
        for i, arg in enumerate(instr.operands):
            instruction_string += ' ' + format_instruction_arg(instr, arg)
            if i != len(instr.operands) - 1:
                instruction_string += ','

        instruction_string += '\t\t\t'
        # parse as an ObjcInstruction
        wrapped_instr = ObjcInstruction.parse_instruction(function_analyzer,
                                                          function_analyzer.get_instruction_at_address(instr.address))

        if isinstance(wrapped_instr, ObjcBranchInstruction):
            instruction_string += '#\t'
            if function_analyzer.is_local_branch(wrapped_instr):
                instruction_string += 'local branch'
            elif wrapped_instr.symbol:
                instruction_string += wrapped_instr.symbol

                if not wrapped_instr.selector:
                    instruction_string += '();'
                else:
                    instruction_string += '(id, @selector({})'.format(wrapped_instr.selector.name)

                    # figure out argument count passed to selector
                    arg_count = wrapped_instr.selector.name.count(':')
                    for i in range(arg_count):
                        # x0 is self, x1 is the SEL, real args start at x2
                        register = 'x{}'.format(i + 2)
                        method_arg = function_analyzer.get_register_contents_at_instruction(register, wrapped_instr)

                        method_arg_string = ', '
                        if method_arg.type == RegisterContentsType.UNKNOWN:
                            method_arg_string += '<?>'
                        elif method_arg.type == RegisterContentsType.FUNCTION_ARG:
                            method_arg_string += sel_args[method_arg.value]
                        elif method_arg.type == RegisterContentsType.IMMEDIATE:
                            method_arg_string += hex(method_arg.value)

                        instruction_string += method_arg_string
                    instruction_string += ');'
        else:
            if len(instr.operands) == 2 and instr.operands[1].type == ARM64_OP_IMM:
                # try reading a string
                binary_str = binary.read_string_at_address(instr.operands[1].value.imm)
                if binary_str:
                    instruction_string += '#\t"{}"'.format(binary_str)
        disassembled_text.append(instruction_string)

    return '\n'.join(disassembled_text)


def print_binary_info(binary: MachoBinary) -> None:
    print(f'Mach-O type: {binary.file_type.name}')
    print(f"{'Big' if binary.is_swap else 'Little'} endian")
    print(f'Virtual base: {hex(binary.get_virtual_base())}')
    print(f'Contains encrypted section? {binary.is_encrypted()}')


def print_binary_load_commands(binary: MachoBinary) -> None:
    print('\nLoad commands:')
    load_commands = binary.load_dylib_commands
    for cmd in load_commands:
        dylib_name_addr = binary.get_virtual_base() + cmd.fileoff + cmd.dylib.name.offset
        dylib_name = binary.read_string_at_address(dylib_name_addr)
        dylib_version = cmd.dylib.current_version
        print('\t{} v.{}'.format(dylib_name, hex(dylib_version)))


def print_binary_segments(binary: MachoBinary) -> None:
    print('\nSegments:')
    for segment, cmd in binary.segment_commands.items():
        print(f"\t[{format(cmd.vmaddr, '#011x')} - {format(cmd.vmaddr + cmd.vmsize, '#011x')}] {segment}")


def print_binary_sections(binary: MachoBinary) -> None:
    print('\nSections:')
    for section, cmd in binary.sections.items():
        print(f'\t[{hex(cmd.address)} - {hex(cmd.end_address)}] {section}')


def print_analyzer_imported_symbols(analyzer: MachoAnalyzer) -> None:
    print('\nSymbols:')
    print('\tImported symbols:')
    stub_map = analyzer.external_symbol_names_to_branch_destinations
    for imported_sym in analyzer.imported_symbols:
        print('\t\t{}'.format(imported_sym))
        # attempt to find the call stub for this symbol
        if imported_sym in stub_map:
            print('\t\t\tCallable dyld stub @ {}'.format(hex(stub_map[imported_sym])))


def print_analyzer_exported_symbols(analyzer: MachoAnalyzer) -> None:
    print('\tExported symbols:')
    for exported_sym in analyzer.exported_symbols:
        print('\t\t{}'.format(exported_sym))


def print_analyzer_methods(analyzer: MachoAnalyzer) -> None:
    print('\nObjective-C Methods:')
    methods = analyzer.get_objc_methods()
    for method_info in methods:
        # belongs to a class or category?
        if isinstance(method_info.objc_class, ObjcCategory):
            category = method_info.objc_class   # type: ObjcCategory
            class_name = '{} ({})'.format(category.base_class, category.name)
        else:
            class_name = method_info.objc_class.name

        print('\t-[{} {}] defined at {}'.format(class_name,
                                                method_info.objc_sel.name,
                                                hex(method_info.objc_sel.implementation)))


def print_analyzer_classes(analyzer: MachoAnalyzer):
    print('\nObjective-C Classes:')
    classes = analyzer.objc_classes()
    for objc_class in classes:
        # belongs to a class or category?
        if isinstance(objc_class, ObjcCategory):
            category = objc_class   # type: ObjcCategory
            class_name = '{} ({})'.format(category.base_class, category.name)
        else:
            class_name = objc_class.name
        print(f'\t{class_name}: {len(objc_class.selectors)} selectors')


def print_analyzer_protocols(analyzer: MachoAnalyzer):
    print('\nProtocols conformed to within the binary:')
    protocols = analyzer.get_conformed_protocols()
    for protocol in protocols:
        print(f'\t{protocol.name}: {len(protocol.selectors)} selectors')
