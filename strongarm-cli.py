# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import sys
import re
import argparse
from ctypes import sizeof

from strongarm.macho import MachoParser, MachoBinary, MachoAnalyzer, ObjcCategory, ObjcClass
from strongarm.macho import CPU_TYPE, DylibCommand
from strongarm.debug_util import DebugUtil
from strongarm.objc import CodeSearch, CodeSearchTermCallDestination, RegisterContentsType, ObjcFunctionAnalyzer, \
    ObjcBranchInstruction, ObjcBasicBlock


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


def print_header(args) -> None:
    header_lines = [
        '\nstrongarm - Mach-O analyzer',
        '{}'.format(args.binary_path),
    ]
    # find longest line
    longest_line_len = 0
    for line in header_lines:
        longest_line_len = max(longest_line_len, len(line))
    # add a line of hyphens, where the hyphen count matches the longest line
    header_lines.append('-' * longest_line_len)
    header_lines.append('')

    # print header
    for line in header_lines:
        print(line)


parser = argparse.ArgumentParser(description='Mach-O Analyzer')
parser.add_argument(
    '--verbose', action='store_true', help=
    'Output extra info while analyzing'
)
parser.add_argument(
    'binary_path', metavar='binary_path', type=str, help=
    'Path to binary to analyze'
)
args = parser.parse_args()

if args.verbose:
    DebugUtil.debug = True

print_header(args)

parser = MachoParser(args.binary_path)

# print slice info
print('Slices:')
for macho_slice in parser.slices:
    print('\t{} Mach-O slice @ {}'.format(macho_slice.cpu_type.name, hex(macho_slice._offset_within_fat)))

binary = pick_macho_slice(parser)

print('Reading {} slice'.format(binary.cpu_type.name))

endianness = 'Big' if binary.is_swap else 'Little'
endianness = '{} endian'.format(endianness)
print(endianness)
print('Virtual base: {}'.format(hex(binary.get_virtual_base())))

print('\nLoad commands:')
load_commands = binary.load_dylib_commands
for cmd in load_commands:
    dylib_name_addr = binary.get_virtual_base() + cmd.fileoff + cmd.dylib.name.offset
    dylib_name = binary.read_string_at_address(dylib_name_addr)
    dylib_version = cmd.dylib.current_version
    print('\t{} v.{}'.format(dylib_name, hex(dylib_version)))

print('\nSegments:')
for segment, cmd in binary.segment_commands.items():
    print('\t{} @ [{} - {}]'.format(segment, hex(cmd.vmaddr), hex(cmd.vmaddr + cmd.vmsize)))

print('\nSections:')
print('\tContains encrypted section? {}'.format(binary.is_encrypted()))
for section, cmd in binary.sections.items():
    print('\t{} @ [{} - {}]'.format(section, hex(cmd.address), hex(cmd.end_address)))

# we defer initializing the analyzer until as late as possible
# this is so we can still print out preliminary info about the binary, even if it's encrypted
analyzer = MachoAnalyzer.get_analyzer(binary)
print('\nSymbols:')
print('\tImported symbols:')
stub_map = analyzer.external_symbol_names_to_branch_destinations
for imported_sym in analyzer.imported_symbols:
    print('\t\t{}'.format(imported_sym))
    # attempt to find the call stub for this symbol
    if imported_sym in stub_map:
        print('\t\t\tCallable dyld stub @ {}'.format(hex(stub_map[imported_sym])))

print('\tExported symbols:')
for exported_sym in analyzer.exported_symbols:
    print('\t\t{}'.format(exported_sym))

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


from capstone import CsInsn
from capstone.arm64 import Arm64Op, ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

from typing import Text


def format_instruction_arg(instruction: CsInsn, arg: Arm64Op) -> Text:
    if arg.type == ARM64_OP_REG:
        return instruction.reg_name(arg.value.reg)
    elif arg.type == ARM64_OP_IMM:
        return hex(arg.value.imm)
    elif arg.type == ARM64_OP_MEM:
        return '[{} #{}]'.format(instruction.reg_name(arg.mem.base), hex(arg.mem.disp))
    raise RuntimeError('unknown arg type {}'.format(arg.type))


while True:
    print('\n\nEnter a SEL to disassemble:')
    desired_sel = input()
    try:
        desired_imp = [x for x in methods if x.objc_sel.name == desired_sel][0]
    except IndexError:
        print('Unknown SEL {}'.format(desired_sel))
        continue

    # figure out the arguments based on the sel name
    sel_components = desired_imp.objc_sel.name.split(':')
    sel_args = ['self', '@selector({})'.format(desired_imp.objc_sel.name)]
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

    signature = '\n\n-[{} {}]('.format(desired_imp.objc_class.name, desired_imp.objc_sel.name)
    for i, arg in enumerate(sel_args):
        signature += arg
        if i != len(sel_args) - 1:
            signature += ', '
    signature += ');'
    print(signature)

    function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(binary, desired_imp.imp_addr)

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
        wrapped_instr = function_analyzer.get_instruction_at_address(instr.address)
        if wrapped_instr.symbol:
            instruction_string += '#\t'
            instruction_string += wrapped_instr.symbol

            if isinstance(wrapped_instr, ObjcBranchInstruction):
                # TODO(PT): count args by counting colons in selector name
                if wrapped_instr.selector:
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

        print(instruction_string)
