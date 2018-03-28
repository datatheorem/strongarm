# -*- coding: utf-8 -*-

import argparse


from strongarm.cli.utils import pick_macho_slice, disassemble_method
from strongarm.macho import MachoParser, MachoAnalyzer, ObjcCategory
from strongarm.debug_util import DebugUtil


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


class StrongarmShell:
    def __init__(self, binary: MachoBinary, analyzer: MachoAnalyzer):
        self.binary = binary
        self.analyzer = analyzer

        self.commands = {
            'help': ('Display available commands', self.help),
            'exit': ('Exit interactive shell', self.exit),
            'info': (InfoCommand(self.binary, self.analyzer).description(), self.info)
        }
        print('strongarm interactive shell\nType \'help\' for available commands.')
        self.active = True

    def help(self, args):
        print('Commands\n'
              '----------------')
        for name, (description, funcptr) in self.commands.items():
            print(f'{name}: {description}')

    def info(self, args):
        info_cmd = InfoCommand(self.binary, self.analyzer)
        if not len(args):
            print('No option provided')
            print(info_cmd.description())
        for option in args:
            info_cmd.run_command(option)

    def exit(self, args):
        print('Quitting...')
        self.active = False

    def process_command(self):
        user_input = input('strongarm$ ')
        components = user_input.split(' ')
        cmd_name = components[0]
        cmd_args = components[1:]

        if cmd_name not in self.commands:
            print(f'Unknown command: \'{cmd_name}\'. Type \'help\' for available commands.')
            return self.active

        func = self.commands[cmd_name][1]
        func(cmd_args)
        return self.active


def main():
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
    print('Mach-O type: {}'.format(binary.file_type.name))

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

    while True:
        print('\n\nEnter a SEL to disassemble:')
        desired_sel = input()
        try:
            desired_method = [x for x in methods if x.objc_sel.name == desired_sel][0]
            disassembled_str = disassemble_method(binary, desired_method)
            print(disassembled_str)
        except IndexError:
            print('Unknown SEL {}'.format(desired_sel))
            continue


if __name__ == '__main__':
    main()
