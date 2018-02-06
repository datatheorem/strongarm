# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import sys
import argparse

from strongarm.macho import MachoParser, MachoBinary, MachoAnalyzer
from strongarm.macho import CPU_TYPE
from strongarm.debug_util import DebugUtil
from strongarm.objc import CodeSearch, CodeSearchTermCallDestination, RegisterContentsType, ObjcFunctionAnalyzer


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
