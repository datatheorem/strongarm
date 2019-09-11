"""Example implementation of `extract_xar` using strongarm.
`extract_xar` is a utility to extract the XAR containing LLVM embedded in a 'Bitcode' Mach-O
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import pathlib
import argparse

from strongarm.macho import MachoParser


def main():
    arg_parser = argparse.ArgumentParser(description='extract_xar clone')
    arg_parser.add_argument(
        'binary_path', metavar='binary_path', type=str, help=
        'Path to Bitcode binary'
    )
    arg_parser.add_argument(
        'output_path', metavar='output_path', type=str, help=
        'Path to output the extracted XAR containing LLVM bitcode'
    )
    args = arg_parser.parse_args()

    binary = MachoParser(pathlib.Path(args.binary_path)).get_arm64_slice()
    # Dump the contents of the __LLVM segment to the output file
    bitcode_segment = binary.segment_with_name('__LLVM')
    if not bitcode_segment:
        raise ValueError(f'The provided Mach-O does not contain Bitcode.')

    xar_data = binary.get_bytes(bitcode_segment.fileoff, bitcode_segment.filesize)
    with open(args.output_path, 'xb') as f:
        f.write(xar_data)


if __name__ == '__main__':
    main()
