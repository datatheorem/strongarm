"""Example implementation of `lipo` using strongarm.
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import pathlib
import argparse

from strongarm.macho import MachoParser, MachoBinary


def main():
    arg_parser = argparse.ArgumentParser(description='lipo clone')
    arg_parser.add_argument(
        '-archs', action='store_true', help='Display the architecture names present in each slice of the archive.'
    )
    arg_parser.add_argument(
        '-create', action='store_true', help='Create a FAT archive from the provided input files'
    )
    arg_parser.add_argument(
        '-extract', dest='desired_arch', type=str, help=
        'Extract a single architecture from the input FAT into an output file'
    )
    arg_parser.add_argument(
        'input_paths', type=str, nargs='+', help=
        'Path to binary'
    )
    arg_parser.add_argument(
        'output_path', type=str, nargs='?', help='Path to place generated binary, if using -create or -extract'
    )
    args = arg_parser.parse_args()

    if args.archs:
        for file in args.input_paths:
            parser = MachoParser(pathlib.Path(file))
            # Print each architecture in the archive
            for slice in parser.slices:
                print(slice.cpu_type.name.lower())
        return

    if args.create:
        if not args.output_path:
            raise ValueError(f'-create option requires an output_path')
        parsers = [MachoParser(pathlib.Path(path)) for path in args.input_paths]
        all_slices = []
        for parser in parsers:
            all_slices += parser.slices
        MachoBinary.write_fat(all_slices, pathlib.Path(args.output_path))
        return

    if args.extract:
        if not args.output_path:
            raise ValueError(f'-create option requires an output_path')
        # Find the desired architecture in the slices of the input files
        for input_path in args.input_paths:
            parser = MachoParser(pathlib.Path(input_path))
            for binary in parser.slices:
                if binary.cpu_type.name.lower() == args.desired_arch:
                    # Found the desired slice - extract it into its own output binary
                    binary.write_binary(pathlib.Path(args.output_path))
                    return
        print(f'Failed to find a {args.desired_arch} slice in the input archives.')
        return


if __name__ == '__main__':
    main()
