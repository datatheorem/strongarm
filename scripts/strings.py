"""Example implementation of `strings` using strongarm.
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import pathlib
import argparse

from strongarm.macho import MachoParser, MachoBinary, MachoAnalyzer


def main():
    arg_parser = argparse.ArgumentParser(description='strings clone')
    arg_parser.add_argument(
        'binary_path', metavar='binary_path', type=str, help=
        'Path to binary whose strings should be printed'
    )
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))

    # Get the unique strings from all slices
    all_strings = set()
    for fat_slice in parser.slices:
        # Parsing the string table requires a MachoAnalyzer
        analyzer = MachoAnalyzer.get_analyzer(fat_slice)
        all_strings.update(analyzer.strings())

    for string in all_strings:
        print(string)


if __name__ == '__main__':
    main()
