"""Dump the entitlements of the provided binary.
"""
import argparse
import pathlib

from strongarm.macho import MachoParser


def main():
    arg_parser = argparse.ArgumentParser(description='dump a binary\'s entitlements')
    arg_parser.add_argument(
        'binary_path', metavar='binary_path', type=str, help=
        'Path to binary'
    )
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))

    for binary in parser.slices:
        print(f'Entitlements of {binary.cpu_type.name.lower()} slice:')
        print(binary.get_entitlements().decode())
        print()


if __name__ == '__main__':
    main()
