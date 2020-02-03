"""Add a load command to a binary.
This will invalidate the binary's load signature, if any.
"""
import argparse
import pathlib

from strongarm.macho import MachoBinary, MachoParser


def main():
    arg_parser = argparse.ArgumentParser(description="Add a load command to a binary")
    arg_parser.add_argument("binary_path", type=str, help="Path to binary")
    arg_parser.add_argument(
        "output_path",
        type=str,
        help="Path to write the modified binary (must not already exist)",
    )
    arg_parser.add_argument(
        "load_path", type=str, help="The dylib load path to be added to the binary"
    )
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))
    # Add the load command to each slice of the Mach-O
    modified_binaries = []
    for binary in parser.slices:
        # Inserting load commands is currently supported on 64-bit binaries only
        if not binary.is_64bit:
            continue
        modified_binary = binary.insert_load_dylib_cmd(args.load_path)
        modified_binaries.append(modified_binary)

    # Create an output FAT with each of the modified binaries
    MachoBinary.write_fat(modified_binaries, pathlib.Path(args.output_path))


if __name__ == "__main__":
    main()
