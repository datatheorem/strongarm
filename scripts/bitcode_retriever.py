"""Example implementation of `bitcode_retriever` using strongarm.
`bitcode_retriever` is a utility to extract the XAR containing LLVM embedded in a 'Bitcode' Mach-O
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import argparse
import pathlib

from strongarm.macho import MachoParser


def main() -> None:
    arg_parser = argparse.ArgumentParser(description="bitcode_retriever clone")
    arg_parser.add_argument("binary_path", metavar="binary_path", type=str, help="Path to Bitcode binary")
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))

    print(f"Reading {len(parser.slices)} Mach-O slices...")
    for binary in parser.slices:
        # Does the slice contain a Bitcode archive?
        bitcode_segment = binary.segment_with_name("__LLVM")
        if not bitcode_segment:
            continue

        # Dump the Bitcode  adjacent to this file, named <arch>.xar
        bitcode_segment = binary.segment_with_name("__LLVM")
        if not bitcode_segment:
            raise ValueError(f"The provided Mach-O does not contain Bitcode.")
        xar_data = binary.get_bytes(bitcode_segment.offset, bitcode_segment.size)

        # Place the bitcode adjacent to this file, named <arch>.xar
        output_path = pathlib.Path(__file__).parent / f"{binary.cpu_type.name.lower()}.xar"
        with open(output_path, "xb") as f:
            f.write(xar_data)

        print(f"Dumped {binary.cpu_type.name.lower()} Bitcode XAR to {output_path}")


if __name__ == "__main__":
    main()
