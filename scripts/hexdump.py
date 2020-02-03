"""Example implementation of `hexdump` using strongarm.
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import argparse
import pathlib

from strongarm.macho import MachoParser, StaticFilePointer


def dump_memory(parser: MachoParser, start_address: int, size: int) -> None:
    # XXX(PT): Modified from strongarm-cli
    data = parser.get_bytes(StaticFilePointer(start_address), size)

    # split to 16 byte regions
    region_size = 16
    current_index = 0
    while True:
        if current_index >= size or current_index >= len(data):
            break
        # grab the next grouping of bytes
        byte_region = data[current_index : current_index + region_size]

        region_start = start_address + current_index
        print(f"{region_start:#011x}", end="\t\t")

        ascii_rep = "|"
        for idx, byte in enumerate(byte_region):
            print("{:02x}".format(byte), end=" ")
            # indent every 8 bytes
            if idx > 0 and (idx + 1) % 8 == 0:
                print("\t", end="")

            ascii_byte = chr(byte) if 32 <= byte < 127 else "."
            ascii_rep += ascii_byte
        ascii_rep += "|"
        print(ascii_rep)

        current_index += region_size


def main():
    arg_parser = argparse.ArgumentParser(description="hexdump clone")
    arg_parser.add_argument("binary_path", type=str, help="Path to binary")
    arg_parser.add_argument(
        "-s",
        dest="start_address_str",
        type=str,
        help="Byte-count to skip before beginning hexdump (base16)",
    )
    arg_parser.add_argument(
        "-n", dest="count", type=int, help="Number of bytes to hex-dump"
    )
    arg_parser.set_defaults(start_address_str="0x0", count=0x100000000)
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))
    # Convert hex string to int
    start_address = int(args.start_address_str, 16)
    dump_memory(parser, start_address, args.count)


if __name__ == "__main__":
    main()
