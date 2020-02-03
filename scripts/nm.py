"""Example implementation of `nm` using strongarm.
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import argparse
import pathlib

from strongarm.macho import MachoAnalyzer, MachoBinary, MachoParser


def get_source_library_of_imported_symbol(analyzer: MachoAnalyzer, symbol_name: str) -> str:
    # TODO(PT): This should be straightforward through MachoAnalyzer.imported_symbols
    # For now, we need to cross-reference the same info with the dyld bound-symbol map, which has more info
    bound_sym = [x for x in analyzer.dyld_bound_symbols.values() if x.name == symbol_name][0]
    return analyzer.binary.dylib_name_for_library_ordinal(bound_sym.library_ordinal)


def print_binary_symbols(binary: MachoBinary, verbose: bool = True) -> None:
    print(f"\n{binary.path.as_posix()} (for architecture {binary.cpu_type.name.lower()})")

    # Parsing the symbol table requires a MachoAnalyzer
    analyzer = MachoAnalyzer.get_analyzer(binary)

    # Print imported symbols
    for sym in analyzer.imported_symbols:
        segment = "U"
        source_library_info = ""  # Only include this when the verbose flag is set
        if verbose:
            segment = "(undefined)"
            source_library_info = f"(from {get_source_library_of_imported_symbol(analyzer, sym)})"

        # To match nm output, indent everything by the length of a 64-bit virtual address
        indent = " " * 11
        print(f"{indent} {segment} {sym} {source_library_info}")

    # Print exported symbols
    for addr, sym in analyzer.exported_symbol_pointers_to_names.items():
        section = binary.section_for_address(addr)
        section_name = section.name.decode()

        if verbose:
            # In verbose mode, report the source section as (segment,section)
            segment_name = section.cmd.segname.decode()
            section_name = f"({segment_name},{section_name})"
        else:
            # In non-verbose mode, report the source section as the first letter of the section name
            # Trim out the '__' prefix
            section_name = section_name[2:3].upper()

        print(f"{addr:#011x} {section_name} {sym}")


def main():
    arg_parser = argparse.ArgumentParser(description="nm clone")
    arg_parser.add_argument(
        "binary_path", metavar="binary_path", type=str, help="Path to binary whose symbol table should be output"
    )
    arg_parser.add_argument(
        "-m",
        action="store_true",
        help="Increase verbosity. Display the source library of imported symbols & list sections of exported symbols.",
    )
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))
    for fat_slice in parser.slices:
        print_binary_symbols(fat_slice, args.verbose)


if __name__ == "__main__":
    main()
