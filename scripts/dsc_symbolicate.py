"""Generate a CSV symbol map from a dyld_shared_cache
"""
import argparse
import csv
import logging
from pathlib import Path
from typing import List, Tuple

from strongarm.macho import DyldSharedCacheParser, MachoAnalyzer, VirtualMemoryPointer
from strongarm.logger import strongarm_logger

logger = strongarm_logger.getChild(__file__)


def main() -> None:
    logging.basicConfig(level=logging.INFO)

    arg_parser = argparse.ArgumentParser(description="dyld_shared_cache symbol map generator")
    arg_parser.add_argument(
        "dyld_shared_cache_path", type=str, help="Path to the dyld_shared_cache which should be symbolicated"
    )
    arg_parser.add_argument("output_csv_path", type=str, help="Output CSV path")
    args = arg_parser.parse_args()

    dyld_shared_cache = DyldSharedCacheParser(Path(args.dyld_shared_cache_path))
    symbols: List[Tuple[VirtualMemoryPointer, str, Path]] = []

    # Iterate each image in the DSC, extract it, and record its symbols
    image_count = len(dyld_shared_cache.embedded_binary_info)
    for idx, path in enumerate(dyld_shared_cache.embedded_binary_info.keys()):
        # The DSC has more than 1,000 binaries, so try to free up resources after each image
        MachoAnalyzer.clear_cache()

        logger.info(f"({idx+1}/{image_count}) Symbolicating {path}...")
        try:
            binary = dyld_shared_cache.get_embedded_binary(path)
            analyzer = MachoAnalyzer.get_analyzer(binary)
            for sym, addr in analyzer.exported_symbol_names_to_pointers.items():
                symbols.append((VirtualMemoryPointer(addr), sym, path))
        except Exception:
            logger.error(f"Failed to symbolicate {path}")
            continue

    with open(str(args.output_csv_path), "w", newline="") as output_csv:
        csv_writer = csv.writer(output_csv, delimiter=",", quoting=csv.QUOTE_MINIMAL)
        for row in symbols:
            csv_writer.writerow(row)


if __name__ == "__main__":
    main()
