import pathlib

from strongarm.macho.macho_parse import MachoParser


class TestFatMachO:
    THIN_BIN_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"
    FAT_BIN_PATH = pathlib.Path(__file__).parent / "bin" / "TestBinary4"

    def setup_method(self) -> None:
        self.thin_parser = MachoParser(TestFatMachO.THIN_BIN_PATH)
        self.fat_parser = MachoParser(TestFatMachO.FAT_BIN_PATH)

    def test_fat_parsing(self) -> None:
        assert not self.thin_parser.is_fat
        assert self.fat_parser.is_fat
        # Ensure we have at most header.nfat_arch slices found
        assert self.fat_parser.header
        max_slices = self.fat_parser.header.nfat_arch
        assert len(self.fat_parser.slices) <= max_slices

    def test_endianness(self) -> None:
        assert not self.thin_parser.is_swapped
        assert self.fat_parser.is_swapped

    def test_slices(self) -> None:
        for slice in self.fat_parser.slices:
            magic = slice.header.magic
            assert magic in MachoParser.SUPPORTED_MAG
