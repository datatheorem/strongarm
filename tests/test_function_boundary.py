import pathlib

from strongarm.macho import MachoBinary, VirtualMemoryPointer
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser


class TestFunctionBoundary:
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"

    def setup_method(self):
        parser = MachoParser(TestFunctionBoundary.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_find_method_code(self):
        sel = "application:didFinishLaunchingWithOptions:"
        # found in Hopper
        correct_start_address = VirtualMemoryPointer(0x1000066DC)
        correct_end_address = VirtualMemoryPointer(0x1000066E4)

        imp_func = self.analyzer.get_imps_for_sel(sel)[0]
        assert imp_func.start_address == correct_start_address
        assert imp_func.end_address == correct_end_address

        instructions = self.analyzer.get_function_instructions(correct_start_address)
        start_address = instructions[0].address
        end_address = instructions[-1].address

        assert start_address == correct_start_address
        assert end_address == correct_end_address - MachoBinary.BYTES_PER_INSTRUCTION
        assert instructions[0].address == correct_start_address
        assert instructions[-1].address == correct_end_address - MachoBinary.BYTES_PER_INSTRUCTION

        correct_instruction_count = int(
            (correct_end_address - correct_start_address) / MachoBinary.BYTES_PER_INSTRUCTION
        )
        assert len(instructions) == correct_instruction_count
