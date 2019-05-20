import os
from ctypes import create_string_buffer

from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.objc.dataflow import determine_function_boundary


class TestFunctionBoundary:
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    def setup_method(self):
        parser = MachoParser(TestFunctionBoundary.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_function_boundary_ret(self):
        # found in Hopper
        # address of -[DTHAppDelegate application:didFinishLaunchingWithOptions:]
        # this function ends with a ret instruction
        start_address = 0x1000066dc
        end_address = 0x1000066e0

        # defined in MachoAnalyzer
        max_function_size = 0x2000
        binary_data = self.binary.get_content_from_virtual_address(start_address, max_function_size)
        bytecode = create_string_buffer(bytes(binary_data), max_function_size)
        # not in cache. calculate function boundary, then cache it
        guessed_end_address = determine_function_boundary(bytecode, start_address)

        assert guessed_end_address == end_address

    def test_function_boundary_bl(self):
        # found in Hopper
        # address of -[DTHAppDelegate setWindow:]
        # this function ends with a b/bl instruction
        start_address = 0x100006708
        end_address = 0x100006718

        # defined in MachoAnalyzer
        max_function_size = 0x2000
        binary_data = self.binary.get_content_from_virtual_address(start_address, max_function_size)
        bytecode = create_string_buffer(bytes(binary_data), max_function_size)
        # not in cache. calculate function boundary, then cache it
        guessed_end_address = determine_function_boundary(bytecode, start_address)

        assert guessed_end_address == end_address

    def test_find_method_code(self):
        sel = 'application:didFinishLaunchingWithOptions:'
        # found in Hopper
        correct_start_address = 0x1000066dc
        correct_end_address = 0x1000066e0

        imp_func = self.analyzer.get_imps_for_sel(sel)[0]
        assert imp_func.start_address == correct_start_address
        assert imp_func.end_address == correct_end_address

        instructions = self.analyzer.get_function_instructions(correct_start_address)
        start_address = instructions[0].address
        end_address = instructions[-1].address

        assert start_address == correct_start_address
        assert end_address == correct_end_address
        assert instructions[0].address == correct_start_address
        assert instructions[-1].address == correct_end_address

        bytes_per_instruction = 4
        # add 1 to account for the instruction starting at end_address
        correct_instruction_count = int((correct_end_address - correct_start_address) / bytes_per_instruction) + 1
        assert len(instructions) == correct_instruction_count
