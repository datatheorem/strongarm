import pathlib

from strongarm.macho.macho_analyzer import MachoAnalyzer, VirtualMemoryPointer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer


class TestBasicBlocks:
    TARGET_PATH = pathlib.Path(__file__).parent / 'bin' / 'StrongarmControlFlowTarget'

    def setup_method(self):
        parser = MachoParser(TestBasicBlocks.TARGET_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_find_basic_blocks_1(self):
        # Given I provide a method implementation which contains a switch statement
        function_analyzer = self.analyzer.get_imps_for_sel('switchControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x10000675c, 0x100006774), (0x100006774, 0x100006778), (0x100006778, 0x100006794),
            (0x100006794, 0x1000067a8), (0x1000067a8, 0x1000067b4), (0x1000067b4, 0x1000067c0),
            (0x1000067c0, 0x1000067cc), (0x1000067cc, 0x1000067d8), (0x1000067d8, 0x1000067e0),
            (0x1000067e0, 0x1000067e4), (0x1000067e4, 0x1000067f4),
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_2(self):
        # Given I provide a method implementation with a backwards local jump
        function_analyzer = self.analyzer.get_imps_for_sel('forControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x100006804, 0x100006820), (0x100006820, 0x10000682c), (0x10000682c, 0x100006838),
            (0x100006838, 0x100006848),
        ]

        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_3(self):
        # Given I provide a method implementation with a backwards local jump
        function_analyzer = self.analyzer.get_imps_for_sel('whileControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x100006848, 0x100006864), (0x100006864, 0x100006870), (0x100006870, 0x10000687c),
            (0x10000687c, 0x100006888), (0x100006888, 0x100006898),
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_4(self):
        # Given I provide a function with no internal branching
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(self.binary, VirtualMemoryPointer(0x100006898))

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then I see one big basic block
        correct_basic_blocks = [
            (0x100006898, 0x1000068b4), (0x1000068b4, 0x1000068cc), (0x1000068cc, 0x1000068d0),
            (0x1000068d0, 0x1000068d8), (0x1000068d8, 0x1000068f0), (0x1000068f0, 0x1000068fc),
            (0x1000068fc, 0x100006904), (0x100006904, 0x100006918),
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_5(self):
        # Given I provide a method implementation with forwards local jumps
        function_analyzer = self.analyzer.get_imps_for_sel('ifControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x1000066e4, 0x1000066f8), (0x1000066f8, 0x1000066fc), (0x1000066fc, 0x100006720),
            (0x100006720, 0x100006724), (0x100006724, 0x100006730), (0x100006730, 0x10000673c),
            (0x10000673c, 0x100006744), (0x100006744, 0x100006748), (0x100006748, 0x100006754),
            (0x100006754, 0x10000675c),
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_control_flow_6(self):
        # Given I provide a method implementation with both forwards and backwards local jumps
        function_analyzer = self.analyzer.get_imps_for_sel('nestedControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x100006648, 0x10000665c), (0x10000665c, 0x100006660), (0x100006660, 0x100006664),
            (0x100006664, 0x100006684), (0x100006684, 0x100006690), (0x100006690, 0x10000669c),
            (0x10000669c, 0x1000066a8), (0x1000066a8, 0x1000066b0), (0x1000066b0, 0x1000066bc),
            (0x1000066bc, 0x1000066c4), (0x1000066c4, 0x1000066d0), (0x1000066d0, 0x1000066e4),
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]
