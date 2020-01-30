import pathlib

from strongarm.macho.macho_analyzer import MachoAnalyzer, VirtualMemoryPointer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer
from tests.utils import function_containing_asm


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
        # (Right-exclusive basic blocks copied from Hopper's UI)
        correct_basic_blocks = [
            (0x10000675c, 0x100006794), (0x100006794, 0x1000067a8), (0x1000067a8, 0x1000067b4),
            (0x1000067b4, 0x1000067c0), (0x1000067c0, 0x1000067cc), (0x1000067cc, 0x1000067d8),
            (0x1000067d8, 0x1000067e0), (0x1000067e0, 0x1000067f4)
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_2(self):
        # Given I provide a method implementation with a backwards local jump
        function_analyzer = self.analyzer.get_imps_for_sel('forControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x100006804, 0x100006820), (0x100006820, 0x100006838), (0x100006838, 0x100006848)
        ]

        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_3(self):
        # Given I provide a method implementation with a backwards local jump
        function_analyzer = self.analyzer.get_imps_for_sel('whileControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x100006848, 0x100006864), (0x100006864, 0x10000687c), (0x10000687c, 0x100006898)
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_4(self):
        # Given I provide a function with no internal branching
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(self.binary, VirtualMemoryPointer(0x100006898))

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then I see one big basic block
        correct_basic_blocks = [
            (0x100006898, 0x100006918)
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_5(self):
        # Given I provide a method implementation with forwards local jumps
        function_analyzer = self.analyzer.get_imps_for_sel('ifControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x1000066e4, 0x100006720), (0x100006720, 0x100006724), (0x100006724, 0x100006730),
            (0x100006730, 0x10000673c), (0x10000673c, 0x100006744), (0x100006744, 0x10000675c),
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_control_flow_6(self):
        # Given I provide a method implementation with both forwards and backwards local jumps
        function_analyzer = self.analyzer.get_imps_for_sel('nestedControlFlow')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block-boundaries are correctly identified
        correct_basic_blocks = [
            (0x100006648, 0x100006660), (0x100006660, 0x100006684), (0x100006684, 0x100006690),
            (0x100006690, 0x1000066a8), (0x1000066a8, 0x1000066b0), (0x1000066b0, 0x1000066c4),
            (0x1000066c4, 0x1000066d0), (0x1000066d0, 0x1000066e4)
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_7(self):
        # Given I provide a method implementation with no conditional branching which ends in an unconditional jump
        binary_path = pathlib.Path(__file__).parent / 'bin' / 'StrongarmTarget'
        binary = MachoParser(binary_path).get_arm64_slice()
        analyzer = MachoAnalyzer.get_analyzer(binary)
        function_analyzer = analyzer.get_imps_for_sel('bluetoothManagerCall')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block boundaries are correctly identified
        correct_basic_blocks = [(0x100006534, 0x100006590)]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_find_basic_blocks_8(self):
        binary_path = pathlib.Path(__file__).parent / 'bin' / 'DynStaticChecks'
        binary = MachoParser(binary_path).get_arm64_slice()
        analyzer = MachoAnalyzer.get_analyzer(binary)
        function_analyzer = analyzer.get_imps_for_sel('UsageDESAlgorithm')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block boundaries are correctly identified
        correct_basic_blocks = [
            (0x100007b1c, 0x100007bc4), (0x100007bc4, 0x100007bd4), (0x100007bd4, 0x100007bd8)
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_early_return(self):
        # Given I provide a function that has a `ret` instruction on an early code path, with more basic blocks after it
        binary_path = pathlib.Path(__file__).parent / 'bin' / 'DynStaticChecks'
        binary = MachoParser(binary_path).get_arm64_slice()
        analyzer = MachoAnalyzer.get_analyzer(binary)
        function_analyzer = analyzer.get_imps_for_sel('earlyReturn')[0]

        # If I query the basic-block layout of the method
        basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

        # Then the basic-block boundaries are correctly identified
        correct_basic_blocks = [
            (0x100008e4c, 0x100008e6c), (0x100008e6c, 0x100008e8c), (0x100008e8c, 0x100008ed4),
            (0x100008ed4, 0x100008ee4), (0x100008ee4, 0x100008f24), (0x100008f24, 0x100008f3c)
        ]
        assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]

    def test_early_return2(self):
        # Given I provide a function that has a `ret` instruction on an early code path, with more basic blocks after it
        source = """
        mov x0, #0x123
        and x1, x0, #0x1
        ; Load the address after the ret. 
        ; Be careful with these lines!
        ldr x9, .+4
        br x9
        ; x0 was even - return early
        ret
        ; We checked a condition and jumped - run some more code
        mov x1, x0
        mov x0, x2
        """
        with function_containing_asm(source) as (analyzer, function_analyzer):
            # If I query the basic-block layout of the method
            basic_blocks = [(x.start_address, x.end_address) for x in function_analyzer.basic_blocks]

            # Then the basic-block boundaries are correctly identified
            correct_basic_blocks = [
                (0x100007f90, 0x100007fa0), (0x100007fa0, 0x100007fa4), (0x100007fa4, 0x100007fb4)
            ]
            assert basic_blocks == [(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in correct_basic_blocks]
