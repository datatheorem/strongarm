from strongarm.macho import VirtualMemoryPointer
from strongarm.decompiler.variable import ConstantValue
from strongarm.decompiler.exec_context import ConditionFlag

from .utils import simulate_assembly


class TestAArch64CmpInstruction:
    # Less than, less equal, equal, greater equal, greater than
    def test_cmp__imm_lt(self):
        # Given I evaluate a comparison of a smaller number to a larger immediate number
        source = """
        mov x2, #0x800
        cmp x2, #0x900
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN]

    def test_cmp__reg_lt(self):
        # Given I evaluate a comparison of a smaller number to a larger number in a register
        source = """
        mov x2, #0x800
        mov x3, #0x801
        cmp x2, x3
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN]

    def test_cmp__imm_eq(self):
        # Given I evaluate a comparison of a number and itself as an immediate
        source = """
        mov x2, #0x800
        cmp x2, #0x800
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmp__reg_eq(self):
        # Given I evaluate a comparison of a number and itself in another register
        source = """
        mov x2, #0x800
        mov x3, #0x800
        cmp x2, x3
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmp__imm_gt(self):
        # Given I evaluate a comparison of a larger number to a smaller immediate number
        source = """
        mov x2, #0x800
        cmp x2, #0x700
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmp__reg_gt(self):
        # Given I evaluate a comparison of a larger number to a smaller number in another register
        source = """
        mov x2, #0x800
        mov x3, #0x799
        cmp x2, x3
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL]

    def test_flags_updated(self):
        # Given I perform multiple comparisons
        source = """
        mov x2, #0x100
        cmp x2, #0x300
        mov x4, #0x70
        cmp x2, x4
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The status register reflects the last conditional which was evaluated
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmp__reg_shifted(self):
        # Given I evaluate a comparison of a value in another register with a shift applied
        source = """
        mov x2, #0x1000
        mov x3, #0x1
        cmp x2, x3, lsl #12
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The status register indicates the operands were equal, because the shift was correctly applied
            assert ctx.condition_flags == [ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL]


class TestAArch64CmnInstruction:
    def test_cmn__imm_lt(self):
        # Given I evaluate a negative comparison of a smaller number to a larger immediate number
        source = """
        mov x2, #0x800
        cmn x2, #0x900
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmn__reg_lt(self):
        # Given I evaluate a negative comparison of a smaller number to a larger number in a register
        source = """
        mov x2, #0x800
        mov x3, #0x801
        cmn x2, x3
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmn__imm_eq(self):
        # Given I evaluate a comparison of a number and itself as a negative immediate
        source = """
        mov x2, #0x800
        cmn x2, #-0x800
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmn__reg_eq(self):
        # Given I evaluate a negative comparison of a number and itself in another register
        source = """
        mov x2, #0x800
        mov x3, #-0x800
        cmn x2, x3
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL]

    def test_cmn__imm_gt(self):
        # Given I evaluate a negative comparison of a larger number to a smaller immediate number
        source = """
        mov x2, #0x800
        cmn x2, #-0x900
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN]

    def test_cmn__reg_gt(self):
        # Given I evaluate a negative comparison of a larger number to a smaller number in another register
        source = """
        mov x2, #0x800
        mov x3, #-0x900
        cmn x2, x3
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The correct status flags are set
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN]

    def test_flags_updated(self):
        # Given I perform multiple negative comparisons
        source = """
        mov x2, #0x100
        cmn x2, #0x300
        mov x4, #-0x400
        cmn x2, x4
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The status register reflects the last conditional which was evaluated
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN]

    def test_cmn__reg_shifted(self):
        # Given I evaluate a negative comparison of a value in another register with a shift applied
        source = """
        mov x2, #-0x80
        mov x3, #0x1
        cmp x2, x3, lsl #12
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The status register indicates the first operand was lesser, because the shift was correctly applied
            assert ctx.condition_flags == [ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN]
