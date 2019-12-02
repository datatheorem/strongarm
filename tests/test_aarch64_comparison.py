from strongarm.decompiler import ConstantValue
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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN}

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
            assert ctx.condition_flags == {ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL}


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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.GREATER_THAN,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.GREATER_EQUAL}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN}

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
            assert ctx.condition_flags == {ConditionFlag.NOT_EQUAL,
                                           ConditionFlag.LESS_EQUAL,
                                           ConditionFlag.LESS_THAN}


class TestAArch64CSelInstruction:
    def test_select_op0(self):
        # Given I perform a conditional select where the evaluated condition was "greater than"
        source = """
        ; Compare some data
        mov x0, #0x200
        mov x1, #0x100
        cmp x0, x1
        
        mov x5, #0x1
        mov x6, #0x2
        ; Choose 1 or 2 based on the conditional evaluation
        csel x4, x5, x6, ge
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The 1st operand was selected, because the condition was true
            assert ctx.register('x4').read(ConstantValue).value() == 0x1

    def test_select_op1(self):
        # Given I perform a conditional select where the evaluated condition was "not equal"
        source = """
        ; Compare some equal data
        mov x0, #0x200
        mov x1, #0x200
        cmp x0, x1

        mov x5, #0x1
        mov x6, #0x2
        ; Choose 1 or 2 based on the conditional evaluation
        csel x4, x5, x6, ne
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The 2nd operand was selected, because the condition was false
            assert ctx.register('x4').read(ConstantValue).value() == 0x2


class TestAArch64CcmpInstruction:
    def test_ccmp__initial_condition_passed(self):
        # Given I perform a conditional compare where the initial condition is true
        source = """
        ; Set up a "greater-than" comparison
        mov x4, #0x300
        cmp x4, #0x250
        
        mov x0, #0xf00d
        mov x1, x0
        
        ; Compare x0 and x1 only if the previous condition was greater-than
        ; Comparing x0 and x1 will move 0x4 (EQUAL) into status register
        ; Else, move 0xa (LESS_THAN) into status register
        ccmp x0, x1, #0xa, ge
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The status register is set to EQUAL, because:
            # - The initial condition to ccmp was true
            # - Therefore, op0 and op1 were compared
            assert ctx.condition_flags == {ConditionFlag.EQUAL,
                                           ConditionFlag.GREATER_EQUAL,
                                           ConditionFlag.LESS_EQUAL}

    def test_ccmp__initial_condition_failed(self):
        # Given I perform a conditional compare where the initial condition is false
        source = """
        ; Set up an "equal" comparison
        mov x4, #0x250
        cmp x4, #0x250

        mov x0, #0xf00d
        mov x1, #0xf00e

        ; Compare x0 and x1 only if the previous condition was not-equal
        ; Comparing x0 and x1 will move 0x0 (GREATER_THAN) into the status register
        ; Else, move 0xa (LESS_THAN) into status register
        ccmp x0, x1, #0xa, ne
        """
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # The status register is set to LESS_THAN, because:
            # - The initial condition to ccmp was false
            # - Therefore, the status register was overridden with the value of the 3rd operand
            assert ctx.condition_flags == {ConditionFlag.LESS_THAN}
