import pytest
import pathlib
from typing import Type

from strongarm.macho import VirtualMemoryPointer, MachoParser, MachoAnalyzer
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer

from strongarm.decompiler.variable import ConstantValue, Variable, NonLocalVariable
from strongarm.decompiler.objc_class import NSObject, FunctionArgumentObject, NSDictionary, NSNumber
from strongarm.decompiler.exec_context import ExecContext
from strongarm.decompiler.simulator import Simulator

from .utils import binary_containing_code, simulate_assembly

import logging

logging.basicConfig(level=logging.DEBUG)


class TestSimulator:
    def test_local_infinite_loop_exits(self):
        # Given source code which contains a function-local infinite loop
        source_code = """
        - (void)infiniteLoop {
            for (;;) {
                printf("bad!");
            }
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When the code is simulated
            func = ObjcFunctionAnalyzer.get_function_analyzer_for_signature(binary, 'SourceClass', 'infiniteLoop')
            sim = Simulator(analyzer, func, [func.start_address, func.end_address])

            # Then simulation eventually returns, because a maximum call-depth was exceeded
            sim.run()

    def test_non_local_infinite_loop_exits(self):
        # Given source code which contains a non-local infinite loop
        source_code = """
        - (int)m1 {
            return [self m2];
        }
        - (int)m2 {
            return [self m1];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When the code is simulated
            func = ObjcFunctionAnalyzer.get_function_analyzer_for_signature(binary, 'SourceClass', 'm1')
            sim = Simulator(analyzer, func, [func.start_address, func.end_address])
            # Then simulation eventually completes, because a maximum call-depth was exceeded
            sim.run()

    def test_write_sp_updates_exec_context(self):
        # Given I write to the register named sp
        source = """mov sp, #0x1000"""
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # Then the machine's stack_pointer_field is written
            assert ctx.stack_pointer == 0x1000

        # Given I write to the register named x13, which is a synonym for the stack pointer
        source = """mov x13, #0x2000"""
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # Then the machine's stack_pointer field is correctly updated
            assert ctx.stack_pointer == 0x2000

        # Given I add to the stack pointer register
        source = """add sp, sp, 0x500"""
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # Then the machine's stack_pointer field is correctly updated
            assert ctx.stack_pointer == ctx.VIRTUAL_STACK_BASE + 0x500

        # Given I subtract from the stack pointer register
        source = """sub sp, sp, 0x500"""
        # When I simulate the code
        with simulate_assembly(source) as ctxs:
            ctx = ctxs[0]
            # Then the machine's stack_pointer field is correctly updated
            assert ctx.stack_pointer == 0x8fffffb00
