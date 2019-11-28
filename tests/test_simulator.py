import pytest
import pathlib
from typing import Type

from strongarm.macho import VirtualMemoryPointer, MachoParser, MachoAnalyzer
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer

from strongarm.decompiler.variable import ConstantValue, Variable, NonLocalVariable
from strongarm.decompiler.objc_class import NSObject, FunctionArgumentObject, NSDictionary, NSNumber
from strongarm.decompiler.exec_context import ExecContext
from strongarm.decompiler.simulator import Simulator

from .utils import binary_containing_code

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
