# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import unittest
import os

from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_analyzer import MachoAnalyzer


class FunctionBoundaryTests(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    def setUp(self):
        parser = MachoParser(FunctionBoundaryTests.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_function_boundary_ret(self):
        # found in Hopper
        # address of -[DTHAppDelegate application:didFinishLaunchingWithOptions:]
        # this function ends with a ret instruction
        start_address = 0x1000066dc
        end_address = 0x1000066e0
        actual_size = end_address - start_address

        _, guessed_end_address = self.analyzer._find_function_boundary(start_address, actual_size * 2, [])
        self.assertEqual(end_address, guessed_end_address)

    def test_function_boundary_bl(self):
        # found in Hopper
        # address of -[DTHAppDelegate setWindow:]
        # this function ends with a b/bl instruction
        start_address = 0x100006708
        end_address = 0x100006718

        actual_size = end_address - start_address

        _, guessed_end_address = self.analyzer._find_function_boundary(start_address, actual_size * 2, [])
        self.assertEqual(end_address, guessed_end_address)

    def test_find_method_code(self):
        sel = 'application:didFinishLaunchingWithOptions:'
        # found in Hopper
        correct_start_address = 0x1000066dc
        correct_end_address = 0x1000066e0

        imp_func = self.analyzer.get_imps_for_sel(sel)[0]
        self.assertEqual(correct_start_address, imp_func.start_address)
        self.assertEqual(correct_end_address, imp_func.end_address)

        instructions, start_address, end_address = self.analyzer._find_function_code(correct_start_address)
        self.assertEqual(correct_start_address, start_address)
        self.assertEqual(correct_end_address, end_address)
        self.assertEqual(correct_start_address, instructions[0].address)
        self.assertEqual(correct_end_address, instructions[-1].address)

        bytes_per_instruction = 4
        # add 1 to account for the instruction starting at end_address
        correct_instruction_count = int((correct_end_address - correct_start_address) / bytes_per_instruction) + 1
        self.assertEqual(correct_instruction_count, len(instructions))
