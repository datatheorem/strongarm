from __future__ import absolute_import
from __future__ import unicode_literals

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
        start_address = 0x100006844
        end_address = 0x100006848
        actual_size = end_address - start_address

        guessed_end_address = self.analyzer._find_function_boundary(start_address, actual_size * 2)
        self.assertEqual(end_address, guessed_end_address)

    def test_function_boundary_bl(self):
        # found in Hopper
        # address of -[DTHAppDelegate setWindow:]
        # this function ends with a b/bl instruction
        start_address = 0x100006870
        end_address = 0x100006880

        actual_size = end_address - start_address

        guessed_end_address = self.analyzer._find_function_boundary(start_address, actual_size * 2)
        self.assertEqual(end_address, guessed_end_address)

    def test_get_method_address_range(self):
        sel = 'application:didFinishLaunchingWithOptions:'
        # found in Hopper
        correct_start_address = 0x100006844
        correct_end_address = 0x100006848

        found_start_address, found_end_address = self.analyzer.get_method_address_range(sel)
        self.assertEqual(correct_start_address, found_start_address)
        self.assertEqual(correct_end_address, found_end_address)

    def test_get_method_size(self):
        sel = 'application:didFinishLaunchingWithOptions:'
        # found in Hopper
        correct_start_address = 0x100006844
        correct_end_address = 0x100006848
        correct_size = correct_end_address - correct_start_address

        guessed_size = self.analyzer.get_method_size(sel)
        self.assertEqual(correct_size, guessed_size)
