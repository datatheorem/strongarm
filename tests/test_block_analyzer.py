# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import os
import unittest

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcBlockAnalyzer


class TestBlockAnalyzer(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    def setUp(self):
        parser = MachoParser(TestBlockAnalyzer.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

        self.implementations = self.analyzer.get_imps_for_sel(u'URLSession:didReceiveChallenge:completionHandler:')
        self.instructions = self.implementations[0].instructions
        self.imp_addr = self.instructions[0].address
        self.block_analyzer = ObjcBlockAnalyzer(self.binary, self.instructions, u'x4')

    def test_find_block_invoke(self):
        self.assertIsNotNone(self.block_analyzer.invoke_instruction)

        correct_invoke_idx = 53
        invoke_instr_idx = self.instructions.index(self.block_analyzer.invoke_instruction.raw_instr)
        self.assertEqual(correct_invoke_idx, invoke_instr_idx)

    def test_find_block_invocation_instruction_index(self):
        correct_invoke_idx = 53
        reported_invoke_idx = self.block_analyzer.invocation_instruction_index
        self.assertEqual(correct_invoke_idx, reported_invoke_idx)
