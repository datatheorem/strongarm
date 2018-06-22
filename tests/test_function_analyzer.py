# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import os
import unittest

from strongarm.macho import MachoAnalyzer, MachoParser
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction


class TestFunctionAnalyzer(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    OBJC_RETAIN_STUB_ADDR = 0x1000067cc
    SEC_TRUST_EVALUATE_STUB_ADDR = 0x100006760

    URL_SESSION_DELEGATE_IMP_ADDR = 0x100006420

    def setUp(self):
        parser = MachoParser(TestFunctionAnalyzer.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

        self.implementations = self.analyzer.get_imps_for_sel(u'URLSession:didReceiveChallenge:completionHandler:')
        self.instructions = self.implementations[0].instructions

        self.imp_addr = self.instructions[0].address
        self.assertEqual(self.imp_addr, TestFunctionAnalyzer.URL_SESSION_DELEGATE_IMP_ADDR)

        self.function_analyzer = ObjcFunctionAnalyzer(self.binary, self.instructions)

    def test_call_targets(self):
        for i in self.function_analyzer.call_targets:
            # if no destination address, it can only be an external objc_msgSend call
            if not i.destination_address:
                self.assertTrue(i.is_msgSend_call)
                self.assertTrue(i.is_external_objc_call)
                self.assertIsNotNone(i.selref)
                self.assertIsNotNone(i.symbol)

        external_targets = {0x1000067cc: '_objc_retain',
                            0x1000068ec: '_objc_msgSend',
                            0x1000067c0: '_objc_release',
                            0x1000067d8: '_objc_retainAutoreleasedReturnValue',
                            TestFunctionAnalyzer.SEC_TRUST_EVALUATE_STUB_ADDR: '_SecTrustEvaluate'
                            }
        local_targets = [0x100006504, # loc_100006504
                         0x100006518, # loc_100006518
        ]

        for target in self.function_analyzer.call_targets:
            if not target.destination_address:
                self.assertTrue(target.is_external_objc_call)
            else:
                self.assertTrue(target.destination_address in
                                list(external_targets.keys()) + local_targets)
                if target.is_external_c_call:
                    correct_sym_name = external_targets[target.destination_address]
                    self.assertEqual(target.symbol, correct_sym_name)

    def test_search_call_graph(self):
        from strongarm.objc import CodeSearch, CodeSearchTermCallDestination
        # external function
        search = CodeSearch([
            CodeSearchTermCallDestination(
                self.binary,
                invokes_address=TestFunctionAnalyzer.SEC_TRUST_EVALUATE_STUB_ADDR
            )
        ])
        results = self.function_analyzer.search_call_graph(search)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].found_instruction.address, 0x1000064a0)

        # local branch
        search = CodeSearch(
            [CodeSearchTermCallDestination(self.binary, invokes_address=0x100006518)]
        )
        results = self.function_analyzer.search_call_graph(search)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].found_instruction.address, 0x100006500)

        # fake destination
        search = CodeSearch(
            [CodeSearchTermCallDestination(self.binary, invokes_address=0xdeadbeef)],
        )
        results = self.function_analyzer.search_call_graph(search)
        self.assertEqual(len(results), 0)

    def test_search_selector(self):
        from strongarm.objc import CodeSearch, CodeSearchTermCallDestination
        query = CodeSearch(
            [CodeSearchTermCallDestination(self.binary, invokes_selector='initWithFrame:')],
        )
        results = self.analyzer.search_code(query)
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual(result.found_instruction.address, 0x100006254)
        self.assertEqual(result.found_instruction.symbol, '_objc_msgSendSuper2')
        self.assertEqual(result.found_instruction.selector.name, 'initWithFrame:')
        self.assertEqual(result.found_instruction.selref.selector_literal, 'initWithFrame:')
        self.assertEqual(result.found_instruction.selref.source_address, 0x100009070)

        self.assertEqual(result.found_function.start_address, 0x100006228)

    def test_get_register_contents_at_instruction(self):
        from strongarm.objc import RegisterContentsType
        first_instr = self.function_analyzer.get_instruction_at_index(0)
        contents = self.function_analyzer.get_register_contents_at_instruction('x4', first_instr)
        self.assertEqual(contents.type, RegisterContentsType.FUNCTION_ARG)
        self.assertEqual(contents.value, 4)

        another_instr = self.function_analyzer.get_instruction_at_index(16)
        contents = self.function_analyzer.get_register_contents_at_instruction('x1', another_instr)
        self.assertEqual(contents.type, RegisterContentsType.IMMEDIATE)
        self.assertEqual(contents.value, 0x1000090c0)

    def test_get_selref(self):
        objc_msgSendInstr = ObjcInstruction.parse_instruction(self.function_analyzer, self.instructions[16])
        selref = self.function_analyzer.get_selref_ptr(objc_msgSendInstr)
        self.assertEqual(selref, 0x1000090c0)

        non_branch_instruction = ObjcInstruction.parse_instruction(self.function_analyzer, self.instructions[15])
        self.assertRaises(ValueError, self.function_analyzer.get_selref_ptr, non_branch_instruction)

    def test_find_next_branch(self):
        # find first branch
        branch = self.function_analyzer.next_branch_after_instruction_index(0)
        self.assertIsNotNone(branch)
        self.assertFalse(branch.is_msgSend_call)
        self.assertFalse(branch.is_external_objc_call)
        self.assertTrue(branch.is_external_c_call)
        self.assertEqual(branch.symbol, '_objc_retain')
        self.assertEqual(branch.destination_address, TestFunctionAnalyzer.OBJC_RETAIN_STUB_ADDR)

        # find branch in middle of function
        branch = self.function_analyzer.next_branch_after_instruction_index(25)
        self.assertIsNotNone(branch)
        self.assertTrue(branch.is_msgSend_call)
        self.assertIsNotNone(branch.selref)

        # there's only 68 instructions, there's no way there could be another branch after this index
        branch = self.function_analyzer.next_branch_after_instruction_index(68)
        self.assertIsNone(branch)
