from __future__ import absolute_import
from __future__ import unicode_literals

import os
import unittest

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer


class TestFunctionAnalyzer(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    def setUp(self):
        parser = MachoParser(TestFunctionAnalyzer.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

        self.implementations = self.analyzer.get_implementations(u'URLSession:didReceiveChallenge:completionHandler:')
        self.instructions = self.implementations[0]
        self.imp_addr = self.instructions[0].address
        self.function_analyzer = ObjcFunctionAnalyzer(self.binary, self.instructions)

    def test_call_targets(self):
        for i in self.function_analyzer.call_targets:
            # if no destination address, it can only be an external objc_msgSend call
            if not i.destination_address:
                self.assertTrue(i.is_msgSend_call)
                self.assertTrue(i.is_external_objc_call)
                self.assertIsNotNone(i.selref)
                self.assertIsNotNone(i.symbol)

        external_targets = {0x100006910: '_objc_retain',
                            0x1000068ec: '_objc_msgSend',
                            0x100006904: '_objc_release',
                            0x10000691c: '_objc_retainAutoreleasedReturnValue',
                            0x1000068bc: '_SecTrustEvaluate'
                            }
        local_targets = [0x1000067a8, # loc_1000067a8
                         0x100006794, # loc_100006794
        ]

        for target in self.function_analyzer.call_targets:
            if not target.destination_address:
                self.assertTrue(target.is_external_objc_call)
            else:
                self.assertTrue(target.destination_address in
                                external_targets.keys() + local_targets)
                if target.is_external_c_call:
                    correct_sym_name = external_targets[target.destination_address]
                    self.assertEqual(target.symbol, correct_sym_name)

    def test_can_execute_call(self):
        # external function
        secTrustEvaluate_address = 0x1000068bc
        self.assertTrue(self.function_analyzer.can_execute_call(secTrustEvaluate_address))

        # local branch
        local_branch_address = 0x1000067a8
        self.assertTrue(self.function_analyzer.can_execute_call(secTrustEvaluate_address))

        # fake destination
        self.assertFalse(self.function_analyzer.can_execute_call(0xdeadbeef))

    def test_determine_register_contents(self):
        func_arg_idx, is_func_arg = self.function_analyzer.determine_register_contents('x4', 0)
        self.assertEqual(func_arg_idx, 4)
        self.assertTrue(is_func_arg)

        register_val, is_func_arg = self.function_analyzer.determine_register_contents('x1', 16)
        self.assertEqual(register_val, 0x100008f40)
        self.assertFalse(is_func_arg)

    def test_get_selref(self):
        objc_msgSendInstr = self.instructions[16]
        selref = self.function_analyzer.get_selref_ptr(objc_msgSendInstr)
        self.assertEqual(selref, 0x100008f40)

        non_branch_instruction = self.instructions[15]
        self.assertRaises(ValueError, self.function_analyzer.get_selref_ptr, non_branch_instruction)

    def test_find_next_branch(self):
        # find first branch
        branch = self.function_analyzer.next_branch_after_instruction_index(0)
        self.assertIsNotNone(branch)
        self.assertFalse(branch.is_msgSend_call)
        self.assertFalse(branch.is_external_objc_call)
        self.assertTrue(branch.is_external_c_call)
        self.assertEqual(branch.symbol, '_objc_retain')
        self.assertEqual(branch.destination_address,  0x100006910)

        # find branch in middle of function
        branch = self.function_analyzer.next_branch_after_instruction_index(25)
        self.assertIsNotNone(branch)
        self.assertTrue(branch.is_msgSend_call)
        self.assertIsNotNone(branch.selref)

        # there's only 68 instructions, there's no way there could be another branch after this index
        branch = self.function_analyzer.next_branch_after_instruction_index(68)
        self.assertIsNone(branch)

    def test_track_register(self):
        found_registers_containing_initial_reg = self.function_analyzer.track_reg('x4')
        final_registers_containing_initial_reg = [u'x4', u'x19', u'x0']
        self.assertEqual(
            sorted(found_registers_containing_initial_reg),
            sorted(final_registers_containing_initial_reg)
        )
