from __future__ import absolute_import
from __future__ import unicode_literals

import os
import unittest

from gammaray.ios_app import IosAppPackage
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer


class TestFunctionAnalyzer(unittest.TestCase):
    IPA_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget.ipa')

    def test_call_targets(self):
        # we can't use setUp because the app binary file is context-managed by IosAppPackage
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range(
                'URLSession:didReceiveChallenge:completionHandler:'
            )
            instructions = analyzer.get_function_instructions(imp_addr)
            function_analyzer = ObjcFunctionAnalyzer(binary, instructions)

            for i in function_analyzer.call_targets:
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

            for target in function_analyzer.call_targets:
                if not target.destination_address:
                    self.assertTrue(target.is_external_objc_call)
                else:
                    self.assertTrue(target.destination_address in
                                    external_targets.keys() + local_targets)
                    if target.is_external_c_call:
                        correct_sym_name = external_targets[target.destination_address]
                        self.assertEqual(target.symbol, correct_sym_name)

    def test_can_execute_call(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range(
                'URLSession:didReceiveChallenge:completionHandler:'
            )
            instructions = analyzer.get_function_instructions(imp_addr)
            function_analyzer = ObjcFunctionAnalyzer(binary, instructions)

            # external function
            secTrustEvaluate_address = 0x1000068bc
            self.assertTrue(function_analyzer.can_execute_call(secTrustEvaluate_address))

            # local branch
            local_branch_address = 0x1000067a8
            self.assertTrue(function_analyzer.can_execute_call(secTrustEvaluate_address))

            # fake destination
            self.assertFalse(function_analyzer.can_execute_call(0xdeadbeef))

    def test_determine_register_contents(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range(
                'URLSession:didReceiveChallenge:completionHandler:'
            )
            instructions = analyzer.get_function_instructions(imp_addr)
            function_analyzer = ObjcFunctionAnalyzer(binary, instructions)

            # there's no way we could determine the value of an initial argument
            self.assertRaises(
                RuntimeError,
                function_analyzer.determine_register_contents,
                'x4', 0
            )

            register_val = function_analyzer.determine_register_contents('x1', 16)
            self.assertEqual(register_val, 0x100008f40)

    def test_get_selref(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range(
                'URLSession:didReceiveChallenge:completionHandler:'
            )
            instructions = analyzer.get_function_instructions(imp_addr)
            function_analyzer = ObjcFunctionAnalyzer(binary, instructions)

            objc_msgSendInstr = instructions[16]
            selref = function_analyzer.get_selref(objc_msgSendInstr)
            self.assertEqual(selref, 0x100008f40)

            non_branch_instruction = instructions[15]
            self.assertRaises(ValueError, function_analyzer.get_selref, non_branch_instruction)

    def test_find_next_branch(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range(
                'URLSession:didReceiveChallenge:completionHandler:'
            )
            instructions = analyzer.get_function_instructions(imp_addr)

            function_analyzer = ObjcFunctionAnalyzer(binary, instructions)

            # find first branch
            branch = function_analyzer.next_branch(0)
            self.assertIsNotNone(branch)
            self.assertFalse(branch.is_msgSend_call)
            self.assertFalse(branch.is_external_objc_call)
            self.assertTrue(branch.is_external_c_call)
            self.assertEqual(branch.symbol, '_objc_retain')
            self.assertEqual(branch.destination_address,  0x100006910)

            # find branch in middle of function
            branch = function_analyzer.next_branch(25)
            self.assertIsNotNone(branch)
            self.assertTrue(branch.is_msgSend_call)
            self.assertIsNotNone(branch.selref)

            # there's only 68 instructions
            branch = function_analyzer.next_branch(68)
            self.assertIsNone(branch)

    def test_track_register(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range(
                'URLSession:didReceiveChallenge:completionHandler:'
            )
            instructions = analyzer.get_function_instructions(imp_addr)

            function_analyzer = ObjcFunctionAnalyzer(binary, instructions)
            found_registers_containing_initial_reg = function_analyzer.track_reg('x4')
            final_registers_containing_initial_reg = [u'x4', u'x19', u'x0']
            self.assertEqual(
                sorted(found_registers_containing_initial_reg),
                sorted(final_registers_containing_initial_reg)
            )
