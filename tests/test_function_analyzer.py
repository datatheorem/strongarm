from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from strongarm.macho_analyzer import MachoAnalyzer
from strongarm.objc_analyzer import ObjcFunctionAnalyzer
from gammaray.ios_app import IosAppPackage
import os


class TestFunctionAnalyzer(unittest.TestCase):
    IPA_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget.ipa')

    def test_call_targets(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            imp_addr, _ = app.get_main_executable().get_method_address_range('URLSession:didReceiveChallenge:completionHandler:')
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

