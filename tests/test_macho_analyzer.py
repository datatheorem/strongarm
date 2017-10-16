from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from strongarm.macho_analyzer import MachoAnalyzer
from strongarm.objc_analyzer import ObjcFunctionAnalyzer
from gammaray.ios_app import IosAppPackage
import os


class TestMachoAnalyzer(unittest.TestCase):
    IPA_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget.ipa')

    def test_imp_for_selref(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            # selref for -[DTLabel configureLabel]
            imp_within_bin_selref = 0x100008ef8
            found_imp_address = analyzer.imp_for_selref(imp_within_bin_selref)
            correct_imp_address = 0x100006514
            self.assertTrue(found_imp_address == correct_imp_address)

            # selref for -[UIFont systemFontOfSize:]
            imp_outside_bin_selref = 0x100008f08
            self.assertRaises(analyzer.imp_for_selref(imp_outside_bin_selref))

            imp_nonexisting = None
            self.assertIsNone(analyzer.imp_for_selref(imp_nonexisting))

    def test_get_function_address_range(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            start_addr = 0x1000066b0
            correct_end_addr = 0x1000067c0

            start, end = analyzer.get_function_address_range(start_addr)
            self.assertEqual(end, correct_end_addr)
