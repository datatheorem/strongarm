from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from gammaray.ios_app import *


class FileChecksTests(unittest.TestCase):

    IPA_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'GammaRayTestGood.ipa')

    def test_function_boundary_ret(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)
            # found in Hopper
            # address of -[DTHAppDelegate application:didFinishLaunchingWithOptions:]
            # this function ends with a ret instruction
            start_address = 0x1000045f0
            end_address = 0x100004834
            actual_size = end_address - start_address

            guessed_end_address = analyzer._find_function_boundary(start_address, actual_size * 2)
            self.assertEqual(end_address, guessed_end_address)

    def test_function_boundary_bl(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            # found in Hopper
            # address of -[DTHAppDelegate setWindow:]
            # this function ends with a b/bl instruction
            start_address = 0x1000049d4
            end_address = 0x100004a34
            actual_size = end_address - start_address

            guessed_end_address = analyzer._find_function_boundary(start_address, actual_size * 2)
            self.assertEqual(end_address, guessed_end_address)

    def test_get_method_address_range(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            sel = 'application:didFinishLaunchingWithOptions:'
            # found in Hopper
            correct_start_address = 0x1000045f0
            correct_end_address = 0x100004834

            found_start_address, found_end_address = app.get_main_executable().get_method_address_range(sel)
            self.assertEqual(correct_start_address, found_start_address)
            self.assertEqual(correct_end_address, found_end_address)

    def test_get_method_size(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            sel = 'application:didFinishLaunchingWithOptions:'
            # found in Hopper
            correct_start_address = 0x1000045f0
            correct_end_address = 0x100004834
            correct_size = correct_end_address - correct_start_address

            guessed_size = app.get_main_executable().get_method_size(sel)
            self.assertEqual(correct_size, guessed_size)
