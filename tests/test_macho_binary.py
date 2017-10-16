from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from gammaray.ios_app import IosAppPackage
import os


class TestMachoBinary(unittest.TestCase):
    IPA_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget.ipa')

    def test_imp_for_selref(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()

            self.assertEqual(binary.get_virtual_base(), 0x100000000)
