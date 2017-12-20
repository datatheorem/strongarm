# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import unittest
import os

from strongarm.macho.macho_definitions import MachArch
from strongarm.macho.macho_parse import MachoParser


class TestFatMachO(unittest.TestCase):
    THIN_BIN_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')
    FAT_BIN_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'GammaRayTestBad')

    def setUp(self):
        self.thin_parser = MachoParser(TestFatMachO.THIN_BIN_PATH)
        self.fat_parser = MachoParser(TestFatMachO.FAT_BIN_PATH)

    def test_fat_parsing(self):
        self.assertFalse(self.thin_parser.is_fat)
        self.assertTrue(self.fat_parser.is_fat)
        # ensure we have at most header.nfat_arch slices found
        max_slices = self.fat_parser.header.nfat_arch
        self.assertLessEqual(len(self.fat_parser.slices), max_slices)

    def test_endianness(self):
        self.assertFalse(self.thin_parser.is_swapped)
        self.assertTrue(self.fat_parser.is_swapped)

    def test_slices(self):
        for slice in self.fat_parser.slices:
            magic = slice.header.magic
            self.assertIn(magic, MachoParser.SUPPORTED_MAG)
            self.assertTrue(self.fat_parser._check_is_macho_header(slice._offset_within_fat))
