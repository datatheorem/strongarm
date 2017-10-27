from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from strongarm.macho.macho_definitions import *
from strongarm.macho.macho_parse import MachoParser


class TestFatMachO(unittest.TestCase):

    def setUp(self):
        self.thin_parser = MachoParser(u'./bin/StrongarmTarget')
        self.fat_parser = MachoParser(u'./bin/GammaRayTestBad')

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
            self.assertTrue(magic == MachArch.MH_MAGIC_64 or magic == MachArch.MH_CIGAM_64)
            self.assertTrue(self.fat_parser._check_is_macho_header(slice.offset_within_fat))
