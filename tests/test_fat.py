from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from strongarm.macho_parse import MachoParser
from strongarm.macho_definitions import *

class TestFatMachO(unittest.TestCase):

    def setUp(self):
        self.parser = MachoParser(u'./bin/Payload/GammaRayTestBad.app/GammaRayTestBad')

    def test_fat_parsing(self):
        self.assertTrue(self.parser.is_fat)
        # ensure we have at most header.nfat_arch slices found
        max_slices = self.parser.header.nfat_arch
        self.assertLessEqual(len(self.parser.slices), max_slices)

    def test_endianness(self):
        self.assertTrue(self.parser.is_swapped)

    def test_slices(self):
        for slice in self.parser.slices:
            magic = slice.header.magic
            self.assertTrue(magic == MachArch.MH_MAGIC_64 or magic == MachArch.MH_CIGAM_64)
            self.assertTrue(self.parser._check_is_macho_header(slice.offset_within_fat))