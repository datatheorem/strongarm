from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from strongarm.macho_parse import MachoParser
from strongarm.macho_binary import MachoBinary
from strongarm.macho_definitions import *


class TestThinMachO(unittest.TestCase):

    def setUp(self):
        self.parser = MachoParser(u'./bin/GoodCertificateValidation')

    def test_single_slice(self):
        # ensure only one slice is returned with a thin Mach-O
        slices = self.parser.slices
        self.assertEqual(len(slices), 1)
        slice = self.parser.slices[0]
        self.assertIsNotNone(slice)
        self.assertIsNotNone(slice.header)

    def test_correct_arch(self):
        slice = self.parser.slices[0]
        # GoodCertificateValidation is known to be a thin arm64 slice
        self.assertIsNotNone(slice)
        self.assertEqual(slice.cpu_type, CPU_TYPE.ARM64)

    def test_finds_segments(self):
        slice = self.parser.slices[0]
        # ensure standard segments are present
        self.assertIsNotNone(slice.segments['__PAGEZERO'])
        self.assertIsNotNone(slice.segments['__TEXT'])
        self.assertIsNotNone(slice.segments['__DATA'])
        self.assertIsNotNone(slice.segments['__LINKEDIT'])

    def test_find_symtabs(self):
        # did we find symtab command and dysymtab command?
        slice = self.parser.slices[0]
        self.assertIsNotNone(slice.symtab)
        self.assertIsNotNone(slice.dysymtab)

    def test_find_sections(self):
        slice = self.parser.slices[0]
        # try a few sections from different segment
        # from __TEXT:
        self.assertIsNotNone(slice.get_section_with_name('__text'))
        self.assertIsNotNone(slice.get_section_with_name('__stubs'))
        self.assertIsNotNone(slice.get_section_with_name('__objc_methname'))
        self.assertIsNotNone(slice.get_section_with_name('__objc_classname'))
        self.assertIsNotNone(slice.get_section_with_name('__cstring'))
        # from __DATA:
        self.assertIsNotNone(slice.get_section_with_name('__const'))
        self.assertIsNotNone(slice.get_section_with_name('__objc_classlist'))
        self.assertIsNotNone(slice.get_section_with_name('__data'))