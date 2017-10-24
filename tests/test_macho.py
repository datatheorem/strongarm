from __future__ import absolute_import
from __future__ import unicode_literals

import unittest

from strongarm.macho.macho_definitions import *
from strongarm.macho.macho_parse import MachoParser


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
        self.assertIsNotNone(slice.segment_commands['__PAGEZERO'])
        self.assertIsNotNone(slice.segment_commands['__TEXT'])
        self.assertIsNotNone(slice.segment_commands['__DATA'])
        self.assertIsNotNone(slice.segment_commands['__LINKEDIT'])

    def test_find_symtabs(self):
        # did we find symtab command and dysymtab command?
        slice = self.parser.slices[0]
        self.assertIsNotNone(slice.symtab)
        self.assertIsNotNone(slice.dysymtab)

    def test_find_sections(self):
        slice = self.parser.slices[0]
        # try a few sections from different segment
        # from __TEXT:
        self.assertIsNotNone(slice.sections['__text'])
        self.assertIsNotNone(slice.sections['__stubs'])
        self.assertIsNotNone(slice.sections['__objc_methname'])
        self.assertIsNotNone(slice.sections['__objc_classname'])
        self.assertIsNotNone(slice.sections['__cstring'])
        # from __DATA:
        self.assertIsNotNone(slice.sections['__const'])
        self.assertIsNotNone(slice.sections['__objc_classlist'])
        self.assertIsNotNone(slice.sections['__data'])

    def test_header_flags(self):
        slice = self.parser.slices[0]
        # this binary is known to have masks 1, 4, 128, 2097152
        self.assertTrue(HEADER_FLAGS.NOUNDEFS in slice.header_flags)
        self.assertTrue(HEADER_FLAGS.DYLDLINK in slice.header_flags)
        self.assertTrue(HEADER_FLAGS.TWOLEVEL in slice.header_flags)
        self.assertTrue(HEADER_FLAGS.PIE in slice.header_flags)

        # the binary definitely shouldn't have this flag
        self.assertFalse(HEADER_FLAGS.ROOT_SAFE in slice.header_flags)
