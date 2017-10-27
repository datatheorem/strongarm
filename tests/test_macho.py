from __future__ import absolute_import
from __future__ import unicode_literals

import unittest
import os

from strongarm.macho.macho_definitions import *
from strongarm.macho.macho_parse import MachoParser


class TestMachoBinary(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'GoodCertificateValidation')

    def setUp(self):
        self.parser = MachoParser(TestMachoBinary.FAT_PATH)
        # ensure only one slice is returned with a thin Mach-O
        slices = self.parser.slices
        self.assertEqual(len(slices), 1)
        self.binary = self.parser.slices[0]
        self.assertIsNotNone(self.binary)

    def test_virt_base(self):
        self.assertEqual(self.binary.get_virtual_base(), 0x100000000)

    def test_single_slice(self):
        self.assertIsNotNone(self.binary)
        self.assertIsNotNone(self.binary.header)

    def test_correct_arch(self):
        # GoodCertificateValidation is known to be a thin arm64 slice
        self.assertIsNotNone(self.binary)
        self.assertEqual(self.binary.cpu_type, CPU_TYPE.ARM64)

    def test_finds_segments(self):
        # ensure standard segments are present
        self.assertIsNotNone(self.binary.segment_commands['__PAGEZERO'])
        self.assertIsNotNone(self.binary.segment_commands['__TEXT'])
        self.assertIsNotNone(self.binary.segment_commands['__DATA'])
        self.assertIsNotNone(self.binary.segment_commands['__LINKEDIT'])

    def test_find_symtabs(self):
        # did we find symtab command and dysymtab command?
        self.assertIsNotNone(self.binary.symtab)
        self.assertIsNotNone(self.binary.dysymtab)

    def test_find_sections(self):
        # try a few sections from different segment
        # from __TEXT:
        self.assertIsNotNone(self.binary.sections['__text'])
        self.assertIsNotNone(self.binary.sections['__stubs'])
        self.assertIsNotNone(self.binary.sections['__objc_methname'])
        self.assertIsNotNone(self.binary.sections['__objc_classname'])
        self.assertIsNotNone(self.binary.sections['__cstring'])
        # from __DATA:
        self.assertIsNotNone(self.binary.sections['__const'])
        self.assertIsNotNone(self.binary.sections['__objc_classlist'])
        self.assertIsNotNone(self.binary.sections['__data'])

    def test_header_flags(self):
        # this binary is known to have masks 1, 4, 128, 2097152
        self.assertTrue(HEADER_FLAGS.NOUNDEFS in self.binary.header_flags)
        self.assertTrue(HEADER_FLAGS.DYLDLINK in self.binary.header_flags)
        self.assertTrue(HEADER_FLAGS.TWOLEVEL in self.binary.header_flags)
        self.assertTrue(HEADER_FLAGS.PIE in self.binary.header_flags)

        # the binary definitely shouldn't have this flag
        self.assertFalse(HEADER_FLAGS.ROOT_SAFE in self.binary.header_flags)

    def test_get_symtab_contents(self):
        from pprint import pprint
        symtabs = self.binary.symtab_contents
        self.assertTrue(len(symtabs) == 31)
