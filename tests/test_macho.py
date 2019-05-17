import os
import pytest

from strongarm.macho.macho_definitions import *
from strongarm.macho import MachoParser
from strongarm.macho import BinaryEncryptedError


class TestMachoBinary:
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')
    ENCRYPTED_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'RxTest')

    def setup_method(self):
        self.parser = MachoParser(TestMachoBinary.FAT_PATH)
        # ensure only one slice is returned with a thin Mach-O
        slices = self.parser.slices
        assert len(slices) == 1
        self.binary = self.parser.slices[0]
        assert self.binary is not None

    def test_translate_virtual_address(self):
        # ensure virtual addresses are correctly translated to file offsets
        virt = 0x100006db8
        correct_bytes = b'application:openURL:sourceApplication:annotation:\x00'
        found_bytes = self.binary.get_content_from_virtual_address(virtual_address=virt, size=len(correct_bytes))
        assert found_bytes == correct_bytes

        # test an address before the end of load commands
        virt = 0x100000ad0
        correct_phys = 0xad0
        found_phys = self.binary.file_offset_for_virtual_address(virt)
        assert found_phys == correct_phys

    def test_virt_base(self):
        assert self.binary.get_virtual_base() == 0x100000000

    def test_single_slice(self):
        assert self.binary is not None
        assert self.binary.header is not None

    def test_correct_arch(self):
        # GoodCertificateValidation is known to be a thin arm64 slice
        assert self.binary is not None
        assert self.binary.cpu_type == CPU_TYPE.ARM64

    def test_finds_segments(self):
        # ensure standard segments are present
        assert self.binary.segment_commands['__PAGEZERO'] is not None
        assert self.binary.segment_commands['__TEXT'] is not None
        assert self.binary.segment_commands['__DATA'] is not None
        assert self.binary.segment_commands['__LINKEDIT'] is not None

    def test_find_symtabs(self):
        # did we find symtab command and dysymtab command?
        assert self.binary.symtab is not None
        assert self.binary.dysymtab is not None

    def test_find_sections(self):
        # try a few sections from different segment
        # from __TEXT:
        assert self.binary.sections['__text'] is not None
        assert self.binary.sections['__stubs'] is not None
        assert self.binary.sections['__objc_methname'] is not None
        assert self.binary.sections['__objc_classname'] is not None
        assert self.binary.sections['__cstring'] is not None
        # from __DATA:
        assert self.binary.sections['__const'] is not None
        assert self.binary.sections['__objc_classlist'] is not None
        assert self.binary.sections['__data'] is not None

    def test_header_flags(self):
        # this binary is known to have masks 1, 4, 128, 2097152
        assert HEADER_FLAGS.NOUNDEFS in self.binary.header_flags
        assert HEADER_FLAGS.DYLDLINK in self.binary.header_flags
        assert HEADER_FLAGS.TWOLEVEL in self.binary.header_flags
        assert HEADER_FLAGS.PIE in self.binary.header_flags

        # the binary definitely shouldn't have this flag
        assert not (HEADER_FLAGS.ROOT_SAFE in self.binary.header_flags)

    def test_get_symtab_contents(self):
        from pprint import pprint
        symtabs = self.binary.symtab_contents
        assert len(symtabs) == 32

    def test_read_encrypted_info(self):
        encrypted_binary = MachoParser(TestMachoBinary.ENCRYPTED_PATH).get_armv7_slice()
        with pytest.raises(BinaryEncryptedError):
            # encrypted region is 0x4000 to 0x18000
            encrypted_binary.get_bytes(0x5000, 0x1000)
        # read from unencrypted section should not raise
        encrypted_binary.get_bytes(0x3000, 0x500)
