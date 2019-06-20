import os
import pytest
import pathlib

from strongarm.macho.macho_definitions import *
from strongarm.macho import MachoParser
from strongarm.macho import BinaryEncryptedError


class TestMachoBinary:
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')
    ENCRYPTED_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'RxTest')
    # Found within this app: https://pythia.sourcetheorem.com/mobile_app_scans/5196911454191616
    MULTIPLE_CONST_SECTIONS = pathlib.Path(__file__).parent / 'bin' / 'BroadSoftDialpadFramework'

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
        # Ensure standard segments are present
        assert self.binary.segment_with_name('__PAGEZERO') is not None
        assert self.binary.segment_with_name('__TEXT') is not None
        assert self.binary.segment_with_name('__DATA') is not None
        assert self.binary.segment_with_name('__LINKEDIT') is not None
        # Ensure a fake segment isn't found
        assert self.binary.segment_with_name('FAKE_SEGMENT') is None

    def test_find_symtabs(self):
        # did we find symtab command and dysymtab command?
        assert self.binary.symtab is not None
        assert self.binary.dysymtab is not None

    def test_find_sections(self):
        # try a few sections from different segments
        # from __TEXT:
        assert self.binary.section_with_name('__text', '__TEXT') is not None
        assert self.binary.section_with_name('__stubs', '__TEXT') is not None
        assert self.binary.section_with_name('__objc_methname', '__TEXT') is not None
        assert self.binary.section_with_name('__objc_classname', '__TEXT') is not None
        assert self.binary.section_with_name('__cstring', '__TEXT') is not None
        assert self.binary.section_with_name('fake_section', '__TEXT') is None
        # from __DATA:
        assert self.binary.section_with_name('__la_symbol_ptr', '__DATA') is not None
        assert self.binary.section_with_name('__objc_classlist', '__DATA') is not None
        assert self.binary.section_with_name('__data', '__DATA') is not None
        assert self.binary.section_with_name('fake_section', '__DATA') is None

    def test_section_name_collision(self):
        # Given I provide a binary which has two sections with the same name
        binary = MachoParser(self.MULTIPLE_CONST_SECTIONS.as_posix()).get_arm64_slice()
        # If I read the two sections
        text_const = binary.section_with_name('__const', '__TEXT')
        data_const = binary.section_with_name('__const', '__DATA')
        # Then I get two sections
        assert text_const is not None
        assert data_const is not None
        # And each section contains the correct information
        assert text_const.address == 0x1a0d0
        assert data_const.address == 0x1c458

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

    def test_read_string_table(self):
        # Given the binary's string table contains exactly these bytes:
        correct_strings = b'\x00\x00\x00\x00__mh_execute_header\x00_NSClassFromString\x00_NSLog\x00_NSStringFrom' \
                          b'CGRect\x00_NSStringFromClass\x00_OBJC_CLASS_$_NSObject\x00_OBJC_CLASS_$_NSURLCredential' \
                          b'\x00_OBJC_CLASS_$_UIFont\x00_OBJC_CLASS_$_UILabel\x00_OBJC_CLASS_$_UIResponder\x00' \
                          b'_OBJC_CLASS_$_UIViewController\x00_OBJC_METACLASS_$_NSObject\x00_OBJC_METACLASS_$_UILabel' \
                          b'\x00_OBJC_METACLASS_$_UIResponder\x00_OBJC_METACLASS_$_UIViewController\x00' \
                          b'_SecTrustEvaluate\x00_UIApplicationMain\x00' \
                          b'___CFConstantStringClassReference\x00__objc_empty_cache\x00_dlopen\x00' \
                          b'_objc_autoreleasePoolPop\x00_objc_autoreleasePoolPush\x00_objc_getClass\x00' \
                          b'_objc_msgSend\x00_objc_msgSendSuper2\x00_objc_release\x00_objc_retain\x00' \
                          b'_objc_retainAutoreleasedReturnValue\x00_objc_storeStrong\x00_rand\x00' \
                          b'dyld_stub_binder\x00radr://5614542\x00\x00\x00\x00'
        # If I ask strongarm to read the binary's strings
        read_strings = bytes(self.binary.get_raw_string_table())
        # Then I get the correct data out
        assert read_strings == correct_strings
