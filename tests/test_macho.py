import pathlib
from tempfile import TemporaryDirectory

import pytest

from strongarm.macho import (
    CPU_TYPE,
    HEADER_FLAGS,
    BinaryEncryptedError,
    MachoBinary,
    MachoParser,
    MachoSegmentCommand64,
    NoEmptySpaceForLoadCommandError,
)


class TestMachoBinary:
    THIN_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "GammaRayTestBad"
    ENCRYPTED_PATH = pathlib.Path(__file__).parent / "bin" / "RxTest"
    # Found within this app: https://pythia.sourcetheorem.com/mobile_app_scans/5196911454191616
    MULTIPLE_CONST_SECTIONS = pathlib.Path(__file__).parent / "bin" / "BroadSoftDialpadFramework"
    # Test binary from Eric for the secure enclave check
    CLASSLIST_DATA_CONST = pathlib.Path(__file__).parent / "bin" / "CKTest2"

    def setup_method(self):
        self.parser = MachoParser(pathlib.Path(TestMachoBinary.THIN_PATH))
        # ensure only one slice is returned with a thin Mach-O
        slices = self.parser.slices
        assert len(slices) == 1
        self.binary = self.parser.slices[0]
        assert self.binary is not None

    def test_translate_virtual_address(self):
        # ensure virtual addresses are correctly translated to file offsets
        virt = 0x100006DB8
        correct_bytes = b"application:openURL:sourceApplication:annotation:\x00"
        found_bytes = self.binary.get_content_from_virtual_address(virtual_address=virt, size=len(correct_bytes))
        assert found_bytes == correct_bytes

        # test an address before the end of load commands
        virt = 0x100000AD0
        correct_phys = 0xAD0
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
        assert self.binary.segment_with_name("__PAGEZERO") is not None
        assert self.binary.segment_with_name("__TEXT") is not None
        assert self.binary.segment_with_name("__DATA") is not None
        assert self.binary.segment_with_name("__LINKEDIT") is not None
        # Ensure a fake segment isn't found
        assert self.binary.segment_with_name("FAKE_SEGMENT") is None

    def test_find_symtabs(self):
        # did we find symtab command and dysymtab command?
        assert self.binary.symtab is not None
        assert self.binary.dysymtab is not None

    def test_find_sections(self):
        # try a few sections from different segments
        # from __TEXT:
        assert self.binary.section_with_name("__text", "__TEXT") is not None
        assert self.binary.section_with_name("__stubs", "__TEXT") is not None
        assert self.binary.section_with_name("__objc_methname", "__TEXT") is not None
        assert self.binary.section_with_name("__objc_classname", "__TEXT") is not None
        assert self.binary.section_with_name("__cstring", "__TEXT") is not None
        assert self.binary.section_with_name("fake_section", "__TEXT") is None
        # from __DATA:
        assert self.binary.section_with_name("__la_symbol_ptr", "__DATA") is not None
        assert self.binary.section_with_name("__objc_classlist", "__DATA") is not None
        assert self.binary.section_with_name("__data", "__DATA") is not None
        assert self.binary.section_with_name("fake_section", "__DATA") is None

    def test_section_name_collision(self):
        # Given I provide a binary which has two sections with the same name
        binary = MachoParser(self.MULTIPLE_CONST_SECTIONS).get_arm64_slice()
        # If I read the two sections
        text_const = binary.section_with_name("__const", "__TEXT")
        data_const = binary.section_with_name("__const", "__DATA")
        # Then I get two sections
        assert text_const is not None
        assert data_const is not None
        # And each section contains the correct information
        assert text_const.address == 0x1A0D0
        assert data_const.address == 0x1C458

    def test_header_flags(self):
        # this binary is known to have masks 1, 4, 128, 2097152
        assert HEADER_FLAGS.NOUNDEFS in self.binary.header_flags
        assert HEADER_FLAGS.DYLDLINK in self.binary.header_flags
        assert HEADER_FLAGS.TWOLEVEL in self.binary.header_flags
        assert HEADER_FLAGS.PIE in self.binary.header_flags

        # the binary definitely shouldn't have this flag
        assert not (HEADER_FLAGS.ROOT_SAFE in self.binary.header_flags)

    def test_get_symtab_contents(self):
        pass

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
        correct_strings = (
            b"\x00\x00\x00\x00__mh_execute_header\x00_NSClassFromString\x00_NSLog\x00_NSStringFrom"
            b"CGRect\x00_NSStringFromClass\x00_OBJC_CLASS_$_NSObject\x00_OBJC_CLASS_$_NSURLCredential"
            b"\x00_OBJC_CLASS_$_UIFont\x00_OBJC_CLASS_$_UILabel\x00_OBJC_CLASS_$_UIResponder\x00"
            b"_OBJC_CLASS_$_UIViewController\x00_OBJC_METACLASS_$_NSObject\x00_OBJC_METACLASS_$_UILabel"
            b"\x00_OBJC_METACLASS_$_UIResponder\x00_OBJC_METACLASS_$_UIViewController\x00"
            b"_SecTrustEvaluate\x00_UIApplicationMain\x00"
            b"___CFConstantStringClassReference\x00__objc_empty_cache\x00_dlopen\x00"
            b"_objc_autoreleasePoolPop\x00_objc_autoreleasePoolPush\x00_objc_getClass\x00"
            b"_objc_msgSend\x00_objc_msgSendSuper2\x00_objc_release\x00_objc_retain\x00"
            b"_objc_retainAutoreleasedReturnValue\x00_objc_storeStrong\x00_rand\x00"
            b"dyld_stub_binder\x00radr://5614542\x00\x00\x00\x00"
        )
        # If I ask strongarm to read the binary's strings
        read_strings = bytes(self.binary.get_raw_string_table())
        # Then I get the correct data out
        assert read_strings == correct_strings

    def test_read_classlist_data_segment(self):
        # Given a binary which stores the __objc_classlist section in the __DATA segment
        binary_with_data_classlist = MachoParser(TestMachoBinary.THIN_PATH).get_arm64_slice()

        # If I read the __objc_classlist pointer section
        locations, entries = binary_with_data_classlist.read_pointer_section("__objc_classlist")
        correct_locations = [0x100008178, 0x100008180, 0x100008188, 0x100008190]
        correct_entries = [0x100009120, 0x100009170, 0x1000091E8, 0x100009238]

        # Then I get the correct data
        assert sorted(locations) == sorted(correct_locations)
        assert sorted(entries) == sorted(correct_entries)

    def test_read_classlist_data_const_segment(self):
        # Given a binary which stores the __objc_classlist section in the __DATA_CONST segment
        binary_with_data_classlist = MachoParser(TestMachoBinary.CLASSLIST_DATA_CONST).get_arm64_slice()

        # If I read the __objc_classlist pointer section
        locations, entries = binary_with_data_classlist.read_pointer_section("__objc_classlist")
        correct_locations = [0x100008098, 0x1000080A0, 0x1000080A8]
        correct_entries = [0x10000D3C0, 0x10000D438, 0x10000D488]

        # Then I get the correct data
        assert sorted(locations) == sorted(correct_locations)
        assert sorted(entries) == sorted(correct_entries)

    def test_function_starts_command(self):
        # Given a binary that contains functions
        binary_with_functions = MachoParser(TestMachoBinary.CLASSLIST_DATA_CONST).get_arm64_slice()
        # And I get the function starts command
        function_starts = binary_with_functions._function_starts_cmd
        # The command has the expected attributes
        assert function_starts.cmd == 0x26
        assert function_starts.cmdsize == 0x10
        assert function_starts.dataoff == 0x10680
        assert function_starts.datasize == 0x18
        assert function_starts.sizeof == 0x10
        assert function_starts.binary_offset == 0xB38

    def test_write_bytes_thin_physical(self):
        # Given a thin binary with file_type == 0x2
        binary = MachoParser(pathlib.Path(TestMachoBinary.CLASSLIST_DATA_CONST)).get_arm64_slice()
        assert binary.file_type == 0x2

        # If I patch the non-virtual bytes of the file_type field to hold a different value
        new_file_type_val = 5
        # This field is a 32-bit little-endian encoded int
        new_file_type_bytes = new_file_type_val.to_bytes(4, "little")
        modified_binary = binary.write_bytes(new_file_type_bytes, 0x0C)

        # Then the modified binary's raw bytes contain the correct data
        modified_header = modified_binary.get_contents_from_address(0, 32, is_virtual=False)
        assert modified_header == bytearray(
            b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x05\x00\x00\x00\x18\x00\x00\x00H\x0b\x00\x00\x85\x00 \x00\x00\x00\x00\x00"  # noqa: E501
        )
        # And the MachoBinary attribute contains the correct value
        assert modified_binary.file_type == 0x5

    def test_write_bytes_thin_virtual(self):
        # Given a thin binary with file_type == 0x2
        binary = MachoParser(pathlib.Path(TestMachoBinary.CLASSLIST_DATA_CONST)).get_arm64_slice()
        assert binary.file_type == 0x2

        # If I patch the virtual bytes of the file_type field to hold a different value
        new_file_type_val = 10
        # This field is a 32-bit little-endian encoded int
        new_file_type_bytes = new_file_type_val.to_bytes(4, "little")
        modified_binary = binary.write_bytes(new_file_type_bytes, 0x10000000C, virtual=True)

        # Then the modified binary's raw bytes contain the correct data
        modified_header = modified_binary.get_contents_from_address(0x100000000, 32, True)
        assert modified_header == bytearray(
            b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01\x00\x00\x00\x00\x0a\x00\x00\x00\x18\x00\x00\x00H\x0b\x00\x00\x85\x00 \x00\x00\x00\x00\x00"  # noqa: E501
        )
        # And the MachoBinary attribute contains the correct value
        assert modified_binary.file_type == 10

    def test_write_struct(self):
        # Given a thin binary with certain values for its first segment
        binary = MachoParser(pathlib.Path(TestMachoBinary.THIN_PATH)).get_arm64_slice()
        segment = binary.segments[0]
        assert segment.name == "__PAGEZERO"
        assert segment.vmaddr == 0x0
        assert segment.vmsize == 0x100000000
        assert segment.offset == 0x0
        assert segment.size == 0x0
        assert segment.maxprot == 0
        assert segment.initprot == 0
        assert segment.section_count == 0
        assert segment.flags == 0

        # If I create a new structure and overwrite the original structure with it
        new_segment = MachoSegmentCommand64()
        new_segment.cmd = 0x19
        new_segment.cmdsize = 0x48
        new_segment.segname = b"__FAKESEG"
        new_segment.vmaddr = 0x111
        new_segment.vmsize = 0x222
        new_segment.fileoff = 0x333
        new_segment.filesize = 0x444
        new_segment.maxprot = 5
        new_segment.initprot = 6
        new_segment.nsects = 7
        new_segment.flags = 8

        # Then we get a MachoBinary which can be successfully parsed, and contains the modified structure
        modified_binary = binary.write_struct(new_segment, segment.cmd.binary_offset)
        segment = modified_binary.segments[0]
        assert segment.name == "__FAKESEG"
        assert segment.vmaddr == 0x111
        assert segment.vmsize == 0x222
        assert segment.offset == 0x333
        assert segment.size == 0x444
        assert segment.maxprot == 5
        assert segment.initprot == 6
        assert segment.section_count == 7
        assert segment.flags == 8

    def test_add_load_command(self):
        # Given a binary with some known load-commands
        binary = MachoParser(self.CLASSLIST_DATA_CONST).get_arm64_slice()
        original_dylibs = [
            "/System/Library/Frameworks/Foundation.framework/Foundation",
            "/usr/lib/libobjc.A.dylib",
            "/usr/lib/libSystem.B.dylib",
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            "/System/Library/Frameworks/Security.framework/Security",
            "/System/Library/Frameworks/UIKit.framework/UIKit",
        ]
        found_dylibs = [binary.dylib_name_for_library_ordinal(i + 1) for i in range(len(binary.load_dylib_commands))]
        assert found_dylibs == original_dylibs

        # If I create a new binary with an inserted load command
        modified_binary = binary.insert_load_dylib_cmd(f"@rpath/Frameworks/Interject.framework/Interject")
        modified_dylibs = [
            "/System/Library/Frameworks/Foundation.framework/Foundation",
            "/usr/lib/libobjc.A.dylib",
            "/usr/lib/libSystem.B.dylib",
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            "/System/Library/Frameworks/Security.framework/Security",
            "/System/Library/Frameworks/UIKit.framework/UIKit",
            "@rpath/Frameworks/Interject.framework/Interject",
        ]
        found_dylibs = [
            modified_binary.dylib_name_for_library_ordinal(i + 1)
            for i in range(len(modified_binary.load_dylib_commands))
        ]
        assert found_dylibs == modified_dylibs

    def test_no_space_for_new_load_command(self):
        # Given a binary with 0x5630 bytes of free space at the end of the Mach-O header
        binary = MachoParser(self.THIN_PATH).get_arm64_slice()

        dylib_path = "@rpath/load_cmd_with_32_chrcters"
        # If I have a dylib load command which will take up `0x20 + len(dylib_path) = 0x38` bytes
        # Then I should be able to add this load command exactly 344 times before the binary runs out of space
        for _ in range(344):
            binary = binary.insert_load_dylib_cmd(dylib_path)
        with pytest.raises(NoEmptySpaceForLoadCommandError):
            binary.insert_load_dylib_cmd(dylib_path)

    def test_write_thin_binary(self):
        binary = MachoParser(self.THIN_PATH).get_arm64_slice()
        original_dylibs = [binary.dylib_name_for_library_ordinal(i + 1) for i in range(len(binary.load_dylib_commands))]
        # Given I add a load command to a binary
        new_dylib_name = "@rpath/Frameworks/Interject.framework/Interject"
        modified_binary = binary.insert_load_dylib_cmd(new_dylib_name)

        with TemporaryDirectory() as tempdir:
            output_binary_path = pathlib.Path(tempdir) / "modified_binary"
            # If I write the binary to disk, then parse the on-disk version
            modified_binary.write_binary(output_binary_path)
            on_disk_binary = MachoParser(output_binary_path).get_arm64_slice()

            # Then the new on-disk binary contains the modification
            new_dylibs = [
                on_disk_binary.dylib_name_for_library_ordinal(i + 1)
                for i in range(len(on_disk_binary.load_dylib_commands))
            ]
            assert new_dylibs == original_dylibs + [new_dylib_name]

    def test_write_fat_binary(self):
        # Given I add a load command to the arm64 slice of an armv7/arm64 FAT file
        parser = MachoParser(self.FAT_PATH)
        binary = parser.get_arm64_slice()
        original_dylibs = [binary.dylib_name_for_library_ordinal(i + 1) for i in range(len(binary.load_dylib_commands))]
        new_dylib_name = "@rpath/Frameworks/Interject.framework/Interject"
        modified_binary = binary.insert_load_dylib_cmd(new_dylib_name)

        with TemporaryDirectory() as tempdir:
            output_binary_path = pathlib.Path(tempdir) / "modified_fat"
            # If I write the FAT to disk with both slices, then parse the on-disk version
            MachoBinary.write_fat([parser.get_armv7_slice(), modified_binary], output_binary_path)
            on_disk_fat_parser = MachoParser(output_binary_path)

            assert len(on_disk_fat_parser.slices) == 2

            # Then I get a FAT with valid slices
            armv7 = on_disk_fat_parser.get_armv7_slice()
            assert armv7 is not None
            assert len(armv7.segments) == 4

            arm64 = on_disk_fat_parser.get_arm64_slice()
            assert arm64 is not None
            assert len(arm64.segments) == 4
            # And the arm64 segment contains the new load command
            new_dylibs = [arm64.dylib_name_for_library_ordinal(i + 1) for i in range(len(arm64.load_dylib_commands))]
            assert new_dylibs == original_dylibs + [new_dylib_name]

    def test_get_dylib_id(self):
        # Given an executable binary, it has no dylib ID
        assert not MachoParser(self.THIN_PATH).get_arm64_slice().dylib_id()
        # Given a dylib, it has a dylib ID which is parsed correctly
        expected_dylib_id = "@rpath/BroadSoftDialpadFramework.framework/BroadSoftDialpadFramework"
        assert MachoParser(self.MULTIPLE_CONST_SECTIONS).get_arm64_slice().dylib_id() == expected_dylib_id
