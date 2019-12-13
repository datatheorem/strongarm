"""These tests cannot run in CI as they require a dyld_shared_cache image, which is > 1GB
"""
import os
import pytest
from pathlib import Path

from strongarm.macho import DyldSharedCacheParser, VirtualMemoryPointer, MachoAnalyzer


@pytest.mark.skipif('CI' in os.environ, reason="Cannot run dyld_shared_cache tests in CI")
class TestDyldSharedCache:
    # XXX(PT): This test suite expects to run on a mounted IPSW of iOS 12.1.1 iPad 6 WiFi
    _FIRMWARE_ROOT = Path('/') / 'Volumes' / 'PeaceC16C50.J71bJ72bJ71sJ72sJ71tJ72tOS'
    DSC_PATH = _FIRMWARE_ROOT / 'System' / 'Library' / 'Caches' / 'com.apple.dyld' / 'dyld_shared_cache_arm64'

    @pytest.fixture
    def dyld_shared_cache(self) -> DyldSharedCacheParser:
        return DyldSharedCacheParser(self.DSC_PATH)

    def test_parses_dsc_maps(self, dyld_shared_cache):
        # Ensure the structures at the start of the DSC were parsed exactly as expected
        assert dyld_shared_cache.file_magic == 0x646c7964

        assert len(dyld_shared_cache.segment_mappings) == 3

        text_map = dyld_shared_cache.segment_mappings[0]
        assert text_map.file_offset == 0x0
        assert text_map.address == 0x180000000
        assert text_map.size == 0x2eca8000
        assert text_map.init_prot == text_map.max_prot == 0x5

        data_map = dyld_shared_cache.segment_mappings[1]
        assert data_map.file_offset == 0x2eca8000
        assert data_map.address == 0x1b0ca8000
        assert data_map.size == 0x95a8000
        assert data_map.init_prot == data_map.max_prot == 0x3

        linkedit_map = dyld_shared_cache.segment_mappings[2]
        assert linkedit_map.file_offset == 0x38250000
        assert linkedit_map.address == 0x1bc250000
        assert linkedit_map.size == 0x7884000
        assert linkedit_map.init_prot == linkedit_map.max_prot == 0x1

    def test_parses_dsc_images(self, dyld_shared_cache):
        assert len(dyld_shared_cache.embedded_binary_info) == 1400
        # Pick out a binary and ensure its location is reported correctly
        image_path = Path('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        corefoundation_range = dyld_shared_cache.embedded_binary_info[image_path]
        assert corefoundation_range == (VirtualMemoryPointer(0x180db9000), VirtualMemoryPointer(0x18111d000))

    def test_find_image_for_code_address(self, dyld_shared_cache):
        # Given an address within an embedded image
        code_addr = VirtualMemoryPointer(0x180ac1000)
        # When I ask which image contains it
        implementing_image = dyld_shared_cache.image_for_text_address(code_addr)
        # The correct image is returned
        assert implementing_image == Path('/usr/lib/system/libsystem_malloc.dylib')

    def test_analyze_embedded_binary(self, dyld_shared_cache):
        # Given I parse an embedded binary
        binary = dyld_shared_cache.get_embedded_binary(Path('/usr/lib/libSystem.B.dylib'))
        # The binary appears to be parsed correctly
        assert binary.get_virtual_base() == 0x18002e000
        assert binary.get_functions() == {0x18002fa7c, 0x18002fb7c, 0x18002fb34, 0x18002fb58, 0x18002fbbc}

        # And the binary can be analyzed further
        analyzer = MachoAnalyzer.get_analyzer(binary)
        # And the analyzed binary reports the correct information
        assert len(analyzer.imported_symbols) == 47
        expected_exports = {'<redacted>': 0x18002fbbc,
                            '___crashreporter_info__': 0x1b7c574b8,
                            '_libSystem_atfork_child': 0x18002fb7c,
                            '_libSystem_atfork_parent': 0x18002fb58,
                            '_libSystem_atfork_prepare': 0x18002fb34,
                            '_mach_init_routine': 0x1b7c574b0}
        assert analyzer.exported_symbol_names_to_pointers == expected_exports

