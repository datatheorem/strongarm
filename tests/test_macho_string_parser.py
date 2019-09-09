import pathlib

from strongarm.macho import MachoStringTableHelper
from strongarm.macho.macho_parse import MachoParser


class TestMachoStringParser:
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"

    def setup_method(self):
        parser = MachoParser(self.FAT_PATH)
        self.binary = parser.slices[0]
        self.string_helper = MachoStringTableHelper(self.binary)

    def test_exposed_symbol_list(self):
        # The exported symbols from the binary
        found_exported = self.string_helper.exported_symbols

        # Matches the expected value
        expected = ["__mh_execute_header"]
        assert found_exported == expected

    def test_imported_symbol_list(self):
        # The imported symbols from the binary
        found_imported = self.string_helper.imported_symbols

        # Matches the expected value
        expected = [
            "_NSClassFromString",
            "_NSLog",
            "_NSStringFromCGRect",
            "_NSStringFromClass",
            "_OBJC_CLASS_$_NSObject",
            "_OBJC_CLASS_$_NSURLCredential",
            "_OBJC_CLASS_$_UIFont",
            "_OBJC_CLASS_$_UILabel",
            "_OBJC_CLASS_$_UIResponder",
            "_OBJC_CLASS_$_UIViewController",
            "_OBJC_METACLASS_$_NSObject",
            "_OBJC_METACLASS_$_UILabel",
            "_OBJC_METACLASS_$_UIResponder",
            "_OBJC_METACLASS_$_UIViewController",
            "_SecTrustEvaluate",
            "_UIApplicationMain",
            "___CFConstantStringClassReference",
            "__objc_empty_cache",
            "_dlopen",
            "_objc_autoreleasePoolPop",
            "_objc_autoreleasePoolPush",
            "_objc_getClass",
            "_objc_msgSend",
            "_objc_msgSendSuper2",
            "_objc_release",
            "_objc_retain",
            "_objc_retainAutoreleasedReturnValue",
            "_objc_storeStrong",
            "_rand",
            "dyld_stub_binder",
        ]
        assert set(found_imported) == set(expected)

    def test_address_to_symbol_parsing(self):
        # The mapping of function addresses to symbol names
        symbol_table = self.string_helper._address_to_exported_symbol

        # Matches the expected value
        expected = {4294967296: "__mh_execute_header"}
        assert symbol_table == expected

    def test_get_symbol_for_address(self):
        # Given the address of a function
        address = 4294967296
        # And the symbol name of that function
        symbol_name = self.string_helper.get_symbol_name_for_address(address)
        # The name is the expected value
        assert symbol_name == "__mh_execute_header"
