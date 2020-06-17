import pathlib

from strongarm.macho import VirtualMemoryPointer
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser


class TestDyldInfoParser:
    BINARY1_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"
    BINARY2_PATH = pathlib.Path(__file__).parent / "bin" / "TestBinary4"

    def test_identify_imported_symbols_1(self) -> None:
        parser = MachoParser(TestDyldInfoParser.BINARY1_PATH)
        binary = parser.get_arm64_slice()
        assert binary
        analyzer = MachoAnalyzer.get_analyzer(binary)

        correct_imported_symbols_raw = {
            4295004408: "_OBJC_CLASS_$_NSURLCredential",
            4295004656: "_OBJC_CLASS_$_NSObject",
            4295004488: "_OBJC_METACLASS_$_NSObject",
            4295004568: "_OBJC_METACLASS_$_NSObject",
            4295004608: "_OBJC_METACLASS_$_NSObject",
            4295004616: "_OBJC_METACLASS_$_NSObject",
            4295004688: "_OBJC_METACLASS_$_NSObject",
            4295004464: "__objc_empty_cache",
            4295004504: "__objc_empty_cache",
            4295004544: "__objc_empty_cache",
            4295004584: "__objc_empty_cache",
            4295004624: "__objc_empty_cache",
            4295004664: "__objc_empty_cache",
            4295004704: "__objc_empty_cache",
            4295004744: "__objc_empty_cache",
            4295000064: "dyld_stub_binder",
            4295000216: "___CFConstantStringClassReference",
            4295000248: "___CFConstantStringClassReference",
            4295000280: "___CFConstantStringClassReference",
            4295000312: "___CFConstantStringClassReference",
            4295000344: "___CFConstantStringClassReference",
            4295000376: "___CFConstantStringClassReference",
            4295000408: "___CFConstantStringClassReference",
            4295004400: "_OBJC_CLASS_$_UIFont",
            4295004456: "_OBJC_CLASS_$_UILabel",
            4295004736: "_OBJC_CLASS_$_UIResponder",
            4295004536: "_OBJC_CLASS_$_UIViewController",
            4295004496: "_OBJC_METACLASS_$_UILabel",
            4295004696: "_OBJC_METACLASS_$_UIResponder",
            4295004576: "_OBJC_METACLASS_$_UIViewController",
            4295000080: "_NSClassFromString",
            4295000088: "_NSLog",
            4295000096: "_NSStringFromCGRect",
            4295000104: "_NSStringFromClass",
            4295000112: "_SecTrustEvaluate",
            4295000120: "_UIApplicationMain",
            4295000128: "_dlopen",
            4295000136: "_objc_autoreleasePoolPop",
            4295000144: "_objc_autoreleasePoolPush",
            4295000152: "_objc_getClass",
            4295000160: "_objc_msgSend",
            4295000168: "_objc_msgSendSuper2",
            4295000176: "_objc_release",
            4295000184: "_objc_retain",
            4295000192: "_objc_retainAutoreleasedReturnValue",
            4295000200: "_objc_storeStrong",
            4295000208: "_rand",
        }
        correct_imported_symbols = {VirtualMemoryPointer(k): v for k, v in correct_imported_symbols_raw.items()}

        assert analyzer.imported_symbols_to_symbol_names == correct_imported_symbols
        for imported_pointer in correct_imported_symbols.keys():
            symbol_name = correct_imported_symbols[imported_pointer]
            if "_OBJC_CLASS_$_" in symbol_name:
                assert analyzer.class_name_for_class_pointer(imported_pointer) == symbol_name

    def test_identify_imported_symbols_2(self) -> None:
        parser = MachoParser(TestDyldInfoParser.BINARY2_PATH)
        binary = parser.get_arm64_slice()
        assert binary
        analyzer = MachoAnalyzer.get_analyzer(binary)

        # TestBinary4's dyld binding opcodes utilize BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
        # which previously had a bug where we didn't increment the data pointer after binding

        # Bound symbol in ObjC category in __objc_const
        assert (
            analyzer.imported_symbols_to_symbol_names[VirtualMemoryPointer(0x100212338)] == "_OBJC_CLASS_$_UIAlertView"
        )
        # Bound classref in __objc_classrefs
        assert (
            analyzer.imported_symbols_to_symbol_names[VirtualMemoryPointer(0x10026AE40)] == "_OBJC_CLASS_$_UIAlertView"
        )
        # This API should return the classref, not the bound class in the category definition
        assert analyzer.classref_for_class_name("_OBJC_CLASS_$_UIAlertView") == VirtualMemoryPointer(0x10026AE40)
