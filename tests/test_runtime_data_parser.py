import pathlib
from distutils.version import LooseVersion
from typing import List

from strongarm.macho import DyldInfoParser, MachoParser, ObjcCategory, ObjcRuntimeDataParser
from strongarm.macho.macho_definitions import MachoBuildTool, MachoBuildVersionPlatform, VirtualMemoryPointer


class TestObjcRuntimeDataParser:
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"
    CATEGORY_PATH = pathlib.Path(__file__).parent / "bin" / "TestBinary1"
    PROTOCOL_32BIT_PATH = pathlib.Path(__file__).parent / "bin" / "Protocol32Bit"
    IOS14_RELATIVE_METHOD_LIST_BIN_PATH = pathlib.Path(__file__).parent / "bin" / "iOS14_relative_method_list"
    IOS13_ABSOLUTE_METHOD_LIST_BIN_PATH = pathlib.Path(__file__).parent / "bin" / "iOS13_objc_opt"

    def test_path_for_external_symbol(self) -> None:
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        binary = parser.slices[0]
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)

        correct_map = {
            "_NSLog": "/System/Library/Frameworks/Foundation.framework/Foundation",
            "_NSStringFromCGRect": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_NSStringFromClass": "/System/Library/Frameworks/Foundation.framework/Foundation",
            "_OBJC_CLASS_$_NSURLCredential": "/System/Library/Frameworks/Foundation.framework/Foundation",
            "_OBJC_CLASS_$_UIFont": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_OBJC_CLASS_$_UILabel": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_OBJC_CLASS_$_UIResponder": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_OBJC_CLASS_$_UIViewController": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_OBJC_METACLASS_$_NSObject": "/usr/lib/libobjc.A.dylib",
            "_OBJC_METACLASS_$_UILabel": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_OBJC_METACLASS_$_UIResponder": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_OBJC_METACLASS_$_UIViewController": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "_SecTrustEvaluate": "/System/Library/Frameworks/Security.framework/Security",
            "_UIApplicationMain": "/System/Library/Frameworks/UIKit.framework/UIKit",
            "___CFConstantStringClassReference": "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
            "__objc_empty_cache": "/usr/lib/libobjc.A.dylib",
            "_objc_autoreleasePoolPop": "/usr/lib/libobjc.A.dylib",
            "_objc_autoreleasePoolPush": "/usr/lib/libobjc.A.dylib",
            "_objc_msgSend": "/usr/lib/libobjc.A.dylib",
            "_objc_msgSendSuper2": "/usr/lib/libobjc.A.dylib",
            "_objc_release": "/usr/lib/libobjc.A.dylib",
            "_objc_retain": "/usr/lib/libobjc.A.dylib",
            "_objc_retainAutoreleasedReturnValue": "/usr/lib/libobjc.A.dylib",
            "_objc_storeStrong": "/usr/lib/libobjc.A.dylib",
            "_rand": "/usr/lib/libSystem.B.dylib",
            "dyld_stub_binder": "/usr/lib/libSystem.B.dylib",
        }
        for symbol in correct_map:
            assert objc_parser.path_for_external_symbol(symbol) == correct_map[symbol]
        assert objc_parser.path_for_external_symbol("XXX_fake_symbol_XXX") is None

    def test_find_categories(self) -> None:
        parser = MachoParser(TestObjcRuntimeDataParser.CATEGORY_PATH)
        binary = parser.slices[0]
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)

        # extract category list
        category_classes = [x for x in objc_parser.classes if isinstance(x, ObjcCategory)]
        assert len(category_classes) == 9

        # look at one category
        category = [x for x in category_classes if x.name == "_OBJC_CLASS_$_NSURLRequest (DataController)"][0]
        assert category.base_class == "_OBJC_CLASS_$_NSURLRequest"
        assert category.category_name == "DataController"
        assert len(category.selectors) == 1
        selector = category.selectors[0]
        assert selector.name == "allowsAnyHTTPSCertificateForHost:"
        assert selector.implementation == 0x100005028

    def test_parse_ivars(self) -> None:
        parser = MachoParser(TestObjcRuntimeDataParser.CATEGORY_PATH)
        binary = parser.get_arm64_slice()
        assert binary
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)

        # Given I read a class with a known ivar layout
        cls = [x for x in objc_parser.classes if x.name == "AamvaPDF417"][0]
        # If I read its parsed ivar layout
        parsed_ivars = [(ivar.name, ivar.class_name, ivar.field_offset) for ivar in cls.ivars]
        correct_ivar_layout = [
            ("_fields", '@"NSMutableDictionary"', 8),
            ("fields_desc", '@"NSDictionary"', 16),
            ("found_bar_codes", '@"NSDictionary"', 24),
            ("source", '@"NSString"', 32),
            ("data_element_separator", "S", 40),
            ("record_separator", "S", 42),
            ("segment_terminator", "S", 44),
            ("file_type", '@"NSString"', 48),
            ("number_of_entries", "i", 56),
            ("header_length", "i", 60),
            ("aamva_version_number", "i", 64),
            ("jurisdiction_version_number", "i", 68),
            ("mandatory", '@"NSDictionary"', 72),
            ("optional", '@"NSDictionary"', 80),
            ("_failed", '@"NSMutableArray"', 88),
        ]
        # Then the correct data is provided
        assert sorted(parsed_ivars) == sorted(correct_ivar_layout)

    def test_find_protocols(self) -> None:
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        binary = parser.get_arm64_slice()
        assert binary
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)

        protocols = objc_parser.protocols
        assert len(protocols) == 3

        correct_protocols = ["NSObject", "NSURLSessionDelegate", "UIApplicationDelegate"]
        for p in correct_protocols:
            assert p in [a.name for a in protocols]

    def test_parse_protocol(self) -> None:
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        binary = parser.get_arm64_slice()
        assert binary
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)

        protocols = objc_parser.protocols
        # look at one protocol
        session_protocol = [p for p in protocols if p.name == "NSURLSessionDelegate"][0]
        assert len(session_protocol.selectors) == 3
        correct_selectors = [
            "URLSession:didBecomeInvalidWithError:",
            "URLSession:didReceiveChallenge:completionHandler:",
            "URLSessionDidFinishEventsForBackgroundURLSession:",
        ]
        for s in correct_selectors:
            assert s in [sel.name for sel in session_protocol.selectors]

    def test_class_conforming_protocols(self) -> None:
        def check_class_conformed_protocols(class_name: str, correct_protocols: List[str]) -> None:
            cls = [x for x in objc_parser.classes if x.name == class_name][0]
            assert cls is not None
            conformed_protocol_names = [x.name for x in cls.protocols]
            assert conformed_protocol_names == correct_protocols

        parser = MachoParser(TestObjcRuntimeDataParser.CATEGORY_PATH)
        binary = parser.get_arm64_slice()
        assert binary
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)

        check_class_conformed_protocols(
            "CDVInAppBrowserViewController",
            ["CDVScreenOrientationDelegate", "WKNavigationDelegate", "WKUIDelegate", "WKScriptMessageHandler"],
        )
        check_class_conformed_protocols(
            "_TtC26Digital_Advisory_Solutions21LicenceViewController", ["UITableViewDataSource"]
        )
        # this class doesn't conform to any protocols
        check_class_conformed_protocols("BadFilesDetector", [])

    def test_protocol_32bit(self) -> None:
        parser = MachoParser(TestObjcRuntimeDataParser.PROTOCOL_32BIT_PATH)
        binary = parser.get_armv7_slice()
        assert binary
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)
        assert len(objc_parser.classes) == 66
        test_cls = [x for x in objc_parser.classes if x.name == "Pepsico_iPhoneAppDelegate"][0]
        assert len(test_cls.protocols) == 2
        proto_names = [x.name for x in test_cls.protocols]
        assert proto_names == ["UIApplicationDelegate", "UITabBarControllerDelegate"]

    def test_ios14_build_version_cmd(self):
        # Given a binary compiled with a minimum deployment target of iOS 14
        parser = MachoParser(TestObjcRuntimeDataParser.IOS14_RELATIVE_METHOD_LIST_BIN_PATH)
        binary = parser.get_arm64_slice()

        # When I query properties such as the minimum deployment target, deployment platform,
        # and build tool versions
        # Then the correct data is parsed and returned
        assert binary.get_minimum_deployment_target() == LooseVersion("14.0.0")
        assert binary.get_build_version_platform() == MachoBuildVersionPlatform.IOS

        build_tool_versions = binary.get_build_tool_versions()
        assert len(build_tool_versions) == 1
        ld_version = build_tool_versions[0]
        assert ld_version.tool == MachoBuildTool.LD
        assert ld_version.version == 0x2610000

    def test_ios13_absolute_method_lists(self):
        # Given a binary compiled with a minimum deployment target of iOS 13
        parser = MachoParser(TestObjcRuntimeDataParser.IOS13_ABSOLUTE_METHOD_LIST_BIN_PATH)
        binary = parser.get_arm64_slice()
        binary.get_minimum_deployment_target()

        # When the Objective C methods within the binary are parsed
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)
        selref_selector_map = objc_parser.selrefs_to_selectors()

        # Then the method structures are correctly parsed
        assert len(selref_selector_map) == 3

        s1 = selref_selector_map[VirtualMemoryPointer(0x10000D380)]
        assert s1.implementation is None
        assert s1.is_external_definition is True
        assert s1.name == "role"

        s2 = selref_selector_map[VirtualMemoryPointer(0x10000D388)]
        assert s2.implementation is None
        assert s2.is_external_definition is True
        assert s2.name == "initWithName:sessionRole:"

        s3 = selref_selector_map[VirtualMemoryPointer(0x10000D378)]
        assert s3.implementation == VirtualMemoryPointer(0x100006354)
        assert s3.is_external_definition is False
        assert s3.name == "viewDidLoad"

    def test_ios14_relative_method_lists(self):
        # Given a binary compiled with a minimum deployment target of iOS 14
        parser = MachoParser(TestObjcRuntimeDataParser.IOS14_RELATIVE_METHOD_LIST_BIN_PATH)
        binary = parser.get_arm64_slice()
        binary.get_minimum_deployment_target()

        # When the Objective C methods within the binary are parsed
        dyld_info_parser = DyldInfoParser(binary)
        objc_parser = ObjcRuntimeDataParser(binary, dyld_info_parser)
        selref_selector_map = objc_parser.selrefs_to_selectors()

        # Then the method structures are correctly parsed
        assert len(selref_selector_map) == 7

        external_sel = selref_selector_map[VirtualMemoryPointer(0x10000C0E0)]
        assert external_sel.implementation is None
        assert external_sel.is_external_definition is True
        assert external_sel.name == "evaluateJavaScript:inFrame:inContentWorld:completionHandler:"

        internal_sel = selref_selector_map[VirtualMemoryPointer(0x10000C0B0)]
        assert internal_sel.implementation == VirtualMemoryPointer(0x100007BFC)
        assert internal_sel.is_external_definition is False
        assert internal_sel.name == "usesWebView"
