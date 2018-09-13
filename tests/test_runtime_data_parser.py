# -*- coding: utf-8 -*-
import os
import unittest
from typing import List

from strongarm.macho import MachoParser, ObjcRuntimeDataParser, ObjcCategory


class TestObjcRuntimeDataParser(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')
    CATEGORY_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'DigitalAdvisorySolutions')

    def test_path_for_external_symbol(self):
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        binary = parser.slices[0]
        objc_parser = ObjcRuntimeDataParser(binary)

        correct_map = {
            '_NSLog': '/System/Library/Frameworks/Foundation.framework/Foundation',
            '_NSStringFromCGRect': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_NSStringFromClass': '/System/Library/Frameworks/Foundation.framework/Foundation',
            '_OBJC_CLASS_$_NSURLCredential': '/System/Library/Frameworks/Foundation.framework/Foundation',
            '_OBJC_CLASS_$_UIFont': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_OBJC_CLASS_$_UILabel': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_OBJC_CLASS_$_UIResponder': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_OBJC_CLASS_$_UIViewController': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_OBJC_METACLASS_$_NSObject': '/usr/lib/libobjc.A.dylib',
            '_OBJC_METACLASS_$_UILabel': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_OBJC_METACLASS_$_UIResponder': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_OBJC_METACLASS_$_UIViewController': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '_SecTrustEvaluate': '/System/Library/Frameworks/Security.framework/Security',
            '_UIApplicationMain': '/System/Library/Frameworks/UIKit.framework/UIKit',
            '___CFConstantStringClassReference': '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
            '__objc_empty_cache': '/usr/lib/libobjc.A.dylib',
            '_objc_autoreleasePoolPop': '/usr/lib/libobjc.A.dylib',
            '_objc_autoreleasePoolPush': '/usr/lib/libobjc.A.dylib',
            '_objc_msgSend': '/usr/lib/libobjc.A.dylib',
            '_objc_msgSendSuper2': '/usr/lib/libobjc.A.dylib',
            '_objc_release': '/usr/lib/libobjc.A.dylib',
            '_objc_retain': '/usr/lib/libobjc.A.dylib',
            '_objc_retainAutoreleasedReturnValue': '/usr/lib/libobjc.A.dylib',
            '_objc_storeStrong': '/usr/lib/libobjc.A.dylib',
            '_rand': '/usr/lib/libSystem.B.dylib',
            'dyld_stub_binder': '/usr/lib/libSystem.B.dylib',
        }
        for symbol in correct_map:
            self.assertEqual(correct_map[symbol], objc_parser.path_for_external_symbol(symbol))
        self.assertIsNone(objc_parser.path_for_external_symbol('XXX_fake_symbol_XXX'))

    def test_find_categories(self):
        parser = MachoParser(TestObjcRuntimeDataParser.CATEGORY_PATH)
        binary = parser.slices[0]
        objc_parser = ObjcRuntimeDataParser(binary)

        # extract category list
        category_classes = [x for x in objc_parser.classes if isinstance(x, ObjcCategory)]
        self.assertEqual(len(category_classes), 9)

        # look at one category
        category = [x for x in category_classes if x.name == 'DataController'][0]
        self.assertEqual(len(category.selectors), 1)
        selector = category.selectors[0]
        self.assertEqual(selector.name, 'allowsAnyHTTPSCertificateForHost:')
        self.assertEqual(selector.implementation, 0x100005028)

    def test_find_protocols(self):
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        binary = parser.get_arm64_slice()
        objc_parser = ObjcRuntimeDataParser(binary)

        protocols = objc_parser.protocols
        self.assertEqual(len(protocols), 3)

        correct_protocols = ['NSObject', 'NSURLSessionDelegate', 'UIApplicationDelegate']
        for p in correct_protocols:
            self.assertTrue(p in [a.name for a in protocols])

    def test_parse_protocol(self):
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        binary = parser.get_arm64_slice()
        objc_parser = ObjcRuntimeDataParser(binary)

        protocols = objc_parser.protocols
        # look at one protocol
        session_protocol = [p for p in protocols if p.name == 'NSURLSessionDelegate'][0]
        self.assertEqual(len(session_protocol.selectors), 3)
        correct_selectors = ['URLSession:didBecomeInvalidWithError:',
                             'URLSession:didReceiveChallenge:completionHandler:',
                             'URLSessionDidFinishEventsForBackgroundURLSession:']
        for s in correct_selectors:
            self.assertTrue(s in [sel.name for sel in session_protocol.selectors])

    def test_class_conforming_protocols(self):
        def check_class_conformed_protocols(class_name: str, correct_protocols: List[str]):
            cls = [x for x in objc_parser.classes if x.name == class_name][0]
            self.assertIsNotNone(cls)
            conformed_protocol_names = [x.name for x in cls.protocols]
            self.assertEqual(correct_protocols, conformed_protocol_names)

        parser = MachoParser(TestObjcRuntimeDataParser.CATEGORY_PATH)
        binary = parser.get_arm64_slice()
        objc_parser = ObjcRuntimeDataParser(binary)

        check_class_conformed_protocols(
            'CDVInAppBrowserViewController',
            [
                'CDVScreenOrientationDelegate',
                'WKNavigationDelegate',
                'WKUIDelegate',
                'WKScriptMessageHandler'
            ]
        )
        check_class_conformed_protocols(
            '_TtC26Digital_Advisory_Solutions21LicenceViewController',
            ['UITableViewDataSource']
        )
        # this class doesn't conform to any protocols
        check_class_conformed_protocols(
            'BadFilesDetector',
            []
        )
