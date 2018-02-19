# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import os
import unittest

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

