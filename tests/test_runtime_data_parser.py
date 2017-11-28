# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import os
import unittest

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.objc_runtime_data_parser import ObjcRuntimeDataParser


class TestObjcRuntimeDataParser(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    def setUp(self):
        parser = MachoParser(TestObjcRuntimeDataParser.FAT_PATH)
        self.binary = parser.slices[0]
        self.objc_parser = ObjcRuntimeDataParser(self.binary)

    def test_path_for_external_symbol(self):
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
            self.assertEqual(correct_map[symbol], self.objc_parser.path_for_external_symbol(symbol))
        self.assertIsNone(self.objc_parser.path_for_external_symbol('XXX_fake_symbol_XXX'))
