# -*- coding: utf-8 -*-
import os
import unittest
from ctypes import create_string_buffer

from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.objc.dataflow import determine_function_boundary


class TestMachoAnalyzer(unittest.TestCase):
    FAT_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget')

    def setUp(self):
        parser = MachoParser(TestMachoAnalyzer.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_imp_for_selref(self):
        # selref for -[DTLabel configureLabel]
        imp_within_bin_selref = 0x100009078
        found_imp_address = self.analyzer.imp_for_selref(imp_within_bin_selref)
        correct_imp_address = 0x100006284
        self.assertEqual(found_imp_address, correct_imp_address)

        # selref for -[UIFont systemFontOfSize:]
        imp_outside_bin_selref = 0x100009088
        self.assertIsNone(self.analyzer.imp_for_selref(imp_outside_bin_selref))

        imp_nonexisting = None
        self.assertIsNone(self.analyzer.imp_for_selref(imp_nonexisting))

    def test_find_function_boundary(self):
        start_addr = 0x100006420
        correct_end_addr = 0x100006530

        # defined in MachoAnalyzer
        max_function_size = 0x2000
        binary_data = self.binary.get_content_from_virtual_address(start_addr, max_function_size)
        bytecode = create_string_buffer(bytes(binary_data), max_function_size)
        # not in cache. calculate function boundary, then cache it
        guessed_end_address = determine_function_boundary(bytecode, start_addr)

        self.assertEqual(guessed_end_address, correct_end_addr)

    def test_find_imported_symbols(self):
        correct_imported_symbols = ['_NSClassFromString',
                                    '_NSLog',
                                    '_NSStringFromCGRect',
                                    '_NSStringFromClass',
                                    '_OBJC_CLASS_$_NSObject',
                                    '_OBJC_CLASS_$_NSURLCredential',
                                    '_OBJC_CLASS_$_UIFont',
                                    '_OBJC_CLASS_$_UILabel',
                                    '_OBJC_CLASS_$_UIResponder',
                                    '_OBJC_CLASS_$_UIViewController',
                                    '_OBJC_METACLASS_$_NSObject',
                                    '_OBJC_METACLASS_$_UILabel',
                                    '_OBJC_METACLASS_$_UIResponder',
                                    '_OBJC_METACLASS_$_UIViewController',
                                    '_SecTrustEvaluate',
                                    '_UIApplicationMain',
                                    '___CFConstantStringClassReference',
                                    '__objc_empty_cache',
                                    '_dlopen',
                                    '_objc_autoreleasePoolPop',
                                    '_objc_autoreleasePoolPush',
                                    '_objc_getClass',
                                    '_objc_msgSend',
                                    '_objc_msgSendSuper2',
                                    '_objc_release',
                                    '_objc_retain',
                                    '_objc_retainAutoreleasedReturnValue',
                                    '_objc_storeStrong',
                                    '_rand',
                                    'dyld_stub_binder'
                                    ]
        found_imported_symbols = self.analyzer.imported_symbols
        # we don't want the test to fail if the arrays contain the same elements but in a different order
        # so, sort the arrays before comparing them
        self.assertEqual(sorted(correct_imported_symbols), sorted(found_imported_symbols))

    def test_find_exported_symbols(self):
        # TODO(PT): figure out how to export symbols ourselves so we can write a better test for this
        # simply defining a function in C code does not work, and simply delcaring an ObjC class does not
        # automatically export it either. We should try making a framework, a hunch says they'd have lots of
        # exported symbols :}
        correct_exported_symbols = ['__mh_execute_header']
        found_exported_symbols = self.analyzer.exported_symbols
        # we don't want the test to fail if the arrays contain the same elements but in a different order
        # so, sort the arrays before comparing them
        self.assertEqual(sorted(correct_exported_symbols), sorted(found_exported_symbols))

    def test_cached_analyzer(self):
        # there should only be one MachoAnalyzer for a given MachoBinary
        analyzer1 = MachoAnalyzer.get_analyzer(self.binary)
        analyzer2 = MachoAnalyzer.get_analyzer(self.binary)
        self.assertEqual(analyzer1, analyzer2)

    def test_external_symbol_addr_map(self):
        sym_map = self.analyzer.dyld_bound_symbols
        imported_syms = self.analyzer.imported_symbols
        # make sure all the symbols listed in imported_symbols are present here
        for sym in sym_map.values():
            name = sym.name
            self.assertTrue(name in imported_syms)

        # make sure all addresses from stubs have been mapped to real destination addresses
        stubs_map = self.analyzer.imp_stubs
        call_destinations = [d.destination for d in stubs_map]
        for call_destination in call_destinations:
            self.assertTrue(call_destination in sym_map.keys())

    def test_find_dyld_bound_symbols(self):
        bound_symbols = self.analyzer.dyld_bound_symbols
        correct_bound_symbols = {
            0x1000090f8: '_OBJC_CLASS_$_NSURLCredential',
            0x1000091f0: '_OBJC_CLASS_$_NSObject',
            0x100009148: '_OBJC_METACLASS_$_NSObject',
            0x100009198: '_OBJC_METACLASS_$_NSObject',
            0x1000091c0: '_OBJC_METACLASS_$_NSObject',
            0x1000091c8: '_OBJC_METACLASS_$_NSObject',
            0x100009210: '_OBJC_METACLASS_$_NSObject',
            0x100009130: '__objc_empty_cache',
            0x100009158: '__objc_empty_cache',
            0x100009180: '__objc_empty_cache',
            0x1000091a8: '__objc_empty_cache',
            0x1000091d0: '__objc_empty_cache',
            0x1000091f8: '__objc_empty_cache',
            0x100009220: '__objc_empty_cache',
            0x100009248: '__objc_empty_cache',
            0x100008000: 'dyld_stub_binder',
            0x100008098: '___CFConstantStringClassReference',
            0x1000080b8: '___CFConstantStringClassReference',
            0x1000080d8: '___CFConstantStringClassReference',
            0x1000080f8: '___CFConstantStringClassReference',
            0x100008118: '___CFConstantStringClassReference',
            0x100008138: '___CFConstantStringClassReference',
            0x100008158: '___CFConstantStringClassReference',
            0x1000090f0: '_OBJC_CLASS_$_UIFont',
            0x100009128: '_OBJC_CLASS_$_UILabel',
            0x100009240: '_OBJC_CLASS_$_UIResponder',
            0x100009178: '_OBJC_CLASS_$_UIViewController',
            0x100009150: '_OBJC_METACLASS_$_UILabel',
            0x100009218: '_OBJC_METACLASS_$_UIResponder',
            0x1000091a0: '_OBJC_METACLASS_$_UIViewController',
            0x100008010: '_NSClassFromString',
            0x100008018: '_NSLog',
            0x100008020: '_NSStringFromCGRect',
            0x100008028: '_NSStringFromClass',
            0x100008030: '_SecTrustEvaluate',
            0x100008038: '_UIApplicationMain',
            0x100008040: '_dlopen',
            0x100008048: '_objc_autoreleasePoolPop',
            0x100008050: '_objc_autoreleasePoolPush',
            0x100008058: '_objc_getClass',
            0x100008060: '_objc_msgSend',
            0x100008068: '_objc_msgSendSuper2',
            0x100008070: '_objc_release',
            0x100008078: '_objc_retain',
            0x100008080: '_objc_retainAutoreleasedReturnValue',
            0x100008088: '_objc_storeStrong',
            0x100008090: '_rand',
        }
        self.assertEqual(sorted(bound_symbols), sorted(correct_bound_symbols))

    def test_symbol_name_for_branch_destination(self):
        # bogus destination
        self.assertRaises(RuntimeError, self.analyzer.symbol_name_for_branch_destination, 0xdeadbeef)

        # objc_msgSend
        self.assertEqual(self.analyzer.symbol_name_for_branch_destination(0x10000676c), '_UIApplicationMain')

    def test_selref_to_name_map(self):
        correct_selref_to_imp_map = {
            0x100009070: 0x100006228,
            0x100009078: 0x100006284,
            0x1000090b8: 0x1000063e8,
            0x1000090b0: 0x1000063b0,
        }
        # did analyzer map all selrefs?
        for selref in correct_selref_to_imp_map:
            self.assertEqual(correct_selref_to_imp_map[selref], self.analyzer.imp_for_selref(selref))

        # can we get an IMP from a selref?
        self.assertEqual(self.analyzer.imp_for_selref(0x100009070), 0x100006228)

        # nonexistent or missing selref handled correctly?
        self.assertIsNone(self.analyzer.imp_for_selref(None))
        self.assertIsNone(self.analyzer.imp_for_selref(0xdeadbeef))

        # TODO(PT): handle checking selref which is defined outside binary
