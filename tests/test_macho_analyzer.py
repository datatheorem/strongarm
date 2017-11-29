# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

import os
import unittest

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_binary import MachoBinary


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

    def test_get_function_address_range(self):
        start_addr = 0x100006420
        correct_end_addr = 0x100006530

        start, end = self.analyzer.get_function_address_range(start_addr)
        self.assertEqual(end, correct_end_addr)

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
        sym_map = self.analyzer._la_symbol_ptr_to_symbol_name_map
        imported_syms = self.analyzer.imported_symbols
        # make sure all the symbols listed in imported_symbols are present here
        for sym in sym_map.values():
            self.assertTrue(sym in imported_syms)

        # make sure all addresses from stubs have been mapped to real destination addresses
        stubs_map = self.analyzer.imp_stubs
        call_destinations_map = [d.destination for d in stubs_map]
        self.assertEqual(sorted(sym_map.keys()), sorted(call_destinations_map))

    def test_symbols_to_destination_address_resolving(self):
        address_to_symbol_map = self.analyzer.external_branch_destinations_to_symbol_names
        symbol_to_address_map = self.analyzer.external_symbol_names_to_branch_destinations

        # verify both contain the same data
        for k,v in address_to_symbol_map.items():
            self.assertEqual(symbol_to_address_map[v], k)
        for k,v in symbol_to_address_map.items():
            self.assertEqual(address_to_symbol_map[v], k)

        # ensure they contain the correct data
        correct_destination_symbol_map = {
            0x100006730: '_NSClassFromString',
            0x100006790: '_objc_autoreleasePoolPush',
            0x10000676c: '_UIApplicationMain',
            0x100006754: '_NSStringFromClass',
            0x100006784: '_objc_autoreleasePoolPop',
            0x100006760: '_SecTrustEvaluate',
            0x10000673c: '_NSLog',
            0x1000067b4: '_objc_msgSendSuper2',
            0x100006748: '_NSStringFromCGRect',
            0x1000067a8: '_objc_msgSend',
            0x1000067cc: '_objc_retain',
            0x1000067c0: '_objc_release',
            0x1000067e4: '_objc_storeStrong',
            0x1000067f0: '_rand',
            0x1000067d8: '_objc_retainAutoreleasedReturnValue',
            0x100006778: '_dlopen',
            0x10000679c: '_objc_getClass',
        }
        self.assertEqual(sorted(correct_destination_symbol_map), sorted(address_to_symbol_map))

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
