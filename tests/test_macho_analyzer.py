from __future__ import absolute_import
from __future__ import unicode_literals

import os
import unittest

from gammaray.ios_app import IosAppPackage
from strongarm.macho.macho_analyzer import MachoAnalyzer


class TestMachoAnalyzer(unittest.TestCase):
    IPA_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmTarget.ipa')

    def test_imp_for_selref(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            # selref for -[DTLabel configureLabel]
            imp_within_bin_selref = 0x100008ef8
            found_imp_address = analyzer.imp_for_selref(imp_within_bin_selref)
            correct_imp_address = 0x100006514
            self.assertTrue(found_imp_address == correct_imp_address)

            # selref for -[UIFont systemFontOfSize:]
            imp_outside_bin_selref = 0x100008f08
            self.assertRaises(analyzer.imp_for_selref(imp_outside_bin_selref))

            imp_nonexisting = None
            self.assertIsNone(analyzer.imp_for_selref(imp_nonexisting))

    def test_get_function_address_range(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            start_addr = 0x1000066b0
            correct_end_addr = 0x1000067c0

            start, end = analyzer.get_function_address_range(start_addr)
            self.assertEqual(end, correct_end_addr)

    def test_parse_imported_symbols(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            correct_imported_symbols = ['radr://5614542',
                                        '__mh_execute_header',
                                        '_NSLog',
                                        '_NSStringFromCGRect',
                                        '_NSStringFromClass',
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
                                        '_objc_autoreleasePoolPop',
                                        '_objc_autoreleasePoolPush',
                                        '_objc_msgSend',
                                        '_objc_msgSendSuper2',
                                        '_objc_release',
                                        '_objc_retain',
                                        '_objc_retainAutoreleasedReturnValue',
                                        '_objc_storeStrong',
                                        '_rand',
                                        'dyld_stub_binder'
                                        ]
            found_imported_symbols = analyzer.imported_functions
            # we don't want the test to fail if the arrays contain the same elements but in a different order
            # so, sort the arrays before comparing them
            self.assertEqual(sorted(correct_imported_symbols), sorted(found_imported_symbols))

    def test_cached_analyzer(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            # there should only be one MachoAnalyzer for a given MachoBinary
            analyzer1 = MachoAnalyzer.get_analyzer(binary)
            analyzer2 = MachoAnalyzer.get_analyzer(binary)
            self.assertEqual(analyzer1, analyzer2)

    def test_external_symbol_addr_map(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            sym_map = analyzer.external_symbol_addr_map
            imported_syms = analyzer.imported_functions
            # make sure all the symbols listed in imported_symbols are present here
            for sym in sym_map.itervalues():
                self.assertTrue(sym in imported_syms)

            # make sure all addresses from stubs have been mapped to real destination addresses
            stubs_map = analyzer.imp_stub_section_map
            call_destinations_map = [d.destination for d in stubs_map]
            self.assertEqual(sorted(sym_map.keys()), sorted(call_destinations_map))

    def test_symbols_to_destination_address_resolving(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            address_to_symbol_map = analyzer.address_to_symbol_name_map
            symbol_to_address_map = analyzer.symbol_name_to_address_map

            # verify both contain the same data
            for k,v in address_to_symbol_map.iteritems():
                self.assertEqual(symbol_to_address_map[v], k)
            for k,v in symbol_to_address_map.iteritems():
                self.assertEqual(address_to_symbol_map[v], k)

            # ensure they contain the correct data
            correct_destination_symbol_map = {
                0x1000068e0: '_objc_autoreleasePoolPush',
                0x1000068c8: '_UIApplicationMain',
                0x1000068b0: '_NSStringFromClass',
                0x1000068d4: '_objc_autoreleasePoolPop',
                0x1000068bc: '_SecTrustEvaluate',
                0x100006898: '_NSLog',
                0x1000068f8: '_objc_msgSendSuper2',
                0x1000068a4: '_NSStringFromCGRect',
                0x1000068ec: '_objc_msgSend',
                0x100006910: '_objc_retain',
                0x100006904: '_objc_release',
                0x100006928: '_objc_storeStrong',
                0x100006934: '_rand',
                0x10000691c: '_objc_retainAutoreleasedReturnValue',
            }
            self.assertEqual(sorted(correct_destination_symbol_map), sorted(address_to_symbol_map))

    def test_symbol_name_for_branch_destination(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            # bogus destination
            self.assertRaises(RuntimeError, analyzer.symbol_name_for_branch_destination, 0xdeadbeef)

            # objc_msgSend
            self.assertEqual(analyzer.symbol_name_for_branch_destination(0x1000068c8), '_UIApplicationMain')

    def test_selref_to_name_map(self):
        with IosAppPackage(self.IPA_PATH) as app:
            binary = app.get_main_executable().get_parsed_binary()
            analyzer = MachoAnalyzer.get_analyzer(binary)

            correct_selref_to_imp_map = {
                0x100008f38: 0x100006678,
                0x100008ef0: 0x1000064b8,
                0x100008ef8: 0x100006514,
                0x100008f30: 0x100006640,
            }
            # did analyzer map all selrefs?
            self.assertEqual(sorted(correct_selref_to_imp_map), sorted(analyzer._selref_ptr_to_imp_map))

            # can we get an IMP from a selref?
            self.assertEqual(analyzer.imp_for_selref(0x100008f38), 0x100006678)

            # nonexistent or missing selref handled correctly?
            self.assertIsNone(analyzer.imp_for_selref(None))
            self.assertRaises(RuntimeError, analyzer.imp_for_selref, 0xdeadbeef)

            # TODO(PT): handle checking selref which is defined outside binary
