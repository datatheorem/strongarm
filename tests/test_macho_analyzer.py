from typing import List

import pytest
import pathlib

from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_analyzer import MachoAnalyzer, VirtualMemoryPointer

from strongarm.objc import CodeSearch, CodeSearchFunctionCallWithArguments
from strongarm.objc import ObjcFunctionAnalyzer


class TestMachoAnalyzer:
    FAT_PATH = pathlib.Path(__file__).parent / 'bin' / 'StrongarmTarget'

    def setup_method(self):
        parser = MachoParser(TestMachoAnalyzer.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_imp_for_selref(self):
        # selref for -[DTLabel configureLabel]
        imp_within_bin_selref = 0x100009078
        found_imp_address = self.analyzer.imp_for_selref(imp_within_bin_selref)
        correct_imp_address = 0x100006284
        assert found_imp_address == correct_imp_address

        # selref for -[UIFont systemFontOfSize:]
        imp_outside_bin_selref = 0x100009088
        assert self.analyzer.imp_for_selref(imp_outside_bin_selref) is None

        imp_nonexisting = None
        assert self.analyzer.imp_for_selref(imp_nonexisting) is None

    def test_find_function_boundary(self):
        start_addr = 0x100006420
        correct_end_addr = 0x100006530

        found_instructions = self.analyzer.get_function_instructions(start_addr)
        assert len(found_instructions) == 69
        found_end_addr = found_instructions[-1].address
        assert found_end_addr == correct_end_addr

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
        assert sorted(found_imported_symbols) == sorted(correct_imported_symbols)

    def test_find_exported_symbols(self):
        assert self.analyzer.exported_symbol_pointers_to_names == {4294967296: '__mh_execute_header'}
        assert self.analyzer.exported_symbol_names_to_pointers == {'__mh_execute_header': 4294967296}

    def test_cached_analyzer(self):
        # there should only be one MachoAnalyzer for a given MachoBinary
        analyzer1 = MachoAnalyzer.get_analyzer(self.binary)
        analyzer2 = MachoAnalyzer.get_analyzer(self.binary)
        assert analyzer1 == analyzer2

    def test_external_symbol_addr_map(self):
        sym_map = self.analyzer.dyld_bound_symbols
        imported_syms = self.analyzer.imported_symbols
        # make sure all the symbols listed in imported_symbols are present here
        for sym in sym_map.values():
            name = sym.name
            assert name in imported_syms

        # make sure all addresses from stubs have been mapped to real destination addresses
        stubs_map = self.analyzer.imp_stubs
        call_destinations = [d.destination for d in stubs_map]
        for call_destination in call_destinations:
            assert call_destination in sym_map.keys()

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
        assert sorted(bound_symbols) == sorted(correct_bound_symbols)

    def test_symbol_name_for_branch_destination(self):
        # bogus destination
        with pytest.raises(RuntimeError):
            self.analyzer.symbol_name_for_branch_destination(0xdeadbeef)

        # objc_msgSend
        assert self.analyzer.symbol_name_for_branch_destination(0x10000676c) == '_UIApplicationMain'

    def test_selref_to_name_map(self):
        correct_selref_to_imp_map = {
            0x100009070: 0x100006228,
            0x100009078: 0x100006284,
            0x1000090b8: 0x1000063e8,
            0x1000090b0: 0x1000063b0,
        }
        # did analyzer map all selrefs?
        for selref in correct_selref_to_imp_map:
            assert self.analyzer.imp_for_selref(selref) == correct_selref_to_imp_map[selref]

        # can we get an IMP from a selref?
        assert self.analyzer.imp_for_selref(0x100009070) == 0x100006228

        # nonexistent or missing selref handled correctly?
        assert self.analyzer.imp_for_selref(None) is None
        assert self.analyzer.imp_for_selref(0xdeadbeef) is None

        # TODO(PT): handle checking selref which is defined outside binary

    def test_read_imported_symbol_pointers(self):
        # Given the binary's imported symbol pointers are the following values
        # Given the binary contains imported symbol stubs with the following values
        correct_imp_stub_address_to_sym_name = {
            4294993712: '_NSClassFromString', 4294993724: '_NSLog', 4294993736: '_NSStringFromCGRect',
            4294993748: '_NSStringFromClass', 4294993760: '_SecTrustEvaluate', 4294993772: '_UIApplicationMain',
            4294993784: '_dlopen', 4294993796: '_objc_autoreleasePoolPop', 4294993808: '_objc_autoreleasePoolPush',
            4294993820: '_objc_getClass', 4294993832: '_objc_msgSend', 4294993844: '_objc_msgSendSuper2',
            4294993856: '_objc_release', 4294993868: '_objc_retain', 4294993880: '_objc_retainAutoreleasedReturnValue',
            4294993892: '_objc_storeStrong', 4294993904: '_rand'
        }
        # If I ask strongarm to retrieve the map of stubs to imported symbol names
        found_imp_stub_to_sym_name = self.analyzer.imp_stubs_to_symbol_names
        # Then I find the correct data
        assert found_imp_stub_to_sym_name == correct_imp_stub_address_to_sym_name

    def test_read_xref(self):
        # When I ask for an XRef
        # Then I get the correct data
        xrefs = self.analyzer.calls_to(VirtualMemoryPointer(0x100006748))
        assert len(xrefs) == 1
        xref = xrefs[0]
        assert xref.caller_func_start_address == VirtualMemoryPointer(0x100006308)
        assert xref.caller_addr == 0x100006350

        method_info = self.analyzer.method_info_for_entry_point(xref.caller_func_start_address)
        assert method_info

        # TODO(PT): ObjcFunctionAnalyzer.get_function_analyzer* should return singletons
        from strongarm.objc import ObjcFunctionAnalyzer
        caller_func = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.analyzer.binary, method_info)
        assert caller_func.method_info.objc_class.name == 'DTLabel'
        assert caller_func.method_info.objc_sel.name == 'logLabel'

    def test_read_xref_in_search_callback(self):
        # Given I queue a CodeSearch which accesses XRef data

        def callback(analyzer: MachoAnalyzer,
                     search: CodeSearch,
                     results: List):
            # When I access XRef data within the callback
            # Then I can read valid data, because the XRef callback should have been invoked first.
            xrefs = self.analyzer.calls_to(VirtualMemoryPointer(0x100006748))
            assert len(xrefs) == 1
            xref = xrefs[0]

            method_info = self.analyzer.method_info_for_entry_point(xref.caller_func_start_address)
            assert method_info
            caller_func = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.analyzer.binary, method_info)
            # TODO(PT): ObjcFunctionAnalyzer.get_function_analyzer* should return singletons
            assert caller_func.method_info.objc_class.name == 'DTLabel'
            assert caller_func.method_info.objc_sel.name == 'logLabel'
            assert caller_func.start_address == VirtualMemoryPointer(0x100006308)
            assert xref.caller_addr == 0x100006350

        self.analyzer.queue_code_search(CodeSearchFunctionCallWithArguments(
            self.binary, [], {}
        ), callback)
        self.analyzer.search_all_code()

    def test_find_symbols_by_address(self):
        # Given I provide a locally-defined callable symbol (__mh_execute_header)
        # If I ask for the information about this symbol
        addr = VirtualMemoryPointer(0x100000000)
        symbol = self.analyzer.callable_symbol_for_address(addr)
        # Then it is reported correctly
        assert symbol.is_imported is False
        assert symbol.address == addr
        assert symbol.symbol_name == '__mh_execute_header'

        # Given I provide an externally-defined imported symbol (_objc_msgSend)
        # If I ask for the information about this symbol
        addr = VirtualMemoryPointer(0x1000067a8)
        symbol = self.analyzer.callable_symbol_for_address(addr)
        # Then it is reported correctly
        assert symbol.is_imported is True
        assert symbol.address == addr
        assert symbol.symbol_name == '_objc_msgSend'

        # Given I provide a branch destination which does not have an associated symbol name (an anonymous label)
        addr = VirtualMemoryPointer(0x100006270)
        symbol = self.analyzer.callable_symbol_for_address(addr)
        # Then no named symbol is returned
        assert symbol is None

    def test_find_symbols_by_name(self):
        # Given I provide a locally-defined callable symbol (__mh_execute_header)
        # If I ask for the information about this symbol
        symbol = self.analyzer.callable_symbol_for_symbol_name('__mh_execute_header')
        # Then it is reported correctly
        assert symbol.is_imported is False
        assert symbol.address == VirtualMemoryPointer(0x100000000)
        assert symbol.symbol_name == '__mh_execute_header'

        # Given I provide an externally-defined imported symbol (_objc_msgSend)
        # If I ask for the information about this symbol
        symbol = self.analyzer.callable_symbol_for_symbol_name('_objc_msgSend')
        # Then it is reported correctly
        assert symbol.is_imported is True
        assert symbol.address == VirtualMemoryPointer(0x1000067a8)
        assert symbol.symbol_name == '_objc_msgSend'

        # Given I provide a symbol name that is not present in the binary
        symbol = self.analyzer.callable_symbol_for_symbol_name('_fake_symbol')
        # Then no named symbol is returned
        assert symbol is None
