import pathlib
from contextlib import contextmanager
from textwrap import dedent
from typing import Generator, List, Tuple

import pytest

from strongarm.macho import MachoBinary, ObjcCategory
from strongarm.macho.macho_analyzer import CallerXRef, MachoAnalyzer, ObjcMsgSendXref, VirtualMemoryPointer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc import ObjcFunctionAnalyzer
from tests.utils import binary_containing_code, binary_with_name


class TestMachoAnalyzerControlFlowTarget:
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmControlFlowTarget"

    def setup_method(self) -> None:
        parser = MachoParser(self.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_get_function_end_address(self) -> None:
        test_cases = (
            # -[CFDataFlowMethods switchControlFlow] defined at 0x10000675c
            (0x10000675C, 0x1000067F4),
        )
        for entry_point, expected_end_address in test_cases:
            end_address = self.analyzer.get_function_end_address(VirtualMemoryPointer(entry_point))
            assert end_address == expected_end_address


class TestMachoAnalyzer:
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "StrongarmTarget"

    def setup_method(self) -> None:
        parser = MachoParser(self.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_imp_for_selref(self) -> None:
        # selref for -[DTLabel configureLabel]
        imp_within_bin_selref = VirtualMemoryPointer(0x100009078)
        found_imp_address = self.analyzer.imp_for_selref(imp_within_bin_selref)
        correct_imp_address = VirtualMemoryPointer(0x100006284)
        assert found_imp_address == correct_imp_address

        # selref for -[UIFont systemFontOfSize:]
        imp_outside_bin_selref = VirtualMemoryPointer(0x100009088)
        assert self.analyzer.imp_for_selref(imp_outside_bin_selref) is None

        imp_nonexisting = None
        assert self.analyzer.imp_for_selref(imp_nonexisting) is None  # type: ignore

    def test_find_function_boundary(self) -> None:
        start_addr = VirtualMemoryPointer(0x100006420)
        correct_end_addr = VirtualMemoryPointer(0x100006530)

        found_instructions = self.analyzer.get_function_instructions(start_addr)
        assert len(found_instructions) == 69
        found_end_addr = found_instructions[-1].address
        assert found_end_addr == correct_end_addr

    def test_get_function_boundaries(self) -> None:
        correct_entry_points = [
            0x100006228,
            0x100006284,
            0x100006308,
            0x1000063B0,
            0x1000063E8,
            0x100006420,
            0x100006534,
            0x100006590,
            0x1000065EC,
            0x10000665C,
            0x1000066DC,
            0x1000066E4,
            0x1000066E8,
            0x1000066EC,
            0x1000066F0,
            0x1000066F4,
            0x1000066F8,
            0x100006708,
            0x10000671C,
        ]
        boundaries = self.analyzer.get_function_boundaries()
        entry_points, end_addresses = zip(*sorted(boundaries))
        assert list(entry_points) == correct_entry_points
        assert list(end_addresses) == correct_entry_points[1:] + [0x100006730]

    def test_get_function_end_address(self) -> None:
        start_addr = VirtualMemoryPointer(0x100006420)
        correct_end_addr = VirtualMemoryPointer(0x100006534)

        end_address = self.analyzer.get_function_end_address(start_addr)
        assert end_address == correct_end_addr

    def test_find_imported_symbols(self) -> None:
        correct_imported_symbols = [
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
        found_imported_symbols = self.analyzer.imported_symbols
        # we don't want the test to fail if the arrays contain the same elements but in a different order
        # so, sort the arrays before comparing them
        assert sorted(found_imported_symbols) == sorted(correct_imported_symbols)

    def test_find_exported_symbols(self) -> None:
        assert self.analyzer.exported_symbol_pointers_to_names == {4294967296: "__mh_execute_header"}
        assert self.analyzer.exported_symbol_names_to_pointers == {"__mh_execute_header": 4294967296}

    def test_cached_analyzer(self) -> None:
        # there should only be one MachoAnalyzer for a given MachoBinary
        analyzer1 = MachoAnalyzer.get_analyzer(self.binary)
        analyzer2 = MachoAnalyzer.get_analyzer(self.binary)
        assert analyzer1 == analyzer2

    def test_external_symbol_addr_map(self) -> None:
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

    def test_find_dyld_bound_symbols(self) -> None:
        bound_symbols = self.analyzer.dyld_bound_symbols
        correct_bound_symbols = {
            0x1000090F8: "_OBJC_CLASS_$_NSURLCredential",
            0x1000091F0: "_OBJC_CLASS_$_NSObject",
            0x100009148: "_OBJC_METACLASS_$_NSObject",
            0x100009198: "_OBJC_METACLASS_$_NSObject",
            0x1000091C0: "_OBJC_METACLASS_$_NSObject",
            0x1000091C8: "_OBJC_METACLASS_$_NSObject",
            0x100009210: "_OBJC_METACLASS_$_NSObject",
            0x100009130: "__objc_empty_cache",
            0x100009158: "__objc_empty_cache",
            0x100009180: "__objc_empty_cache",
            0x1000091A8: "__objc_empty_cache",
            0x1000091D0: "__objc_empty_cache",
            0x1000091F8: "__objc_empty_cache",
            0x100009220: "__objc_empty_cache",
            0x100009248: "__objc_empty_cache",
            0x100008000: "dyld_stub_binder",
            0x100008098: "___CFConstantStringClassReference",
            0x1000080B8: "___CFConstantStringClassReference",
            0x1000080D8: "___CFConstantStringClassReference",
            0x1000080F8: "___CFConstantStringClassReference",
            0x100008118: "___CFConstantStringClassReference",
            0x100008138: "___CFConstantStringClassReference",
            0x100008158: "___CFConstantStringClassReference",
            0x1000090F0: "_OBJC_CLASS_$_UIFont",
            0x100009128: "_OBJC_CLASS_$_UILabel",
            0x100009240: "_OBJC_CLASS_$_UIResponder",
            0x100009178: "_OBJC_CLASS_$_UIViewController",
            0x100009150: "_OBJC_METACLASS_$_UILabel",
            0x100009218: "_OBJC_METACLASS_$_UIResponder",
            0x1000091A0: "_OBJC_METACLASS_$_UIViewController",
            0x100008010: "_NSClassFromString",
            0x100008018: "_NSLog",
            0x100008020: "_NSStringFromCGRect",
            0x100008028: "_NSStringFromClass",
            0x100008030: "_SecTrustEvaluate",
            0x100008038: "_UIApplicationMain",
            0x100008040: "_dlopen",
            0x100008048: "_objc_autoreleasePoolPop",
            0x100008050: "_objc_autoreleasePoolPush",
            0x100008058: "_objc_getClass",
            0x100008060: "_objc_msgSend",
            0x100008068: "_objc_msgSendSuper2",
            0x100008070: "_objc_release",
            0x100008078: "_objc_retain",
            0x100008080: "_objc_retainAutoreleasedReturnValue",
            0x100008088: "_objc_storeStrong",
            0x100008090: "_rand",
        }
        assert sorted(bound_symbols) == sorted(correct_bound_symbols)

    def test_symbol_name_for_branch_destination(self) -> None:
        # bogus destination
        with pytest.raises(RuntimeError):
            self.analyzer.symbol_name_for_branch_destination(VirtualMemoryPointer(0xDEADBEEF))

        # objc_msgSend
        assert (
            self.analyzer.symbol_name_for_branch_destination(VirtualMemoryPointer(0x10000676C)) == "_UIApplicationMain"
        )

    def test_selref_to_name_map(self) -> None:
        correct_selref_to_imp_map_raw = {
            0x100009070: 0x100006228,
            0x100009078: 0x100006284,
            0x1000090B8: 0x1000063E8,
            0x1000090B0: 0x1000063B0,
        }
        correct_selref_to_imp_map = {VirtualMemoryPointer(k): v for k, v in correct_selref_to_imp_map_raw.items()}

        # did analyzer map all selrefs?
        for selref in correct_selref_to_imp_map:
            assert self.analyzer.imp_for_selref(selref) == correct_selref_to_imp_map[selref]

        # can we get an IMP from a selref?
        assert self.analyzer.imp_for_selref(VirtualMemoryPointer(0x100009070)) == 0x100006228

        # nonexistent or missing selref handled correctly?
        assert self.analyzer.imp_for_selref(VirtualMemoryPointer(0xDEADBEEF)) is None

        # TODO(PT): handle checking selref which is defined outside binary

    def test_read_imported_symbol_pointers(self) -> None:
        # Given the binary's imported symbol pointers are the following values
        # Given the binary contains imported symbol stubs with the following values
        correct_imp_stub_address_to_sym_name = {
            4294993712: "_NSClassFromString",
            4294993724: "_NSLog",
            4294993736: "_NSStringFromCGRect",
            4294993748: "_NSStringFromClass",
            4294993760: "_SecTrustEvaluate",
            4294993772: "_UIApplicationMain",
            4294993784: "_dlopen",
            4294993796: "_objc_autoreleasePoolPop",
            4294993808: "_objc_autoreleasePoolPush",
            4294993820: "_objc_getClass",
            4294993832: "_objc_msgSend",
            4294993844: "_objc_msgSendSuper2",
            4294993856: "_objc_release",
            4294993868: "_objc_retain",
            4294993880: "_objc_retainAutoreleasedReturnValue",
            4294993892: "_objc_storeStrong",
            4294993904: "_rand",
        }
        # If I ask strongarm to retrieve the map of stubs to imported symbol names
        found_imp_stub_to_sym_name = self.analyzer.imp_stubs_to_symbol_names
        # Then I find the correct data
        assert found_imp_stub_to_sym_name == correct_imp_stub_address_to_sym_name

    def test_read_xref(self) -> None:
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
        caller_func = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.analyzer.binary, method_info)
        assert caller_func.method_info
        assert caller_func.method_info.objc_class.name == "DTLabel"
        assert caller_func.method_info.objc_sel.name == "logLabel"

    def test_find_symbols_by_address(self) -> None:
        # Given I provide a locally-defined callable symbol (__mh_execute_header)
        # If I ask for the information about this symbol
        addr = VirtualMemoryPointer(0x100000000)
        symbol = self.analyzer.callable_symbol_for_address(addr)
        # Then it is reported correctly
        assert symbol
        assert symbol.is_imported is False
        assert symbol.address == addr
        assert symbol.symbol_name == "__mh_execute_header"

        # Given I provide an externally-defined imported symbol (_objc_msgSend)
        # If I ask for the information about this symbol
        addr = VirtualMemoryPointer(0x1000067A8)
        symbol = self.analyzer.callable_symbol_for_address(addr)
        # Then it is reported correctly
        assert symbol
        assert symbol.is_imported is True
        assert symbol.address == addr
        assert symbol.symbol_name == "_objc_msgSend"

        # Given I provide a branch destination which does not have an associated symbol name (an anonymous label)
        addr = VirtualMemoryPointer(0x100006270)
        symbol = self.analyzer.callable_symbol_for_address(addr)
        # Then no named symbol is returned
        assert symbol is None

    def test_find_symbols_by_name(self) -> None:
        # Given I provide a locally-defined callable symbol (__mh_execute_header)
        # If I ask for the information about this symbol
        symbol = self.analyzer.callable_symbol_for_symbol_name("__mh_execute_header")
        # Then it is reported correctly
        assert symbol
        assert symbol.is_imported is False
        assert symbol.address == VirtualMemoryPointer(0x100000000)
        assert symbol.symbol_name == "__mh_execute_header"

        # Given I provide an externally-defined imported symbol (_objc_msgSend)
        # If I ask for the information about this symbol
        symbol = self.analyzer.callable_symbol_for_symbol_name("_objc_msgSend")
        # Then it is reported correctly
        assert symbol
        assert symbol.is_imported is True
        assert symbol.address == VirtualMemoryPointer(0x1000067A8)
        assert symbol.symbol_name == "_objc_msgSend"

        # Given I provide a symbol name that is not present in the binary
        symbol = self.analyzer.callable_symbol_for_symbol_name("_fake_symbol")
        # Then no named symbol is returned
        assert symbol is None

    def test_strings(self) -> None:
        source_code = """
        @interface Class1 : NSObject
        - (void)selectorOutsideCString;
        @end
        @implementation Class1
        - (void)selectorOutsideCString {
            NSLog(@"Wheee!");
        }
        @end
        @interface Class2 : NSObject
        - (void)foo;
        @end
        @implementation Class2
        - (void)foo {
            // Ensure there is an XRef to the selector literal in __objc_methname
           [[[Class1 alloc] init] selectorOutsideCString];
        }
        @end
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for the list of strings in __cstrings
            cstrings = analyzer.get_cstrings()
            # I get 1 item - the hardcoded string
            assert len(cstrings) == 1
            assert "Wheee!" in cstrings

            # When I ask for all strings
            all_strings = analyzer.strings()
            assert len(all_strings) > 5
            # I get methods, classes, methodtypes, and cstrings
            assert "selectorOutsideCString" in all_strings
            assert "Class2" in all_strings
            assert "Wheee!" in all_strings
            assert "v16@0:8" in all_strings

    def test_parses_cfstrings_with_rebases__ios15(self) -> None:
        # Given a binary that contains chained fixup rebases within the CFString static structures
        chained_fixup_pointers_binary = binary_with_name("iOS15_chained_fixup_pointers")
        # When I parse the C string/CFString data
        a = MachoAnalyzer.get_analyzer(chained_fixup_pointers_binary)
        # Then the data is correctly parsed
        assert a._cfstring_to_stringref_map == {
            "x is: %d i is %d": VirtualMemoryPointer(0x100008070),
            "Default Configuration": VirtualMemoryPointer(0x100008090),
        }
        assert a._cstring_to_stringref_map == {"x is: %d i is %d": 0x100007F71, "Default Configuration": 0x100007F82}
        # And I can query it via APIs
        assert a.stringref_for_string('@"x is: %d i is %d"') == VirtualMemoryPointer(0x100008070)
        assert a.stringref_for_string('@"Default Configuration"') == VirtualMemoryPointer(0x100008090)

    def test_class_name_for_class_pointer__with_rebases(self) -> None:
        # Given a binary that contains chained fixup rebases within the class ref static structures
        # For class refs to appear in a binary, a class has to reference another class
        outer_source_code = dedent(
            """
            @interface ApiProvider : NSObject
            + (void)setApiKey:(NSString *)apiKey;
            @end
            @implementation ApiProvider
            + (void)setApiKey:(NSString *)apiKey {
            }
            @end
            @interface ApiConsumer : NSObject
            @end
            @implementation ApiConsumer
            - (void)performApiCall {
                [ApiProvider setApiKey:@"private_api_key_do_not_leak"];
            }
            @end
            """
        ).strip()
        expected_values_mapping = {
            VirtualMemoryPointer(0x000000010000C1C0): "ApiProvider",
        }
        with binary_containing_code("", is_assembly=False, code_outside_objc_class=outer_source_code) as (
            binary,
            analyzer,
        ):
            # When I parse the Objc class ref data
            class_names = [analyzer.class_name_for_class_pointer(pointer) for pointer in expected_values_mapping]
            # Then the data is correctly parsed
            assert class_names == list(expected_values_mapping.values())


class TestMachoAnalyzerDynStaticChecks:
    FAT_PATH = pathlib.Path(__file__).parent / "bin" / "DynStaticChecks"

    def setup_method(self) -> None:
        parser = MachoParser(self.FAT_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_get_function_boundaries(self) -> None:
        correct_entry_points = [
            0x100007B1C,
            0x100007BD8,
            0x100007C94,
            0x100007D50,
            0x100007E0C,
            0x100007EC8,
            0x100007F84,
            0x100007FE4,
            0x1000080D0,
            0x100008158,
            0x1000081CC,
            0x100008254,
            0x1000082C8,
            0x100008350,
            0x1000083C4,
            0x1000083FC,
            0x100008434,
            0x10000849C,
            0x100008504,
            0x1000085F0,
            0x100008610,
            0x100008690,
            0x100008774,
            0x1000087F0,
            0x100008864,
            0x1000089EC,
            0x100008AB8,
            0x100008B48,
            0x100008C3C,
            0x100008D6C,
            0x100008E4C,
            0x100008F3C,
            0x100008F50,
            0x10000901C,
            0x1000090A4,
            0x100009104,
            0x100009188,
            0x10000920C,
            0x100009274,
            0x1000092E4,
            0x1000093A4,
            0x1000093D8,
            0x100009460,
            0x10000950C,
            0x100009584,
            0x100009604,
            0x100009688,
            0x100009700,
            0x1000097EC,
            0x1000097F4,
            0x1000097F8,
            0x1000097FC,
            0x100009800,
            0x100009804,
            0x100009808,
            0x100009818,
            0x10000982C,
            0x100009840,
            0x10000992C,
            0x100009968,
            0x1000099A8,
            0x1000099E8,
            0x100009A64,
            0x100009AE4,
            0x100009B64,
            0x100009BB4,
            0x100009C08,
            0x100009C5C,
            0x100009CE8,
            0x100009D78,
            0x100009E08,
            0x100009E50,
        ]
        correct_entry_points = list(map(VirtualMemoryPointer, correct_entry_points))
        boundaries = self.analyzer.get_function_boundaries()
        entry_points, end_addresses = zip(*sorted(boundaries))
        assert list(entry_points) == correct_entry_points
        assert list(end_addresses) == correct_entry_points[1:] + [0x100009EA8]

    def test_get_function_end_address(self) -> None:
        test_cases = (
            # -[PTObjectTracking earlyReturn] defined at 0x100008e4c
            (0x100008E4C, 0x100008F3C),
            # -[PTObjectTracking .cxx_destruct] defined at 0x100008f3c
            (0x100008F3C, 0x100008F50),
            # -[ITJRSA SecKeyDecryptStaticPrivateKey] defined at 0x10000901c
            (0x10000901C, 0x1000090A4),
            # -[ITJCCKeyDerivationPBKDF lowRoundCount] defined at 0x100009604
            (0x100009604, 0x100009688),
        )
        for entry_point, expected_end_address in test_cases:
            end_address = self.analyzer.get_function_end_address(VirtualMemoryPointer(entry_point))
            assert end_address == expected_end_address

    def test_xref_objc_opt_new(self) -> None:
        # Given I provide a binary which contains the code:
        # _objc_opt_new(_OBJC_CLASS_$_ARSKView)
        binary = binary_with_name("iOS13_objc_opt")
        analyzer = MachoAnalyzer.get_analyzer(binary)

        expected_call_site = ObjcMsgSendXref(
            caller_func_start_address=VirtualMemoryPointer(0x100006388),
            caller_addr=VirtualMemoryPointer(0x1000063B4),
            destination_addr=VirtualMemoryPointer(0x10000659C),
            class_name="_OBJC_CLASS_$_ARSKView",
            selector="new",
        )

        # When I ask for XRefs to `ARSKView`
        objc_calls = analyzer.objc_calls_to(
            objc_class_names=["_OBJC_CLASS_$_ARSKView"], objc_selectors=[], requires_class_and_sel_found=False
        )
        # Then the code location is returned
        assert len(objc_calls) == 1
        assert objc_calls[0] == expected_call_site

        # And when I ask for XRefs to `new`
        objc_calls = analyzer.objc_calls_to(
            objc_class_names=[], objc_selectors=["new"], requires_class_and_sel_found=False
        )
        # Then the code location is returned
        assert len(objc_calls) == 1
        assert objc_calls[0] == expected_call_site

        # And when I ask for XRefs to `[ARSKView new]`
        objc_calls = analyzer.objc_calls_to(
            objc_class_names=["_OBJC_CLASS_$_ARSKView"], objc_selectors=["new"], requires_class_and_sel_found=False
        )
        # Then the code location is returned
        assert len(objc_calls) == 1
        assert objc_calls[0] == expected_call_site

    def test_xref_objc_opt_class(self) -> None:
        # Given I provide a binary which contains the code:
        # _objc_opt_class(_OBJC_CLASS_$_ARFaceTrackingConfiguration)
        binary = binary_with_name("iOS13_objc_opt")
        analyzer = MachoAnalyzer.get_analyzer(binary)

        expected_call_site = ObjcMsgSendXref(
            caller_func_start_address=VirtualMemoryPointer(0x100006388),
            caller_addr=VirtualMemoryPointer(0x10000639C),
            destination_addr=VirtualMemoryPointer(0x100006590),
            class_name="_OBJC_CLASS_$_ARFaceTrackingConfiguration",
            selector="class",
        )

        # When I ask for XRefs to `ARSKView`
        objc_calls = sorted(
            analyzer.objc_calls_to(
                objc_class_names=["_OBJC_CLASS_$_ARFaceTrackingConfiguration"],
                objc_selectors=[],
                requires_class_and_sel_found=False,
            )
        )
        # Then the code location is returned
        assert len(objc_calls) == 1
        assert objc_calls[0] == expected_call_site

        # And when I ask for XRefs to `class`
        objc_calls = sorted(
            analyzer.objc_calls_to(objc_class_names=[], objc_selectors=["class"], requires_class_and_sel_found=False)
        )
        # Then the code location is returned
        assert len(objc_calls) == 2
        assert objc_calls[0] == expected_call_site

        # And when I ask for XRefs to `[ARFaceTrackingConfiguration class]`
        # Then the code location is returned
        objc_calls = sorted(
            analyzer.objc_calls_to(
                objc_class_names=["_OBJC_CLASS_$_ARFaceTrackingConfiguration"],
                objc_selectors=[],
                requires_class_and_sel_found=False,
            )
        )
        # Then the code location is returned
        assert len(objc_calls) == 1
        assert objc_calls[0] == expected_call_site

    @contextmanager
    def uiwebview_bound_symbol_collision(self) -> Generator[Tuple[MachoBinary, MachoAnalyzer], None, None]:
        """Yields a binary/analyzer pair that contains two dyld bound symbols for _OBJC_CLASS_$_UIWebView.
        One binding points to the base class of an Objective-C category, and one points to a classref used to perform
        an _objc_msgSend call.
        """
        with binary_containing_code(
            code_inside_objc_class="""
            - (instancetype)initWithValue:(NSInteger)value {
                if ((self = [super init])) {
                    NSLog(@"value: %d", value);
                }
            }
            - (void)useWebView {
                // Use a UIWebView to make sure there's a UIWebView classref in the binary
                UIWebView* wv = [[UIWebView alloc] initWithFrame:CGRectZero];
                [wv myCategoryMethod];
            }
            - (void)useThisClass {
                SourceClass* sc = [[SourceClass alloc] initWithValue:5];
                NSLog(@"sc: %@", sc);
            }
            """,
            is_assembly=False,
            code_outside_objc_class="""
            @interface UIWebView (LocalCategory)
            - (void)myCategoryMethod;
            @end
            @implementation UIWebView (LocalCategory)
            - (void)myCategoryMethod {
                NSLog(@"category code");
            }
            @end
            @interface LocalClass2 : SourceClass
            - (void)newMethod;
            @end
            @implementation LocalClass2
            - (void)newMethod {
                LocalClass2* sc = [[LocalClass2 alloc] initWithValue:5];
            }
            - (instancetype)initWithValue:(NSInteger)value {
                if ((self = [super init])) {
                    NSLog(@"value: %d", value);
                }
            }
            @end
            """,
        ) as (binary, analyzer):
            yield binary, analyzer

    def test_returns_imported_classref_with_multiple_bound_addresses(self) -> None:
        # Given a binary that contains multiple dyld bindings for _OBJC_CLASS_$_UIWebView
        with self.uiwebview_bound_symbol_collision() as (binary, analyzer):
            uiwebview_bindings = [
                addr
                for addr, name in analyzer.imported_symbols_to_symbol_names.items()
                if name == "_OBJC_CLASS_$_UIWebView"
            ]
            # And the binding in __objc_const is placed before the binding in __objc_classrefs
            objc_const_binding = VirtualMemoryPointer(0x10000C048)
            objc_classrefs_binding = VirtualMemoryPointer(0x10000C250)

            assert uiwebview_bindings == [objc_const_binding, objc_classrefs_binding]

            # When the classref for UIWebView is queried
            uiwebview_classref = analyzer.classref_for_class_name("_OBJC_CLASS_$_UIWebView")
            # Then the address of the bound symbol in __objc_classrefs is returned
            # (The address of the bound symbol in __objc_const should not be returned by this API)
            assert uiwebview_classref == objc_classrefs_binding

    def test_class_name_for_class_pointer(self) -> None:
        # Given a binary that contains imported and local class names
        with self.uiwebview_bound_symbol_collision() as (binary, analyzer):
            # When I ask for the class name of a binding in __objc_const (the base class of a category)
            # Then the correct imported class name is returned
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C048)) == "_OBJC_CLASS_$_UIWebView"

            # When I ask for the class name of a binding in __objc_classrefs (a classref used for _objc_msgSend)
            # Then the correct imported class name is returned
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C250)) == "_OBJC_CLASS_$_UIWebView"

            # When I ask for the class name of a binding in __objc_data (the superclass of a local class)
            # Then the correct imported class name is returned
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C2F0)) == "_OBJC_CLASS_$_NSObject"

            # When I ask for the class name of a locally implemented class using the __objc_data pointer
            # Then the correct locally defined class name is returned
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C270)) == "LocalClass2"
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C2E8)) == "SourceClass"

            # When I ask for the class name of a locally implemented class using the __objc_classrefs pointer
            # Then the correct locally defined class name is returned
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C248)) == "LocalClass2"
            assert analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C258)) == "SourceClass"

            # When I ask for the name of a category referencing an imported base class using the __objc_const struct
            # Then the correct name is returned
            assert (
                analyzer.class_name_for_class_pointer(VirtualMemoryPointer(0x10000C040))
                == "_OBJC_CLASS_$_UIWebView (LocalCategory)"
            )

    def test_parse_superclass_and_category_base(self) -> None:
        # Given a binary that contains locally defined classes and categories
        # That inherit from local and imported symbols
        with self.uiwebview_bound_symbol_collision() as (binary, analyzer):
            class_superclass_pairs = []
            # When the name and super/base-class name of each class is read
            for objc_cls in analyzer.objc_classes():
                if isinstance(objc_cls, ObjcCategory):
                    class_superclass_pairs.append((objc_cls.category_name, objc_cls.base_class))
                else:
                    assert objc_cls.superclass_name
                    class_superclass_pairs.append((objc_cls.name, objc_cls.superclass_name))

            # Then the super/base-class names are correctly parsed
            assert class_superclass_pairs == [
                ("LocalClass2", "SourceClass"),
                ("SourceClass", "_OBJC_CLASS_$_NSObject"),
                ("LocalCategory", "_OBJC_CLASS_$_UIWebView"),
            ]

    def test_find_string_xref(self) -> None:
        # Given a binary that accesses different constant strings throughout the code
        source_code = """
        - (void)method1 {
            NSLog(@"ConstString1");
        }
        - (void)method2 {
            NSString* x = [NSString stringWithFormat:@"ConstString2"];
        }
        - (void)method3 {
            NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
            dateFormatter.dateFormat = @"ConstString3";
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for the XRefs to each string
            # Then every XRef is correctly shown
            #
            # The exact string load addr comes from checking the compiled binary, but check against the expected
            # methods each XRef should be contained within
            string_to_xrefs = {
                "ConstString1": [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method1"
                        ).start_address,
                        VirtualMemoryPointer(0x100007DFC),
                    )
                ],
                "ConstString2": [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method2"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E40),
                    )
                ],
                "ConstString3": [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method3"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E88),
                    )
                ],
            }

            for string, expected_xrefs in string_to_xrefs.items():
                xrefs = analyzer.string_xrefs_to(string)
                assert xrefs == expected_xrefs

    def test_find_string_xref__multiple_xrefs(self) -> None:
        # Given a binary that accesses the same constant string in multiple locations
        source_code = """
        - (void)method1 {
            printf([@"ConstString1" utf8String]);
        }
        - (void)method2 {
            NSLog(@"The constant string is: %@", @"ConstString1");
        }
        - (void)method3 {
            NSDateFormatter* dateFormatter = [[NSDateFormatter alloc] init];
            dateFormatter.dateFormat = @"ConstString1";
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for XRefs to the constant string
            # Then every location that loads the string is correctly shown
            xrefs = sorted(analyzer.string_xrefs_to("ConstString1"))
            expected_xrefs = sorted(
                [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method1"
                        ).start_address,
                        VirtualMemoryPointer(0x100007DDC),
                    ),
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method2"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E24),
                    ),
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method3"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E74),
                    ),
                ]
            )
            assert xrefs == expected_xrefs

    def test_find_string_xref__ignores_unrelated_constant_data(self) -> None:
        # Given a binary that contains static variables stored as constant data
        source_code = """
        static char const1[256] = {0};
        static int const2 = 42;
        static char* const3 = "hello world";

        - (void)method1 {
            NSString* x = [NSString stringWithFormat:@"ConstString1"];
            NSLog(@"%s %d %s", const1, const2, const3);
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for the XRefs to a string
            # Then the XRef generator is not confused by the constant data
            # (The string XRef heuristic doesn't match the constant data)
            # And the XRef is correctly shown
            xrefs = analyzer.string_xrefs_to("ConstString1")
            expected_xrefs = [
                (
                    ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                        binary, "SourceClass", "method1"
                    ).start_address,
                    VirtualMemoryPointer(0x100007E98),
                )
            ]
            assert xrefs == expected_xrefs

    def test_find_string_xref__adr_pattern(self) -> None:
        # Given a binary that references a static string
        # And the binary was compiled such that the string is loaded via the `adr` pattern
        binary = binary_with_name("TestBinary5")
        analyzer = MachoAnalyzer.get_analyzer(binary)
        # When I ask for the XRefs to the string
        xrefs = analyzer.string_xrefs_to("DELETE FROM testfairy WHERE id = %d;")
        # Then the code location is correctly shown
        assert xrefs == [(VirtualMemoryPointer(0x10003ABE8), VirtualMemoryPointer(0x10003ACB0))]

    @pytest.mark.xfail(reason="Generating XRefs to strings in static variables / constant data is not yet supported")
    def test_find_string_xref__finds_string_in_constant_data(self) -> None:
        # Given a binary that stores a string in a static var (constant data), then uses the string via the static var
        source_code = """
        static NSString* staticStr = @"ConstString1";
        - (void)method1 {
            printf([staticStr utf8String]);
        }
        - (void)method2 {
            NSLog(@"The static string is: %@", staticStr);
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for the XRefs to each string
            # Then every XRef is correctly shown
            xrefs = analyzer.string_xrefs_to("ConstString1")
            expected_xrefs = [
                (
                    ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                        binary, "SourceClass", "method1"
                    ).start_address,
                    VirtualMemoryPointer(0x100007E74),
                ),
                (
                    ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                        binary, "SourceClass", "method2"
                    ).start_address,
                    VirtualMemoryPointer(0x100007EB0),
                ),
            ]
            assert xrefs == expected_xrefs

    def test_find_string_xref__cstring(self) -> None:
        # Given a binary that accesses different C constant strings throughout the code
        source_code = """
        - (void)method1 {
            printf("ConstString1");
        }
        - (void)method2 {
            printf("ConstString1");
        }
        - (void)method3 {
            printf("ConstString2");
            [NSString stringWithFormat:@"ConstString3"];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for the XRefs to each string
            # Then every XRef is correctly shown, even thouth the strings are C strings and not CFStrings
            string_to_xrefs = {
                "ConstString1": [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method2"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E70),
                    ),
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method1"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E44),
                    ),
                ],
                "ConstString2": [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method3"
                        ).start_address,
                        VirtualMemoryPointer(0x100007E9C),
                    )
                ],
                "ConstString3": [
                    (
                        ObjcFunctionAnalyzer.get_function_analyzer_for_signature(
                            binary, "SourceClass", "method3"
                        ).start_address,
                        VirtualMemoryPointer(0x100007EC0),
                    )
                ],
            }

            for string, expected_xrefs in string_to_xrefs.items():
                xrefs = analyzer.string_xrefs_to(string)
                assert sorted(xrefs) == sorted(expected_xrefs)

    def test_find_strings_in_func(self) -> None:
        # Given a binary that accesses C and CF strings in a few functions / methods
        source_code = """
        void func1() {
            printf("CString1");
            NSLog(@"CFString1");
        }
        - (void)method1 {
            func1();
            printf("CString2");
            [NSString stringWithFormat:@"CFString2"];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I ask for the strings referenced by each function/method
            # Then each string is correctly returned
            functions_to_string_data = {
                VirtualMemoryPointer(0x100007E44): [(0x100007E54, "CString1"), (0x100007E60, "CFString1")],
                VirtualMemoryPointer(0x100007E7C): [(0x100007E98, "CString2"), (0x100007EBC, "CFString2")],
            }
            for function_addr, expected_string_load_and_strings in functions_to_string_data.items():
                strings_in_func = analyzer.strings_in_func(VirtualMemoryPointer(function_addr))
                assert strings_in_func == expected_string_load_and_strings

    def test_objc_fast_path_xrefs(self) -> None:
        # Given a binary that intentionally hits the ObjC fast-paths
        source_code = """
        - (void)objc_opt_class {
            Class x = [NSObject class];
        }
        - (void)objc_opt_isKindOfClass {
            BOOL x = [NSObject isKindOfClass:[NSArray class]];
        }
        - (void)objc_opt_new {
            NSObject* x = [NSObject new];
        }
        - (void)objc_opt_respondsToSelector {
            BOOL x = [NSObject respondsToSelector:@selector(fake)];
        }
        - (void)objc_opt_self {
            id x = [[NSObject new] self];
        }
        - (void)objc_alloc {
            id x = [NSObject alloc];
        }
        - (void)objc_alloc_init {
            id x = [[NSObject alloc] init];
        }
        - (void)useMsgSend {
            // Ensure the binary has _objc_msgSend since SA requires it
            id x = [NSArray arrayWithArray:@[@2]];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # And ensure that each ObjC fast path is actually used in the binary
            fast_paths = [
                "_objc_opt_class",
                "_objc_opt_isKindOfClass",
                "_objc_opt_new",
                "_objc_opt_respondsToSelector",
                "_objc_opt_self",
                "_objc_alloc",
                "_objc_alloc_init",
            ]
            for fast_path_func in fast_paths:
                assert analyzer.callable_symbol_for_symbol_name(fast_path_func) is not None

            sels_to_expected_call_site = {
                "class": "objc_opt_class",
                "isKindOfClass:": "objc_opt_isKindOfClass",
                "new": "objc_opt_new",
                "respondsToSelector:": "objc_opt_respondsToSelector",
                "self": "objc_opt_self",
                "alloc": "objc_alloc",
                "init": "objc_alloc_init",
            }
            for selector, expected_method_name_containing_xref in sels_to_expected_call_site.items():
                # When I ask for XRefs to the selector
                xrefs = analyzer.objc_calls_to(
                    objc_class_names=[], objc_selectors=[selector], requires_class_and_sel_found=False
                )

                callers: List[str] = []
                for xref in xrefs:
                    entry_point = VirtualMemoryPointer(xref.caller_func_start_address)
                    method_info = analyzer.method_info_for_entry_point(entry_point)
                    if not method_info:
                        continue
                    callers.append(method_info.objc_sel.name)

                # Then the method contains a usage of the fast-path selector, masked behind an _objc_opt_* call
                assert expected_method_name_containing_xref in callers

    def test_parse_xrefs__binary_lacks_objc_msgSend(self) -> None:
        # Given a binary that hits ObjC fast-path functions but does not contain an imported _objc_msgSend symbol
        source_code = """
        - (void)objc_opt_new {
            NSObject* x = [NSObject new];
            NSLog(@"x: %@", x);
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # Validate assumptions
            assert analyzer.callable_symbol_for_symbol_name("_objc_msgSend") is None
            assert analyzer._objc_msgSend_addr is None

            objc_opt_new_sym = analyzer.callable_symbol_for_symbol_name("_objc_opt_new")
            assert objc_opt_new_sym is not None
            objc_opt_new_stub_addr = objc_opt_new_sym.address

            nslog_imported_sym = analyzer.callable_symbol_for_symbol_name("_NSLog")
            assert nslog_imported_sym is not None
            nslog_stub_addr = nslog_imported_sym.address

            # When I use various XRef APIs
            objc_new_xrefs = analyzer.objc_calls_to([], ["new"], False)
            nslog_xrefs = analyzer.calls_to(nslog_stub_addr)

            # Then XRefs are successfully parsed even though there is no _objc_msgSend symbol
            # And the XRefs look correct
            assert len(objc_new_xrefs) == 1
            objc_new_xref = objc_new_xrefs[0]
            assert objc_new_xref.class_name == "_OBJC_CLASS_$_NSObject"
            assert objc_new_xref.selector == "new"
            # Test all properties to ensure XRef system works
            assert objc_new_xref.destination_addr == objc_opt_new_stub_addr
            assert objc_new_xref.caller_addr == 0x100007EDC
            assert objc_new_xref.caller_func_start_address == 0x100007EBC

            assert len(nslog_xrefs) == 1
            nslog_xref = nslog_xrefs[0]
            assert nslog_xref.destination_addr == nslog_stub_addr
            # Test all properties to ensure XRef system works
            assert nslog_xref.caller_addr == 0x100007EF8
            assert nslog_xref.caller_func_start_address == 0x100007EBC

    def test_parse_xrefs__objc_msgSend(self) -> None:
        # Given a binary that uses _objc_msgSend in a few places
        source_code = """
        - (void)m1 {
            NSString* x = [NSString stringWithFormat:@"test"];
            NSLog(@"%@", x);
        }
        - (void)m2 {
            UIView* x = [[UIView alloc] initWithFrame:CGRectZero];
            NSLog(@"%@", x);
        }
        - (void)m3 {
            // Try to get a call to -addObject: without a valid classref
            NSMutableArray* m = [NSMutableArray alloc];
            [[UIView alloc] init];
            NSLog(@"%@", @"123");
            [m init];
            [m addObject:@4];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # Validate assumptions
            objc_msgSend_sym = analyzer.callable_symbol_for_symbol_name("_objc_msgSend")
            assert objc_msgSend_sym is not None
            objc_msgSend_addr = objc_msgSend_sym.address

            objc_alloc_sym = analyzer.callable_symbol_for_symbol_name("_objc_alloc")
            assert objc_alloc_sym is not None
            objc_alloc_addr = objc_alloc_sym.address

            objc_alloc_init_sym = analyzer.callable_symbol_for_symbol_name("_objc_alloc_init")
            assert objc_alloc_init_sym is not None
            objc_alloc_init_addr = objc_alloc_init_sym.address

            m1_addr = analyzer.get_method_imp_addresses("m1")[0]
            m2_addr = analyzer.get_method_imp_addresses("m2")[0]
            m3_addr = analyzer.get_method_imp_addresses("m3")[0]

            # When I look at the raw Objective-C Xrefs that were generated
            analyzer._build_xref_database()
            objc_xrefs = [x for x in analyzer._db_handle.execute("SELECT * from objc_msgSends")]

            # Then they are generated correctly and include every ObjC call in the binary
            correct_xrefs = [
                (objc_msgSend_addr, 0x100007D0C, m1_addr, "_OBJC_CLASS_$_NSString", "stringWithFormat:"),
                (objc_alloc_addr, 0x100007D64, m2_addr, "_OBJC_CLASS_$_UIView", "alloc"),
                (objc_msgSend_addr, 0x100007D88, m2_addr, "_OBJC_CLASS_$_UIView", "initWithFrame:"),
                (objc_alloc_addr, 0x100007DD4, m3_addr, "_OBJC_CLASS_$_NSMutableArray", "alloc"),
                (objc_alloc_init_addr, 0x100007DE8, m3_addr, "_OBJC_CLASS_$_UIView", "init"),
                (objc_msgSend_addr, 0x100007E1C, m3_addr, "___CFConstantStringClassReference", "init"),
                (objc_msgSend_addr, 0x100007E48, m3_addr, "_OBJC_CLASS_$_NSNumber", "numberWithInt:"),
                (objc_msgSend_addr, 0x100007E68, m3_addr, None, "addObject:"),
            ]
            assert sorted(objc_xrefs) == sorted(correct_xrefs)

    def test_generate_xrefs__malformed_bytecode(self) -> None:
        # Given a binary with a function that intentionally embeds invalid AArch64 bytecode
        source_code = """
        - (void)method1 {
            NSLog(@"Some code");
        }
        - (void)method2 {
            [self method1];
        }
        - (void)badBytecode {
            NSLog(@"Some other code");
            [self method2];

            // Some garbage instructions that'll fail to disassemble
            asm volatile(".word 0xffffffff");
            asm volatile(".word 0xffffffff");

            NSLog(@"Some more code");
            [self method2];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I generate XRefs for the binary
            objc_xrefs = sorted(analyzer.objc_calls_to([], ["method1"], False))
            nslog_symbol = analyzer.callable_symbol_for_symbol_name("_NSLog")
            assert nslog_symbol is not None
            c_xrefs = sorted(analyzer.calls_to(nslog_symbol.address))

            # Then XRefs are generated successfully, even though a function contained invalid bytecode
            assert objc_xrefs == [
                ObjcMsgSendXref(
                    destination_addr=VirtualMemoryPointer(0x100007EE4),
                    caller_addr=VirtualMemoryPointer(0x100007E40),
                    caller_func_start_address=VirtualMemoryPointer(0x100007E1C),
                    class_name=None,
                    selector="method1",
                )
            ]
            assert c_xrefs == [
                CallerXRef(
                    destination_addr=VirtualMemoryPointer(0x100007ED8),
                    caller_addr=VirtualMemoryPointer(0x100007E0C),
                    caller_func_start_address=VirtualMemoryPointer(0x100007DF0),
                )
            ]

    def test_generate_xrefs__malformed_bytecode_in_string_xref(self) -> None:
        # Given a binary with a function that intentionally embeds invalid AArch64 bytecode
        # And the bytecode will trigger the lookahead-disassemble to parse a string load XRef
        source_code = """
        - (void)method1 {
            NSLog(@"Some code");
        }
        - (void)method2 {
            [self method1];
        }
        - (void)badBytecode {
            NSLog(@"Some other code");
            [self method2];

            // This massaged bytecode was copied from the app referenced by SCAN-2415
            // Instruction 1: Relative jump to after the bytecode sequence
            asm volatile(".word 0x14000005");

            // Instruction 2: adrp x0, #0x114e40000
            // XRef generation will interpret this as the first half of a string load,
            // and will try to disassemble the next instruction to complete the string load
            asm volatile(".word 0xb00a71c0");

            // Instructions 3 & 4: garbage, will fail to disassemble
            asm volatile(".word 0xffffffff");
            asm volatile(".word 0xffffffff");

            NSLog(@"Some more code");
            [self method2];
        }
        - (void)method3 {
            NSLog(@"Some more code");
            [self method2];
        }
        """
        with binary_containing_code(source_code, is_assembly=False) as (binary, analyzer):
            # When I generate XRefs for the binary
            objc_xrefs = sorted(analyzer.objc_calls_to([], ["method1"], False))
            nslog_symbol = analyzer.callable_symbol_for_symbol_name("_NSLog")
            assert nslog_symbol is not None
            c_xrefs = sorted(analyzer.calls_to(nslog_symbol.address))

            # Then XRefs are generated successfully, even though a function contained invalid bytecode
            assert objc_xrefs == [
                ObjcMsgSendXref(
                    destination_addr=VirtualMemoryPointer(0x100007ED4),
                    caller_addr=VirtualMemoryPointer(0x100007DE8),
                    caller_func_start_address=VirtualMemoryPointer(0x100007DC4),
                    class_name=None,
                    selector="method1",
                )
            ]
            assert len(c_xrefs) == 3

    def test_generates_xrefs__malformed_binary(self) -> None:
        # Given a malformed binary (generated by AFL++) that causes an exception when calling `selector_for_selref`
        binary = binary_with_name("AFLMalformedSelref")
        # When we generate the XRef database
        analyzer = MachoAnalyzer.get_analyzer(binary)
        # Then no exception / SIGSEGV is hit
        try:
            analyzer.calls_to(VirtualMemoryPointer(0x0))
        except Exception:
            pass

    def test_get_objc_selector_stubs(self) -> None:
        # Given a binary compiled with an Xcode version that does not produce __objc_stubs
        binary_without_objc_stubs = binary_with_name("iOS13_objc_opt")
        assert not binary_without_objc_stubs.section_with_name("__objc_stubs", "__TEXT")
        # When I call the API to retrieve the ObjC stubs
        # Then no error is raised, and no stubs are returned
        assert MachoAnalyzer.get_analyzer(binary_without_objc_stubs)._get_objc_selector_stubs() == {}

        # Given a binary compiled with an Xcode version that does produce __objc_stubs
        binary_with_objc_stubs = binary_with_name("Xcode14_objc_stubs")
        assert binary_with_objc_stubs.section_with_name("__objc_stubs", "__TEXT")
        # When I call the API to retrieve the ObjC stubs
        # Then the stubs are computed correctly
        # XXX(PT): Interestingly, it seems selector stubs always sit on 32-byte (0x20) boundaries. I wonder why.
        assert MachoAnalyzer.get_analyzer(binary_with_objc_stubs)._get_objc_selector_stubs() == {
            0x100007C60: "URLByAppendingPathComponent:",
            0x100007C80: "URLForResource:withExtension:",
            0x100007CA0: "URLsForDirectory:inDomains:",
            0x100007CC0: "defaultManager",
            0x100007CE0: "initForWritingWithMutableData:",
            0x100007D00: "initWithConcurrencyType:",
            0x100007D20: "initWithContentsOfURL:",
            0x100007D40: "initWithManagedObjectModel:",
            0x100007D60: "lastObject",
            0x100007D80: "mainBundle",
            0x100007DA0: "persistentStoreCoordinator",
            0x100007DC0: "setPersistentStoreCoordinator:",
        }

    def test_find_xref_from_selector_stub(self) -> None:
        # Given a binary that contains calls to a stub in __objc_stubs
        binary_with_objc_stubs = binary_with_name("Xcode14_objc_stubs")
        # When I search for XRefs to a selector in __objc_stubs
        xrefs = MachoAnalyzer.get_analyzer(binary_with_objc_stubs).objc_calls_to(
            [], ["initForWritingWithMutableData:"], False
        )
        # Then the XRef is correctly found
        assert xrefs == [
            ObjcMsgSendXref(
                destination_addr=VirtualMemoryPointer(0x100007CE0),
                caller_addr=VirtualMemoryPointer(0x100007C18),
                caller_func_start_address=VirtualMemoryPointer(0x100007BDC),
                class_name="_OBJC_CLASS_$_NSData",
                selector="initForWritingWithMutableData:",
            )
        ]
