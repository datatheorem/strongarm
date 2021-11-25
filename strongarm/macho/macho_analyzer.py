import functools
import pathlib
import shutil
import sqlite3
import tempfile
import time
from contextlib import closing
from ctypes import sizeof
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Type, TypeVar, cast

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs, CsInsn
from more_itertools import first, pairwise

from strongarm.logger import strongarm_logger
from strongarm.macho.arch_independent_structs import CFString32, CFString64, CFStringStruct
from strongarm.macho.dyld_info_parser import DyldBoundSymbol
from strongarm.macho.macho_binary import InvalidAddressError, MachoBinary
from strongarm.macho.macho_definitions import VirtualMemoryPointer
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.macho_string_table_helper import MachoStringTableHelper
from strongarm.macho.objc_runtime_data_parser import (
    ObjcCategory,
    ObjcClass,
    ObjcProtocol,
    ObjcRuntimeDataParser,
    ObjcSelector,
)

if TYPE_CHECKING:
    from strongarm.objc import ObjcFunctionAnalyzer, ObjcMethodInfo

logger = strongarm_logger.getChild(__file__)

_T = TypeVar("_T")


ANALYZER_SQL_SCHEMA = """
    CREATE TABLE function_boundaries(
        entry_point INT NOT NULL UNIQUE,
        end_address INT NOT NULL UNIQUE,
        CHECK (entry_point < end_address)
    );
    CREATE TABLE basic_blocks(
        entry_point INT NOT NULL,
        start_address INT NOT NULL,
        end_address INT NOT NULL,
        CHECK(entry_point <= start_address),
        CHECK(start_address < end_address),
        UNIQUE(entry_point, start_address, end_address)
    );

    CREATE TABLE function_calls(
        destination_address INT,
        caller_address INT,
        caller_func_start_address INT
    );

    CREATE TABLE objc_msgSends(
        destination_address INT,
        caller_address INT,
        caller_func_start_address INT,
        class_name TEXT,
        selector TEXT
    );

    CREATE TABLE named_callable_symbols(
        is_imported INT,
        address INT,
        symbol_name TEXT
    );

    CREATE TABLE string_xrefs(
        string_literal TEXT,
        accessor_address INT,
        accessor_func_start_address INT
    );
"""


class DisassemblyFailedError(Exception):
    """Raised when Capstone fails to disassemble a bytecode sequence."""


@dataclass(order=True, frozen=True)
class CallerXRef:
    destination_addr: VirtualMemoryPointer
    caller_addr: VirtualMemoryPointer
    caller_func_start_address: VirtualMemoryPointer


@dataclass(order=True, frozen=True)
class ObjcMsgSendXref(CallerXRef):
    class_name: Optional[str]
    selector: Optional[str]


@dataclass
class CallableSymbol:
    """A locally-defined function or externally-defined imported function."""

    address: VirtualMemoryPointer
    is_imported: bool
    symbol_name: str


CallableT = TypeVar("CallableT", bound=Callable)


def _requires_xrefs_computed(func: CallableT) -> CallableT:
    @functools.wraps(func)
    def wrap(self: "MachoAnalyzer", *args: Any, **kwargs: Any) -> Any:
        if not self._has_computed_xrefs:
            logger.info(
                f"called {func.__name__} before XRefs were computed for {self.binary.path.name}, computing now..."
            )
            self._build_xref_database()
        return func(self, *args, **kwargs)

    return cast(CallableT, wrap)


class cached_property(object):
    """A property whose value is computed only once.
    Used as a < py3.8 alternative to @functools.cached_property
    Avoiding @functools.lru_cache as they would keep-alive the MachoAnalyzer forever. See:
    https://bugs.python.org/issue19859
    Implementation copied from:
    https://github.com/pallets/werkzeug/blob/0e1b8c4fe598725b343085c5a9a867e90b966db6/werkzeug/utils.py#L35-L73
    """

    def __init__(self, func: Callable) -> None:
        self.__name__ = func.__name__
        self.__module__ = func.__module__
        self.__doc__ = func.__doc__
        self.func = func

    def __get__(self, obj: Any, _type: Type = None) -> Any:
        if obj is None:
            return self
        value = obj.__dict__.get(self.__name__, None)
        if value is None:
            value = self.func(obj)
            obj.__dict__[self.__name__] = value
        return value


class MachoAnalyzer:
    # This class does expensive one-time cross-referencing operations
    # Therefore, we want only one instance to exist for any MachoBinary
    # Thus, the preferred interface for getting an instance of this class is MachoAnalyzer.get_analyzer(binary),
    # which utilizes this cache
    # XXX(PT): These references live to process termination, or until clear_cache() is called
    _ANALYZER_CACHE: Dict[MachoBinary, "MachoAnalyzer"] = {}

    def __init__(self, binary: MachoBinary) -> None:
        self.binary = binary
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        # Each __stubs function calls a single dyld stub address, which has a corresponding DyldBoundSymbol.
        # Map of each __stub function to the associated name of the DyldBoundSymbol
        self._imported_symbol_addresses_to_names: Dict[VirtualMemoryPointer, str] = {}

        self.crossref_helper = MachoStringTableHelper(binary)
        self.imported_symbols = self.crossref_helper.imported_symbols

        self.imp_stubs = MachoImpStubsParser(binary, self.cs).imp_stubs
        self._objc_helper: Optional[ObjcRuntimeDataParser] = None
        self._objc_method_list: List[ObjcMethodInfo] = []

        # Use a temporary database to store cross-referenced data. This provides constant-time lookups for things like
        # finding all the calls to a particular function.
        self._has_computed_xrefs = False
        self._db_tempdir = pathlib.Path(tempfile.mkdtemp())
        self._db_path = self._db_tempdir / "strongarm.db"
        self._db_handle = sqlite3.connect(self._db_path.as_posix())
        cursor = self._db_handle.executescript(ANALYZER_SQL_SCHEMA)
        with self._db_handle:
            cursor.close()

        self._build_callable_symbol_index()
        self._build_function_boundaries_index()

        self._cfstring_to_stringref_map = self._build_cfstring_map()
        self._cstring_to_stringref_map = self._build_cstring_map()

        # Done setting up, store this analyzer in class cache
        MachoAnalyzer._ANALYZER_CACHE[binary] = self

    def __repr__(self) -> str:
        return f"<MachoAnalyzer binary={self.binary.path.as_posix()}>"

    @_requires_xrefs_computed
    def calls_to(self, address: VirtualMemoryPointer) -> List[CallerXRef]:
        """Return the list of code-locations within the binary which branch to the provided address."""
        xrefs_cursor = self._db_handle.execute(
            "SELECT * from function_calls WHERE destination_address=?", (int(address),)
        )
        return [CallerXRef(x[0], x[1], x[2]) for x in xrefs_cursor]

    @_requires_xrefs_computed
    def objc_calls_to(
        self, objc_class_names: List[str], objc_selectors: List[str], requires_class_and_sel_found: bool
    ) -> List[ObjcMsgSendXref]:
        """Return the list of code-locations in the binary which invoke _objc_msgSend with any of the provided
        classes or selectors.
        This also covers iOS 13.5+'s optimized calls that bypass _objc_msgSend, such as _objc_alloc_init.

        If requires_class_and_sel_found is set, a call-site will only be yielded if one of the
        classes and one of the selectors are messaged in the same call.
        Otherwise, a call-site will be yielded if one of the classes *or* one of the selectors are messaged
        at a call site.
        """
        classes_int_list = ", ".join(f'"{x}"' for x in objc_class_names)
        selectors_int_list = ", ".join(f'"{x}"' for x in objc_selectors)

        # Do we require the class and selector being messaged to both be messaged at the same call site?
        query_predicate = "AND" if requires_class_and_sel_found else "OR"
        query = (
            f"SELECT * from objc_msgSends"
            f" WHERE class_name IN ({classes_int_list}) {query_predicate} selector IN ({selectors_int_list})"
        )
        objc_calls_cursor = self._db_handle.execute(query)
        return [ObjcMsgSendXref(x[0], x[1], x[2], x[3], x[4]) for x in objc_calls_cursor]

    def _compute_function_basic_blocks(
        self, entry_point: VirtualMemoryPointer, end_address: VirtualMemoryPointer
    ) -> Iterable[Tuple[int, int]]:
        # PT: This implicitly links against the capstone shared library,
        # and if capstone is not installed correctly it will raise an ImportError.
        # Report this in a clearer way so the user can see exactly what went wrong.
        try:
            from strongarm_dataflow.dataflow import compute_function_basic_blocks_fast
        except ImportError as e:
            if "libcapstone" in str(e):
                import sys

                print("\ncapstone 4.x could not be found, is the capstone backend installed?\n")
                sys.exit(1)
            raise

        bytecode = self.binary.get_content_from_virtual_address(
            virtual_address=entry_point, size=end_address - entry_point
        )
        basic_block_starts = compute_function_basic_blocks_fast(bytecode, entry_point)
        # Convert basic-block starts to [start, end] pairs
        return pairwise(x for x in basic_block_starts)

    def get_basic_block_boundaries(
        self, entry_point: VirtualMemoryPointer
    ) -> List[Tuple[VirtualMemoryPointer, VirtualMemoryPointer]]:
        """Given the function starting at the provided address, return the list of (start_addr, end_addr) basic blocks."""  # noqa: E501
        cursor = self._db_handle.execute(
            "SELECT start_address, end_address FROM basic_blocks WHERE entry_point=?", (entry_point,)
        )
        with closing(cursor):
            return [(VirtualMemoryPointer(x[0]), VirtualMemoryPointer(x[1])) for x in cursor]

    def _build_function_boundaries_index(self) -> None:
        """Iterate all the entry points listed in the binary metadata and compute the end-of-function address for each.
        The end-of-function address for each entry point is then stored in a DB table.

        To compute function boundaries, each function's basic blocks are determined. The end-address is then the
        final address in the final basic block.
        """
        cursor = self._db_handle.cursor()
        sorted_entry_points = sorted(self.get_functions())

        # Computing a function boundaries uses the next entry point address as a hint. For the last entry point in the
        # binary, use the end of the section as the hint.
        try:
            last_entry = sorted_entry_points[-1]
        except IndexError:
            pass
        else:
            section = self.binary.section_for_address(last_entry)
            assert section is not None and section.end_address >= last_entry
            sorted_entry_points.append(VirtualMemoryPointer(section.end_address))

        for entry_point, end_address in pairwise(sorted_entry_points):
            # The end address of the function is the last instruction in the last basic block
            basic_blocks = [x for x in self._compute_function_basic_blocks(entry_point, end_address)]
            # If we found a function with no code, just skip it
            # This can happen in the assembly unit tests, where we insert a jump to a dummy __text label
            if len(basic_blocks) == 0:
                continue
            end_address = VirtualMemoryPointer(max((bb_end for _, bb_end in basic_blocks)))
            cursor.execute(
                "INSERT INTO function_boundaries (entry_point, end_address) VALUES (?, ?)", (entry_point, end_address)
            )
            cursor.executemany(
                "INSERT INTO basic_blocks VALUES (?, ?, ?)", [(entry_point, t[0], t[1]) for t in basic_blocks]
            )

        with self._db_handle:
            cursor.close()

    @cached_property
    def _objc_msgSend_addr(self) -> Optional[VirtualMemoryPointer]:
        objc_msgsend_symbol = self.callable_symbol_for_symbol_name("_objc_msgSend")
        if not objc_msgsend_symbol:
            return None
        return VirtualMemoryPointer(objc_msgsend_symbol.address)

    @cached_property
    def _objc_fastpath_ptrs_to_selector_names(self) -> Dict[VirtualMemoryPointer, str]:
        # Some special selectors have a fast-path, _objc_opt_<selector>, that was added in iOS 13
        # The _objc_opt_* call is emitted instead of _objc_msgSend when the NSObject implementation will be called.
        # Found with: $ nm "/usr/lib/libobjc.A.dylib" | grep "objc_opt"
        # There are also functions in this family that don't begin with "_opt", such as _objc_alloc.
        fastpath_function_names_to_selector_names = {
            "_objc_opt_class": "class",
            "_objc_opt_isKindOfClass": "isKindOfClass:",
            "_objc_opt_new": "new",
            "_objc_opt_respondsToSelector": "respondsToSelector:",
            "_objc_opt_self": "self",
            "_objc_alloc": "alloc",
            "_objc_alloc_init": "init",
        }
        fastpath_funcptrs_to_selector_names: Dict[VirtualMemoryPointer, str] = {}
        for func_name, selector_name in fastpath_function_names_to_selector_names.items():
            # A callable symbol is only present if the function has been used in this binary
            sym = self.callable_symbol_for_symbol_name(func_name)
            if not sym:
                continue
            fastpath_funcptrs_to_selector_names[sym.address] = selector_name
        return fastpath_funcptrs_to_selector_names

    def _build_xref_database(self) -> None:
        """Iterate all the code in the binary and populate the following DB tables:
        * function_calls
        * objc_msgSends
        * string_xrefs
        """
        from strongarm_dataflow.dataflow import build_xref_database_fast

        if self._has_computed_xrefs:
            logger.error("Already computed xrefs, why was _build_xref_database called again?")
            return

        start_time = time.time()
        logger.debug(f"{self.binary.path} computing call XRefs...")

        objc_function_family = list(self._objc_fastpath_ptrs_to_selector_names.keys())
        if self._objc_msgSend_addr:
            objc_function_family.append(self._objc_msgSend_addr)

        build_xref_database_fast(
            self,
            self.binary.path.as_posix(),
            self._db_path.as_posix(),
            self.binary.get_virtual_base(),
            self.binary.get_file_offset(),
            self._objc_msgSend_addr,
            objc_function_family,
            list(self.get_function_boundaries()),
        )

        self._has_computed_xrefs = True
        end_time = time.time()
        logger.debug(f"Finding xrefs took {end_time - start_time} seconds")

    @classmethod
    def clear_cache(cls) -> None:
        """Delete cached MachoAnalyzer's
        This can be used when you are finished analyzing a binary set and don't want to retain the cached data in memory
        """
        for binary, analyzer in cls._ANALYZER_CACHE.items():
            logger.debug(f"Deleting db {analyzer._db_path}...")
            analyzer._db_handle.close()
            shutil.rmtree(analyzer._db_tempdir.as_posix())

        cls._ANALYZER_CACHE.clear()

    @property
    def objc_helper(self) -> ObjcRuntimeDataParser:
        if not self._objc_helper:
            self._objc_helper = ObjcRuntimeDataParser(self.binary)
        return self._objc_helper

    @classmethod
    def get_analyzer(cls, binary: MachoBinary) -> "MachoAnalyzer":
        """Get a cached analyzer for a given MachoBinary."""
        if binary in cls._ANALYZER_CACHE:
            # There exists a MachoAnalyzer for this binary - use it instead of making a new one
            return cls._ANALYZER_CACHE[binary]
        return MachoAnalyzer(binary)

    def method_info_for_entry_point(self, entry_point: VirtualMemoryPointer) -> Optional["ObjcMethodInfo"]:
        # TODO(PT): This should return any symbol name, not just Obj-C methods
        from strongarm.objc.objc_analyzer import ObjcMethodInfo

        for objc_cls in self.objc_classes():
            for sel in objc_cls.selectors:
                if sel.implementation == entry_point:
                    return ObjcMethodInfo(objc_cls, sel, sel.implementation)
        return None

    def objc_classes(self) -> List[ObjcClass]:
        """Return the List of classes and categories implemented within the binary."""
        return self.objc_helper.classes

    def objc_categories(self) -> List[ObjcCategory]:
        """Return the List of categories implemented within the app."""
        all_classes = self.objc_classes()
        categories: List[ObjcCategory] = [c for c in all_classes if isinstance(c, ObjcCategory)]
        return categories

    def get_conformed_protocols(self) -> List[ObjcProtocol]:
        """Return the List of protocols to which code within the binary conforms."""
        return self.objc_helper.protocols

    @property
    def dyld_bound_symbols(self) -> Dict[VirtualMemoryPointer, DyldBoundSymbol]:
        """Return a Dict of each imported dyld stub to the corresponding symbol to be bound at runtime."""
        return self.binary.dyld_bound_symbols

    @property
    def imp_stubs_to_symbol_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of callable implementation stubs to the names of the imported symbols they correspond to."""
        if self._imported_symbol_addresses_to_names:
            return self._imported_symbol_addresses_to_names

        symbol_name_map = {}
        stubs = self.imp_stubs
        stub_map = self.dyld_bound_symbols

        unnamed_stub_count = 0
        for stub in stubs:
            if stub.destination in stub_map:
                symbol_name = stub_map[stub.destination].name
                symbol_name_map[stub.address] = symbol_name
            else:
                # add in stub which is not backed by a named symbol
                # a stub contained in the __stubs section that was not backed by a named symbol was first
                # encountered in com.intuit.mobilebanking01132.app/PlugIns/CMA Balance Widget.appex/CMA Balance Widget
                name = f"unnamed_stub_{unnamed_stub_count}"
                unnamed_stub_count += 1
                symbol_name_map[stub.destination] = name

        self._imported_symbol_addresses_to_names = symbol_name_map
        return symbol_name_map

    @cached_property
    def imported_symbols_to_symbol_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of imported symbol pointers to their names.
        These symbols are not necessarily callable, but may rather be imported classes, for example.
        Inverse of MachoAnalyzer.imported_symbol_names_to_pointers()
        """
        return {addr: x.name for addr, x in self.dyld_bound_symbols.items()}

    @cached_property
    def imported_symbol_names_to_pointers(self) -> Dict[str, VirtualMemoryPointer]:
        """Return a Dict of imported symbol names to their pointers.
        These symbols are not necessarily callable.
        Inverse of MachoAnalyzer.imported_symbol_names_to_pointers()

        NOTE: This API can lose information! A bound symbol of the same name may be bound to multiple locations,
        and this API only retains one of those locations. For example, ___CFConstantStringClassReference is bound to
        the first field of every CFStringStruct in the binary. This API probably shouldn't be used for this reason...
        """
        return {x.name: addr for addr, x in self.dyld_bound_symbols.items()}

    @property
    def exported_symbol_pointers_to_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of pointers to exported symbol definitions to their symbol names.
        Inverse of MachoAnalyzer.exported_symbol_names_to_pointers()
        """
        return self.crossref_helper.exported_symbols

    @cached_property
    def exported_symbol_names_to_pointers(self) -> Dict[str, VirtualMemoryPointer]:
        """Return a Dict of exported symbol names to pointers to their definitions.
        Inverse of MachoAnalyzer.exported_symbols_to_symbol_names()
        """
        return {y: x for x, y in self.exported_symbol_pointers_to_names.items()}

    def exported_symbol_name_for_address(self, address: VirtualMemoryPointer) -> Optional[str]:
        """Return the symbol name for the provided address, or None if the address is not a named exported symbol."""
        if address in self.exported_symbol_pointers_to_names:
            return self.exported_symbol_pointers_to_names[address]
        return None

    def symbol_name_for_branch_destination(self, branch_address: VirtualMemoryPointer) -> str:
        """Get the associated symbol name for a given branch destination."""
        if branch_address in self.imp_stubs_to_symbol_names:
            return self.imp_stubs_to_symbol_names[branch_address]
        raise RuntimeError(f"Unknown branch destination {hex(branch_address)}. Is this a local branch?")

    def disassemble_region(self, start_address: VirtualMemoryPointer, size: int) -> List[CsInsn]:
        """Disassemble the executable code in a given region into a list of CsInsn objects."""
        func_str = bytes(self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size))
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        if not len(instructions):
            raise DisassemblyFailedError(f"Failed to disassemble code at {hex(start_address)}:{hex(size)}")
        return instructions

    def get_function_instructions(self, start_address: VirtualMemoryPointer) -> List[CsInsn]:
        """Get a list of disassembled instructions for the function beginning at start_address."""
        end_address = self.get_function_end_address(start_address)

        if end_address is None:
            raise RuntimeError(f"No function with start address {start_address} found.")

        instructions = self.disassemble_region(start_address, end_address - start_address)
        return instructions

    def imp_for_selref(self, selref_ptr: VirtualMemoryPointer) -> Optional[VirtualMemoryPointer]:
        selector = self.objc_helper.selector_for_selref(selref_ptr)
        if not selector:
            return None
        return selector.implementation

    def selector_for_selref(self, selref_ptr: VirtualMemoryPointer) -> Optional[ObjcSelector]:
        return self.objc_helper.selector_for_selref(selref_ptr)

    def selector_for_selector_literal(self, selref_ptr: VirtualMemoryPointer) -> Optional[ObjcSelector]:
        return self.objc_helper.selector_for_selector_literal(selref_ptr)

    def get_method_imp_addresses(self, selector: str) -> List[VirtualMemoryPointer]:
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL."""
        return self.objc_helper.get_method_imp_addresses(selector)

    def get_imps_for_sel(self, selector: str) -> List["ObjcFunctionAnalyzer"]:
        """Retrieve a list of the disassembled function data for every implementation of a provided selector
        Args:
            selector: The selector name who's implementations should be found

        Returns:
            A list of ObjcFunctionAnalyzers corresponding to each found implementation of the provided selector.
        """
        from strongarm.objc import ObjcFunctionAnalyzer  # noqa: F811

        implementation_analyzers = []
        imp_addresses = self.get_method_imp_addresses(selector)
        for imp_start in imp_addresses:
            imp_instructions = self.get_function_instructions(imp_start)
            function_analyzer = ObjcFunctionAnalyzer(self.binary, imp_instructions)
            implementation_analyzers.append(function_analyzer)
        return implementation_analyzers

    def get_objc_methods(self) -> List["ObjcMethodInfo"]:
        """Get a List of ObjcMethodInfo's representing all ObjC methods implemented in the Mach-O."""
        from strongarm.objc import ObjcMethodInfo  # type: ignore

        if self._objc_method_list:
            return self._objc_method_list
        method_list = []
        for objc_class in self.objc_classes():
            for objc_sel in objc_class.selectors:
                imp_addr = objc_sel.implementation

                info = ObjcMethodInfo(objc_class, objc_sel, imp_addr)
                method_list.append(info)
        self._objc_method_list = method_list
        return self._objc_method_list

    def get_functions(self) -> Set[VirtualMemoryPointer]:
        """Get a list of the function entry points defined in LC_FUNCTION_STARTS. This includes objective-c methods.

        Returns: A list of VirtualMemoryPointers corresponding to each function's entry point.
        """
        return self.binary.get_functions()

    def get_function_boundaries(self) -> Set[Tuple[VirtualMemoryPointer, VirtualMemoryPointer]]:
        cursor = self._db_handle.execute("SELECT entry_point, end_address FROM function_boundaries")

        with closing(cursor):
            return {(VirtualMemoryPointer(a), VirtualMemoryPointer(b)) for a, b in cursor}

    def get_function_end_address(self, entry_point: VirtualMemoryPointer) -> Optional[VirtualMemoryPointer]:
        cursor = self._db_handle.execute(
            "SELECT end_address FROM function_boundaries WHERE entry_point = ?", (entry_point,)
        )

        with closing(cursor):
            results = cursor.fetchone()

        if results is None:
            return None

        return VirtualMemoryPointer(results[0])

    @cached_property
    def class_for_class_pointer_map(self) -> Dict[VirtualMemoryPointer, ObjcClass]:
        return {VirtualMemoryPointer(x.raw_struct.binary_offset): x for x in self.objc_classes()}

    def class_name_for_class_pointer(self, classref: VirtualMemoryPointer) -> Optional[str]:
        """Given a classref, return the name of the class.
        This method will handle classes implemented within the binary and imported classes.
        """
        # Did the caller provide a classref for an imported class?
        local_class = self.imported_symbols_to_symbol_names.get(classref)
        if local_class:
            return local_class

        # The class is implemented within the binary and has an associated ObjcClass object
        # We could have been passed either a classref pointer in __objc_classrefs, or the direct address of
        # an __objc_data structure in __objc_const. Try both variants to search for the associated class.

        # First, check if we were provided with the address of an __objc_data struct in __objc_data representing
        # the class.
        local_class = self.class_for_class_pointer_map.get(classref)
        if local_class:
            return local_class.name

        # Then, check if we were passed a classref pointer in __objc_classrefs
        try:
            dereferenced_classref = VirtualMemoryPointer(self.binary.read_word(classref))
        except InvalidAddressError:
            # Invalid classref
            return None

        local_class = self.class_for_class_pointer_map.get(dereferenced_classref)
        if local_class:
            return local_class.name

        # Invalid classref
        return None

    def classref_for_class_name(self, class_name: str) -> Optional[VirtualMemoryPointer]:
        """Given a class name, try to find a classref for it."""
        classrefs = [
            addr
            for addr, name in self.imported_symbols_to_symbol_names.items()
            if name == class_name and self.binary.section_name_for_address(addr) == "__objc_classrefs"
        ]
        if len(classrefs):
            return classrefs[0]

        # TODO(PT): this is expensive! We should do one analysis step of __objc_classrefs and create a map.
        # is it a local class?
        class_locations = [x.raw_struct.binary_offset for x in self.objc_classes() if x.name == class_name]
        if not len(class_locations):
            # unknown class name
            return None
        class_location = VirtualMemoryPointer(class_locations[0])

        classref_addr_to_pointer_map = self.binary.read_pointer_section("__objc_classrefs")
        # If None is returned, it is an unknown class name
        return first((k for k, v in classref_addr_to_pointer_map.items() if v == class_location), None)

    def selref_for_selector_name(self, selector_name: str) -> Optional[VirtualMemoryPointer]:
        return self.objc_helper.selref_for_selector_name(selector_name)

    @_requires_xrefs_computed
    def strings(self) -> Set[str]:
        """Return a list containing every string in the binary."""
        # Gather strings from various sections
        all_strings = set()
        for section_name in ["__cstring", "__objc_methname", "__objc_methtype", "__objc_classname", "__const"]:
            section_strings = self._strings_in_section(section_name)
            all_strings.update(section_strings)

        # Gather strings found via Xrefs
        c = self._db_handle.cursor()
        xref_strings_rows = c.execute("SELECT string_literal from string_xrefs").fetchall()
        xref_strings = [xref_strings_row[0] for xref_strings_row in xref_strings_rows]
        all_strings.update(set(xref_strings))

        return all_strings

    def get_cstrings(self) -> Set[str]:
        """Return the list of strings in the binary's __cstring section."""
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        # This method should cache its result.
        return self._strings_in_section("__cstring")

    def _build_cstring_map(self) -> Dict[str, VirtualMemoryPointer]:
        strings_section = self.binary.section_with_name("__cstring", "__TEXT")
        if not strings_section:
            return {}

        strings_base = strings_section.address
        strings_content = self.binary.get_bytes(strings_section.offset, strings_section.size)

        string_to_stringrefs = {}
        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(strings_content)
        transformed_strings = MachoStringTableHelper.transform_string_section(string_table)
        for idx, entry in transformed_strings.items():
            # Address is the base of __cstring plus the index of the entry
            stringref_address = VirtualMemoryPointer(strings_base + idx)
            string_to_stringrefs[entry.full_string] = stringref_address
        return string_to_stringrefs

    def _stringref_for_cstring(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref in __cstrings for a provided C string.
        If the string is not present in the __cstrings section, this method returns None.
        """
        if string not in self._cstring_to_stringref_map:
            return None
        return self._cstring_to_stringref_map[string]

    def _build_cfstring_map(self) -> Dict[str, VirtualMemoryPointer]:
        cfstrings_section = self.binary.section_with_name("__cfstring", "__DATA")
        if not cfstrings_section:
            cfstrings_section = self.binary.section_with_name("__cfstring", "__DATA_CONST")
            if not cfstrings_section:
                return {}

        sizeof_cfstring = sizeof(CFString64) if self.binary.is_64bit else sizeof(CFString32)
        cfstrings_base = cfstrings_section.address

        cfstring_to_stringrefs = {}
        cfstrings_count = int((cfstrings_section.end_address - cfstrings_section.address) / sizeof_cfstring)
        for i in range(cfstrings_count):
            cfstring_addr = cfstrings_base + (i * sizeof_cfstring)
            cfstring = self.binary.read_struct_with_rebased_pointers(cfstring_addr, CFStringStruct, virtual=True)
            literal = self.binary.read_string_at_address(cfstring.literal)
            if literal:
                cfstring_to_stringrefs[literal] = VirtualMemoryPointer(cfstring_addr)
        return cfstring_to_stringrefs

    def _stringref_for_cfstring(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref in __cfstrings for a provided Objective-C string literal.
        If the string is not present in the __cfstrings section, this method returns None.
        """
        if string not in self._cfstring_to_stringref_map:
            return None
        return self._cfstring_to_stringref_map[string]

    def stringref_for_string(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref for a provided string.
        If the string is not present in the binary, this method returns None.

        If you are looking for a C string, pass the string with no additional formatting.
        If you are looking for an Objective-C string literal (CFStringRef), enclose your string in @"".
        """
        is_cfstring = False
        if string.startswith('@"'):
            if not string.endswith('"'):
                raise RuntimeError(f"incorrectly formatted ObjC string literal {string}")

            is_cfstring = True
            # trim the @" prefix and the " suffix
            string = string[2:-1]

        if is_cfstring:
            return self._stringref_for_cfstring(string)
        return self._stringref_for_cstring(string)

    @functools.lru_cache(64)
    def callable_symbol_for_address(self, branch_destination: VirtualMemoryPointer) -> Optional[CallableSymbol]:
        """Retrieve information about a callable branch destination.
        It's the caller's responsibility to provide a valid branch destination with a symbol associated with it.
        """
        c = self._db_handle.cursor()
        symbols = c.execute("SELECT * from named_callable_symbols WHERE address=?", (branch_destination,)).fetchall()
        if not len(symbols):
            return None
        assert len(symbols) == 1, f"Found more than 1 symbol at {branch_destination}?"
        symbol_data = symbols[0]

        return CallableSymbol(
            is_imported=bool(symbol_data[0]), address=VirtualMemoryPointer(symbol_data[1]), symbol_name=symbol_data[2]
        )

    def callable_symbol_for_symbol_name(self, symbol_name: str) -> Optional[CallableSymbol]:
        """Retrieve information about a name within the imported or exported symbols tables.
        It's the caller's responsibility to provide a valid callable symbol name.
        """
        c = self._db_handle.cursor()
        symbols = c.execute("SELECT * from named_callable_symbols WHERE symbol_name=?", (symbol_name,)).fetchall()
        if not len(symbols):
            return None
        assert len(symbols) == 1, f"Found more than 1 symbol named {symbol_name}?"
        symbol_data = symbols[0]

        return CallableSymbol(
            is_imported=bool(symbol_data[0]), address=VirtualMemoryPointer(symbol_data[1]), symbol_name=symbol_data[2]
        )

    @_requires_xrefs_computed
    def string_xrefs_to(self, string_literal: str) -> List[Tuple[VirtualMemoryPointer, VirtualMemoryPointer]]:
        """Retrieve each code location that loads the provided (C or CF) string.
        Returns a tuple of (function entry point, instruction which completes the string load)
        """
        c = self._db_handle.cursor()
        xrefs_query = c.execute(
            "SELECT accessor_func_start_address, accessor_address from string_xrefs WHERE string_literal=?",
            (string_literal,),
        ).fetchall()
        string_xrefs = [(VirtualMemoryPointer(x[0]), VirtualMemoryPointer(x[1])) for x in xrefs_query]
        return string_xrefs

    @_requires_xrefs_computed
    def strings_in_func(self, func_addr: VirtualMemoryPointer) -> List[Tuple[VirtualMemoryPointer, str]]:
        """Fetch the list of strings referenced by the provided function.
        Returns a tuple of (instruction that completes the string load, loaded string literal)
        """
        c = self._db_handle.cursor()
        xrefs: Iterable[Tuple[int, str]] = c.execute(
            "SELECT accessor_address, string_literal from string_xrefs WHERE accessor_func_start_address=?",
            (func_addr,),
        )
        string_loads = [(VirtualMemoryPointer(x[0]), x[1]) for x in xrefs]
        return string_loads

    def _build_callable_symbol_index(self) -> None:
        """Build a database index for every callable symbol to symbol name.
        This index includes both imported and exported symbols.
        """
        c = self._db_handle.cursor()

        # Process __imp_stubs
        imp_stub_addr_and_symbol_name = (
            (stub_addr, sym_name) for stub_addr, sym_name in self.imp_stubs_to_symbol_names.items()
        )
        c.executemany("INSERT INTO named_callable_symbols VALUES (1, ?, ?)", imp_stub_addr_and_symbol_name)

        # Process the symbols defined in the binary
        callable_addr_and_sym_name = (
            (callable_addr, sym_name) for callable_addr, sym_name in self.exported_symbol_pointers_to_names.items()
        )
        c.executemany("INSERT INTO named_callable_symbols VALUES (0, ?, ?)", callable_addr_and_sym_name)

        self._db_handle.commit()

    def _strings_in_section(self, section_name: str) -> Set[str]:
        """Fetch the list of strings located inside the provided section."""
        discovered_strings = set()
        string_section = self.binary.section_with_name(section_name, "__TEXT")
        if string_section:
            strings_content = self.binary.get_bytes(string_section.offset, string_section.size)
            transformed_strings = MachoStringTableHelper.transform_string_section(list(strings_content))
            discovered_strings = set((x.full_string for x in transformed_strings.values()))
        return discovered_strings
