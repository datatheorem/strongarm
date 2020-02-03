import time
import functools
import shutil
import sqlite3
import logging
import pathlib
import tempfile
from contextlib import closing
from ctypes import sizeof
from dataclasses import dataclass

from itertools import tee
from typing import TYPE_CHECKING
from typing import Set, List, Dict, Optional, Callable
from typing import Iterable
from typing import Tuple
from typing import TypeVar
from capstone import Cs, CsInsn, CS_ARCH_ARM64, CS_MODE_ARM

from strongarm.macho.macho_definitions import VirtualMemoryPointer
from strongarm.macho.arch_independent_structs import CFStringStruct, CFString32, CFString64
from strongarm.macho.macho_imp_stubs import MachoImpStubsParser
from strongarm.macho.macho_binary import MachoBinary, InvalidAddressError
from strongarm.macho.dyld_info_parser import DyldInfoParser, DyldBoundSymbol
from strongarm.macho.macho_string_table_helper import MachoStringTableHelper
from strongarm.macho.progress_bar import ConsoleProgressBar

from strongarm.macho.objc_runtime_data_parser import (
    ObjcClass,
    ObjcCategory,
    ObjcProtocol,
    ObjcSelector,
    ObjcRuntimeDataParser,
)

if TYPE_CHECKING:
    from strongarm.objc import (
        ObjcFunctionAnalyzer, ObjcMethodInfo,
        CodeSearch, CodeSearchResult
    )


_T = TypeVar("_T")

# Callback invoked when the results for a previously queued CodeSearch have been found.
# This will be dispatched some time after MachoAnalyzer.search_all_code() is called
CodeSearchCallback = Callable[['MachoAnalyzer', 'CodeSearch', List['CodeSearchResult']], None]

ANALYZER_SQL_SCHEMA = """
    CREATE TABLE function_boundaries(
        entry_point INT NOT NULL UNIQUE,
        end_address INT NOT NULL UNIQUE,
        CHECK (entry_point < end_address)
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
        classref INT,
        selref INT
    );

    CREATE TABLE named_callable_symbols(
        is_imported INT,
        address INT,
        symbol_name TEXT
    );
"""


def pairwise(iterable: Iterable[_T]) -> Iterable[Tuple[_T, _T]]:
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


class DisassemblyFailedError(Exception):
    """Raised when Capstone fails to disassemble a bytecode sequence.
    """


@dataclass
class CallerXRef:
    destination_addr: VirtualMemoryPointer
    caller_addr: VirtualMemoryPointer
    caller_func_start_address: VirtualMemoryPointer


@dataclass
class ObjcMsgSendXref(CallerXRef):
    classref: VirtualMemoryPointer
    selref: VirtualMemoryPointer


@dataclass
class CallableSymbol:
    """A locally-defined function or externally-defined imported function
    """
    address: VirtualMemoryPointer
    is_imported: bool
    symbol_name: str


@dataclass
class CodeSearchRequest:
    search: 'CodeSearch'
    callback: CodeSearchCallback


class MachoAnalyzer:
    # This class does expensive one-time cross-referencing operations
    # Therefore, we want only one instance to exist for any MachoBinary
    # Thus, the preferred interface for getting an instance of this class is MachoAnalyzer.get_analyzer(binary),
    # which utilizes this cache
    # XXX(PT): These references live to process termination, or until clear_cache() is called
    _ANALYZER_CACHE: Dict[MachoBinary, 'MachoAnalyzer'] = {}

    def __init__(self, binary: MachoBinary) -> None:
        from strongarm.objc import CodeSearch

        self.binary = binary
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        # Worker to parse dyld bytecode stream and extract dyld stub addresses to the DyldBoundSymbol they represent
        self._dyld_info_parser: Optional[DyldInfoParser] = None
        # Each __stubs function calls a single dyld stub address, which has a corresponding DyldBoundSymbol.
        # Map of each __stub function to the associated name of the DyldBoundSymbol
        self._imported_symbol_addresses_to_names: Dict[VirtualMemoryPointer, str] = {}

        self.crossref_helper = MachoStringTableHelper(binary)
        self.imported_symbols = self.crossref_helper.imported_symbols

        self.imp_stubs = MachoImpStubsParser(binary, self.cs).imp_stubs
        self._objc_helper: Optional[ObjcRuntimeDataParser] = None
        self._objc_method_list: List[ObjcMethodInfo] = []

        # For efficiency, API clients submit several CodeSearch's to be performed in a batch, instead of sequentially.
        # Iterating the binary's code is an expensive operation, and this allows us to do it just once.
        # This map is where we store the CodeSearch's that are waiting to be executed, and the
        # callbacks which should be invoked once results are found.
        self._queued_code_searches: List[CodeSearchRequest] = []

        # Use a temporary database to store cross-referenced data. This provides constant-time lookups for things like
        # finding all the calls to a particular function. In the past, CodeSearch would be used for the same purpose.
        self._has_computed_call_xrefs = False
        self._db_tempdir = pathlib.Path(tempfile.mkdtemp())
        self._db_path = self._db_tempdir / 'strongarm.db'
        self._db_handle = sqlite3.connect(self._db_path.as_posix())

        cursor = self._db_handle.executescript(ANALYZER_SQL_SCHEMA)

        with self._db_handle:
            cursor.close()

        self._build_callable_symbol_index()
        self._build_function_boundaries_index()

        # Done setting up, store this analyzer in class cache
        MachoAnalyzer._ANALYZER_CACHE[binary] = self

    def calls_to(self, address: VirtualMemoryPointer) -> List[CallerXRef]:
        """Return the list of code-locations within the binary which branch to the provided address.
        """
        if not self._has_computed_call_xrefs:
            self._build_branch_xrefs_index()

        c = self._db_handle.cursor()
        xrefs = c.execute(f'SELECT * from function_calls WHERE destination_address={int(address)}').fetchall()
        xrefs = [CallerXRef(x[0], x[1], x[2]) for x in xrefs]
        return xrefs

    def objc_calls_to(self,
                      objc_classrefs: List[VirtualMemoryPointer],
                      objc_selrefs: List[VirtualMemoryPointer],
                      requires_class_and_sel_found: bool) -> List[ObjcMsgSendXref]:
        """Return the list of code-locations in the binary which invoke _objc_msgSend with any of the provided
        classrefs or selrefs.

        If requires_class_and_sel_found is set, a call-site will only be yielded if one of the
        classrefs and one of the selrefs are messaged in the same call.
        Otherwise, a call-site will be yielded if one of the classrefs *or* one of the selrefs are messaged
        at a call site.
        """
        if not self._has_computed_call_xrefs:
            self._build_branch_xrefs_index()

        c = self._db_handle.cursor()

        # Do we require the classref and selref being messaged to both be messaged at the same call site?
        if not requires_class_and_sel_found:
            # The classref and selref don't both need to be present to yield a match
            objc_calls = c.execute(f'SELECT * from objc_msgSends '
                                   f'WHERE classref IN ({", ".join([str(int(x)) for x in objc_classrefs])})').fetchall()

            objc_calls += c.execute(f'SELECT * from objc_msgSends '
                                    f'WHERE selref IN ({", ".join([str(int(x)) for x in objc_selrefs])})').fetchall()

        else:
            # The classref and selref must both be present to yield a match
            objc_calls = c.execute(f'SELECT * from objc_msgSends '
                                   f'WHERE classref IN ({", ".join([str(int(x)) for x in objc_classrefs])}) '
                                   f'AND selref IN ({", ".join([str(int(x)) for x in objc_selrefs])})').fetchall()
        objc_calls = [ObjcMsgSendXref(x[0], x[1], x[2], x[3], x[4]) for x in objc_calls]
        return objc_calls

    def _compute_function_basic_blocks(
            self,
            entry_point: VirtualMemoryPointer,
            end_address: VirtualMemoryPointer,
    ) -> Iterable[Tuple[VirtualMemoryPointer, VirtualMemoryPointer]]:
        from strongarm.objc import ObjcUnconditionalBranchInstruction

        bytecode = self.binary.get_content_from_virtual_address(
            virtual_address=entry_point,
            size=end_address-entry_point,
        )
        # Grab a chunk of code within which to search for a function boundary
        disassembled_code = self.cs.disasm(bytecode, entry_point)

        # Find the basic blocks in this code chunk which are before the next entry point
        basic_block_starts = {entry_point}

        branch_mnemonic_to_dest_addr_op_idx = {
            **dict.fromkeys(ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS, 0),
            'cbz': 1,
            'cbnz': 1,
            'tbz': 2, 'tbnz': 2,
            # No destination address available for these mnemonics
            'br': None, 'ret': None,
        }
        for instr in disassembled_code:
            # Ensure we're looking at a branch instruction and pull out the destination address
            if instr.mnemonic not in branch_mnemonic_to_dest_addr_op_idx:
                continue

            dest_addr_op_idx = branch_mnemonic_to_dest_addr_op_idx[instr.mnemonic]
            if dest_addr_op_idx is None:
                # Special instruction which does not have a destination address we can resolve
                # "ret" always means EOF, "br" might always mean a local jump
                basic_block_starts.add(VirtualMemoryPointer(instr.address + instr.size))
            else:
                destination_address = instr.operands[dest_addr_op_idx].value.imm

                # Is it a branch to a local label within the function?
                if entry_point <= destination_address <= end_address:
                    basic_block_starts.add(VirtualMemoryPointer(instr.address + instr.size))
                    basic_block_starts.add(VirtualMemoryPointer(destination_address))
                    continue

                # Unconditional branches always end a basic block, even if jumping somewhere outside the function
                # (such as a tail call at the end of a code path)
                if instr.mnemonic == 'b':
                    basic_block_starts.add(VirtualMemoryPointer(instr.address + instr.size))

                # If a function contains a stack canary, its last instruction will be a branch-with-link to
                # __stack_chk_fail. A 'normal' branch-with-link would not be a sensible function-end, but a
                # stack canary is special because it's guaranteed to trigger an exception.
                # Handle this by assuming if we see a branch-with-link at the last instruction before the next entry-
                # point, it's probably a stack-canary (and thus another basic-block boundary).
                # We could make this heuristic stronger by parsing the instruction and checking if it jumps to the
                # __stack_chk_fail symbol, but this likely gets the job done most of the time.
                if instr.address == end_address - instr.size and instr.mnemonic == 'bl':
                    basic_block_starts.add(VirtualMemoryPointer(instr.address + instr.size))

        # Convert basic-block starts to [start, end] pairs
        return pairwise(sorted(basic_block_starts))

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
            end_address = max((bb_end for _, bb_end in basic_blocks))
            cursor.execute(f"INSERT INTO function_boundaries (entry_point, end_address) VALUES (?, ?)", (entry_point, end_address))

        with self._db_handle:
            cursor.close()

    def _build_branch_xrefs_index(self) -> None:
        from strongarm.objc import ObjcUnconditionalBranchInstruction

        if self._has_computed_call_xrefs:
            logging.error(f'Already computed xrefs, why was _build_branch_xrefs_index called again?')
            return

        start_time = time.time()
        logging.debug(f'{self.binary.path} computing call XRefs...')

        # Create the table which will store XRefs
        c = self._db_handle.cursor()

        # TODO(PT): Test this on a binary with no ObjcMsgSend
        objc_msgsend_symbol = self.callable_symbol_for_symbol_name('_objc_msgSend')
        if not objc_msgsend_symbol:
            raise NotImplementedError(f'{self.binary.path} has no imported _objc_msgSend symbol')
        objc_msgsend_addr = objc_msgsend_symbol.address

        # Some special selectors have a fast-path, _objc_opt_<selector>, that was added in iOS 13
        # The _objc_opt_* call is emitted instead of _objc_msgSend when the class has not re-implemented the selector.
        # In other words, these fast-paths are only used if the default NSObject implementation will be called
        # Found with: $ nm "/usr/lib/libobjc.A.dylib" | grep "objc_opt"
        objc_opt_function_names = [
            '_objc_opt_class',
            '_objc_opt_isKindOfClass',
            '_objc_opt_new',
            '_objc_opt_respondsToSelector',
            '_objc_opt_self'
        ]
        objc_opt_function_addrs: List[VirtualMemoryPointer] = []
        for func_name in objc_opt_function_names:
            # A callable symbol is only present if the function has been used in this binary
            sym = self.callable_symbol_for_symbol_name(func_name)
            if sym:
                objc_opt_function_addrs.append(sym.address)
            else:
                objc_opt_function_addrs.append(VirtualMemoryPointer(-1))
        objc_function_addrs = objc_opt_function_addrs + [objc_msgsend_addr]

        for entry_point, end_address in self.get_function_boundaries():
            function_size = end_address - entry_point

            # Iterate the disassembled code
            try:
                disassembled_code = self.disassemble_region(entry_point, function_size)
            except DisassemblyFailedError:
                # Skip code regions containing invalid bytecode
                continue

            function_branches = []
            objc_calls = []
            func_analyzer = None
            for instr in disassembled_code:
                # Is it an unconditional branch instruction?
                if (
                    instr.mnemonic
                    not in ObjcUnconditionalBranchInstruction.UNCONDITIONAL_BRANCH_MNEMONICS
                ):
                    continue

                # Record that the branch receiver has an XRef from this instruction
                destination_address = instr.operands[0].value.imm

                if destination_address in objc_function_addrs:
                    # Branch to function in the _objc_* family
                    from strongarm.objc import (
                        RegisterContentsType,
                        ObjcFunctionAnalyzer,
                    )

                    if not func_analyzer:
                        func_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
                            self.binary, entry_point
                        )

                    parsed_instr = ObjcUnconditionalBranchInstruction.parse_instruction(
                        func_analyzer, instr, patch_msgSend_destination=False
                    )

                    classref = 0x0
                    selref = 0x0

                    classref_reg = func_analyzer.get_register_contents_at_instruction(
                        "x0", parsed_instr
                    )
                    if classref_reg.type == RegisterContentsType.IMMEDIATE:
                        classref = classref_reg.value

                    if destination_address == objc_msgsend_addr:
                        # Branch to _objc_msgSend
                        selref_reg = func_analyzer.get_register_contents_at_instruction(
                            "x1", parsed_instr
                        )
                        if selref_reg.type == RegisterContentsType.IMMEDIATE:
                            selref = selref_reg.value

                        # If we're branching to a locally-implemented Objective-C method, set the `destination_addr`
                        # field to be the address of the local Objective-C entry point
                        # Additionally, in this case, include a 'function call' XRef. This enables getting all the
                        # callers to a locally-implemented Objective-C method *or* C function via the `calls_to` API.
                        # TODO(PT): Re-evaluate whether this is necessary or if the objc_calls_to() API is sufficient
                        selector = self.selector_for_selref(
                            VirtualMemoryPointer(selref)
                        )
                        if selector and selector.implementation:
                            destination_address = selector.implementation
                            function_call_xref = (
                                destination_address,
                                instr.address,
                                entry_point,
                            )
                            function_branches.append(function_call_xref)
                    else:
                        # Branch to _objc_opt*. Even though the specific _objc_opt_* function tells us which method is
                        # being invoked, we can't fill in the XRef's selref.
                        # Consider a call to _objc_opt_new(_OBJC_CLASS_$_MyClass). We see that the class is being sent
                        # @selector(new), but we can't fill in the `new` selref in the XRef because there is no
                        # guarantee that `new` will be in the binary's selref table unless it's used with
                        # _objc_msgSend elsewhere.
                        pass

                    objc_call = (
                        int(destination_address),
                        instr.address,
                        entry_point,
                        int(classref),
                        int(selref),
                    )
                    objc_calls.append(objc_call)

                else:
                    # Non-ObjC function call, i.e. a branch to any address other than _objc_msgSend/_objc_opt_*
                    # Could be an imported C function, a local C function, a block, etc.
                    xref = (destination_address, instr.address, entry_point)
                    function_branches.append(xref)

            # Add each branch in this source function to the SQLite db
            # TODO(PT): After discussion with Fede, we can condense this into one table.
            # Each entry could have an `is_objc` field. If its set, then the `classref` and `selref` fields may also
            # be filled in.
            # Additionally, if `is_local` is set *and* `is_objc` set, there may be some other field for the entry point
            # to the locally implemented ObjC method.
            for xref in function_branches:
                c.execute(
                    "INSERT INTO function_calls VALUES (?, ?, ?)", (xref[0], xref[1], xref[2])
                )
            for objc_call in objc_calls:
                c.execute(
                    "INSERT INTO objc_msgSends "
                    "VALUES (?, ?, ?, ?, ?)", (objc_call[0], objc_call[1], objc_call[2], objc_call[3], objc_call[4])
                )

        self._db_handle.commit()
        self._has_computed_call_xrefs = True
        end_time = time.time()
        logging.debug(f"Finding call xrefs took {end_time - start_time} seconds")

    @classmethod
    def clear_cache(cls) -> None:
        """Delete cached MachoAnalyzer's
        This can be used when you are finished analyzing a binary set and don't want to retain the cached data in memory
        """
        for binary, analyzer in cls._ANALYZER_CACHE.items():
            logging.debug(f"Deleting db {analyzer._db_path}...")
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
        """Get a cached analyzer for a given MachoBinary
        """
        if binary in cls._ANALYZER_CACHE:
            # There exists a MachoAnalyzer for this binary - use it instead of making a new one
            return cls._ANALYZER_CACHE[binary]
        return MachoAnalyzer(binary)

    def method_info_for_entry_point(
        self, entry_point: VirtualMemoryPointer
    ) -> Optional["ObjcMethodInfo"]:
        # TODO(PT): This should return any symbol name, not just Obj-C methods
        from strongarm.objc.objc_analyzer import ObjcMethodInfo

        for objc_cls in self.objc_classes():
            for sel in objc_cls.selectors:
                if sel.implementation == entry_point:
                    return ObjcMethodInfo(objc_cls, sel, sel.implementation)
        return None

    def objc_classes(self) -> List[ObjcClass]:
        """Return the List of classes and categories implemented within the binary
        """
        return self.objc_helper.classes

    def objc_categories(self) -> List[ObjcCategory]:
        """Return the List of categories implemented within the app
        """
        all_classes = self.objc_classes()
        categories: List[ObjcCategory] = [c for c in all_classes if isinstance(c, ObjcCategory)]
        return categories

    def get_conformed_protocols(self) -> List[ObjcProtocol]:
        """Return the List of protocols to which code within the binary conforms
        """
        return self.objc_helper.protocols

    @property
    def dyld_info_parser(self) -> DyldInfoParser:
        if not self._dyld_info_parser:
            self._dyld_info_parser = DyldInfoParser(self.binary)
        return self._dyld_info_parser

    @property
    def dyld_bound_symbols(self) -> Dict[VirtualMemoryPointer, DyldBoundSymbol]:
        """Return a Dict of each imported dyld stub to the corresponding symbol to be bound at runtime.
        """
        return self.dyld_info_parser.dyld_stubs_to_symbols

    @property
    def imp_stubs_to_symbol_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of callable implementation stubs to the names of the imported symbols they correspond to.
        """
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
                name = f'unnamed_stub_{unnamed_stub_count}'
                unnamed_stub_count += 1
                symbol_name_map[stub.destination] = name

        self._imported_symbol_addresses_to_names = symbol_name_map
        return symbol_name_map

    @property
    def imported_symbols_to_symbol_names(self) -> Dict[VirtualMemoryPointer, str]:
        """Return a Dict of imported symbol pointers to their names.
        These symbols are not necessarily callable, but may rather be imported classes, for example.
        Inverse of MachoAnalyzer.imported_symbol_names_to_pointers()
        """
        return {addr: x.name for addr, x in self.dyld_bound_symbols.items()}

    @property
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

    @property
    def exported_symbol_names_to_pointers(self) -> Dict[str, VirtualMemoryPointer]:
        """Return a Dict of exported symbol names to pointers to their definitions.
        Inverse of MachoAnalyzer.exported_symbols_to_symbol_names()
        """
        return {y: x for x, y in self.exported_symbol_pointers_to_names.items()}

    def exported_symbol_name_for_address(self, address: VirtualMemoryPointer) -> Optional[str]:
        """Return the symbol name for the provided address, or None if the address is not a named exported symbol.
        """
        if address in self.exported_symbol_pointers_to_names:
            return self.exported_symbol_pointers_to_names[address]
        return None

    def symbol_name_for_branch_destination(self, branch_address: VirtualMemoryPointer) -> str:
        """Get the associated symbol name for a given branch destination
        """
        if branch_address in self.imp_stubs_to_symbol_names:
            return self.imp_stubs_to_symbol_names[branch_address]
        raise RuntimeError(f'Unknown branch destination {hex(branch_address)}. Is this a local branch?')

    def disassemble_region(self, start_address: VirtualMemoryPointer, size: int) -> List[CsInsn]:
        """Disassemble the executable code in a given region into a list of CsInsn objects
        """
        func_str = bytes(self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size))
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        if not len(instructions):
            raise DisassemblyFailedError(f'Failed to disassemble code at {hex(start_address)}:{hex(size)}')
        return instructions

    def get_function_instructions(self, start_address: VirtualMemoryPointer) -> List[CsInsn]:
        """Get a list of disassembled instructions for the function beginning at start_address
        """
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
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        return self.objc_helper.get_method_imp_addresses(selector)

    def get_imps_for_sel(self, selector: str) -> List['ObjcFunctionAnalyzer']:
        """Retrieve a list of the disassembled function data for every implementation of a provided selector
        Args:
            selector: The selector name who's implementations should be found

        Returns:
            A list of ObjcFunctionAnalyzers corresponding to each found implementation of the provided selector.
        """
        from strongarm.objc import ObjcFunctionAnalyzer     # type: ignore

        implementation_analyzers = []
        imp_addresses = self.get_method_imp_addresses(selector)
        for imp_start in imp_addresses:
            imp_instructions = self.get_function_instructions(imp_start)
            function_analyzer = ObjcFunctionAnalyzer(self.binary, imp_instructions)
            implementation_analyzers.append(function_analyzer)
        return implementation_analyzers

    def get_objc_methods(self) -> List['ObjcMethodInfo']:
        """Get a List of ObjcMethodInfo's representing all ObjC methods implemented in the Mach-O.
        """
        from strongarm.objc import ObjcMethodInfo   # type: ignore
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
            "SELECT end_address FROM function_boundaries WHERE entry_point = ?",
            (entry_point,)
        )

        with closing(cursor):
            results = cursor.fetchone()

        if results is None:
            return None

        return VirtualMemoryPointer(results[0])

    def queue_code_search(self, code_search: 'CodeSearch', callback: CodeSearchCallback) -> None:
        """Enqueue a CodeSearch. It will be ran when `search_all_code` runs. `callback` will then be invoked.
        The search space is all known Objective-C entry points within the binary.

        A CodeSearch describes criteria for matching code. A CodeSearchResult encapsulates a CPU instruction and its
        containing source function which matches the criteria of the search.

        Once the CodeSearch has been run over the binary, the `callback` will be invoked, passing the relevant
        info about the discovered code.
        """
        # logging.info(f'{self.binary.path.name} enqueuing CodeSearch {code_search}. Will invoke {callback}')
        self._queued_code_searches.append(CodeSearchRequest(code_search, callback))

    def search_all_code(self, display_progress: bool = True) -> None:
        """Iterate every function in the binary, and run each pending CodeSearch over them.
        The search space is all known entry points within the binary.

        A CodeSearch describes criteria for matching code. A CodeSearchResult encapsulates a CPU instruction and its
        containing source function which matches the criteria of the search.

        For each search which is executed, this method will invoke the CodeSearchCallback provided when the search
        was requested, with the List of CodeSearchResult's which were found.
        """
        from strongarm.objc import ObjcFunctionAnalyzer     # type: ignore

        # If there are no queued code searches, we have nothing to do
        queued_searches = self._queued_code_searches
        if not len(queued_searches):
            return

        logging.info(f'Running {len(queued_searches)} code searches on {self.binary.path.name}')

        entry_point_list = self.get_functions()
        search_results: List[List[CodeSearchResult]] = [[] for _ in range(len(queued_searches))]

        # Searching all code can be a time-consumptive operation. Provide UI feedback on the progress.
        # This displays a progress bar to stdout. The progress bar will be erased when the context manager exits.
        code_size = self.binary.slice_filesize / 1024 / 1024
        with ConsoleProgressBar(prefix=f'{self.binary.path.stem} CodeSearch {int(code_size)}mb', enabled=display_progress) as progress_bar:

            # Build analyzers for function entry points.
            for i, entry_address in enumerate(entry_point_list):
                try:
                    # Try to find a method-info with a matching address
                    matched_method_info = None
                    for method_info in self.get_objc_methods():
                        if method_info.imp_addr == entry_address:
                            matched_method_info = method_info
                            break
                    if matched_method_info:
                        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_method(self.binary, matched_method_info)
                    else:
                        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(self.binary, entry_address)
                except DisassemblyFailedError as e:
                    logging.error(f'Failed to disassemble function {hex(entry_address)}: {str(e)}')
                    continue

                # Run every code search on this function and record their respective results
                for idx, request in enumerate(queued_searches):
                    search_results[idx] += function_analyzer.search_code(request.search)

                progress_bar.set_progress(i / len(entry_point_list))

        # Invoke every callback with their respective search results
        for request, results in zip(queued_searches, search_results):
            # Remove the CodeSearch from the waiting queue before dispatching the callback
            # This ensures that if the callback runs another CodeSearch, the queue will be in the right state.
            self._queued_code_searches.remove(request)
            try:
                request.callback(self, request.search, results)     # type: ignore
            except Exception as e:
                logging.exception(f'CodeSearch callback raised {type(e)}: {e}')
                continue

        # We've completed all of the waiting code searches. Drain the queue
        self._queued_code_searches.clear()

    def class_name_for_class_pointer(self, classref: VirtualMemoryPointer) -> Optional[str]:
        """Given a classref, return the name of the class.
        This method will handle classes implemented within the binary and imported classes.
        """
        if classref in self.imported_symbols_to_symbol_names:
            # imported class
            return self.imported_symbols_to_symbol_names[classref]

        # otherwise, the class is implemented within a binary and we have an ObjcClass for it
        try:
            class_location = self.binary.read_word(classref)
        except InvalidAddressError:
            # invalid classref
            return None

        local_class = [x for x in self.objc_classes() if x.raw_struct.binary_offset == class_location]
        if len(local_class):
            return local_class[0].name

        # invalid classref
        return None

    def classref_for_class_name(self, class_name: str) -> Optional[VirtualMemoryPointer]:
        """Given a class name, try to find a classref for it.
        """
        classrefs = [addr for addr, name in self.imported_symbols_to_symbol_names.items() if name == class_name]
        if len(classrefs):
            return classrefs[0]

        # TODO(PT): this is expensive! We should do one analysis step of __objc_classrefs and create a map.
        classref_locations, classref_destinations = self.binary.read_pointer_section('__objc_classrefs')

        # is it a local class?
        class_locations = [x.raw_struct.binary_offset for x in self.objc_classes() if x.name == class_name]
        if not len(class_locations):
            # unknown class name
            return None
        class_location = VirtualMemoryPointer(class_locations[0])

        if class_location not in classref_destinations:
            # unknown class name
            return None

        classref_index = classref_destinations.index(class_location)
        return classref_locations[classref_index]

    def selref_for_selector_name(self, selector_name: str) -> Optional[VirtualMemoryPointer]:
        return self.objc_helper.selref_for_selector_name(selector_name)

    def strings(self) -> Set[str]:
        """Return the list of strings in the binary's __cstring section.
        """
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        # This method should cache its result.
        strings_section = self.binary.section_with_name('__cstring', '__TEXT')
        if not strings_section:
            return set()

        strings_content = strings_section.content

        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(strings_content)
        transformed_strings = MachoStringTableHelper.transform_string_section(string_table)
        return set((x.full_string for x in transformed_strings.values()))

    def _stringref_for_cstring(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref in __cstrings for a provided C string.
        If the string is not present in the __cstrings section, this method returns None.
        """
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        strings_section = self.binary.section_with_name('__cstring', '__TEXT')
        if not strings_section:
            return None

        strings_base = strings_section.address
        strings_content = strings_section.content

        # split into characters (string table is packed and each entry is terminated by a null character)
        string_table = list(strings_content)
        transformed_strings = MachoStringTableHelper.transform_string_section(string_table)
        for idx, entry in transformed_strings.items():
            if entry.full_string == string:
                # found the string we're looking for
                # the address is the base of __cstring plus the index of the entry
                stringref_address = strings_base + idx
                return stringref_address

        # didn't find the string the user requested
        return None

    def _stringref_for_cfstring(self, string: str) -> Optional[VirtualMemoryPointer]:
        """Try to find the stringref in __cfstrings for a provided Objective-C string literal.
        If the string is not present in the __cfstrings section, this method returns None.
        """
        # TODO(PT): This is SLOW and WASTEFUL!!!
        # These transformations should be done ONCE on initial analysis!
        cfstrings_section = self.binary.section_with_name('__cfstring', '__DATA')
        if not cfstrings_section:
            return None

        sizeof_cfstring = sizeof(CFString64) if self.binary.is_64bit else sizeof(CFString32)
        cfstrings_base = cfstrings_section.address

        cfstrings_count = int((cfstrings_section.end_address - cfstrings_section.address) / sizeof_cfstring)
        for i in range(cfstrings_count):
            cfstring_addr = cfstrings_base + (i * sizeof_cfstring)
            cfstring = self.binary.read_struct(cfstring_addr, CFStringStruct, virtual=True)

            # check if this is the string the user requested
            string_address = cfstring.literal
            if self.binary.read_string_at_address(string_address) == string:
                return VirtualMemoryPointer(cfstring_addr)

        return None

    def stringref_for_string(self, string: str) -> Optional[int]:
        """Try to find the stringref for a provided string.
        If the string is not present in the binary, this method returns None.

        If you are looking for a C string, pass the string with no additional formatting.
        If you are looking for an Objective-C string literal (CFStringRef), enclose your string in @"".
        """
        is_cfstring = False
        if string.startswith('@"'):
            if not string.endswith('"'):
                raise RuntimeError(f'incorrectly formatted ObjC string literal {string}')

            is_cfstring = True
            # trim the @" prefix and the " suffix
            string = string[2:-1]

        if is_cfstring:
            return self._stringref_for_cfstring(string)
        return self._stringref_for_cstring(string)

    @functools.lru_cache(64)
    def callable_symbol_for_address(self,
                                    branch_destination: VirtualMemoryPointer) -> Optional[CallableSymbol]:
        """Retrieve information about a callable branch destination.
        It's the caller's responsibility to provide a valid branch destination with a symbol associated with it.
        """
        c = self._db_handle.cursor()
        symbols = c.execute(f'SELECT * from named_callable_symbols WHERE address={branch_destination}').fetchall()
        if not len(symbols):
            return None
        assert len(symbols) == 1, f'Found more than 1 symbol at {branch_destination}?'
        symbol_data = symbols[0]

        return CallableSymbol(is_imported=bool(symbol_data[0]),
                              address=VirtualMemoryPointer(symbol_data[1]),
                              symbol_name=symbol_data[2])

    def callable_symbol_for_symbol_name(self,
                                        symbol_name: str) -> Optional[CallableSymbol]:
        """Retrieve information about a name within the imported or exported symbols tables.
        It's the caller's responsibility to provide a valid callable symbol name.
        """
        c = self._db_handle.cursor()
        symbols = c.execute(f"SELECT * from named_callable_symbols WHERE symbol_name='{symbol_name}'").fetchall()
        if not len(symbols):
            return None
        assert len(symbols) == 1, f'Found more than 1 symbol named {symbol_name}?'
        symbol_data = symbols[0]

        return CallableSymbol(is_imported=bool(symbol_data[0]),
                              address=VirtualMemoryPointer(symbol_data[1]),
                              symbol_name=symbol_data[2])

    def _build_callable_symbol_index(self) -> None:
        """Build a database index for every callable symbol to symbol name.
        This index includes both imported and exported symbols.
        """
        c = self._db_handle.cursor()

        # Process __imp_stubs
        imported_bound_symbols = self.imp_stubs_to_symbol_names
        for imp_stub_addr, symbol_name in imported_bound_symbols.items():
            c.execute("INSERT INTO named_callable_symbols VALUES (1, ?, ?)", (imp_stub_addr, symbol_name))

        # Process the symbols defined in the binary
        for callable_addr, symbol_name in self.exported_symbol_pointers_to_names.items():
            c.execute("INSERT INTO named_callable_symbols VALUES (0, ?, ?)", (callable_addr, symbol_name))

        self._db_handle.commit()
