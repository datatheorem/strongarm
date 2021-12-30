from ctypes import c_int8, c_int16, c_long, c_uint16, c_uint32, c_uint64, sizeof
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple, Type

from strongarm.logger import strongarm_logger

from .arch_independent_structs import (
    ArchIndependentStructure,
    DylibCommandStruct,
    MachoDyldChainedFixupsHeader,
    MachoDyldChainedImport,
    MachoDyldChainedImportAddend64,
    MachoDyldChainedPtr64Bind,
    MachoDyldChainedPtr64Rebase,
    MachoDyldChainedStartsInImage,
    MachoDyldChainedStartsInSegment,
)
from .macho_binary import MachoBinary
from .macho_definitions import MachoDyldChainedImportFormat, StaticFilePointer, VirtualMemoryPointer

logger = strongarm_logger.getChild(__file__)


class BindOpcode(IntEnum):
    BIND_OPCODE_DONE = 0x00
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
    BIND_OPCODE_SET_TYPE_IMM = 0x50
    BIND_OPCODE_SET_ADDEND_SLEB = 0x60
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
    BIND_OPCODE_ADD_ADDR_ULEB = 0x80
    BIND_OPCODE_DO_BIND = 0x90
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
    BIND_OPCODE_THREADED = 0xD0

    # The immediate will contain a sub-opcode for BIND_OPCODE_THREADED
    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x00
    BIND_SUBOPCODE_THREADED_APPLY = 0x01


@dataclass
class DyldBoundSymbol:
    binary: MachoBinary
    address: VirtualMemoryPointer
    library_ordinal: int
    name: str
    dylib: Optional[DylibCommandStruct] = field(init=False)

    def __post_init__(self) -> None:
        self.dylib = self.binary.dylib_for_library_ordinal(self.library_ordinal)


class DyldChainedPointerMagics(IntEnum):
    """Special values in the chained pointer info structs that influence parsing."""

    # No fixups in this page
    DYLD_CHAINED_PTR_NO_STARTS_IN_PAGE = 0xFFFF
    # Multiple chain starts in this page
    DYLD_CHAINED_PTR_START_MULTI = 0x8000


class DyldInfoParser:
    """Wraps up the logic to parse __LINKEDIT data so that we can make sense of rebased pointers and bound dyld symbols.
    On < iOS 15 binaries:
        Parses the dyld bytecode stream and extract dyld bound addresses to the DyldBoundSymbol they represent
    On >= iOS 15 binaries:
        Parses the chained fixup pointers and generates a map of rebased pointer locations to their values
        Also creates the map of dyld import addresses to the corresponding DyldBoundSymbol
    """

    @staticmethod
    def _compute_library_ordinal_for_chained_import_type(lib_value: int) -> int:
        if lib_value > 0xF0:
            # Cast to int8
            return c_int8(lib_value).value
        return lib_value

    @staticmethod
    def _compute_library_ordinal_for_chained_import_addend64_type(lib_value: int) -> int:
        if lib_value > 0xFFF0:
            # Cast to int16
            return c_int16(lib_value).value
        return lib_value

    @staticmethod
    def _read_chained_imports(
        binary: MachoBinary,
        chained_fixups_data_start: StaticFilePointer,
        chained_fixups_header: MachoDyldChainedFixupsHeader,
    ) -> List[DyldBoundSymbol]:
        """Parse the chained imports table in __LINKEDIT into a list of DyldBoundSymbols."""
        chained_import_addr = chained_fixups_data_start + chained_fixups_header.imports_offset
        symbols_start_addr = chained_fixups_data_start + chained_fixups_header.symbols_offset
        dyld_bound_symbols: List[DyldBoundSymbol] = []

        # Different imports formats have different layouts and parsing rules
        imports_format = chained_fixups_header.imports_format

        chained_import_struct: Type[ArchIndependentStructure]
        if imports_format == MachoDyldChainedImportFormat.DYLD_CHAINED_IMPORT:
            chained_import_struct = MachoDyldChainedImport
            compute_library_ordinal = DyldInfoParser._compute_library_ordinal_for_chained_import_type

        elif imports_format == MachoDyldChainedImportFormat.DYLD_CHAINED_IMPORT_ADDEND64:
            # net.salkosuo.clp.ttmsg includes ADDEND64 imports, but the binary is too big to include in the test tree.
            # TODO(PT): This same binary contains imports with an ordinal of BIND_SPECIAL_DYLIB_WEAK_LOOKUP (-3),
            # which appears to be imports for locally defined symbols (?!)
            chained_import_struct = MachoDyldChainedImportAddend64
            compute_library_ordinal = DyldInfoParser._compute_library_ordinal_for_chained_import_addend64_type

        else:
            raise ValueError(f"Unsupported chained import pointer format: {imports_format}")

        for i in range(chained_fixups_header.imports_count):
            chained_import = binary.read_struct(chained_import_addr, chained_import_struct)
            symbol_addr = symbols_start_addr + chained_import.name_offset
            symbol_string = binary.get_full_string_from_start_address(symbol_addr, virtual=False)

            if not symbol_string:
                raise ValueError(f"Should not happen: Failed to read a string for chained import {chained_import_addr}")

            dyld_bound_symbols.append(
                DyldBoundSymbol(
                    binary=binary,
                    address=chained_import_addr,
                    library_ordinal=compute_library_ordinal(chained_import.lib_ordinal),
                    name=symbol_string,
                )
            )
            chained_import_addr += chained_import.sizeof
        return dyld_bound_symbols

    @staticmethod
    def parse_chained_fixups(
        binary: MachoBinary,
    ) -> Tuple[Dict[VirtualMemoryPointer, VirtualMemoryPointer], Dict[VirtualMemoryPointer, DyldBoundSymbol]]:
        """Parses the chained fixup pointer data in __LINKEDIT
        Returns:
            Tuple[
                Dict[address containing a pointer needing to be rebased, destination assuming the stated virtual base],
                Dict[address containing a pointer that needs to be bound at load time, corresponding DyldBoundSymbol],
            ]
        """
        if not binary._dyld_chained_fixups:
            raise ValueError("This method expects the provided binary to contain chained fixup pointers")

        chained_fixups_data_start = binary._dyld_chained_fixups.dataoff
        chained_fixups_header = binary.read_struct(chained_fixups_data_start, MachoDyldChainedFixupsHeader)

        # First, read the table of bound symbols that are present anywhere within the binary
        # Bound fixup pointers will encode an index ("ordinal") into this table to state the symbol they're referring to
        dyld_bound_symbols = DyldInfoParser._read_chained_imports(
            binary, chained_fixups_data_start, chained_fixups_header
        )
        logger.debug(f"dyld chained imports table contains {len(dyld_bound_symbols)} symbols")

        # By parsing each chain of fixup pointers in the binary, we'll populate this map of addresses -> binds
        dyld_bound_addresses_to_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}

        # Next, parse the structure directly after the chained fixups header.
        # This structure gives the locations of each chain of fixup pointers within each binary segment.
        #
        # The first word of this structure provides the number of uint32_t offsets to follow
        # Each offset is added to the base address of this structure to provide the address of a
        # `struct dyld_chained_starts_in_segment`.
        chained_starts_in_image_off = chained_fixups_data_start + chained_fixups_header.starts_offset
        chained_starts_in_image = binary.read_struct(chained_starts_in_image_off, MachoDyldChainedStartsInImage)
        chained_starts_in_seg_offsets_base = chained_starts_in_image_off + chained_starts_in_image.sizeof

        # While processing rebases, we'll need to overwrite the rebase fixup pointer with the internal pointer it's
        # referring to. Since we'll be making many such writes, use a MachoBinaryWriter to do them more efficiently.
        rebases: Dict[VirtualMemoryPointer, VirtualMemoryPointer] = {}
        for segment_idx in range(chained_starts_in_image.seg_count):
            # Read entry of variable-length array of words. See comment in MachoDyldChainedStartsInImageRaw
            starts_in_seg_struct_offset = binary.read_word(
                chained_starts_in_seg_offsets_base + (segment_idx * sizeof(c_uint32)),
                virtual=False,
                word_type=c_uint32,
            )
            # Skip segments that don't contain chains
            if starts_in_seg_struct_offset == 0:
                continue

            starts_in_seg_addr = chained_starts_in_image_off + starts_in_seg_struct_offset
            chained_starts_in_seg = binary.read_struct(starts_in_seg_addr, MachoDyldChainedStartsInSegment)
            logger.debug(
                f"ChainedStartsInSegment\tsegment {segment_idx}\t"
                f"pointer_fmt {chained_starts_in_seg.pointer_format}\tpage count {chained_starts_in_seg.page_count}"
            )

            offset_in_page_start = starts_in_seg_addr + chained_starts_in_seg.sizeof
            for page_idx in range(chained_starts_in_seg.page_count):
                # Read entry of variable-length array of words. See comment in MachoDyldChainedStartsInSegmentRaw
                offset_in_page = binary.read_word(
                    offset_in_page_start + (page_idx * sizeof(c_uint16)), virtual=False, word_type=c_uint16
                )

                # Some offset_in_page values have special meaning
                if offset_in_page == DyldChainedPointerMagics.DYLD_CHAINED_PTR_NO_STARTS_IN_PAGE:
                    logger.debug(f"Skipping PageIdx {page_idx} with no chain starts")
                    continue
                elif offset_in_page == DyldChainedPointerMagics.DYLD_CHAINED_PTR_START_MULTI:
                    raise NotImplementedError("Encountered page with multiple chain starts")

                logger.debug(f"\tPageIdx {page_idx}, offset in page {hex(offset_in_page)}")

                chain_base = (
                    chained_starts_in_seg.segment_offset + (page_idx * chained_starts_in_seg.page_size) + offset_in_page
                )
                # Process this chain of fixup pointers
                rebases_in_chain, bound_addresses_in_chain = DyldInfoParser._process_fixup_pointer_chain(
                    binary, dyld_bound_symbols, chain_base
                )
                rebases.update(rebases_in_chain)
                dyld_bound_addresses_to_symbols.update(bound_addresses_in_chain)

        return rebases, dyld_bound_addresses_to_symbols

    @staticmethod
    def _process_fixup_pointer_chain(
        binary: MachoBinary, dyld_bound_symbols_table: List[DyldBoundSymbol], chain_base: VirtualMemoryPointer
    ) -> Tuple[Dict[VirtualMemoryPointer, VirtualMemoryPointer], Dict[VirtualMemoryPointer, DyldBoundSymbol]]:
        rebased_pointers: Dict[VirtualMemoryPointer, VirtualMemoryPointer] = {}
        dyld_bound_addresses_to_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}
        virtual_base = binary.get_virtual_base()
        # As each fixup pointer will tell us whether there are any more to follow, loop forever
        # XXX(PT): Impose an upper bound on this loop, just in case
        for _ in range(10000):
            chained_rebase_ptr = binary.read_struct(chain_base, MachoDyldChainedPtr64Rebase)
            # Rebase or bind?
            if chained_rebase_ptr.bind == 1:
                # Bind. Keep track that there is an imported symbol bind here
                chained_bind_ptr = binary.read_struct(chain_base, MachoDyldChainedPtr64Bind)
                bound_symbol = dyld_bound_symbols_table[chained_bind_ptr.ordinal]
                logger.debug(
                    f"\t\t{hex(chain_base)}: BIND\tordinal {chained_bind_ptr.ordinal}\t"
                    f"addend {chained_bind_ptr.addend}\treserved {chained_bind_ptr.reserved}\t"
                    f"next {chained_bind_ptr.next}\tsymbol {bound_symbol.name}\t\t"
                    f"dylib {binary.dylib_name_for_library_ordinal(bound_symbol.library_ordinal)}"
                )
                dyld_bound_addresses_to_symbols[chain_base + virtual_base] = bound_symbol
                chain_base += chained_bind_ptr.next * 4
            else:
                # Rebase. Overwrite the fixup pointer with the internal binary pointer it refers to
                # Rebase. Keep track that there's a rebased pointer here
                chained_ptr_raw = binary.read_word(chain_base, word_type=c_uint64, virtual=False)
                logger.debug(
                    f"\t\t{hex(chain_base)}: DyldChainedPtr64Rebase(raw: {hex(chained_ptr_raw)}) "
                    f"target={StaticFilePointer(chained_rebase_ptr.target)}"
                )
                rebased_pointers[VirtualMemoryPointer(chain_base + virtual_base)] = VirtualMemoryPointer(
                    chained_rebase_ptr.target + virtual_base
                )
                chain_base += chained_rebase_ptr.next * 4

            # Reached the end of the chain?
            if chained_rebase_ptr.next == 0:
                break
        else:
            raise ValueError("Failed to find end of fixup pointer chain")

        return rebased_pointers, dyld_bound_addresses_to_symbols

    @staticmethod
    def read_uleb(data: bytearray, offset: int) -> Tuple[int, int]:
        byte = data[offset]
        offset += 1

        result = byte & 0x7F
        shift = 7
        while byte & 0x80:
            byte = data[offset]
            result |= (byte & 0x7F) << shift
            shift += 7
            offset += 1

        # attempt to catch signed values and convert them if encountered
        if result > 0x100000000:
            result = c_long(result).value

        return result, offset

    @staticmethod
    def parse_dyld_info(binary: MachoBinary) -> Dict[VirtualMemoryPointer, DyldBoundSymbol]:
        if not binary.dyld_info:
            raise ValueError("This method expects the provided binary to contain LC_DYLD_INFO")

        return {
            **DyldInfoParser._parse_dyld_bytestream(binary, binary.dyld_info.bind_off, binary.dyld_info.bind_size),
            **DyldInfoParser._parse_dyld_bytestream(
                binary, binary.dyld_info.lazy_bind_off, binary.dyld_info.lazy_bind_size
            ),
        }

    @staticmethod
    def _parse_dyld_bytestream(
        binary: MachoBinary, file_offset: StaticFilePointer, size: int
    ) -> Dict[VirtualMemoryPointer, DyldBoundSymbol]:
        from ctypes import sizeof

        dyld_stubs_to_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}

        binding_info = binary.get_bytes(file_offset, size)
        pointer_size = sizeof(binary.platform_word_type)

        index = 0
        name_bytes: bytearray
        segment_index = 0
        segment_offset = 0
        library_ordinal = 0
        target_table_count = 0

        def commit_stub() -> None:
            segment_command = binary.segment_for_index(segment_index)
            segment_start = segment_command.vmaddr
            stub_addr = VirtualMemoryPointer(segment_start + segment_offset)
            name = name_bytes.decode("utf-8")

            symbol = DyldBoundSymbol(binary, stub_addr, library_ordinal, name)
            dyld_stubs_to_symbols[stub_addr] = symbol

        while index != len(binding_info):
            byte = binding_info[index]
            opcode = byte & 0xF0
            immediate = byte & 0x0F
            index += 1

            if opcode == BindOpcode.BIND_OPCODE_DONE:
                pass
            elif opcode == BindOpcode.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                library_ordinal = immediate
            elif opcode == BindOpcode.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                library_ordinal, index = DyldInfoParser.read_uleb(binding_info, index)
            elif opcode == BindOpcode.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                library_ordinal = -immediate
            elif opcode == BindOpcode.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                name_end = binding_info.find(b"\0", index)
                name_bytes = binding_info[index:name_end]
                index = name_end
            elif opcode == BindOpcode.BIND_OPCODE_SET_TYPE_IMM:
                pass
            elif opcode == BindOpcode.BIND_OPCODE_SET_ADDEND_SLEB:
                _, index = DyldInfoParser.read_uleb(binding_info, index)
            elif opcode == BindOpcode.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment_index = immediate
                segment_offset, index = DyldInfoParser.read_uleb(binding_info, index)
            elif opcode == BindOpcode.BIND_OPCODE_ADD_ADDR_ULEB:
                addend, index = DyldInfoParser.read_uleb(binding_info, index)
                segment_offset += addend
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND:
                commit_stub()
                segment_offset += pointer_size
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                commit_stub()
                segment_offset += pointer_size

                addend, index = DyldInfoParser.read_uleb(binding_info, index)
                segment_offset += addend
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                commit_stub()
                # I think the format is <immediate>, <repeat times>
                # So, we always reserve at least one pointer, then skip the 'repeat' count pointers.
                segment_offset += pointer_size + (immediate * pointer_size)
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count, index = DyldInfoParser.read_uleb(binding_info, index)
                skip, index = DyldInfoParser.read_uleb(binding_info, index)
                for i in range(count):
                    commit_stub()
                    segment_offset += pointer_size + skip
            elif opcode == BindOpcode.BIND_OPCODE_THREADED:
                if immediate == BindOpcode.BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
                    target_table_count, index = DyldInfoParser.read_uleb(binding_info, index)
                    if target_table_count >= (pow(2, 16) - 1):
                        raise ValueError("Invalid target_table_count")
                elif immediate == BindOpcode.BIND_SUBOPCODE_THREADED_APPLY:
                    # TODO(PT): Parse a fixup pointer chain here
                    pass
                else:
                    raise ValueError(f"Invalid threaded sub-opcode: {immediate}")
            else:
                logger.error(f"unknown dyld bind opcode {hex(opcode)}, immediate {hex(immediate)}")

        return dyld_stubs_to_symbols
