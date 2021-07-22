from ctypes import sizeof, c_uint32, c_uint16, c_uint64, c_long
import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Tuple, List, Optional

from .arch_independent_structs import MachoDyldChainedFixupsHeader, MachoDyldChainedImport, \
    MachoDyldChainedStartsInImage, MachoDyldChainedStartsInSegment, MachoDyldChainedPtr64Rebase, \
    MachoDyldChainedPtr64Bind, DylibCommandStruct
from .macho_binary import MachoBinary
from .macho_binary_writer import MachoBinaryWriter
from .macho_definitions import StaticFilePointer, VirtualMemoryPointer


class BindOpcode(IntEnum):
    BIND_OPCODE_DONE = 0
    BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 1
    BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 2
    BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 3
    BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 4
    BIND_OPCODE_SET_TYPE_IMM = 5
    BIND_OPCODE_SET_ADDEND_SLEB = 6
    BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 7
    BIND_OPCODE_ADD_ADDR_ULEB = 8
    BIND_OPCODE_DO_BIND = 9
    BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 10
    BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 11
    BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 12


@dataclass
class DyldBoundSymbol:
    binary: MachoBinary
    address: VirtualMemoryPointer
    library_ordinal: int
    name: str
    dylib: Optional[DylibCommandStruct] = field(init=False)

    def __post_init__(self) -> None:
        self.dylib = self.binary.dylib_for_library_ordinal(self.library_ordinal)


class DyldInfoParser:
    """Wraps up the logic to parse __LINKEDIT data so that we can make sense of rebased and bound dyld symbols.
    On < iOS 15 binaries:
        Parses the dyld bytecode stream and extract dyld stub addresses to the DyldBoundSymbol they represent
    On >= iOS 15 binaries:
        Parses the chained fixup pointers and rewrites the underlying binary memory to contain the fixed-up pointers
        Also creates the map of dyld import addresses to the corresponding DyldBoundSymbol
    """
    @staticmethod
    def preprocess_chained_fixups(binary: MachoBinary) -> Tuple[Dict[VirtualMemoryPointer, DyldBoundSymbol], bytes]:
        if not binary._dyld_chained_fixups:
            raise ValueError(f'This method expects the provided binary to contain chained fixup pointers')

        chained_fixups_data_start = binary._dyld_chained_fixups.dataoff
        header = binary.read_struct(chained_fixups_data_start, MachoDyldChainedFixupsHeader)

        chained_import_addr = chained_fixups_data_start + header.imports_offset
        symbols_start_addr = chained_fixups_data_start + header.symbols_offset
        dyld_bound_symbols: List[DyldBoundSymbol] = []
        for i in range(header.imports_count):
            chained_import = binary.read_struct(chained_import_addr, MachoDyldChainedImport)
            symbol_addr = symbols_start_addr + chained_import.name_offset
            symbol_string = binary.get_full_string_from_start_address(symbol_addr, virtual=False)
            print(f'Chained import\tidx {i}\taddr {hex(chained_import_addr)}\tlib_ordinal {chained_import.lib_ordinal}\tweak_imp {chained_import.weak_import}\tsym {symbol_string}')
            dyld_bound_symbols.append(DyldBoundSymbol(
                binary=binary,
                address=chained_import_addr,
                library_ordinal=chained_import.lib_ordinal,
                name=symbol_string,
            ))

            chained_import_addr += chained_import.sizeof
        dyld_bound_addresses_to_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}

        # The first word of this structure provides the number of uint32_t offsets to follow
        # Each offset is added to the base address of this structure to provide the address of a
        # `struct dyld_chained_starts_in_segment`.
        chained_starts_in_image_off = chained_fixups_data_start + header.starts_offset
        chained_starts_in_image = binary.read_struct(chained_starts_in_image_off, MachoDyldChainedStartsInImage)
        chained_starts_in_seg_offsets_base = chained_starts_in_image_off + chained_starts_in_image.sizeof

        writer = MachoBinaryWriter(binary)
        with writer:
            for segment_idx in range(chained_starts_in_image.seg_count):
                # Read entry of variable-length array of words. See comment in MachoDyldChainedStartsInImageRaw
                starts_in_seg_struct_offset = binary.read_word(
                    chained_starts_in_seg_offsets_base + (segment_idx * sizeof(c_uint32)),
                    virtual=False,
                    word_type=c_uint32,
                    )
                if starts_in_seg_struct_offset == 0:
                    continue

                starts_in_seg_addr = chained_starts_in_image_off + starts_in_seg_struct_offset
                chained_starts_in_seg = binary.read_struct(starts_in_seg_addr, MachoDyldChainedStartsInSegment)

                seg = binary.segment_for_index(segment_idx)
                print(f'{segment_idx}:{seg.name} ChainedStartsInSegment size {hex(chained_starts_in_seg.size)} page_size {hex(chained_starts_in_seg.page_size)} pointer_fmt {chained_starts_in_seg.pointer_format} segment_offset {hex(chained_starts_in_seg.segment_offset)} max_valid_ptr {chained_starts_in_seg.max_valid_pointer} page_count {chained_starts_in_seg.page_count}')

                offset_in_page_start = starts_in_seg_addr + chained_starts_in_seg.sizeof
                for page_idx in range(chained_starts_in_seg.page_count):
                    # Read entry of variable-length array of words. See comment in MachoDyldChainedStartsInSegmentRaw
                    offset_in_page = binary.read_word(
                        offset_in_page_start + (page_idx * sizeof(c_uint16)),
                        virtual=False,
                        word_type=c_uint16
                    )
                    print(f'\tPageIdx {page_idx}, offset in page {hex(offset_in_page)}')

                    chain_base = chained_starts_in_seg.segment_offset + (page_idx * chained_starts_in_seg.page_size) + offset_in_page
                    while True:
                        chained_rebase_ptr = binary.read_struct(chain_base, MachoDyldChainedPtr64Rebase)
                        # Rebase or bind?
                        if chained_rebase_ptr.bind == 1:
                            chained_bind_ptr = binary.read_struct(chain_base, MachoDyldChainedPtr64Bind)
                            bound_symbol = dyld_bound_symbols[chained_bind_ptr.ordinal]
                            print(f'\t\t{hex(chain_base)}: BIND\tordinal {chained_bind_ptr.ordinal}\taddend {chained_bind_ptr.addend}\treserved {chained_bind_ptr.reserved}\tnext {chained_bind_ptr.next}\tsymbol {bound_symbol.name}\t\tdylib {binary.dylib_name_for_library_ordinal(bound_symbol.library_ordinal)}')
                            dyld_bound_addresses_to_symbols[chain_base + binary.get_virtual_base()] = bound_symbol
                            chain_base += (chained_bind_ptr.next * 4)
                        else:
                            chained_ptr_raw = binary.read_word(chain_base, word_type=c_uint64, virtual=False)
                            # b = chain_base + (a.target * 4)
                            # print(f'\t\t{hex(chain_base)}: DyldChainedPtr64Rebase(raw: {hex(chained_ptr_raw)}) target off {hex(a.target)} high8 {hex(a.high8)} reserved {hex(a.reserved)} next {a.next} bind {a.bind}')
                            print(f'\t\t{hex(chain_base)}: DyldChainedPtr64Rebase(raw: {hex(chained_ptr_raw)}) target={StaticFilePointer(chained_rebase_ptr.target)}')
                            virt_addr = binary.get_virtual_base() + chain_base
                            rebased_ptr = binary.get_virtual_base() + chained_rebase_ptr.target
                            # print(f'\t\t\t{hex(virt_addr)}\t.write({rebased_ptr})')
                            writer.write_word(c_uint64(chained_rebase_ptr.target + binary.get_virtual_base()), chain_base, virtual=False)
                            # writer.write_word(c_uint64(rebased_ptr), virt_addr, virtual=True)
                            # print(f'\t\tTarget: {hex(b)} in {seg.name if seg else None}')
                            chain_base += (chained_rebase_ptr.next * 4)

                        if chained_rebase_ptr.next == 0:
                            break

        return dyld_bound_addresses_to_symbols, writer.modified_binary._cached_binary

    def parse_export_trie(self, start: StaticFilePointer, size: StaticFilePointer):
        data = self.binary.get_bytes(start, size)
        off = 0
        terminal_size, off = DyldInfoParser.read_uleb(data, off)
        print(terminal_size)
        children_count = data[off]
        print(f'children count {children_count}')
        raise RuntimeError("test")
        pass

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
            raise ValueError(f'This method expects the provided binary to contain LC_DYLD_INFO')

        return {
            **DyldInfoParser._parse_dyld_bytestream(binary, binary.dyld_info.bind_off, binary.dyld_info.bind_size),
            **DyldInfoParser._parse_dyld_bytestream(binary, binary.dyld_info.lazy_bind_off, binary.dyld_info.lazy_bind_size)
        }

    @staticmethod
    def _parse_dyld_bytestream(binary: MachoBinary, file_offset: StaticFilePointer, size: int) -> Dict[VirtualMemoryPointer, DyldBoundSymbol]:
        from ctypes import sizeof

        dyld_stubs_to_symbols: Dict[VirtualMemoryPointer, DyldBoundSymbol] = {}

        binding_info = binary.get_bytes(file_offset, size)
        pointer_size = sizeof(binary.platform_word_type)

        index = 0
        name_bytes: bytearray
        segment_index = 0
        segment_offset = 0
        library_ordinal = 0

        def commit_stub() -> None:
            segment_command = binary.segment_for_index(segment_index)
            segment_start = segment_command.vmaddr
            stub_addr = VirtualMemoryPointer(segment_start + segment_offset)
            name = name_bytes.decode("utf-8")

            symbol = DyldBoundSymbol(binary, stub_addr, library_ordinal, name)
            dyld_stubs_to_symbols[stub_addr] = symbol

        while index != len(binding_info):
            byte = binding_info[index]
            opcode = byte >> 4
            immediate = byte & 0xF
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
            else:
                logging.error(f"unknown dyld bind opcode {hex(opcode)}, immediate {hex(immediate)}")

        return dyld_stubs_to_symbols
