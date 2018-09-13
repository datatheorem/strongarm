# -*- coding: utf-8 -*-
import ctypes
import logging

from typing import Dict
from enum import IntEnum

from .macho_binary import MachoBinary


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


class DyldBoundSymbol:
    def __init__(self,
                 binary: MachoBinary,
                 stub_addr: int,
                 library_ordinal: int,
                 name: str):
        self.binary = binary
        self.address = stub_addr
        self.library_ordinal = library_ordinal
        self.name = name
        self.dylib = self.binary.dylib_for_library_ordinal(library_ordinal)


class DyldInfoParser:
    def __init__(self, binary: MachoBinary):
        self.binary = binary
        self.dyld_info_cmd = self.binary.dyld_info
        self.dyld_stubs_to_symbols: Dict[int, DyldBoundSymbol] = {}
        if self.dyld_info_cmd:
            self.parse_dyld_info()

    @staticmethod
    def read_uleb(data, offset):
        byte = data[offset]
        offset += 1

        result = byte & 0x7f
        shift = 7
        while byte & 0x80:
            byte = data[offset]
            result |= (byte & 0x7f) << shift
            shift += 7
            offset += 1

        # attempt to catch signed values and convert them if encountered
        if result > 0x100000000:
            result = ctypes.c_long(result).value

        return result, offset

    @staticmethod
    def get_uleb128(data, offset):
        value = 0
        i = 0
        tmp = 0
        for x in range(0, 5):
            i = x
            tmp = data[offset+i] & 0x7f
            value = tmp << (i * 7) | value
            if (data[offset+i] & 0x80) != 0x80:
                break
        if i == 4 and (tmp & 0xf0) != 0:
            print(f'parse error uleb128')
            return -1
        return value, i + 1

    def parse_dyld_info(self):
        self.parse_dyld_bytestream(self.dyld_info_cmd.bind_off, self.dyld_info_cmd.bind_size)
        self.parse_dyld_bytestream(self.dyld_info_cmd.lazy_bind_off, self.dyld_info_cmd.lazy_bind_size)

    def parse_dyld_bytestream(self, fileoff: int, size: int):
        from ctypes import sizeof
        binding_info = self.binary.get_bytes(fileoff, size)
        pointer_size = sizeof(self.binary.platform_word_type)

        index = 0
        name_bytes = ""
        segment = 0
        segment_offset = 0
        library_ordinal = 0

        def commit_stub():
            segment_start = self.binary.segment_for_index(segment).vmaddr
            stub_addr = segment_start + segment_offset
            name = name_bytes.decode('utf-8')

            symbol = DyldBoundSymbol(self.binary, stub_addr, library_ordinal, name)
            self.dyld_stubs_to_symbols[stub_addr] = symbol

        while index != len(binding_info):
            byte = binding_info[index]
            opcode = byte >> 4
            immediate = byte & 0xf
            index += 1

            if opcode == BindOpcode.BIND_OPCODE_DONE:
                pass
            elif opcode == BindOpcode.BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                library_ordinal = immediate
            elif opcode == BindOpcode.BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                library_ordinal, index = self.read_uleb(binding_info, index)
            elif opcode == BindOpcode.BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                library_ordinal = -immediate
            elif opcode == BindOpcode.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                name_end = binding_info.find(b'\0', index)
                name_bytes = binding_info[index:name_end]
                index = name_end
            elif opcode == BindOpcode.BIND_OPCODE_SET_TYPE_IMM:
                pass
            elif opcode == BindOpcode.BIND_OPCODE_SET_ADDEND_SLEB:
                _, index = self.read_uleb(binding_info, index)
            elif opcode == BindOpcode.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment = immediate
                segment_offset, index = self.read_uleb(binding_info, index)
            elif opcode == BindOpcode.BIND_OPCODE_ADD_ADDR_ULEB:
                addend, index = self.read_uleb(binding_info, index)
                segment_offset += addend
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND:
                commit_stub()
                segment_offset += pointer_size
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                commit_stub()
                segment_offset += pointer_size
                
                addend, index = self.read_uleb(binding_info, index)
                segment_offset += addend
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                commit_stub()
                # I think the format is <immediate>, <repeat times>
                # So, we always reserve at least one pointer, then skip the 'repeat' count pointers.
                segment_offset += pointer_size + (immediate * pointer_size)
            elif opcode == BindOpcode.BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                count, index = self.read_uleb(binding_info, index)
                skip, index = self.read_uleb(binding_info, index)
                for i in range(count):
                    commit_stub()
                    segment_offset += pointer_size + skip
            else:
                logging.error(f'unknown dyld bind opcode {hex(opcode)}, immediate {hex(immediate)}')
