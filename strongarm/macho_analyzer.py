from macho_binary import MachoBinary
from capstone import *
from typing import Text
from decorators import memoized


class MachoImpStub(object):
    def __init__(self, address, destination):
        self.address = address
        self.destination = destination


class MachoAnalyzer(object):
    # keep map of active MachoAnalyzer instances
    # each MachoAnalyzer operates on a single MachoBinary which will never change in the lifecycle of the analyzer
    # also, some MachoAnalyzer operations are expensive, but they only have to be done once per instance
    # so, we only keep one analyzer for each MachoBinary
    active_analyzer_map = {}

    def __init__(self, bin):
        # type: (MachoBinary) -> MachoAnalyzer
        self.binary = bin
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        # store this analyzer in class cache
        MachoAnalyzer.active_analyzer_map[bin] = self

    @classmethod
    def get_analyzer(cls, bin):
        if bin in cls.active_analyzer_map:
            # use cached analyzer for this binary
            return cls.active_analyzer_map[bin]
        return MachoAnalyzer(bin)

    @property
    @memoized
    def external_symbol_addr_map(self):
        # type: () -> {int, Text}
        imported_symbol_map = {}
        lazy_sym_section = self.binary.get_section_with_name('__la_symbol_ptr')
        external_symtab = self.binary.get_external_sym_pointers()
        indirect_symtab = self.binary.get_indirect_symbol_table()
        symtab = self.binary.get_symtab_contents()
        string_table = self.binary.get_raw_string_table()

        for (index, symbol_ptr) in enumerate(external_symtab):
            # the reserved1 field of the lazy symbol section header holds the starting index of this table's entries,
            # within the indirect symbol table
            # so, for any address in the lazy symbol, its translated address into the indirect symbol table is:
            # lazy_sym_section.reserved1 + index
            offset = indirect_symtab[lazy_sym_section.reserved1 + index]
            sym = symtab[offset]
            strtab_idx = sym.n_un.n_strx

            # string table is an array of characters
            # these characters represent symbol names,
            # with a null character delimiting each symbol name
            # find the length of this symbol by looking for the next null character starting from
            # the first index of the symbol
            symbol_string_len = string_table[strtab_idx::].index('\x00')
            strtab_end_idx = strtab_idx + symbol_string_len
            symbol_str_characters = string_table[strtab_idx:strtab_end_idx:]
            symbol_str = ''.join(symbol_str_characters)

            # record this mapping of address to symbol name
            imported_symbol_map[symbol_ptr] = symbol_str
        return imported_symbol_map

    def parse_stub(self, instr1, instr2, instr3):
        # each stub follows one of two patterns
        # pattern 1: nop / ldr x16, <sym> / br x16
        # pattern 2: adrp x16, <page> / ldr x16, [x16 <offset>] / br x16
        # try parsing both of these formats
        patterns = [
            ['nop', 'ldr', 'br'],
            ['adrp', 'ldr', 'br'],
        ]
        # differentiate between patterns by looking at the opcode of the first instruction
        pattern_idx = 0
        if instr1.mnemonic == patterns[0][0]:
            pattern_idx = 0
        elif instr1.mnemonic == patterns[1][0]:
            pattern_idx = 1
        else:
            # unknown stub format
            return None

        expected_ops = patterns[pattern_idx]
        for idx, op in enumerate([instr1, instr2, instr3]):
            # sanity check
            if op.mnemonic != expected_ops[idx]:
                raise RuntimeError('Expected instruction {} to be {} while parsing stub, was instead {}'.format(
                    idx,
                    expected_ops[idx],
                    op.mnemonic
                ))

        stub_addr = instr1.address
        stub_dest = 0
        # nop/ldr/br pattern
        if pattern_idx == 0:
            stub_dest = instr2.operands[1].value.imm
        # adrp/ldr/br pattern
        elif pattern_idx == 1:
            stub_dest_page = instr1.operands[1].value.imm
            stub_dest_pageoff = instr2.operands[1].mem.disp
            stub_dest = stub_dest_page + stub_dest_pageoff
        stub = MachoImpStub(stub_addr, stub_dest)
        return stub

    @property
    @memoized
    def imp_stub_section_map(self):
        # type: () -> List[MachoImpStub]
        imp_stub_map = self.external_symbol_addr_map
        stubs_section = self.binary.get_section_with_name('__stubs')

        func_str = self.binary.get_bytes(stubs_section.offset, stubs_section.size)
        instructions = [instr for instr in self.cs.disasm(func_str, self.binary.get_virtual_base() + stubs_section.offset)]

        stubs = []
        # each stub follows one of two patterns
        # pattern 1: nop / ldr x16, <sym> / br x16
        # pattern 2: adrp x16, <page> / ldr x16, [x16 <offset>] / br x16
        # try parsing both of these formats

        irpd = iter(instructions)
        for instr1, instr2, instr3 in zip(irpd, irpd, irpd):
            stub = self.parse_stub(instr1, instr2, instr3)
            if not stub:
                raise RuntimeError('Failed to parse stub')
            stubs.append(stub)
        return stubs

    @property
    @memoized
    def address_to_symbol_name_map(self):
        symbol_name_map = {}
        stubs = self.imp_stub_section_map
        imp_stub_map = self.external_symbol_addr_map

        for stub in stubs:
            symbol_name = imp_stub_map[stub.destination]
            symbol_name_map[stub.address] = symbol_name
        return symbol_name_map

    def symbol_name_for_branch_destination(self, branch_address):
        # type: (int) -> Text
        if branch_address in self.address_to_symbol_name_map:
            return self.address_to_symbol_name_map[branch_address]
        raise RuntimeError('Unknown branch destination {}. Is this a local branch?'.format(
            hex(branch_address)
        ))

