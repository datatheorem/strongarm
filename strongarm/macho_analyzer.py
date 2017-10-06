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

    @property
    @memoized
    def symbol_name_to_address_map(self):
        call_address_map = {}
        for key, value in self.address_to_symbol_name_map.iteritems():
            call_address_map[value] = key
        return call_address_map

    def symbol_name_for_branch_destination(self, branch_address):
        # type: (int) -> Text
        if branch_address in self.address_to_symbol_name_map:
            return self.address_to_symbol_name_map[branch_address]
        raise RuntimeError('Unknown branch destination {}. Is this a local branch?'.format(
            hex(branch_address)
        ))

    def _find_function_boundary(self, start_address, size):
        # type: (int, int) -> int
        """Helper function to search for a function boundary within a given block of executable code

        This function searches from start_address up to start_address + size looking for a set of
        instructions resembling a function boundary. If a function boundary is identified its address will be returned,
        or else 0 will be returned if no boundary was found.
        """

        # get executable code in requested region
        func_str = self.binary.get_content_from_virtual_address(virtual_address=start_address, size=size)

        # transform func_str into list of CsInstr
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]

        # this will be set to an address if we find one,
        # or will stay 0. If it remains 0 we know we didn't find the end of the function
        end_address = 0
        # flag to be used when we encounter an unconditional branch
        # if we encounter an unconditional branch and recently loaded the link register with a stored value,
        # it is exceedingly likely that the unconditional branch serves as the last statement in the function,
        # as after the branch the link register will contain whatever it was after loading it from the stack here,
        # and execution will jump back to the caller of this function
        next_branch_is_return = False
        # if a function makes no other calls to other subroutines
        # (and thus never modifies the link register),
        # then it's possible for the last instruction to be an unconditional branch,
        # without first loading the link register from the stack
        # this tracks whether the link register has been modified in the code block
        # if it has, then we know we can only be at the end of function if we've seen a
        # ldp ..., x30, ...
        has_modified_lr = False

        # traverse instructions, looking for signs of end-of-function
        for instr in instructions:
            # ret mnemonic is sure sign we've found end of the function!
            if instr.mnemonic == 'ret':
                end_address = instr.address
                break

            # slightly less strong heuristic
            # in the uncommon case that a function ends in a branch,
            # it *must* have moved something sane into the link register,
            # or else the program would jump to an unreasonable place after the branch.
            # The sole exception to this rule is if a function never modifies the link
            # register in the first place, which is tracked by has_modified_lr.
            # we could possibly strengthen the has_modified_lr check by also checking for this pattern:
            # in the prologue, stp ..., x30, [sp, #0x...]
            # then a corresponding ldp ..., x30, [sp, #0x...]
            elif instr.mnemonic == 'ldp':
                # are we restoring a value into link register?
                load_dst_1 = instr.reg_name(instr.operands[0].value.reg)
                load_dst_2 = instr.reg_name(instr.operands[1].value.reg)
                # link register on ARM64 is x30
                link_register = 'x30'
                if load_dst_1 == link_register or load_dst_2 == link_register:
                    next_branch_is_return = True

            # branch with link inherently modifies the link register,
            # which means the function *must* have stored link register at some point,
            # which means we can later use an ldp ..., x30 as a heuristic for function epilogue
            elif instr.mnemonic == 'bl':
                has_modified_lr = True
            elif instr.mnemonic == 'b':
                if next_branch_is_return or not has_modified_lr:
                    end_address = instr.address
                    break

        # long to int
        end_address = int(end_address)
        return end_address

    def get_function_address_range(self, function_address):
        """Retrieve the address range of executable function beginning at function_address

        The return value will be a tuple containing the start and end addresses of executable code belonging
        to the function starting at address function_address
        """

        # get_content_from_virtual_address wants a size for how much data to grab,
        # but we don't actually know how big the function is!
        # start off by grabbing 256 bytes, and keep doubling search area until we encounter the
        # function boundary.
        end_address = 0
        search_size = 0x100
        while not end_address:
            end_address = self._find_function_boundary(function_address, search_size)
            # double search space
            search_size *= 2

        return function_address, end_address

    def get_function_instructions(self, start_address):
        _, end_address = self.get_function_address_range(start_address)
        if not end_address:
            raise RuntimeError('Couldn\'t parse function @ {}'.format(start_address))
        function_size = end_address - start_address

        func_str = self.binary.get_bytes(start_address, function_size)
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        return instructions
