from macho_binary import MachoBinary
from capstone import *
from capstone.arm64 import *

class ObjcFunctionAnalyzer(object):
    def __init__(self, instructions):
        # type: (List[CsInsn]) -> ObjcFunctionAnalyzer
        self._instructions = instructions

    @classmethod
    def format_instruction(cls, instr):
        # type: (CsInsn) -> Text
        """Stringify a CsInsn for printing
        :param instr: Instruction to create formatted string representation for
        :return: Formatted string representing instruction
        """
        return "{addr}:\t{mnemonic}\t{ops}".format(addr=hex(int(instr.address)),
                                                   mnemonic=instr.mnemonic,
                                                   ops=instr.op_str)

    def track_reg(self, reg):
        # type: (Text) -> List[Text]
        """
        Track the flow of data starting in a register through a list of instructions
        :param reg: Register containing initial location of data
        :return: List containing all registers which contain data originally in reg
        """
        # list containing all registers which hold the same value as initial argument reg
        regs_holding_value = [reg]
        for instr in self._instructions:
            # TODO(pt) track other versions of move w/ suffix e.g. movz
            # do instructions like movz only operate on literals? we only care about reg to reg
            if instr.mnemonic == 'mov':
                if len(instr.operands) != 2:
                    raise RuntimeError('Encountered mov with more than 2 operands! {}'.format(
                        self.format_instruction(instr)
                    ))
                # in mov instruction, operands[0] is dst and operands[1] is src
                src = instr.reg_name(instr.operands[1].value.reg)
                dst = instr.reg_name(instr.operands[0].value.reg)

                # check if we're copying tracked value to another register
                if src in regs_holding_value and dst not in regs_holding_value:
                    # add destination register to list of registers containing value to track
                    regs_holding_value.append(dst)
                # check if we're copying something new into a register previously containing tracked value
                elif dst in regs_holding_value and src not in regs_holding_value:
                    # register being overwrote -- no longer contains tracked value, so remove from list
                    regs_holding_value.remove(dst)
        return regs_holding_value

    def next_blr_to_reg(self, reg, start_index):
        # type: (Text, int) -> int
        """
        Search for the next 'blr' instruction to a target register, starting from the instruction at start_index
        :param reg: Register whose 'branch to' instruction should be found
        :param start_index: Instruction index to begin search at
        :return: Index of next 'blr' instruction to reg
        """
        index = start_index
        for instr in self._instructions[start_index::]:
            if instr.mnemonic == 'blr':
                dst = instr.operands[0]
                if instr.reg_name(dst.value.reg) == reg:
                    return index
            index += 1
        return -1

    def next_branch(self, start_index):
        branch_mnemonics = ['b',
                            'bl',
                            'bx',
                            'blx',
                            'bxj',
                            ]
        for instr in self._instructions[start_index::]:
            if instr.mnemonic in branch_mnemonics:
                return instr
        return None


class ObjcBlockAnalyzer(ObjcFunctionAnalyzer):
    def __init__(self, instructions, initial_block_reg):
        ObjcFunctionAnalyzer.__init__(self, instructions)

        self.registers_containing_block = self.track_reg(initial_block_reg)
        self.load_reg, self.load_index = self.find_block_load()
        self.invoke_index = self.find_block_invoke()

    def find_block_load(self):
        """
        Find instruction where Block->invoke is loaded into
        :return: Tuple of register containing Block->invoke, and the index this instruction was found at
        """
        index = 0
        for instr in self._instructions:
            if instr.mnemonic == 'ldr':
                print(self.format_instruction(instr))
                if len(instr.operands) != 2:
                    raise RuntimeError('Encountered ldr with more than 2 operands! {}'.format(
                        self.format_instruction(instr)
                    ))
                # we're looking for an instruction in the format:
                # ldr <reg> [<reg_containing_block>, #0x10]
                # block->invoke is always 0x10 from start of block
                # so if we see the above then we know we're loading the block's executable start addr
                dst = instr.operands[0]
                src = instr.operands[1]
                if src.type == ARM64_OP_MEM:
                    if instr.reg_name(src.mem.base) in self.registers_containing_block and src.mem.disp == 0x10:
                        # found load of block's invoke addr!
                        return instr.reg_name(dst.value.reg), index
            index += 1

    def find_block_invoke(self):
        return self.next_blr_to_reg(self.load_reg, self.load_index)

    def get_block_arg(self, arg_index):
        # type: (int) -> int
        """
        Starting from the index where a function is called, search backwards for the assigning of
        a register corresponding to function argument at index arg_index
        Currently this function will only detect arguments who are assigned to an immediate value
        :param arg_index: Positional argument index (0 for first argument, 1 for second, etc.)
        :return: Index of instruction where argument is assigned
        """
        desired_register = u'x{}'.format(arg_index)

        for instr in self._instructions[self.invoke_index::-1]:
            if instr.mnemonic == 'movz' or instr.mnemonic == 'mov':
                # arg1 will be stored in x1
                dst = instr.operands[0]
                src = instr.operands[1]
                if instr.reg_name(dst.value.reg) == desired_register:
                    # return immediate value if source is not a register
                    if instr.mnemonic == 'movz':
                        return src.value.imm
                    # source is a register, return reg name
                    return instr.reg_name(src.value.reg)

class MachoImpStub(object):
    def __init__(self, address, destination):
        self.address = address
        self.destination = destination


class MachoAnalyzer(object):
    def __init__(self, bin):
        # type: (MachoBinary) -> MachoAnalyzer
        self.binary = bin
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

    @property
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

    @property
    def imp_stub_section_map(self):
        # type: () -> List[MachoImpStub]
        imp_stub_map = self.external_symbol_addr_map
        stubs_section = self.binary.get_section_with_name('__stubs')
        print('stubs section: {}'.format(stubs_section))

        func_str = self.binary.get_bytes(stubs_section.offset, stubs_section.size)
        instructions = [instr for instr in self.cs.disasm(func_str, self.binary.get_virtual_base() + stubs_section.offset)]

        stubs = []
        # each stub follows this format:
        # nop
        # ldr x16, <sym>
        # br x16
        # parse this known format
        irpd = iter(instructions)
        for nop_instr, load_instr, br_instr in zip(irpd, irpd, irpd):
            print(ObjcFunctionAnalyzer.format_instruction(nop_instr))
            print(ObjcFunctionAnalyzer.format_instruction(load_instr))
            print(ObjcFunctionAnalyzer.format_instruction(br_instr))
            expected_ops = ['nop', 'ldr', 'br']
            for idx, op in enumerate([nop_instr, load_instr, br_instr]):
                # sanity check
                if op.mnemonic != expected_ops[idx]:
                    raise RuntimeError('Expected instruction {} to be {} while parsing stub, was instead {}'.format(
                        idx,
                        expected_ops[idx],
                        op.mnemonic
                    ))

            stub_addr = nop_instr.address
            # op 1, 0 is destination register
            stub_dest = load_instr.operands[1].value.imm
            stub = MachoImpStub(stub_addr, stub_dest)
            stubs.append(stub)
        return stubs

    @property
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

