from ctypes import c_uint64, sizeof

from capstone import *
from typing import Text, List, Dict, Optional

from strongarm.debug_util import DebugUtil
from strongarm.decorators import memoized
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import ObjcClass, ObjcMethod, ObjcMethodList, ObjcData
from macho_cross_referencer import MachoCrossReferencer


class MachoImpStub(object):
    """Encapsulates entry in __imp_stubs section

    An 'entry' in the __imp_stubs section is a very short function which jumps to a pointer in the __got or
    __la_symbol_ptr lists. This pointer is a 'garbage' value which will be filled by dyld at runtime the first time
    the stub is invoked by a function called dyld_stub_binder.
    An entry in the __imp_stubs section might be assembly like the following:
    0x0000000100006898         nop
    0x000000010000689c         ldr        x16, #0x100008010
    0x00000001000068a0         br         x16
    In this case, 0x100008010 is an address in __la_symbol_ptr, which contains `dq 0x100010000`. I don't know the exact
    mechanism by which dyld_stub_binder rewrites __imp_stubs/__la_symbol_ptr at runtime to change garbage pointers such
    as 0x100010000 into the address the symbol was loaded at, but it's not really relevant here.
    More relevant is the fact that the first address of each stub entry (0x100006898 in this example) will be the
    branch destination anytime someone addresses the external symbol in question.
    So, if the imp stub above corresponded to the `__la_symbol_ptr` entry for NSLog, a caller calling NSLog would
    actually branch to 0x100006898.
    By chaining all this information together along with symbol names cross-referenced with __la_symbol_ptr from
    the indirect symbol table + string table, we can cross-reference branch destinations to external symbol names.

    This object contains the starting address of the stub (which will be the destination for branches),
    as well as the __la_symbol_ptr entry which is targeted by the stub.
    """
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
        # type: (MachoBinary) -> None
        self.binary = bin
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

        self._selrefs = None
        self.selector_names_to_imps = None
        self._selector_name_pointers_to_imps = None

        self.imported_functions = None
        self.classlist = None
        self._contains_objc = False

        self.crossref_helper = MachoCrossReferencer(bin)
        self.imported_functions = self.crossref_helper.imported_symbol_list()

        self.parse_classlist()

        if self._contains_objc:
            self._create_selref_to_name_map()

        # done setting up, store this analyzer in class cache
        MachoAnalyzer.active_analyzer_map[bin] = self

    @classmethod
    def get_analyzer(cls, bin):
        if bin in cls.active_analyzer_map:
            # use cached analyzer for this binary
            return cls.active_analyzer_map[bin]
        return MachoAnalyzer(bin)

    @property
    @memoized
    def _la_symbol_ptr_to_symbol_name_map(self):
        # type: () -> Dict[int, Text]
        """Cross-reference Mach-O sections to produce __la_symbol_ptr pointers -> external symbol name map.
        
        This map will only contain entries for symbols that are defined outside the main binary.
        This method cross references data in __la_symbol_ptr, the indirect symbol table

        The map created by this method DOES NOT correspond to the addresses used by branch destinations.
        Branch destinations will actually point to entries in __imp_stubs. This is a helper function for a method
        to map __imp_stubs entries to symbol names

        Returns:
            Map of __la_symbol_ptr pointers to the strings corresponding to the name of each symbol
        """
        imported_symbol_map = {}

        # the reserved1 field of the lazy symbol section header holds the starting index of this table's entries,
        # within the indirect symbol table
        # so, for any address in the lazy symbol, its translated address into the indirect symbol table is:
        # lazy_sym_section.reserved1 + index
        lazy_sym_offset_within_indirect_symtab = self.binary.sections['__la_symbol_ptr'].cmd.reserved1
        # this list contains the contents of __la_symbol_ptr
        external_symtab = self.binary.get_external_sym_pointers()

        # indirect symbol table is a list of indexes into larger symbol table
        indirect_symtab = self.binary.get_indirect_symbol_table()

        symtab = self.binary.symtab_contents
        string_table = self.binary.get_raw_string_table()

        for (index, symbol_ptr) in enumerate(external_symtab):
            # as above, for an index idx in __la_symbol_ptr, the corresponding entry within the symbol table (from which
            # we can get the string name of this symbol) is given by the value in the indirect symbol table at index:
            # la_symbol_ptr_command.reserved1 + idx
            offset = indirect_symtab[lazy_sym_offset_within_indirect_symtab + index]
            sym = symtab[offset]

            # we now have the Nlist64 symbol for the __la_symbol_ptr entry
            # the starting index of the string within the string table for this symbol is given by the n_strx field
            strtab_idx = sym.n_un.n_strx

            symbol_name = self.crossref_helper.string_table_entry_for_strtab_index(strtab_idx).full_string
            # record this mapping of address to symbol name
            imported_symbol_map[symbol_ptr] = symbol_name
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
    def imp_stubs(self):
        # type: () -> List[MachoImpStub]
        stubs_section = self.binary.sections['__stubs']

        func_str = self.binary.get_bytes(stubs_section.cmd.offset, stubs_section.cmd.size)
        instructions = [instr for instr in self.cs.disasm(
            func_str,
            self.binary.get_virtual_base() + stubs_section.cmd.offset)]

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
    def external_branch_destination_to_symbol_names(self):
        # TODO(PT): clarify this is an imported symbols map
        symbol_name_map = {}
        stubs = self.imp_stubs
        la_sym_ptr_name_map = self._la_symbol_ptr_to_symbol_name_map

        for stub in stubs:
            symbol_name = la_sym_ptr_name_map[stub.destination]
            symbol_name_map[stub.address] = symbol_name
        return symbol_name_map

    @property
    @memoized
    def symbol_name_to_address_map(self):
        # TODO(PT): clarify this is an imported symbols map
        call_address_map = {}
        for key, value in self.external_branch_destination_to_symbol_names.iteritems():
            call_address_map[value] = key
        return call_address_map

    def symbol_name_for_branch_destination(self, branch_address):
        # type: (int) -> Text
        if branch_address in self.external_branch_destination_to_symbol_names:
            return self.external_branch_destination_to_symbol_names[branch_address]
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

        func_str = self.binary.get_bytes(start_address - self.binary.get_virtual_base(), function_size)
        instructions = [instr for instr in self.cs.disasm(func_str, start_address)]
        return instructions

    def parse_classlist(self):
        classlist_sect = self.binary.sections['__objc_classlist']
        # does this binary contain an Objective-C classlist?
        if not classlist_sect:
            # nothing to do here, must be a purely C or Swift binary
            self._contains_objc = False
            return
        self._contains_objc = True

        classlist_data = classlist_sect.content
        classlist_size = len(classlist_data) / sizeof(c_uint64)
        classlist_off = 0
        classlist = []
        for i in range(classlist_size):
            data_end = classlist_off + sizeof(c_uint64)
            val = c_uint64.from_buffer(bytearray(classlist_data[classlist_off:data_end])).value
            classlist.append(val)
            classlist_off += sizeof(c_uint64)

        self.classlist = classlist
        self.crossref_classlist()
        return classlist

    def read_classlist_entry(self, entry_location):
        file_ptr = entry_location - self.binary.get_virtual_base()
        raw_struct_data = self.binary.get_bytes(file_ptr, sizeof(ObjcClass))
        class_entry = ObjcClass.from_buffer(bytearray(raw_struct_data))

        # sanitize class_entry
        # it seems for Swift classes,
        # the compiler will add 1 to the data field
        # TODO(pt) detecting this can be a heuristic for finding Swift classes!
        # mod data field to a byte size
        overlap = class_entry.data % 0x8
        class_entry.data -= overlap
        return class_entry

    def crossref_classlist(self):
        objc_data = self.binary.sections['__objc_data']
        objc_data_start = objc_data.cmd.addr
        objc_data_end = objc_data_start + objc_data.cmd.size

        classlist_entries = []
        for idx, ent in enumerate(self.classlist):
            class_entry = self.read_classlist_entry(ent)
            classlist_entries.append(class_entry)

            # is the metaclass implemented within this binary?
            # we know if it's implemented within the binary if the metaclass pointer is within the __objc_data
            # section.
            if objc_data_start <= class_entry.metaclass < objc_data_end:
                # read metaclass as well and append to list
                metaclass_entry = self.read_classlist_entry(class_entry.metaclass)
                classlist_entries.append(metaclass_entry)

        self.parse_classlist_entries(classlist_entries)

    def parse_classlist_entries(self, classlist_entries):
        # type: (List[ObjcClass]) -> None
        objc_data_entries = []
        for i, class_ent in enumerate(classlist_entries):
            data_file_ptr = class_ent.data - self.binary.get_virtual_base()
            raw_struct_data = self.binary.get_bytes(data_file_ptr, sizeof(ObjcData))
            data_entry = ObjcData.from_buffer(bytearray(raw_struct_data))
            # ensure this is a valid entry
            if data_entry.name < self.binary.get_virtual_base():
                DebugUtil.log(self, 'caught ObjcData struct with invalid fields at {}'.format(
                    hex(int(data_file_ptr + self.binary.get_virtual_base()))
                ))
                continue
            objc_data_entries.append(data_entry)
        self.parse_objc_data_entries(objc_data_entries)

    def parse_objc_data_entries(self, objc_data_entries):
        # type: (List[ObjcData]) -> None

        self.selector_names_to_imps = {}
        self._selector_name_pointers_to_imps = {}

        for ent in objc_data_entries:
            methlist_file_ptr = ent.base_methods - self.binary.get_virtual_base()
            if ent.base_methods == 0:
                continue
            raw_struct_data = self.binary.get_bytes(methlist_file_ptr, sizeof(ObjcMethodList))
            methlist = ObjcMethodList.from_buffer(bytearray(raw_struct_data))

            # parse every entry in method list
            method_entry_off = methlist_file_ptr + sizeof(ObjcMethodList)
            for i in range(methlist.methcount):
                raw_struct_data = self.binary.get_bytes(method_entry_off, sizeof(ObjcMethod))
                method_ent = ObjcMethod.from_buffer(bytearray(raw_struct_data))

                # TODO(PT): preprocess __objc_methname so we don't have to search for null byte for every string here
                name_start = method_ent.name
                name_len = 0
                found_null_terminator = False
                # grab 512 bytes
                max_len = 512
                name_bytes = self.binary.get_content_from_virtual_address(virtual_address=name_start, size=max_len)
                # search for null terminator in this content
                for ch in name_bytes:
                    if ch == '\x00':
                        found_null_terminator = True
                        break
                    name_len += 1
                # did we find null terminator?
                if not found_null_terminator:
                    current_buffer = str(name_bytes[:name_len:])
                    raise RuntimeError('__objc_methname entry was longer than {} bytes ({}). Fix me!'.format(
                        max_len,
                        current_buffer
                    ))
                # read full string
                symbol_name = str(name_bytes[:name_len:])

                self._selector_name_pointers_to_imps[method_ent.name] = method_ent.implementation

                # if this is the first instance of this selector name we've seen,
                # map it to an array just containing the IMP address
                if symbol_name not in self.selector_names_to_imps:
                    self.selector_names_to_imps[symbol_name] = [method_ent.implementation]
                # if we've already recorded an IMP for this sel name, just add the new one to the list
                else:
                    self.selector_names_to_imps[symbol_name].append(method_ent.implementation)

                method_entry_off += sizeof(ObjcMethod)

    def _create_selref_to_name_map(self):
        self._selrefs = {}

        selref_sect = self.binary.sections['__objc_selrefs']
        entry_count = selref_sect.cmd.size / sizeof(c_uint64)

        for i in range(entry_count):
            content_off = i * sizeof(c_uint64)
            selref_val_data = selref_sect.content[content_off:content_off + sizeof(c_uint64)]
            selref_val = c_uint64.from_buffer(bytearray(selref_val_data)).value
            virt_location = content_off + selref_sect.cmd.addr
            self._selrefs[virt_location] = selref_val

        # we now have an array of tuples of (selref ptr, string literal ptr)
        # self._selector_name_pointers_to_imps contains a map of {string literal ptr, IMP}
        # create mapping from selref ptr to IMP
        self._selref_ptr_to_imp_map = {}
        for selref_ptr, string_ptr in self._selrefs.items():
            try:
                imp_ptr = self._selector_name_pointers_to_imps[string_ptr]
            except KeyError as e:
                # if this selref had no IMP, it must be a selector for a method defined outside this binary
                # we don't mind, just continue
                continue
            self._selref_ptr_to_imp_map[selref_ptr] = imp_ptr

    def imp_for_selref(self, selref_ptr):
        if not selref_ptr:
            return None
        try:
            return self._selref_ptr_to_imp_map[selref_ptr]
        except KeyError as e:
            # if we have a selector reference entry for this pointer but no IMP,
            # it must be a selector for a class defined outside this binary
            if selref_ptr in self._selrefs:
                return None
            # if we had no record of this selref, it's an invalid pointer and an exception should be raised
            raise RuntimeError('invalid selector reference pointer {}'.format(hex(int(selref_ptr))))

    def get_method_imp_addresses(self, selector):
        # type: (Text) -> List[int]
        """Given a selector, return a list of virtual addresses corresponding to the start of each IMP for that SEL
        """
        return self.selector_names_to_imps[selector]

    def get_method_address_ranges(self, selector):
        # type: (Text) -> List[(int, int)]
        """Retrieve a list of addresses where the provided SEL is implemented

        If no implementations exist for the provided selector, an empty list will be returned.
        If implementations exist, the list will contain tuples in the form: (IMP start address, IMP end address)
        """
        ranges_list = []
        start_addresses = self.get_method_imp_addresses(selector)
        if not start_addresses:
            # get_method_imp_address failed, selector might not exist
            # return empty list
            return ranges_list

        for idx, start_address in enumerate(start_addresses):
            end_address = self.get_function_address_range(start_address)
            # get_content_from_virtual_address wants a size for how much data to grab,
            # but we don't actually know how big the function is!
            # start off by grabbing 256 bytes, and keep doubling search area until we encounter the
            # function boundary.
            end_address = 0
            search_size = 0x100
            while not end_address:
                end_address = self._find_function_boundary(start_address, search_size)
                # double search space
                search_size *= 2

            ranges_list.append((start_address, end_address))
        return ranges_list

    def get_implementations(self, selector):
        # type: (Text) -> List[List[CsInsn]]
        """Retrieve a list of the disassembled function data for every implementation of a provided selector
        Args:
            selector: The selector name who's implementations should be found

        Returns:
            A list of lists containing CsInsn objects. Each entry in the outer list represents an implementation of
            the selector, suitable for being passed to an ObjcFunctionAnalyzer constructor
        """
        implementations = []
        imp_addresses = self.get_method_address_ranges(selector)
        for imp_start, imp_end in imp_addresses:
            imp_size = imp_end - imp_start
            imp_data = self.binary.get_content_from_virtual_address(virtual_address=imp_start, size=imp_size)
            imp_instructions = [instr for instr in self.cs.disasm(imp_data, imp_start)]
            implementations.append(imp_instructions)
        return implementations
