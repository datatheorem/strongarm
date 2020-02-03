from typing import List

from capstone import Cs, CsInsn

from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import VirtualMemoryPointer


class MachoImpStub:
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

    def __init__(self, address: VirtualMemoryPointer, destination: VirtualMemoryPointer) -> None:
        self.address = address
        self.destination = destination


class MachoImpStubsParser:
    def __init__(self, binary: MachoBinary, capstone_disasm: Cs) -> None:
        self.binary = binary
        self._cs = capstone_disasm
        self.imp_stubs = self._parse_all_stubs()

    @staticmethod
    def _parse_stub_from_instructions(instr1: CsInsn, instr2: CsInsn, instr3: CsInsn) -> MachoImpStub:
        # TODO(PT): write CsInsn by hand to test this function
        # each stub follows one of two patterns
        # pattern 1: nop / ldr x16, <sym> / br x16
        # pattern 2: adrp x16, <page> / ldr x16, [x16 <offset>] / br x16
        # try parsing both of these formats
        patterns = [["nop", "ldr", "br"], ["adrp", "ldr", "br"]]
        # differentiate between patterns by looking at the opcode of the first instruction
        if instr1.mnemonic == patterns[0][0]:
            pattern_idx = 0
        elif instr1.mnemonic == patterns[1][0]:
            pattern_idx = 1
        else:
            # unknown stub format
            raise NotImplementedError({hex(instr1.address)})

        expected_ops = patterns[pattern_idx]
        for idx, op in enumerate([instr1, instr2, instr3]):
            # sanity check
            if op.mnemonic != expected_ops[idx]:
                raise RuntimeError(
                    f"Expected instr {hex(op.address)} (idx {idx}) to be {expected_ops[idx]}"
                    f" while parsing stub, was instead {op.mnemonic}"
                )

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
        stub = MachoImpStub(VirtualMemoryPointer(stub_addr), VirtualMemoryPointer(stub_dest))
        return stub

    def _parse_all_stubs(self) -> List[MachoImpStub]:
        stubs_section = self.binary.section_with_name("__stubs", "__TEXT")
        if not stubs_section:
            return []

        func_str = bytes(
            self.binary.get_bytes(
                stubs_section.offset, stubs_section.cmd.size, _translate_addr_to_file=False
            )  # When working with DSC's, the reported offset should not be translated
        )
        instructions = [instr for instr in self._cs.disasm(func_str, stubs_section.address)]

        stubs = []
        # each stub follows one of two patterns
        # pattern 1: nop / ldr x16, <sym> / br x16
        # pattern 2: adrp x16, <page> / ldr x16, [x16 <offset>] / br x16
        # try parsing both of these formats

        irpd = iter(instructions)
        for instr1, instr2, instr3 in zip(irpd, irpd, irpd):
            stub = self._parse_stub_from_instructions(instr1, instr2, instr3)
            if not stub:
                raise RuntimeError("Failed to parse stub")
            stubs.append(stub)
        return stubs
