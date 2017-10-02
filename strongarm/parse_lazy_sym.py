from strongarm.macho_parse import *
from ctypes import *
import sys

# TODO(pt) prototyping, get this from the slide declared in macho header
vmem_base = 0x10000000


def get_external_sym_pointers(binary):
    section = binary.get_section_with_name('__la_symbol_ptr')
    sym_ptr_count = section.size / sizeof(c_void_p)

    section_pointers = []
    section_data_ptr = section.offset
    print('{} data starts at {}'.format(
        section.sectname,
        hex(section_data_ptr),
    ))
    for i in range(sym_ptr_count):
        pointer_raw = binary.get_bytes(section_data_ptr, sizeof(c_void_p))
        pointer_val = c_void_p.from_buffer(bytearray(pointer_raw)).value
        print('pointer_val @ {}: {}'.format(hex(section_data_ptr), hex(pointer_val)))
        #section_pointers.append(pointer_val)
        section_pointers.append(section_data_ptr + vmem_base)
        section_data_ptr += sizeof(c_void_p)
    return section_pointers


def get_indirect_symbol_table(binary):
    dysymtab_cmd = binary.dysymtab
    indirect_symtab = []
    indirect_symtab_off = dysymtab_cmd.indirectsymoff
    print('indirect symtab @ {} with {} entries'.format(
        hex(indirect_symtab_off),
        hex(dysymtab_cmd.nindirectsyms)
    ))
    for i in xrange(dysymtab_cmd.nindirectsyms):
        macho_file.seek(indirect_symtab_off)
        # indirect symtab is an array of uint32's
        indirect_symtab_entry = c_uint32.from_buffer(bytearray(macho_file.read(sizeof(c_uint32))))
        indirect_symtab.append(int(indirect_symtab_entry.value))
        indirect_symtab_off += sizeof(c_uint32)
    return indirect_symtab


filename = '../tests/bin/GoodCertificateValidation'
macho_file = open(filename, 'r')
parser = MachoParser(filename)
binary = parser.slices[0]

indirect_symbol_table = get_indirect_symbol_table(binary)
external_symtab = get_external_sym_pointers(binary)

# get tables we need to perform external symbol lookup
# packed array of null-terminated external symbol names
string_table = binary.get_raw_string_table()
# array of NlistStruct's containing indexes into string_table
symbol_table = binary.get_symtab_contents()

# attempt to parse __la_symbol_ptr and __nl_symbol_ptr,
# if they're present in the binary
external_symbol_sections = []
try:
    non_lazy_sym_section = binary.get_section_with_name('__nl_symbol_ptr')
    external_symbol_sections.append(non_lazy_sym_section)
except KeyError as e:
    pass
try:
    lazy_sym_section = binary.get_section_with_name('__la_symbol_ptr')
    external_symbol_sections.append(lazy_sym_section)
except KeyError as e:
    pass

# get array from contents of la_symbol_ptr
# symbol names corresponding to each address are at:
# a = la_symbol index
# sym = symtab[indirect_symtab[lazy_sym_section.reserved1] + a]
# name = strtab[sym.n_un.n_strx]

print('reserved1 {}'.format(lazy_sym_section.reserved1))
for (index, ptr) in enumerate(external_symtab):
    offset = indirect_symbol_table[lazy_sym_section.reserved1 + index]
    sym = symbol_table[offset]
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

    print('{} maps to {}'.format(hex(ptr), symbol_str))