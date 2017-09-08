from strongarm.macho_parse import *
from ctypes import *
import sys

def parse_strtab(macho_file, symtab_cmd):
    """
    Get string table as described by symtab_cmd from Mach-O file macho_file
    Args:
        macho_file: Mach-O executable file to retrieve string table from
        symtab_cmd: SymtabCommand containing offset and size of string table

    Returns: Array of characters containing macho_file's external symbol string table
    """
    macho_file.seek(symtab_cmd.stroff)
    string_tab_data = macho_file.read(symtab_cmd.strsize)
    # split into characters (string table is packed and each entry is terminated by a null character)
    string_table = list(string_tab_data)
    return string_table


def parse_symtab(macho_file, symtab_cmd):
    """
    Parse symbol table containing list of Nlist64's
    Args:
        macho_file: Mach-O executable file to retrieve symbol table from
        symtab_cmd: SymtabCommand containing offset and number of Nlist's in symbol table

    Returns: Array of Nlist64's representing file's symbol table

    """
    symtab = []
    # start reading from symoff and increment by one Nlist64 each iteration
    symoff = symtab_cmd.symoff
    for i in xrange(symtab_cmd.nsyms):
        macho_file.seek(symoff)
        nlist_data = bytearray(macho_file.read(sizeof(MachoNlist64)))
        nlist = MachoNlist64.from_buffer(nlist_data)
        symtab.append(nlist)
        # go to next Nlist in file
        symoff += sizeof(MachoNlist64)
    return symtab


def parse_indirect_symtab(macho_file, dysymtab_cmd):
    """
    Parse indirect symbol table containing pointers to external symbols
    Args:
        macho_file: Mach-O executable file to retrieve indirect symbol table from
        dysymtab_cmd: DysymtabCommand containing offset and number of indirect symtab entries

    Returns: Array of pointers of Mach-O's external symbols

    """
    indirect_symtab = []
    indirect_symtab_off = dysymtab_cmd.indirectsymoff
    for i in xrange(dysymtab_cmd.nindirectsyms):
        macho_file.seek(indirect_symtab_off)
        #indirect symtab is an array of uint32's
        indirect_symtab_entry = c_uint32.from_buffer(bytearray(macho_file.read(sizeof(c_uint32))))
        indirect_symtab.append(int(indirect_symtab_entry.value))
        indirect_symtab_off += sizeof(c_uint32)
    return indirect_symtab

def get_external_sym_pointers(macho_file, section):
    if section.sectname != '__la_symbol_ptr' and section.sectname != '__got':
        print('Unknown external section type: {}'.format(section.sectname))
        return None

    sym_ptr_count = section.size / sizeof(c_void_p)

    section_pointers = []
    section_data_ptr = section.offset
    print('{} data starts at {}'.format(
        section.sectname,
        hex(section_data_ptr),
    ))
    for i in xrange(sym_ptr_count):
        macho_file.seek(section_data_ptr)
        # TODO account for 32-bit MachO binaries - c_void_p will be smaller on that arch
        pointer_bytes = bytearray(macho_file.read(sizeof(c_void_p)))
        pointer_val = c_void_p.from_buffer(pointer_bytes).value
        section_pointers.append(pointer_val)
        section_data_ptr += sizeof(c_void_p)
    return section_pointers


def get_external_sym_map(macho_file, section, indirect_symtab, symtab, strtab):
    if section.sectname != '__la_symbol_ptr' and section.sectname != '__got':
        print('Unknown external section type: {}'.format(section.sectname))
        return None

    section_symbols = get_external_sym_pointers(macho_file, section)
    if not section_symbols:
        print('Couldn\'t retrieve section pointers')
        return None

    indirect_symtab_base = section.reserved1
    print('{} indirect symtab base: {} ({} symbols)'.format(
        section.sectname,
        indirect_symtab_base,
        len(section_symbols)
    ))
    symbol_map = {}
    for i in xrange(len(section_symbols)):
        symtab_idx = indirect_symtab[indirect_symtab_base + i]
        strtab_idx = symtab[symtab_idx].n_un.n_strx

        # string table is an array of characters
        # these characters represent symbol names,
        # with a null character delimiting each symbol name
        # find the length of this symbol by looking for the next null character starting from
        # the first index of the symbol
        symbol_string_len = string_table[strtab_idx::].index('\x00')
        strtab_end_idx = strtab_idx + symbol_string_len
        symbol_str_characters = string_table[strtab_idx:strtab_end_idx:]
        symbol_str = ''.join(symbol_str_characters)

        symbol_map[section_symbols[i]] = symbol_str
    return symbol_map

filename = '../GoodCertificateValidation'
macho_file = open(filename, 'r')
parser = MachoParser(filename)

dysymtab_cmd = parser.dysymtab
symtab_cmd = parser.symtab

if not dysymtab_cmd or not symtab_cmd:
    print('Couldn\'t retrieve MachO symbol tables from {}'.format(filename))
    sys.exit(1)

# get tables we need to perform external symbol lookup
# packed array of null-terminated external symbol names
string_table = parse_strtab(macho_file, symtab_cmd)
# array of NlistStruct's containing indexes into string_table
symbol_table = parse_symtab(macho_file, symtab_cmd)
# array of pointers to external symbols,
# where the index of a pointer in this table is the same index of the corresponding NlistStruct in symbol_table
indirect_symbol_table = parse_indirect_symtab(macho_file, dysymtab_cmd)

parser = MachoParser(filename)

# attempt to parse __la_symbol_ptr and __nl_symbol_ptr,
# if they're present in the binary
external_symbol_sections = []
try:
    non_lazy_sym_section = parser.sections['__nl_symbol_ptr']
    external_symbol_sections.append(non_lazy_sym_section)
except KeyError as e:
    pass
try:
    lazy_sym_section = parser.sections['__la_symbol_ptr']
    external_symbol_sections.append(lazy_sym_section)
except KeyError as e:
    pass

# generate external maps for non-lazy/lazy symbols, if available
for section in external_symbol_sections:
    symbol_map = get_external_sym_map(macho_file,
                                      section,
                                      indirect_symbol_table,
                                      symbol_table,
                                      string_table)
    print('{} symbol map:'.format(section.sectname))
    for ptr in symbol_map:
        print('\t{}: {}'.format(
            hex(ptr),
            symbol_map[ptr]
        ))

