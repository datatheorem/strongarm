strongarm
============

strongarm is a library for parsing and analyzing Mach-O binaries.
strongarm includes a Mach-O/FAT archive parser as well as utilities for reconstructing flow from compiled ARM64 assembly.

strongarm's primary innovation is the name. ('macho', as well as 'arm').

Components
---------
* Mach-O Parser
    - `strongarm` module
    - includes `MachoParser` and `MachoBinary`,
    as well as contents of `macho_definitions.py`,
    which describes Mach-O header structures.
* ARM64 analyzer
    - `strongarm` module
    - track register data flow
    - resolve branches to external symbols
    - identify Objective-C blocks, their call locations,
    arguments, etc
    - check for calls to specific Objective-C selectors and their call locations
    
Usage
--------------
* Mach-O Parser

```python
from strongarm.macho_parse import MachoParser
from strongarm.macho_definitions import *
parser = MachoParser('filename')
for slice in parser.slices:
    cpu = slice.cpu_type
    print('found slice with CPU type: {}'.format(
        if cpu == CPU_TYPE.ARM64 then 'ARM64' 
        elif cpu == CPU_TYPE.ARMV7 then 'ARMV7'
        else 'unkwn'
    ))
    # access slice.segments, slice.sections,
    # slice.symtab, etc 
```
    
How it works
--------------

One of the main challenges in strongarm was mapping branch destinations in the Mach-O `__stubs` section to 
human-readable symbol names.

The `__stubs` section contains some number of short functions like this:

```
                       imp___stubs__objc_msgSend:
0x000000010000685c         nop
0x0000000100006860         ldr        x16, #0x100008050
0x0000000100006864         br         x16
                        ; endp
```

Each stub function targets an external C function which is not present in the binary itself. In the above example,
the external C symbol which the stub targets is `objc_msgSend`.

Each stub actually just jumps to another pointer - in the above example, it's `0x100008050`. This address
does not actually contain the code of the function, but is rather just a reserved location in the virtual
address space. When this application calls any external C symbol, a function called `dyld_stub_binder` will
take the target address, `0x100008050` in this case, and overwrite it with the actual implementation of the function,
once it's loaded at runtime. This means the Mach-O can locally branch to known addresses, without needing
to know where the actual implementation will end up at runtime. 

What this means is, every branch destination to some location other than a function defined within the binary
will be targeting an address in the `__stubs` section. If we can resolve the addresses which each stub targets,
we can resolve what external function any branch destination represents.

A section called `__la_symbol_ptr` stores an array of pointers, containing the 'dummy' pointers targeted by each
stub in `__stubs`. As each dummy pointer will be overwritten at runtime and is never targeted by a branch instruction
locally, the actual contents of this section are not useful. However, the _order of pointers_ in the table is
shared with the _order of symbol names_ in other tables, so the _destination address of the stub_ is recorded for 
cross referencing.

The _indirect symbol table_ is a table of integers whose size and location is given by `dysymtab`. 
It is a shared table of indexes into the larger external symbol table. `__la_symbol_ptr`, as well as other tables,
store their symbol's _indexes into the larger symbol table_ in the indirect symbol table. The offset of a segment's
data in the indirect symbol table is given by `segment.reserved1`.

Thus, to get references to symbols in the external symbol table of the pointers in the `__la_symbol_ptr` segment,
we can use a loop like:
```python
        for (index, symbol_ptr) in enumerate(external_symtab):
            # the reserved1 field of the lazy symbol section header holds the starting index of this table's entries,
            # within the indirect symbol table
            # so, for any address in the lazy symbol, its translated address into the indirect symbol table is:
            # lazy_sym_section.reserved1 + index
            offset = indirect_symtab[lazy_sym_section.reserved1 + index]
            sym = symtab[offset]
```

The external symtab is a List of `Nlist64` structures. The index of the symbol name for this symbol within the 
packed string table can be retrieved from the `sym.n_un.n_strx` field.

The string table is a _packed_ array of characters. It is a contiguous array of char's, and each string is delimited 
by NULL. Thus, to get the symbol name, start reading from `sym.n_un.n_strx`, and continue until you hit NULL.

So, to map `__stubs` to symbol names:
* Record virtual addresses of pointers within `__la_symbol_ptr`
* Find offset for `__la_symbol_ptr` entries in the indirect symbol table,
  using the offset defined in the `__la_symbol_ptr` section header 
* For each index listed in the indirect symbol table, look at the corresponding symbol at that index in the larger
  external symbol table.
* Read symbol names from string table using string table index from symbol structure

