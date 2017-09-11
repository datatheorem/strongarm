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

```
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
    