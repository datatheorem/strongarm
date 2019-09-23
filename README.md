strongarm
-----------------

*strongarm* is a cross-platform, full-featured Mach-O analysis library.
strongarm is production-ready and is used heavily throughout DataTheorem's iOS static analyzer stack.

Features:

- Read and cross-reference Mach-O info
- Dataflow analysis
- Function detection

Mach-O parsing:

- Metadata (architecture, endianness, etc)
- Load commands
- Symbol tables
- String tables
- Code signature
- APIs to lookup metadata of an address
- Dyld info

Mach-O analysis:

- Function boundary detection & disassembly
- Read Objective-C info (classes, categories, protocols, methods, ivars, etc)
- Cross-reference addresses to imported/exported symbols
- Dyld bound symbols & implementation stubs
- Parse constant NSStrings
- Basic block analysis

Mach-O editing:

- Load command insertion
- Write Mach-O structures
- Byte-edit binaries


Quickstart
-----------

Pass an input file to `MachoParser`, which will read a Mach-O or FAT and provide access to individual `MachoBinary` slices.

```python
import pathlib
# Load an input file
from strongarm.macho import MachoParser
parser = MachoParser(pathlib.Path('~/Downloads/Skype.app/Skype'))
# Read the ARM64 slice and perform some operations
binary = parser.get_arm64_slice()
print(binary.get_entitlements().decode())
print(hex(binary.section_with_name('__text','__TEXT').address))
```

You can also modify Mach-O's by overwriting structures or inserting load commands:
```python
# Overwrite a structure
binary: MachoBinary = ...
new_symbol_table = MachoSymtabCommand()
new_symbol_table.nsyms = 0
modified_binary = binary.write_struct(new_symbol_table, binary.symtab.address, virtual=True)

# Add a load command
modified_binary = modified_binary.insert_load_dylib_cmd('/System/Frameworks/UIKit.framework/UIKit')

# Write the modified binary to a file
MachoBinary.write_binary(pathlib.Path(__file__).parent / 'modified_binary')
```

Some APIs which require more memory or cross-referencing are available through `MachoAnalyzer`

```python
binary: MachoBinary = ...
analyzer = MachoAnalyzer.get_analyzer(binary)

# Print some interesting info
print(analyzer.imported_symbol_names_to_pointers)   # All the dynamically linked symbols which will be bound at runtime
print(analyzer.exported_symbol_names_to_pointers)   # All the symbols which this binary defines and exports
print(analyzer.get_functions())                     # Entry-point list of the binary. Each of these can be wrapped in an ObjcFunctionAnalyzer
print(analyzer.strings())                           # __cstring segment
print(analyzer.get_imps_for_sel('viewDidLoad'))     # Convenience accessor for an ObjcFunctionAnalyzer

# Print the Objective-C class information
for objc_cls in analyzer.objc_classes():
    print(objc_cls.name)
    for objc_ivar in objc_cls.ivars:
        print(f'\tivar: {objc_ivar.name}')
    for objc_sel in objc_cls.selectors:
        print(f'\tmethod: {objc_sel.name} @ {hex(objc_sel.implementation)}')
```

Once you have a handle to a `FunctionAnalyzer`, representing a source code function, you can inspect different attributes of the code:

```python
from strongarm.objc import ObjcFunctionAnalyzer
binary: MachoBinary = ...
function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer_for_signature(binary, 'ViewController', 'viewDidLoad')
print(function_analyzer.basic_blocks)   # Find the basic block boundaries

# Print some interesting info about Objective-C method calls in the function
for instr in function_analyzer.instructions:
    if not instr.is_msgSend_call:
        continue
    
    # In an Objective-C message send, x0 stores the receiver and x1 stores the selector being messaged.
    classref = pass
    receiver = pass
    selector = pass
   
    # Prints "0x100000000: _objc_msgSend(_OBJC_CLASS_$_UIView, @selector(alloc));"
    print(f'{hex(instr.address)}: {instr.symbol}({receiver}, @selector({selector}));')

```