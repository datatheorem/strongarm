# Changelog

## Unreleased

### SCAN-3832: Fix library ordinals parsing

The parsing of library_ordinal when opcode is BIND_OPCODE_SET_DYLIB_SPECIAL_IMM would negate the value, instead it should handle the special value 0 and sign extend the rest of the values:

```python
    if immediate == 0:
       library_ordinal = 0
    else:
       library_ordinal = c_int8(BindOpcode.BIND_OPCODE_MASK | immediate).value
```

Handle `BIND_SPECIAL_DYLIB_*` ordinals in MachoBinary.dylib_for_library_ordinal() and MachoBinary.dylib_name_for_library_ordinal() to return None and special values respectively.


## 2022-11-23: 14.0.1

### SCAN-3705: Fix parsing __objc_classrefs on iOS 15+

`__objc_classrefs` contains internal pointers to `__objc_data` that need to be rebased. 

On iOS 15+, these pointers are rebased via chained fixup pointers, and therefore the literal binary data at each `u64` in `__objc_classrefs` needs to be fixed up.

This release uses the correct internal API (`MachoBinary.read_rebased_pointer()`) when parsing classrefs.

## 2022-11-17: 14.0.0

### SCAN-3620: Add Dynamic Library processing

Prior to this release, strongarm didn't have an ergonomic API for enumerating the dylibs loaded by a binary. 
strongarm provided `MachoBinary.loaded_dylib_commands`, but the caller had to jump through awkward hoops to, for example, list the load paths of dylibs:

```python
for cmd in binary.load_dylib_commands:
    dylib_name_addr = binary.get_virtual_base() + cmd.binary_offset + cmd.dylib.name.offset
    dylib_name = binary.read_string_at_address(dylib_name_addr)
```

This release replaces `MachoBinary.loaded_dylib_commands` with `MachoBinary.linked_dylibs`:

```python
for dylib in binary.loaded_dylibs:
    dylib_name = dylib.name
```

## 2022-10-04: 13.2.1

### SCAN-3569: Fix reading CFStrings on iOS 15+

`struct __cfstring` has fields that might need to be rebased via chained fixup pointers. Therefore, the internal strongarm API that parses them needs to use 

`MachoBinary.read_struct_with_rebased_pointers()` rather than `MachoBinary.read_struct()`. 

I only noticed this on a binary built with Xcode 14, but since it involves chained fixup pointers, it may affect any iOS 15+ binary. 

## 2022-09-27: 13.2.0

### SCAN-3401: Support XRefs for calls to `__objc_stubs`

Historically, the pattern for sending a message to an Objective-C class looks similar to the following:

```
; Base page of the classref
adrp x0, #0x1001f7000
; Page offset of the classref
ldr  x0, [x0, #0xe00]
; Base page of the selref
adrp x1, #0x10000c000
; Page offset of the selref
ldr  x0, [x0, #0xc8]
; Classref and selref are now loaded into x0 and x1, respectively - we're ready to send the message
bl _objc_msgSend
```

This `adrp`, `ldr`, `bl` pattern is repetitive and can greatly contribute to the final code size of an application. 

In [early 2021](https://www.uber.com/en-GB/blog/how-uber-deals-with-large-ios-app-size/), Uber detailed a technique by which 
they greatly reduced binary code size by outlining this sequence to a dedicated function. Now, each time we want to message a selector, 
we only need to include one instruction (a branch to the outlined instructions) at each call site, instead of 3. 

Perhaps relatedly, in Xcode 14, Apple's toolchain performs the same optimization (for binaries targeting older OS versions as well as new). 

There is a new Mach-O section, `__objc_stubs`, which contains these outlined sequences. In this strongarm version, we now support
generating XRefs to these calls. In other words, in the user-facing `MachoAnalyzer.objc_calls_to()` API, a branch to a stub in `__objc_stubs`
will be indistinguishable from a direct `_objc_msgSend` call that uses the inlined `adrp`, `ldr`, `bl` pattern. Perhaps in the future I'll add
some kind of discriminator so the API consumer can know what kind of call site it is, but the important thing for now is that the XRefs show up. 

There's a new internal API to facilitate this:

`MachoAnalyzer._get_objc_selector_stubs() -> Dict[VirtualMemoryPointer, str]`

The API for the dataflow module has also changed, as we now provide the XRef builder with the above map upon entry. This version is released in tandem with `strongarm-dataflow@3.0.0`.

Unrelatedly, I added a small terseness helper to the unit test suite:

`tests.utils.binary_with_name(name: str) -> MachoBinary`

It allows the caller to retrieve and parse a binary from `/tests/bin/` without needing to spell it all out.

## 2022-09-15: 13.1.0

### SCAN-3546: Further support for binaries with code outside `__TEXT`

Other APIs within strongarm had baked-in assumptions that certain Mach-O sections would be contained within `__TEXT`.

This version more correctly looks for these sections dynamically, rather than assuming they'll always be in `__TEXT`.

Specifically, the following features and APIs will now look for `__cstrings` in either `__TEXT` or `__RODATA`:

* `MachoAnalyzer.get_cstrings() -> Set[str]`
* `MachoAnalyzer.build_cstring_map() -> Dict[str, VirtualMemoryPointer]`
* The `strings` command in the CLI

Additionally:

* `MachoBinary.get_cstring_section() -> Optional[MachoSection]` is a new API to facilitate segment-agnostic `__cstring` retrieval
* `MachoImpStubsParser.get_dyld_stubs_section() -> Optional[MachoSection]` is a new API to facilitate segment-agnostic `__stubs` retrieval
* `MachoAnalyzer._strings_in_section(section_name: str)` has a new kwarg, `segment_name: str = "__TEXT"`
* `MachoBinary.insert_load_dylib_cmd(dylib_path: str)` will now dynamically find the first section after the Mach-O header, rather than assuming it's `__text,__TEXT`
* `MachoImpStubsParser` now looks for `__stubs` in other segments if it wasn't found in `__TEXT`

## 2022-09-12: 13.0.7

### SCAN-3535: Support binaries with code outside `__TEXT`

Some binaries use tricks in which their code is stored in custom segments rather than `__TEXT`. 

In the cases I've seen so far, `__TEXT` is still around, but only contains mandated sections (such as `__const`, `__bss`, `__swift51_hooks`, etc). 

The dataflow module mostly gets this right, as it gets its entry points from `LC_FUNCTION_STARTS` (which points to valid locations in the custom segment).
However, it needs a bit of help. The dataflow module previously used the assumption that `code_slice_offset = code_virt_addr - __TEXT.base`.
This relied on the knowledge that `__TEXT` always begins at offset 0. Of course, if code is stored outside `__TEXT`, this will result in incorrect calculations.

Previously, the dataflow module was just passed a list of code entry points to analyze. In this change, it is also passed the corresponding slice offsets 
for each entry point, which is easier to compute in strongarm proper than the dataflow module.

## 2022-06-27: 13.0.6

### SCAN-3221: Support parsing `DYLD_CHAINED_IMPORT_ADDEND`

Similarly to the support added in `13.0.5`, this release supports the `DYLD_CHAINED_IMPORT_ADDEND` pointer format. 

## 2022-04-05: 13.0.5

### SCAN-3221: Support parsing `DYLD_CHAINED_PTR_64`

Previously, while parsing chained fixup pointers, we'd implicitly treat all `target` fields in a packed rebase as though it were `DYLD_CHAINED_PTR_64_OFFSET`; 
that is, we'd always add a virtual memory base to `target` to yield a final rebase target address. 
However, the correct interpretation of `target` depends on the value of the `pointer_format` 
field in the `MachoDyldChainedStartsInSegmentRaw` structure. 
This version supports parsing absolute and relative targets, and will explicitly error out if an unsupported pointer format is encountered in a fixup chain.

## 2022-01-20: 13.0.4

### SCAN-3119: Cache the results of `MachoAnalyzer.get_cstrings()` and `MachoAnalyzer.strings()`

## 2022-01-03: 13.0.3

### SCAN-3091: Support parsing `DYLD_CHAINED_IMPORT_ADDEND64`

Previously, we supported parsing only one type of chained fixup pointers: DYLD_CHAINED_IMPORT_ADDEND. Some chained fixup pointers are of type DYLD_CHAINED_IMPORT_ADDEND64, which has a different data layout.
Note that every chained import has a ‘library ordinal’ describing which linked dylib it comes from (starting at an index of 1). For some binaries we've come across, this value was -3, which corresponds to the constant BIND_SPECIAL_DYLIB_WEAK_LOOKUP. It appears that this constant mean “this isn’t an import, this symbol is actually locally defined”. I don’t understand the use case for this.

## 2021-11-29: 13.0.2

### SCAN-3007: Add a cache to speed up `ObjcRuntimeDataParser.selector_for_selref()`

This method is queried for every selector in the binary while building the XRef database, so it needs to be constant-time.
The previous implementation did an O(n) search through all the selrefs in the binary when the input selref refers to an imported, 
rather than locally defined, selector. The new implementation builds a cache while enumerating the Objective-C runtime data
to avoid this. 

### SCAN-2972: Switch from Pipenv to pip-tools

(Maintenance): Bump black dependency from 19.10b0 to 20.8b1.

## 2021-11-05: 13.0.1

### SCAN-2970: Handle magic values in dyld chained fixup pointer page starts

As part of the dyld implementation of chained fixup pointers, binaries contain structures describing the locations of
fixup chains in various parts of the binary. One of the fields of such a structure denotes the offset into a page where
a chain begins. Normally, this value represents the offset into a page from which we should begin reading a chain.

However, some values of this offset field have special significance, such as to signify that there are actually no
chains within the page. strongarm was previously interpreting these values as though they were real offsets into a
page, leading to bad parse states.

Note that another special value this field can hold indicates that there are multiple fixup chains within a single page.
This ticket doesn't add support for parsing these, but does error out if they're encountered.

## 2021-10-27: 13.0.0

### SCAN-2950: The type signature of `MachoBinary.read_pointer_section` has been simplified to clarify its semantics
### SCAN-2960: Handle `NULL` ivar offset pointer

(Breaking): The initialisers of `MachoSection` and `MachoSegment` have changed to reflect they no longer need a reference to a `MachoBinary`.

(Breaking): `MachoBinary.read_pointer_section` has changed its return signature from `Tuple[List[VirtualMemoryPointer], List[VirtualMemoryPointer]]` to `Dict[VirtualMemoryPointer, VirtualMemoryPointer]`.

(Fix): Handle ivars with a `NULL` offset pointer. Observed for the `$defaultActor` ivar within a Swift source class.

## 2021-10-26: 12.0.2

### SCAN-2946: Bump strongarm_dataflow to 2.1.6

## 2021-10-26: 12.0.1

### SCAN-2950: Minor cleanup

(New): Use a non-root `logger`.
(New):  Add CLI flags for quick data querying.

## 2021-10-07: 12.0.0

### SCAN-2944: ObjcClass.selectors no longer contains its superclass's selectors

(Breaking): `ObjcClass.selectors` no longer contains its superclass's selectors. This was originally added for convenience, but does not reflect the underlying binary, and violates assumptions an API client was making.

## 2021-10-06: 11.0.3

### SCAN-2929: Optimise load-command insertion code path

Strongarm used to parse the symbol table on startup. This caused unnecessary CPU/RAM consumption when the API user
simply wants to insert a load command.

(New): Defer parsing of `MachoBinary.symtab_contents` until first requested.

(New): `MachoBinary.read_struct()` calls `MachoBinary.get_minimum_deployment_target()` on each invocation, and the latter function 
uses `LooseVersion`, which does regex parsing. Add a cache so this attribute is computed only once.

## 2021-09-23: 11.0.2

### Necessary version bump to replace a malformed source archive on PyPI

## 2021-09-23: 11.0.1

### SCAN-2907: Add basic support for BIND_OPCODE_THREADED
### SCAN-2909: Don't try to parse ARM64e slices for now (Will be reverted by SCAN-2910)

## 2021-07-26 11.0.0

### SCAN-2795: Add support for iOS 15 binaries

Support parsing binaries with a minimum deployment target of iOS 15 that use the "chained fixup pointer" dyld format.

This release is a breaking change. 

(New): strongarm will now track the locations of rebases and will parse structures containing internal rebased pointers with fixups applied.

(Breaking): Reduce memory usage by removing duplicated binary memory in `MachoSection.content` and `MachoSegment.content`. Read the memory directly from the binary if you need to access it, as these were always direct copies.

(New): `MachoAnalyzer.stringref_for_string` is now more efficient, as C strings and CFStrings are now parsed as a whole when analysis begins.

(New): `MachoBinaryWriter` has been added to facilitate several binary modifications at once without triggering a binary parse per modification.

Use it like so:

```python
from pathlib import Path
from ctypes import c_uint64, sizeof
from strongarm.macho.macho_binary_writer import MachoBinaryWriter

# Initialise a batch binary writer
writer = MachoBinaryWriter(binary)

# Make a series of changes to the binary
with writer:
    for i in range(5):
        writer.write_word(word=c_uint64(0xdeadbeef), address=0x1000 + (i * sizeof(c_uint64)), virtual=False)

# `writer.modified_binary` contains the re-parsed binary containing the provided changes
# Persist the modified binary to disk
writer.modified_binary.write_binary(Path(__file__) / "modified_binary")
```

(Fix): Fix a bug in which parsing an Objective-C protocol after parsing an Objective-C class implementing that protocol 
may result in strongarm not reporting implementation pointers for the implemented selectors.

## 2021-06-11 10.5.7

### SCAN-2740: Improve log and error messages

### SCAN-2666: Speed up MachoAnalyzer.class_name_for_class_pointer()

### SCAN-2658: Read strings from __const section

## 2021-03-16 10.5.6

### SCAN-2515: Prevent a NULL-dereference when building XRef table of a malformed binary

## 2021-02-16 10.5.5

### SCAN-783: Avoid shell injection when invoking c++filt

Disclosed by Keegan Saunders <keegan@undefinedbehaviour.org>

Also, drop `DebugUtil` in favor of the standard library's `logging` module.

## 2021-02-10 10.5.3

## 2021-02-16 10.5.4

### SCAN-783: Bump strongarm-dataflow to 2.1.4

## 2021-02-10 10.5.3

### SCAN-783: Validate capstone install upon failing to import strongarm_dataflow

The cause of the failed import may be a linking error when the C-ext tries to link capstone. 
If this is the case, report it more cleanly to the user so it’s clear what’s going on.

## 2021-02-02 10.5.2

### SCAN-783: Metadata tweaks pending open-source release

## 2020-12-21 10.5.1

### SCAN-2419: A binary built for iOS 14 may still include relative instead of absolute method lists.

This release will look at both the deployment target and a flag bit set in the method list header when choosing whether to parse a relative or absolute method list. 

### SCAN-2415: Handle edge-case around encountering invalid bytecode while generating XRefs

Prior to this release, XRef generation already had handling for when it encountered invalid bytecode within a source function.
However, a particular assembly contruction like the following could reach a code path that did not have this handling:

```c
    // Instruction 1: Relative jump to after the bytecode sequence
    asm volatile(".word 0x14000005");

    // Instruction 2: adrp x0, #0x114e40000
    // XRef generation will interpret this as the first half of a string load,
    // and will try to disassemble the next instruction to complete the string load
    asm volatile(".word 0xb00a71c0");

    // Instructions 3 & 4: garbage, will fail to disassemble
    asm volatile(".word 0xffffffff");
    asm volatile(".word 0xffffffff");
```

`_generate_function_xrefs` dispatches to one of a few functions to generate an XRef, depending on the XRef type. 
One of these is `_generate_loaded_string_xref.`

Instead of looking just at the current disassembled instruction, `_generate_loaded_string_xref` sometimes needs a 1-instruction lookahead 
to parse a string load. Thus, `_generate_loaded_string_xref` sometimes needs to use cs_disasm directly outside of the main cs_disasm_iter loop. 

If this lookahead instruction was invalid bytecode, we threw an unhandled exception and eventually failed to generate XRefs. 
This release adds handling in this code path. Now, when the lookahead instruction is invalid, XRef generation will correctly skip the function,
similarly to how a function is skipped if a source function contains invalid bytecode in the common case.

## 2020-11-04 10.5.0 

### SCAN-2316: `MachoBinary` exposes its file offset within a larger FAT via `MachoBinary.get_file_offset() -> StaticFilePointer`.

## 2020-11-02 10.4.0 

### SCAN-2305: XRef generation is now implemented entirely in C++ within `strongarm-dataflow`. This give a substantial performance boost.

### SCAN-2298: `MachoAnalyzer.strings()` was renamed to `MachoAnalyzer.get_cstrings()`, and only returns the contents of the `__cstring` section.

`MachoAnalyzer.strings()` now tries to return the full list of strings in the binary, including:
- `__cstring`
- `__objc_methname`
- `__objc_methtype`
- `__objc_classname`
- Any string access identified during XRef generation

## 2020-10-26 10.3.1

### SCAN-2299: XRef generation no longer crashes when encountering malformed opcodes in bytecode.

## 2020-10-22 10.3.0

### SCAN-2217: The inner XRef generation is now implemented in C++ within `strongarm-dataflow`. 

Also, basic-block-boundaries are now cached within the internal database in a new table, 
since basic-block-boundaries are queried multiple times during initial analysis.
Also, the get_register_contents_at_instruction_fast API changed to facilitate calling it from other CPP. 
Its signature changed from:

```python
def get_register_contents_at_instruction_fast(
  desired_register: str,
  function_analyzer: ObjcFunctionAnalyzer
  instruction: ObjcInstruction
  basic_block_start_addr: VirtualMemoryPointer
) -> RegisterContents
```

To:

```python
def get_register_contents_at_instruction_fast(
  desired_register: str,
  function_entry_point: VirtualMemoryPointer
  function_bytecode: bytearray,
  basic_block_start_address: VirtualMemoryPointer
  instruction_address: VirtualMemoryPointer
) -> RegisterContents
```

## 2020-10-08 10.2.0

### SCAN-2227: `MachoAnalyzer` XRef generation works on binaries that don't use `objc_msgSend`

## 2020-10-07 10.1.0

### SCAN-2216: Basic-block-detection is now implemented in C++ within `strongarm-dataflow`. This gives a substantial performance boost.

## 2020-10-01 10.0.0

### SCAN-1373: XRefs are correctly generated for ObjC calls made via `_objc_opt_*` fast-paths.

Around iOS 13, Apple started adding new fast-paths for some `NSObject` selectors: `new`, `alloc`, `isKindOfClass:`, 
totalling less than 10. These selectors bypass `_objc_msgSend` and are implemented in C directly, 
but will only be emitted by the compiler in cases where the default `NSObject` implementation would be used. 
The function names are things like `_objc_opt_isKindOfClass(classref*)` and `_objc_alloc_init(classref*)`.
In SCAN-1199, I added support for generating XRefs from these calls. However, the `ObjcMsgSendXRef` that is 
generated by one of these calls never has the selref available.

This version adds support for searching for these calls. It does so by changing the `ObjcMsgSendXRef` 
format to include a class_name: str and selector: str instead of a classref and selref. It’s valid for a binary to 
contain an `_objc_opt_respondsToSelector` call without containing a `@selector(respondsToSelector:)` selref, 
so the API had to be changed.

Also, previously when encountering an `_objc_msgSend call` to a binary-defined selector, we would generate 
the `ObjcMsgSendXRef`, then would also generate a `FunctionCallXRef` with the destination address set to the 
selector’s implementation. It was unclear what use case this was serving, and is a confusing edge case, so I dropped it.

## 2020-09-28 9.4.0

### SCAN-2174: Add support for parsing `LC_BUILD_VERSION`

This is exposed by the following new methods:

```python
MachoBinary.get_minimum_deployment_target() -> Optional[LooseVersion]: ...
MachoBinary.get_build_version_platform() -> Optional[MachoBuildVersionPlatform]: ...
MachoBinary.get_build_tool_versions() -> Optional[List[MachoBuildToolVersionStruct]]: ...
```

In the past, Mach-O previously had a different load command for each platform’s minimum OS version; 
`LC_VERSION_MIN_MACOSX`, `LC_VERSION_MIN_IPHONEOS`, `LC_VERSION_MIN_TVOS`, etc. These were unified into `LC_BUILD_VERSION` 
that reports both a platform and version. The associated structure also includes a list of the versions of the build 
tools that were used to produce the binary, such as the `clang` and `ld` versions.

### SCAN-2175: Add support for iOS 14's relative method lists.

When the minimum deployment target is set to iOS 14, `struct objc_method`'s layout changes from:

```c
struct objc_method {
    uint64_t name_ptr;
    uint64_t type_encoding_ptr;
    uint64_t imp_addr_ptr;
}
```

To:

```c
struct objc_method {
  int32_t selref_off_from_this_field;
  int32_t type_encoding_off_from_this_field;
  int32_t imp_off_from_this_field;
}
```

This is a bit of a hairy one. There is already a mechanism for having two underlying data layouts that map to the 
same data structure, one of which is chosen based on the binary’s architecture (`ArchIndependentStructure`). 
This is similar but slightly different, because it instead depends on the binary’s toolchain version.

I played around with a few ways of organising this and settled on one. In addition to `ArchIndependentStructure` 
having a 32-bit and 64-bit underlying data layout, there is also a new `alternate_layout` that can be defined, 
and selected for parsing if the caller passes a new flag.

Then, the Objective-C runtime data parser conditionally parses this new structure if the toolchain version is high enough. 
Since all other parts of the code assume that this structure contains absolute pointers, 
this new code path also rewrites the pointers to be absolute, instead of relative offsets.

Lastly, the `name` absolute-pointer field has been replaced with a `selref` offset field. 
The fix-up also dereferences this selref to store the `name` in the resulting `ObjcMethodStruct`.

## 2020-07-22 9.3.0

### SCAN-1917: The following attributes are now cached after calculation:

```python
MachoAnalyzer.imported_symbols_to_symbol_names() -> Dict[VirtualMemoryPointer, str]: ...
MachoAnalyzer.imported_symbol_names_to_pointers() -> Dict[str, VirtualMemoryPointer]: ...
MachoAnalyzer.exported_symbol_names_to_pointers() -> Dict[str, VirtualMemoryPointer]: ...
```

## 2020-06-17 9.2.2

### SCAN-1888: Python library is now exported as `strongarm-dataflow` instead of `strongarm_dataflow`

## 2020-06-17 9.2.1

### SCAN-1888: Fix flake8 and typing errors

## 2020-06-17 9.2.0

### SCAN-1885: New API to retrieve strings accessed by a function

This is exposed as `MachoAnalyzer.strings_in_func(self, func_addr: VirtualMemoryPointer) -> List[Tuple[VirtualMemoryPointer, str]]: ...`

## 2020-06-12 9.1.0

### SCAN-1881: XRef generation now also generates XRefs for string accesses

This is exposed as `MachoAnalyzer.string_xrefs_to(str) -> List[Tuple[VirtualMemoryPointer, VirtualMemoryPointer]]: ...`.

This API provides each place in the binary code that a string literal is used. It handles both C strings and CFStrings.

XRef generation now records string loads matching the following assembly patterns:

```aarch64
adrp x2, #0x1001f7000
add  x2, x2,   #0xc00  ; @"Reachable via WiFi" 
```

```aarch64
adr x2, #0x1001f7354  ; @"Reachable via WiFi"
```

This only handles string-literals in source code like so:

```objective-c
- (void)m {
    NSLog(@"This literal is x-ref'd");
}
```

And does not handle string-literals referenced behind indirection of other constant data:

```objective-c
static NSString* x = @"This literal is NOT x-ref'd";
- (void)m {
    NSLog(x);
}
```

### SCAN-1881: APIs requiring XRef computation are gated behind a new `@_requires_xrefs_computed` decorator.

## 2020-05-05: 9.0.0

### SCAN-1795: Support parsing super/base-class of ObjC classes/categories

In the past, Objective-C categories would be reported as `$_Unknown_Class (CategoryName)`. 

strongarm will now return these as the correct `_OBJC_CLASS_$_UIWebView (CategoryName)`.

`ObjcCategory.base_class` will now return the real base-class, instead of a placeholder value.

`ObjcClass.superclass_name` has been added, and functions the same way. strongarm can now parse superclass names. 

#### Related bug fix:

`MachoAnalyzer.classref_for_class_name` and `MachoAnalyzer.class_name_for_class_pointer` would return the _first_ 
dyld bound address for a given classname, instead of using the _classref_ bound symbol.

Consider:

```aarch64
.section _objc_const

; ObjC Category declaration
struct __objc_data {
  name_ptr = 0x10000f000  ; "CategoryName" stringref
  base_class_ptr = 0x0  ; _OBJC_CLASS_$_UIWebView dyld bound symbol
  ...
}


.section _objc_classrefs
_objc_cls_ref_UIWebView = dq 0x0  ; _OBJC_CLASS_$_UIWebView dyld bound symbol
```

`MachoAnalyzer.classref_for_class_name("_OBJC_CLASS_$_UIWebView")` would return the bound symbol in the ObjC category 
declaration, which was incorrect and caused further bugs.
