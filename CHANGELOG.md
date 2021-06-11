# Changelog

## 2020-06-11 10.5.7

### SCAN-2740: Improve log and error messages

### SCAN-2666: Speed up MachoAnalyzer.class_name_for_class_pointer()

### SCAN-2658: Read strings from __const section

## 2020-03-16 10.5.6

### SCAN-2515: Prevent a NULL-dereference when building XRef table of a malformed binary

## 2020-02-16 10.5.5

### SCAN-783: Avoid shell injection when invoking c++filt

Disclosed by Keegan Saunders <keegan@undefinedbehaviour.org>

Also, drop `DebugUtil` in favor of the standard library's `logging` module.

## 2020-02-10 10.5.3

## 2020-02-16 10.5.4

### SCAN-783: Bump strongarm-dataflow to 2.1.4

## 2020-02-10 10.5.3

### SCAN-783: Validate capstone install upon failing to import strongarm_dataflow

The cause of the failed import may be a linking error when the C-ext tries to link capstone. 
If this is the case, report it more cleanly to the user so it’s clear what’s going on.

## 2020-02-02 10.5.2

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
