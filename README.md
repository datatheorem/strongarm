strongarm
============

strongarm is a library for parsing and analyzing Mach-O binaries.
strongarm includes a Mach-O/FAT archive parser as well as utilities for reconstructing flow from compiled ARM64 assembly.

The name 'strongarm' refers to both 'macho' and 'arm'.

Components
---------
* Mach-O Parser
    - `strongarm` module
    - includes `MachoParser` and `MachoBinary`,
    as well as contents of `macho_definitions.py`,
    which describes Mach-O header structures.
    - Map branch destinations to human-readable symbol names, even if the branch is to an external function
* ARM64 analyzer
    - `strongarm` module
    - track register data flow
    - resolve branches to external symbols
    - identify Objective-C blocks, their call locations,
    arguments, etc
    - check for calls to specific Objective-C selectors and their call locations
    - break functions into basic blocks
    - determine register contents at an arbitrary instruction index
    
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

### Branches and basic blocks

Imagine you have a set of assembly instructions which represent a function. 

In normal execution, these instructions would be executed sequentially one-by-one.
To analyze this function, you would iterate these instructions one-by-one. 

However, one class of instructions (branches) can actually redirect where the next instruction should be executed from.
This ability to redirect code execution splits the function into code chunks called basic blocks.

Each basic block is the destination of some branch instruction, and each basic block ends with its own branch instruction.
This even applies for the last basic block in a function, which would end in `ret`:
`ret`, internally, would really do something like `bx lr`, which branches back to the instruction after the one which
initiated the function call.

There a few boundaries which splits code into basic blocks:

At a branch instruction, the instruction immediately following the branch is the start of a new basic block. 
The branch instruction also marks the end of its basic block. This also applies to `ret`.

Additionally, whatever destination is targeted by the branch is the start of a basic block. By definition, the start
and end of functions are basic block boundaries, so every function has at least one basic block.

Branches are split into two classes: unconditional and conditional. 

Unconditional branches will jump to their
destination address no matter what, once the branch instruction is executed. A branch instruction might look like:
```
0x1000066ee    b #0x100008800
```
where `b` is a mnemonic for `branch`.

Conditional branches will jump to their destination address, but only if a bit in the status register is set.
The bit in the status register which is checked depends on the specific mnemonic used. For example, a function
could check if two numbers were equal, then jump to another basic block if so:
```
0x100004400    cmp x0, x1           <-- compare two registers for equality
0x100004404    b.eq #0x100004410    <-- pick a basic block based on result of comparison
0x100004408    mov x0, #3           <-- basic block 1, executed if branch failed
0x10000440c    b 0x100004414        <-- continue past comparison blocks
0x100004410    mov x0, #5           <-- basic block 2, executed if branch passed 
0x100004414    ....                 <-- basic block 3, executed after either basic block
```

### Yeah, so what?

In an assembly function, if there is an instruction with a conditional branch such as `cbz` ('compare and branch if 
zero-flag is set), we cannot statically determine which of the two possible basic-block destinations will be chosen
at runtime. 

Theoretically it would be possible to statically determine code paths for some runtime conditions we're interested in,
but I don't think this is a good thing to invest time in right now.

Again: when we see a conditional branch instruction, the test will either fail or succeed. As a result, one of
two basic blocks will be executed: if the test failed, the basic block directly following the branch instruction will
be run. If the test succeeded, the basic block at the branch destination will be run. 

And, we don't know whether a given test will fail or succeed.

Therefore, we can imagine that every test has a 50/50 chance of passing. To put this in more accurate terms, there are
two possible basic blocks that will be executed after a conditional branch, and we can say that 50% of 
existing code paths reach the first code path, and 50% reach the second code path.

Chaining this with other conditionals, we could identify some bad code, look at the conditional branches required to
pass for its basic block to be executed, and say that 12.5% of code paths hit this insecure code.

Is this useful? Would we ever want to report 'unsafe code path coverage' in a finding? 

i.e. 'there exists a code path 
where an SSL certificate is accepted without validation which is run in 25% of all code paths of the delegate method.
Here is the address and basic block of code where this happens, and the address and instructions for every test that
needs to pass at runtime for this to happen.'

### Taking dataflow tracking further

Thanks to strongarm's data-flow tracking, we can pretty accurately see any address being referenced in code.
This means, if we like, we can see which selector and class refs are being loaded and passed to objc_msgSend.

In turn, this means that we can actually model object allocations, ivar assignments, property set/gets, 
what objects are being returned by methods, etc. 

In addition to seeing what objects are returned by methods, we can see what immediates are returned by methods too.
In the case of multiple code paths, we can return a List of all possible return values, as well as their 
'code coverage percent', i.e. the percent of total code paths within the function that return a given return value.

### More cross-ref magic

Currently, you can get a List of implementations for a given selector. There's no reason we can't expand this,
and let the client also specify the desired class.

You could have an API where you specify the exact signature you're interested in, and strongarm will give you
an `ObjcFunctionAnalyzer` for it if it's found.

### One-off ideas

* We could see exactly which APIs are being accessed (`imported_functions`) - we could change that API so we can
query imported classes as well. Could report when an unsafe/deprecated API is used. "In function `-[ClassSignature
methodSignature]`, `UIAlertView` is created, which was deprecated in iOS x.x. Update to supported APIs."

    - We can also see exactly which private APIs are accessed, and where in the code. We don't even have to hard-code
    classes to look for, we can just look at the symbol entry and see the path the symbol is referenced from.
    If the path contains `/System/Library/PrivateFrameworks/` (or similar), we know a private API is being accessed.
    We could make an App Store Blocker check?

* Port 'privacy sensitive APIs' check from interject (what does that do?)

* If we implement the described idea for expanding dataflow tracking to see every object instantiation/associated
method calls, we can see exactly what filesystem paths are hit by the app. Maybe some FS paths are insecure/shared by
apps? Ask Alban. Could also see keychain access maybe. See when app spawns/listens to local web server?

* Could have two data flow routines: `determine_register_contents_basic`, which is a bootstrap to mark basic blocks, 
and reads instructions in reverse-sequential order to determine register contents (which ignores control flow).
Once we have basic blocks parsed, we could have `determine_register_contents_control_flow`, which will 
read register contents but respect basic blocks. How could we specify which code paths to take?

* Check if critical validation delegates have really short implementations?

* Again, depending on how far we go with tracking object references, we could look at `-didReceiveMemoryWarning`
implementations and see how much resources are being freed. We could do similar behavior with other system-wide
event delegates. Maybe the app has a camera view that doesn't get paused when app gets a telephony notification, 
or something.

* I still like the idea of looking for high entropy strings in `sections[__cstring]`. Would have to fiddle with 
thresholds, but I think it could be useful. Could even just do regex checks if gammaray doesn't already (does it?)

* We can see all protocols any class conforms to, along with the class hierarchy. Objc leaves lots of runtime data
in the MachO.

* We can look if an app passes `nil` to an `error:` out-parameter, or `nil` to a completion block. This could allow us
to create some interesting checks.

On the same note, we could even look at any system API accessed, and see what arguments are being passed in every
invocation of a given signature. This could be seperated from a single `ObjcFunctionAnalyzer`.

For example, we could take the whole binary, and call 
`get_invocation_arguments('NSURL', 'dataTaskWithURL:completionHandler:)`, which would return a List like:
```
('https://google.com', 0x100008800),
('http://my_unsafe_site.com', nil),
```

### Rewrite of Data Dependency to be more efficient for analyzing entire binaries

todo - while writing this, I realized dataflow analysis might do the wrong thing with sub instruction, because
it always just takes the immediate as a signed offset, so the sign would be wrong. Think about if this happens with
any other instructions?

todo - make data dependency respect basic blocks! 

### Dataflow Analysis? More about that!

Currently, the API for performing dataflow analysis is reachable through `ObjcFunctionAnalyzer.`
`determine_register_contents(desired_reg, start_index)`. The algorithm is split into a few main tasks:

1) Search the instructions in the function up to start_index, marking every register which contains some piece of data
which is eventually combined into the value of `desired_reg`. 

All of the integer values in these marked registers must be determined to determine the final value of `desired_reg`. 
This means that for every register marked by 1), we must repeat 1) with the marked register as `desired_reg`, 
so we obtain the full dependency tree of registers whose values must be known before the original `desired_reg` can 
be calculated.

Because of this, work expands:

2) In addition, we must also mark any register which has data needed by any of the registers which 
`desired_reg` needs to be resolved. 

When we do find an immediate value for a register, store the register along with its value. 

An immediate value for a register looks like this:
```
0x1000044cc    ldr x16, #0xdeadbeef
```
Thus, a resolved register value might be stored as `x16: 0xdeadbeef`

If we see a register depending on another, store that the register has a 'data dependency' for the other register.
A register depending on another register for its value looks like this:
```
0x1000044cc    adrp x3, [x5 #0xdeadbeef]
```
Here, before we can say what's in `x3`, we need to know what's in `x5`, and then we know to offset `x5`'s value by
`0xdeadbeef` to get `x3`'s value at this instruction. Thus, a data dependency can be stored as `x3: (x5, 0xdeadbeef)`

Now that we know the chain of all registers that need known values to compute `desired_reg`, we need to resolve
that whole chain.

3) For every register in the dependency chain, use the rest of the chain to resolve its value. 
Do this recursively until `desired_reg` has been resolved.

### Make it better?

todo - even only analyze a func for the first time when it's requested, not the whole binary at once

Right now, you have to make a call to `determine_register_contents` each time you want to find the contents of any
register any time, and every time it goes through the ordeal of the above. Steps 1 and 2 are combined into an O(n) loop
over the instruction count of the function, and step 3 is O(n^2) over the size of the register dependency chain.

If we want strongarm to be able to do lots of on-the-fly analysis over a whole binary, this is just not feasible.
Luckily, we can vastly improve the overall speed of binary analysis if we eat the cost of dataflow analysis upfront:

The first time we're asked to analyze a register in a function, do this:

Unlike `ObjcFunctionAnalyzer.determine_register_contents()` which resolves backwards, we should just read the function
sequentially and record the register state at every instruction index. This is kind of similar to actually running
the code. 

We can use basic dataflow, `ObjcFunctionAnalyzer.determine_register_contents`, to find basic block boundaries.
Then, we can find register values while respecting basic blocks! This means that for any instruction index in the 
function, we can report the correct value for any client-chosen register based on any client-chosen code path!

This is an inefficient description that we can improve, but to provide a model:
Store a List the same size as the function instruction list. 
At each index, have a map of register names, r0 to r30, including pc, to their immediate value at index (or unassigned). 
In the far future, this map could even include the stack pointer.

I guess what I'm describing here is an arm64 interpreter which saves machine state snapshots at every instruction
in the binary.

The above could also only happen once for every function, and would only be done on a function the first time a
register value lookup for that function is requested.

Using the cross ref'ing of classrefs and selrefs, we can actually do higher-level interpretation of code, and track
object lifecycles/states. 
We can have a check to if a method is called on a specific instance of an object, if an
ivar value ever equals a certain value, if certain objects are created, if classes/methods are accessed, introspect 
stuff about an object at certain points in code, whatever we want. 
Lots of cool possibilities in this space.

If we rewrite dataflow analysis to do this, strongarm could be seen as either a strong static analysis tool, or an
ARM simulator
It's hard to argue, with the above scheme, that we are not interpreting assembly, or simulating the 
CPU with extra steps. 
Kind of crazy, I don't know where this could go. If it gets advanced enough, we could even port 'dynamic' checks?
No idea. 

I'd really really like some input here, there's so many places we could take this but I think I need someone to tell
me what's feasible/valuable and what isn't.

Things like this from aster can totally be ported to strongarm:
```python
class ClassSignatureFilter(AndroguardCodeFilter):
    """
    Find a class whose name matches a specific classname or extends a mentioned superclass or implements a list of
        interfaces or has a specific method
    """
```

### Finding entry points

We need a way to iterate every class's methods, or simply every function entry point. 

Looking at the ObjC class data in the MachO header is likely a good approach as it gives an easy way to iterate
each class's selectors, and we'll know exactly which class/SEL is being iterated.

The downside of that is it will miss C functions. However, while analyzing, we can look at branch destinations
and add them to our function entry list if not already in it (similar to what `ObjcFunctionAnalyzer.can_execute_call()`
does).

The downside of _that_ is it means we need to iterate the entire binary if we want to have a complete list of all 
branch destinations before we begin analyzing.

So, here's the approach:

`MachoEntryPoint.get_objc_entry_points()` will return a `List[MachoEntryPoint]` only containing the IMPs
described by MachO sections. We can then iterate this list and find any other functions/method that weren't caught
just by looking at ObjC sections:
```python
def scan_binary(binary):
    unscanned_targets = MachoEntryPoint.get_objc_entry_points(binary)
    scanned_targets = []

    # we're going to incrementally add to unscanned_targets, so loop while it contains anything
    while len(unscanned_targets):
        # make copy of list so we can modify it
        for function in list(unscanned_targets):
            # ...
            # do some work here
            # ...
            if function.is_c_function:
                print('C function at {}'.format(hex(function.address)))
            elif function.is_objc_method:
                print('-[{} {}] at {}'.format(function.objc_class, function.objc_selector, hex(function.address)))
            
            # track anything reachable from this function
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(binary, function.start_address)
            functions_reachable_from_here = function_analyzer.call_targets
            for reachable_function in functions_reachable_from_here:
                # skip functions that we already know about
                if reachable_function in unscanned_targets + scanned_targets:
                    continue
                unscanned_targets.append(reachable_function)
    # once we exit the above loop, we've iterated every Objc method in the binary, as well as any C functions
    # referenced by any Objc method
```
