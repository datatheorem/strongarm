Open Sourcing Strongarm
-----------------------

strongarm is a valuable library for interpreting Mach-O exectuables with (I think) a usable and relatively 
understandable API. Open sourcing strongarm would be positive in a few ways: it gets name recognition 
for DT, it gives us yet another technology to point to, helps the community, etc. 

However, by retaining key parts of the source, we can maintain a competitive advantage over anyone who 
does end up using strongarm.

Specifically, I think parts of these APIs represent a competitive advantage:

* `ObjcFunctionAnalyzer`
    - Parent class for most code analysis
* `ObjcBlockAnalyzer`
    - Function analyzer with utilities for analyzing block invocations
* `ObjcQuery`
    - Implementation of searching through code and matching predicates

However, not all functionality in these APIs should be removed from the open-source version.

# Reserved functionality

## ObjcFunctionAnalyzer breakdown

#### Remove from open-source version
* `ObjcFunctionAnalyzer.call_targets()`
    - Find the list of call addresses which originate from a source function (code analysis)

* `ObjcFunctionAnalyzer.function_call_targets()`
    - Find a list of _implemented_ functions originating from a source function. Each entry in the list is a 
    code-backed function analyzer (code analysis)

* `ObjcFunctionAnalyzer.search_code()`
    - Executes a code search (code analysis)

* `ObjcFunctionAnalyzer.search_call_graph()`
    - Code searches on paths from a source code function. Note: One cool use case of this would be if 
    you hooked it up to some code looking at basic blocks, you could do symbolic execution of a binary.
    
* `ObjcFunctionAnalyzer.get_register_contents_at_instruction()`
    - Function-level symbolic execution to determine a register's value (code analysis)
    
* `ObjcFunctionAnalyzer.get_selref_ptr()`
    - Find the selref targeted by a branch to `objc_msgSend`. 
    - This function is helpful 
    for analyzing Objective-C code, but there's no way to include 
    it in the OS version without open sourcing the data-flow tracking too.

#### Keep in open-source version

* `ObjcFunctionAnalyzer.get_local_branches()`
    - Find a list of the local labels within the function. 
    - This is technically code analysis, but it's used to 
    derive basic block info too and if the client knows basic block addresses then they can trivially calculate 
    this, so it only saves work.

* `ObjcFunctionAnalyzer.track_reg()`
    - TODO(PT): deprecate this
    
* `ObjcFunctionAnalyzer.next_branch_after_instruction_index()`
    - Find the next branch instruction after a given mnemonic. Trivial code analysis
    
## ObjcBlockAnalyzer breakdown

#### Remove from open-source version

* `ObjcBlockAnalyzer.find_block_invoke()`
    - Track the block argument to the function to its invocation. (code analysis)
    
## ObjcQuery breakdown

#### Remove from open-source version

All `CodeSearch` functionality and support classes  should be stripped from the open-source version, as they depend on
code analysis.

# Ambiguous

These classes could either be retained or stripped in the open source version:

* `ObjcRuntimeDataParser`
    - Data-provider for much of the `MachoAnalyzer` methods which return info about the Objective-C data within a
    binary. 
    - This includes all of the info about the Objective C classes and selectors implemented in the binary, their
    signatures, implementation locations, class properties, ivars, selref locations, etc. 
    - Additionally, this class provides data on the imported/exported symbols of the binary, methods for resolving 
    information about linked binaries, etc. All of this is valuable information for introspecting a binary implementing
    Objective-C code.
    
# Safe to open-source

All of these classes provide useful utilities for introspecting on a Mach-O:

* `MachoParser`
    - Top-level Mach-O parser
    
* `MachoBinary`
    - Representation of a parsed Mach-O slice. 
    - Provides utilities for reading info, such as extracting segments +
     sections, reading data at a given offset, reading __cstring / Core Foundation strings, 
     
* `MachoAnalyzer`
    - Aggregates resolved info from other internal sources. 
    - Some parts of this will have to be trimmed out in the open sourced version, as this class contains functions 
    which call-through to code analysis methods. An example is `MachoAnalyzer.search_code()`
    - `MachoAnalyzer` also resolves branch destinations -> external symbol names, which I think should be retained.
    - `MachoAnalyzer.find_function_boundary()`/`MachoAnalyzer.get_function_instructions()` are useful for 
    disassembling functions and, I think, should be retained
    
* `ObjcBasicBlock`
    - Analyzes a function and splits it into basic block regions. 
    - We don't use this for anything internally yet, so it should be fine to open source.
 
* `ObjcInstruction` (and subclasses)
    - Encapsulate CsInsn instructions in a higher-level abstraction which gives some more useful info,
    such as the Objective-C messages targeted by a branch instruction. 


