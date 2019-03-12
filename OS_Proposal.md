Open Sourcing strongarm... question mark?
-----------------------------------------

I propose we open source the Mach-O parsing/cross-referencing APIs of strongarm, and keep the `CodeSearch` API for internal use.

Open sourcing strongarm would be positive for several reasons:

* Puts DataTheorem in a better position in terms of cool tech we can point to publicly (in addition to TrustKit, alfred, etc.)
* strongarm cannibalizes several popular Mach-O tools
    * Lots of people (and businesses, **including us!**) rely on random Github projects that might not always be maintained
    * strongarm scripts become a one-stop shop for various Mach-O questions/operations
* Provides a de-facto tool for cross-platform Mach-O scripting.
    * strongarm provides functionality of tools like otool and codesign, which are macOS only.
* General-purpose Mach-O library, and has more usefulness than what DataTheorem uses it for.
    * DataTheorem doesn't need/use every strongarm use case (SSLyze vs Redink)
    * strongarm can solve problems other people have, without any impact to DataTheorem aside from more goodwill in the world.
* It's something I put a lot of effort/heart in to, and it would be personally positive to be able to show it off

That said, it's dangerous to hand out something we rely on for highly technical checks. Thus, `CodeSearch` and related subclasses should be kept private.
They make it too easy to ask high-level questions about a binary's code, which can be used in straightforward ways to write security checks.

Even so, we may want to use some scary license that makes commercial use prohibitive. 
Personally, I think it's fair to give out the parsing/cross-referencing APIs and allow commercial use. 
After all, strongarm replaces tools like `insert_dylib`, a free project which we use commercially.

As part of this, we should also write and include several scripts which implement common tools in small strongarm scripts.
This would have a few benefits:

* Serves as API documentation
* Demonstrate API and scope
* Demonstrate how easy it is to extract/manipulate/cross-ref high-level data from Mach-O's

Open Source Components
---------------

* All Mach-O parsing/cross referencing APIs

    * Allows easy creation of scripts to query information about Mach-O's
        * Strings
        * Codesign information     
        * Segment/section information
        * Symbol imports/exports
        * ObjC selector/class/category data
        * etc
        
    * Replaces otool, nm, strings, classdump, some uses of jtool
        * **Platform agnostic** otool substitute
        
    * Allows modification of Mach-O's (planned feature)
        * Replaces insert_dylib, ldid, macho_edit, some uses of jtool
        
* CLI for interactive analysis of Mach-O's 

* Dataflow analysis (`get_register_contents_at_instruction`)
    * The CLI depends on DFA for annotating C and Objective-C calls in assembly.
    * Important part of `CodeSearch`, but has other uses throughout strongarm
    * **NOTE** This is implemented in C++ and works as a C Python extension. If we think the code is valuable, we can distribute the compiled extension rather than the C++ source.
    
* Function boundary detection (`find_function_boundary`)
    * The CLI depends on function boundary detection to disassemble methods
    * **NOTE** Same note as above

Closed Source Components
---------------

* API which allows simple searches through all a binary's code for execution points matching a query.
    * Allows creation of typically dynamic security checks. Specifically, checking for invocations of some 'unsafe' API.
    * This is the most business-critical portion of strongarm
    
Provided Scripts
---------------

* strongarm_nm
* strongarm_cli (shell which provides hex dumping, strings, otool, etc)
* strongarm_ldid
* strongarm_otool
* strongarm_strings
* strongarm_hexdump
* strongarm_classdump
* strongarm_macho_edit
* strongarm_extract_xar
* others? there are lots of random Mach-O projects with heavy use on github that are trivial to implement with strongarm, but I don't remember them all
