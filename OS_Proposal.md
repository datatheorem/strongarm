I propose we open source the Mach-O parsing/cross-referencing APIs of strongarm, and keep the `CodeSearch` API for internal use.

Open sourcing strongarm would be positive for several reasons:
    * Puts DT in a better position in terms of tech we can point to publicly (in addition to TrustKit, alfred, etc.)
    * As strongarm cannibalizes several popular Mach-O tools, strongarm scripts become a one-stop-shop for various Mach-O questions people like me often need to ask.
        * Lots of people (and businesses, including us!) rely on these random Github projects that aren't always maintained
    * Provides a de-facto tool for cross-platform Mach-O scripting.
        * strongarm provides functionality of tools like otool and codesign, which are macOS only.
    * It's something I put a lot of effort/heart in to, and it would be personally positive to be able to show it off
    
That said, it's dangerous to hand out something we rely on for highly technical checks. Thus, `CodeSearch` and related subclasses should be kept private.
They make it too easy to ask high-level questions about a binary's code, which can be used in straightforward ways to write security checks.

Even so, we may want to use some scary license that makes commercial use prohibitive. 
Personally, I think it's fair to give out the parsing/cross-referencing APIs and allow commercial use. 
After all, strongarm replaces tools like `insert_dylib`, a free project which we use commercially.

As part of this, we should also write and include several scripts which implement common tools in small strongarm scripts.
This would have a few benefits:
    * Demonstrating strongarm's API and scope
    * Demonstrating how easy it is to extract and manipulate high-level data from Mach-O's
    * Serve as API documentation

Open Source
---------------
* All Mach-O parsing/cross referencing APIs

    * Allows easy creation of scripts to query information about Mach-O's
        * Strings
        * Codesign information     
        * Segment/section information
        * Symbol imports/exports
        * ObjC selector/class/category data
        
    * Replaces otool, nm, strings, classdump, some uses of jtool
        * Platform agnostic otool substitute
        
    * Allows modification of Mach-O's (planned feature)
        * Replaces insert_dylib, ldid, macho_edit, some uses of jtool
        
* CLI for interactive analysis of Mach-O's 

* Dataflow analysis (`get_register_contents_at_instruction`)
    * While this is used heavily within `CodeSearch`, it has other uses throughout strongarm.
    * The CLI depends on DFA for annotating C and Objective-C calls in assembly.
    * *NOTE* this is implemented in C++ and works as a C Python extension. If we think the code is valuable, we can distribute the compiled extension rather than the C++ source.
    
* Function boundary detection
    * The CLI depends on function boundary detection to disassemble methods

Closed Source
---------------
* API which allows searching through code for execution points matching a query
    * Allows creation of typically dynamic security checks. Specifically, checking for invocations of some 'unsafe' API.
    * This is the most business-critical portion of strongarm
    
Scripts
---------------
* strongarm_nm
* strongarm_cli (provides hex dumping, strings, otool, etc)
* strongarm_ldid
* strongarm_otool
* strongarm_strings
* strongarm_hexdump
* strongarm_classdump
* strongarm_macho_edit
* strongarm_extract_xar
* others? there are lots of random Mach-O projects with heavy use on github that are trivial to implement with strongarm, but I don't remember them all
