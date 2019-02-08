I propose we open source the entirety of strongarm, **excluding** the `CodeSearch` API and related subclasses.

As part of this effort, we should also write and include several scripts which reimplement common tools in small strongarm scripts.
This has several benefits, such as demonstrating strongarm's API and scope. 

Open Source
---------------
* All Mach-O parsing/cross referencing APIs

    * Allows easy creation of scripts to query information about Mach-O's
        * Strings
        * Codesign information     
        * Segment/section information
        * Symbol imports/exports
        * ObjC selector/class/category data
        
    * Replaces otool, nm, strings, some uses of jtool
        * Platform agnostic otool substitute
        
    * TBD allows modification of Mach-O's
        * Replaces insert_dylib, ldid, some uses of jtool
        
* CLI for interactive analysis of Mach-O's

* Dataflow analysis
    * While this is used heavily within `CodeSearch`, it has other uses throughout strongarm.
    * The CLI depends on DFA for annotating C and Objective-C calls in assembly.
    
* Function boundary detection
    * The CLI depends on function boundary detection to disassemble methods

Closed Source
---------------
* API which allows searching through code for execution points matching a query
    * Allows creation of typically dynamic security checks. Specifically, checking for invocations of some 'unsafe' API.
    * This is the most business-critical portion of strongarm
    
Scripts
---------------
* strongarm-nm
* strongarm-cli
* strongarm-ldid
* strongarm-otool
* strongarm-strings
* strongarm-hexdump
* strongarm-classdump
