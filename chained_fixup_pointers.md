# iOS 15's chained fixup pointers support

A Mach-O contains 2 things of note to this discussion:

* Internal pointers

  * For example, a pointer from __objc_selrefs to the selector literal in another section

* External pointers

  * For example, the superclass pointer of an __objc_class pointing to _OBJC_CLASS_$_NSObject

The first set of pointers need to be adjusted based on where ASLR loads the binary, and the operation associated with adjusting them is called “rebasing”. The second set of pointers need to be set to the respective addresses of where dyld has loaded their source binary, and this operation is called “binding”.

To carry these out when a binary is loaded, dyld needs to know where all the rebases and bind operations in the binary need to be performed, as well as some metadata associated with them - in other words, where all of the internal / external pointers in the binary are located, and (for example) what external symbol the latter pointers should be bound to.

In pre-iOS 15 binaries, this works like so:

There is a load command, LC_DYLD_INFO, that will give an offset into __LINKEDIT. There is an interpreter byte code stream here that, when interpreted, will generate the lists of rebases and binds. dyld will then perform these operations.

Prior to dyld performing the operations (i.e. what strongarm sees), this is the state of each pointer:

* Each pointer that is to be rebased contains its real destination value, but the ASLR slide is assumed to be 0x100000000 
  
  * For example, the static binary will contain section.__objc_selrefs.0x100005000: 0x100000f000

    * If ASLR loads the binary at 0x230000000, the pointer at 0x230005000 will be rebased to contain the address 0x23000f000.

* Each pointer that is to be bound contains a dummy value of 0x00000000

  * Be careful, Hopper will lie and pretend that these addresses contain a pointer to an address within Hopper’s fake “External Symbols” section. Switch to hex-editor mode to show that they’re really zeroes.

iOS 15 changes this system and does away with the interpreted bytecode that produces the tables indicating where these pointers are. This is how the new scheme works:

There is a load command, LC_DYLD_CHAINED_FIXUPS, that will give an offset into __LINKEDIT. This offset will be the start of a series of structures describing the locations of “pointer chains” in other parts of the binary. dyld will then traverse these pointer chains to find rebases and binds, and perform them.

Prior to dyld performing the operations (i.e. what strongarm sees), this is the state of each pointer:

* Each pointer that is to be rebased contains a packed structure (a “fixup pointer”). This packed structure contains a few pieces of information:

    * The distance to the next fixup pointer

    * The offset to the internal pointer destination

    * A bit indicating that this is a rebase, not a bind

    * For example, the static binary will contain section.__objc_selrefs.0x100005000: 0x20000000a000

      * This packed structure tells us that the next fixup pointer in the chain is 2 uint32_t's away, and that the offset to the internal destination is 0xa000 bytes away

      * If ASLR loads the binary at 0x230000000, the pointer at 0x230005000 will be rebased to contain the address 0x23000f000.

* Each pointer that is to be bound contains a packed structure (another fixup pointer, with different fields). This packed structure will contain some other information:

    * The distance to the next fixup pointer

    * An index into a table in __LINKEDIT that, when looked up, will give the symbol name and source dylib that this pointer is bound to

    * A bit indicating that this is a bind, not a rebase

Since strongarm has long assumed that rebases contain valid pointers, and not the “garbage pointer” that a fixup appears to be at first glance, I’ve changed strongarm such that the first thing it does is rewrite chains of rebases to contain the pre-iOS-15-style addresses. The binary is then re-parsed as normal.

