import struct
from ctypes import Structure, Union, c_char, c_char_p, c_int16, c_int32, c_uint8, c_uint16, c_uint32, c_uint64
from enum import IntEnum
from typing import TypeVar

_BasePointerT = TypeVar("_BasePointerT", bound="_BasePointer")


class _BasePointer(int):
    def __add__(self: _BasePointerT, other: int) -> _BasePointerT:
        return type(self)(super().__add__(other))

    def __sub__(self: _BasePointerT, other: int) -> _BasePointerT:
        return self.__class__(super().__sub__(other))

    def __mul__(self: _BasePointerT, other: int) -> _BasePointerT:
        return self.__class__(super().__mul__(other))

    def __truediv__(self: _BasePointerT, other: int) -> _BasePointerT:
        return self.__class__(super().__truediv__(other))

    def __floordiv__(self: _BasePointerT, other: int) -> _BasePointerT:
        return self.__class__(super().__floordiv__(other))

    def __str__(self) -> str:
        return hex(self)

    def __repr__(self) -> str:
        return hex(self)


class StaticFilePointer(_BasePointer):
    """A pointer analogous to a file offset within the Mach-O
    """

    def __str__(self) -> str:
        return f"Phys[{super().__str__()}]"

    def __repr__(self) -> str:
        return f"Phys[{super().__repr__()}]"


class VirtualMemoryPointer(_BasePointer):
    """A pointer representing a virtual memory location within the Mach-O
    """


def swap32(i: int) -> int:
    """Reverse the bytes of a little-endian integer representation ie (3) -> 50331648"""
    return struct.unpack("<I", struct.pack(">I", i))[0]


class MachArch(IntEnum):
    MH_MAGIC = 0xFEEDFACE
    MH_CIGAM = 0xCEFAEDFE
    MH_MAGIC_64 = 0xFEEDFACF
    MH_CIGAM_64 = 0xCFFAEDFE

    FAT_MAGIC = 0xCAFEBABE
    FAT_CIGAM = 0xBEBAFECA

    MH_CPU_ARCH_ABI64 = 0x01000000
    MH_CPU_TYPE_ARM = 12
    MH_CPU_TYPE_ARM64 = MH_CPU_TYPE_ARM | MH_CPU_ARCH_ABI64

    DYLD_SHARED_CACHE_MAGIC = 0x646C7964  # b'dyld'


class VMProtFlags(IntEnum):
    # https://opensource.apple.com/source/xnu/xnu-1504.7.4/osfmk/mach/vm_prot.h.auto.html
    VM_PROT_NONE = 0 << 0
    VM_PROT_READ = 1 << 0
    VM_PROT_WRITE = 1 << 1
    VM_PROT_EXECUTE = 1 << 2


class CPU_TYPE(IntEnum):
    ARMV7 = 0
    ARM64 = 1
    UNKNOWN = 2


class MachoFileType(IntEnum):
    MH_OBJECT = 1  # relocatable object file
    MH_EXECUTE = 2  # demand paged executable file
    MH_FVMLIB = 3  # fixed VM shared library file
    MH_CORE = 4  # core file
    MH_PRELOAD = 5  # preloaded executable file
    MH_DYLIB = 6  # dynamically bound shared library
    MH_DYLINKER = 7  # dynamic link editor
    MH_BUNDLE = 8  # dynamically bound bundle file
    MH_DYLIB_STUB = 9  # shared library stub for static linking only, no section contents
    MH_DSYM = 10  # shared library stub for static
    MH_KEXT_BUNDLE = 11  # x86_64 kext


class MachoHeader32(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("cputype", c_uint32),
        ("cpusubtype", c_uint32),
        ("filetype", c_uint32),
        ("ncmds", c_uint32),
        ("sizeofcmds", c_uint32),
        ("flags", c_uint32),
    ]


class MachoHeader64(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("cputype", c_uint32),
        ("cpusubtype", c_uint32),
        ("filetype", c_uint32),
        ("ncmds", c_uint32),
        ("sizeofcmds", c_uint32),
        ("flags", c_uint32),
        ("reserved", c_uint32),
    ]


class MachoLoadCommand(Structure):
    _fields_ = [("cmd", c_uint32), ("cmdsize", c_uint32)]


class MachoSegmentCommand32(Structure):
    _fields_ = [
        *MachoLoadCommand._fields_,
        ("segname", c_char * 16),
        ("vmaddr", c_uint32),
        ("vmsize", c_uint32),
        ("fileoff", c_uint32),
        ("filesize", c_uint32),
        ("maxprot", c_uint32),
        ("initprot", c_uint32),
        ("nsects", c_uint32),
        ("flags", c_uint32),
    ]


class MachoSegmentCommand64(Structure):
    _fields_ = [
        *MachoLoadCommand._fields_,
        ("segname", c_char * 16),
        ("vmaddr", c_uint64),
        ("vmsize", c_uint64),
        ("fileoff", c_uint64),
        ("filesize", c_uint64),
        ("maxprot", c_uint32),
        ("initprot", c_uint32),
        ("nsects", c_uint32),
        ("flags", c_uint32),
    ]


class MachoSection32Raw(Structure):
    _fields_ = [
        ("sectname", c_char * 16),
        ("segname", c_char * 16),
        ("addr", c_uint32),
        ("size", c_uint32),
        ("offset", c_uint32),
        ("align", c_uint32),
        ("reloff", c_uint32),
        ("nreloc", c_uint32),
        ("flags", c_uint32),
        ("reserved1", c_uint32),
        ("reserved2", c_uint32),
    ]


class MachoSection64Raw(Structure):
    _fields_ = [
        ("sectname", c_char * 16),
        ("segname", c_char * 16),
        ("addr", c_uint64),
        ("size", c_uint64),
        ("offset", c_uint32),
        ("align", c_uint32),
        ("reloff", c_uint32),
        ("nreloc", c_uint32),
        ("flags", c_uint32),
        ("reserved1", c_uint32),
        ("reserved2", c_uint32),
        ("reserved3", c_uint32),
    ]


class MachoDysymtabCommand(Structure):
    """Python representation of struct dysymtab_command

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [
        *MachoLoadCommand._fields_,
        ("ilocalsym", c_uint32),
        ("nlocalsym", c_uint32),
        ("iextdefsym", c_uint32),
        ("nextdefsym", c_uint32),
        ("iundefsym", c_uint32),
        ("nundefsym", c_uint32),
        ("tocoff", c_uint32),
        ("ntoc", c_uint32),
        ("modtaboff", c_uint32),
        ("nmodtab", c_uint32),
        ("extrefsymoff", c_uint32),
        ("nextrefsyms", c_uint32),
        ("indirectsymoff", c_uint32),
        ("nindirectsyms", c_uint32),
        ("extreloff", c_uint32),
        ("nextrel", c_uint32),
        ("locreloff", c_uint32),
        ("nlocrel", c_uint32),
    ]


class MachoSymtabCommand(Structure):
    """Python representation of struct symtab_command

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [
        *MachoLoadCommand._fields_,
        ("symoff", c_uint32),
        ("nsyms", c_uint32),
        ("stroff", c_uint32),
        ("strsize", c_uint32),
    ]


class MachoDyldInfoCommand(Structure):
    """Python representation of struct dyld_info_command

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [
        *MachoLoadCommand._fields_,
        ("rebase_off", c_uint32),
        ("rebase_size", c_uint32),
        ("bind_off", c_uint32),
        ("bind_size", c_uint32),
        ("weak_bind_off", c_uint32),
        ("weak_bind_size", c_uint32),
        ("lazy_bind_off", c_uint32),
        ("lazy_bind_size", c_uint32),
        ("export_off", c_uint32),
        ("export_size", c_uint32),
        ("weak_bind_size", c_uint32),
        ("weak_bind_size", c_uint32),
    ]


class MachoLinkeditDataCommand(Structure):
    """Python representation of struct linkedit_data_command

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [*MachoLoadCommand._fields_, ("dataoff", c_uint32), ("datasize", c_uint32)]


class MachoBuildVersionCommand(Structure):
    """Python representation of struct build_version_command

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [
        *MachoLoadCommand._fields_,
        ("platform", c_uint32),
        ("minos", c_uint32),
        ("sdk", c_uint32),
        ("ntools", c_uint32),
    ]


class MachoBuildVersionPlatform(IntEnum):
    MACOS = 1
    IOS = 2
    TVOS = 3
    WATCHOS = 4
    BRIDGEOS = 5
    IOSMAC = 6
    MACCATALYST = 6
    IOSSIMULATOR = 7
    TVOSSIMULATOR = 8
    WATCHOSSIMULATOR = 9
    DRIVERKIT = 10


class MachoBuildToolVersion(Structure):
    """Python representation of struct build_tool_version

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [
        ("tool", c_uint32),
        ("version", c_uint32),
    ]


class MachoBuildTool(IntEnum):
    CLANG = 1
    SWIFT = 2
    LD = 3


class MachoNlistUn(Union):
    """Python representation of union n_un

    Definition found in <mach-o/nlist.h>
    """

    __slots__ = ["n_strx"]
    _fields_ = [("n_strx", c_uint32)]


class MachoNlist32(Structure):
    """Python representation of struct nlist

    Definition found in <mach-o/nlist.h>
    """

    __slots__ = ["n_un", "n_type", "n_sect", "n_desc", "n_value"]
    _fields_ = [
        ("n_un", MachoNlistUn),
        ("n_type", c_uint8),
        ("n_sect", c_uint8),
        ("n_desc", c_int16),
        ("n_value", c_uint32),
    ]


class MachoNlist64(Structure):
    """Python representation of struct nlist_64

    Definition found in <mach-o/nlist.h>
    """

    __slots__ = ["n_un", "n_type", "n_sect", "n_desc", "n_value"]
    _fields_ = [
        ("n_un", MachoNlistUn),
        ("n_type", c_uint8),
        ("n_sect", c_uint8),
        ("n_desc", c_uint16),
        ("n_value", c_uint64),
    ]


class MachoEncryptionInfo32Command(Structure):
    """Python representation of a struct encryption_info_command

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [*MachoLoadCommand._fields_, ("cryptoff", c_uint32), ("cryptsize", c_uint32), ("cryptid", c_uint32)]


class MachoEncryptionInfo64Command(Structure):
    """Python representation of a struct encryption_info_command_64

    Definition found in <mach-o/loader.h>
    """

    _fields_ = [
        *MachoLoadCommand._fields_,
        ("cryptoff", c_uint32),
        ("cryptsize", c_uint32),
        ("cryptid", c_uint32),
        ("pad", c_uint32),
    ]


class MachoFatHeader(Structure):
    """Python representation of a struct fat_header

    Definition found in <mach-o/fat.h>
    """

    _fields_ = [("magic", c_uint32), ("nfat_arch", c_uint32)]


class MachoFatArch(Structure):
    """Python representation of a struct fat_arch

    Definition found in <mach-o/fat.h>
    """

    _fields_ = [
        ("cputype", c_uint32),
        ("cpusubtype", c_uint32),
        ("offset", c_uint32),
        ("size", c_uint32),
        ("align", c_uint32),
    ]


class DyldSharedCacheHeader(Structure):
    # https://opensource.apple.com/source/dyld/dyld-655.1.1/launch-cache/dyld_cache_format.h.auto.html
    _fields_ = [
        ("magic", c_char * 16),  # e.g. "dyld_v1   arm64"
        ("mappingOffset", c_uint32),  # file offset to first shared_file_mapping
        ("mappingCount", c_uint32),  # number of shared_file_mapping entries
        ("imagesOffset", c_uint32),  # file offset to first dyld_cache_image_info
        ("imagesCount", c_uint32),  # number of dyld_cache_image_info entries
        ("dyldBaseAddress", c_uint64),  # base address of dyld when cache was built
        ("codeSignOffset", c_uint64),  # file offset of code signature blob
        ("codeSignSize", c_uint64),  # size of code signature blob
        ("slideInfoOffset", c_uint64),  # file offset of kernel slid info
        ("slideInfoSize", c_uint64),  # size of kernel slid info
        ("localSymbolsOffset", c_uint64),  # file offset where local symbols are stored
        ("localSymbolsSize", c_uint64),  # size of local symbols
        ("uuid", c_char * 16),  # unique value for each shared_cache file
        ("cacheType", c_uint64),  # 0 for dev, 1 for prod
        ("branchPoolsOffset", c_uint32),  # file offset to table of uint64_t pool addresses
        ("branchPoolsSize", c_uint32),  # number of uint64_t entries
        ("accelerateInfoAddr", c_uint64),  # (unslid) address of optimization info
        ("accelerateInfoSize", c_uint64),  # size of optimization info
        ("imagesTextOffset", c_uint64),  # file offset to first dyld_cache_image_text_info
        ("imagesTextCount", c_uint64),  # number of dyld_cache_image_text_info entries
    ]


class DyldSharedFileMapping(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("size", c_uint64),
        ("file_offset", c_uint64),
        ("max_prot", c_uint32),
        ("init_prot", c_uint32),
    ]


class DyldSharedCacheImageInfo(Structure):
    _fields_ = [
        ("address", c_uint64),
        ("modTime", c_uint64),
        ("inode", c_uint64),
        ("pathFileOffset", c_uint32),
        ("pad", c_uint32),
    ]


class NLIST_NTYPE(IntEnum):
    N_STAB = 0xE0  # symbollic debugging entry
    N_PEXT = 0x10  # private external symbol bit
    N_TYPE = 0x0E  # mask for type bits
    N_EXT = 0x01  # external symbol bit


class NTYPE_VALUES(IntEnum):
    N_UNDF = 0x0  # undefined, n_sect == NO_SECT
    N_ABS = 0x2  # absolute, n_sect == NO_SECT
    N_SECT = 0xE  # defined in section n_sect
    N_PBUD = 0xC  # prebound undefined (defined in a dylib)
    N_INDR = 0xA  # indirect


class HEADER_FLAGS(IntEnum):
    NOUNDEFS = 0x1
    INCRLINK = 0x2
    DYLDLINK = 0x4
    BINDATLOAD = 0x8
    PREBOUND = 0x10
    SPLIT_SEGS = 0x20
    LAZY_INIT = 0x40
    TWOLEVEL = 0x80
    FORCE_FLAT = 0x100
    NOMULTIDEFS = 0x200
    NOFIXPREBINDING = 0x400
    PREBINDABLE = 0x800
    ALLMODSBOUND = 0x1000
    SUBSECTIONS_VIA_SYMBOLS = 0x2000
    CANONICAL = 0x4000
    WEAK_DEFINES = 0x8000
    BINDS_TO_WEAK = 0x10000
    ALLOW_STACK_EXECUTION = 0x20000
    ROOT_SAFE = 0x40000
    SETUID_SAFE = 0x80000
    NO_REEXPORTED_DYLIBS = 0x100000
    PIE = 0x200000
    DEAD_STRIPPABLE_DYLIB = 0x400000
    HAS_TLV_DESCRIPTORS = 0x800000
    NO_HEAP_EXECUTION = 0x1000000
    APP_EXTENSION_SAFE = 0x2000000


# Some of these can be found at
# https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.h.auto.html


class ObjcProtocolRaw32(Structure):
    _fields_ = [
        ("isa", c_uint32),
        ("name", c_uint32),
        ("protocols", c_uint32),
        ("required_instance_methods", c_uint32),
        ("required_class_methods", c_uint32),
        ("optional_instance_methods", c_uint32),
        ("optional_class_methods", c_uint32),
        ("instance_properties", c_uint32),
        ("instance_properties", c_uint32),
        ("size", c_uint32),
        ("flags", c_uint32),
    ]


class ObjcProtocolRaw64(Structure):
    _fields_ = [
        ("isa", c_uint64),
        ("name", c_uint64),
        ("protocols", c_uint64),
        ("required_instance_methods", c_uint64),
        ("required_class_methods", c_uint64),
        ("optional_instance_methods", c_uint64),
        ("optional_class_methods", c_uint64),
        ("instance_properties", c_uint64),
        ("instance_properties", c_uint64),
        ("size", c_uint32),
        ("flags", c_uint32),
    ]


class ObjcCategoryRaw32(Structure):
    _fields_ = [
        ("name", c_uint32),
        ("base_class", c_uint32),
        ("instance_methods", c_uint32),
        ("class_methods", c_uint32),
        ("base_protocols", c_uint32),
        ("instance_properties", c_uint32),
    ]


class ObjcCategoryRaw64(Structure):
    _fields_ = [
        ("name", c_uint64),
        ("base_class", c_uint64),
        ("instance_methods", c_uint64),
        ("class_methods", c_uint64),
        ("base_protocols", c_uint64),
        ("instance_properties", c_uint64),
    ]


class ObjcClassRaw32(Structure):
    _fields_ = [
        ("metaclass", c_uint32),
        ("superclass", c_uint32),
        ("cache", c_uint32),
        ("vtable", c_uint32),
        ("data", c_uint32),
    ]


class ObjcClassRaw64(Structure):
    _fields_ = [
        ("metaclass", c_uint64),
        ("superclass", c_uint64),
        ("cache", c_uint64),
        ("vtable", c_uint64),
        ("data", c_uint64),
    ]


class ObjcDataRaw32(Structure):
    _fields_ = [
        ("flags", c_uint32),
        ("instance_start", c_uint32),
        ("instance_size", c_uint32),
        ("ivar_layout", c_uint32),
        ("name", c_uint32),
        ("base_methods", c_uint32),
        ("base_protocols", c_uint32),
        ("ivars", c_uint32),
        ("weak_ivar_layout", c_uint32),
        ("base_properties", c_uint32),
    ]


class ObjcDataRaw64(Structure):
    _fields_ = [
        ("flags", c_uint32),
        ("instance_start", c_uint32),
        ("instance_size", c_uint32),
        ("reserved", c_uint32),
        ("ivar_layout", c_uint64),
        ("name", c_uint64),
        ("base_methods", c_uint64),
        ("base_protocols", c_uint64),
        ("ivars", c_uint64),
        ("weak_ivar_layout", c_uint64),
        ("base_properties", c_uint64),
    ]


class ObjcMethodList(Structure):
    _fields_ = [("flags", c_uint32), ("methcount", c_uint32)]


class ObjcIvarList(Structure):
    _fields_ = [("entsize", c_uint32), ("count", c_uint32)]


class ObjcProtocolList32(Structure):
    _fields_ = [("count", c_uint32)]


class ObjcProtocolList64(Structure):
    _fields_ = [("count", c_uint64)]


class ObjcMethod32(Structure):
    _fields_ = [("name", c_uint32), ("signature", c_uint32), ("implementation", c_uint32)]


class ObjcMethod64(Structure):
    _fields_ = [("name", c_uint64), ("signature", c_uint64), ("implementation", c_uint64)]


class ObjcMethodRelativeData(Structure):
    # Keep the field names the same so that this can be interacted with in the same way as any other ObjcMethodStruct
    # In reality, these fields are closer to: selref_off, signature_off, implementation_off
    # Note that the `name` field instead points to a selref that must be dereferenced to retrieve the name.
    _fields_ = [("name", c_int32), ("signature", c_int32), ("implementation", c_int32)]


class ObjcIvar32(Structure):
    _fields_ = [
        ("offset_ptr", c_uint32),
        ("name", c_uint32),
        ("type", c_uint32),
        ("unknown", c_uint32),
        ("size", c_uint32),
    ]


class ObjcIvar64(Structure):
    _fields_ = [
        ("offset_ptr", c_uint64),
        ("name", c_uint64),
        ("type", c_uint64),
        ("unknown", c_uint32),
        ("size", c_uint32),
    ]


class LcStrUnion(Union):
    _fields_ = [("offset", c_uint32), ("ptr", c_char_p)]


class DylibStruct(Structure):
    _fields_ = [
        ("name", LcStrUnion),
        ("timestamp", c_uint32),
        ("current_version", c_uint32),
        ("compatibility_version", c_uint32),
    ]


class DylibCommand(Structure):
    _fields_ = [*MachoLoadCommand._fields_, ("dylib", DylibStruct)]


class CFString32(Structure):
    _fields_ = [("base", c_uint32), ("flags", c_uint32), ("literal", c_uint32), ("length", c_uint32)]


class CFString64(Structure):
    _fields_ = [("base", c_uint64), ("flags", c_uint64), ("literal", c_uint64), ("length", c_uint64)]


class MachoDyldChainedFixupsHeaderRaw(Structure):
    _fields_ = [
        # 0
        ("fixups_version", c_uint32),
        # Offset of dyld_chained_starts_in_image in chain_data
        ("starts_offset", c_uint32),
        # Offset of imports table in chain_data
        ("imports_offset", c_uint32),
        # Offset of symbol strings in chain_data
        ("symbols_offset", c_uint32),
        # Number of imported symbol names
        ("imports_count", c_uint32),
        # DYLD_CHAINED_IMPORT*
        ("imports_format", c_uint32),
        # 0 => uncompressed, 1 => zlib compressed
        ("symbols_format", c_uint32),
    ]


class MachoDyldChainedImportFormat(IntEnum):
    DYLD_CHAINED_IMPORT = 1
    DYLD_CHAINED_IMPORT_ADDEND = 2
    DYLD_CHAINED_IMPORT_ADDEND64 = 3


class MachoDyldChainedImportRaw(Structure):
    _fields_ = [
        ("lib_ordinal", c_uint32, 8),
        ("weak_import", c_uint32, 1),
        ("name_offset", c_uint32, 23),
    ]


class MachoDyldChainedStartsInImageRaw(Structure):
    _fields_ = [
        ("seg_count", c_uint32),
        # Each entry is offset into this struct for that segment
        # followed by pool of dyld_chain_starts_in_segment data
        # XXX(PT): Although this is declared as uint32_t[1] array in the dyld source, it's actually
        # an array of `seg_count` entries.
        # To avoid hacks that would let ctypes parse this correctly, we manually read the offsets
        # ("seg_info_offset", c_uint32 * 1),
    ]


class MachoDyldChainedStartsInSegmentRaw(Structure):
    # https://docs.python.org/3/library/ctypes.html#structure-union-alignment-and-byte-order
    # XXX(PT): Force alignment to uint16_t, as by default this structure is reported as being 2 bytes too big
    # The correct size is important when we're parsing data that is placed directly after this structure
    _pack_ = 2

    _fields_ = [
        # Size of this (amount kernel needs to copy)
        ("size", c_uint32),
        # 0x1000 or 0x4000
        ("page_size", c_uint16),
        # DYLD_CHAINED_PTR_*
        ("pointer_format", c_uint16),
        # Offset in memory to start of segment
        ("segment_offset", c_uint64),
        # For 32-bit OS, any value beyond this is not a pointer
        ("max_valid_pointer", c_uint32),
        # How many pages are in array
        ("page_count", c_uint16),
        # Each entry is offset in each page of first element in chain
        # or DYLD_CHAINED_PTR_START_NONE if no fixups on page
        # XXX(PT): Variable-length array, see comment on MachoDyldChainedStartsInImageRaw
        # ("page_start", c_uint16),
        # Some 32-bit formats may require multiple starts per page.
        # For those, if high bit is set in page_starts[], then it
        # is index into chain_starts[] which is a list of starts
        # the last of which has the high bit set
        # XXX(PT): Variable-length array, see comment on MachoDyldChainedStartsInImageRaw
        # ("chain_starts", c_uint16),
    ]


class MachoDyldChainedPointerStartType(IntEnum):
    # Used in page_start[] to denote a page with no fixups
    DYLD_CHAINED_PTR_START_NONE = 0xFFFF
    # Used in page_start[] to denote a page which has multiple starts
    DYLD_CHAINED_PTR_START_MULTI = 0x8000
    # Used in chain_starts[] to denote last start in list for page
    DYLD_CHAINED_PTR_START_LAST = 0x8000


class MachoDyldChainedPtr64RebaseRaw(Structure):
    # Used with DYLD_CHAINED_PTR_64/DYLD_CHAINED_PTR_64_OFFSET
    _fields_ = [
        # 64GB max image size (DYLD_CHAINED_PTR_64 => vmAddr, DYLD_CHAINED_PTR_64_OFFSET => runtimeOffset)
        ("target", c_uint64, 36),
        # Top 8 bits set to this (DYLD_CHAINED_PTR_64 => after slide added,
        # DYLD_CHAINED_PTR_64_OFFSET => before slide added)
        ("high8", c_uint64, 8),
        # All zeros
        ("reserved", c_uint64, 7),
        # 4-byte stride
        ("next", c_uint64, 12),
        # == 0
        ("bind", c_uint64, 1),
    ]


class MachoDyldChainedPtr64BindRaw(Structure):
    _fields_ = [
        ("ordinal", c_uint64, 24),
        # 0 thru 255
        ("addend", c_uint64, 8),
        # All zeroes
        ("reserved", c_uint64, 19),
        # 4-byte stride
        ("next", c_uint64, 12),
        # == 1
        ("bind", c_uint64, 1),
    ]
