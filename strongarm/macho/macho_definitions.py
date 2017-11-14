import struct
from ctypes import *
from enum import IntEnum


def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]


class MachArch(IntEnum):
    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe

    FAT_MAGIC = 0xcafebabe
    FAT_CIGAM = 0xbebafeca

    MH_CPU_ARCH_ABI64 = 0x01000000
    MH_CPU_TYPE_ARM = 12
    MH_CPU_TYPE_ARM64 = MH_CPU_TYPE_ARM | MH_CPU_ARCH_ABI64


class CPU_TYPE(IntEnum):
    ARMV7 = 0
    ARM64 = 1
    UNKNOWN = 2


class MachoHeader64(Structure):
    _fields_ = [
        ('magic', c_uint32),
        ('cputype', c_uint32),
        ('cpusubtype', c_uint32),
        ('filetype', c_uint32),
        ('ncmds', c_uint32),
        ('sizeofcmds', c_uint32),
        ('flags', c_uint32),
        ('reserved', c_uint32),
    ]


class MachoSegmentCommand64(Structure):
    _fields_ = [
        ('cmd', c_int32),
        ('cmdsize', c_int32),
        ('segname', c_char * 16),
        ('vmaddr', c_uint64),
        ('vmsize', c_uint64),
        ('fileoff', c_uint64),
        ('filesize', c_uint64),
        ('maxprot', c_uint32),
        ('initprot', c_uint32),
        ('nsects', c_uint32),
        ('flags', c_uint32),
    ]


class MachOLoadCommand(Structure):
    _fields_ = [
        ('cmd', c_uint32),
        ('cmdsize', c_uint32),
    ]


class MachoSection64Raw(Structure):
    _fields_ = [
        ('sectname', c_char * 16),
        ('segname', c_char * 16),
        ('addr', c_int64),
        ('size', c_int64),
        ('offset', c_int32),
        ('align', c_int32),
        ('reloff', c_int32),
        ('nreloc', c_int32),
        ('flags', c_int32),
        ('reserved1', c_int32),
        ('reserved2', c_int32),
        ('reserved3', c_int32),
    ]


class MachoDysymtabCommand(Structure):
    """Python representation of struct dysymtab_command

    Definition found in <mach-o/loader.h>
    """
    _fields_ = [
        ('cmd', c_uint32),
        ('cmdsize', c_uint32),
        ('ilocalsym', c_uint32),
        ('nlocalsym', c_uint32),
        ('iextdefsym', c_uint32),
        ('nextdefsym', c_uint32),
        ('iundefsym', c_uint32),
        ('nundefsym', c_uint32),
        ('tocoff', c_uint32),
        ('ntoc', c_uint32),
        ('modtaboff', c_uint32),
        ('nmodtab', c_uint32),
        ('extrefsymoff', c_uint32),
        ('nextrefsyms', c_uint32),
        ('indirectsymoff', c_uint32),
        ('nindirectsyms', c_uint32),
        ('extreloff', c_uint32),
        ('nextrel', c_uint32),
        ('locreloff', c_uint32),
        ('nlocrel', c_uint32)
    ]


class MachoSymtabCommand(Structure):
    """Python representation of struct symtab_command

    Definition found in <mach-o/loader.h>
    """
    _fields_ = [
        ('cmd', c_uint32),
        ('cmdsize', c_uint32),
        ('symoff', c_uint32),
        ('nsyms', c_uint32),
        ('stroff', c_uint32),
        ('strsize', c_uint32)
    ]


class MachoNlistUn(Union):
    """Python representation of union n_un

    Definition found in <mach-o/nlist.h>
    """
    _fields_ = [
        ('n_strx', c_uint32),
    ]


class MachoNlist64(Structure):
    """Python representation of struct nlist_64

    Definition found in <mach-o/nlist.h>
    """
    _fields_ = [
        ('n_un', MachoNlistUn),
        ('n_type', c_uint8),
        ('n_sect', c_uint8),
        ('n_desc', c_uint16),
        ('n_value', c_uint64),
    ]


class MachoEncryptionInfo64Command(Structure):
    """Python representation of a struct encryption_info_command_64

    Definition found in <mach-o/loader.h>
    """
    _fields_ = [
        ('cmd', c_uint32),
        ('cmdsize', c_uint32),
        ('cryptoff', c_uint32),
        ('cryptsize', c_uint32),
        ('cryptid', c_uint32),
        ('pad', c_uint32),
    ]


class MachoFatHeader(Structure):
    """Python representation of a struct fat_header

    Definition found in <mach-o/fat.h>
    """
    _fields_ = [
        ('magic', c_uint32),
        ('nfat_arch', c_uint32),
    ]


class MachoFatArch(Structure):
    """Python representation of a struct fat_arch

    Definition found in <mach-o/fat.h>
    """
    _fields_ = [
        ('cputype', c_uint32),
        ('cpusubtype', c_uint32),
        ('offset', c_uint32),
        ('size', c_uint32),
        ('align', c_uint32),
    ]


class NLIST_NTYPE(IntEnum):
    N_STAB = 0xe0 # symbollic debugging entry
    N_PEXT = 0x10 # private external symbol bit
    N_TYPE = 0x0e # mask for type bits
    N_EXT = 0x01 # external symbol bit


class NTYPE_VALUES(IntEnum):
    N_UNDF = 0x0 # undefined, n_sect == NO_SECT
    N_ABS = 0x2 # absolute, n_sect == NO_SECT
    N_SECT = 0xe # defined in section n_sect
    N_PBUD = 0xc # prebound undefined (defined in a dylib)
    N_INDR = 0xa # indirect


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


class ObjcClass(Structure):
    _fields_ = [
        ('metaclass', c_uint64),
        ('superclass', c_uint64),
        ('cache', c_uint64),
        ('vtable', c_uint64),
        ('data', c_uint64)
    ]


class ObjcData(Structure):
    _fields_ = [
        ('flags', c_uint32),
        ('instance_start', c_uint32),
        ('instance_size', c_uint32),
        ('reserved', c_uint32),
        ('ivar_layout', c_uint64),
        ('name', c_uint64),
        ('base_methods', c_uint64),
        ('base_protocols', c_uint64),
        ('ivars', c_uint64),
        ('weak_ivar_layout', c_uint64),
        ('base_properties', c_uint64),
    ]


class ObjcMethodList(Structure):
    _fields_ = [
        ('flags', c_uint32),
        ('methcount', c_uint32),
    ]


class ObjcMethod(Structure):
    _fields_ = [
        ('name', c_uint64),
        ('signature', c_uint64),
        ('implementation', c_uint64)
    ]
