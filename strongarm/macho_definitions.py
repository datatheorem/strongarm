from typing import Text
from macho_load_commands import MachoLoadCommands
from ctypes import *


class CPU_TYPES(object):
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


class MachoSection64(Structure):
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
