# -*- coding: utf-8 -*-
import struct

from enum import IntEnum
from ctypes import BigEndianStructure, c_uint8, c_uint32

from strongarm.macho.arch_independent_structs import ArchIndependentStructure


class CodesignBlobTypeEnum(IntEnum):
    """Magic numbers for codesigning blobs
    https://opensource.apple.com/source/Security/Security-57031.1.35/Security/libsecurity_codesigning/lib/CSCommonPriv.h
    https://opensource.apple.com/source/libsecurity_utilities/libsecurity_utilities-55030/lib/blob.h.auto.html
    https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/kern/cs_blobs.h.auto.html
    https://opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/sys/codesign.h
    """
    CSMAGIC_REQUIREMENT           = 0xfade0c00  # single requirement blob
    CSMAGIC_REQUIREMENT_SET       = 0xfade0c01  # requirements vector (internal requirements)
    CSMAGIC_CODE_DIRECTORY        = 0xfade0c02  # CodeDirectory blob
    CSMAGIC_EMBEDDED_SIGNATURE    = 0xfade0cc0  # embedded signature data
    CSMAGIC_DETACHED_SIGNATURE    = 0xfade0cc1  # multi-arch collection of embedded signatures
    CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171  # embedded entitlements
    CSMAGIC_BLOBWRAPPER           = 0xfade0b01  # CMS signature, "among other things" from the source code


class CSCodeDirectoryStruct(BigEndianStructure):
    _fields_ = [
        ('magic', c_uint32),
        ('length', c_uint32),
        ('version', c_uint32),
        ('flags', c_uint32),
        ('hash_offset', c_uint32),
        ('identifier_offset', c_uint32),
        ('special_slots_count', c_uint32),
        ('code_slots_count', c_uint32),
        ('code_limit', c_uint32),
        ('hash_size', c_uint8),
        ('hash_type', c_uint8),
        ('platform', c_uint8),
        ('page_size', c_uint8),
        ('unused', c_uint32),
        ('scatter_offset', c_uint32),
        ('team_offset', c_uint32),
    ]


class CSCodeDirectory(ArchIndependentStructure):
    _32_BIT_STRUCT = CSCodeDirectoryStruct
    _64_BIT_STRUCT = CSCodeDirectoryStruct
