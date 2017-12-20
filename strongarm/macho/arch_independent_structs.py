from strongarm.macho.macho_definitions import \
    MachoHeader32, \
    MachoHeader64, \
    MachoSegmentCommand32, \
    MachoSegmentCommand64, \
    MachoSection32Raw, \
    MachoSection64Raw, \
    MachoEncryptionInfo32Command, \
    MachoEncryptionInfo64Command, \
    MachoNlist32, \
    MachoNlist64
from ctypes import sizeof


class ArchIndependentStructure(object):
    _32_BIT_STRUCT = None
    _64_BIT_STRUCT = None

    def __init__(self, binary, binary_offset):
        from strongarm.macho.macho_binary import MachoBinary
        # type: (MachoBinary, int) -> None
        struct_type = self._64_BIT_STRUCT \
            if binary.is_64bit \
            else self._32_BIT_STRUCT
        struct_bytes = binary.get_bytes(binary_offset, sizeof(struct_type))
        struct = struct_type.from_buffer(bytearray(struct_bytes))

        for field_name, _ in struct._fields_:
            # clone fields from struct to this class
            setattr(self, field_name, getattr(struct, field_name))
        # record size of underlying struct, for when traversing file by structs
        self.sizeof = sizeof(struct_type)


class MachoHeaderStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoHeader32
    _64_BIT_STRUCT = MachoHeader64


class MachoSegmentCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoSegmentCommand32
    _64_BIT_STRUCT = MachoSegmentCommand64


class MachoSectionRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoSection32Raw
    _64_BIT_STRUCT = MachoSection64Raw


class MachoEncryptionInfoStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoEncryptionInfo32Command
    _64_BIT_STRUCT = MachoEncryptionInfo64Command


class MachoNlistStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoNlist32
    _64_BIT_STRUCT = MachoNlist64


class ObjcDataRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcDataRaw32
    _64_BIT_STRUCT = ObjcDataRaw64


class ObjcClassRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcClassRaw32
    _64_BIT_STRUCT = ObjcClassRaw64


class ObjcMethodStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcMethod32
    _64_BIT_STRUCT = ObjcMethod64


class CFStringStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = CFString32
    _64_BIT_STRUCT = CFString64
