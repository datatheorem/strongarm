from ctypes import sizeof
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
    MachoNlist64, \
    ObjcDataRaw32, \
    ObjcDataRaw64, \
    ObjcClassRaw32, \
    ObjcClassRaw64, \
    ObjcMethod32, \
    ObjcMethod64, \
    CFString32, \
    CFString64


class ArchIndependentStructure(object):
    _32_BIT_STRUCT = None
    _64_BIT_STRUCT = None

    def __init__(self, binary, binary_offset, virtual=False):
        from strongarm.macho.macho_binary import MachoBinary
        # type: (MachoBinary, int, bool) -> None
        """Parse structure from 32bit or 64bit definition, depending on the active binary
        
        Args:
            binary: The Mach-O slice to read the struct from
            binary_offset: The file offset or virtual address of the struct to read
            virtual: False if the offset is a file offset, True if it is a virtual address
        """
        struct_type = self._64_BIT_STRUCT \
            if binary.is_64bit \
            else self._32_BIT_STRUCT
        if virtual:
            struct_bytes = binary.get_content_from_virtual_address(binary_offset, sizeof(struct_type))
        else:
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
