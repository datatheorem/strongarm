from ctypes import sizeof

from typing import Union, Type, Any, Text
from typing import TYPE_CHECKING

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
    CFString64, \
    ObjcMethodList, \
    DylibCommand, \
    MachoLoadCommand, \
    MachoSymtabCommand, \
    MachoDysymtabCommand, \
    MachoDyldInfoCommand, \
    ObjcCategoryRaw32, \
    ObjcCategoryRaw64, \
    ObjcProtocolRaw32, \
    ObjcProtocolRaw64

# create type alias for the following classes that inherit from ArchIndependentStructure
if TYPE_CHECKING:
    from strongarm.macho.macho_binary import MachoBinary
    _32_BIT_STRUCT_ALIAS = Union[Type[MachoHeader32], Type[MachoSegmentCommand32], Type[MachoSection32Raw],
                                 Type[MachoEncryptionInfo32Command], Type[MachoNlist32], Type[MachoLoadCommand],
                                 Type[ObjcDataRaw32], Type[ObjcClassRaw32], Type[ObjcMethod32], Type[ObjcMethodList],
                                 Type[DylibCommand], Type[CFString32], Type[MachoSymtabCommand],
                                 Type[MachoDyldInfoCommand], Type[MachoDysymtabCommand], Type[ObjcCategoryRaw32],
                                 Type[ObjcProtocolRaw32]]

    _64_BIT_STRUCT_ALIAS = Union[Type[MachoHeader64], Type[MachoSegmentCommand64], Type[MachoSection64Raw],
                                 Type[MachoEncryptionInfo64Command], Type[MachoNlist64], Type[MachoLoadCommand],
                                 Type[ObjcDataRaw64], Type[ObjcClassRaw64], Type[ObjcMethod64], Type[ObjcMethodList],
                                 Type[DylibCommand], Type[CFString64], Type[MachoSymtabCommand],
                                 Type[MachoDyldInfoCommand], Type[MachoDysymtabCommand], Type[ObjcCategoryRaw64],
                                 Type[ObjcProtocolRaw64]]


class ArchIndependentStructure(object):
    _32_BIT_STRUCT = None   # type: _32_BIT_STRUCT_ALIAS
    _64_BIT_STRUCT = None   # type: _64_BIT_STRUCT_ALIAS

    def __init__(self, binary, binary_offset, virtual=False):
        # type: ('MachoBinary', int, bool) -> None
        """Parse structure from 32bit or 64bit definition, depending on the active binary
        
        Args:
            binary: The Mach-O slice to read the struct from
            binary_offset: The file offset or virtual address of the struct to read
            virtual: False if the offset is a file offset, True if it is a virtual address
        """
        if binary.is_64bit:
            struct_type = self._64_BIT_STRUCT
        else:
            struct_type = self._32_BIT_STRUCT
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
        # record the location in the binary this struct was parsed from
        self.binary_offset = binary_offset

    if TYPE_CHECKING:
        # GVR suggested to use this pattern to ignore dynamic attribute assignment errors
        def __getattr__(self, key):
            # type: (Text) -> Any
            pass

        implementation = None   # type: Any
        data = None # type: Any


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
    __slots__ = ['n_un', 'n_type', 'n_sect', 'n_desc', 'n_value']
    _32_BIT_STRUCT = MachoNlist32
    _64_BIT_STRUCT = MachoNlist64


class ObjcDataRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcDataRaw32
    _64_BIT_STRUCT = ObjcDataRaw64


class ObjcProtocolRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcProtocolRaw32
    _64_BIT_STRUCT = ObjcProtocolRaw64


class ObjcCategoryRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcCategoryRaw32
    _64_BIT_STRUCT = ObjcCategoryRaw64


class ObjcClassRawStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcClassRaw32
    _64_BIT_STRUCT = ObjcClassRaw64


class ObjcMethodStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcMethod32
    _64_BIT_STRUCT = ObjcMethod64


class CFStringStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = CFString32
    _64_BIT_STRUCT = CFString64


class ObjcMethodListStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcMethodList
    _64_BIT_STRUCT = ObjcMethodList


class DylibCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = DylibCommand
    _64_BIT_STRUCT = DylibCommand

    def __init__(self, binary, binary_offset, virtual=False):
        # type: (Any, int, bool) -> None
        super(DylibCommandStruct, self).__init__(binary, binary_offset, virtual)
        self.fileoff = None # type: int


class MachoLoadCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoLoadCommand
    _64_BIT_STRUCT = MachoLoadCommand


class MachoSymtabCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoSymtabCommand
    _64_BIT_STRUCT = MachoSymtabCommand


class MachoDysymtabCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoDysymtabCommand
    _64_BIT_STRUCT = MachoDysymtabCommand


class MachoDyldInfoCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoDyldInfoCommand
    _64_BIT_STRUCT = MachoDyldInfoCommand
