from ctypes import sizeof

from typing import Union, Type, Any, Optional
from typing import TYPE_CHECKING

from strongarm.macho.macho_definitions import (
    MachoHeader32, MachoHeader64,
    MachoSegmentCommand32, MachoSegmentCommand64,
    MachoSection32Raw, MachoSection64Raw,
    MachoEncryptionInfo32Command, MachoEncryptionInfo64Command,
    MachoNlist32, MachoNlist64,
    MachoLoadCommand,
    MachoSymtabCommand,
    MachoDysymtabCommand,
    MachoDyldInfoCommand,
    MachoLinkeditDataCommand,
    ObjcDataRaw32, ObjcDataRaw64,
    ObjcClassRaw32, ObjcClassRaw64,
    ObjcMethod32, ObjcMethod64,
    ObjcMethodList,
    ObjcCategoryRaw32, ObjcCategoryRaw64,
    ObjcProtocolRaw32, ObjcProtocolRaw64,
    ObjcProtocolList32, ObjcProtocolList64,
    CFString32, CFString64,
    DylibCommand,
)

# create type alias for the following classes that inherit from ArchIndependentStructure
if TYPE_CHECKING:
    from .codesign.codesign_definitions import (
        CSBlobStruct,
        CSSuperblobStruct,
        CSCodeDirectoryStruct,
        CSBlobIndexStruct,
    )

# Create type alias for the following classes that inherit from ArchIndependentStructure
_32_BIT_STRUCT_ALIAS = Union[Type[MachoHeader32], Type[MachoSegmentCommand32], Type[MachoSection32Raw],
                             Type[MachoEncryptionInfo32Command], Type[MachoNlist32], Type[MachoLoadCommand],
                             Type[MachoSymtabCommand], Type[MachoDysymtabCommand], Type[MachoDyldInfoCommand],
                             Type[MachoLinkeditDataCommand], Type[ObjcDataRaw32], Type[ObjcClassRaw32],
                             Type[ObjcMethod32], Type[ObjcMethodList], Type[ObjcCategoryRaw32],
                             Type[ObjcProtocolRaw32], Type[ObjcProtocolList32], Type[CFString32],
                             Type[DylibCommand], Type['CSBlobStruct'], Type['CSSuperblobStruct'],
                             Type['CSCodeDirectoryStruct'], Type['CSBlobIndexStruct']]

_64_BIT_STRUCT_ALIAS = Union[Type[MachoHeader64], Type[MachoSegmentCommand64], Type[MachoSection64Raw],
                             Type[MachoEncryptionInfo64Command], Type[MachoNlist64], Type[MachoLoadCommand],
                             Type[MachoSymtabCommand], Type[MachoDysymtabCommand], Type[MachoDyldInfoCommand],
                             Type[MachoLinkeditDataCommand], Type[ObjcDataRaw64], Type[ObjcClassRaw64],
                             Type[ObjcMethod64], Type[ObjcMethodList], Type[ObjcCategoryRaw64],
                             Type[ObjcProtocolRaw64], Type[ObjcProtocolList64], Type[CFString64],
                             Type[DylibCommand], Type['CSBlobStruct'], Type['CSSuperblobStruct'],
                             Type['CSCodeDirectoryStruct'], Type['CSBlobIndexStruct']]


class ArchIndependentStructure:
    _32_BIT_STRUCT: Optional[_32_BIT_STRUCT_ALIAS] = None
    _64_BIT_STRUCT: Optional[_64_BIT_STRUCT_ALIAS] = None

    @classmethod
    def struct_size(cls, is_64bit: bool = True) -> int:
        """Get the size of the structure
        Args:
            is_64bit: Binary's 64 bitness
        Returns:
            size of the structure
        """
        struct_type = cls._64_BIT_STRUCT if is_64bit else cls._32_BIT_STRUCT
        if struct_type is None:
            raise ValueError('Undefined struct_type')

        return sizeof(struct_type)

    def __init__(self, binary_offset: int, struct_bytes: bytearray, is_64bit: bool = True) -> None:
        """Parse structure from 32bit or 64bit definition

        Args:
            binary_offset: The file offset or virtual address of the struct to read
            struct_bytes: The struct bytes
            is_64bit: The binary's 64 bitness
        """
        struct_type = self._64_BIT_STRUCT if is_64bit else self._32_BIT_STRUCT
        if struct_type is None:
            raise ValueError('Undefined struct_type')

        struct: ArchIndependentStructure = struct_type.from_buffer(struct_bytes)

        for field_name, _ in struct._fields_:
            # clone fields from struct to this class
            setattr(self, field_name, getattr(struct, field_name))

        # record size of underlying struct, for when traversing file by structs
        self.sizeof = sizeof(struct_type)
        # record the location in the binary this struct was parsed from
        self.binary_offset = binary_offset

    if TYPE_CHECKING:
        # GVR suggested to use this pattern to ignore dynamic attribute assignment errors
        def __getattr__(self, key: str) -> Any:
            pass

        implementation: Any = None
        data: Any = None

    def __repr__(self) -> str:
        attributes = '\t'.join([f'{x}: {hex(getattr(self, x))}' for x in self.__dict__.keys()])
        rep = f'{self.__class__.__name__} ({attributes})'
        return rep


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


class ObjcProtocolListStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcProtocolList32
    _64_BIT_STRUCT = ObjcProtocolList64


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


class MachoLinkeditDataCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoLinkeditDataCommand
    _64_BIT_STRUCT = MachoLinkeditDataCommand
