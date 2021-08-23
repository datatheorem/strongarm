import logging
from ctypes import Structure, c_uint64, sizeof
from distutils.version import LooseVersion
from typing import TYPE_CHECKING, Any, Optional, Type, Union

from strongarm.macho.macho_definitions import (
    CFString32,
    CFString64,
    DylibCommand,
    MachoBuildToolVersion,
    MachoBuildVersionCommand,
    MachoDyldChainedFixupsHeaderRaw,
    MachoDyldChainedImportRaw,
    MachoDyldChainedPtr64BindRaw,
    MachoDyldChainedPtr64RebaseRaw,
    MachoDyldChainedStartsInImageRaw,
    MachoDyldChainedStartsInSegmentRaw,
    MachoDyldInfoCommand,
    MachoDysymtabCommand,
    MachoEncryptionInfo32Command,
    MachoEncryptionInfo64Command,
    MachoHeader32,
    MachoHeader64,
    MachoLinkeditDataCommand,
    MachoLoadCommand,
    MachoNlist32,
    MachoNlist64,
    MachoSection32Raw,
    MachoSection64Raw,
    MachoSegmentCommand32,
    MachoSegmentCommand64,
    MachoSymtabCommand,
    ObjcCategoryRaw32,
    ObjcCategoryRaw64,
    ObjcClassRaw32,
    ObjcClassRaw64,
    ObjcDataRaw32,
    ObjcDataRaw64,
    ObjcIvar32,
    ObjcIvar64,
    ObjcIvarList,
    ObjcMethod32,
    ObjcMethod64,
    ObjcMethodList,
    ObjcMethodRelativeData,
    ObjcProtocolList32,
    ObjcProtocolList64,
    ObjcProtocolRaw32,
    ObjcProtocolRaw64,
    VirtualMemoryPointer,
)

# create type alias for the following classes that inherit from ArchIndependentStructure
if TYPE_CHECKING:
    from .codesign.codesign_definitions import (  # noqa: F401
        CSBlobIndexStruct,
        CSBlobStruct,
        CSCodeDirectoryStruct,
        CSSuperblobStruct,
    )
    from .macho_binary import MachoBinary

# Create type alias for the following classes that inherit from ArchIndependentStructure
_32_BIT_STRUCT_ALIAS = Union[
    Type[MachoHeader32],
    Type[MachoSegmentCommand32],
    Type[MachoSection32Raw],
    Type[MachoEncryptionInfo32Command],
    Type[MachoNlist32],
    Type[MachoLoadCommand],
    Type[MachoSymtabCommand],
    Type[MachoDysymtabCommand],
    Type[MachoDyldInfoCommand],
    Type[MachoLinkeditDataCommand],
    Type[ObjcDataRaw32],
    Type[ObjcClassRaw32],
    Type[ObjcMethod32],
    Type[ObjcIvar32],
    Type[ObjcMethodList],
    Type[ObjcCategoryRaw32],
    Type[ObjcProtocolRaw32],
    Type[ObjcProtocolList32],
    Type[CFString32],
    Type[DylibCommand],
    Type["CSBlobStruct"],
    Type["CSSuperblobStruct"],
    Type["CSCodeDirectoryStruct"],
    Type["CSBlobIndexStruct"],
    Type["ObjcIvarList"],
    Type["MachoBuildVersionCommand"],
    Type["MachoBuildToolVersion"],
]

_64_BIT_STRUCT_ALIAS = Union[
    Type[MachoHeader64],
    Type[MachoSegmentCommand64],
    Type[MachoSection64Raw],
    Type[MachoEncryptionInfo64Command],
    Type[MachoNlist64],
    Type[MachoLoadCommand],
    Type[MachoSymtabCommand],
    Type[MachoDysymtabCommand],
    Type[MachoDyldInfoCommand],
    Type[MachoLinkeditDataCommand],
    Type[ObjcDataRaw64],
    Type[ObjcClassRaw64],
    Type[ObjcMethod64],
    Type[ObjcIvar64],
    Type[ObjcMethodList],
    Type[ObjcCategoryRaw64],
    Type[ObjcProtocolRaw64],
    Type[ObjcProtocolList64],
    Type[CFString64],
    Type[DylibCommand],
    Type["CSBlobStruct"],
    Type["CSSuperblobStruct"],
    Type["CSCodeDirectoryStruct"],
    Type["CSBlobIndexStruct"],
    Type["ObjcIvarList"],
    Type["MachoBuildVersionCommand"],
    Type["MachoBuildToolVersion"],
    Type["MachoDyldChainedFixupsHeaderRaw"],
    Type["MachoDyldChainedImportRaw"],
    Type["MachoDyldChainedStartsInImageRaw"],
    Type["MachoDyldChainedStartsInSegmentRaw"],
    Type["MachoDyldChainedPtr64RebaseRaw"],
    Type["MachoDyldChainedPtr64BindRaw"],
    Type["MachoBuildToolVersion"],
]


class ArchIndependentStructure:
    _32_BIT_STRUCT: Optional[_32_BIT_STRUCT_ALIAS] = None
    _64_BIT_STRUCT: Optional[_64_BIT_STRUCT_ALIAS] = None

    @classmethod
    def get_backing_data_layout(
        cls, is_64bit: bool = True, minimum_deployment_target: Optional[LooseVersion] = None
    ) -> Type[Structure]:
        """The underlying data layout may be different depending on the binary type.
        Args:
            is_64bit: Binary's 64 bitness
            minimum_deployment_target: The minimum deployment target (target OS version) of the binary, if available
        Returns:
            size of the structure in bytes
        """
        struct_type = cls._64_BIT_STRUCT if is_64bit else cls._32_BIT_STRUCT

        if struct_type is None:
            raise ValueError("Undefined struct_type")

        return struct_type

    def __init__(self, binary_offset: int, struct_bytes: bytearray, backing_layout: Type[Structure]):
        struct: ArchIndependentStructure = backing_layout.from_buffer(struct_bytes)  # type: ignore

        for field_name, *_ in struct._fields_:
            # clone fields from struct to this class
            setattr(self, field_name, getattr(struct, field_name))

        # record size of underlying struct, for when traversing file by structs
        self.sizeof = sizeof(backing_layout)
        # record the location in the binary this struct was parsed from
        self.binary_offset = binary_offset

    if TYPE_CHECKING:
        # GVR suggested to use this pattern to ignore dynamic attribute assignment errors
        def __getattr__(self, key: str) -> Any:
            pass

    def __repr__(self) -> str:
        attributes = "\t".join([f"{x}: {getattr(self, x)}" for x in self.__dict__.keys()])
        rep = f"{self.__class__.__name__} ({attributes})"
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
    __slots__ = ["n_un", "n_type", "n_sect", "n_desc", "n_value"]
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

    @classmethod
    def get_backing_data_layout(
        cls,
        is_64bit: bool = True,
        minimum_deployment_target: Optional[LooseVersion] = None,
        methlist_flags: Optional[int] = None,
    ) -> Type[Structure]:
        # Prior to iOS 14, 64-bit targets would use an ObjcMethod64 structure with absolute addresses.
        # On iOS 14 and later, 64-bit targets use a structure with 32-bit relative offsets from each field.
        if is_64bit and minimum_deployment_target and minimum_deployment_target >= LooseVersion("14.0.0"):
            # SCAN-2419: Binaries can be built for iOS 14 and still use an absolute method list, so also check a flag
            # bit set in the method list
            if methlist_flags and methlist_flags & (1 << 31) != 0:
                return ObjcMethodRelativeData

        return super().get_backing_data_layout(is_64bit, minimum_deployment_target)

    @classmethod
    def read_method_struct(
        cls, binary: "MachoBinary", address: VirtualMemoryPointer, methlist_flags: Optional[int] = None
    ) -> "ObjcMethodStruct":  # noqa
        """Read an ObjcMethodStruct from the provided binary address.
        This method accounts for post-iOS-14 binaries using a relative-offset layout for this structure, and
         patches the field values to appear as absolute addresses to callers, to match the layout from prior versions.
        """
        struct_type = cls.get_backing_data_layout(
            binary.is_64bit, binary.get_minimum_deployment_target(), methlist_flags
        )
        data = binary.get_contents_from_address(address=address, size=sizeof(struct_type), is_virtual=True)
        method_ent = ObjcMethodStruct(address, data, struct_type)

        # If we're parsing the iOS14+ structure that encodes signed 32b offsets instead of 64b absolute addresses,
        # translate the offsets to absolute addresses for caller convenience.
        if struct_type == ObjcMethodRelativeData:
            # Fix up each field by translating it from a 32b signed offset to an absolute address
            method_entry_off = address
            method_ent.signature += method_entry_off + 4  # type: ignore
            method_ent.implementation += method_entry_off + 8  # type: ignore

            # Rather than pointing to a selector literal, this field points to a selref. Dereference it now
            selref_addr = method_ent.name + method_entry_off  # type: ignore
            # This selref may be rebased
            method_ent.name = binary.read_rebased_pointer(selref_addr)  # type: ignore
        else:
            for field_name, field_type, *_ in struct_type._fields_:
                field_offset = getattr(getattr(struct_type, field_name), "offset")
                field_address = address + field_offset
                if field_type == c_uint64 and field_address in binary.dyld_rebased_pointers:
                    pointer_value = binary.dyld_rebased_pointers[field_address]
                    logging.debug(
                        f"Setting rebased pointer within {struct_type}+{field_offset} -> "
                        f"{pointer_value} at {field_address}"
                    )
                    setattr(method_ent, field_name, pointer_value)

        return method_ent


class ObjcIvarStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcIvar32
    _64_BIT_STRUCT = ObjcIvar64


class CFStringStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = CFString32
    _64_BIT_STRUCT = CFString64


class ObjcMethodListStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcMethodList
    _64_BIT_STRUCT = ObjcMethodList


class ObjcIvarListStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = ObjcIvarList
    _64_BIT_STRUCT = ObjcIvarList


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


class MachoBuildVersionCommandStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoBuildVersionCommand
    _64_BIT_STRUCT = MachoBuildVersionCommand


class MachoBuildToolVersionStruct(ArchIndependentStructure):
    _32_BIT_STRUCT = MachoBuildToolVersion
    _64_BIT_STRUCT = MachoBuildToolVersion


class MachoDyldChainedFixupsHeader(ArchIndependentStructure):
    _64_BIT_STRUCT = MachoDyldChainedFixupsHeaderRaw


class MachoDyldChainedImport(ArchIndependentStructure):
    _64_BIT_STRUCT = MachoDyldChainedImportRaw


class MachoDyldChainedStartsInImage(ArchIndependentStructure):
    _64_BIT_STRUCT = MachoDyldChainedStartsInImageRaw


class MachoDyldChainedStartsInSegment(ArchIndependentStructure):
    _64_BIT_STRUCT = MachoDyldChainedStartsInSegmentRaw


class MachoDyldChainedPtr64Rebase(ArchIndependentStructure):
    _64_BIT_STRUCT = MachoDyldChainedPtr64RebaseRaw


class MachoDyldChainedPtr64Bind(ArchIndependentStructure):
    _64_BIT_STRUCT = MachoDyldChainedPtr64BindRaw
