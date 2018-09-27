from typing import Tuple
from ctypes import sizeof, c_uint32, c_uint64

from strongarm.macho.macho_binary import MachoBinary

from .codesign_definitions import (
    CodesignBlobTypeEnum,
    CSBlob,
    CSCodeDirectory
)


class CodesignParser:
    def __init__(self, binary: MachoBinary):
        self.binary = binary
        self.entitlements: bytearray = None
        self.signing_identifier: str = None
        self.signing_team_id: str = None

        self._codesign_entry = self.binary.code_signature.dataoff
        self.parse_codesign_resource(self._codesign_entry)

    def read_cs_byte(self, offset: int) -> Tuple[int, int]:
        """Read a byte from the file offset.
        Returns the byte that was read and an incremented file pointer.
        """
        byte = int.from_bytes(self.binary.get_bytes(offset, 1), byteorder='little')
        return byte, offset + 1

    def read_cs32(self, offset: int) -> Tuple[int, int]:
        """Read a 32-bit word from the file offset in big-endian order.
        Returns the word that was read and an incremented file pointer.
        """
        word = self.binary.read_word(offset,
                                     virtual=False,
                                     swap=True,
                                     word_type=c_uint32)
        return word, offset + 4

    def read_cs64(self, offset: int) -> Tuple[int, int]:
        """Read a 64-bit word from the file offset in big-endian order.
        Returns the word that was read and an incremented file pointer.
        """
        word = self.binary.read_word(offset,
                                     virtual=False,
                                     swap=True,
                                     word_type=c_uint64)
        return word, offset + 8

    def parse_codesign_resource(self, file_offset: int) -> None:
        """High-level parser to parse the codesign construct at the file offset.
        """
        magic, _ = self.read_cs32(file_offset)

        if magic == CodesignBlobTypeEnum.CSMAGIC_CODE_DIRECTORY:
            self.parse_code_directory(file_offset)
        elif magic == CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_SIGNATURE:
            self.parse_superblob(file_offset)
        elif magic == CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_ENTITLEMENTS:
            self.entitlements = self.parse_entitlements(file_offset)
        elif magic == CodesignBlobTypeEnum.CSMAGIC_REQUIREMENT:
            print(f'Skipping CodeSign requirement at {hex(file_offset)}')
        elif magic == CodesignBlobTypeEnum.CSMAGIC_REQUIREMENT_SET:
            print(f'Skipping CodeSign requirement set at {hex(file_offset)}')
        elif magic == CodesignBlobTypeEnum.CSMAGIC_DETACHED_SIGNATURE:
            print(f'Skipping CodeSign detached signature at {hex(file_offset)}')
        elif magic == CodesignBlobTypeEnum.CSMAGIC_BLOBWRAPPER:
            print(f'Skipping CodeSign blob wrapper at {hex(file_offset)}')
        else:
            print(f'Skipping unknown codesign magic: {hex(magic)}')

    def parse_superblob(self, file_offset: int):
        """Parse a codesign 'superblob' at the provided file offset.
        This is a blob which embeds several child blobs.
        The superblob format is the superblob header, followed by several 'csblob_index' structures describing
        the layout of the child blobs.
        """
        print(f'Parsing CodeSign superblob at {hex(file_offset)}')
        blob_magic, file_offset = self.read_cs32(file_offset)
        if blob_magic != CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_SIGNATURE:
            raise RuntimeError(f'Can blobs other than embedded signatures be superblobs? Investigate {hex(blob_magic)}')

        blob_length, file_offset = self.read_cs32(file_offset)
        index_entry_count, file_offset = self.read_cs32(file_offset)

        print(f'Superblob has {index_entry_count} sub-blobs')

        for i in range(index_entry_count):
            self.parse_csblob_index(file_offset)
            file_offset += sizeof(c_uint32)*2

    def parse_csblob_index(self, file_offset: int):
        """Parse a csblob_index at the file offset.
        A csblob_index is a header structure describing the type/layout of a superblob's child blob.
        This method will parse the index header, then parse the sub-blob itself.
        """
        blob_type, file_offset = self.read_cs32(file_offset)
        blob_offset, file_offset = self.read_cs32(file_offset)
        blob_file_offset = self._codesign_entry + blob_offset

        # cs_blobs.h
        blob_types = {0: 'Code Directory',
                      1: 'Info slot',
                      2: 'Requirement Set',
                      3: 'Resource Directory',
                      4: 'Application',
                      5: 'Embedded Entitlements',
                      0x1000: 'Alternate Code Directory',
                      0x10000: 'CMS Signature'}
        print(f'Sub-blob @ {hex(blob_file_offset)}: {blob_types[blob_type]}')
        # parse the blob we learned about
        self.parse_codesign_resource(blob_file_offset)

    def parse_code_directory(self, file_offset: int):
        """Parse a Code Directory at the file offset.
        """
        # TODO(PT): make mach-o structures for CodeSigning structs
        print(f'Parsing CodeSign Code Directory')
        code_directory_head = file_offset

        code_directory = CSCodeDirectory(self.binary, file_offset, virtual=False)
        if code_directory.magic != CodesignBlobTypeEnum.CSMAGIC_CODE_DIRECTORY:
            raise RuntimeError(f'incorrect magic for CodeDirectory header: {hex(code_directory.magic)}')
        # Version 0x20100: scatter_offset
        # Version 0x20200: team offset

        print(f'CodeSign Code Directory @ {hex(code_directory_head)}\n'
              f'-----------------------\n'
              f'Magic: {hex(code_directory.magic)}\n'
              f'Length: {hex(code_directory.length)}\n'
              f'Version: {hex(code_directory.version)}\n'
              f'Flags: {hex(code_directory.flags)}\n'
              f'Hash offset: {hex(code_directory.hash_offset)}\n'
              f'Identifier offset: {hex(code_directory.identifier_offset)}\n'
              f'Special slots count: {code_directory.special_slots_count}\n'
              f'Code slots count: {code_directory.code_slots_count}\n'
              f'Code limit: {hex(code_directory.code_limit)}\n'
              f'Hash size: {hex(code_directory.hash_size)}\n'
              f'Hash type: {hex(code_directory.hash_type)}\n'
              f'Platform: {hex(code_directory.platform)}\n'
              f'Page size: {hex(code_directory.page_size)}\n'
              f'Scatter offset: {hex(code_directory.scatter_offset)}\n'
              f'Team ID offset: {hex(code_directory.team_offset)}\n')
        identifier_address = code_directory.binary_offset + code_directory.identifier_offset
        identifier_string = self.binary.get_full_string_from_start_address(identifier_address, virtual=False)
        self.signing_identifier = identifier_string
        print(f'Identifier ({hex(identifier_address)}): {self.signing_identifier}')

        team_id_address = code_directory.binary_offset + code_directory.team_offset
        team_id_string = self.binary.get_full_string_from_start_address(team_id_address, virtual=False)
        self.signing_team_id = team_id_string
        print(f'Team ID    ({hex(team_id_address)}): {self.signing_team_id}')

    def parse_entitlements(self, file_offset: int) -> bytearray:
        """Parse the embedded entitlements blob at the file offset.
        Returns a bytearray of the embedded entitlements.
        """
        print(f'Parsing CodeSign embedded entitlements at {hex(file_offset)}')

        entitlements_blob = CSBlob(self.binary, file_offset, virtual=False)
        if entitlements_blob.magic != CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_ENTITLEMENTS:
            raise RuntimeError(f'incorrect magic for embedded entitlements: {hex(entitlements_blob.magic)}')
        blob_end = entitlements_blob.binary_offset + entitlements_blob.length

        xml_start = file_offset
        xml_length = blob_end - xml_start
        print(f'Entitlements XML from {hex(xml_start)} to {hex(xml_start + xml_length)}')

        xml = self.binary.get_bytes(xml_start, xml_length)
        print(f'Found embedded entitlements XML:\n{xml}')
        return xml
