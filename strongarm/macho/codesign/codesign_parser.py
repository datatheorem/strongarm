from strongarm.macho.macho_binary import MachoBinary
from typing import Tuple
from ctypes import sizeof, c_uint32, c_uint64
from enum import IntEnum


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
        magic, file_offset = self.read_cs32(file_offset)
        if magic != CodesignBlobTypeEnum.CSMAGIC_CODE_DIRECTORY:
            raise RuntimeError(f'incorrect magic for CodeDirectory header: {magic}')

        length, file_offset = self.read_cs32(file_offset)
        version, file_offset = self.read_cs32(file_offset)
        flags, file_offset = self.read_cs32(file_offset)
        hash_offset, file_offset = self.read_cs32(file_offset)
        identifier_offset, file_offset = self.read_cs32(file_offset)
        special_slots_count, file_offset = self.read_cs32(file_offset)
        code_slots_count, file_offset = self.read_cs32(file_offset)
        code_limit, file_offset = self.read_cs32(file_offset)
        hash_size, file_offset = self.read_cs_byte(file_offset)
        hash_type, file_offset = self.read_cs_byte(file_offset)
        platform, file_offset = self.read_cs_byte(file_offset)
        page_size, file_offset = self.read_cs_byte(file_offset)
        unused, file_offset = self.read_cs32(file_offset)

        # Version 0x20100
        scatter_offset, file_offset = self.read_cs32(file_offset)
        # Version 0x20200
        team_offset, file_offset = self.read_cs32(file_offset)

        print(f'CodeSign Code Directory @ {hex(code_directory_head)}\n'
              f'-----------------------\n'
              f'Magic: {hex(magic)}\n'
              f'Length: {hex(length)}\n'
              f'Version: {hex(version)}\n'
              f'Flags: {hex(flags)}\n'
              f'Hash offset: {hex(hash_offset)}\n'
              f'Identifier offset: {hex(identifier_offset)}\n'
              f'Special slots count: {special_slots_count}\n'
              f'Code slots count: {code_slots_count}\n'
              f'Code limit: {hex(code_limit)}\n'
              f'Hash size: {hex(hash_size)}\n'
              f'Hash type: {hex(hash_type)}\n'
              f'Platform: {hex(platform)}\n'
              f'Page size: {hex(page_size)}\n'
              f'Scatter offset: {hex(scatter_offset)}\n'
              f'Team ID offset: {hex(team_offset)}\n')
        identifier_address = code_directory_head + identifier_offset
        identifier_string = self.binary.get_full_string_from_start_address(identifier_address, virtual=False)
        self.signing_identifier = identifier_string
        print(f'Identifier ({hex(identifier_address)}): {self.signing_identifier}')

        team_id_address = code_directory_head + team_offset
        team_id_string = self.binary.get_full_string_from_start_address(team_id_address, virtual=False)
        self.signing_team_id = team_id_string
        print(f'Team ID    ({hex(team_id_address)}): {self.signing_team_id}')

    def parse_entitlements(self, file_offset: int) -> bytearray:
        """Parse the embedded entitlements blob at the file offset.
        Returns a bytearray of the embedded entitlements.
        """
        print(f'Parsing CodeSign embedded entitlements at {hex(file_offset)}')

        entitlements_blob_start = file_offset
        magic, file_offset = self.read_cs32(file_offset)
        if magic != CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_ENTITLEMENTS:
            raise RuntimeError(f'incorrect magic for embedded entitlements: {hex(magic)}')
        blob_length, file_offset = self.read_cs32(file_offset)
        blob_end = entitlements_blob_start + blob_length

        xml_start = file_offset
        xml_length = blob_end - xml_start
        print(f'Entitlements XML from {hex(xml_start)} to {hex(xml_start + xml_length)}')

        xml = self.binary.get_bytes(xml_start, xml_length)
        print(f'Found embedded entitlements XML:\n{xml}')
        return xml
