from typing import Optional

from strongarm.logger import strongarm_logger
from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import StaticFilePointer

from .codesign_definitions import CodesignBlobTypeEnum, CSBlob, CSBlobIndex, CSCodeDirectory, CSSuperblob

logger = strongarm_logger.getChild(__file__)


class CodesignParser:
    """Parser for the CodeSign blobs in __LINKEDIT pointed to by LC_CODE_SIGNATURE.
    https://opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/sys/codesign.h
    https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/kern/cs_blobs.h.auto.html
    https://opensource.apple.com/source/libsecurity_utilities/libsecurity_utilities-55030/lib/blob.h.auto.html
    https://opensource.apple.com/source/Security/Security-57031.1.35/Security/libsecurity_codesigning/lib/CSCommonPriv.h
    """

    def __init__(self, binary: MachoBinary) -> None:
        self.binary = binary
        self.entitlements: bytearray = bytearray(b"<plist></plist>")
        self.signing_identifier: Optional[str] = None
        self.signing_team_id: Optional[str] = None

        # If the binary does not have a code signature, we have nothing to do
        if not self.binary.code_signature_cmd:
            return

        self._codesign_entry = self.binary.code_signature_cmd.dataoff
        self.parse_codesign_blob(self._codesign_entry)

    def read_32_big_endian(self, offset: StaticFilePointer) -> int:
        """Read a 32-bit word from the file offset in big-endian order."""
        word_bytes = self.binary.get_bytes(offset, 4)
        word = int.from_bytes(word_bytes, byteorder="big")
        return word

    def parse_codesign_blob(self, file_offset: StaticFilePointer) -> None:
        """High-level parser to parse the codesign blob at the file offset."""
        magic = self.read_32_big_endian(file_offset)

        if magic == CodesignBlobTypeEnum.CSMAGIC_CODE_DIRECTORY:
            self.parse_code_directory(file_offset)
        elif magic == CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_SIGNATURE:
            self.parse_superblob(file_offset)
        elif magic == CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_ENTITLEMENTS:
            self.entitlements = self.parse_entitlements(file_offset)
        elif magic == CodesignBlobTypeEnum.CSMAGIC_REQUIREMENT:
            pass
        elif magic == CodesignBlobTypeEnum.CSMAGIC_REQUIREMENT_SET:
            pass
        elif magic == CodesignBlobTypeEnum.CSMAGIC_DETACHED_SIGNATURE:
            pass
        elif magic == CodesignBlobTypeEnum.CSMAGIC_BLOBWRAPPER:
            pass
        else:
            # unknown magic
            logger.debug(self, f"Unknown CodeSign blob magic @ {hex(file_offset)}: {hex(magic)}")

    def parse_superblob(self, file_offset: StaticFilePointer) -> None:
        """Parse a codesign 'superblob' at the provided file offset.
        This is a blob which embeds several child blobs.
        The superblob format is the superblob header, followed by several csblob_index structures describing
        the layout of the child blobs.
        """
        internal_file_offset = int(file_offset)
        superblob = self.binary.read_struct(internal_file_offset, CSSuperblob)
        if superblob.magic != CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_SIGNATURE:
            raise RuntimeError(f"Can blobs other than embedded signatures be superblobs? {hex(superblob.magic)}")

        # move past the superblob header to the first index struct entry
        internal_file_offset += superblob.sizeof

        # parse each struct csblob_index following the superblob header
        for i in range(superblob.index_entry_count):
            csblob_index = self.parse_csblob_index(StaticFilePointer(internal_file_offset))
            csblob_file_offset = self._codesign_entry + csblob_index.offset

            # found a blob, now parse it
            self.parse_codesign_blob(StaticFilePointer(csblob_file_offset))

            # iterate to the next blob index struct in list
            internal_file_offset += csblob_index.sizeof

    @staticmethod
    def get_index_blob_name(blob_index: CSBlobIndex) -> str:
        """Get the human-readable blob type from the `type` field in a CSBlobIndex."""
        # cs_blobs.h
        blob_types = {
            0: "Code Directory",
            1: "Info slot",
            2: "Requirement Set",
            3: "Resource Directory",
            4: "Application",
            5: "Embedded Entitlements",
            0x1000: "Alternate Code Directory",
            0x10000: "CMS Signature",
        }
        return blob_types[blob_index.type]

    def parse_csblob_index(self, file_offset: StaticFilePointer) -> CSBlobIndex:
        """Parse a csblob_index at the file offset.
        A csblob_index is a header structure describing the type/layout of a superblob's child blob.
        This method will parse and return the index header.
        """
        blob_index = self.binary.read_struct(file_offset, CSBlobIndex)
        return blob_index

    def parse_code_directory(self, file_offset: StaticFilePointer) -> None:
        """Parse a Code Directory at the file offset."""
        code_directory = self.binary.read_struct(file_offset, CSCodeDirectory)

        identifier_address = code_directory.binary_offset + code_directory.identifier_offset
        identifier_string = self.binary.get_full_string_from_start_address(identifier_address, virtual=False)
        self.signing_identifier = identifier_string

        # Version 0x20100+ includes scatter_offset
        # Version 0x20200+ includes team offset
        if code_directory.version >= 0x20200:
            # Note that if the version < 0x20200, the CSCodeDirectory structure parses past the end of the actual struct
            team_id_address = code_directory.binary_offset + code_directory.team_offset
            team_id_string = self.binary.get_full_string_from_start_address(team_id_address, virtual=False)
            self.signing_team_id = team_id_string

    def print_code_directory(self, code_dir: CSCodeDirectory) -> None:
        print(f"CodeDirectory @ {hex(code_dir.binary_offset)}")
        print("-----------------------")
        print(f"Version: {hex(code_dir.version)}")
        print(f"Flags: {hex(code_dir.flags)}")
        print(f"Hash offset: {hex(code_dir.hash_offset)}")
        print(f"Identifier offset: {hex(code_dir.identifier_offset)}")
        print(f"Special slots count: {code_dir.special_slots_count}")
        print(f"Code limit: {hex(code_dir.code_limit)}")
        print(f"Hash size: {hex(code_dir.hash_size)}")
        print(f"Hash type: {hex(code_dir.hash_type)}")
        print(f"Platform: {hex(code_dir.platform)}")
        print(f"Page size: {hex(code_dir.page_size)}")
        print(f"Scatter offset: {hex(code_dir.scatter_offset)}")
        print(f"Team offset: {hex(code_dir.team_offset)}")
        print()

    def parse_entitlements(self, file_offset: StaticFilePointer) -> bytearray:
        """Parse the embedded entitlements blob at the file offset.
        Returns a bytearray of the embedded entitlements.
        """
        entitlements_blob = self.binary.read_struct(file_offset, CSBlob)
        if entitlements_blob.magic != CodesignBlobTypeEnum.CSMAGIC_EMBEDDED_ENTITLEMENTS:
            raise RuntimeError(f"incorrect magic for embedded entitlements: {hex(entitlements_blob.magic)}")

        blob_end = entitlements_blob.binary_offset + entitlements_blob.length

        xml_start = StaticFilePointer(file_offset + entitlements_blob.sizeof)
        xml_length = blob_end - xml_start
        xml = self.binary.get_bytes(xml_start, xml_length)
        return xml
