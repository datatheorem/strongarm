from ctypes import c_uint32, sizeof
from pathlib import Path
from typing import List, Optional

from strongarm.macho.macho_binary import MachoBinary
from strongarm.macho.macho_definitions import MachArch, MachoFatArch, MachoFatHeader, StaticFilePointer, swap32


class ArchitectureNotSupportedError(Exception):
    pass


class MachoParser:
    _FAT_MAGIC = [MachArch.FAT_MAGIC, MachArch.FAT_CIGAM]
    _MACHO_MAGIC = [MachArch.MH_MAGIC, MachArch.MH_CIGAM, MachArch.MH_MAGIC_64, MachArch.MH_CIGAM_64]
    _BIG_ENDIAN_MAG = [MachArch.FAT_CIGAM, MachArch.MH_CIGAM, MachArch.MH_CIGAM_64]

    _SUPPORTED_SLICE_MAG = MachoBinary.SUPPORTED_MAG

    SUPPORTED_MAG = _FAT_MAGIC + _SUPPORTED_SLICE_MAG

    def __init__(self, path: Path) -> None:
        self.path = path

        self.header: Optional[MachoFatHeader] = None
        self.is_swapped: bool = False
        self.slices: List[MachoBinary] = []

        self.parse()

    def get_arm64_slice(self) -> Optional[MachoBinary]:
        """Retrieve the parsed slice from the FAT built for ARM64."""
        arm64_slices = [x for x in self.slices if x.header.cputype == MachArch.MH_CPU_TYPE_ARM64]
        if len(arm64_slices):
            return arm64_slices[0]
        return None

    def get_armv7_slice(self) -> Optional[MachoBinary]:
        """Retrieve the parsed slice from the FAT built for ARMv7."""
        armv7_slices = [x for x in self.slices if x.header.cputype == MachArch.MH_CPU_TYPE_ARM]
        if len(armv7_slices):
            return armv7_slices[0]
        return None

    def parse(self) -> None:
        """Parse a Mach-O or FAT archive represented by file at a given path
        This method will throw an exception if an binary is passed which is malformed or not a
        valid Mach-O or FAT archive
        """
        if not self.is_magic_supported():
            raise ArchitectureNotSupportedError(self.path.as_posix())

        self.is_swapped = self.should_swap_bytes()

        if self.is_fat:
            self.parse_fat_header()
        else:
            file_size = self.path.stat().st_size
            self.parse_thin_header(StaticFilePointer(0), file_size)

    def parse_thin_header(self, fileoff: StaticFilePointer, slice_size: int) -> None:
        """Parse a known Mach-O header at a given file offset, and add it to self.slices
        This method will throw an Exception if the data at fileoff is not a valid Mach-O header

        Args:
            fileoff: byte index into file to interpret Mach-O header at
            slice_size: Byte-count of the Mach-O slice in the file
        """
        # sanity check
        if not self._check_is_macho_header(fileoff):
            raise RuntimeError(f"Parsing error: data at file offset {hex(int(fileoff))} was not a valid Mach-O slice!")

        slice_data = self.get_bytes(fileoff, slice_size)
        attempt = MachoBinary(self.path, slice_data, file_offset=fileoff)

        # if the MachoBinary does not have a header, there was a problem parsing it
        if not attempt.header:
            raise RuntimeError("parsed MachoBinary missing Mach-O header field")
        self.slices.append(attempt)

    def parse_fat_header(self) -> None:
        """Parse the FAT header implicitly found at the start of the file
        This method will also parse all Mach-O slices that the FAT describes
        """
        # sanity check
        if self._check_is_macho_header(StaticFilePointer(0)):
            raise RuntimeError("Parsing error: Expected FAT header but found incorrect magic!")

        # start reading from the start of the file
        read_off = 0
        header_bytes = bytearray(self.get_bytes(StaticFilePointer(read_off), sizeof(MachoFatHeader)))
        self.header = MachoFatHeader.from_buffer(header_bytes)
        # first fat_arch structure is directly after FAT header
        read_off += sizeof(MachoFatHeader)

        # remember to swap fields if file contains non-native byte order
        if self.is_swapped:
            self.header.nfat_arch = swap32(self.header.nfat_arch)  # type: ignore

        for i in range(self.header.nfat_arch):  # type: ignore
            arch_bytes = self.get_bytes(StaticFilePointer(read_off), sizeof(MachoFatArch))
            fat_arch = MachoFatArch.from_buffer(bytearray(arch_bytes))

            # do we need to byte swap?
            # TODO(pt): come up with more elegant mechanism for swapping byte order in every word of Structure
            if self.is_swapped:
                # non-native byte order, swap every field in fat_arch
                fat_arch.cputype = swap32(int(fat_arch.cputype))
                fat_arch.cpusubtype = swap32(int(fat_arch.cpusubtype))
                fat_arch.offset = swap32(int(fat_arch.offset))
                fat_arch.size = swap32(int(fat_arch.size))
                fat_arch.align = swap32(int(fat_arch.align))

            # TODO(PT): SCAN-2910: Don't skip ARM64E slices
            if fat_arch.cputype == MachArch.MH_CPU_TYPE_ARM64 and fat_arch.cpusubtype == (
                MachArch.MH_CPU_SUBTYPE_PTRAUTH_ABI | MachArch.MH_CPU_SUBTYPE_ARM64E
            ):
                continue

            self.parse_thin_header(StaticFilePointer(fat_arch.offset), fat_arch.size)
            # move to next fat_arch structure in file
            read_off += sizeof(MachoFatArch)

    def _check_is_macho_header(self, offset: StaticFilePointer) -> bool:
        """Check if the data located at a file offset represents a valid Mach-O header, based on the magic

        Args:
            offset: File offset to read magic from

        Returns:
            True if the byte content of the file at 'offset' contain the magic number for a Mach-O slice,
            False if the magic is anything else

        """
        magic = c_uint32.from_buffer(bytearray(self.get_bytes(offset, sizeof(c_uint32)))).value
        return magic in MachoParser._MACHO_MAGIC

    def is_magic_supported(self) -> bool:
        """Check whether a magic number represents a file format which this class is capable of parsing

        Args:
            magic: Magic value denoting file type to check against

        Returns:
            True if the magic number represents a supported file format, False otherwise

        """
        return self.file_magic in MachoParser.SUPPORTED_MAG

    @property
    def file_magic(self) -> int:
        """Read file magic."""
        return c_uint32.from_buffer(bytearray(self.get_bytes(StaticFilePointer(0), sizeof(c_uint32)))).value

    @property
    def is_fat(self) -> bool:
        """Check if file magic indicates a FAT archive or not

        Returns:
            True if the magic indicates FAT format, False otherwise

        """
        return self.file_magic in MachoParser._FAT_MAGIC

    def should_swap_bytes(self) -> bool:
        """Check if we need to swap due to a difference in endianness between host and binary

        Returns:
            True if the host and binary differ in endianness, False otherwise

        """
        # TODO(PT): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
        return self.file_magic in MachoParser._BIG_ENDIAN_MAG

    def get_bytes(self, offset: StaticFilePointer, size: int) -> bytes:
        """Read a byte list from binary file of a given size, starting from a given offset

        Args:
            offset: Offset within file to begin reading from
            size: Maximum number of bytes to read

        Returns:
            Byte list representing contents of file at provided address

        """
        with open(self.path, "rb") as binary_file:
            binary_file.seek(offset)
            return binary_file.read(size)
