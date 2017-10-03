from macho_definitions import *
from macho_binary import MachoBinary


class MachoParser(object):
    def __init__(self, filename):
        # type: (str) -> MachoParser
        self.is_swapped = False
        self.magic = 0
        self._file = None

        self.header = None
        self.is_fat = False

        self.slices = []
        self.parse(filename)

    def parse(self, filename):
        # type: (str) -> None
        """
        Parse a Mach-O or FAT archive
        This method will throw an exception if an binary is passed which is malformed or not a
        valid Mach-O or FAT archive
        Args:
            filename: path to binary to interpret
        """
        self._file = open(filename, 'rb')

        self.magic, self.is_fat = self.check_magic()
        if not self._is_supported(self.magic):
            raise RuntimeError('Unsupported Mach-O magic {}'.format(
                hex(int(self.magic))
            ))

        self.is_swapped = self.should_swap_bytes()

        if self.is_fat:
            self.header = self.parse_fat_header()
        else:
            self.header = self.parse_thin_header(0)

    def parse_thin_header(self, fileoff):
        # type: (int) -> None
        """
        Parse a known Mach-O header at a given file offset, and add it to self.slices
        This method will throw an Exception if the data at fileoff is not a valid Mach-O header
        Args:
            fileoff: byte index into file to interpret Mach-O header at
        """
        # sanity check
        if not self._check_is_macho_header(fileoff):
            raise RuntimeError('Parsing error: MachO archive at {} was not a valid Macho archive!'.format(hex(fileoff)))

        # MachoBinary constructor will throw an exception if the header can't be parsed
        try:
            attempt = MachoBinary(self._file, fileoff)
            # if the MachoBinary does not have a header, there was a problem parsing it
            if attempt.header:
                self.slices.append(attempt)
        except RuntimeError as e:
            pass

    @staticmethod
    def _is_little_endian(magic):
        # type: (int) -> bool
        """
        Check whether a given magic represents a little endian MachO or FAT archive
        Args:
            magic: magic value to check type of

        Returns:
            True if the magic corresponds to a little endian Mach-O or FAT archive, False otherwise
        """
        return magic in [MachArch.MH_MAGIC,
                         MachArch.MH_MAGIC_64,
                         MachArch.FAT_MAGIC,
                         ]

    def parse_fat_header(self):
        # type: (None) -> None
        """
        Parse the FAT header implicitly found at the start of the file
        This method will also parse all Mach-O's that the FAT describes
        """
        # sanity check
        if self._check_is_macho_header(0):
            raise RuntimeError('Parsing error: Expected FAT header but found incorrect magic!')


        # start reading from the start of the file
        read_off = 0
        self.header = MachoFatHeader.from_buffer(bytearray(self.get_bytes(0, sizeof(MachoFatHeader))))
        # first fat_arch structure is directly after FAT header
        read_off += sizeof(MachoFatHeader)

        # remember to swap fields if file contains non-native byte order
        if self.is_swapped:
            self.header.nfat_arch = swap32(self.header.nfat_arch)

        for i in range(self.header.nfat_arch):
            arch_bytes = self.get_bytes(read_off, sizeof(MachoFatArch))
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

            self.parse_thin_header(fat_arch.offset)
            # move to next fat_arch structure in file
            read_off += sizeof(MachoFatArch)

        return self.header

    def _check_is_macho_header(self, offset):
        # type: (int) -> bool
        """
        Check if the bytes located at a file offset represents a valid Mach-O header, based on the magic
        Args:
            offset: File offset to read magic from
        Returns:
            True if the byte content of the file at 'offset' contain the magic number for Mach-O slices,
            False if the content is something else
        """
        self._file.seek(offset)
        magic = c_uint32.from_buffer(bytearray(self._file.read(sizeof(c_uint32)))).value
        macho_magics = [MachArch.MH_MAGIC,
                        MachArch.MH_CIGAM,
                        MachArch.MH_MAGIC_64,
                        MachArch.MH_CIGAM_64,
                        ]
        return magic in macho_magics

    def _is_supported(self, magic):
        # type: (int) -> bool
        """
        Check whether a magic number represents a file format which this class is capable of parsing
        Args:
            magic: Magic value denoting file type to check against
        Returns:
            True if the magic number represents a supported file format, False otherwise
        """
        supported = [
            MachArch.FAT_MAGIC,
            MachArch.FAT_CIGAM,
            MachArch.MH_MAGIC_64,
            MachArch.MH_CIGAM_64,
            ]
        return magic in supported

    def check_magic(self, offset=0):
        # type: (int) -> (int, bool)
        """
        Parse file magic and return the magic, and whether the format represents a FAT
        Args:
            offset: File offset to read the header from
        Returns:
            A tuple containing the magic that was read, and a bool indicating whether the header is a FAT
        """
        magic = c_uint32.from_buffer(bytearray(self.get_bytes(offset, sizeof(c_uint32)))).value
        is_fat = False
        # FAT archive?
        if magic == MachArch.FAT_MAGIC or magic == MachArch.FAT_CIGAM:
            is_fat = True
        return magic, is_fat

    def should_swap_bytes(self):
        # type: (None) -> bool
        """
        Check if we need to swap due to a difference in endianness between host and binary
        Returns:
            True if the host and binary differ in endianness, False otherwise
        """
        # TODO(pt): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
        big_endian = [MachArch.MH_CIGAM,
                      MachArch.MH_CIGAM_64,
                      MachArch.FAT_CIGAM,
                      ]
        return self.magic in big_endian

    def get_bytes(self, offset, size):
        # type: (int, int) -> str
        """
        Retrieve a string containing up to 'size' bytes beginning from file offset 'offset'
        Args:
            offset: Offset within file to begin reading from
            size: Maximum number of bytes to read

        Returns:
            String representing byte contents of file at provided address
        """
        self._file.seek(offset)
        return self._file.read(size)

    def __del__(self):
        # don't waste this file descriptor!
        # close open file once the object is destroyed
        self._file.close()
