from macho_definitions import *
from macho_binary import MachoBinary


class MachoParser(object):
    def __init__(self, filename):
        self.is_swapped = False
        self.magic = 0
        self._file = None

        self.header = None
        self.is_fat = False

        self.slices = []
        self.parse(filename)

    def parse(self, filename):
        self._file = open(filename, 'rb')

        self.magic, self.is_fat = self.check_magic()
        if not self._is_supported(self.magic):
            print('Couldn\'t parse {}'.format(self._file.name))
            return
        self.is_swapped = self.should_swap_bytes()

        if self.is_fat:
            self.header = self.parse_fat_header()
        else:
            self.header = self.parse_thin_header(0)

    def parse_thin_header(self, fileoff):
        # sanity check
        if not self._check_is_macho_header(fileoff):
            raise RuntimeError('Parsing error: MachO archive at {} was not a valid Macho archive!'.format(hex(fileoff)))
        self.slices.append(MachoBinary(self._file, fileoff))

    def _is_little_endian(self, magic):
        return magic in [MachArch.MH_MAGIC,
                         MachArch.MH_MAGIC_64,
                         MachArch.FAT_MAGIC,
                         ]

    def parse_fat_header(self):
        # sanity check
        if self._check_is_macho_header(0):
            raise RuntimeError('Parsing error: Expected FAT header but found incorrect magic!')

        read_off = 0
        self.header = MachoFatHeader.from_buffer(bytearray(self.get_bytes(0, sizeof(MachoFatHeader))))
        read_off += sizeof(MachoFatHeader)

        if self.is_swapped:
            self.header.nfat_arch = swap32(self.header.nfat_arch)

        print('Parsing {} MachO slices...'.format(self.header.nfat_arch))
        for i in range(self.header.nfat_arch):
            arch_bytes = self.get_bytes(read_off, sizeof(MachoFatArch))
            fat_arch = MachoFatArch.from_buffer(bytearray(arch_bytes))

            # do we need to byte swap?
            # TODO(pt): come up with more elegant mechanism for swapping byte order in every word of Structure
            if self.is_swapped:
                fat_arch.cputype = swap32(int(fat_arch.cputype))
                fat_arch.cpusubtype = swap32(int(fat_arch.cpusubtype))
                fat_arch.offset = swap32(int(fat_arch.offset))
                fat_arch.size = swap32(int(fat_arch.size))
                fat_arch.align = swap32(int(fat_arch.align))

            self.parse_thin_header(fat_arch.offset)
            read_off += sizeof(MachoFatArch)

        return self.header

    def _check_is_macho_header(self, offset):
        self._file.seek(offset)
        magic = c_uint32.from_buffer(bytearray(self._file.read(sizeof(c_uint32)))).value
        macho_magics = [MachArch.MH_MAGIC,
                        MachArch.MH_CIGAM,
                        MachArch.MH_MAGIC_64,
                        MachArch.MH_CIGAM_64,
                        ]
        return magic in macho_magics

    def _is_supported(self, magic):
        supported = [
            MachArch.FAT_MAGIC,
            MachArch.FAT_CIGAM,
            MachArch.MH_MAGIC_64,
            MachArch.MH_CIGAM_64,
            ]
        return magic in supported

    def check_magic(self, offset=0):
        self._file.seek(offset)
        magic = c_uint32.from_buffer(bytearray(self._file.read(sizeof(c_uint32)))).value
        is_fat = False
        # FAT archive?
        if magic == MachArch.FAT_MAGIC:
            print('FAT archive @ {} detected (FAT in little endian)'.format(hex(offset)))
            is_fat = True
            return magic, is_fat
        elif magic == MachArch.FAT_CIGAM:
            print('FAT archive @ {} detected (FAT in big endian)'.format(hex(offset)))
            is_fat = True
            return magic, is_fat

        # what kind of Mach O?
        if magic == MachArch.MH_MAGIC or magic == MachArch.MH_CIGAM:
            print('32-bit Mach-O binaries not yet supported.')
            return magic, is_fat
        elif magic == MachArch.MH_MAGIC_64:
            print('64-bit Mach-O magic ok @ {}  (little endian)'.format(hex(offset)))
            return magic, is_fat
        elif magic == MachArch.MH_CIGAM_64:
            print('64-bit Mach-O magic ok @ {} (big endian)'.format(hex(offset)))
            return magic, is_fat
        # unknown magic!
        print('Unrecognized file magic {}'.format(hex(magic)))
        return False

    def should_swap_bytes(self):
        # TODO(pt): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
        big_endian = [MachArch.MH_CIGAM,
                      MachArch.MH_CIGAM_64,
                      MachArch.FAT_CIGAM,
                      ]
        return self.magic in big_endian

    def get_bytes(self, offset, size):
        self._file.seek(offset)
        return self._file.read(size)

    def __del__(self):
        self._file.close()