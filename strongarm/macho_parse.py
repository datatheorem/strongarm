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

        if not self.check_magic():
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
            raise RuntimeError('Parsing error: MachO archive at {} was not a valid Macho archive!'.format(fileoff))
        self.slices.append(MachoBinary(self._file, fileoff))

    def parse_fat_header(self):
        # sanity check
        if self._check_is_macho_header(0):
            raise RuntimeError('Parsing error: Expected FAT header but found incorrect magic!')

        read_off = 0
        header_bytes = self.get_bytes(0, sizeof(MachoFatHeader))
        read_off += sizeof(MachoFatHeader)
        self.header = MachoFatHeader.from_buffer(bytearray(header_bytes))
        print('header magic {}'.format(hex(self.header.magic)))

        print('Parsing {} MachO slices...'.format(self.header.nfat_arch))
        for i in range(self.header.nfat_arch):
            arch_bytes = self.get_bytes(read_off, sizeof(MachoFatArch))
            read_off += sizeof(MachoFatArch)
            fat_arch = MachoFatArch.from_buffer(bytearray(arch_bytes))

            self.parse_thin_header(fat_arch.offset)

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

    def check_magic(self):
        self._file.seek(0)
        self.magic = c_uint32.from_buffer(bytearray(self._file.read(sizeof(c_uint32)))).value
        # FAT archive?
        if self.magic == MachArch.FAT_MAGIC or self.magic == MachArch.FAT_CIGAM:
            print('FAT archive detected')
            self.is_fat = True
            return True

        if self.magic == MachArch.MH_MAGIC or self.magic == MachArch.MH_CIGAM:
            print('32-bit Mach-O binaries not yet supported.')
            return False
        elif self.magic == MachArch.MH_MAGIC_64 or self.magic == MachArch.MH_CIGAM_64:
            print('64-bit Mach-O magic ok')
            return True
        # unknown magic!
        print('Unrecognized file magic {}'.format(hex(self.magic)))
        return False

    def should_swap_bytes(self):
        # TODO(pt): figure out whether we need to swap to little or big endian,
        # based on system endianness and binary endianness
        # everything we touch currently is little endian, so let's not worry about it for now
        big_endian = [MachArch.MH_MAGIC,
                      MachArch.MH_MAGIC_64,
                      MachArch.FAT_MAGIC,
                      ]
        return self.magic in big_endian

    def get_bytes(self, offset, size):
        self._file.seek(offset)
        return self._file.read(size)

    def __del__(self):
        self._file.close()