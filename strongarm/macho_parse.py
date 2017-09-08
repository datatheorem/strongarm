from typing import Text
from ctypes import *

class MachoHeader64(Structure):
    _fields_ = [
        ('magic', c_uint32),
        ('cputype', c_uint32),
        ('cpusubtype', c_uint32),
        ('filetype', c_uint32),
        ('ncmds', c_uint32),
        ('sizeofcmds', c_uint32),
        ('flags', c_uint32),
        ('reserved', c_uint32),
    ]

class MachoSegmentCommand64(Structure):
    _fields_ = [
        ('cmd', c_int32),
        ('cmdsize', c_int32),
        ('segname', c_char * 16),
        ('vmaddr', c_uint64),
        ('vmsize', c_uint64),
        ('fileoff', c_uint64),
        ('filesize', c_uint64),
        ('maxprot', c_uint32),
        ('initprot', c_uint32),
        ('nsects', c_uint32),
        ('flags', c_uint32),
    ]

class MachOLoadCommand(Structure):
    _fields_ = [
        ('cmd', c_uint32),
        ('cmdsize', c_uint32),
    ]

class MachoSection64(Structure):
    _fields_ = [
        ('sectname', c_char * 16),
        ('segname', c_char * 16),
        ('addr', c_int64),
        ('size', c_int64),
        ('offset', c_int32),
        ('align', c_int32),
        ('reloff', c_int32),
        ('nreloc', c_int32),
        ('flags', c_int32),
        ('reserved1', c_int32),
        ('reserved2', c_int32),
        ('reserved3', c_int32),
    ]


class MachoParser(object):
    MH_MAGIC = 0xfeedface
    MH_CIGAM = 0xcefaedfe
    MH_MAGIC_64 = 0xfeedfacf
    MH_CIGAM_64 = 0xcffaedfe

    LC_SEGMENT = 0x1
    LC_SEGMENT_64 = 0x19

    def __init__(self, filename):
        self.is_64bit = False
        self.is_swapped = False
        self.load_commands_offset = 0
        self.magic = 0
        self._file = None
        self.segments = {}
        self.sections = {}

        self.parse(filename)

    def parse(self, filename):
        self._file = open(filename, 'rb')

        if not self.check_magic():
            print('Couldn\'t parse {}'.format(self._file.name))
            return
        self.is_64bit = self.magic_is_64()
        self.is_swapped = self.should_swap_bytes()
        self.parse_header()
        self._file.close()

    def check_magic(self):
        self._file.seek(0)
        self.magic = c_uint32.from_buffer(bytearray(self._file.read(sizeof(c_uint32)))).value
        if self.magic == self.MH_MAGIC or self.magic == self.MH_CIGAM:
            print('32-bit Mach-O binaries not yet supported.')
            return False
        elif self.magic == self.MH_MAGIC_64 or self.magic == self.MH_CIGAM_64:
            print('64-bit Mach-O magic ok')
            return True
        # unknown magic!
        print('Unrecognized file magic {}'.format(self.magic))
        return False

    def should_swap_bytes(self):
        return self.magic == self.MH_CIGAM_64 or self.magic == self.MH_CIGAM

    def magic_is_64(self):
        return self.magic == self.MH_MAGIC_64 or self.magic == self.MH_CIGAM_64

    def get_bytes(self, offset, size):
        self._file.seek(offset)
        return self._file.read(size)

    def parse_segments(self):
        pass

    def parse_header(self):
        header_bytes = self.get_bytes(0, sizeof(MachoHeader64))
        header = MachoHeader64.from_buffer(bytearray(header_bytes))
        self.num_commands = header.ncmds
        self.load_commands_offset += sizeof(MachoHeader64)
        self.parse_segment_commands(self.load_commands_offset)

    def parse_segment_commands(self, offset):
        for i in xrange(self.num_commands):
            load_command_bytes = self.get_bytes(offset, sizeof(MachOLoadCommand))
            load_command = MachOLoadCommand.from_buffer(bytearray(load_command_bytes))
            # TODO(pt) handle byte swap of load_command
            if load_command.cmd == self.LC_SEGMENT_64:
                segment_bytes = self.get_bytes(offset, sizeof(MachoSegmentCommand64))
                segment = MachoSegmentCommand64.from_buffer(bytearray(segment_bytes))
                # TODO(pt) handle byte swap of segment
                self.segments[segment.segname] = segment
                #print('Segment {} @ off {}'.format(segment.segname, hex(offset)))
                self.parse_sections(segment, offset)
            elif load_command.cmd == self.LC_SEGMENT:
                print('32-bit segments not supported!')
            offset += load_command.cmdsize

    def parse_sections(self, segment, segment_offset):
        if not segment.nsects:
            return

        section_offset = segment_offset + sizeof(MachoSegmentCommand64)
        section_size = sizeof(MachoSection64)
        for i in xrange(segment.nsects):
            section_bytes = self.get_bytes(section_offset, sizeof(MachoSection64))
            section = MachoSection64.from_buffer(bytearray(section_bytes))
            # TODO(pt) handle byte swap of segment
            self.sections[section.sectname] = section
            #print('\tSection {} @ off {}'.format(section.sectname, hex(section_offset)))

            section_offset += section_size
