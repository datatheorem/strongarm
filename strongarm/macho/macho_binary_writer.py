from ctypes import c_uint32, c_uint64, sizeof
from dataclasses import dataclass
from types import TracebackType
from typing import List, Optional, Type, Union

from .macho_binary import MachoBinary, StaticFilePointer, VirtualMemoryPointer


@dataclass
class MachoBinaryQueuedWrite:
    file_offset: StaticFilePointer
    bytes_to_write: bytearray


class MachoBinaryWriter:
    def __init__(self, binary: MachoBinary) -> None:
        self.binary = binary
        self.modified_binary = binary
        self.queued_writes: List[MachoBinaryQueuedWrite] = []

    def __enter__(self) -> None:
        pass

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> None:
        # Create a new binary with the overwritten data
        new_binary_data = bytearray(len(self.binary._cached_binary))
        new_binary_data[:] = self.binary._cached_binary
        for write in self.queued_writes:
            new_binary_data[write.file_offset : write.file_offset + len(write.bytes_to_write)] = write.bytes_to_write

        self.modified_binary = MachoBinary(self.binary.path, new_binary_data,)

    def write_word(self, word: Union[c_uint32, c_uint64], address: int, virtual: bool = True) -> None:
        """Enqueue a write of the provided word to the binary.
        Note: This will invalidate the binary's code signature, if present.
        """
        # Ensure there is valid data in this address region by trying to read from it
        self.binary.get_contents_from_address(address, sizeof(word), virtual)

        # If the above did not throw an exception, the provided address range is valid.
        file_offset = StaticFilePointer(address)
        if virtual:
            file_offset = self.binary.file_offset_for_virtual_address(VirtualMemoryPointer(address))

        # Queue a binary write here
        self.queued_writes.append(
            MachoBinaryQueuedWrite(
                file_offset=file_offset,
                bytes_to_write=bytearray(word.value.to_bytes(length=sizeof(word), byteorder="little")),
            )
        )
