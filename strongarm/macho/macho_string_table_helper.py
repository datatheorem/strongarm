from typing import Dict, List, Optional

from strongarm.macho.macho_binary import MachoBinary, VirtualMemoryPointer
from strongarm.macho.macho_definitions import NLIST_NTYPE, NTYPE_VALUES


class MachoStringTableEntry:
    """Class encapsulating an entry into the Mach-O string table."""

    __slots__ = ["start_idx", "length", "full_string"]

    def __init__(self, start_idx: int, length: int, content: str) -> None:
        self.start_idx = start_idx
        self.length = length
        self.full_string = content


class MachoStringTableHelper:
    """Class containing helper functions for processing different tables in a Mach-O."""

    # TODO(PT): generalize the preprocessing of a string table where we efficiently map string start addresses to
    # full strings, so we don't need to do an O(n) search for a (struct __objc_data).name or something

    def __init__(self, binary: MachoBinary) -> None:
        self.binary = binary
        self.string_table_entries = MachoStringTableHelper.transform_string_section(self.binary.get_raw_string_table())
        self.imported_symbols: List[str] = []
        self.exported_symbols: Dict[VirtualMemoryPointer, str] = {}
        self.parse_sym_lists()

    @classmethod
    def transform_string_section(cls, strtab: List[int]) -> Dict[int, MachoStringTableEntry]:
        """Create more efficient representation of string table data

        Often, tables in a Mach-O will reference data within the string table.
        The string table is a large array of characters, representing NULL-terminated strings. There is no separator
        between entries aside from a NULL terminator. When other sections reference a string table entry, they will
        only reference the starting index. Thus, if we did no other processing, every time we got an index we'd need to
        do an O(n) loop to find the next NULL character, indicating the end of the string.

        To avoid this, we preprocess the string table into the full strings it represents. To make these lookups easier,
        we create a map of start indexes to MachoStringTableEntry's

        Returns:
            Map of string table entry start indexes to MachoStringTableEntry's
        """
        string_table_entries = {}
        entry_start_idx = 0
        for idx, ch in enumerate(strtab):
            # end of current string?
            if ch == 0x00:
                length = idx - entry_start_idx

                # read this string now that we know the start index and length
                entry_end_idx = entry_start_idx + length
                entry_byte_content = bytearray(strtab[entry_start_idx:entry_end_idx:])
                try:
                    entry_content = entry_byte_content.decode("utf-8")
                except UnicodeDecodeError:
                    # get a string literal of the raw bytes. 0x0080 -> "b'\\x00\\x80'"
                    entry_content = str(bytes(entry_byte_content))

                # record in list
                ent = MachoStringTableEntry(entry_start_idx, length, entry_content)
                string_table_entries[entry_start_idx] = ent

                # move to starting index of next string
                entry_start_idx = idx + 1
        return string_table_entries

    def string_table_entry_for_strtab_index(self, start_idx: int) -> Optional[MachoStringTableEntry]:
        """For a index in the packed character table, get the corresponding MachoStringTableEntry

        Returns:
            A MachoStringTableEntry if provided index was the starting character of a string table entry, None if not
        """
        if start_idx in self.string_table_entries:
            return self.string_table_entries[start_idx]
        return None

    def parse_sym_lists(self) -> None:
        """Read imported and exported symbol names referenced by symtab from the string table."""

        self.imported_symbols = []

        symtab = self.binary.symtab_contents
        for idx, sym in enumerate(symtab):
            strtab_idx = sym.n_un.n_strx
            string_table_entry = self.string_table_entry_for_strtab_index(strtab_idx)
            if not string_table_entry:
                continue
            symbol_str = string_table_entry.full_string

            is_shared_symbol = int(sym.n_type & NLIST_NTYPE.N_EXT)
            symbol_type = sym.n_type & NLIST_NTYPE.N_TYPE

            if symbol_type == NTYPE_VALUES.N_UNDF:
                # symbols marked (imported, shared) are actually duplicated as exported symbols later in the symbol
                # table. I don't know why this is.
                # Let's just ignore (imported, shared) symbols. If they do contain duplicate entries as exported
                # symbols later, they'll be caught then.
                if not is_shared_symbol:
                    continue
                self.imported_symbols.append(symbol_str)
            elif symbol_type == NTYPE_VALUES.N_SECT:
                self.exported_symbols[sym.n_value] = symbol_str

    def get_symbol_name_for_address(self, address: VirtualMemoryPointer) -> Optional[str]:
        """For an address of a function entrypoint, return the function's symbol name."""
        if address in self.exported_symbols:
            return self.exported_symbols[address]
        return None
