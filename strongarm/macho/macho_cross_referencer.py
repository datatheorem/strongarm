from typing import List, Text, Optional, Dict
from macho_binary import MachoBinary


class MachoStringTableEntry(object):
    """Class encapsulating an entry into the Mach-O string table
    """

    def __init__(self, start_idx, length, content):
        self.start_idx = start_idx
        self.length = length
        self.full_string = content


class MachoCrossReferencer(object):
    """Class containing helper functions for processing different tables in a Mach-O
    """

    def __init__(self, binary):
        # type: (MachoBinary) -> None
        self.binary = binary
        self.string_table_entries = self._process_string_table_entries()

    def _process_string_table_entries(self):
        # type: () -> Dict[int, MachoStringTableEntry]
        """Create more efficient representation of string table data

        Often, tables in a Mach-O will reference data within the string table.
        The string table is a large array of characters, representing NULL-terminated strings. There is no seperator
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
        strtab = self.binary.get_raw_string_table()
        for idx, ch in enumerate(strtab):
            # end of current string?
            if ch == '\x00':
                length = idx - entry_start_idx

                # read this string now that we know the start index and length
                entry_end_idx = entry_start_idx + length
                entry_content = ''.join(strtab[entry_start_idx:entry_end_idx:])

                # record in list
                ent = MachoStringTableEntry(entry_start_idx, length, entry_content)
                # max to ensure there's at least 1 entry in list, even if this string entry is just a null char
                # also, add 1 entry for null character
                count_to_include = max(1, length + 1)
                string_table_entries[entry_start_idx] = ent

                # move to starting index of next string
                entry_start_idx = idx + 1
        return string_table_entries

    def string_table_entry_for_strtab_index(self, start_idx):
        # type: (int) -> Optional[MachoStringTableEntry]
        """For a index in the packed character table, get the corresponding MachoStringTableEntry

        Returns:
            True if the provided index was the starting character of a string table entry, None if not
        """
        for ent in self.string_table_entries:
            if ent.start_idx == start_idx:
                return ent
        return None

    def imported_symbol_list(self):
        # type: () -> List[Text]
        """Read symbol names referenced by the symtab command from the string table.

        Returns:
            List of strings representing symbols in binary's string table
        """
        symtab = self.binary.symtab_contents
        symbol_names = []
        for sym in symtab:
            strtab_idx = sym.n_un.n_strx
            symbol_str = self.string_table_entry_for_strtab_index(strtab_idx).full_string
            symbol_names.append(symbol_str)
        return symbol_names
