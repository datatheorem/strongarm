from typing import List

from strongarm.macho import VirtualMemoryPointer, MachoBinary


class ObjcBasicBlockLocation(object):
    def __init__(self,
                 function_analyzer: 'ObjcFunctionAnalyzer',
                 start_address: VirtualMemoryPointer,
                 end_address: VirtualMemoryPointer) -> None:
        self.start_address = start_address
        self.start_instr_idx = (start_address - function_analyzer.start_address) / MachoBinary.BYTES_PER_INSTRUCTION

        self.end_address = end_address
        self.end_instr_idx = (end_address - function_analyzer.start_address) / MachoBinary.BYTES_PER_INSTRUCTION

    @classmethod
    def find_basic_blocks(cls, function_analyzer: 'ObjcFunctionAnalyzer') -> List['ObjcBasicBlockLocation']:
        from .objc_analyzer import ObjcFunctionAnalyzer
        local_branch_instructions = function_analyzer.get_local_branches()

        # first basic block is at index 0
        basic_block_start_indexes = [0]
        # last basic block ends at the last instruction in the function
        basic_block_end_indexes = [len(function_analyzer.instructions)+1]

        for branch in local_branch_instructions:
            instruction_index = (function_analyzer.start_address - branch.address) / MachoBinary.BYTES_PER_INSTRUCTION

            # a basic block begins at the branch destination
            basic_block_start_indexes.append(instruction_index)
            # a basic block ends just before the branch destination
            basic_block_end_indexes.append(instruction_index)

            branch_index = function_analyzer.instructions.index(branch.raw_instr)
            # a basic block ends at this branch
            basic_block_start_indexes.append(branch_index + 1)
            # a basic block begins after this branch
            basic_block_end_indexes.append(branch_index + 1)

        # sort arrays of basic block start/end addresses so we can zip them together into basic block ranges
        basic_block_start_indexes.sort()
        basic_block_end_indexes.sort()

        basic_block_indexes = list(zip(basic_block_start_indexes, basic_block_end_indexes))
        # trim empty blocks
        for start, end in list(basic_block_indexes):
            if start == end:
                basic_block_indexes.remove((start, end))

        basic_blocks = []
        for start_idx, end_idx in basic_block_indexes:
            start_address = function_analyzer.start_address + (start_idx * MachoBinary.BYTES_PER_INSTRUCTION)
            end_address = function_analyzer.start_address + (end_idx * MachoBinary.BYTES_PER_INSTRUCTION)
            bb = ObjcBasicBlockLocation(function_analyzer, start_address, end_address)
            basic_blocks.append(bb)

        return basic_blocks
