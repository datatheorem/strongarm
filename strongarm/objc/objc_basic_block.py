from typing import List, Text

import objc_analyzer
from strongarm.debug_util import DebugUtil


class ObjcBasicBlock(object):
    def __init__(self, function_analyzer, start_index):
        # type: (objc_analyzer.ObjcFunctionAnalyzer) -> None
        self._function_analyzer = function_analyzer

    @classmethod
    def get_basic_blocks(cls, function_analyzer):
        # type: (objc_analyzer.ObjcFunctionAnalyzer) -> List[ObjcBasicBlock]
        local_branch_instructions = function_analyzer.get_local_branches()

        # TODO(PT): make it more efficient to get the start indexes of local branches
        # first basic block is at index 0
        basic_block_start_indexes = [0]
        # last basic block ends at the last instruction in the function
        basic_block_end_indexes = [len(function_analyzer.instructions)+1]

        for branch in local_branch_instructions:
            # TODO(PT): use instruction address offset from start_address to get instr index
            # this is a constant-time way to get an instruction index from an instruction

            # TODO(PT): this is O(n^2) on the size of the analyzed function! bad bad bad
            instruction_index = 0
            for instr in function_analyzer.instructions:
                if instr.address == branch.destination_address:
                    break
                instruction_index += 1

            # a basic block begins at the branch destination
            basic_block_start_indexes.append(instruction_index)
            # a basic block ends just before the branch destination
            basic_block_end_indexes.append(instruction_index)

            branch_index = function_analyzer.instructions.index(branch.raw_instr)
            # a basic block ends at this branch
            basic_block_start_indexes.append(branch_index+1)
            # a basic block begins after this branch
            basic_block_end_indexes.append(branch_index+1)

        # sort arrays of basic block start/end addresses so we can zip them together into basic block ranges
        basic_block_start_indexes.sort()
        basic_block_end_indexes.sort()

        basic_block_indexes = zip(basic_block_start_indexes, basic_block_end_indexes)
        # trim empty blocks
        for start, end in list(basic_block_indexes):
            if start == end:
                basic_block_indexes.remove((start, end))

        DebugUtil.log(cls, 'local branch indexes: {}'.format(basic_block_indexes))

        basic_blocks = []
        for start_idx, end_idx in basic_block_indexes:
            basic_blocks.append(function_analyzer.instructions[start_idx:end_idx])

        DebugUtil.log(cls, 'Basic blocks for function @ {}'.format(hex(int(function_analyzer.start_address))))
        for idx, block in enumerate(basic_blocks):
            DebugUtil.log(cls, 'Basic Block #{}:'.format(idx))
            for instr in block:
                DebugUtil.log(cls, objc_analyzer.ObjcFunctionAnalyzer.format_instruction(instr))

        return basic_blocks

