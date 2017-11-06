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
        DebugUtil.log(ObjcBasicBlock, 'local branches: {}'.format(local_branch_instructions))

        # TODO(PT): make it more efficient to get the start indexes of local branches
        # first basic block is at index 0
        local_branch_start_indexes = [0]
        for branch in local_branch_instructions:
            idx = function_analyzer._instructions.index(branch.raw_instr)
            local_branch_start_indexes.append(idx)

        # sort basic block start index order so we can figure out where each block ends
        local_branch_start_indexes.sort()

        # the end index of each basic block is one less than the start index of the next basic block
        local_branch_end_indexes = []
        # start from the first basic block after instruction at index 0
        for idx in local_branch_start_indexes[1::]:
            local_branch_end_indexes.append(idx-1)
        # the last basic block ends at the end of the function
        local_branch_end_indexes.append(len(function_analyzer._instructions))

        DebugUtil.log(cls, 'local branch start indexes {}'.format(local_branch_start_indexes))
        DebugUtil.log(cls, 'local branch end   indexes {}'.format(local_branch_end_indexes))

        basic_block_indexes = zip(local_branch_start_indexes, local_branch_end_indexes)
        DebugUtil.log(cls, 'local branch indexes: {}'.format(basic_block_indexes))

        basic_blocks = []
        for start_idx, end_idx in basic_block_indexes:
            basic_blocks.append(function_analyzer._instructions[start_idx:end_idx])

        DebugUtil.log(cls, 'Basic blocks for function @ {}'.format(hex(int(function_analyzer.start_address))))
        for idx, block in enumerate(basic_blocks):
            DebugUtil.log(cls, 'Basic Block #{}:'.format(idx))
            for instr in block:
                DebugUtil.log(cls, objc_analyzer.ObjcFunctionAnalyzer.format_instruction(instr))

        return basic_blocks

