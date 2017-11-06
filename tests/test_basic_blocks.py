from __future__ import absolute_import
from __future__ import unicode_literals

import os
import unittest

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer
from strongarm.objc.objc_basic_block import ObjcBasicBlock
from strongarm.debug_util import DebugUtil

class TestBasicBlocks(unittest.TestCase):
    TARGET_PATH = os.path.join(os.path.dirname(__file__), 'bin', 'StrongarmControlFlowTarget')

    def setUp(self):
        # turn on strongarm debug output
        DebugUtil.debug = True

        parser = MachoParser(TestBasicBlocks.TARGET_PATH)
        self.binary = parser.slices[0]
        self.analyzer = MachoAnalyzer.get_analyzer(self.binary)

    def test_get_basic_block_list(self):
        target_method_addr, _ = self.analyzer.get_method_address_ranges('switchControlFlow')[0]
        print('target_method_addr {}'.format(target_method_addr))
        instructions = self.analyzer.get_function_instructions(target_method_addr)
        function_analyzer = ObjcFunctionAnalyzer(self.binary, instructions)

        basic_blocks = ObjcBasicBlock.get_basic_blocks(function_analyzer)
        print('got basic blocks {}'.format(basic_blocks))
