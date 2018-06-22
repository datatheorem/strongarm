# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from time import time

from strongarm.macho import MachoAnalyzer
from strongarm.macho import MachoParser
from strongarm.objc import CodeSearch, CodeSearchTermCallDestination, RegisterContentsType
from strongarm.debug_util import DebugUtil

start_time = time()

DebugUtil.debug = True

path = '/Users/philliptennen/apps/Netflix/saved/Argo'
parser = MachoParser(path)
binary = parser.get_arm64_slice()
analyzer = MachoAnalyzer.get_analyzer(binary)

code_search = CodeSearch(
    [
        CodeSearchTermCallDestination(binary, invokes_symbol='_NSLog'),
        CodeSearchTermCallDestination(binary, invokes_symbol='_dlopen')
    ],
)
matches = analyzer.search_code(code_search)
for search_result in matches:
    found_function = search_result.found_function
    found_instruction = search_result.found_instruction
    method_info = found_function.method_info
    caller_signature = '-[{} {}]'.format(method_info.objc_class.name, method_info.objc_sel.name)

    register_contents = found_function.get_register_contents_at_instruction('x0', found_instruction)
    if register_contents.type != RegisterContentsType.IMMEDIATE:
        # we couldn't statically figure out the function argument, so skip it
        continue
    function_arg = binary.read_string_at_address(register_contents.value)
    if not function_arg:
        # reading the string could have failed
        continue

    print('{} calls {} with arg0: {}'.format(
        caller_signature,
        search_result.matched_search_terms[0].invokes_symbol,
        function_arg
    ))

end_time = time()
print('time: {}'.format(end_time - start_time))

import sys
sys.exit(0)
