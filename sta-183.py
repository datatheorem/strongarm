from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.macho.macho_binary import MachoBinary
from strongarm.objc.objc_analyzer import ObjcFunctionAnalyzer
from strongarm.objc.objc_query import ObjcPredicateBranchQuery
from strongarm.debug_util import DebugUtil

from strongarm.macho.macho_definitions import CFStringStruct
from ctypes import c_uint64, sizeof

import njas

DebugUtil.debug = False
binary = MachoParser('./tests/bin/StrongarmTarget').slices[0]
analyzer = MachoAnalyzer.get_analyzer(binary)

nsclass_from_string_check = [ObjcPredicateBranchQuery(binary, destination_symbol='_NSClassFromString')]
objc_get_class_check = [ObjcPredicateBranchQuery(binary, destination_symbol='_objc_getClass')]
dlopen_check = [ObjcPredicateBranchQuery(binary, destination_symbol='_dlopen')]

matches = analyzer.perform_query([nsclass_from_string_check, objc_get_class_check, dlopen_check])

sym_resolver = njas.resolve_sym.SymbolResolver()

for result in matches:
    found_func = ''
    if result.predicate_list == nsclass_from_string_check:
        found_func = 'NSClassFromString'
    elif result.predicate_list == objc_get_class_check:
        found_func = 'objc_getClass'
    elif result.predicate_list == dlopen_check:
        found_func = 'dlopen'
    print('found result at {}'.format(hex(int(result.function_analyzer.start_address))))

    import sys
    #sys.exit(0)

    func = result.function_analyzer
    call_idx = func.instructions.index(result.instruction)
    function_arg, depends_on_argument = func.determine_register_contents('x0', start_index=call_idx)

    if depends_on_argument:
        if function_arg == 0:
            # argument to function depends on method arg 0, which is always 'self' in ObjC
            # since we know we're asking for self's class, use known class name
            function_arg = result.objc_class.name
        else:
            pass
    else:
        function_arg = binary.read_embedded_string(int(function_arg))
    print('-[{} {}]'.format(result.objc_class.name, result.objc_selector.name))
    print('\t{}({})'.format(found_func, function_arg))

    # typically, symbols in symbol tables are prepended with _
    class_symbol = '_{}'.format(function_arg)
    source_binary_path = sym_resolver.binary_for_symbol(class_symbol)
    print('\t\t{}'.format(source_binary_path))
