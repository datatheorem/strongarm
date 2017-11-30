# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals
from __future__ import print_function

from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_query import ObjcPredicateBranchQuery
from strongarm.debug_util import DebugUtil

from njas.resolve_sym import SymbolResolver

binary = MachoParser('./tests/bin/StrongarmTarget').slices[0]
analyzer = MachoAnalyzer.get_analyzer(binary)

nsclass_from_string_check = [ObjcPredicateBranchQuery(binary, destination_symbol='_NSClassFromString')]
objc_get_class_check = [ObjcPredicateBranchQuery(binary, destination_symbol='_objc_getClass')]
dlopen_check = [ObjcPredicateBranchQuery(binary, destination_symbol='_dlopen')]

matches = analyzer.perform_query([nsclass_from_string_check, objc_get_class_check, dlopen_check])

sym_resolver = SymbolResolver()

def print_dlopen_finding(search_result, function_name, function_arg):
    print('-[{} {}]'.format(search_result.objc_class.name, search_result.objc_selector.name))
    print('\t{}({})'.format(function_name, function_arg))


def print_symbol_finding(search_result, function_name, function_arg):
    print('-[{} {}]'.format(search_result.objc_class.name, search_result.objc_selector.name))
    print('\t{}({})'.format(function_name, function_arg))
    print('\t\t{}'.format(source_binary_path))

for result in matches:
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

    found_func = ''
    if result.predicate_list == dlopen_check:
        found_func = 'dlopen'
        if 'PrivateFrameworks' in function_arg:
            print_dlopen_finding(result, found_func, function_arg)
        continue

    elif result.predicate_list == nsclass_from_string_check:
        found_func = 'NSClassFromString'
    elif result.predicate_list == objc_get_class_check:
        found_func = 'objc_getClass'

    # check if the symbol passed to the function was private
    # typically, symbols in symbol tables are prepended with _
    full_symbol_name = '_{}'.format(function_arg)
    source_binary_path = sym_resolver.binary_for_symbol(full_symbol_name)
    if source_binary_path:
        print_symbol_finding(result, found_func, function_arg)
