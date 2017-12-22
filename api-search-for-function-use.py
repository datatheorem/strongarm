from strongarm.macho import MachoParser
from strongarm.macho import MachoAnalyzer
from strongarm.objc import CodeSearchResult, CodeSearch, CodeSearchTermCallDestination

binary = MachoParser('./tests/bin/GammaRayTestBad').get_arm64_slice()
analyzer = MachoAnalyzer

log_search = CodeSearch(
    required_matches=[
        CodeSearchTermCallDestination(binary, invokes_symbol='_printf'),
        CodeSearchTermCallDestination(binary, invokes_symbol='_NSLog')
    ],
    requires_all_terms_matched=False
)
for function_containing_log_call, log_call_instruction in analyzer.search_code(log_search):
    print('Found call to {} in -[{} {}] at {}'.format(
        log_call_instruction.symbol,
        function_containing_log_call.objc_class.name,
        function_containing_log_call.objc_selector.name,
        log_call_instruction.address,
    ))

    string_arg = log_call_instruction.get_argument(0)
    # the string passed to the log call may have been passed as an argument to this function
    if string_arg.type == FUNCTION_ARG:
        print('{}() called with a string passed to function {} in argument #{}'.format(
            log_call_instruction.symbol,
            hex(function_containing_log_call.start_address),
            string_arg.value
        ))
    elif string_arg.type == IMMEDIATE:
        # string_arg is a pointer to the string literal. Read it!
        string_to_print = binary.read_string_at_address(string_arg)
        print('Function called {}(\"{}\")'.format(
            log_call_instruction.symbol,
            string_to_print
        ))

