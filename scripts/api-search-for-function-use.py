# TODO(PT): This file is out of date
from strongarm.macho import MachoAnalyzer, MachoParser
from strongarm.objc import CodeSearch, RegisterContentsType

binary = MachoParser("./tests/bin/StrongarmControlFlowTarget").get_arm64_slice()
analyzer = MachoAnalyzer(binary)

log_search = CodeSearch(
    [
        CodeSearchTermCallDestination(binary, invokes_symbol="_printf"),
        CodeSearchTermCallDestination(binary, invokes_symbol="_NSLog"),
    ]
)
search_results = analyzer.queue_code_search(log_search)
for search_result in search_results:
    function_containing_log_call = search_result.found_function
    method_info = function_containing_log_call.method_info
    log_call_instruction = search_result.found_instruction
    print(
        f"Found call to {log_call_instruction.symbol} in -[{method_info.objc_class.name} {method_info.objc_sel.name}]"
        f" at {hex(method_info.imp_addr)}:"
    )

    string_arg = function_containing_log_call.get_register_contents_at_instruction(
        register="r0", instruction=log_call_instruction
    )
    # the string passed to the log call may have been passed as an argument to this function
    if string_arg.type == RegisterContentsType.FUNCTION_ARG:
        print(
            f"\t{log_call_instruction.symbol}() called with a string passed to function"
            f" {hex(function_containing_log_call.start_address)} in argument #{string_arg.value}"
        )
    elif string_arg.type == RegisterContentsType.IMMEDIATE:
        # string_arg is a pointer to the string literal. Read it!
        string_to_print = binary.read_string_at_address(string_arg.value)
        print(
            f'\t{hex(log_call_instruction.address)}: {log_call_instruction.symbol}("{string_to_print}")'
        )
