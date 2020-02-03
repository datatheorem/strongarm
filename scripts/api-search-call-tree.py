from strongarm import DebugUtil
from strongarm.macho import MachoAnalyzer, MachoParser
from strongarm.objc import CodeSearch, CodeSearchTermCallDestination

DebugUtil.debug = True
binary = MachoParser("./tests/bin/StrongarmTarget").get_arm64_slice()
analyzer = MachoAnalyzer(binary)

# we do not specify a class, because this is an NSURLSessionDelegate method and we don't
# know which class will implement it
desired_selector = "URLSession:didReceiveChallenge:completionHandler:"
implementations = analyzer.get_imps_for_sel(desired_selector)
for imp_function in implementations:
    log_search = CodeSearch(
        [CodeSearchTermCallDestination(binary, invokes_symbol="_NSLog")]
    )
    for search_result in imp_function.search_call_graph(log_search):
        function_containing_log_call = search_result.found_function
        print(
            f"Found a reachable code branch which calls NSLog originating from source function"
            f" {hex(function_containing_log_call.start_address)} at {hex(search_result.found_instruction.address)}"
        )
