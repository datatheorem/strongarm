from strongarm.macho import MachoParser, MachoAnalyzer
from strongarm.objc import CodeSearchResult, CodeSearch, CodeSearchTermCallDestination
from strongarm import DebugUtil

DebugUtil.debug = True
binary = MachoParser('./tests/bin/StrongarmTarget').get_arm64_slice()
analyzer = MachoAnalyzer(binary)

# we do not specify a class, because this is an NSURLSessionDelegate method and we don't
# know which class will implement it
desired_selector = 'URLSession:didReceiveChallenge:completionHandler:'
implementations = analyzer.get_imps_for_sel(desired_selector)
for imp_function in implementations:
    log_search = CodeSearch(
        required_matches=[CodeSearchTermCallDestination(binary, invokes_symbol='_NSLog')],
        requires_all_terms_matched=True
    )
    for search_result in imp_function.search_call_graph(log_search):
        function_containing_log_call = search_result.found_function
        print('Found a reachable code branch which calls NSLog originating from source method -[{} {}]'.format(
            function_containing_log_call.objc_class.name,
            function_containing_log_call.objc_class.selector
        ))
