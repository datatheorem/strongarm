from typing import Text

from gammaray.ios_app import IosAppPackage
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.objc.objc_analyzer import ObjcBlockAnalyzer


def test_sta_142(path):
    # type: (Text) -> bool
    with IosAppPackage(path) as app_package:
        print('--- STA 142 test on {} ---'.format(path))

        app = app_package.get_main_executable()
        macho = app.get_parsed_binary()
        analyzer = MachoAnalyzer.get_analyzer(macho)

        # get ranges for URLSession:didReceiveChallenge:completionHandler: delegate method IMP
        imp_addr, imp_end = app.get_method_address_range('URLSession:didReceiveChallenge:completionHandler:')
        imp_size = imp_end - imp_addr

        print('Found -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] IMP '
              'from {} to {}'.format(
            hex(int(imp_addr)),
            hex(int(imp_end))
        ))

        # grab machine code for this IMP
        func = macho.get_content_from_virtual_address(virtual_address=imp_addr, size=imp_size)
        instructions = [instr for instr in analyzer.cs.disasm(func, imp_addr)]

        # register signature for URLSession:didReceiveChallenge:completionHandler: will be as follows:
        # x0: self
        # x1: _cmd
        # x2: session
        # x3: challenge
        # x4: completionHandler
        # therefore, we need to track what happens to the block initially in register x4
        block_analyzer = ObjcBlockAnalyzer(macho, instructions, u'x4')

        # get details about completion block invocation
        block_invoke_instr = block_analyzer.invoke_instr
        if not block_invoke_instr:
            print('Buggy app! -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] completion '
                  'block never invoked.')
            return False

        # does this IMP have any branches calling out to _SecTrustEvaluate?
        search_target = '_SecTrustEvaluate'
        target_stub_addr = analyzer.symbol_name_to_address_map[search_target]
        print('Target {} implementation stub at {}'.format(
            search_target,
            hex(int(target_stub_addr))
        ))

        is_target_reachable = block_analyzer.can_execute_call(target_stub_addr)
        print('is {} reachable from any code path from func({})? {}'.format(
            search_target,
            hex(int(imp_addr)),
            is_target_reachable
        ))

        # signature for block invocation:
        # arg0: Block object (applies to all Block invocations)
        # arg1: credentials disposition
        # arg2: user-provided NSURLCredentials
        # find arg1 to block call
        # TODO(PT): deprecate ObjcBlockAnalyzer.get_block_arg()
        block_arg1 = block_analyzer.determine_register_contents('x1', block_analyzer.invoke_idx)

        authChallengeDispositions = ['NSURLSessionAuthChallengeUseCredential',
                                     'NSURLSessionAuthChallengePerformDefaultHandling',
                                     'NSURLSessionAuthChallengeCancelAuthenticationChallenge',
                                     'NSURLSessionAuthChallengeRejectProtectionSpace']

        insecure = False
        # see what kind of behavior this app is requesting for the completion block
        try:
            # if the block argument is a register rather than an immediate, this line will crash,
            # because we have no way to track dataflow in registers.
            # TODO(PT): improve register dataflow analysis so we can read the immediate values in block arguments
            auth_challenge_behavior = authChallengeDispositions[block_arg1]
        except TypeError as e:
            print('Block argument analysis failed. Stronger dataflow analysis required to determine block arg')
            print('WARNING: block arguments not properly analyzed, finding unreliable')
            auth_challenge_behavior = authChallengeDispositions[0]

        if auth_challenge_behavior == 'NSURLSessionAuthChallengeUseCredential':
            # app is saying to accept the credentials
            # did they verify that the credentials were valid?
            if not is_target_reachable:
                insecure = True
        else:
            print('App either rejected or let system handle certificate validation.')

        if insecure:
            print('-[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] deterministically does '
                  'not call SecTrustEvaluate, but uses NSURLSessionAuthChallengeUseCredential. '
                  'This app does not perform certificate validation.')
        else:
            print('App appears to handle certificate validation correctly. AuthDisposition: {} '
                  'SecTrustEvaluate called? {}'.format(
                auth_challenge_behavior,
                is_target_reachable
            ))
    return insecure

paths = [
#    u'./tests/bin/Sportacular.ipa',
#    u'./tests/bin/Events.ipa',
    u'./tests/bin/AdobeAcrobat.ipa',
#    u'./tests/bin/Cricket.ipa',
#    u'./tests/bin/Airbnb.ipa',
#    u'./tests/bin/HealthHub.ipa',
#    u'./tests/bin/GammaRayTestBad.ipa'
]

DebugUtil.debug = True
for app_path in paths:
    print('STA-142 check on {}'.format(app_path))
    vulnerable = test_sta_142(app_path)
    print('{} passed? {}'.format(app_path, not vulnerable))
