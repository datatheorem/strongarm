from typing import Text
import os

from gammaray.ios_app import IosAppPackage
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcBlockAnalyzer


def test_sta_142(path):
    # type: (Text) -> (bool, int)
    with IosAppPackage(path) as app_package:
        print('--- STA 142 test on {} ---'.format(path))

        app_path = app_package.get_main_executable().get_path()
        macho = MachoParser(app_path).slices[0]
        analyzer = MachoAnalyzer.get_analyzer(macho)

        # get ranges for URLSession:didReceiveChallenge:completionHandler: delegate method IMP
        implementations = analyzer.get_implementations('URLSession:didReceiveChallenge:completionHandler:')

        for instructions in implementations:
            imp_addr = instructions[0].address
            imp_end = instructions[len(instructions)-1].address
            print('Found -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] IMP '
                  'from {} to {}'.format(
                hex(int(imp_addr)),
                hex(int(imp_end))
            ))

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
                return False, 0

            # does this IMP have any branches calling out to _SecTrustEvaluate?
            search_target = '_SecTrustEvaluate'
            target_stub_addr = analyzer.external_symbol_names_to_branch_destinations[search_target]
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

            # check if there's any control flow before block invocation
            local_branches = block_analyzer.get_local_branches()
            for b in local_branches:
                branch_idx = instructions.index(b.raw_instr)
                # did the branch happen before the block invocation?
                if branch_idx < block_analyzer.invoke_idx:
                    # no way to know what's going on with control flow
                    print('branch idx {} block invoke idx {}'.format(branch_idx, block_analyzer.invoke_idx))
                    print('control flow before block invocation, assuming correct behavior')
                    return False, 0

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
                # return insecure - True
                return True, imp_addr
            else:
                print('App appears to handle certificate validation correctly. AuthDisposition: {} '
                      'SecTrustEvaluate called? {}'.format(
                    auth_challenge_behavior,
                    is_target_reachable
                ))
    # exited loop and no implementations of the selector failed test
    # not insecure, return False
    return False, 0

from strongarm.debug_util import DebugUtil

#DebugUtil.debug = True
vulnerable_apps = []
safe_apps = []

apps_dir = os.path.join(os.path.dirname(__file__), 'sta-142/')
for app_path in os.listdir(apps_dir):
    app_path = os.path.join(apps_dir, app_path)
    app_path = unicode(app_path)

    if app_path.endswith('.ipa'):
        print('STA-142 check on {}'.format(app_path))
        is_vulnerable, vuln_method_addr = test_sta_142(app_path)
        if is_vulnerable:
            vulnerable_apps.append((app_path, vuln_method_addr))
        else:
            safe_apps.append(app_path)
        print('{} passed? {}'.format(app_path, not is_vulnerable))

with open('STA-142-Results.txt', 'w') as output:
    output.write('Passing apps:\n')
    for name in safe_apps:
        output.write('{}\n'.format(name))
    output.write('\nFailing apps:\n')
    for name, addr in vulnerable_apps:
        output.write('{} at {}\n'.format(name, hex(int(addr))))
