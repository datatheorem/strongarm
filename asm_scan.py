from typing import Text
import os

from gammaray.ios_app import IosAppPackage
from strongarm.macho.macho_analyzer import MachoAnalyzer
from strongarm.macho.macho_parse import MachoParser
from strongarm.objc.objc_analyzer import ObjcBlockAnalyzer


authChallengeDispositions = ['NSURLSessionAuthChallengeUseCredential',
                             'NSURLSessionAuthChallengePerformDefaultHandling',
                             'NSURLSessionAuthChallengeCancelAuthenticationChallenge',
                             'NSURLSessionAuthChallengeRejectProtectionSpace']


def control_flow_before_block(block_analyzer):
    # check if there's any control flow before block invocation
    local_branches = block_analyzer.get_local_branches()
    for b in local_branches:
        branch_idx = block_analyzer.instructions.index(b.raw_instr)
        print('branch index {} block invoke index {}'.format(
            hex(branch_idx),
            hex(block_analyzer.invocation_instruction_index)
        ))
        # did the branch happen before the block invocation?
        if branch_idx < block_analyzer.invocation_instruction_index:
            # no way to know what's going on with control flow
            print('branch idx {} block invoke idx {}'.format(
                branch_idx,
                block_analyzer.invocation_instruction_index
            ))
            return True
    print('no control flow before block invocation')
    return False


def get_auth_challenge_disposition(block_analyzer):
    # signature for block invocation:
    # arg0: Block object (applies to all Block invocations)
    # arg1: credentials disposition
    # arg2: user-provided NSURLCredentials
    # find arg1 to block call
    # TODO(PT): deprecate ObjcBlockAnalyzer.get_block_arg()
    block_arg1 = block_analyzer.determine_register_contents('x1', block_analyzer.invocation_instruction_index)
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
    return auth_challenge_behavior


def test_sta_142(path):
    # type: (Text) -> (bool, int)
    with IosAppPackage(path) as app_package:
        print('--- STA 142 test on {} ---'.format(path))

        app_path = app_package.get_main_executable().get_path()
        macho = MachoParser(app_path).slices[0]
        macho_analyzer = MachoAnalyzer.get_analyzer(macho)

        # get ranges for URLSession:didReceiveChallenge:completionHandler: delegate method IMP
        implementations = macho_analyzer.get_implementations('URLSession:didReceiveChallenge:completionHandler:')

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
            try:
                block_analyzer = ObjcBlockAnalyzer(macho, instructions, u'x4')
            except RuntimeError as e:
                print('CAUGHT BUG ON APP')
                return False, 0

            # get details about completion block invocation
            block_invoke_instr = block_analyzer.invoke_instruction
            if not block_invoke_instr:
                print('Buggy app! -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] completion '
                      'block never invoked.')
                return True, imp_addr

            # does this IMP have any branches calling out to _SecTrustEvaluate?
            does_delegate_call_SecTrustEvaluate = False
            search_target = '_SecTrustEvaluate'
            if search_target in macho_analyzer.external_symbol_names_to_branch_destinations:
                target_stub_addr = macho_analyzer.external_symbol_names_to_branch_destinations[search_target]
                print('Target {} implementation stub at {}'.format(
                    search_target,
                    hex(int(target_stub_addr))
                ))

                does_delegate_call_SecTrustEvaluate = block_analyzer.can_execute_call(target_stub_addr)

            print('was {} reachable from any code path from func({})? {}'.format(
                search_target,
                hex(int(imp_addr)),
                does_delegate_call_SecTrustEvaluate
            ))

            if not does_delegate_call_SecTrustEvaluate:
                # this app never calls _SecTrustEvaluate
                # check block behavior
                if not control_flow_before_block(block_analyzer):
                    # app never calls SecTrustEvaluate AND no control flow before block!
                    disposition = get_auth_challenge_disposition(block_analyzer)
                    if disposition == 'NSURLSessionAuthChallengeUseCredential':
                        # never called SecTrustEvaluate
                        # no control flow before completion block
                        # uses NSURLSessionAuthChallengeUseCredentials
                        # definitely insecure
                        print('App doesn\'t call SecTrustEvaluate, has no control flow before block invocation,'
                              ' and accepts credentials. Insecure!')
                        return True, imp_addr
                    else:
                        print('App doesn\'t call SecTrustEvaluate and has no control flow before block invocation',
                              ' but does not accept credentials. Secure.')
                else:
                    print('App had control flow before block invocation, assuming correctly handled. Secure.')
            else:
                print('App called SecTrustEvaluate. Secure.')
                return False, 0

    # exited loop and no implementations of the selector failed test
    # not insecure, return False
    return False, 0

from strongarm.debug_util import DebugUtil

#DebugUtil.debug = True
vulnerable_apps = []
safe_apps = []

apps_dir = os.path.join(os.path.dirname(__file__), 'sta-142-2/')
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
