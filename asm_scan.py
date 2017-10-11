from typing import Text, List
from capstone import *
from capstone.arm64 import *
import sys

from strongarm.macho_parse import MachoParser
from strongarm.macho_analyzer import *
from strongarm.macho_binary import MachoBinary
from strongarm.objc_analyzer import *

from gammaray import ios_app

def calls_selector(app, instructions, sel):
    # type: (IosAppBinary, List[CsInsn], Text) -> bool
    imp_addr, _ = app.get_method_address_range(sel)
    print("sel {} implemented at {}".format(sel, imp_addr))
    for instr in instructions:
        if instr.mnemonic == 'b' or instr.mnemonic == 'bl':
            branch_dest = instr.operands[0].value.imm
            # are we branching to passed selector?
            if imp_addr == branch_dest:
                return True
    return False

from gammaray.ios_app import *

def test_sta_142(path):
    # type: (Text) -> bool
    with IosAppPackage(path) as app_package:
        app = app_package.get_main_executable()
        macho = app.get_parsed_binary()
        analyzer = MachoAnalyzer.get_analyzer(macho)

        print('Analyzing -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] IMP')
        # get ranges for URLSession:didReceiveChallenge:completionHandler: delegate method IMP
        imp_addr, imp_end = app.get_method_address_range('URLSession:didReceiveChallenge:completionHandler:')
        imp_size = imp_end - imp_addr

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
        secTrustEvaluate_stub_addr = analyzer.symbol_name_to_address_map['_SecTrustEvaluate']
        secTrustEvaluate_reachable = block_analyzer.can_execute_call(secTrustEvaluate_stub_addr)
        print('secTrustEvaluate_stub_addr {} reachable {}'.format(
            hex(int(secTrustEvaluate_stub_addr)),
            secTrustEvaluate_reachable
        ))

        # signature for block invocation:
        # arg0: Block object (applies to all Block invocations)
        # arg1: credentials disposition
        # arg2: user-provided NSURLCredentials

        # find arg1 to block call
        block_arg1 = block_analyzer.get_block_arg(1)
        print('block_arg1 {}'.format(block_arg1))

        authChallengeDispositions = ['NSURLSessionAuthChallengeUseCredential',
                                     'NSURLSessionAuthChallengePerformDefaultHandling',
                                     'NSURLSessionAuthChallengeCancelAuthenticationChallenge',
                                     'NSURLSessionAuthChallengeRejectProtectionSpace']

        insecure = False
        # see what kind of behavior this app is requesting for the completion block
        try:
            # possible this wasn't the first block invocation!
            # this will crash if so, so catch
            # TODO(pt) handle more than one block
            #print('falling back on incorrect behavior because there is more than 1 block invocation')
            authChallengeBehavior = authChallengeDispositions[block_arg1]
        except TypeError as e:
            print('unknown block arg {}'.format(block_arg1))
            authChallengeBehavior = authChallengeDispositions[0]

        if authChallengeBehavior == 'NSURLSessionAuthChallengeUseCredential':
            # app is saying to accept the credentials
            # did they verify that the credentials were valid?
            if not secTrustEvaluate_reachable:
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
                authChallengeBehavior,
                secTrustEvaluate_reachable
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
    #print('{} vulnerable to STA-142? {}'.format(app_path, vulnerable))
