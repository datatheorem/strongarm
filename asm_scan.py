from typing import Text, List
from capstone import *
from capstone.arm64 import *
import sys

from strongarm.macho_parse import MachoParser
from strongarm.macho_analyzer import *
from strongarm.objc_analyzer import *

from gammaray import ios_app

def calls_selector(app, instructions, sel):
    # type (IosAppBinary, List[capstone.CsInsn], Text) -> bool
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
        block_invoke_instr_idx = instructions.index(block_invoke_instr)
        block_invoke_addr = block_invoke_instr.address

        if not block_invoke_instr:
            print('Buggy app! -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] completion '
                  'block never invoked.')
            return False

        # check for any sort of control flow before block invocation
        # look at every branch preceding block invocation
        # if _SecTrustEvaluate is called, or a local function is called,
        # we assume the function acts safely
        can_call_sec_trust_eval = False

        # check every branch up to block invocation
        last_branch = 0
        while last_branch < block_invoke_instr_idx:
            branch_instr = block_analyzer.next_branch(last_branch)

            if branch_instr.is_external_call:
                print('Instruction @ {} calls external sym {}'.format(
                    hex(int(branch_instr.address)),
                    branch_instr.symbol
                ))
                if branch_instr.symbol == '_SecTrustEvaluate':
                    can_call_sec_trust_eval = True
            else:
                print('Instruction @ {} calls local addr   {}'.format(
                    hex(int(branch_instr.address)),
                    hex(int(branch_instr.destination_address))
                ))
                # TODO(pt) follow local branches and determine if SecTrustEvaluate is
                # really called before declaring secure
                can_call_sec_trust_eval = True

            # record that we checked this branch
            last_branch = instructions.index(branch_instr.raw_instr)
            # add 1 to last branch so on the next loop iteration,
            # we start searching for branches following this instruction which is known to have a branch
            last_branch += 1

        # signature for block invocation:
        # arg0: Block object (applies to all Block invocations)
        # arg1: credentials disposition
        # arg2: user-provided NSURLCredentials

        # find arg1 to block call
        block_arg1 = block_analyzer.get_block_arg(1)

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
            authChallengeBehavior = authChallengeDispositions[block_arg1]
        except TypeError as e:
            authChallengeBehavior = authChallengeDispositions[0]

        print('Blck invoke @ {} completionBlock({}, ptr)'.format(
            hex(int(block_invoke_addr)),
            authChallengeBehavior
        ))

        if authChallengeBehavior == 'NSURLSessionAuthChallengeUseCredential':
            # app is saying to accept the credentials
            # did they verify that the credentials were valid?
            if not can_call_sec_trust_eval:
                insecure = True
        else:
            print('App either rejected or let system handle certificate validation.')

        if insecure:
            print('-[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] deterministically does not '
                  'call SecTrustEvaluate. This app does not perform certificate validation.')
        else:
            print('App appears to handle certificate validation correctly. AuthDisposition: {} '
                  'SecTrustEvaluate called? {}'.format(
                authChallengeBehavior,
                can_call_sec_trust_eval
            ))
    return insecure

IPA_PATH_GMRY_BAD = unicode(os.path.join(os.path.dirname(__file__), 'bin', 'GammaRayTestGood.ipa'))
IPA_PATH_GMRY_BAD = u'/Users/philliptennen/PycharmProjects/strongarm-ios/tests/bin/GammaRayTestGood.ipa'
IPA_PATH_GMRY_BAD = u'/Users/philliptennen/PycharmProjects/strongarm-ios/tests/bin/GammaRayTestGood.ipa'
IPA_PATH_GMRY_BAD = u'/Users/philliptennen/PycharmProjects/strongarm-ios/tests/bin/AdobeAcrobat.ipa'
IPA_PATH_GMRY_BAD = u'/Users/philliptennen/PycharmProjects/strongarm-ios/tests/bin/Events.ipa'
IPA_PATH_GMRY_BAD = u'/Users/philliptennen/PycharmProjects/strongarm-ios/tests/bin/Sportacular.ipa'
vulnerable = test_sta_142(IPA_PATH_GMRY_BAD)
print('{} vulnerable to STA-142? {}'.format(IPA_PATH_GMRY_BAD, vulnerable))

#    def test_afn_2_4_1(self):
#        with IosAppPackage(self.IPA_PATH_AFN_2_4_1) as app:
#            version = AFNetworkingUtils.find_afnetworking_version(app)
#            self.assertEqual(version, AFNetworkingUtils.VERSION_2_1_0_TO_2_4_1)


