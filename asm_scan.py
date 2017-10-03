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

filename = './tests/bin/GoodCertificateValidation'
macho_file = open(filename, 'r')
parser = MachoParser(filename)
binary = parser.slices[0]
analyzer = MachoAnalyzer.get_analyzer(binary)

app = ios_app.IosAppBinary(filename)
macho = app.get_parsed_binary()

print('Analyzing -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] IMP')
# get ranges for URLSession:didReceiveChallenge:completionHandler: delegate method IMP
imp_addr, imp_end = app.get_method_address_range('URLSession:didReceiveChallenge:completionHandler:')
imp_size = imp_end - imp_addr

# grab machine code for this IMP
func = macho.get_content_from_virtual_address(virtual_address=imp_addr, size=imp_size)
# func is a List[int]
# we want a string containing bytes
# so, map chr over every item in func,
# then join them with no seperator into a string
func_str = ''.join(map(chr, func))
instructions = [instr for instr in analyzer.cs.disasm(func_str, imp_addr)]

# register signature for URLSession:didReceiveChallenge:completionHandler: will be as follows:
# x0: self
# x1: _cmd
# x2: session
# x3: challenge
# x4: completionHandler

# therefore, we need to track what happens to the block initially in register x4
block_analyzer = ObjcBlockAnalyzer(binary, instructions, u'x4')

# get details about completion block invocation
block_invoke_instr = block_analyzer.invoke_instr
block_invoke_instr_idx = instructions.index(block_invoke_instr)
block_invoke_addr = block_invoke_instr.address

if not block_invoke_instr:
    print('Buggy app! -[NSURLSessionDelegate URLSession:didReceiveChallenge:completionHandler:] completion '
          'block never invoked.')
    sys.exit(0)

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
        # TODO(pt) follow local branches and determine if SecTrustEvaluate is really called before declaring secure
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
authChallengeBehavior = authChallengeDispositions[block_arg1]

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

