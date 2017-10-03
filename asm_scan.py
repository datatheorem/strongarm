from typing import Text, List
from capstone import *
from capstone.arm64 import *
import sys
from strongarm.macho_parse import MachoParser
from strongarm.macho_analyzer import *
from gammaray import ios_app


def calls_selector(app, instructions, sel):
    # type (IosAppBinary, List[capstone.CsInsn], Text) -> bool
    imp_addr = app.get_method_address_range(sel)
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
analyzer = MachoAnalyzer(binary)

app = ios_app.IosAppBinary(filename)
macho = app.get_parsed_binary()

#URLSession:didReceiveChallenge:completionHandler: delegate method IMP
imp_addr, imp_end = app.get_method_address_range('URLSession:didReceiveChallenge:completionHandler:')
imp_size = imp_end - imp_addr

func = macho.get_content_from_virtual_address(virtual_address=imp_addr, size=imp_size)
# func is a List[int]
# we want a string containing bytes
# so, map chr over every item in func,
# then join them with no seperator into a string
func_str = ''.join(map(chr, func))

# register signature for URLSession:didReceiveChallenge:completionHandler: will be as follows:
# x0: self
# x1: _cmd
# x2: session
# x3: challenge
# x4: completionHandler

# therefore, we need to track what happens to the block initially in register x4
instructions = [instr for instr in analyzer.cs.disasm(func_str, imp_addr)]
for instr in instructions:
    print(ObjcFunctionAnalyzer.format_instruction(instr))

analyzer = ObjcBlockAnalyzer(instructions, u'x4')

# check for any sort of control flow before block invocation
block_invoke_idx = analyzer.invoke_index
next_branch_instr = analyzer.next_branch(0)
next_branch_index = analyzer._instructions.index(next_branch_instr)

if next_branch_index < block_invoke_idx:
    # does control flow before invoking block!
    # we can't safely assume that it's not validating the certificate
    print('Detected control flow before block invocation, assuming app validates certificate.')
    sys.exit(0)
print('block invoked from reg {}, loaded at instruction index {}'.format(
    analyzer.load_reg,
    analyzer.load_index
))
print('block invoked at instruction index {}'.format(analyzer.invoke_index))
print('block args: {} {} {}'.format(
    analyzer.get_block_arg(0),
    analyzer.get_block_arg(1),
    analyzer.get_block_arg(2),
))

# signature for block invocation:
# arg0: Block object (applies to all Block invocations)
# arg1: credentials disposition
# arg2: user-provided NSURLCredentials

# find arg1 to block call
block_arg1 = analyzer.get_block_arg(1)
print('block arg1 {}'.format(block_arg1))

authChallengeDispositions = ['NSURLSessionAuthChallengeUseCredential',
                             'NSURLSessionAuthChallengePerformDefaultHandling',
                             'NSURLSessionAuthChallengeCancelAuthenticationChallenge',
                             'NSURLSessionAuthChallengeRejectProtectionSpace']

insecure = False
# see what kind of behavior this app is requesting for the completion block
authChallengeBehavior = authChallengeDispositions[block_arg1]
if authChallengeBehavior == 'NSURLSessionAuthChallengeUseCredential':
    insecure = True

if insecure:
    print('{file} replaces system SSL handshake.  Potentially insecure.'.format(file=filename))
else:
    print('{file} performs safe SSL handshake handling.'.format(file=filename))