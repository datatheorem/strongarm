# PT: Importing from strongarm_dataflow implicitly links against the capstone shared library,
# and if capstone is not installed correctly it will raise an ImportError.
# Report this in a clearer way so the user can see exactly what went wrong.
try:
    # Re-export symbols from from the sequestered strongarm_dataflow module
    from strongarm_dataflow.dataflow import get_register_contents_at_instruction_fast
    from strongarm_dataflow.register_contents import RegisterContents, RegisterContentsType
except ImportError as e:
    if "libcapstone" in str(e):
        import sys

        print("\ncapstone 4.x could not be found, is the capstone backend installed?\n")
        sys.exit(1)
    raise

from .objc_analyzer import BasicBlock, ObjcFunctionAnalyzer, ObjcMethodInfo
from .objc_instruction import (
    ObjcBranchInstruction,
    ObjcConditionalBranchInstruction,
    ObjcInstruction,
    ObjcUnconditionalBranchInstruction,
)

__all__ = [
    "get_register_contents_at_instruction_fast",
    "BasicBlock",
    "ObjcFunctionAnalyzer",
    "ObjcMethodInfo",
    "RegisterContents",
    "RegisterContentsType",
    "ObjcBranchInstruction",
    "ObjcConditionalBranchInstruction",
    "ObjcInstruction",
    "ObjcUnconditionalBranchInstruction",
]
