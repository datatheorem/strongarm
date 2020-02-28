from strongarm.macho import VirtualMemoryPointer
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContents

def get_register_contents_at_instruction_fast(
    desired_register: str,
    function_analyzer: ObjcFunctionAnalyzer,
    instruction: ObjcInstruction,
    basic_block_start_addr: VirtualMemoryPointer,
) -> RegisterContents: ...
