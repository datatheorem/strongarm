import re
from typing import List

from capstone import CsInsn
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG, Arm64Op

from strongarm.macho import (
    CPU_TYPE,
    MachoAnalyzer,
    MachoBinary,
    MachoParser,
    ObjcCategory,
    ObjcClass,
    ObjcSelector,
    VirtualMemoryPointer,
)
from strongarm.objc import (
    ObjcBranchInstruction,
    ObjcFunctionAnalyzer,
    ObjcInstruction,
    ObjcMethodInfo,
    RegisterContentsType,
)


class StringFormatter:
    @staticmethod
    def green(string: str) -> str:
        return f"\033[0;32m{string}\033[0m"

    @staticmethod
    def magenta(string: str) -> str:
        return StringFormatter.seed(197, string)

    @staticmethod
    def red(string: str) -> str:
        return f"\033[31;1m{string}\033[0m"

    @staticmethod
    def orange(string: str) -> str:
        return StringFormatter.seed(208, string)

    @staticmethod
    def blue(string: str) -> str:
        return f"\033[34;1m{string}\033[0m"

    @staticmethod
    def seed(seed: int, string: str) -> str:
        return f"\033[38;5;{seed}m{string}\033[0m"

    @staticmethod
    def none(string: str) -> str:
        return string

    @staticmethod
    def bold(string: str) -> str:
        return f"\033[1m{string}\033[0m"


def pick_macho_slice(parser: MachoParser) -> MachoBinary:
    """Retrieve a MachoBinary slice from a MachoParser, with a preference for an arm64 slice
    """
    binary_slices = parser.slices

    # Sanity checks (an empty list is falsey)
    if not binary_slices:
        raise ValueError(f"Could not parse {parser.path.name} as a Mach-O or FAT")

    parsed_binary = binary_slices[0]
    # Return 64 bit slice if there is one
    for binary_slice in binary_slices:
        parsed_binary = binary_slice
        if parsed_binary.cpu_type == CPU_TYPE.ARM64:
            break
    return parsed_binary


class _StringPalette:
    REG = StringFormatter.none
    IMM = StringFormatter.none
    MNEMONIC = StringFormatter.none
    BASIC_BLOCk = StringFormatter.none
    ADDRESS = StringFormatter.none
    ANNOTATION = StringFormatter.none
    STRING = StringFormatter.none


class StringPalette(_StringPalette):
    REG = StringFormatter.green
    IMM = StringFormatter.blue
    MNEMONIC = StringFormatter.magenta
    BASIC_BLOCK = StringFormatter.orange
    ADDRESS = StringFormatter.bold
    ANNOTATION = StringFormatter.orange
    ANNOTATION_ARGS = StringFormatter.blue
    STRING = StringFormatter.red


def format_instruction_arg(instruction: CsInsn, arg: Arm64Op) -> str:
    if arg.type == ARM64_OP_REG:
        return StringPalette.REG(instruction.reg_name(arg.value.reg))
    elif arg.type == ARM64_OP_IMM:
        return StringPalette.IMM(hex(arg.value.imm))
    elif arg.type == ARM64_OP_MEM:
        return f"[{StringPalette.REG(instruction.reg_name(arg.mem.base))} #{StringPalette.IMM(hex(arg.mem.disp))}]"
    raise RuntimeError(f"unknown arg type {arg.type}")


def args_from_sel_name(sel: str) -> List[str]:
    sel_args = ["self", f"@selector({sel})"]
    if ":" not in sel:
        return sel_args

    sel_components = sel.split(":")
    for component in sel_components:
        if not len(component):
            sel_args.append("")
            continue
        # extract the last capitalized word
        split = re.findall("[A-Z][^A-Z]*", component)
        # if no capitalized word, use the full component
        if not len(split):
            split.append(component)
        # lowercase it
        sel_args.append(split[-1].lower())
    return sel_args


def disassemble_method(binary: MachoBinary, method: ObjcMethodInfo) -> str:
    disassembled_text: List[str] = []

    # Figure out the arguments based on the sel name
    sel_args = args_from_sel_name(method.objc_sel.name)

    argument_list = ", ".join(sel_args)
    signature = f"\n-[{method.objc_class.name} {method.objc_sel.name}]({argument_list});"
    disassembled_text.append(signature)

    if not method.imp_addr:
        return f"Could not find address for [{method.objc_class.name} {method.objc_sel.name}]"
    return disassemble_function(binary, method.imp_addr, disassembled_text, sel_args)


def print_instr(instr: ObjcInstruction) -> None:
    raw_instr = instr.raw_instr
    instruction_string = f"\t{hex(instr.address)}\t\t{raw_instr.mnemonic}"

    # Add each arg to the string
    instruction_string += ", ".join([format_instruction_arg(raw_instr, arg) for arg in raw_instr.operands])
    print(instruction_string)


def annotate_instruction(function_analyzer: ObjcFunctionAnalyzer, sel_args: List[str], instr: CsInsn) -> str:
    annotation = "\t\t"
    # Parse as an ObjcInstruction
    wrapped_instr = ObjcInstruction.parse_instruction(
        function_analyzer, function_analyzer.get_instruction_at_address(instr.address)
    )

    if isinstance(wrapped_instr, ObjcBranchInstruction):
        wrapped_branch_instr: ObjcBranchInstruction = wrapped_instr

        annotation += "#\t"
        if function_analyzer.is_local_branch(wrapped_branch_instr):
            annotation += StringPalette.ANNOTATION(f"jump loc_{hex(wrapped_branch_instr.destination_address)}")

        elif wrapped_instr.symbol:
            annotation += StringPalette.ANNOTATION(wrapped_instr.symbol)

            if not wrapped_branch_instr.selector:
                annotation += StringPalette.ANNOTATION("();")
            else:
                annotation += StringPalette.ANNOTATION_ARGS(f"(id, @selector({wrapped_branch_instr.selector.name})")

                # Figure out argument count passed to selector
                arg_count = wrapped_branch_instr.selector.name.count(":")
                for i in range(arg_count):
                    # x0 is self, x1 is the SEL, real args start at x2
                    register = f"x{i + 2}"
                    method_arg = function_analyzer.get_register_contents_at_instruction(register, wrapped_branch_instr)

                    method_arg_string = ", "
                    if method_arg.type == RegisterContentsType.IMMEDIATE:
                        method_arg_string += hex(method_arg.value)
                    else:
                        method_arg_string += "<?>"

                    annotation += StringPalette.STRING(method_arg_string)
                annotation += ");"

        else:
            annotation += StringPalette.ANNOTATION(f"({hex(instr.address)})(")
            arg_count = 4
            for i in range(arg_count):
                # x0 is self, x1 is the SEL, real args start at x2
                register = f"x{i}"
                method_arg = function_analyzer.get_register_contents_at_instruction(register, wrapped_instr)

                method_arg_string = f"{register}: "
                if method_arg.type == RegisterContentsType.IMMEDIATE:
                    method_arg_string += hex(method_arg.value)
                else:
                    method_arg_string += "<?>"

                annotation += StringPalette.ANNOTATION_ARGS(method_arg_string)
                annotation += ", "
            annotation += ");"
    else:
        # Try to annotate string loads
        # This code taken from Ethan's potential passwords check
        if instr.mnemonic in ["ldr", "adr", "adrp", "add"]:
            # Only care about general purpose registers that are being written into
            if not ObjcInstruction.instruction_uses_vector_registers(instr):
                _, instr_mutated_regs = instr.regs_access()
                if len(instr_mutated_regs):
                    # Get the contents of the register (an address)
                    register = instr.reg_name(instr_mutated_regs[0])
                    wrapped_instr = ObjcInstruction.parse_instruction(function_analyzer, instr)
                    register_contents = function_analyzer.get_register_contents_at_instruction(register, wrapped_instr)
                    if register_contents.type == RegisterContentsType.IMMEDIATE:
                        # Try reading a string
                        binary_str = function_analyzer.binary.read_string_at_address(
                            VirtualMemoryPointer(register_contents.value)
                        )
                        if binary_str:
                            annotation += StringPalette.STRING(f'#\t"{binary_str}"')

    return annotation


def disassemble_function(
    binary: MachoBinary, function_addr: VirtualMemoryPointer, prefix: List[str] = None, sel_args: List[str] = None
) -> str:
    if not prefix:
        prefix = []
    if not sel_args:
        sel_args = []

    disassembled_text = prefix
    function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(binary, function_addr)

    # Transform basic blocks into tuples of (basic block start addr, basic block end addr)
    basic_block_boundaries = [[block.start_address, block.end_address] for block in function_analyzer.basic_blocks]
    # Flatten basic_block_boundaries into one-dimensional list
    basic_block_boundaries_flat = [x for boundaries in basic_block_boundaries for x in boundaries]
    # Remove duplicate boundaries
    basic_block_boundaries_set = set(basic_block_boundaries_flat)

    for instr in function_analyzer.instructions:
        line = ""
        # Add visual indicator if this is a basic block boundary
        if instr.address in basic_block_boundaries_set:
            line += StringPalette.BASIC_BLOCK(f"--- loc_{hex(instr.address)} ----------\n")

        lines = [
            StringPalette.ADDRESS(hex(instr.address)),
            StringPalette.MNEMONIC(f"{instr.mnemonic:5}"),
            ", ".join([format_instruction_arg(instr, x) for x in instr.operands]),
            annotate_instruction(function_analyzer, sel_args, instr),
        ]
        line += "\t" + "\t".join(lines)
        disassembled_text.append(line)

    return "\n".join(disassembled_text)


def print_binary_info(binary: MachoBinary) -> None:
    print(f"Mach-O type: {binary.file_type.name}")
    print(f"{'Big' if binary.is_swap else 'Little'} endian")
    print(f"Virtual base: {hex(binary.get_virtual_base())}")
    print(f"Contains encrypted section? {binary.is_encrypted()}")


def print_binary_load_commands(binary: MachoBinary) -> None:
    print("\nLoad commands:")
    load_commands = binary.load_dylib_commands
    for cmd in load_commands:
        dylib_name_addr = binary.get_virtual_base() + cmd.binary_offset + cmd.dylib.name.offset
        dylib_name = binary.read_string_at_address(dylib_name_addr)
        dylib_version = cmd.dylib.current_version
        print(f"\t{dylib_name} v.{hex(dylib_version)}")


def print_binary_segments(binary: MachoBinary) -> None:
    print("\nSegments:")
    for segment in binary.segments:
        virtual_loc = f"[{segment.vmaddr:#011x} - {segment.vmaddr + segment.vmsize:#011x}]"
        file_loc = f"[{segment.offset:#011x} - {segment.offset + segment.size:#011x}]"
        print(f"\t{virtual_loc} (file {file_loc}) {segment.name}")


def print_binary_sections(binary: MachoBinary) -> None:
    print("\nSections:")
    for section in binary.sections:
        print(f"\t[{hex(section.address)} - {hex(section.end_address)}] {section.name} ({section.segment.name})")


def print_analyzer_imported_symbols(analyzer: MachoAnalyzer) -> None:
    print("\nSymbols:")
    print("\tImported symbols:")
    stub_map = analyzer.imported_symbol_names_to_pointers
    for imported_sym in analyzer.imported_symbols:
        print(f"\t\t{imported_sym}: ", end="")
        # Attempt to find the call stub for this symbol
        stub_location = ""
        if imported_sym in stub_map:
            stub_location = f"dyld stub at {hex(stub_map[imported_sym])}"
        print(stub_location)


def print_analyzer_exported_symbols(analyzer: MachoAnalyzer) -> None:
    print("\tExported symbols:")
    for exported_sym, exported_addr in analyzer.exported_symbol_names_to_pointers.items():
        print(f"\t\t{exported_sym}: {hex(exported_addr)}")


def print_selector(objc_class: ObjcClass, selector: ObjcSelector) -> None:
    # Belongs to a class or category?
    if isinstance(objc_class, ObjcCategory):
        category: ObjcCategory = objc_class
        class_name = f"{category.base_class} ({category.name})"
    else:
        class_name = objc_class.name
    if selector.implementation:
        print(f"\t-[{class_name} {selector.name}] defined at {hex(selector.implementation)}")
    else:
        print(f"\t-[{class_name} {selector.name}]")


def print_analyzer_methods(analyzer: MachoAnalyzer) -> None:
    print("\nObjective-C Methods:")
    methods = analyzer.get_objc_methods()
    for method_info in methods:
        print_selector(method_info.objc_class, method_info.objc_sel)


def print_analyzer_classes(analyzer: MachoAnalyzer) -> None:
    print("\nObjective-C Classes:")
    classes = analyzer.objc_classes()
    classes = sorted(classes, key=lambda c: c.name)
    for objc_class in classes:
        # Belongs to a class or category?
        if isinstance(objc_class, ObjcCategory):
            category: ObjcCategory = objc_class
            class_name = f"{category.base_class} ({category.name})"
        else:
            class_name = objc_class.name
        print(f"\t{class_name}: {len(objc_class.selectors)} selectors")


def print_analyzer_protocols(analyzer: MachoAnalyzer) -> None:
    print("\nProtocols conformed to within the binary:")
    protocols = analyzer.get_conformed_protocols()
    protocols = sorted(protocols, key=lambda p: p.name)
    for protocol in protocols:
        print(f"\t{protocol.name}: {len(protocol.selectors)} selectors")


def print_raw_strings(binary: MachoBinary) -> None:
    strings_section = binary.section_with_name("__cstring", "__TEXT")
    if strings_section is None:
        return

    print("\nStrings:")
    strings_content = binary.get_bytes(strings_section.offset, strings_section.size)
    for string in strings_content.split(b"\0"):
        try:
            print(f"\t{string.decode()}")
        except UnicodeDecodeError:
            print(f"\t{string}")
