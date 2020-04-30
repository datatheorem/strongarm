import hashlib
import pathlib
import shutil
import subprocess
from contextlib import contextmanager
from tempfile import TemporaryDirectory
from typing import Generator, Tuple

from strongarm.macho import MachoAnalyzer, MachoBinary, MachoParser
from strongarm.objc import ObjcFunctionAnalyzer


@contextmanager
def _compile_code(source_code: str, is_assembly: bool, source_outside_class="") -> Generator[pathlib.Path, None, None]:
    """Compile the provided source code & yield the path to the compiled binary. The path is in a temporary directory.
    If is_assembly is set, the source code is treated as AArch64 assembly. Otherwise, as Objective-C source.
    """
    if is_assembly:
        wrapped_source = f"""
        .text
        .balign 4
        .global _main
        .extern data_label

        _main:
            {source_code}
            nop
            ret

        text_label:
            .long 0xfeedface

        .ltorg
        .end

        .const
        .balign 0x1000  ; Align on a page boundary
        .global data_label
        data_label:
            .long 0xcafebabe

        .end
        """
    else:
        wrapped_source = f"""
        #import <Foundation/Foundation.h>
        #import <UIKit/UIKit.h>
        #import <CoreGraphics/CoreGraphics.h>

        // Provide this dummy function in case any test wants to use it
        void UnsafeFunc(NSDictionary* d) {{}}

        // Provide a dummy class which unit test code is placed within
        @interface SourceClass : NSObject
        @end

        // Allow unit tests to define code outside a class definition
        {source_outside_class}

        @implementation SourceClass

        // Insert the source code requested by the unit test
        {source_code}

        @end

        // Dummy main()
        int main(int argc, char** argv) {{
            return 0;
        }}
        """

    with TemporaryDirectory() as tempdir:
        if is_assembly:
            source_filepath = pathlib.Path(tempdir) / "source.asm"
        else:
            source_filepath = pathlib.Path(tempdir) / "source.m"
        output_filepath = pathlib.Path(tempdir) / "compiled_bin"
        with open(source_filepath.as_posix(), "w+") as source_file:
            source_file.write(wrapped_source)

        ret = subprocess.run(
            f"xcrun -sdk iphoneos "
            f"clang -arch arm64 "
            f"-framework Foundation "
            f"-framework CoreGraphics "
            f"-framework UIKit "
            f"{source_filepath.as_posix()} -o {output_filepath.as_posix()}",
            shell=True,
            stderr=subprocess.PIPE,
        )
        if ret.returncode:
            print(ret.stderr.decode())
            raise RuntimeError(f"Compilation failed: {wrapped_source}")
        yield output_filepath


@contextmanager
def binary_containing_code(
    source_code: str, is_assembly: bool, source_code_outside_classdef=""
) -> Generator[Tuple[MachoBinary, MachoAnalyzer], None, None]:
    """Provide an app package which contains the compiled source code.
    If is_assembly is set, the source code is treated as AArch64 assembly. Otherwise, as Objective-C source.

    The provided source code is embedded within a class definition.
    If you need to embed code outside the class definition, pass it as source_code_outside_classdef.

    This method will cache the compiled binary in tests/bin/source_code_test_binaries.
    This facilitates running the unit tests using this mechanism in Pipelines.
    """
    # TODO(PT): When you modify source code of a unit test, it means there is a 'dangling' unused binary in the tree.
    # Add a cleanup task to identify these unused binaries and delete them.

    # Do we need to compile this code, or is there a cached version available?
    code_hash = hashlib.md5(f"{source_code}{source_code_outside_classdef}".encode()).hexdigest()
    compiled_artifacts_dir = pathlib.Path(__file__).parent / "bin" / "auto_compiled_binaries"
    compiled_code_bin_path = compiled_artifacts_dir / str(code_hash)
    if not compiled_code_bin_path.exists():
        # Compile and cache this source code
        with _compile_code(
            source_code, is_assembly, source_outside_class=source_code_outside_classdef
        ) as temp_compiled_bin:
            shutil.copy(temp_compiled_bin, compiled_code_bin_path)

    binary = MachoParser(compiled_code_bin_path).get_arm64_slice()
    assert binary is not None
    analyzer = MachoAnalyzer.get_analyzer(binary)
    yield binary, analyzer


@contextmanager
def function_containing_asm(asm_source: str) -> Generator[Tuple[MachoAnalyzer, ObjcFunctionAnalyzer], None, None]:
    with binary_containing_code(asm_source, is_assembly=True) as (binary, analyzer):
        # Assembly compiled with binary_containing_code is always placed in main()
        callable_symbol = analyzer.callable_symbol_for_symbol_name("_main")
        assert callable_symbol is not None

        main_addr = callable_symbol.address
        func = ObjcFunctionAnalyzer.get_function_analyzer(binary, main_addr)
        yield analyzer, func
