from strongarm.macho import CPU_TYPE, MachoAnalyzer, MachoParser


def find_selector_implementations(binary):
    print(f"Analyzing Mach-O slice built for {CPU_TYPE(binary.cpu_type).name}")
    analyzer = MachoAnalyzer(binary)

    desired_selector = "URLSession:didReceiveChallenge:completionHandler:"
    implementations = analyzer.get_imps_for_sel(desired_selector)
    for imp_function in implementations:
        instruction_size = 4
        instruction_count = int((imp_function.end_address - imp_function.start_address) / instruction_size)
        print(
            f"Found implementation of @selector({desired_selector}) at [{hex(imp_function.start_address)}"
            f" - {hex(imp_function.end_address)}] ({instruction_count} instructions)"
        )


parser = MachoParser("./tests/bin/TestBinary4")
binary_64 = parser.get_arm64_slice()
binary_32 = parser.get_armv7_slice()
for binary in [binary_64, binary_32]:  # equivalent to parser.slices
    find_selector_implementations(binary)
