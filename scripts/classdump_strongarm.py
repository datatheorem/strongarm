"""Example implementation of `class-dump` using strongarm.
This implementation isn't feature-complete, but serves as an example of real API use.
"""
import re
import pathlib
import argparse

from strongarm.macho import MachoParser, MachoAnalyzer, CPU_TYPE


def _prototype_from_selector(sel: str) -> str:
    """String-build a method prototype from an Objective-C selector.
    Example:
        >>> _prototype_from_selector('application:didFinishLaunchingWithOptions:')
        '- (void*)application:(void*)application didFinishLaunchingWithOptions:(void*)options;'
    """
    prototype = '- (void*)'
    for component in sel.split(':'):
        if not len(component):
            continue
        # Extract the last capitalized word
        split = re.findall('[A-Z][^A-Z]*', component)
        # If there's no capitalized word in the component, use the full component
        if not len(split):
            split.append(component)
        # Lowercase it
        arg_name = split[-1].lower()

        prototype += f'{component}:(void*){arg_name} '

    # Delete the last space in the string
    prototype = prototype[:len(prototype)-1]
    prototype += ';'
    return prototype


def main():
    arg_parser = argparse.ArgumentParser(description='classdump clone')
    arg_parser.add_argument(
        'binary_path', metavar='binary_path', type=str, help=
        'Path to binary to analyze'
    )
    args = arg_parser.parse_args()

    parser = MachoParser(pathlib.Path(args.binary_path))

    # Find a binary slice, preferring arm64 if available
    arm64_slices = [x for x in parser.slices if x.cpu_type == CPU_TYPE.ARM64]
    binary = arm64_slices[0] if len(arm64_slices) else parser.slices[0]
    analyzer = MachoAnalyzer.get_analyzer(binary)

    for objc_class in analyzer.objc_classes() + analyzer.objc_categories():
        # Print the opening line of the declaration
        class_declaration = f'@interface {objc_class.name} : NSObject'
        if len(objc_class.protocols):
            protocol_list = ", ".join(x.name for x in objc_class.protocols)
            class_declaration += f' <{protocol_list}>'
        print(class_declaration)

        # Print the ivar list
        print('{')
        for ivar in objc_class.ivars:
            # The ivar's class name will be @"enclosed" if it's an Objective-C class. Strip this.
            class_name = ivar.class_name.strip('@"')
            print(f'\t{class_name}* {ivar.name};')
        print('}')

        # Print the method list
        for method in objc_class.selectors:
            # TODO(PT): Guess argument types by using the selector's type encoding
            print(_prototype_from_selector(method.name))

        print(f'@end\n')


if __name__ == '__main__':
    main()
