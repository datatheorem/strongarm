#!/usr/bin/python
import optparse
import sys
import unittest
import os


USAGE = """%prog [test/path | python_module_path]
Run all unit tests within `tests`, under the specified path/file, or using the specified Python module path (eg,
including class name and method name).
"""

def main(test_path):
    if os.path.isfile(test_path):
        suite = unittest.loader.TestLoader().discover(os.path.dirname(test_path), pattern=os.path.basename(test_path))
    elif os.path.isdir(test_path):
        suite = unittest.loader.TestLoader().discover(test_path)
    elif len(test_path) > 0:
        suite = unittest.loader.TestLoader().loadTestsFromName(test_path)
    else:
        suite = unittest.loader.TestLoader().discover(test_path)
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    exit_code = 0 if result.wasSuccessful() else 1
    sys.exit(exit_code)


if __name__ == '__main__':
    parser = optparse.OptionParser(USAGE)
    options, args = parser.parse_args()

    if len(args) > 0:
        main(args[0])
    else:
        main('tests')
