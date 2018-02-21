import os
import sys
from strongarm.macho import MachoParser


folder = sys.argv[1]

# this script expects paths in the form of: /Users/philliptennen/apps/Stride/saved/
# extract app name
app_name = [component for component in folder.split('/')][-3]
paths = [
    os.path.join(folder, app_name),
]

frameworks_folder = os.path.join(folder, 'Frameworks')
for framework_name in os.listdir(frameworks_folder):
    if '.framework' not in framework_name:
        continue
    binary_name = framework_name.split('.framework')[0]
    binary_path = os.path.join(frameworks_folder, framework_name, binary_name)

    paths.append(binary_path)

for path in paths:
    parser = MachoParser(path)
    binary = parser.get_arm64_slice()

    load_commands = binary.load_dylib_commands
    for cmd in load_commands:
        dylib_load_string_fileoff = cmd.fileoff + cmd.dylib.name.offset
        dylib_load_string_len = cmd.cmdsize - cmd.dylib.name.offset
        dylib_load_string_bytes = binary.get_bytes(dylib_load_string_fileoff, dylib_load_string_len)
        # trim anything after NUL character
        dylib_load_string_bytes = dylib_load_string_bytes.split(b'\0')[0]
        dylib_load_string = dylib_load_string_bytes.decode('utf-8')

        dylib_version = cmd.dylib.current_version
        print('{} loads {}'.format(path, dylib_load_string))
