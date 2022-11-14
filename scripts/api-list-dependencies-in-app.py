import os
import sys
from pathlib import Path
from time import time

from strongarm.macho import MachoParser

start = time()

folder = sys.argv[1]

# this script expects paths in the form of: /Users/philliptennen/apps/Stride/saved/
# extract app name
app_name = [component for component in folder.split("/")][-3]
paths = [os.path.join(folder, app_name)]

frameworks_folder = os.path.join(folder, "Frameworks")
for framework_name in os.listdir(frameworks_folder):
    if ".framework" not in framework_name:
        continue
    binary_name = framework_name.split(".framework")[0]
    binary_path = os.path.join(frameworks_folder, framework_name, binary_name)

    paths.append(binary_path)

i = 0
for path in paths:
    parser = MachoParser(Path(path))
    binary = parser.get_arm64_slice()

    for dli in binary.dependent_library_infos:
        print(f"{path} loads {dli.name}")


print(i)
end = time()
print(end - start)
