import os
from subprocess import call, check_output

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

from strongarm import __version__


class CapstoneBuild(build_ext):
    def run(self):
        call(['/bin/sh', './install_dependencies.sh'])
        super(CapstoneBuild, self).run()


# EA: when in a (my?) pipenv enviroment, clang does not inherit the c++ header search path. Manually find and provide
# This is only needed on macOS
xcode_cpp_search_path = ''
if 'Darwin' in os.name:
    xcode_path = check_output('xcode-select -p', shell=True)
    xcode_cpp_search_path = f'{xcode_path}/Toolchains/XcodeDefault.xctoolchain/usr/include/c++/v1'

dataflow_module = Extension('strongarm.objc.dataflow',
                            sources=['strongarm/objc/dataflow.cpp'],
                            include_dirs=['/usr/local/include/', '/usr/include/', xcode_cpp_search_path],
                            libraries=['capstone'],
                            library_dirs=['/usr/local/lib'],
                            language='c++',
                            extra_compile_args=['-std=c++11', '-Wextra', '-O2', '-march=native', '-mtune=native', '-fomit-frame-pointer'])

setup(
    name='strongarm',
    version=__version__,
    description='Mach-O/ARM64 analyzer',
    author='Data Theorem',
    url='https://bitbucket.org/datatheorem/strongarm',
    packages=find_packages(exclude=['tests']),
    ext_modules=[dataflow_module],
    cmdclass={
        'build_ext': CapstoneBuild,
    },
    install_requires=[
        'typing',
        'capstone',
        'enum34',
    ],
)
