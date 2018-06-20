from setuptools import setup, find_packages, Extension
from setuptools.command.install import install
from setuptools.command.build_py import build_py
from subprocess import call

from strongarm import __version__


class CapstoneInstall(install):
    def run(self):
        print(f'XXX Capstone install')
        call(['/bin/sh', './install_dependencies.sh'])
        super(CapstoneInstall, self).run()


class CapstoneBuild(build_py):
    def run(self):
        print(f'XXX Capstone build')
        call(['/bin/sh', './install_dependencies.sh'])
        super(CapstoneBuild, self).run()


dataflow_module = Extension('strongarm.objc.dataflow',
                            sources=['strongarm/objc/dataflow.cpp'],
                            include_dirs=['/usr/local/include'],
                            libraries=['capstone'],
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
        'install': CapstoneInstall,
        'build': CapstoneBuild,
    },
    install_requires=[
        'typing',
        'capstone',
        'enum34',
        'six',
    ],
)
