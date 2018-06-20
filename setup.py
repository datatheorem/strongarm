from setuptools import setup, find_packages, Extension
from setuptools.command.install import install
from subprocess import call

from strongarm import __version__


class CapstoneInstall(install):
    def run(self):
        call(['/bin/sh', './install_dependencies.sh'])
        super(CapstoneInstall, self).run()


dataflow_module = Extension('strongarm.objc.dataflow',
                            sources=['strongarm/objc/dataflow.cpp'],
                            libraries=['capstone'],
                            language='c++',
                            extra_compile_args=['-std=c++11', '-Wextra', '-O2', '-march=native', '-mtune=native', '-fomit-frame-pointer'])


dataflow_module = Extension('strongarm.objc.dataflow',
                            sources=['strongarm/objc/dataflow.cpp'],
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
    },
    install_requires=[
        'typing',
        'capstone',
        'enum34',
        'six',
    ],
)
