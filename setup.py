from setuptools import Extension, find_packages, setup

from strongarm import __version__


dataflow_module = Extension('strongarm.objc.dataflow',
                            sources=['strongarm/objc/dataflow.cpp'],
                            include_dirs=['/usr/local/include/'],
                            libraries=['capstone'],
                            library_dirs=['/usr/local/lib'],
                            language='c++',
                            extra_compile_args=['-std=c++11',
                                                '-Wextra',
                                                '-O2',
                                                '-march=native',
                                                '-mtune=native',
                                                '-fomit-frame-pointer'])

setup(
    name='strongarm',
    version=__version__,
    description='Mach-O/ARM64 analyzer',
    author='Data Theorem',
    url='https://bitbucket.org/datatheorem/strongarm',
    packages=find_packages(exclude=['tests']),
    ext_modules=[dataflow_module],
    install_requires=[
        'typing',
        'capstone',
        'enum34',
    ],
)
