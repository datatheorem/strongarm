from setuptools import setup, find_packages

from strongarm import __version__


setup(
    name='strongarm',
    version=__version__,
    description='Mach-O/ARM64 analyzer',
    author='Data Theorem',
    url='https://bitbucket.org/datatheorem/strongarm',
    packages=find_packages(exclude=['tests']),
    install_requires=[
        'typing',
        'capstone',
    ],
)
