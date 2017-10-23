from setuptools import setup
from strongarm import __version__

setup(
    name='strongarm',
    version=__version__,
    description='Mach-O/ARM64 analyzer',
    author='Data Theorem',
    url='https://bitbucket.org/datatheorem/strongarm',
    packages=['strongarm'],
    install_requires=[
        'typing',
        'capstone',
    ]
)
