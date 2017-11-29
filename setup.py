from setuptools import setup, find_packages
from setuptools.command.install import install
from subprocess import call

from strongarm import __version__


class CapstoneInstall(install):
    def run(self):
        self.do_egg_install()

setup(
    name='strongarm',
    version=__version__,
    description='Mach-O/ARM64 analyzer',
    author='Data Theorem',
    url='https://bitbucket.org/datatheorem/strongarm',
    packages=find_packages(exclude=['tests']),
    cmdclass={
        'install': CapstoneInstall,
    },
    install_requires=[
        'typing',
        'capstone',
        'enum34',
        'six',
        'njas==0.1.4',
    ],
    dependency_links=[
        'git+ssh://git@bitbucket.org/datatheorem/njas.git@0.1.4#egg=njas-0.1.4',
    ],
)
