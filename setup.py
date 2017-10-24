from setuptools import setup
from setuptools.command.install import install
from subprocess import call

from strongarm import __version__


class CapstoneInstall(install):
    def run(self):
        install.run(self)
        call(['/bin/sh', './install_dependencies.sh'])

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
        'gammaray-ios',
    ],
    dependency_links=[
        'git+ssh://git@bitbucket.org/datatheorem/gammaray-ios.git'
    ],
    cmdclass={
        'install': CapstoneInstall,
    }
)
