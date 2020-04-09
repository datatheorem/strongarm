from setuptools import find_packages, setup

from strongarm import __version__

setup(
    name="strongarm",
    version=__version__,
    description="Mach-O/ARM64 analyzer",
    author="Data Theorem",
    url="https://bitbucket.org/datatheorem/strongarm",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        "capstone",
        "strongarm_dataflow @ git+ssh://git@bitbucket.org/datatheorem/strongarm-dataflow.git@1.0.0",
    ],
    package_data={"strongarm": ["py.typed"]},
    data_files=[("", ["LICENSE.txt"])],
)
