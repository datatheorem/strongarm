from subprocess import call

from setuptools import Extension, find_packages, setup
from setuptools.command.build_ext import build_ext

from strongarm import __version__


class CapstoneBuild(build_ext):
    def run(self) -> None:
        call(["/bin/sh", "./install_dependencies.sh"])
        super(CapstoneBuild, self).run()


dataflow_module = Extension(
    "strongarm.objc.dataflow",
    language="c++",
    sources=["strongarm/objc/dataflow.cpp"],
    include_dirs=["/usr/local/include/"],
    libraries=["capstone"],
    library_dirs=["/usr/local/lib"],
    extra_compile_args=[
        "-std=c++11",
        "-Wextra",
        "-O2",
        "-march=native",
        "-mtune=native",
        "-fomit-frame-pointer",
        # Uncomment the following line to enable debug builds of the dataflow module
        # "-DNDEBUG",
    ],
)

setup(
    name="strongarm",
    version=__version__,
    description="Mach-O/ARM64 analyzer",
    author="Data Theorem",
    url="https://bitbucket.org/datatheorem/strongarm",
    packages=find_packages(exclude=["tests"]),
    ext_modules=[dataflow_module],
    cmdclass={"build_ext": CapstoneBuild},
    install_requires=["capstone"],
    package_data={"strongarm": ["py.typed"]},
    data_files=[("", ["LICENSE.txt"])],
)
