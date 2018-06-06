from distutils.core import setup, Extension

dataflow_module = Extension('dataflow', 
                             sources=['dataflow.cpp'],
                             libraries = ['capstone'])
setup(ext_modules=[dataflow_module])
