from distutils.core import setup, Extension

dataflow_module = Extension('dataflow', sources=['dataflow.c'])
setup(ext_modules=[dataflow_module])
