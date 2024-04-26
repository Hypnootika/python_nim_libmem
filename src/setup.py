from setuptools import setup

setup(
   name='pynimlibmem',
   version='0.1.2',
   description='unofficial Python bindings for Libmem, made with nimpy',
   author='Hypnootika',
   packages=['pynimlibmem'],

   url='https://github.com/Hypnootika/libmem_python',
   license='MIT',
   data_files=[('libmem', ["pynimlibmem/pynimlibmem.pyd"])],
)