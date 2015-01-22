#!/usr/bin/python2
#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from distutils.core import setup, Extension
from distutils.sysconfig import get_python_inc
import sys
import os

python_header = os.path.join(get_python_inc(plat_specific=0), 'Python.h')
if not os.path.exists(python_header):
    sys.exit("Cannot find Python development packages that provide Python.h")

module = Extension('_ipap11helper',
                   define_macros = [],
                   include_dirs = [],
                   libraries = ['dl', 'crypto', 'p11-kit'],
                   library_dirs = [],
                   extra_compile_args = [
                       '-std=c99',
                       '-I/usr/include/p11-kit-1',
                       '-ggdb3',
                       '-O2',
                       '-W',
                       '-Wall',
                       '-Wno-unused-parameter',
                       '-Wbad-function-cast',
                       '-Wextra',
                   ],
                   sources = ['p11helper.c', 'library.c'])

setup(name='_ipap11helper',
      version='0.1',
      description='FreeIPA pkcs11 helper',
      author='Martin Basti, Petr Spacek',
      author_email='mbasti@redhat.com, pspacek@redhat.com',
      license='GPLv2+',
      url='http://www.freeipa.org',
      long_description="""
      FreeIPA pkcs11 key manipulation utils.
""",
      ext_modules = [module])
