# Authors:
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from distutils.core import setup, Extension
from distutils.sysconfig import get_python_inc
import sys
import os

python_header = os.path.join(get_python_inc(plat_specific=1), 'Python.h')
if not os.path.exists(python_header):
    sys.exit("Cannot find Python development packages that provide Python.h")

default_encoding_utf8 = Extension('default_encoding_utf8', ['default_encoding_utf8.c'])

setup(name             = 'python-default-encoding',
      version          = '0.1',
      description      = 'Forces the default encoding in Python to be utf-8',
      long_description = 'Forces the default encoding in Python to be utf-8',
      author           = 'John Dennis',
      author_email     = 'jdennis@redhat.com',
      maintainer       = 'John Dennis',
      maintainer_email = 'jdennis@redhat.com',
      license          = 'GPLv3+',
      platforms        = 'posix',
      url              = '',
      download_url     = '',
      ext_modules      = [default_encoding_utf8],
)

