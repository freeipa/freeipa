# Authors:
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

from distutils.core import setup, Extension

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

