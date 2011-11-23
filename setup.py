#!/usr/bin/python

# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

"""
Python-level packaging using distutils.
"""

from distutils.core import setup
from distutils.command.install_data import install_data as _install_data
from distutils.util import change_root, convert_path
from distutils import log
from types import StringType
import ipalib
import os

class install_data(_install_data):
    """Override the built-in install_data to gzip files once they
       are installed.
    """

    def run(self):
        # install_data is a classic class so super() won't work. Call it
        # directly to copy the files first.
        _install_data.run(self)

        # Now gzip them
        for f in self.data_files:
            if type(f) is StringType:
                # it's a simple file
                f = convert_path(f)
                cmd = '/bin/gzip %s/%s' % (self.install_dir, f)
                log.info("gzipping %s/%s" % (self.install_dir, f))
                os.system(cmd)
            else:
                # it's a tuple with path and a list of files
                dir = convert_path(f[0])
                if not os.path.isabs(dir):
                    dir = os.path.join(self.install_dir, dir)
                elif self.root:
                    dir = change_root(self.root, dir)

                if f[1] == []:
                    # If there are no files listed the user must be
                    # trying to create an empty directory. So nothing
                    # to do here.
                    pass
                else:
                    # gzip the files
                    for data in f[1]:
                        data = convert_path(data)
                        cmd = '/bin/gzip %s/%s' % (dir, data)
                        log.info("gzipping %s/%s" % (dir, data))
                        os.system(cmd)

setup(
    name='freeipa',
    version=ipalib.__version__,
    license='GPLv2+',
    url='http://freeipa.org/',
    packages=[
        'ipalib',
        'ipalib.plugins',
        'ipaserver',
        'ipaserver.plugins',
        'ipaserver.install',
        'ipaserver.install.plugins',
    ],
    scripts=['ipa'],
    data_files = [('share/man/man1', ["ipa.1"])],
)
