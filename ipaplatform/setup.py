# Copyright (C) 2014  Red Hat
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
#

"""FreeIPA platform

FreeIPA is a server for identity, policy, and audit.
"""
from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name="ipaplatform",
        doc=__doc__,
        package_dir={'ipaplatform': ''},
        namespace_packages=['ipaplatform'],
        packages=[
            "ipaplatform",
            "ipaplatform.base",
            "ipaplatform.debian",
            "ipaplatform.fedora",
            "ipaplatform.redhat",
            "ipaplatform.rhel"
        ],
        install_requires=[
            "cffi",
            # "ipalib",  # circular dependency
            "ipapython",
            "pyasn1",
            "six",
        ],
    )
