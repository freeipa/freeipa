#!/usr/bin/python2
# Copyright (C) 2007  Red Hat
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

"""FreeIPA python support library

FreeIPA is a server for identity, policy, and audit.
"""
from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name="ipapython",
        doc=__doc__,
        package_dir={'ipapython': ''},
        packages=[
            "ipapython",
            "ipapython.dnssec",
            "ipapython.secrets",
            "ipapython.install"
        ],
        install_requires=[
            "cffi",
            "custodia",
            "cryptography",
            "dnspython",
            "gssapi",
            "jwcrypto",
            "ipaplatform",
            # "ipalib",  # circular dependency
            "pyldap",
            "netaddr",
            "netifaces",
            "python-nss",
            "requests",
            "six",
        ],
        setup_requires=[
            "wheel",
        ],
        extras_require={
            ":python_version<'3'": ["enum34"],
        },
        entry_points={
            'custodia.authorizers': [
                'IPAKEMKeys = ipapython.secrets.kem:IPAKEMKeys',
            ],
            'custodia.stores': [
                'IPASecStore = ipapython.secrets.store:IPASecStore',
            ],
        },
    )
