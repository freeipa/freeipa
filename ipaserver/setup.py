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
Python-level packaging using setuptools
"""
from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name='ipaserver',
        doc=__doc__,
        package_dir={'ipaserver': ''},
        packages=[
            'ipaserver',
            'ipaserver.advise',
            'ipaserver.advise.plugins',
            'ipaserver.dnssec',
            'ipaserver.plugins',
            'ipaserver.secrets',
            'ipaserver.install',
            'ipaserver.install.plugins',
            'ipaserver.install.server',
        ],
        install_requires=[
            "cryptography",
            "custodia",
            "dbus-python",
            "dnspython",
            # dogtag-pki is just the client package on PyPI. ipaserver
            # requires the full pki package.
            # "dogtag-pki",
            "ipaclient",
            "ipalib",
            "ipaplatform",
            "ipapython",
            "jwcrypto",
            "lxml",
            "netaddr",
            "pyasn1",
            "requests",
            "six",
            "python-augeas",
            "python-ldap",
        ],
        entry_points={
            'custodia.authorizers': [
                'IPAKEMKeys = ipaserver.secrets.kem:IPAKEMKeys',
            ],
            'custodia.stores': [
                'IPASecStore = ipaserver.secrets.store:IPASecStore',
            ],
        },
        extras_require={
            # These packages are currently not available on PyPI.
            "dcerpc": ["samba", "pysss", "pysss_nss_idmap"],
            "hbactest": ["pyhbac"],
            "install": ["SSSDConfig"],
            "trust": ["pysss_murmur", "pysss_nss_idmap"],
        }
    )
