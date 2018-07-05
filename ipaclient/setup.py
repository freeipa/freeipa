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

"""FreeIPA client library

FreeIPA is a server for identity, policy, and audit.
"""
from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name="ipaclient",
        doc=__doc__,
        package_dir={'ipaclient': ''},
        packages=[
            "ipaclient",
            "ipaclient.install",
            "ipaclient.plugins",
            "ipaclient.remote_plugins",
            "ipaclient.remote_plugins.2_49",
            "ipaclient.remote_plugins.2_114",
            "ipaclient.remote_plugins.2_156",
            "ipaclient.remote_plugins.2_164",
        ],
        package_data={
            'ipaclient': [
                'csrgen/profiles/*.json',
                'csrgen/rules/*.json',
                'csrgen/templates/*.tmpl',
            ],
        },
        install_requires=[
            "cryptography",
            "ipalib",
            "ipapython",
            "qrcode",
            "six",
        ],
        entry_points={
            'console_scripts': [
                'ipa = ipaclient.__main__:main'
            ]
        },
        extras_require={
            "install": ["ipaplatform"],
            "otptoken_yubikey": ["python-yubico", "pyusb"],
            "csrgen": ["cffi", "jinja2"],
        },
        zip_safe=False,
    )
