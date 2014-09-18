# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os

from ipaplatform.paths import paths
from ipapython import ipautil

CA_NICKNAME_FMT = "%s IPA CA"


def get_ca_nickname(realm, format=CA_NICKNAME_FMT):
    return format % realm


def create_ipa_nssdb():
    pwdfile = os.path.join(paths.IPA_NSSDB_DIR, 'pwdfile.txt')

    ipautil.backup_file(pwdfile)
    ipautil.backup_file(os.path.join(paths.IPA_NSSDB_DIR, 'cert8.db'))
    ipautil.backup_file(os.path.join(paths.IPA_NSSDB_DIR, 'key3.db'))
    ipautil.backup_file(os.path.join(paths.IPA_NSSDB_DIR, 'secmod.db'))

    with open(pwdfile, 'w') as f:
        f.write(ipautil.ipa_generate_password(pwd_len=40))
    os.chmod(pwdfile, 0600)

    ipautil.run([paths.CERTUTIL,
         "-N",
         "-d", paths.IPA_NSSDB_DIR,
         "-f", pwdfile])
    os.chmod(os.path.join(paths.IPA_NSSDB_DIR, 'cert8.db'), 0644)
    os.chmod(os.path.join(paths.IPA_NSSDB_DIR, 'key3.db'), 0644)
    os.chmod(os.path.join(paths.IPA_NSSDB_DIR, 'secmod.db'), 0644)
