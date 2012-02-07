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

from ipapython import ipautil
from ipapython import nsslib
from ipalib import pkcs10
import tempfile
from ipapython.compat import sha1
import shutil
import os

CA_NICKNAME_FMT = "%s IPA CA"
def get_ca_nickname(realm, format=CA_NICKNAME_FMT):
    return format % realm

class CertDB(object):
    """
    To be used for temporary NSS databases only. If temporary is set then
    this willcompletely remove the database it is working on when the
    class is destroyed.
    """
    def __init__(self, secdir, password=None, temporary=False):
        if secdir is None:
            secdir = tempfile.mkdtemp(prefix = "certdb-")
        if password is None:
            password = self.generate_random()
        self.secdir = secdir
        self.password = password
        self.temporary = temporary
        self.noise_file = secdir + "/noise"
        self.pwd_file = secdir + "/pwd"
        self.csr_file = secdir + "/csr.txt"

        f = open(self.pwd_file, "w")
        f.write(self.password)
        f.close()

        if not ipautil.file_exists(secdir + "/secmod.db"):
            self.run_certutil(["-N", "-f", self.pwd_file])

    def __del__(self):
        if self.temporary:
            shutil.rmtree(self.secdir)
        else:
            # clean up
            if ipautil.file_exists(self.noise_file):
                os.remove(self.noise_file)

    def run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.secdir]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

    def generate_random(self):
        return sha1(ipautil.ipa_generate_password()).hexdigest()

    def create_noise_file(self):
        """
        Generate a noise file to be used when creating a key
        """
        if ipautil.file_exists(self.noise_file):
            os.remove(self.noise_file)

        f = open(self.noise_file, "w")
        f.write(self.generate_random())
        f.close()

        return

    def generate_csr(self, subject, keysize=2048, keytype="rsa"):
        """
        Generate a Certificate Signing Request (CSR) and return as a
        string the base-64 result with the BEGIN/END block.
        """
        self.create_noise_file()
        args = ["-R", "-s", subject,
                "-o", self.csr_file,
                "-k", keytype,
                "-g", str(keysize),
                "-z", self.noise_file,
                "-f", self.pwd_file,
                "-a"]
        self.run_certutil(args)

        # read in the CSR
        f = open(self.csr_file, "r")
        csr = f.readlines()
        f.close()
        csr = "".join(csr)

        csr = pkcs10.strip_header(csr)

        return csr

    def add_certificate(self, cert_file, nickname="Server-Cert", is_ca=False):
        """
        Add a certificate to our NSS database.

        Only supports base64-encoded certificates, not DER-encoded.
        """
        if is_ca:
            trust_flag="CT,C,C"
        else:
            trust_flag="u,u,u"

        # Import a certificate from an ASCII file
        args = ["-A",
                "-n", nickname,
                "-t", trust_flag,
                "-i", cert_file,
                "-f", self.pwd_file,
                "-a"]

        self.run_certutil(args)

    def create_pkcs12(self, pkcs12_file, nickname="Server-Cert", password=None):
        if password is None:
            password = self.password

        p12pwd_file = self.secdir + "/pkcs12_pwd"
        f = open(p12pwd_file, "w")
        f.write(password)
        f.close()

        args = ["/usr/bin/pk12util",
                "-d", self.secdir,
                "-o", pkcs12_file,
                "-n", nickname,
                "-k", self.pwd_file,
                "-w", p12pwd_file]
        ipautil.run(args)

        return password
