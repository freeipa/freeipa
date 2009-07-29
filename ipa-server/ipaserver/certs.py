# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import os, stat, subprocess, re
import errno
import tempfile
import shutil
import logging

from ipa import sysrestore
from ipa import ipautil

# The sha module is deprecated in Python 2.6, replaced by hashlib. Try
# that first and fall back to sha.sha if it isn't available.
try:
    from hashlib import sha256 as sha
except ImportError:
    from sha import sha

CA_SERIALNO="/var/lib/ipa/ca_serialno"

class CertDB(object):
    def __init__(self, dir, fstore=None):
        self.secdir = dir

        self.noise_fname = self.secdir + "/noise.txt"
        self.passwd_fname = self.secdir + "/pwdfile.txt"
        self.certdb_fname = self.secdir + "/cert8.db"
        self.keydb_fname = self.secdir + "/key3.db"
        self.secmod_fname = self.secdir + "/secmod.db"
        self.cacert_fname = self.secdir + "/cacert.asc"
        self.pk12_fname = self.secdir + "/cacert.p12"
        self.pin_fname = self.secdir + "/pin.txt"
        self.reqdir = tempfile.mkdtemp('', 'ipa-', '/var/lib/ipa')
        self.certreq_fname = self.reqdir + "/tmpcertreq"
        self.certder_fname = self.reqdir + "/tmpcert.der"

        # Making this a starting value that will generate
        # unique values for the current DB is the
        # responsibility of the caller for now. In the
        # future we might automatically determine this
        # for a given db.
        self.cur_serial = -1

        self.cacert_name = "CA certificate"
        self.valid_months = "120"
        self.keysize = "1024"

        # We are going to set the owner of all of the cert
        # files to the owner of the containing directory
        # instead of that of the process. This works when
        # this is called by root for a daemon that runs as
        # a normal user
        mode = os.stat(self.secdir)
        self.uid = mode[stat.ST_UID]
        self.gid = mode[stat.ST_GID]

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')

    def __del__(self):
        shutil.rmtree(self.reqdir, ignore_errors=True)

    def set_serial_from_pkcs12(self):
        """A CA cert was loaded from a PKCS#12 file. Set up our serial file"""

        self.cur_serial = self.find_cacert_serial()
        try:
            f=open(CA_SERIALNO,"w")
            f.write(str(self.cur_serial))
            f.close()
        except IOError, e:
            raise RuntimeError("Unable to increment serial number: %s" % str(e))

    def next_serial(self):
        try:
            f=open(CA_SERIALNO,"r")
            r = f.readline()
            try:
                self.cur_serial = int(r) + 1
            except ValueError:
                raise RuntimeError("The value in %s is not an integer" % CA_SERIALNO)
            f.close()
        except IOError, e:
            if e.errno == errno.ENOENT:
                self.cur_serial = 1000
                f=open(CA_SERIALNO,"w")
                f.write(str(self.cur_serial))
                f.close()
            else:
                raise RuntimeError("Unable to determine serial number: %s" % str(e))

        try:
            f=open(CA_SERIALNO,"w")
            f.write(str(self.cur_serial))
            f.close()
        except IOError, e:
            raise RuntimeError("Unable to increment serial number: %s" % str(e))

        return str(self.cur_serial)

    def set_perms(self, fname, write=False):
        os.chown(fname, self.uid, self.gid)
        perms = stat.S_IRUSR
        if write:
            perms |= stat.S_IWUSR
        os.chmod(fname, perms)

    def gen_password(self):
        return sha(ipautil.ipa_generate_password()).hexdigest()

    def run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.secdir]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

    def run_signtool(self, args, stdin=None):
        new_args = ["/usr/bin/signtool", "-d", self.secdir]
        new_args = new_args + args
        ipautil.run(new_args, stdin)

    def create_noise_file(self):
        ipautil.backup_file(self.noise_fname)
        f = open(self.noise_fname, "w")
        f.write(self.gen_password())
        self.set_perms(self.noise_fname)

    def create_passwd_file(self, passwd=None):
        ipautil.backup_file(self.passwd_fname)
        f = open(self.passwd_fname, "w")
        if passwd is not None:
            f.write("%s\n" % passwd)
        else:
            f.write(self.gen_password())
        f.close()
        self.set_perms(self.passwd_fname)

    def create_certdbs(self):
        ipautil.backup_file(self.certdb_fname)
        ipautil.backup_file(self.keydb_fname)
        ipautil.backup_file(self.secmod_fname)
        self.run_certutil(["-N",
                           "-f", self.passwd_fname])
        self.set_perms(self.passwd_fname, write=True)

    def create_ca_cert(self):
        # Generate the encryption key
        self.run_certutil(["-G", "-z", self.noise_fname, "-f", self.passwd_fname])
        # Generate the self-signed cert
        self.run_certutil(["-S", "-n", self.cacert_name,
                           "-s", "cn=IPA Test Certificate Authority",
                           "-x",
                           "-t", "CT,,C",
                           "-m", self.next_serial(),
                           "-v", self.valid_months,
                           "-z", self.noise_fname,
                           "-f", self.passwd_fname])

    def export_ca_cert(self, nickname, create_pkcs12=False):
        """create_pkcs12 tells us whether we should create a PKCS#12 file
           of the CA or not. If we are running on a replica then we won't
           have the private key to make a PKCS#12 file so we don't need to
           do that step."""
        # export the CA cert for use with other apps
        ipautil.backup_file(self.cacert_fname)
        self.run_certutil(["-L", "-n", nickname,
                           "-a",
                           "-o", self.cacert_fname])
        self.set_perms(self.cacert_fname)
        if create_pkcs12:
            ipautil.backup_file(self.pk12_fname)
            ipautil.run(["/usr/bin/pk12util", "-d", self.secdir,
                         "-o", self.pk12_fname,
                         "-n", self.cacert_name,
                         "-w", self.passwd_fname,
                         "-k", self.passwd_fname])
            self.set_perms(self.pk12_fname)

    def load_cacert(self, cacert_fname):
        self.run_certutil(["-A", "-n", self.cacert_name,
                           "-t", "CT,,C",
                           "-a",
                           "-i", cacert_fname])

    def find_cacert_serial(self):
        (out,err) = self.run_certutil(["-L", "-n", self.cacert_name])
        data = out.split('\n')
        for line in data:
            x = re.match(r'\s+Serial Number: (\d+) .*', line)
            if x is not None:
                return x.group(1)

        raise RuntimeError("Unable to find serial number")

    def create_server_cert(self, nickname, name, other_certdb=None):
        cdb = other_certdb
        if not cdb:
            cdb = self
        self.request_cert(name)
        cdb.issue_server_cert(self.certreq_fname, self.certder_fname)
        self.add_cert(self.certder_fname, nickname)
        os.unlink(self.certreq_fname)
        os.unlink(self.certder_fname)

    def create_signing_cert(self, nickname, name, other_certdb=None):
        cdb = other_certdb
        if not cdb:
            cdb = self
        self.request_cert(name)
        cdb.issue_signing_cert(self.certreq_fname, self.certder_fname)
        self.add_cert(self.certder_fname, nickname)
        os.unlink(self.certreq_fname)
        os.unlink(self.certder_fname)

    def request_cert(self, name):
        self.run_certutil(["-R", "-s", name,
                           "-o", self.certreq_fname,
                           "-g", self.keysize,
                           "-z", self.noise_fname,
                           "-f", self.passwd_fname])

    def issue_server_cert(self, certreq_fname, cert_fname):
        p = subprocess.Popen(["/usr/bin/certutil",
                              "-d", self.secdir,
                              "-C", "-c", self.cacert_name,
                              "-i", certreq_fname,
                              "-o", cert_fname,
                              "-m", self.next_serial(),
                              "-v", self.valid_months,
                              "-f", self.passwd_fname,
                              "-1", "-5"],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)

        # Bah - this sucks, but I guess it isn't possible to fully
        # control this with command line arguments.
        #
        # What this is requesting is:
        #  -1 (Create key usage extension)
        #     2 - Key encipherment
        #     9 - done
        #     n - not critical
        #
        #  -5 (Create netscape cert type extension)
        #     1 - SSL Server
        #     9 - done
        #     n - not critical
        p.stdin.write("2\n9\nn\n1\n9\nn\n")
        p.wait()

    def issue_signing_cert(self, certreq_fname, cert_fname):
        p = subprocess.Popen(["/usr/bin/certutil",
                              "-d", self.secdir,
                              "-C", "-c", self.cacert_name,
                              "-i", certreq_fname,
                              "-o", cert_fname,
                              "-m", self.next_serial(),
                              "-v", self.valid_months,
                              "-f", self.passwd_fname,
                              "-1", "-5"],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)

        # Bah - this sucks, but I guess it isn't possible to fully
        # control this with command line arguments.
        #
        # What this is requesting is:
        #  -1 (Create key usage extension)
        #     0 - Digital Signature
        #     5 - Cert signing key
        #     9 - done
        #     n - not critical
        #
        #  -5 (Create netscape cert type extension)
        #     3 - Object Signing
        #     9 - done
        #     n - not critical
        p.stdin.write("0\n5\n9\nn\n3\n9\nn\n")
        p.wait()

    def add_cert(self, cert_fname, nickname):
        self.run_certutil(["-A", "-n", nickname,
                           "-t", "u,u,u",
                           "-i", cert_fname,
                           "-f", cert_fname])

    def create_pin_file(self):
        ipautil.backup_file(self.pin_fname)
        f = open(self.pin_fname, "w")
        f.write("Internal (Software) Token:")
        pwd = open(self.passwd_fname)
        f.write(pwd.read())
        f.close()
        self.set_perms(self.pin_fname)

    def find_root_cert(self, nickname):
        p = subprocess.Popen(["/usr/bin/certutil", "-d", self.secdir,
                              "-O", "-n", nickname], stdout=subprocess.PIPE)

        chain = p.stdout.read()
        chain = chain.split("\n")

        root_nickname = re.match('\ *"(.*)" \[.*', chain[0]).groups()[0]

        return root_nickname

    def find_root_cert_from_pkcs12(self, pkcs12_fname, passwd_fname=None):
        """Given a PKCS#12 file, try to find any certificates that do
           not have a key. The assumption is that these are the root CAs.
        """
        args = ["/usr/bin/pk12util", "-d", self.secdir,
                "-l", pkcs12_fname,
                "-k", passwd_fname]
        if passwd_fname:
            args = args + ["-w", passwd_fname]
        try:
            (stdout, stderr) = ipautil.run(args)
        except ipautil.CalledProcessError, e:
            if e.returncode == 17:
                raise RuntimeError("incorrect password")
            else:
                raise RuntimeError("unknown error using pkcs#12 file")

        lines = stdout.split('\n')

        # A simple state machine.
        # 1 = looking for "Certificate:"
        # 2 = looking for the Friendly name (nickname)
        nicknames = []
        state = 1
        for line in lines:
            if state == 2:
                m = re.match("\W+Friendly Name: (.*)", line)
                if m:
                    nicknames.append( m.groups(0)[0])
                    state = 1
            if line == "Certificate:":
                state = 2

        return nicknames

    def trust_root_cert(self, root_nickname):
         if root_nickname is None:
             logging.debug("Unable to identify root certificate to trust. Continuing but things are likely to fail.")
             return

         if root_nickname[:7] == "Builtin":
             logging.debug("No need to add trust for built-in root CA's, skipping %s" % root_nickname)
         else:
             self.run_certutil(["-M", "-n", root_nickname,
                                "-t", "CT,CT,"])

    def find_server_certs(self):
        p = subprocess.Popen(["/usr/bin/certutil", "-d", self.secdir,
                              "-L"], stdout=subprocess.PIPE)

        certs = p.stdout.read()

        certs = certs.split("\n")

        server_certs = []

        for cert in certs:
            fields = cert.split()
            if not len(fields):
                continue
            flags = fields[-1]
            if 'u' in flags:
                name = " ".join(fields[0:-1])
                # NSS 3.12 added a header to the certutil output
                if name == "Certificate Nickname Trust":
                    continue
                server_certs.append((name, flags))

        return server_certs

    def import_pkcs12(self, pkcs12_fname, passwd_fname=None):
        args = ["/usr/bin/pk12util", "-d", self.secdir,
                "-i", pkcs12_fname,
                "-k", self.passwd_fname]
        if passwd_fname:
            args = args + ["-w", passwd_fname]
        try:
            ipautil.run(args)
        except ipautil.CalledProcessError, e:
            if e.returncode == 17:
                raise RuntimeError("incorrect password")
            else:
                raise RuntimeError("unknown error import pkcs#12 file")

    def export_pkcs12(self, pkcs12_fname, pkcs12_pwd_fname, nickname="CA certificate"):
        ipautil.run(["/usr/bin/pk12util", "-d", self.secdir,
                     "-o", pkcs12_fname,
                     "-n", nickname,
                     "-k", self.passwd_fname,
                     "-w", pkcs12_pwd_fname])

    def create_self_signed(self, passwd=None):
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.create_ca_cert()
        self.export_ca_cert(self.cacert_name, True)
        self.create_pin_file()

    def create_from_cacert(self, cacert_fname, passwd=""):
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.load_cacert(cacert_fname)

    def create_from_pkcs12(self, pkcs12_fname, pkcs12_pwd_fname, passwd=None):
        """Create a new NSS database using the certificates in a PKCS#12 file.

           pkcs12_fname: the filename of the PKCS#12 file
           pkcs12_pwd_fname: the file containing the pin for the PKCS#12 file
           nickname: the nickname/friendly-name of the cert we are loading
           passwd: The password to use for the new NSS database we are creating
        """
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.import_pkcs12(pkcs12_fname, pkcs12_pwd_fname)
        server_certs = self.find_server_certs()
        if len(server_certs) == 0:
            raise RuntimeError("Could not find a suitable server cert in import in %s" % pkcs12_fname)

        # We only handle one server cert
        nickname = server_certs[0][0]

        ca_names = self.find_root_cert_from_pkcs12(pkcs12_fname, pkcs12_pwd_fname)
        if len(ca_names) == 0:
            raise RuntimeError("Could not find a CA cert in %s" % pkcs12_fname)

        self.cacert_name = ca_names[0]
        for nickname in ca_names:
            self.trust_root_cert(nickname)

        self.create_pin_file()
        self.export_ca_cert(self.cacert_name, False)

        # This file implies that we have our own self-signed CA. Ensure
        # that it no longer exists (from previous installs, for example).
        try:
            os.remove(CA_SERIALNO)
        except:
            pass

    def backup_files(self):
        self.fstore.backup_file(self.noise_fname)
        self.fstore.backup_file(self.passwd_fname)
        self.fstore.backup_file(self.certdb_fname)
        self.fstore.backup_file(self.keydb_fname)
        self.fstore.backup_file(self.secmod_fname)
        self.fstore.backup_file(self.cacert_fname)
        self.fstore.backup_file(self.pk12_fname)
        self.fstore.backup_file(self.pin_fname)
        self.fstore.backup_file(self.certreq_fname)
        self.fstore.backup_file(self.certder_fname)
