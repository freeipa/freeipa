# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
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
import sha

from ipa import ipautil

class CertDB(object):
    def __init__(self, dir):
        self.secdir = dir

        self.noise_fname = self.secdir + "/noise.txt"
        self.passwd_fname = self.secdir + "/pwdfile.txt"
        self.certdb_fname = self.secdir + "/cert8.db"
        self.keydb_fname = self.secdir + "/key3.db"
        self.secmod_fname = self.secdir + "/secmod.db"
        self.cacert_fname = self.secdir + "/cacert.asc"
        self.pk12_fname = self.secdir + "/cacert.p12"
        self.pin_fname = self.secdir + "/pin.txt"
        self.certreq_fname = self.secdir + "/tmpcertreq"
        self.certder_fname = self.secdir + "/tmpcert.der"

        # Making this a starting value that will generate
        # unique values for the current DB is the
        # responsibility of the caller for now. In the
        # future we might automatically determine this
        # for a given db.
        self.cur_serial = 1000

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
    
    def next_serial(self):
        r = self.cur_serial
        self.cur_serial += 1
        return str(r)

    def set_perms(self, fname, write=False):
        os.chown(fname, self.uid, self.gid)
        perms = stat.S_IRUSR
        if write:
            perms |= stat.S_IWUSR
        os.chmod(fname, perms)

    def gen_password(self):
        return sha.sha(ipautil.ipa_generate_password()).hexdigest()

    def run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.secdir]
        new_args = new_args + args
        ipautil.run(new_args, stdin)

    def run_signtool(self, args, stdin=None):
        new_args = ["/usr/bin/signtool", "-d", self.secdir]
        new_args = new_args + args
        ipautil.run(new_args, stdin)

    def create_noise_file(self):
        ipautil.backup_file(self.noise_fname)
        f = open(self.noise_fname, "w")
        f.write(self.gen_password())
        self.set_perms(self.noise_fname)

    def create_passwd_file(self, passwd=True):
        ipautil.backup_file(self.passwd_fname)
        f = open(self.passwd_fname, "w")
        if passwd:
            f.write(self.gen_password())
        else:
            f.write("\n")
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

    def export_ca_cert(self):
        # export the CA cert for use with other apps
        ipautil.backup_file(self.cacert_fname)
        self.run_certutil(["-L", "-n", "CA certificate",
                           "-a",
                           "-o", self.cacert_fname])
        self.set_perms(self.cacert_fname)
        ipautil.backup_file(self.pk12_fname)
        ipautil.run(["/usr/bin/pk12util", "-d", self.secdir,
                     "-o", self.pk12_fname,
                     "-n", "CA certificate",
                     "-w", self.passwd_fname,
                     "-k", self.passwd_fname])
        self.set_perms(self.pk12_fname)

    def load_cacert(self, cacert_fname):
        self.run_certutil(["-A", "-n", self.cacert_name,
                           "-t", "CT,,C",
                           "-a",
                           "-i", cacert_fname])
        
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

    def trust_root_cert(self, nickname):
        p = subprocess.Popen(["/usr/bin/certutil", "-d", self.secdir,
                              "-O", "-n", nickname], stdout=subprocess.PIPE)

        chain = p.stdout.read()
        chain = chain.split("\n")

        root_nickname = re.match('\ *"(.*)".*', chain[0]).groups()[0]

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

    def create_self_signed(self, passwd=True):
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.create_ca_cert()
        self.export_ca_cert()
        self.create_pin_file()

    def create_from_cacert(self, cacert_fname, passwd=False):
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.load_cacert(cacert_fname)

    def create_from_pkcs12(self, pkcs12_fname, pkcs12_pwd_fname, nickname="CA certificate", passwd=True):
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.import_pkcs12(pkcs12_fname, pkcs12_pwd_fname)
        self.trust_root_cert(nickname)
        self.create_pin_file()
        self.export_ca_cert()

    def backup_files(self):
        sysrestore.backup_file(self.noise_fname)
        sysrestore.backup_file(self.passwd_fname)
        sysrestore.backup_file(self.certdb_fname)
        sysrestore.backup_file(self.keydb_fname)
        sysrestore.backup_file(self.secmod_fname)
        sysrestore.backup_file(self.cacert_fname)
        sysrestore.backup_file(self.pk12_fname)
        sysrestore.backup_file(self.pin_fname)
        sysrestore.backup_file(self.certreq_fname)
        sysrestore.backup_file(self.certder_fname)

        
