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
import sha
import errno
import tempfile
import shutil
import logging
import httplib
import urllib
import xml.dom.minidom
import pwd

from ipapython import nsslib
from ipapython import sysrestore
from ipapython import ipautil

from nss.error import NSPRError
import nss.nss as nss

CA_SERIALNO="/var/lib/ipa/ca_serialno"

def ipa_self_signed():
    """
    Determine if the current IPA CA is self-signed or using another CA

    Note that this doesn't distinguish between dogtag and being provided
    PKCS#12 files from another CA.

    A server is self-signed if /var/lib/ipa/ca_serialno exists
    """
    if ipautil.file_exists(CA_SERIALNO):
        return True
    else:
        return False

def client_auth_data_callback(ca_names, chosen_nickname, password, certdb):
    cert = None
    if chosen_nickname:
        try:
            cert = nss.find_cert_from_nickname(chosen_nickname, password)
            priv_key = nss.find_key_by_any_cert(cert, password)
            return cert, priv_key
        except NSPRError, e:
            logging.debug("client auth callback failed %s" % str(e))
            return False
    else:
        nicknames = nss.get_cert_nicknames(certdb, nss.SEC_CERT_NICKNAMES_USER)
        for nickname in nicknames:
            try:
                cert = nss.find_cert_from_nickname(nickname, password)
                if cert.check_valid_times():
                    if cert.has_signer_in_ca_names(ca_names):
                        priv_key = nss.find_key_by_any_cert(cert, password)
                        return cert, priv_key
            except NSPRError, e:
                logging.debug("client auth callback failed %s" % str(e))
                return False
        return False

class CertDB(object):
    def __init__(self, nssdir, fstore=None, host_name=None):
        self.secdir = nssdir

        self.noise_fname = self.secdir + "/noise.txt"
        self.passwd_fname = self.secdir + "/pwdfile.txt"
        self.certdb_fname = self.secdir + "/cert8.db"
        self.keydb_fname = self.secdir + "/key3.db"
        self.secmod_fname = self.secdir + "/secmod.db"
        self.cacert_fname = self.secdir + "/cacert.asc"
        self.pk12_fname = self.secdir + "/cacert.p12"
        self.pin_fname = self.secdir + "/pin.txt"
        self.pwd_conf = "/etc/httpd/conf/password.conf"
        self.reqdir = tempfile.mkdtemp('', 'ipa-', '/var/lib/ipa')
        self.certreq_fname = self.reqdir + "/tmpcertreq"
        self.certder_fname = self.reqdir + "/tmpcert.der"
        self.host_name = host_name

        self.self_signed_ca = ipa_self_signed()

        if self.self_signed_ca:
            self.subject_format = "CN=%s,ou=test-ipa,O=IPA"
        else:
            self.subject_format = "CN=%s,OU=pki-ipa,O=IPA"

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

    def find_cert_from_txt(self, cert):
        """
        Given a cert blob (str) which may or may not contian leading and
        trailing text, pull out just the certificate part. This will return
        the FIRST cert in a stream of data.
        """
        s = cert.find('-----BEGIN CERTIFICATE-----')
        e = cert.find('-----END CERTIFICATE-----')
        if e > 0: e = e + 25

        if s < 0 or e < 0:
            raise RuntimeError("Unable to find certificate")

        cert = cert[s:e]
        return cert

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
                self.self_signed_ca = True
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

    def set_perms(self, fname, write=False, uid=None):
        if uid:
            pent = pwd.getpwnam(uid)
            os.chown(fname, pent.pw_uid, pent.pw_gid)
        else:
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
        return ipautil.run(new_args, stdin)

    def run_signtool(self, args, stdin=None):
        if not self.self_signed_ca:
            f = open(self.passwd_fname, "r")
            password = f.readline()
            f.close()
            new_args = ["/usr/bin/signtool", "-d", self.secdir, "-p", password]
        else:
            new_args = ["/usr/bin/signtool", "-d", self.secdir]
        new_args = new_args + args
        ipautil.run(new_args, stdin)

    def create_noise_file(self):
        if ipautil.file_exists(self.noise_fname):
            os.remove(self.noise_fname)
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

    def list_certs(self):
        """
        Return a tuple of tuples containing (nickname, trust)
        """
        p = subprocess.Popen(["/usr/bin/certutil", "-d", self.secdir,
                              "-L"], stdout=subprocess.PIPE)

        certs = p.stdout.read()
        certs = certs.split("\n")

        # FIXME, this relies on NSS never changing the formatting of certutil
        certlist = []
        for cert in certs:
            nickname = cert[0:61]
            trust = cert[61:]
            if re.match(r'\w+,\w+,\w+', trust):
                certlist.append((nickname.strip(), trust))

        return tuple(certlist)

    def has_nickname(self, nickname):
        """
        Returns True if nickname exists in the certdb, False otherwise.

        This could also be done directly with:
            certutil -L -d -n <nickname> ...
        """

        certs = self.list_certs()

        for cert in certs:
            if nickname == cert[0]:
                return True

        return False

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
        os.chmod(self.cacert_fname, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
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

    def get_cert_from_db(self, nickname):
        try:
            args = ["-L", "-n", nickname, "-a"]
            (cert, err) = self.run_certutil(args)
            return cert
        except ipautil.CalledProcessError:
            return ''

    def find_cacert_serial(self):
        (out,err) = self.run_certutil(["-L", "-n", self.cacert_name])
        data = out.split('\n')
        for line in data:
            x = re.match(r'\s+Serial Number: (\d+) .*', line)
            if x is not None:
                return x.group(1)

        raise RuntimeError("Unable to find serial number")

    def create_server_cert(self, nickname, hostname, other_certdb=None, subject=None):
        """
        other_certdb can mean one of two things, depending on the context.

        If we are using a self-signed CA then other_certdb contains the
        CA that will be signing our CSR.

        If we are using a dogtag CA then it contains the RA agent key
        that will issue our cert.

        You can override the certificate Subject by specifying a subject.
        """
        cdb = other_certdb
        if not cdb:
            cdb = self
        if subject is None:
            subject=self.subject_format % hostname
        (out, err) = self.request_cert(subject)
        cdb.issue_server_cert(self.certreq_fname, self.certder_fname)
        self.add_cert(self.certder_fname, nickname)
        os.unlink(self.certreq_fname)
        os.unlink(self.certder_fname)

    def create_signing_cert(self, nickname, hostname, other_certdb=None, subject=None):
        cdb = other_certdb
        if not cdb:
            cdb = self
        if subject is None:
            subject=self.subject_format % hostname
        self.request_cert(subject)
        cdb.issue_signing_cert(self.certreq_fname, self.certder_fname)
        self.add_cert(self.certder_fname, nickname)
        os.unlink(self.certreq_fname)
        os.unlink(self.certder_fname)

    def request_cert(self, subject, certtype="rsa", keysize="2048"):
        self.create_noise_file()
        args = ["-R", "-s", subject,
                "-o", self.certreq_fname,
                "-k", certtype,
                "-g", keysize,
                "-z", self.noise_fname,
                "-f", self.passwd_fname]
        if not self.self_signed_ca:
            args.append("-a")
        (stdout, stderr) = self.run_certutil(args)
        os.remove(self.noise_fname)

        return (stdout, stderr)

    def issue_server_cert(self, certreq_fname, cert_fname):
        if self.self_signed_ca:
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
        else:
            if self.host_name is None:
                raise RuntimeError("CA Host is not set.")

            f = open(certreq_fname, "r")
            csr = f.readlines()
            f.close()
            csr = "".join(csr)

            # We just want the CSR bits, make sure there is nothing else
            s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
            e = csr.find("-----END NEW CERTIFICATE REQUEST-----")
            if e > 0:
                e = e + 37
            if s >= 0:
                csr = csr[s:]

            params = urllib.urlencode({'profileId': 'caRAserverCert',
                    'cert_request_type': 'pkcs10',
                    'requestor_name': 'IPA Installer',
                    'cert_request': csr,
                    'xmlOutput': 'true'})
            headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain"}

            # Send the request to the CA
            f = open(self.passwd_fname, "r")
            password = f.readline()
            f.close()
            conn = nsslib.NSSConnection(self.host_name, 9444, dbdir=self.secdir)
            conn.sslsock.set_client_auth_data_callback(client_auth_data_callback, "ipaCert", password, nss.get_default_certdb())
            conn.set_debuglevel(0)

            conn.request("POST", "/ca/ee/ca/profileSubmit", params, headers)
            res = conn.getresponse()
            data = res.read()
            conn.close()
            if res.status != 200:
                raise RuntimeError("Unable to submit cert request")

            # The result is an XML blob. Pull the certificate out of that
            doc = xml.dom.minidom.parseString(data)
            item_node = doc.getElementsByTagName("b64")
            cert = item_node[0].childNodes[0].data
            doc.unlink()
            conn.close()

            # Write the certificate to a file. It will be imported in a later
            # step.
            f = open(cert_fname, "w")
            f.write(cert)
            f.close()

        return

    def issue_signing_cert(self, certreq_fname, cert_fname):
        if self.self_signed_ca:
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
        else:
            if self.host_name is None:
                raise RuntimeError("CA Host is not set.")

            f = open(certreq_fname, "r")
            csr = f.readlines()
            f.close()
            csr = "".join(csr)

            # We just want the CSR bits, make sure there is no thing else
            s = csr.find("-----BEGIN NEW CERTIFICATE REQUEST-----")
            e = csr.find("-----END NEW CERTIFICATE REQUEST-----")
            if e > 0:
                e = e + 37
            if s >= 0:
                csr = csr[s:]

            params = urllib.urlencode({'profileId': 'caJarSigningCert',
                    'cert_request_type': 'pkcs10',
                    'requestor_name': 'IPA Installer',
                    'cert_request': csr,
                    'xmlOutput': 'true'})
            headers = {"Content-type": "application/x-www-form-urlencoded",
                       "Accept": "text/plain"}

            # Send the request to the CA
            f = open(self.passwd_fname, "r")
            password = f.readline()
            f.close()
            conn = nsslib.NSSConnection(self.host_name, 9444, dbdir=self.secdir)
            conn.sslsock.set_client_auth_data_callback(client_auth_data_callback, "ipaCert", password, nss.get_default_certdb())
            conn.set_debuglevel(0)

            conn.request("POST", "/ca/ee/ca/profileSubmit", params, headers)
            res = conn.getresponse()
            data = res.read()
            conn.close()
            if res.status != 200:
                raise RuntimeError("Unable to submit cert request")

            # The result is an XML blob. Pull the certificate out of that
            doc = xml.dom.minidom.parseString(data)
            item_node = doc.getElementsByTagName("b64")
            cert = item_node[0].childNodes[0].data
            doc.unlink()
            conn.close()

            f = open(cert_fname, "w")
            f.write(cert)
            f.close()

        return

    def add_cert(self, cert_fname, nickname):
        args = ["-A", "-n", nickname,
                "-t", "u,u,u",
                "-i", cert_fname,
                "-f", cert_fname]
        if not self.self_signed_ca:
            args.append("-a")
        self.run_certutil(args)

    def create_pin_file(self):
        """
        This is the format of Directory Server pin files.
        """
        ipautil.backup_file(self.pin_fname)
        f = open(self.pin_fname, "w")
        f.write("Internal (Software) Token:")
        pwdfile = open(self.passwd_fname)
        f.write(pwdfile.read())
        f.close()
        pwdfile.close()
        self.set_perms(self.pin_fname)

    def create_password_conf(self):
        """
        This is the format of mod_nss pin files.
        """
        ipautil.backup_file(self.pwd_conf)
        f = open(self.pwd_conf, "w")
        f.write("internal:")
        pwdfile = open(self.passwd_fname)
        f.write(pwdfile.read())
        f.close()
        pwdfile.close()
        self.set_perms(self.pwd_conf, uid="apache")

    def find_root_cert(self, nickname):
        p = subprocess.Popen(["/usr/bin/certutil", "-d", self.secdir,
                              "-O", "-n", nickname], stdout=subprocess.PIPE)

        chain = p.stdout.read()
        chain = chain.split("\n")

        root_nickname = re.match('\ *"(.*)".*', chain[0]).groups()[0]

        return root_nickname

    def trust_root_cert(self, nickname):
        root_nickname = self.find_root_cert(nickname)

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
        if ipautil.file_exists(self.certdb_fname):
            # We already have a cert db, see if it is for the same CA.
            # If it is we leave things as they are.
            f = open(cacert_fname, "r")
            newca = f.readlines()
            f.close()
            newca = "".join(newca)
            newca = self.find_cert_from_txt(newca)

            cacert = self.get_cert_from_db(self.cacert_name)
            if cacert != '':
                cacert = self.find_cert_from_txt(cacert)

            if newca == cacert:
                return

        # The CA certificates are different or something went wrong. Start with
        # a new certificate database.
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.load_cacert(cacert_fname)

    def create_from_pkcs12(self, pkcs12_fname, pkcs12_pwd_fname, passwd=None):
        """Create a new NSS database using the certificates in a PKCS#12 file.

           pkcs12_fname: the filename of the PKCS#12 file
           pkcs12_pwd_fname: the file containing the pin for the PKCS#12 file
           nickname: the nickname/friendly-name of the cert we are loading
           passwd: The password to use for the new NSS database we are creating

           The global CA may be added as well in case it wasn't included in the
           PKCS#12 file. Extra certs won't hurt in any case.
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

        self.cacert_name = self.find_root_cert(nickname)

        # The point here is to list the cert chain to determine which CA
        # to trust. If we get the same nickname back as our server cert
        # go ahead and try to pull in the CA in case it either wasn't in the
        # PKCS#12 file we loaded or isn't showing in the chain from
        # certutil -O (bug #509132)
        if self.cacert_name == nickname:
            self.cacert_name="CA certificate"
            self.load_cacert("/usr/share/ipa/html/ca.crt")
        self.trust_root_cert(nickname)
        self.create_pin_file()
        self.export_ca_cert(self.cacert_name, False)
        self.self_signed_ca=False

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
