# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
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

import os, stat, subprocess, re
import sys
import errno
import tempfile
import shutil
from ipapython.ipa_log_manager import *
import urllib
import xml.dom.minidom
import pwd
import fcntl
import base64

from ipapython import nsslib
from ipapython import dogtag
from ipapython import sysrestore
from ipapython import ipautil
from ipapython import certmonger
from ipapython.certdb import get_ca_nickname
from ipalib import pkcs10
from ConfigParser import RawConfigParser, MissingSectionHeaderError
from ipapython import services as ipaservices
from ipalib import x509
from ipapython.dn import DN
from ipalib.errors import CertificateOperationError
from ipalib.text import _

from nss.error import NSPRError
import nss.nss as nss

from ipalib import api

from ipapython.compat import sha1

# Apache needs access to this database so we need to create it
# where apache can reach
NSS_DIR = "/etc/httpd/alias"

CA_SERIALNO="/var/lib/ipa/ca_serialno"

def ipa_self_signed():
    """
    Determine if the current IPA CA is self-signed or using another CA

    We do this based on the CA plugin that is currently in use.
    """
    if api.env.ra_plugin == 'selfsign':
        return True
    else:
        return False

def ipa_self_signed_master():
    """
    The selfsign backend is enabled only one a single master.

    Return True/False whether this is that master.

    Returns None if not a self-signed server.
    """
    if ipa_self_signed():
        return api.env.enable_ra
    else:
        return None

def find_cert_from_txt(cert, start=0):
    """
    Given a cert blob (str) which may or may not contian leading and
    trailing text, pull out just the certificate part. This will return
    the FIRST cert in a stream of data.

    Returns a tuple (certificate, last position in cert)
    """
    s = cert.find('-----BEGIN CERTIFICATE-----', start)
    e = cert.find('-----END CERTIFICATE-----', s)
    if e > 0: e = e + 25

    if s < 0 or e < 0:
        raise RuntimeError("Unable to find certificate")

    cert = cert[s:e]
    return (cert, e)

def get_cert_nickname(cert):
    """
    Using the subject from cert come up with a nickname suitable
    for NSS. The caller can decide whether to use just the RDN
    or the whole subject.

    Returns a tuple of (rdn, subject_dn) when rdn is the string
    representation of the first RDN in the subject and subject_dn
    is a DN object.
    """
    nsscert = x509.load_certificate(cert)
    subject = str(nsscert.subject)
    dn = DN(subject)

    return (str(dn[0]), dn)

def next_serial(serial_file=CA_SERIALNO):
    """
    Get the next serial number if we're using an NSS-based self-signed CA.

    The file is an ini-like file with following properties:
       lastvalue = the last serial number handed out
       nextreplica = the serial number the next replica should start with
       replicainterval = the number to add to nextreplica the next time a
                         replica is created

    File locking is attempted so we have unique serial numbers.
    """
    fp = None
    parser = RawConfigParser()
    if ipautil.file_exists(serial_file):
        try:
            fp = open(serial_file, "r+")
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            parser.readfp(fp)
            serial = parser.getint('selfsign', 'lastvalue')
            cur_serial = serial + 1
        except IOError, e:
            raise RuntimeError("Unable to determine serial number: %s" % str(e))
        except MissingSectionHeaderError:
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
            fp.close()
            f=open(serial_file,"r")
            r = f.readline()
            f.close()
            cur_serial = int(r) + 1
            fp = open(serial_file, "w")
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            parser.add_section('selfsign')
            parser.set('selfsign', 'nextreplica', 500000)
            parser.set('selfsign', 'replicainterval', 500000)
    else:
        fp = open(serial_file, "w")
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        parser.add_section('selfsign')
        parser.set('selfsign', 'nextreplica', 500000)
        parser.set('selfsign', 'replicainterval', 500000)
        cur_serial = 1000

    try:
        fp.seek(0)
        parser.set('selfsign', 'lastvalue', cur_serial)
        parser.write(fp)
        fp.flush()
        fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        fp.close()
    except IOError, e:
        raise RuntimeError("Unable to increment serial number: %s" % str(e))

    return str(cur_serial)

def next_replica(serial_file=CA_SERIALNO):
    """
    Return the starting serial number for a new self-signed replica
    """
    fp = None
    parser = RawConfigParser()
    if ipautil.file_exists(serial_file):
        try:
            fp = open(serial_file, "r+")
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            parser.readfp(fp)
            serial = parser.getint('selfsign', 'nextreplica')
            nextreplica = serial + parser.getint('selfsign', 'replicainterval')
        except IOError, e:
            raise RuntimeError("Unable to determine serial number: %s" % str(e))
    else:
        raise RuntimeError("%s does not exist, cannot create replica" % serial_file)
    try:
        fp.seek(0)
        parser.set('selfsign', 'nextreplica', nextreplica)
        parser.write(fp)
        fp.flush()
        fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        fp.close()
    except IOError, e:
        raise RuntimeError("Unable to increment serial number: %s" % str(e))

    return str(serial)

class CertDB(object):
    def __init__(self, realm, nssdir=NSS_DIR, fstore=None, host_name=None, subject_base=None):
        self.secdir = nssdir
        self.realm = realm

        self.noise_fname = self.secdir + "/noise.txt"
        self.passwd_fname = self.secdir + "/pwdfile.txt"
        self.certdb_fname = self.secdir + "/cert8.db"
        self.keydb_fname = self.secdir + "/key3.db"
        self.secmod_fname = self.secdir + "/secmod.db"
        self.cacert_fname = self.secdir + "/cacert.asc"
        self.pk12_fname = self.secdir + "/cacert.p12"
        self.pin_fname = self.secdir + "/pin.txt"
        self.pwd_conf = "/etc/httpd/conf/password.conf"
        self.reqdir = None
        self.certreq_fname = None
        self.certder_fname = None
        self.host_name = host_name
        self.subject_base = subject_base
        try:
            self.cwd = os.getcwd()
        except OSError, e:
            raise RuntimeError("Unable to determine the current directory: %s" % str(e))

        self.self_signed_ca = ipa_self_signed()

        if not subject_base:
            self.subject_base = DN(('O', 'IPA'))

        self.cacert_name = get_ca_nickname(self.realm)
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

    subject_base = ipautil.dn_attribute_property('_subject_base')

    def __del__(self):
        if self.reqdir is not None:
            shutil.rmtree(self.reqdir, ignore_errors=True)
        try:
            os.chdir(self.cwd)
        except:
            pass

    def setup_cert_request(self):
        """
        Create a temporary directory to store certificate requests and
        certificates. This should be called before requesting certificates.

        This is set outside of __init__ to avoid creating a temporary
        directory every time we open a cert DB.
        """
        if self.reqdir is not None:
            return

        self.reqdir = tempfile.mkdtemp('', 'ipa-', '/var/lib/ipa')
        self.certreq_fname = self.reqdir + "/tmpcertreq"
        self.certder_fname = self.reqdir + "/tmpcert.der"

        # When certutil makes a request it creates a file in the cwd, make
        # sure we are in a unique place when this happens
        os.chdir(self.reqdir)

    def set_serial_from_pkcs12(self):
        """A CA cert was loaded from a PKCS#12 file. Set up our serial file"""

        cur_serial = self.find_cacert_serial()
        try:
            fp = open(CA_SERIALNO, "w")
            parser = RawConfigParser()
            parser.add_section('selfsign')
            parser.set('selfsign', 'lastvalue', cur_serial)
            parser.set('selfsign', 'nextreplica', 500000)
            parser.set('selfsign', 'replicainterval', 500000)
            parser.write(fp)
            fp.close()
        except IOError, e:
            raise RuntimeError("Unable to increment serial number: %s" % str(e))

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
        return sha1(ipautil.ipa_generate_password()).hexdigest()

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
        os.chdir(self.secdir)
        subject = DN(('cn', '%s Certificate Authority' % self.realm))
        p = subprocess.Popen(["/usr/bin/certutil",
                              "-d", self.secdir,
                              "-S", "-n", self.cacert_name,
                              "-s", str(subject),
                              "-x",
                              "-t", "CT,,C",
                              "-1",
                              "-2",
                              "-5",
                              "-m", next_serial(),
                              "-v", self.valid_months,
                              "-z", self.noise_fname,
                              "-f", self.passwd_fname],
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        # Create key usage extension
        # 0 - Digital Signature
        # 1 - Non-repudiation
        # 5 - Cert signing key
        # Is this a critical extension [y/N]? y
        p.stdin.write("0\n1\n5\n9\ny\n")
        # Create basic constraint extension
        # Is this a CA certificate [y/N]?  y
        # Enter the path length constraint, enter to skip [<0 for unlimited pat
        # Is this a critical extension [y/N]? y
        # 5 6 7 9 n  -> SSL, S/MIME, Object signing CA
        p.stdin.write("y\n\ny\n")
        p.stdin.write("5\n6\n7\n9\nn\n")
        p.wait()
        os.chdir(self.cwd)

    def export_ca_cert(self, nickname, create_pkcs12=False):
        """create_pkcs12 tells us whether we should create a PKCS#12 file
           of the CA or not. If we are running on a replica then we won't
           have the private key to make a PKCS#12 file so we don't need to
           do that step."""
        # export the CA cert for use with other apps
        ipautil.backup_file(self.cacert_fname)
        root_nicknames = self.find_root_cert(nickname)
        fd = open(self.cacert_fname, "w")
        for root in root_nicknames:
            (cert, stderr, returncode) = self.run_certutil(["-L", "-n", root, "-a"])
            fd.write(cert)
        fd.close()
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
        """
        Load all the certificates from a given file. It is assumed that
        this file creates CA certificates.
        """
        fd = open(cacert_fname)
        certs = fd.read()
        fd.close()

        ca_dn = DN(('CN','Certificate Authority'), self.subject_base)
        st = 0
        while True:
            try:
                (cert, st) = find_cert_from_txt(certs, st)
                (rdn, subject_dn) = get_cert_nickname(cert)
                if subject_dn == ca_dn:
                    nick = get_ca_nickname(self.realm)
                else:
                    nick = str(subject_dn)
                self.run_certutil(["-A", "-n", nick,
                                   "-t", "CT,,C",
                                   "-a"],
                                   stdin=cert)
            except RuntimeError:
                break

    def get_cert_from_db(self, nickname, pem=True):
        """
        Retrieve a certificate from the current NSS database for nickname.

        pem controls whether the value returned PEM or DER-encoded. The
        default is the data straight from certutil -a.
        """
        try:
            args = ["-L", "-n", nickname, "-a"]
            (cert, err, returncode) = self.run_certutil(args)
            if pem:
                return cert
            else:
                (cert, start) = find_cert_from_txt(cert, start=0)
                cert = x509.strip_header(cert)
                dercert = base64.b64decode(cert)
                return dercert
        except ipautil.CalledProcessError:
            return ''

    def find_cacert_serial(self):
        (out, err, returncode) = self.run_certutil(["-L", "-n", self.cacert_name])
        data = out.split('\n')
        for line in data:
            x = re.match(r'\s+Serial Number: (\d+) .*', line)
            if x is not None:
                return x.group(1)

        raise RuntimeError("Unable to find serial number")

    def track_server_cert(self, nickname, principal, password_file=None, command=None):
        """
        Tell certmonger to track the given certificate nickname.

        If command is not a full path then it is prefixed with
        /usr/lib[64]/ipa/certmonger.
        """
        if command is not None and not os.path.isabs(command):
            if sys.maxsize > 2**32:
                libpath = 'lib64'
            else:
                libpath = 'lib'
            command = '/usr/%s/ipa/certmonger/%s' % (libpath, command)
        cmonger = ipaservices.knownservices.certmonger
        cmonger.enable()
        ipaservices.knownservices.messagebus.start()
        cmonger.start()
        try:
            (stdout, stderr, rc) = certmonger.start_tracking(nickname, self.secdir, password_file, command)
        except (ipautil.CalledProcessError, RuntimeError), e:
            root_logger.error("certmonger failed starting to track certificate: %s" % str(e))
            return

        cmonger.stop()
        cert = self.get_cert_from_db(nickname)
        nsscert = x509.load_certificate(cert, dbdir=self.secdir)
        subject = str(nsscert.subject)
        m = re.match('New tracking request "(\d+)" added', stdout)
        if not m:
            root_logger.error('Didn\'t get new %s request, got %s' % (cmonger.service_name, stdout))
            raise RuntimeError('%s did not issue new tracking request for \'%s\' in \'%s\'. Use \'ipa-getcert list\' to list existing certificates.' % (cmonger.service_name, nickname, self.secdir))
        request_id = m.group(1)

        certmonger.add_principal(request_id, principal)
        certmonger.add_subject(request_id, subject)

        cmonger.start()

    def untrack_server_cert(self, nickname):
        """
        Tell certmonger to stop tracking the given certificate nickname.
        """

        # Always start certmonger. We can't untrack something if it isn't
        # running
        cmonger = ipaservices.knownservices.certmonger
        ipaservices.knownservices.messagebus.start()
        cmonger.start()
        try:
            certmonger.stop_tracking(self.secdir, nickname=nickname)
        except (ipautil.CalledProcessError, RuntimeError), e:
            root_logger.error("certmonger failed to stop tracking certificate: %s" % str(e))
        cmonger.stop()

    def create_server_cert(self, nickname, hostname, other_certdb=None, subject=None):
        """
        other_certdb can mean one of two things, depending on the context.

        If we are using a self-signed CA then other_certdb contains the
        CA that will be signing our CSR.

        If we are using a dogtag CA then it contains the RA agent key
        that will issue our cert.

        You can override the certificate Subject by specifying a subject.

        Returns a certificate in DER format.
        """
        cdb = other_certdb
        if not cdb:
            cdb = self
        if subject is None:
            subject=DN(('CN', hostname), self.subject_base)
        self.request_cert(subject)
        cdb.issue_server_cert(self.certreq_fname, self.certder_fname)
        self.add_cert(self.certder_fname, nickname)
        fd = open(self.certder_fname, "r")
        dercert = fd.read()
        fd.close()

        os.unlink(self.certreq_fname)
        os.unlink(self.certder_fname)

        return dercert

    def create_signing_cert(self, nickname, hostname, other_certdb=None, subject=None):
        cdb = other_certdb
        if not cdb:
            cdb = self
        if subject is None:
            subject=DN(('CN', hostname), self.subject_base)
        self.request_cert(subject)
        cdb.issue_signing_cert(self.certreq_fname, self.certder_fname)
        self.add_cert(self.certder_fname, nickname)
        os.unlink(self.certreq_fname)
        os.unlink(self.certder_fname)

    def request_cert(self, subject, certtype="rsa", keysize="2048"):
        assert isinstance(subject, DN)
        self.create_noise_file()
        self.setup_cert_request()
        args = ["-R", "-s", str(subject),
                "-o", self.certreq_fname,
                "-k", certtype,
                "-g", keysize,
                "-z", self.noise_fname,
                "-f", self.passwd_fname]
        if not self.self_signed_ca:
            args.append("-a")
        (stdout, stderr, returncode) = self.run_certutil(args)
        os.remove(self.noise_fname)
        return (stdout, stderr)

    def issue_server_cert(self, certreq_fname, cert_fname):
        self.setup_cert_request()
        if self.self_signed_ca:
            p = subprocess.Popen(["/usr/bin/certutil",
                                  "-d", self.secdir,
                                  "-C", "-c", self.cacert_name,
                                  "-i", certreq_fname,
                                  "-o", cert_fname,
                                  "-m", next_serial(),
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
            csr = pkcs10.strip_header(csr)

            params = {'profileId': 'caIPAserviceCert',
                    'cert_request_type': 'pkcs10',
                    'requestor_name': 'IPA Installer',
                    'cert_request': csr,
                    'xmlOutput': 'true'}

            # Send the request to the CA
            f = open(self.passwd_fname, "r")
            password = f.readline()
            f.close()
            result = dogtag.https_request(
                self.host_name,
                api.env.ca_ee_install_port or
                    dogtag.configured_constants().EE_SECURE_PORT,
                "/ca/ee/ca/profileSubmitSSLClient",
                self.secdir, password, "ipaCert", **params)
            http_status, http_reason_phrase, http_headers, http_body = result

            if http_status != 200:
                raise CertificateOperationError(
                    error=_('Unable to communicate with CMS (%s)') %
                        http_reason_phrase)

            # The result is an XML blob. Pull the certificate out of that
            doc = xml.dom.minidom.parseString(http_body)
            item_node = doc.getElementsByTagName("b64")
            try:
                try:
                    cert = item_node[0].childNodes[0].data
                except IndexError:
                    raise RuntimeError("Certificate issuance failed")
            finally:
                doc.unlink()

            # base64-decode the result for uniformity
            cert = base64.b64decode(cert)

            # Write the certificate to a file. It will be imported in a later
            # step. This file will be read later to be imported.
            f = open(cert_fname, "w")
            f.write(cert)
            f.close()

        return

    def issue_signing_cert(self, certreq_fname, cert_fname):
        self.setup_cert_request()
        if self.self_signed_ca:
            p = subprocess.Popen(["/usr/bin/certutil",
                                  "-d", self.secdir,
                                  "-C", "-c", self.cacert_name,
                                  "-i", certreq_fname,
                                  "-o", cert_fname,
                                  "-m", next_serial(),
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
            csr = pkcs10.strip_header(csr)

            params = {'profileId': 'caJarSigningCert',
                    'cert_request_type': 'pkcs10',
                    'requestor_name': 'IPA Installer',
                    'cert_request': csr,
                    'xmlOutput': 'true'}

            # Send the request to the CA
            f = open(self.passwd_fname, "r")
            password = f.readline()
            f.close()
            result = dogtag.https_request(
                self.host_name,
                api.env.ca_ee_install_port or
                    dogtag.configured_constants().EE_SECURE_PORT,
                "/ca/ee/ca/profileSubmitSSLClient",
                self.secdir, password, "ipaCert", **params)
            http_status, http_reason_phrase, http_headers, http_body = result
            if http_status != 200:
                raise RuntimeError("Unable to submit cert request")

            # The result is an XML blob. Pull the certificate out of that
            doc = xml.dom.minidom.parseString(http_body)
            item_node = doc.getElementsByTagName("b64")
            cert = item_node[0].childNodes[0].data
            doc.unlink()

            # base64-decode the cert for uniformity
            cert = base64.b64decode(cert)

            # Write the certificate to a file. It will be imported in a later
            # step. This file will be read later to be imported.
            f = open(cert_fname, "w")
            f.write(cert)
            f.close()

        return

    def add_cert(self, cert_fname, nickname):
        """
        Load a certificate from a PEM file and add minimal trust.
        """
        args = ["-A", "-n", nickname,
                "-t", "u,u,u",
                "-i", cert_fname,
                "-f", self.passwd_fname]
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
        # TODO: replace explicit uid by a platform-specific one
        self.set_perms(self.pwd_conf, uid="apache")

    def find_root_cert(self, nickname):
        """
        Given a nickname, return a list of the certificates that make up
        the trust chain.
        """
        root_nicknames = []
        p = subprocess.Popen(["/usr/bin/certutil", "-d", self.secdir,
                              "-O", "-n", nickname], stdout=subprocess.PIPE)

        chain = p.stdout.read()
        chain = chain.split("\n")

        for c in chain:
            m = re.match('\s*"(.*)" \[.*', c)
            if m:
                root_nicknames.append(m.groups()[0])

        if len(root_nicknames) > 1:
            # If you pass in the name of a CA to get the chain it may only
            # return 1 (self-signed). Return that.
            try:
                root_nicknames.remove(nickname)
            except ValueError:
                # The nickname wasn't in the list
                pass

        # Try to work around a change in the F-11 certutil where untrusted
        # CA's are not shown in the chain. This will make a default IPA
        # server installable.
        if len(root_nicknames) == 0 and self.self_signed_ca:
            return [self.cacert_name]

        return root_nicknames

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
            (stdout, stderr, returncode) = ipautil.run(args)
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
            root_logger.debug("Unable to identify root certificate to trust. Continueing but things are likely to fail.")
            return

        if root_nickname[:7] == "Builtin":
            root_logger.debug("No need to add trust for built-in root CA's, skipping %s" % root_nickname)
        else:
            try:
                self.run_certutil(["-M", "-n", root_nickname,
                                   "-t", "CT,CT,"])
            except ipautil.CalledProcessError, e:
                root_logger.error("Setting trust on %s failed" % root_nickname)

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

    def export_pkcs12(self, pkcs12_fname, pkcs12_pwd_fname, nickname=None):
        if nickname is None:
            nickname = get_ca_nickname(api.env.realm)

        ipautil.run(["/usr/bin/pk12util", "-d", self.secdir,
                     "-o", pkcs12_fname,
                     "-n", nickname,
                     "-k", self.passwd_fname,
                     "-w", pkcs12_pwd_fname])

    def export_pem_p12(self, pkcs12_fname, pkcs12_pwd_fname,
                       nickname, pem_fname):
        ipautil.run(["/usr/bin/openssl", "pkcs12",
                     "-export", "-name", nickname,
                     "-in", pem_fname, "-out", pkcs12_fname,
                     "-passout", "file:" + pkcs12_pwd_fname])

    def create_self_signed(self, passwd=None):
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.create_ca_cert()
        self.export_ca_cert(self.cacert_name, True)
        self.create_pin_file()

    def create_from_cacert(self, cacert_fname, passwd=None):
        if ipautil.file_exists(self.certdb_fname):
            # We already have a cert db, see if it is for the same CA.
            # If it is we leave things as they are.
            f = open(cacert_fname, "r")
            newca = f.readlines()
            f.close()
            newca = "".join(newca)
            (newca, st) = find_cert_from_txt(newca)

            cacert = self.get_cert_from_db(self.cacert_name)
            if cacert != '':
                (cacert, st) = find_cert_from_txt(cacert)

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

        ca_names = self.find_root_cert_from_pkcs12(pkcs12_fname, pkcs12_pwd_fname)
        if len(ca_names) == 0:
            raise RuntimeError("Could not find a CA cert in %s" % pkcs12_fname)

        self.cacert_name = ca_names[0]
        for ca in ca_names:
            self.trust_root_cert(ca)

        self.create_pin_file()
        self.export_ca_cert(nickname, False)
        self.self_signed_ca=False

        # This file implies that we have our own self-signed CA. Ensure
        # that it no longer exists (from previous installs, for example).
        try:
            os.remove(CA_SERIALNO)
        except:
            pass

    def create_kdc_cert(self, nickname, hostname, destdir):
        """Create a new certificate with the spcial othername encoding needed
           by a KDC certificate.

           nickname: the CN name set in the certificate
           destdir: the location where cert and key are to be installed

           destdir will contain kdc.pem if the operation is successful
        """

        reqcfg = "kdc_req.conf"
        extcfg = ipautil.SHARE_DIR + "kdc_extensions.template"
        key_fname = destdir + "/kdckey.pem"
        cert_fname = destdir + "/kdccert.pem"
        key_cert_fname = destdir + "/kdc.pem"

        # Setup the temp dir
        self.setup_cert_request()

        # Copy the CA password file because openssl apparently can't use
        # the same file twice within the same command and throws an error
        ca_pwd_file = self.reqdir + "pwdfile.txt"
        shutil.copyfile(self.passwd_fname, ca_pwd_file)

        # Extract the cacert.pem file used by openssl to sign the certs
        ipautil.run(["/usr/bin/openssl", "pkcs12",
                     "-in", self.pk12_fname,
                     "-passin", "file:" + self.passwd_fname,
                     "-passout", "file:" + ca_pwd_file,
                     "-out", "cacert.pem"])

        # Create the kdc key
        ipautil.run(["/usr/bin/openssl", "genrsa",
                     "-out", key_fname, "2048"])

        # Prepare a simple cert request
        req_dict = dict(PASSWORD=self.gen_password(),
                        SUBJBASE=self.subject_base,
                        CERTNAME=DN(('CN', nickname)))
        req_template = ipautil.SHARE_DIR + reqcfg + ".template"
        conf = ipautil.template_file(req_template, req_dict)
        fd = open(reqcfg, "w+")
        fd.write(conf)
        fd.close()

        base = str(self.subject_base).replace(",", "/")
        esc_subject = DN(('CN', '%s/%s' % (nickname, base)))

        ipautil.run(["/usr/bin/openssl", "req", "-new",
                     "-config", reqcfg,
                     "-subj", str(esc_subject),
                     "-key", key_fname,
                     "-out", "kdc.req"])

        # Finally, sign the cert using the extensions file to set the
        # special name
        ipautil.run(["/usr/bin/openssl", "x509", "-req",
                     "-CA", "cacert.pem",
                     "-extfile", extcfg,
                     "-extensions", "kdc_cert",
                     "-passin", "file:" + ca_pwd_file,
                     "-set_serial", next_serial(),
                     "-in", "kdc.req",
                     "-out", cert_fname],
                    env = { 'REALM':self.realm, 'HOST_FQDN':hostname })

        # Merge key and cert in a single file
        fd = open(key_fname, "r")
        key = fd.read()
        fd.close()
        fd = open(cert_fname, "r")
        cert = fd.read()
        fd.close()
        fd = open(key_cert_fname, "w")
        fd.write(key)
        fd.write(cert)
        fd.close()
        os.unlink(key_fname)
        os.unlink(cert_fname)

    def install_pem_from_p12(self, p12_fname, p12_pwd_fname, pem_fname):
        ipautil.run(["/usr/bin/openssl", "pkcs12", "-nodes",
                     "-in", p12_fname, "-out", pem_fname,
                     "-passin", "file:" + p12_pwd_fname])

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

    def publish_ca_cert(self, location):
        shutil.copy(self.cacert_fname, location)
        os.chmod(location, 0444)
