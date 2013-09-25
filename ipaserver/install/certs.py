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

import os
import stat
import re
import sys
import tempfile
import shutil
import xml.dom.minidom
import pwd
import base64
from hashlib import sha1

from nss import nss
from nss.error import NSPRError

from ipapython.ipa_log_manager import root_logger
from ipapython import dogtag
from ipapython import sysrestore
from ipapython import ipautil
from ipapython import certmonger
from ipapython.certdb import get_ca_nickname
from ipapython import services as ipaservices
from ipapython.dn import DN
from ipalib import pkcs10, x509, api
from ipalib.errors import CertificateOperationError
from ipalib.text import _

# Apache needs access to this database so we need to create it
# where apache can reach
NSS_DIR = "/etc/httpd/alias"

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


class NSSDatabase(object):
    """A general-purpose wrapper around a NSS cert database

    For permanent NSS databases, pass the cert DB directory to __init__

    For temporary databases, do not pass nssdir, and call close() when done
    to remove the DB. Alternatively, a NSSDatabase can be used as a
    context manager that calls close() automatically.
    """
    # Traditionally, we used CertDB for our NSS DB operations, but that class
    # got too tied to IPA server details, killing reusability.
    # BaseCertDB is a class that knows nothing about IPA.
    # Generic NSS DB code should be moved here.
    def __init__(self, nssdir=None):
        if nssdir is None:
            self.secdir = tempfile.mkdtemp()
            self._is_temporary = True
        else:
            self.secdir = nssdir
            self._is_temporary = False

    def close(self):
        if self._is_temporary:
            shutil.rmtree(self.secdir)

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()

    def run_certutil(self, args, stdin=None):
        new_args = ["/usr/bin/certutil", "-d", self.secdir]
        new_args = new_args + args
        return ipautil.run(new_args, stdin)

    def create_db(self, password_filename):
        """Create cert DB

        :param password_filename: Name of file containing the database password
        """
        self.run_certutil(["-N", "-f", password_filename])

    def list_certs(self):
        """Return nicknames and cert flags for all certs in the database

        :return: List of (name, trust_flags) tuples
        """
        certs, stderr, returncode = self.run_certutil(["-L"])
        certs = certs.splitlines()

        # FIXME, this relies on NSS never changing the formatting of certutil
        certlist = []
        for cert in certs:
            nickname = cert[0:61]
            trust = cert[61:]
            if re.match(r'\w*,\w*,\w*', trust):
                certlist.append((nickname.strip(), trust.strip()))

        return tuple(certlist)

    def find_server_certs(self):
        """Return nicknames and cert flags for server certs in the database

        Server certs have an "u" character in the trust flags.

        :return: List of (name, trust_flags) tuples
        """
        server_certs = []
        for name, flags in self.list_certs():
            if 'u' in flags:
                server_certs.append((name, flags))

        return server_certs

    def get_trust_chain(self, nickname):
        """Return names of certs in a given cert's trust chain

        :param nickname: Name of the cert
        :return: List of certificate names
        """
        root_nicknames = []
        chain, stderr, returncode = self.run_certutil([
            "-O", "-n", nickname])
        chain = chain.splitlines()

        for c in chain:
            m = re.match('\s*"(.*)" \[.*', c)
            if m:
                root_nicknames.append(m.groups()[0])

        return root_nicknames

    def import_pkcs12(self, pkcs12_filename, db_password_filename,
                      pkcs12_passwd=None):
        args = ["/usr/bin/pk12util", "-d", self.secdir,
                "-i", pkcs12_filename,
                "-k", db_password_filename, '-v']
        if pkcs12_passwd is not None:
            pkcs12_passwd = pkcs12_passwd + '\n'
            args = args + ["-w", "/dev/stdin"]
        try:
            ipautil.run(args, stdin=pkcs12_passwd)
        except ipautil.CalledProcessError, e:
            if e.returncode == 17:
                raise RuntimeError("incorrect password for pkcs#12 file %s" %
                    pkcs12_filename)
            elif e.returncode == 10:
                raise RuntimeError("Failed to open %s" % pkcs12_filename)
            else:
                raise RuntimeError("unknown error import pkcs#12 file %s" %
                    pkcs12_filename)

    def trust_root_cert(self, root_nickname):
        if root_nickname[:7] == "Builtin":
            root_logger.debug(
                "No need to add trust for built-in root CAs, skipping %s" %
                root_nickname)
        else:
            try:
                self.run_certutil(["-M", "-n", root_nickname,
                                   "-t", "CT,CT,"])
            except ipautil.CalledProcessError, e:
                raise RuntimeError(
                    "Setting trust on %s failed" % root_nickname)

    def export_pem_cert(self, nickname, location):
        """Export the given cert to PEM file in the given location"""
        cert, err, returncode = self.run_certutil(["-L", "-n", nickname, "-a"])
        with open(location, "w+") as fd:
            fd.write(cert)
        os.chmod(location, 0444)

    def import_pem_cert(self, nickname, flags, location):
        """Import a cert form the given PEM file.

        The file must contain exactly one certificate.
        """
        try:
            with open(location) as fd:
                certs = fd.read()
        except IOError as e:
            raise RuntimeError(
                "Failed to open %s: %s" % (location, e.strerror)
            )

        cert, st = find_cert_from_txt(certs)
        self.add_single_pem_cert(nickname, flags, cert)

        try:
            find_cert_from_txt(certs, st)
        except RuntimeError:
            pass
        else:
            raise ValueError('%s contains more than one certificate' %
                             location)

    def add_single_pem_cert(self, nick, flags, cert):
        """Import a cert in PEM format"""
        self.run_certutil(["-A", "-n", nick,
                            "-t", flags,
                            "-a"],
                            stdin=cert)

    def delete_cert(self, nick):
        self.run_certutil(["-D", "-n", nick])

    def verify_server_cert_validity(self, nickname, hostname):
        """Verify a certificate is valid for a SSL server with given hostname

        Raises a ValueError if the certificate is invalid.
        """
        certdb = cert = None
        nss.nss_init(self.secdir)
        try:
            certdb = nss.get_default_certdb()
            cert = nss.find_cert_from_nickname(nickname)
            intended_usage = nss.certificateUsageSSLServer
            try:
                approved_usage = cert.verify_now(certdb, True, intended_usage)
            except NSPRError, e:
                if e.errno != -8102:
                    raise ValueError(e.strerror)
                approved_usage = 0
            if not approved_usage & intended_usage:
                raise ValueError('invalid for a SSL server')
            if not cert.verify_hostname(hostname):
                raise ValueError('invalid for server %s' % hostname)
        finally:
            del certdb, cert
            nss.nss_shutdown()

        return None


class CertDB(object):
    """An IPA-server-specific wrapper around NSS

    This class knows IPA-specific details such as nssdir location, or the
    CA cert name.
    """
    # TODO: Remove all selfsign code
    def __init__(self, realm, nssdir=NSS_DIR, fstore=None, host_name=None, subject_base=None):
        self.nssdb = NSSDatabase(nssdir)

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
        return self.nssdb.run_certutil(args, stdin)

    def run_signtool(self, args, stdin=None):
        with open(self.passwd_fname, "r") as f:
            password = f.readline()
        new_args = ["/usr/bin/signtool", "-d", self.secdir, "-p", password]

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
        self.nssdb.create_db(self.passwd_fname)
        self.set_perms(self.passwd_fname, write=True)

    def list_certs(self):
        """
        Return a tuple of tuples containing (nickname, trust)
        """
        return self.nssdb.list_certs()

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
                self.nssdb.add_single_pem_cert(nick, "CT,,C", cert)
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

    def track_server_cert(self, nickname, principal, password_file=None, command=None):
        """
        Tell certmonger to track the given certificate nickname.

        If command is not a full path then it is prefixed with
        /usr/lib[64]/ipa/certmonger.
        """
        if command is not None and not os.path.isabs(command):
            if sys.maxsize > 2**32L:
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
        If we are using a dogtag CA then other_certdb contains the RA agent key
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
                "-f", self.passwd_fname,
                "-a"]
        (stdout, stderr, returncode) = self.run_certutil(args)
        os.remove(self.noise_fname)
        return (stdout, stderr)

    def issue_server_cert(self, certreq_fname, cert_fname):
        self.setup_cert_request()

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

    def issue_signing_cert(self, certreq_fname, cert_fname):
        self.setup_cert_request()

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

    def add_cert(self, cert_fname, nickname):
        """
        Load a certificate from a PEM file and add minimal trust.
        """
        args = ["-A", "-n", nickname,
                "-t", "u,u,u",
                "-i", cert_fname,
                "-f", self.passwd_fname]
        self.run_certutil(args)

    def delete_cert(self, nickname):
        self.nssdb.delete_cert(nickname)

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
        root_nicknames = self.nssdb.get_trust_chain(nickname)

        return root_nicknames

    def trust_root_cert(self, root_nickname):
        if root_nickname is None:
            root_logger.debug("Unable to identify root certificate to trust. Continuing but things are likely to fail.")
            return

        try:
            self.nssdb.trust_root_cert(root_nickname)
        except RuntimeError:
            pass

    def find_server_certs(self):
        return self.nssdb.find_server_certs()

    def import_pkcs12(self, pkcs12_fname, pkcs12_passwd=None):
        return self.nssdb.import_pkcs12(pkcs12_fname, self.passwd_fname,
                                        pkcs12_passwd=pkcs12_passwd)

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

    def create_from_pkcs12(self, pkcs12_fname, pkcs12_passwd, passwd=None,
                           ca_file=None):
        """Create a new NSS database using the certificates in a PKCS#12 file.

           pkcs12_fname: the filename of the PKCS#12 file
           pkcs12_pwd_fname: the file containing the pin for the PKCS#12 file
           nickname: the nickname/friendly-name of the cert we are loading
           passwd: The password to use for the new NSS database we are creating

           The global CA may be added as well in case it wasn't included in the
           PKCS#12 file. Extra certs won't hurt in any case.

           The global CA may be specified in ca_file, as a PEM filename.
        """
        self.create_noise_file()
        self.create_passwd_file(passwd)
        self.create_certdbs()
        self.import_pkcs12(pkcs12_fname, pkcs12_passwd)
        server_certs = self.find_server_certs()
        if len(server_certs) == 0:
            raise RuntimeError("Could not find a suitable server cert in import in %s" % pkcs12_fname)

        if ca_file:
            self.nssdb.import_pem_cert('CA', 'CT,CT,', ca_file)

        # We only handle one server cert
        nickname = server_certs[0][0]

        ca_names = [name for name, flags
                    in self.nssdb.list_certs() if 'u' not in flags]
        if len(ca_names) == 0:
            raise RuntimeError("Could not find a CA cert in %s" % pkcs12_fname)

        self.cacert_name = ca_names[0]
        for ca in ca_names:
            self.trust_root_cert(ca)

        self.create_pin_file()
        self.export_ca_cert(nickname, False)

    def install_pem_from_p12(self, p12_fname, p12_passwd, pem_fname):
        pwd = ipautil.write_tmp_file(p12_passwd)
        ipautil.run(["/usr/bin/openssl", "pkcs12", "-nodes",
                     "-in", p12_fname, "-out", pem_fname,
                     "-passin", "file:" + pwd.name])

    def publish_ca_cert(self, location):
        shutil.copy(self.cacert_fname, location)
        os.chmod(location, 0444)

    def export_pem_cert(self, nickname, location):
        return self.nssdb.export_pem_cert(nickname, location)
