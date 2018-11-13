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
from __future__ import absolute_import

import collections
import logging
import os
import io
import pwd
import grp
import re
import stat
import tempfile
from tempfile import NamedTemporaryFile
import shutil

import cryptography.x509

from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython.dn import DN
from ipapython.kerberos import Principal
from ipapython import ipautil
from ipalib import x509     # pylint: disable=ipa-forbidden-import


logger = logging.getLogger(__name__)

CA_NICKNAME_FMT = "%s IPA CA"

NSS_DBM_FILES = ("cert8.db", "key3.db", "secmod.db")
NSS_SQL_FILES = ("cert9.db", "key4.db", "pkcs11.txt")
NSS_FILES = NSS_DBM_FILES + NSS_SQL_FILES + ("pwdfile.txt",)

TrustFlags = collections.namedtuple('TrustFlags', 'has_key trusted ca usages')

EMPTY_TRUST_FLAGS = TrustFlags(False, None, None, None)

IPA_CA_TRUST_FLAGS = TrustFlags(
    False, True, True, frozenset({
        x509.EKU_SERVER_AUTH,
        x509.EKU_CLIENT_AUTH,
        x509.EKU_CODE_SIGNING,
        x509.EKU_EMAIL_PROTECTION,
        x509.EKU_PKINIT_CLIENT_AUTH,
        x509.EKU_PKINIT_KDC,
    }),
)

EXTERNAL_CA_TRUST_FLAGS = TrustFlags(
    False, True, True, frozenset({x509.EKU_SERVER_AUTH}),
)

TRUSTED_PEER_TRUST_FLAGS = TrustFlags(
    False, True, False, frozenset({x509.EKU_SERVER_AUTH}),
)


def get_ca_nickname(realm, format=CA_NICKNAME_FMT):
    return format % realm


def find_cert_from_txt(cert, start=0):
    """
    Given a cert blob (str) which may or may not contian leading and
    trailing text, pull out just the certificate part. This will return
    the FIRST cert in a stream of data.

    :returns: a tuple (IPACertificate, last position in cert)
    """
    s = cert.find('-----BEGIN CERTIFICATE-----', start)
    e = cert.find('-----END CERTIFICATE-----', s)
    if e > 0:
        e = e + 25

    if s < 0 or e < 0:
        raise RuntimeError("Unable to find certificate")

    cert = x509.load_pem_x509_certificate(cert[s:e].encode('utf-8'))
    return (cert, e)


def parse_trust_flags(trust_flags):
    """
    Convert certutil trust flags to TrustFlags object.
    """
    has_key = 'u' in trust_flags

    if 'p' in trust_flags:
        if 'C' in trust_flags or 'P' in trust_flags or 'T' in trust_flags:
            raise ValueError("cannot be both trusted and not trusted")
        return False, None, None
    elif 'C' in trust_flags or 'T' in trust_flags:
        if 'P' in trust_flags:
            raise ValueError("cannot be both CA and not CA")
        ca = True
    elif 'P' in trust_flags:
        ca = False
    else:
        return TrustFlags(has_key, None, None, frozenset())

    trust_flags = trust_flags.split(',')
    ext_key_usage = set()
    for i, kp in enumerate((x509.EKU_SERVER_AUTH,
                            x509.EKU_EMAIL_PROTECTION,
                            x509.EKU_CODE_SIGNING)):
        if 'C' in trust_flags[i] or 'P' in trust_flags[i]:
            ext_key_usage.add(kp)
    if 'T' in trust_flags[0]:
        ext_key_usage.add(x509.EKU_CLIENT_AUTH)

    return TrustFlags(has_key, True, ca, frozenset(ext_key_usage))


def unparse_trust_flags(trust_flags):
    """
    Convert TrustFlags object to certutil trust flags.
    """
    has_key, trusted, ca, ext_key_usage = trust_flags

    if trusted is False:
        if has_key:
            return 'pu,pu,pu'
        else:
            return 'p,p,p'
    elif trusted is None or ca is None:
        if has_key:
            return 'u,u,u'
        else:
            return ',,'
    elif ext_key_usage is None:
        if ca:
            if has_key:
                return 'CTu,Cu,Cu'
            else:
                return 'CT,C,C'
        else:
            if has_key:
                return 'Pu,Pu,Pu'
            else:
                return 'P,P,P'

    trust_flags = ['', '', '']
    for i, kp in enumerate((x509.EKU_SERVER_AUTH,
                            x509.EKU_EMAIL_PROTECTION,
                            x509.EKU_CODE_SIGNING)):
        if kp in ext_key_usage:
            trust_flags[i] += ('C' if ca else 'P')
    if ca and x509.EKU_CLIENT_AUTH in ext_key_usage:
        trust_flags[0] += 'T'
    if has_key:
        for i in range(3):
            trust_flags[i] += 'u'

    trust_flags = ','.join(trust_flags)
    return trust_flags


def verify_kdc_cert_validity(kdc_cert, ca_certs, realm):
    """
    Verifies the validity of a kdc_cert, ensuring it is trusted by
    the ca_certs chain, has a PKINIT_KDC extended key usage support,
    and verify it applies to the given realm.
    """
    with NamedTemporaryFile() as kdc_file, NamedTemporaryFile() as ca_file:
        kdc_file.write(kdc_cert.public_bytes(x509.Encoding.PEM))
        kdc_file.flush()
        x509.write_certificate_list(ca_certs, ca_file.name)
        ca_file.flush()

        try:
            ipautil.run(
                [paths.OPENSSL, 'verify', '-CAfile', ca_file.name,
                 kdc_file.name],
                capture_output=True)
        except ipautil.CalledProcessError as e:
            raise ValueError(e.output)

        try:
            eku = kdc_cert.extensions.get_extension_for_class(
                cryptography.x509.ExtendedKeyUsage)
            list(eku.value).index(
                cryptography.x509.ObjectIdentifier(x509.EKU_PKINIT_KDC))
        except (cryptography.x509.ExtensionNotFound,
                ValueError):
            raise ValueError("invalid for a KDC")

        principal = str(Principal(['krbtgt', realm], realm))
        gns = x509.process_othernames(kdc_cert.san_general_names)
        for gn in gns:
            if isinstance(gn, x509.KRB5PrincipalName) and gn.name == principal:
                break
        else:
            raise ValueError("invalid for realm %s" % realm)


class NSSDatabase(object):
CERT_RE = re.compile(
    r'^(?P<nick>.+?)\s+(?P<flags>\w*,\w*,\w*)\s*$'
)
KEY_RE = re.compile(
    r'^<\s*(?P<slot>\d+)>'
    r'\s+(?P<algo>\w+)'
    r'\s+(?P<keyid>[0-9a-z]+)'
    r'\s+(?P<nick>.*?)\s*$'
)


class Pkcs12ImportIncorrectPasswordError(RuntimeError):
    """ Raised when import_pkcs12 fails because of a wrong password.
    """
    pass


class Pkcs12ImportOpenError(RuntimeError):
    """ Raised when import_pkcs12 fails trying to open the file.
    """
    pass


class Pkcs12ImportUnknownError(RuntimeError):
    """ Raised when import_pkcs12 fails because of an unknown error.
    """
    pass


class NSSDatabase:
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

    def __init__(self, nssdir=None, dbtype='auto'):
        if nssdir is None:
            self.secdir = tempfile.mkdtemp()
            self._is_temporary = True
        else:
            self.secdir = nssdir
            self._is_temporary = False
            if dbtype == 'auto':
                dbtype = self._detect_dbtype()

        self.pwd_file = os.path.join(self.secdir, 'pwdfile.txt')
        self.dbtype = None
        self.certdb = self.keydb = self.secmod = None
        # files in actual db
        self.filenames = ()
        # all files that are handled by create_db(backup=True)
        self.backup_filenames = ()
        self._set_filenames(dbtype)

    def _detect_dbtype(self):
        if os.path.isfile(os.path.join(self.secdir, "cert9.db")):
            return 'sql'
        elif os.path.isfile(os.path.join(self.secdir, "cert8.db")):
            return 'dbm'
        else:
            return 'auto'

    def _set_filenames(self, dbtype):
        self.dbtype = dbtype
        dbmfiles = (
            os.path.join(self.secdir, "cert8.db"),
            os.path.join(self.secdir, "key3.db"),
            os.path.join(self.secdir, "secmod.db")
        )
        sqlfiles = (
            os.path.join(self.secdir, "cert9.db"),
            os.path.join(self.secdir, "key4.db"),
            os.path.join(self.secdir, "pkcs11.txt")
        )
        if dbtype == 'dbm':
            self.certdb, self.keydb, self.secmod = dbmfiles
            self.filenames = dbmfiles + (self.pwd_file,)
        elif dbtype == 'sql':
            self.certdb, self.keydb, self.secmod = sqlfiles
            self.filenames = sqlfiles + (self.pwd_file,)
        elif dbtype == 'auto':
            self.certdb = self.keydb = self.secmod = None
            self.filenames = None
        else:
            raise ValueError(dbtype)
        self.backup_filenames = (
            self.pwd_file,
        ) + sqlfiles + dbmfiles

    def close(self):
        if self._is_temporary:
            shutil.rmtree(self.secdir)

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()

    def _check_db(self):
        if self.filenames is None:
            raise RuntimeError(
                "NSSDB '{}' not initialized.".format(self.secdir)
            )

    def run_certutil(self, args, stdin=None, **kwargs):
        self._check_db()
        new_args = [
            paths.CERTUTIL,
            "-d", '{}:{}'.format(self.dbtype, self.secdir)
        ]
        new_args.extend(args)
        new_args.extend(['-f', self.pwd_file])
        # When certutil makes a request it creates a file in the cwd, make
        # sure we are in a unique place when this happens.
        return ipautil.run(new_args, stdin, cwd=self.secdir, **kwargs)

    def run_pk12util(self, args, stdin=None, **kwargs):
        self._check_db()
        new_args = [
            paths.PK12UTIL,
            "-d", '{}:{}'.format(self.dbtype, self.secdir)
        ]
        new_args.extend(args)
        return ipautil.run(new_args, stdin, **kwargs)

    def exists(self):
        """Check DB exists (all files are present)
        """
        if self.filenames is None:
            return False
        return all(os.path.isfile(filename) for filename in self.filenames)

    def create_db(self, user=None, group=None, mode=None, backup=False):
        """Create cert DB

        :param user: User owner the secdir
        :param group: Group owner of the secdir
        :param mode: Mode of the secdir
        :param backup: Backup the sedir files
        """
        if mode is not None:
            dirmode = mode
            filemode = mode & 0o666
            pwdfilemode = mode & 0o660
        else:
            dirmode = 0o750
            filemode = 0o640
            pwdfilemode = 0o640

        uid = -1
        gid = -1
        if user is not None:
            uid = pwd.getpwnam(user).pw_uid
        if group is not None:
            gid = grp.getgrnam(group).gr_gid

        if backup:
            for filename in self.backup_filenames:
                ipautil.backup_file(filename)

        if not os.path.exists(self.secdir):
            os.makedirs(self.secdir, dirmode)

        if not os.path.exists(self.pwd_file):
            # Create the password file for this db
            with io.open(os.open(self.pwd_file,
                                 os.O_CREAT | os.O_WRONLY,
                                 pwdfilemode), 'w', closefd=True) as f:
                f.write(ipautil.ipa_generate_password())
                # flush and sync tempfile inode
                f.flush()
                os.fsync(f.fileno())

        # In case dbtype is auto, let certutil decide which type of DB
        # to create.
        if self.dbtype == 'auto':
            dbdir = self.secdir
        else:
            dbdir = '{}:{}'.format(self.dbtype, self.secdir)
        args = [
            paths.CERTUTIL,
            '-d', dbdir,
            '-N',
            '-f', self.pwd_file,
            # -@ in case it's an old db and it must be migrated
            '-@', self.pwd_file,
        ]
        ipautil.run(args, stdin=None, cwd=self.secdir)
        self._set_filenames(self._detect_dbtype())
        if self.filenames is None:
            # something went wrong...
            raise ValueError(
                "Failed to create NSSDB at '{}'".format(self.secdir)
            )

        # Finally fix up perms
        os.chown(self.secdir, uid, gid)
        os.chmod(self.secdir, dirmode)
        tasks.restore_context(self.secdir, force=True)
        for filename in self.filenames:
            if os.path.exists(filename):
                os.chown(filename, uid, gid)
                if filename == self.pwd_file:
                    new_mode = pwdfilemode
                else:
                    new_mode = filemode
                os.chmod(filename, new_mode)
                tasks.restore_context(filename, force=True)

    def convert_db(self, rename_old=True):
        """Convert DBM database format to SQL database format

        **WARNING** **WARNING** **WARNING** **WARNING** **WARNING**

        The caller must ensure that no other process or service is
        accessing the NSSDB during migration. The DBM format does not support
        multiple processes. If more than one process opens a DBM NSSDB for
        writing, the database will become **irreparably corrupted**.

        **WARNING** **WARNING** **WARNING** **WARNING** **WARNING**
        """
        if (self.dbtype == 'sql' or
                os.path.isfile(os.path.join(self.secdir, "cert9.db"))):
            raise ValueError(
                'NSS DB {} has been migrated already.'.format(self.secdir)
            )

        # use certutil to migrate db to new format
        # see https://bugzilla.mozilla.org/show_bug.cgi?id=1415912
        # https://fedoraproject.org/wiki/Changes/NSSDefaultFileFormatSql
        args = [
            paths.CERTUTIL,
            '-d', 'sql:{}'.format(self.secdir), '-N',
            '-f', self.pwd_file, '-@', self.pwd_file
        ]
        ipautil.run(args, stdin=None, cwd=self.secdir)

        # retain file ownership and permission, backup old files
        migration = (
            ('cert8.db', 'cert9.db'),
            ('key3.db', 'key4.db'),
            ('secmod.db', 'pkcs11.txt'),
        )
        for oldname, newname in migration:
            oldname = os.path.join(self.secdir, oldname)
            newname = os.path.join(self.secdir, newname)
            oldstat = os.stat(oldname)
            os.chmod(newname, stat.S_IMODE(oldstat.st_mode))
            os.chown(newname, oldstat.st_uid, oldstat.st_gid)
            tasks.restore_context(newname, force=True)

        self._set_filenames('sql')
        self.list_certs()  # self-test

        if rename_old:
            for oldname, _ in migration:  # pylint: disable=unused-variable
                oldname = os.path.join(self.secdir, oldname)
                os.rename(oldname, oldname + '.migrated')

    def restore(self):
        for filename in self.backup_filenames:
            backup_path = filename + '.orig'
            save_path = filename + '.ipasave'
            try:
                if os.path.exists(filename):
                    os.rename(filename, save_path)
                if os.path.exists(backup_path):
                    os.rename(backup_path, filename)
            except OSError as e:
                logger.debug('%s', e)

    def list_certs(self):
        """Return nicknames and cert flags for all certs in the database

        :return: List of (name, trust_flags) tuples
        """
        result = self.run_certutil(["-L"], capture_output=True)
        certs = result.output.splitlines()

        # FIXME, this relies on NSS never changing the formatting of certutil
        certlist = []
        for cert in certs:
            match = re.match(r'^(.+?)\s+(\w*,\w*,\w*)\s*$', cert)
            if match:
                nickname = match.group(1)
                trust_flags = parse_trust_flags(match.group(2))
                certlist.append((nickname, trust_flags))

        return tuple(certlist)

    def list_keys(self):
        result = self.run_certutil(
            ["-K"], raiseonerr=False,  capture_output=True
        )
        if result.returncode == 255:
            return ()
        keylist = []
        for line in result.output.splitlines():
            mo = re.match(r'^<\s*(\d+)>\s+(\w+)\s+([0-9a-z]+)\s+(.*)$', line)
            if mo is not None:
                slot, algo, keyid, nick = mo.groups()
                keylist.append((int(slot), algo, keyid, nick.strip()))
        return tuple(keylist)

    def find_server_certs(self):
        """Return nicknames and cert flags for server certs in the database

        Server certs have an "u" character in the trust flags.

        :return: List of (name, trust_flags) tuples
        """
        server_certs = []
        for name, flags in self.list_certs():
            if flags.has_key:
                server_certs.append((name, flags))

        return server_certs

    def get_trust_chain(self, nickname):
        """Return names of certs in a given cert's trust chain

        :param nickname: Name of the cert
        :return: List of certificate names
        """
        root_nicknames = []
        result = self.run_certutil(["-O", "-n", nickname], capture_output=True)
        chain = result.output.splitlines()

        for c in chain:
            m = re.match('\s*"(.*)" \[.*', c)
            if m:
                root_nicknames.append(m.groups()[0])

        return root_nicknames

    def export_pkcs12(self, nickname, pkcs12_filename, pkcs12_passwd=None):
        args = [
            "-o", pkcs12_filename,
            "-n", nickname,
            "-k", self.pwd_file
        ]
        pkcs12_password_file = None
        if pkcs12_passwd is not None:
            pkcs12_password_file = ipautil.write_tmp_file(pkcs12_passwd + '\n')
            args.extend(["-w", pkcs12_password_file.name])
        try:
            self.run_pk12util(args)
        except ipautil.CalledProcessError as e:
            if e.returncode == 17:
                raise RuntimeError("incorrect password for pkcs#12 file %s" %
                                   pkcs12_filename)
            elif e.returncode == 10:
                raise RuntimeError("Failed to open %s" % pkcs12_filename)
            else:
                raise RuntimeError("unknown error exporting pkcs#12 file %s" %
                                   pkcs12_filename)
        finally:
            if pkcs12_password_file is not None:
                pkcs12_password_file.close()

    def import_pkcs12(self, pkcs12_filename, pkcs12_passwd=None):
        args = [
            "-i", pkcs12_filename,
            "-k", self.pwd_file,
            "-v"
        ]
        pkcs12_password_file = None
        if pkcs12_passwd is not None:
            pkcs12_password_file = ipautil.write_tmp_file(pkcs12_passwd + '\n')
            args.extend(["-w", pkcs12_password_file.name])
        try:
            self.run_pk12util(args)
        except ipautil.CalledProcessError as e:
            if e.returncode == 17 or e.returncode == 18:
                raise Pkcs12ImportIncorrectPasswordError(
                    "incorrect password for pkcs#12 file %s" % pkcs12_filename)
            elif e.returncode == 10:
                raise Pkcs12ImportOpenError(
                    "Failed to open %s" % pkcs12_filename)
            else:
                raise Pkcs12ImportUnknownError(
                    "unknown error import pkcs#12 file %s" %
                    pkcs12_filename)
        finally:
            if pkcs12_password_file is not None:
                pkcs12_password_file.close()

    def import_files(self, files, import_keys=False, key_password=None,
                     key_nickname=None):
        """
        Import certificates and a single private key from multiple files

        The files may be in PEM and DER certificate, PKCS#7 certificate chain,
        PKCS#8 and raw private key and PKCS#12 formats.

        :param files: Names of files to import
        :param import_keys: Whether to import private keys
        :param key_password: Password to decrypt private keys
        :param key_nickname: Nickname of the private key to import from PKCS#12
            files
        """
        key_file = None
        extracted_key = None
        extracted_certs = []

        for filename in files:
            try:
                with open(filename, 'rb') as f:
                    data = f.read()
            except IOError as e:
                raise RuntimeError(
                    "Failed to open %s: %s" % (filename, e.strerror))

            # Try to parse the file as PEM file
            matches = list(
                re.finditer(
                    br'-----BEGIN (.+?)-----(.*?)-----END \1-----',
                    data, re.DOTALL
                )
            )
            if matches:
                loaded = False
                for match in matches:
                    body = match.group()
                    label = match.group(1)
                    line = len(data[:match.start() + 1].splitlines())

                    if label in (b'CERTIFICATE', b'X509 CERTIFICATE',
                                 b'X.509 CERTIFICATE'):
                        try:
                            cert = x509.load_pem_x509_certificate(body)
                        except ValueError as e:
                            if label != b'CERTIFICATE':
                                logger.warning(
                                    "Skipping certificate in %s at line %s: "
                                    "%s",
                                    filename, line, e)
                                continue
                        else:
                            extracted_certs.append(cert)
                            loaded = True
                            continue

                    if label in (b'PKCS7', b'PKCS #7 SIGNED DATA',
                                 b'CERTIFICATE'):
                        try:
                            certs = x509.pkcs7_to_certs(body)
                        except ipautil.CalledProcessError as e:
                            if label == b'CERTIFICATE':
                                logger.warning(
                                    "Skipping certificate in %s at line %s: "
                                    "%s",
                                    filename, line, e)
                            else:
                                logger.warning(
                                    "Skipping PKCS#7 in %s at line %s: %s",
                                    filename, line, e)
                            continue
                        else:
                            extracted_certs.extend(certs)
                            loaded = True
                            continue

                    if label in (b'PRIVATE KEY', b'ENCRYPTED PRIVATE KEY',
                                 b'RSA PRIVATE KEY', b'DSA PRIVATE KEY',
                                 b'EC PRIVATE KEY'):
                        if not import_keys:
                            continue

                        if key_file:
                            raise RuntimeError(
                                "Can't load private key from both %s and %s" %
                                (key_file, filename))

                        # the args -v2 aes256 -v2prf hmacWithSHA256 are needed
                        # on OpenSSL 1.0.2 (fips mode). As soon as FreeIPA
                        # requires OpenSSL 1.1.0 we'll be able to drop them
                        args = [
                            paths.OPENSSL, 'pkcs8',
                            '-topk8',
                            '-v2', 'aes256', '-v2prf', 'hmacWithSHA256',
                            '-passout', 'file:' + self.pwd_file,
                        ]
                        if ((label != b'PRIVATE KEY' and key_password) or
                                label == b'ENCRYPTED PRIVATE KEY'):
                            key_pwdfile = ipautil.write_tmp_file(key_password)
                            args += [
                                '-passin', 'file:' + key_pwdfile.name,
                            ]
                        try:
                            result = ipautil.run(
                                args, stdin=body, capture_output=True)
                        except ipautil.CalledProcessError as e:
                            logger.warning(
                                "Skipping private key in %s at line %s: %s",
                                filename, line, e)
                            continue
                        else:
                            extracted_key = result.raw_output
                            key_file = filename
                            loaded = True
                            continue
                if loaded:
                    continue
                raise RuntimeError("Failed to load %s" % filename)

            # Try to load the file as DER certificate
            try:
                cert = x509.load_der_x509_certificate(data)
            except ValueError:
                pass
            else:
                extracted_certs.append(cert)
                continue

            # Try to import the file as PKCS#12 file
            if import_keys:
                try:
                    self.import_pkcs12(filename, key_password)
                except Pkcs12ImportUnknownError:
                    # the file may not be a PKCS#12 file,
                    # go to the generic error about unrecognized format
                    pass
                except RuntimeError as e:
                    raise RuntimeError("Failed to load %s: %s" %
                                       (filename, str(e)))
                else:
                    if key_file:
                        raise RuntimeError(
                            "Can't load private key from both %s and %s" %
                            (key_file, filename))
                    key_file = filename

                    server_certs = self.find_server_certs()
                    if key_nickname:
                        for nickname, _trust_flags in server_certs:
                            if nickname == key_nickname:
                                break
                        else:
                            raise RuntimeError(
                                "Server certificate \"%s\" not found in %s" %
                                (key_nickname, filename))
                    else:
                        if len(server_certs) > 1:
                            raise RuntimeError(
                                "%s server certificates found in %s, "
                                "expecting only one" %
                                (len(server_certs), filename))

                    continue

            # Supported formats were tried but none succeeded
            raise RuntimeError("Failed to load %s: unrecognized format" %
                               filename)

        if import_keys and not key_file:
            raise RuntimeError(
                "No server certificates found in %s" % (', '.join(files)))

        for cert in extracted_certs:
            nickname = str(DN(cert.subject))
            self.add_cert(cert, nickname, EMPTY_TRUST_FLAGS)

        if extracted_key:
            with tempfile.NamedTemporaryFile() as in_file, \
                    tempfile.NamedTemporaryFile() as out_file:
                for cert in extracted_certs:
                    in_file.write(cert.public_bytes(x509.Encoding.PEM))
                in_file.write(extracted_key)
                in_file.flush()
                out_password = ipautil.ipa_generate_password()
                out_pwdfile = ipautil.write_tmp_file(out_password)
                args = [
                    paths.OPENSSL, 'pkcs12',
                    '-export',
                    '-in', in_file.name,
                    '-out', out_file.name,
                    '-passin', 'file:' + self.pwd_file,
                    '-passout', 'file:' + out_pwdfile.name,
                ]
                try:
                    ipautil.run(args)
                except ipautil.CalledProcessError as e:
                    raise RuntimeError(
                        "No matching certificate found for private key from "
                        "%s" % key_file)

                self.import_pkcs12(out_file.name, out_password)

    def trust_root_cert(self, root_nickname, trust_flags):
        if root_nickname[:7] == "Builtin":
            logger.debug(
                "No need to add trust for built-in root CAs, skipping %s",
                root_nickname)
        else:
            trust_flags = unparse_trust_flags(trust_flags)
            try:
                self.run_certutil(["-M", "-n", root_nickname,
                                   "-t", trust_flags])
            except ipautil.CalledProcessError:
                raise RuntimeError(
                    "Setting trust on %s failed" % root_nickname)

    def get_cert(self, nickname):
        """
        :param nickname: nickname of the certificate in the NSS database
        :returns: string in Python2
                  bytes in Python3
        """
        args = ['-L', '-n', nickname, '-a']
        try:
            result = self.run_certutil(args, capture_output=True)
        except ipautil.CalledProcessError:
            raise RuntimeError("Failed to get %s" % nickname)
        cert, _start = find_cert_from_txt(result.output, start=0)
        return cert

    def has_nickname(self, nickname):
        try:
            self.get_cert(nickname)
        except RuntimeError:
            # This might be error other than "nickname not found". Beware.
            return False
        else:
            return True

    def export_pem_cert(self, nickname, location):
        """Export the given cert to PEM file in the given location"""
        cert = self.get_cert(nickname)
        with open(location, "wb") as fd:
            fd.write(cert.public_bytes(x509.Encoding.PEM))
        os.chmod(location, 0o444)

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
        self.add_cert(cert, nickname, flags)

        try:
            find_cert_from_txt(certs, st)
        except RuntimeError:
            pass
        else:
            raise ValueError('%s contains more than one certificate' %
                             location)

    def add_cert(self, cert, nick, flags):
        flags = unparse_trust_flags(flags)
        args = ["-A", "-n", nick, "-t", flags, '-a']
        self.run_certutil(args, stdin=cert.public_bytes(x509.Encoding.PEM))

    def delete_cert(self, nick):
        self.run_certutil(["-D", "-n", nick])

    def verify_server_cert_validity(self, nickname, hostname):
        """Verify a certificate is valid for a SSL server with given hostname

        Raises a ValueError if the certificate is invalid.
        """
        cert = self.get_cert(nickname)

        try:
            self.run_certutil(['-V', '-n', nickname, '-u', 'V'],
                              capture_output=True)
        except ipautil.CalledProcessError as e:
            # certutil output in case of error is
            # 'certutil: certificate is invalid: <ERROR_STRING>\n'
            raise ValueError(e.output)

        try:
            cert.match_hostname(hostname)
        except ValueError:
            raise ValueError('invalid for server %s' % hostname)

    def verify_ca_cert_validity(self, nickname):
        cert = self.get_cert(nickname)

        if not cert.subject:
            raise ValueError("has empty subject")

        try:
            bc = cert.extensions.get_extension_for_class(
                    cryptography.x509.BasicConstraints)
        except cryptography.x509.ExtensionNotFound:
            raise ValueError("missing basic constraints")

        if not bc.value.ca:
            raise ValueError("not a CA certificate")

        try:
            ski = cert.extensions.get_extension_for_class(
                    cryptography.x509.SubjectKeyIdentifier)
        except cryptography.x509.ExtensionNotFound:
            raise ValueError("missing subject key identifier extension")
        else:
            if len(ski.value.digest) == 0:
                raise ValueError("subject key identifier must not be empty")

        try:
            self.run_certutil(
                [
                    '-V',       # check validity of cert and attrs
                    '-n', nickname,
                    '-u', 'L',  # usage; 'L' means "SSL CA"
                    '-e',       # check signature(s); this checks
                                # key sizes, sig algorithm, etc.
                ],
                capture_output=True)
        except ipautil.CalledProcessError as e:
            # certutil output in case of error is
            # 'certutil: certificate is invalid: <ERROR_STRING>\n'
            raise ValueError(e.output)

    def verify_kdc_cert_validity(self, nickname, realm):
        nicknames = self.get_trust_chain(nickname)
        certs = [self.get_cert(nickname) for nickname in nicknames]

        verify_kdc_cert_validity(certs[-1], certs[:-1], realm)
