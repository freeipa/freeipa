# Copyright (C) 2015  IPA Project Contributors, see COPYING for license

from __future__ import print_function, absolute_import
from base64 import b64encode, b64decode
from custodia.store.interface import CSStore  # pylint: disable=relative-import
from jwcrypto.common import json_decode, json_encode
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.certdb import NSSDatabase
from ipaserver.secrets.common import iSecLdap
import ldap
import os
import shutil
import sys
import tempfile


class UnknownKeyName(Exception):
    pass


class DBMAPHandler:

    def __init__(self, config, dbmap, nickname):
        raise NotImplementedError

    def export_key(self):
        raise NotImplementedError

    def import_key(self, value):
        raise NotImplementedError


def log_error(error):
    print(error, file=sys.stderr)


class NSSWrappedCertDB(DBMAPHandler):
    '''
    Store that extracts private keys from an NSSDB, wrapped with the
    private key of the primary CA.
    '''

    def __init__(self, config, dbmap, nickname):
        if 'path' not in dbmap:
            raise ValueError(
                'Configuration does not provide NSSDB path')
        if 'pwdfile' not in dbmap:
            raise ValueError('Configuration does not provide password file')
        if 'wrap_nick' not in dbmap:
            raise ValueError(
                'Configuration does not provide nickname of wrapping key')
        self.nssdb_path = dbmap['path']
        self.nssdb_pwdfile = dbmap['pwdfile']
        self.wrap_nick = dbmap['wrap_nick']
        self.target_nick = nickname

    def export_key(self):
        tdir = tempfile.mkdtemp(dir=paths.TMP)
        try:
            wrapped_key_file = os.path.join(tdir, 'wrapped_key')
            certificate_file = os.path.join(tdir, 'certificate')
            ipautil.run([
                paths.PKI, '-d', self.nssdb_path, '-C', self.nssdb_pwdfile,
                'ca-authority-key-export',
                '--wrap-nickname', self.wrap_nick,
                '--target-nickname', self.target_nick,
                '-o', wrapped_key_file])
            nssdb = NSSDatabase(self.nssdb_path)
            nssdb.run_certutil([
                '-L', '-n', self.target_nick,
                '-a', '-o', certificate_file,
            ])
            with open(wrapped_key_file, 'rb') as f:
                wrapped_key = f.read()
            with open(certificate_file, 'r') as f:
                certificate = f.read()
        finally:
            shutil.rmtree(tdir)
        return json_encode({
            'wrapped_key': b64encode(wrapped_key).decode('ascii'),
            'certificate': certificate})


class NSSCertDB(DBMAPHandler):

    def __init__(self, config, dbmap, nickname):
        if 'type' not in dbmap or dbmap['type'] != 'NSSDB':
            raise ValueError('Invalid type "%s",'
                             ' expected "NSSDB"' % (dbmap['type'],))
        if 'path' not in dbmap:
            raise ValueError('Configuration does not provide NSSDB path')
        if 'pwdfile' not in dbmap:
            raise ValueError('Configuration does not provide password file')
        self.nssdb_path = dbmap['path']
        self.nssdb_pwdfile = dbmap['pwdfile']
        self.nickname = nickname

    def export_key(self):
        tdir = tempfile.mkdtemp(dir=paths.TMP)
        try:
            pk12pwfile = os.path.join(tdir, 'pk12pwfile')
            password = ipautil.ipa_generate_password()
            with open(pk12pwfile, 'w') as f:
                f.write(password)
            pk12file = os.path.join(tdir, 'pk12file')
            nssdb = NSSDatabase(self.nssdb_path)
            nssdb.run_pk12util([
                "-o", pk12file,
                "-n", self.nickname,
                "-k", self.nssdb_pwdfile,
                "-w", pk12pwfile,
            ])
            with open(pk12file, 'rb') as f:
                data = f.read()
        finally:
            shutil.rmtree(tdir)
        return json_encode({'export password': password,
                            'pkcs12 data': b64encode(data).decode('ascii')})

    def import_key(self, value):
        v = json_decode(value)
        tdir = tempfile.mkdtemp(dir=paths.TMP)
        try:
            pk12pwfile = os.path.join(tdir, 'pk12pwfile')
            with open(pk12pwfile, 'w') as f:
                f.write(v['export password'])
            pk12file = os.path.join(tdir, 'pk12file')
            with open(pk12file, 'wb') as f:
                f.write(b64decode(v['pkcs12 data']))
            nssdb = NSSDatabase(self.nssdb_path)
            nssdb.run_pk12util([
                "-i", pk12file,
                "-n", self.nickname,
                "-k", self.nssdb_pwdfile,
                "-w", pk12pwfile,
            ])
        finally:
            shutil.rmtree(tdir)


# Exfiltrate the DM password Hash so it can be set in replica's and this
# way let a replica be install without knowing the DM password and yet
# still keep the DM password synchronized across replicas
class DMLDAP(DBMAPHandler):

    def __init__(self, config, dbmap, nickname):
        if 'type' not in dbmap or dbmap['type'] != 'DMLDAP':
            raise ValueError('Invalid type "%s",'
                             ' expected "DMLDAP"' % (dbmap['type'],))
        if nickname != 'DMHash':
            raise UnknownKeyName("Unknown Key Named '%s'" % nickname)
        self.ldap = iSecLdap(config['ldap_uri'],
                             config.get('auth_type', None))

    def export_key(self):
        conn = self.ldap.connect()
        r = conn.search_s('cn=config', ldap.SCOPE_BASE,
                          attrlist=['nsslapd-rootpw'])
        if len(r) != 1:
            raise RuntimeError('DM Hash not found!')
        rootpw = r[0][1]['nsslapd-rootpw'][0]
        return json_encode({'dmhash': rootpw.decode('ascii')})

    def import_key(self, value):
        v = json_decode(value)
        rootpw = v['dmhash'].encode('ascii')
        conn = self.ldap.connect()
        mods = [(ldap.MOD_REPLACE, 'nsslapd-rootpw', rootpw)]
        conn.modify_s('cn=config', mods)


class PEMFileHandler(DBMAPHandler):
    def __init__(self, config, dbmap, nickname=None):
        if 'type' not in dbmap or dbmap['type'] != 'PEM':
            raise ValueError('Invalid type "{t}", expected PEM'
                             .format(t=dbmap['type']))
        self.certfile = dbmap['certfile']
        self.keyfile = dbmap.get('keyfile')

    def export_key(self):
        _fd, tmpfile = tempfile.mkstemp(dir=paths.TMP)
        password = ipautil.ipa_generate_password()
        args = [
            paths.OPENSSL,
            "pkcs12", "-export",
            "-in", self.certfile,
            "-out", tmpfile,
            "-password", "pass:{pwd}".format(pwd=password)
        ]
        if self.keyfile is not None:
            args.extend(["-inkey", self.keyfile])

        try:
            ipautil.run(args, nolog=(password, ))
            with open(tmpfile, 'rb') as f:
                data = f.read()
        finally:
            os.remove(tmpfile)
        return json_encode({'export password': password,
                            'pkcs12 data': b64encode(data).decode('ascii')})

    def import_key(self, value):
        v = json_decode(value)
        data = b64decode(v['pkcs12 data'])
        password = v['export password']
        fd, tmpdata = tempfile.mkstemp(dir=paths.TMP)
        os.close(fd)
        try:
            with open(tmpdata, 'wb') as f:
                f.write(data)

            # get the certificate from the file
            ipautil.run([paths.OPENSSL,
                         "pkcs12",
                         "-in", tmpdata,
                         "-clcerts", "-nokeys",
                         "-out", self.certfile,
                         "-passin", "pass:{pwd}".format(pwd=password)],
                        nolog=(password, ))

            if self.keyfile is not None:
                # get the private key from the file
                ipautil.run([paths.OPENSSL,
                             "pkcs12",
                             "-in", tmpdata,
                             "-nocerts", "-nodes",
                             "-out", self.keyfile,
                             "-passin", "pass:{pwd}".format(pwd=password)],
                            nolog=(password, ))
        finally:
            os.remove(tmpdata)


NAME_DB_MAP = {
    'ca': {
        'type': 'NSSDB',
        'path': paths.PKI_TOMCAT_ALIAS_DIR,
        'handler': NSSCertDB,
        'pwdfile': paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
    },
    'ca_wrapped': {
        'handler': NSSWrappedCertDB,
        'path': paths.PKI_TOMCAT_ALIAS_DIR,
        'pwdfile': paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
        'wrap_nick': 'caSigningCert cert-pki-ca',
    },
    'ra': {
        'type': 'PEM',
        'handler': PEMFileHandler,
        'certfile': paths.RA_AGENT_PEM,
        'keyfile': paths.RA_AGENT_KEY,
    },
    'dm': {
        'type': 'DMLDAP',
        'handler': DMLDAP,
    }
}


class IPASecStore(CSStore):

    def __init__(self, config=None):
        self.config = config

    def _get_handler(self, key):
        path = key.split('/', 3)
        if len(path) != 3 or path[0] != 'keys':
            raise ValueError('Invalid name')
        if path[1] not in NAME_DB_MAP:
            raise UnknownKeyName("Unknown DB named '%s'" % path[1])
        dbmap = NAME_DB_MAP[path[1]]
        return dbmap['handler'](self.config, dbmap, path[2])

    def get(self, key):
        try:
            key_handler = self._get_handler(key)
            value = key_handler.export_key()
        except Exception as e:  # pylint: disable=broad-except
            log_error('Error retrieving key "%s": %s' % (key, str(e)))
            value = None
        return value

    def set(self, key, value, replace=False):
        try:
            key_handler = self._get_handler(key)
            key_handler.import_key(value)
        except Exception as e:  # pylint: disable=broad-except
            log_error('Error storing key "%s": %s' % (key, str(e)))

    def list(self, keyfilter=None):
        raise NotImplementedError

    def cut(self, key):
        raise NotImplementedError

    def span(self, key):
        raise NotImplementedError


# backwards compatibility with FreeIPA 4.3 and 4.4.
iSecStore = IPASecStore
