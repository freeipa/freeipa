# Copyright (C) 2015  IPA Project Contributors, see COPYING for license

from __future__ import print_function, absolute_import
import os
import sys

from custodia.plugin import CSStore

from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipapython import ipautil


class UnknownKeyName(Exception):
    pass


class InvalidKeyArguments(Exception):
    pass


class DBMAPHandler:
    dbtype = None
    supports_extra_args = False

    def __init__(self, config, dbmap, nickname):
        dbtype = dbmap.get('type')
        if dbtype is None or dbtype != self.dbtype:
            raise ValueError(
                "Invalid type '{}', expected '{}'".format(
                    dbtype, self.dbtype
                )
            )
        self.config = config
        self.dbmap = dbmap
        self.nickname = nickname

    def export_key(self):
        raise NotImplementedError

    def import_key(self, value):
        raise NotImplementedError


class DBMAPCommandHandler(DBMAPHandler):
    def __init__(self, config, dbmap, nickname):
        super().__init__(config, dbmap, nickname)
        self.runas = dbmap.get('runas')
        self.command = os.path.join(
            paths.IPA_CUSTODIA_HANDLER,
            dbmap['command']
        )

    def run_handler(self, extra_args=(), stdin=None):
        """Run handler script to export / import key material
        """
        args = [self.command]
        args.extend(extra_args)
        kwargs = dict(
            runas=self.runas,
            encoding='utf-8',
        )

        if stdin:
            args.extend(['--import', '-'])
            kwargs.update(stdin=stdin)
        else:
            args.extend(['--export', '-'])
            kwargs.update(capture_output=True)

        result = ipautil.run(args, **kwargs)

        if stdin is None:
            return result.output
        else:
            return None


def log_error(error):
    print(error, file=sys.stderr)


class NSSWrappedCertDB(DBMAPCommandHandler):
    """
    Store that extracts private keys from an NSSDB, wrapped with the
    private key of the primary CA.
    """
    dbtype = 'NSSDB'
    supports_extra_args = True

    OID_DES_EDE3_CBC = '1.2.840.113549.3.7'

    def __init__(self, config, dbmap, nickname, *extra_args):
        super().__init__(config, dbmap, nickname)

        # Extra args is either a single OID specifying desired wrap
        # algorithm, or empty.  If empty, we must assume that the
        # client is an old version that only supports DES-EDE3-CBC.
        #
        # Using either the client's requested algorithm or the
        # default of DES-EDE3-CBC, we pass it along to the handler
        # via the --algorithm option.  The handler, in turn, passes
        # it along to the 'pki ca-authority-key-export' program
        # (which is part of Dogtag).
        #
        if len(extra_args) > 1:
            raise InvalidKeyArguments("Too many arguments")
        if len(extra_args) == 1:
            self.alg = extra_args[0]
        else:
            self.alg = self.OID_DES_EDE3_CBC

    def export_key(self):
        return self.run_handler([
            '--nickname', self.nickname,
            '--algorithm', self.alg,
        ])


class NSSCertDB(DBMAPCommandHandler):
    dbtype = 'NSSDB'

    def export_key(self):
        return self.run_handler(['--nickname', self.nickname])

    def import_key(self, value):
        return self.run_handler(
            ['--nickname', self.nickname],
            stdin=value
        )


# Exfiltrate the DM password Hash so it can be set in replica's and this
# way let a replica be install without knowing the DM password and yet
# still keep the DM password synchronized across replicas
class DMLDAP(DBMAPCommandHandler):
    dbtype = 'DMLDAP'

    def __init__(self, config, dbmap, nickname):
        super().__init__(config, dbmap, nickname)
        if nickname != 'DMHash':
            raise UnknownKeyName("Unknown Key Named '%s'" % nickname)

    def export_key(self):
        return self.run_handler()

    def import_key(self, value):
        self.run_handler(stdin=value)


class PEMFileHandler(DBMAPCommandHandler):
    dbtype = 'PEM'

    def export_key(self):
        return self.run_handler()

    def import_key(self, value):
        return self.run_handler(stdin=value)


NAME_DB_MAP = {
    'ca': {
        'type': 'NSSDB',
        'handler': NSSCertDB,
        'command': 'ipa-custodia-pki-tomcat',
        'runas': constants.PKI_USER,
    },
    'ca_wrapped': {
        'type': 'NSSDB',
        'handler': NSSWrappedCertDB,
        'command': 'ipa-custodia-pki-tomcat-wrapped',
        'runas': constants.PKI_USER,
    },
    'ra': {
        'type': 'PEM',
        'handler': PEMFileHandler,
        'command': 'ipa-custodia-ra-agent',
        'runas': None,  # import needs root permission to write to directory
    },
    'dm': {
        'type': 'DMLDAP',
        'handler': DMLDAP,
        'command': 'ipa-custodia-dmldap',
        'runas': None,  # root
    }
}


class IPASecStore(CSStore):

    def __init__(self, config=None):
        self.config = config

    def _get_handler(self, key):
        path = key.split('/', 3)
        if len(path) < 3 or path[0] != 'keys':
            raise ValueError('Invalid name')
        if path[1] not in NAME_DB_MAP:
            raise UnknownKeyName("Unknown DB named '%s'" % path[1])
        dbmap = NAME_DB_MAP[path[1]]
        handler = dbmap['handler']
        if len(path) > 3 and not handler.supports_extra_args:
            raise InvalidKeyArguments('Handler does not support extra args')
        return handler(self.config, dbmap, path[2], *path[3:])

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
