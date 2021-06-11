# Copyright (C) 2016  Custodia Project Contributors - see LICENSE file
"""FreeIPA vault store (PoC)
"""
from __future__ import absolute_import

from ipalib.errors import AuthorizationError, DuplicateEntry, NotFound

import six

from custodia.plugin import CSStore, PluginOption
from custodia.plugin import (
    CSStoreDenied, CSStoreError, CSStoreExists, CSStoreUnsupported
)

from .interface import IPAInterface


def krb5_unparse_principal_name(name):
    """Split a Kerberos principal name into parts

    Returns:
       * ('host', hostname, realm) for a host principal
       * (servicename, hostname, realm) for a service principal
       * (None, username, realm) for a user principal

    :param text name: Kerberos principal name
    :return: (service, host, realm) or (None, username, realm)
    """
    prefix, realm = name.split(u'@')
    if u'/' in prefix:
        service, host = prefix.rsplit(u'/', 1)
        return service, host, realm
    else:
        return None, prefix, realm


class IPAVault(CSStore):
    # vault arguments
    principal = PluginOption(
        str, None,
        "Service principal for service vault (auto-discovered from GSSAPI)"
    )
    user = PluginOption(
        str, None,
        "User name for user vault (auto-discovered from GSSAPI)"
    )
    vault_type = PluginOption(
        str, None,
        "vault type, one of 'user', 'service', 'shared', or "
        "auto-discovered from GSSAPI"
    )

    def __init__(self, config, section=None, api=None):
        super(IPAVault, self).__init__(config, section)
        self._vault_args = None
        self.ipa = None

    def finalize_init(self, config, cfgparser, context=None):
        super(IPAVault, self).finalize_init(config, cfgparser, context)

        if self.ipa is not None:
            return
        self.ipa = IPAInterface.from_config(config)
        self.ipa.finalize_init(config, cfgparser, context=self)

        # connect
        with self.ipa:
            # retrieve and cache KRA transport cert
            response = self.ipa.Command.vaultconfig_show()
            servers = response[u'result'].get(u'kra_server_server', ())
            if servers:
                self.logger.info("KRA server(s) %s", ', '.join(servers))

        service, user_host, realm = krb5_unparse_principal_name(
            self.ipa.principal)
        self._init_vault_args(service, user_host, realm)

    def _init_vault_args(self, service, user_host, realm):
        if self.vault_type is None:
            self.vault_type = 'user' if service is None else 'service'
            self.logger.info("Setting vault type to '%s' from Kerberos",
                             self.vault_type)

        if self.vault_type == 'shared':
            self._vault_args = {'shared': True}
        elif self.vault_type == 'user':
            if self.user is None:
                if service is not None:
                    msg = "{!r}: User vault requires 'user' parameter"
                    raise ValueError(msg.format(self))
                else:
                    self.user = user_host
                    self.logger.info(u"Setting username '%s' from Kerberos",
                                     self.user)
            if six.PY2 and isinstance(self.user, str):
                self.user = self.user.decode('utf-8')
            self._vault_args = {'username': self.user}
        elif self.vault_type == 'service':
            if self.principal is None:
                if service is None:
                    msg = "{!r}: Service vault requires 'principal' parameter"
                    raise ValueError(msg.format(self))
                else:
                    self.principal = u'/'.join((service, user_host))
                    self.logger.info(u"Setting principal '%s' from Kerberos",
                                     self.principal)
            if six.PY2 and isinstance(self.principal, str):
                self.principal = self.principal.decode('utf-8')
            self._vault_args = {'service': self.principal}
        else:
            msg = '{!r}: Invalid vault type {}'
            raise ValueError(msg.format(self, self.vault_type))

    def _mangle_key(self, key):
        if '__' in key:
            raise ValueError
        key = key.replace('/', '__')
        if isinstance(key, bytes):
            key = key.decode('utf-8')
        return key

    def get(self, key):
        key = self._mangle_key(key)
        with self.ipa as ipa:
            try:
                result = ipa.Command.vault_retrieve(
                    key, **self._vault_args)
            except NotFound as e:
                self.logger.info("Key '%s' not found: %s", key, e)
                return None
            except Exception:
                msg = "Failed to retrieve entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreError(msg)
            else:
                return result[u'result'][u'data']

    def set(self, key, value, replace=False):
        key = self._mangle_key(key)
        if not isinstance(value, bytes):
            value = value.encode('utf-8')
        with self.ipa as ipa:
            try:
                ipa.Command.vault_add(
                    key, ipavaulttype=u"standard", **self._vault_args)
            except DuplicateEntry as e:
                self.logger.info("Vault '%s' already exists: %s", key, e)
                if not replace:
                    raise CSStoreExists(key)
            except AuthorizationError:
                msg = "vault_add denied for entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreDenied(msg)
            except Exception:
                msg = "Failed to add entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreError(msg)
            try:
                ipa.Command.vault_archive(
                    key, data=value, **self._vault_args)
            except AuthorizationError:
                msg = "vault_archive denied for entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreDenied(msg)
            except Exception:
                msg = "Failed to archive entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreError(msg)

    def span(self, key):
        raise CSStoreUnsupported("span is not implemented")

    def list(self, keyfilter=None):
        with self.ipa as ipa:
            try:
                result = ipa.Command.vault_find(
                    ipavaulttype=u"standard", **self._vault_args)
            except AuthorizationError:
                msg = "vault_find denied"
                self.logger.exception(msg)
                raise CSStoreDenied(msg)
            except Exception:
                msg = "Failed to list entries"
                self.logger.exception(msg)
                raise CSStoreError(msg)

        names = []
        for entry in result[u'result']:
            cn = entry[u'cn'][0]
            key = cn.replace('__', '/')
            if keyfilter is not None and not key.startswith(keyfilter):
                continue
            names.append(key.rsplit('/', 1)[-1])
        return names

    def cut(self, key):
        key = self._mangle_key(key)
        with self.ipa as ipa:
            try:
                ipa.Command.vault_del(key, **self._vault_args)
            except NotFound:
                return False
            except AuthorizationError:
                msg = "vault_del denied for entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreDenied(msg)
            except Exception:
                msg = "Failed to delete entry {}".format(key)
                self.logger.exception(msg)
                raise CSStoreError(msg)
            else:
                return True


def test():
    from custodia.compat import configparser
    from custodia.log import setup_logging
    from .interface import IPA_SECTIONNAME

    parser = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )
    parser.read_string(u"""
    [auth:ipa]
    handler = IPAInterface
    [store:ipa_vault]
    handler = IPAVault
    """)

    setup_logging(debug=True, auditfile=None)
    config = {
        'authenticators': {
            'ipa': IPAInterface(parser, IPA_SECTIONNAME)
        }
    }
    v = IPAVault(parser, 'store:ipa_vault')
    v.finalize_init(config, parser, None)
    v.set('foo', 'bar', replace=True)
    print(v.get('foo'))
    print(v.list())
    v.cut('foo')
    print(v.list())


if __name__ == '__main__':
    test()
