# Copyright (C) 2017  Custodia Project Contributors - see LICENSE file
"""IPA API wrapper and interface
"""
from __future__ import absolute_import

import os
import sys

import ipalib
import ipalib.constants
from ipalib.krb_utils import get_principal

import six

from custodia.plugin import HTTPAuthenticator, PluginOption


IPA_SECTIONNAME = 'auth:ipa'


class IPAInterface(HTTPAuthenticator):
    """IPA interface authenticator

    Custodia uses a forking server model. We can bootstrap FreeIPA API in
    the main process. Connections must be created in the client process.
    """
    # Kerberos flags
    krb5config = PluginOption(str, None, "Kerberos krb5.conf override")
    keytab = PluginOption(str, None, "Kerberos keytab for auth")
    ccache = PluginOption(
        str, None, "Kerberos ccache, e,g. FILE:/path/to/ccache")

    # ipalib.api arguments
    ipa_confdir = PluginOption(str, None, "IPA confdir override")
    ipa_context = PluginOption(str, "cli", "IPA bootstrap context")
    ipa_debug = PluginOption(bool, False, "debug mode for ipalib")

    # filled by gssapi()
    principal = False

    def __init__(self, config, section=None, api=None):
        super(IPAInterface, self).__init__(config, section)
        # only one instance of this plugin is supported
        if section != IPA_SECTIONNAME:
            raise ValueError(section)

        if api is None:
            self._api = ipalib.api
        else:
            self._api = api

        if self._api.isdone('bootstrap'):
            raise RuntimeError("IPA API already initialized")

        self._ipa_config = dict(
            context=self.ipa_context,
            debug=self.ipa_debug,
            log=None,  # disable logging to file
        )
        if self.ipa_confdir is not None:
            self._ipa_config['confdir'] = self.ipa_confdir

    @classmethod
    def from_config(cls, config):
        return config['authenticators']['ipa']

    def finalize_init(self, config, cfgparser, context=None):
        super(IPAInterface, self).finalize_init(config, cfgparser, context)

        if self.principal:
            # already initialized
            return

        # get rundir from own section or DEFAULT
        rundir = cfgparser.get(self.section, 'rundir', fallback=None)
        if rundir:
            self._ipa_config['dot_ipa'] = rundir
            self._ipa_config['home'] = rundir
            # workaround https://pagure.io/freeipa/issue/6761#comment-440329
            # monkey-patch ipalib.constants and all loaded ipa modules
            ipalib.constants.USER_CACHE_PATH = rundir
            for name, mod in six.iteritems(sys.modules):
                if (name.startswith(('ipalib.', 'ipaclient.')) and
                        hasattr(mod, 'USER_CACHE_PATH')):
                    mod.USER_CACHE_PATH = rundir

        self._gssapi_config()
        self._bootstrap()
        with self:
            self.logger.info("IPA server '%s': %s",
                             self.env.server,
                             self.Command.ping()[u'summary'])

    def handle(self, request):
        request[IPA_SECTIONNAME] = self
        return None

    # rest is interface and initialization

    def _gssapi_config(self):
        # set client keytab env var for authentication
        if self.keytab is not None:
            os.environ['KRB5_CLIENT_KTNAME'] = self.keytab
        if self.ccache is not None:
            os.environ['KRB5CCNAME'] = self.ccache
        if self.krb5config is not None:
            os.environ['KRB5_CONFIG'] = self.krb5config

        self.principal = self._gssapi_cred()
        self.logger.info(u"Kerberos principal '%s'", self.principal)

    def _gssapi_cred(self):
        try:
            return get_principal()
        except Exception:
            self.logger.exception(
                "Unable to get principal from GSSAPI. Are you missing a "
                "TGT or valid Kerberos keytab?"
            )
            raise

    def _bootstrap(self):
        # TODO: bandaid for "A PKCS #11 module returned CKR_DEVICE_ERROR"
        # https://github.com/avocado-framework/avocado/issues/1112#issuecomment-206999400
        os.environ['NSS_STRICT_NOFORK'] = 'DISABLED'
        self._api.bootstrap(**self._ipa_config)
        self._api.finalize()

    @property
    def Command(self):
        return self._api.Command  # pylint: disable=no-member

    @property
    def env(self):
        return self._api.env  # pylint: disable=no-member

    def __enter__(self):
        # pylint: disable=no-member
        self._gssapi_cred()
        if not self._api.Backend.rpcclient.isconnected():
            self._api.Backend.rpcclient.connect()
        # pylint: enable=no-member
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # pylint: disable=no-member
        if self._api.Backend.rpcclient.isconnected():
            self._api.Backend.rpcclient.disconnect()
        # pylint: enable=no-member


if __name__ == '__main__':
    from custodia.compat import configparser
    from custodia.log import setup_logging

    parser = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )
    parser.read_string(u"""
    [auth:ipa]
    handler = IPAInterface
    """)

    setup_logging(debug=True, auditfile=None)
    IPAInterface(parser, "auth:ipa")
