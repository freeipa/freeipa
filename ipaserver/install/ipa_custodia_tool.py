# Copyright (C) 2017-2018  IPA Project Contributors, see COPYING for license
"""Check and regenerate Custodia server.keys and config

KEEP THIS SCRIPT COMPATIBLE WITH FREEIPA 4.5

Christian Heimes <cheimes@redhat.com>
"""
from __future__ import absolute_import, print_function

import logging
import optparse  # pylint: disable=deprecated-module
import os
import platform
import socket
import sys
import warnings

from ipalib import api
from ipaplatform.paths import paths
from ipapython import admintool
from ipapython.ipautil import backup_file
import ipapython.version
from ipaserver.install import installutils
from ipaserver.install import sysupgrade
from ipaserver.install.custodiainstance import CustodiaInstance

from custodia.message.kem import KEY_USAGE_SIG, KEY_USAGE_ENC, KEY_USAGE_MAP

from jwcrypto.common import json_decode
from jwcrypto.jwk import JWK


try:
    # FreeIPA >= 4.5
    from ipaserver.secrets.client import CustodiaClient
except ImportError:
    # FreeIPA <= 4.4
    from ipapython.secrets.client import CustodiaClient

# Ignore security warning from vendored and non-vendored urllib3
try:
    from urllib3.exceptions import SecurityWarning
except ImportError:
    SecurityWarning = None
else:
    warnings.simplefilter("ignore", SecurityWarning)

try:
    from requests.packages.urllib3.exceptions import SecurityWarning
except ImportError:
    SecurityWarning = None
else:
    warnings.simplefilter("ignore", SecurityWarning)


KEYS = [
    'dm/DMHash',
    'ra/ipaCert',
    'ca/auditSigningCert cert-pki-ca',
    'ca/caSigningCert cert-pki-ca',
    'ca/ocspSigningCert cert-pki-ca',
    'ca/subsystemCert cert-pki-ca',
]

IPA_CUSTODIA_KEYFILE = os.path.join(
    paths.IPA_CUSTODIA_CONF_DIR, 'server.keys'
)


logger = logging.getLogger(__name__)


def keys_cb(option, opt_str, value, parser):
    """Poor man's hack for argparse nargs='*'
    """
    args = []
    for arg in parser.rargs:
        if arg.startswith('-'):
            break
        if arg not in option.default:
            raise optparse.OptionValueError("Invalid key '{}'".format(arg))
        args.append(arg)
    del parser.rargs[:len(args)]
    # override defaults
    setattr(parser.values, option.dest, args)


class IPACustodiaTool(admintool.AdminTool):
    command_name = 'ipa-custodia-check'

    usage = "%prog [options]\n"

    console_format = "<%(levelname)s>: %(message)s"

    @classmethod
    def add_options(cls, parser, debug_option=False):
        super(IPACustodiaTool, cls).add_options(parser, debug_option)
        group = optparse.OptionGroup(
            parser, "Check",
            description="Validate ipa-custodia configuration and keys"
        )
        group.add_option(
            "--check",
            action="store", type="string", dest="server",
            help="Check connection with remote host"
        )
        group.add_option(
            '--keys',
            action="callback", callback=keys_cb, dest="keys",
            default=KEYS,
            help="Remote key ({})".format(', '.join(KEYS))
        )
        parser.add_option_group(group)

        group = optparse.OptionGroup(
            parser, "Regenerate",
            description="Create new ipa-custodia keys"
        )
        group.add_option(
            '--regenerate', action="store_true",
            dest="regenerate", default=False,
            help="Perform regeneration"
        )
        parser.add_option_group(group)

    def validate_options(self):
        super(IPACustodiaTool, self).validate_options(needs_root=True)
        try:
            installutils.check_server_configuration()
        except RuntimeError as e:
            raise admintool.ScriptError(e)
        if bool(self.options.server) ^ bool(self.options.regenerate) != 1:
            self.option_parser.exit(
                1,
                "Either --check or --regenerate are required.\n"
            )

    def setup_logging(self, log_file_mode='w'):
        super(IPACustodiaTool, self).setup_logging(log_file_mode)
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            if (isinstance(handler, logging.StreamHandler) and
                    getattr(handler, 'stream', None) is sys.stderr):
                handler.setFormatter(logging.Formatter(
                    self.console_format
                ))

    def run(self):
        super(IPACustodiaTool, self).run()

        # use private in-memory ccache
        os.environ['KRB5CCNAME'] = 'MEMORY:ipa-custodia-regen'
        # use host keytab to acquire TGT for LDAP connection
        os.environ['KRB5_CLIENT_KTNAME'] = paths.KRB5_KEYTAB

        if not api.isdone('finalize'):
            api.bootstrap(
                in_server=True,
                debug=self.options.verbose,
                confdir=paths.ETC_IPA,
            )
            api.finalize()
        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()

        if self.options.regenerate:
            cmd = IPACustodiaRegenerate(self.option_parser, self.options)
        else:
            cmd = IPACustodiaChecker(self.option_parser, self.options)

        cmd()


class IPACustodiaRegenerate(object):
    def __init__(self, parser, options):
        self.parser = parser
        self.options = options

    def __call__(self):
        custodia = CustodiaInstance(
            host_name=api.env.host,
            realm=api.env.realm,
        )
        # patch class to use logger
        custodia.print_msg = logger.info

        # stop service if it is running
        is_running = custodia.is_running()
        if is_running:
            logger.info("Stopping %s", custodia.service_name)
            custodia.stop()

        # backup and remove old file (if exists)
        for filename in (custodia.config_file, custodia.server_keys):
            logger.info("Backing up and removing existing '%s'", filename)
            backup_file(filename)
            installutils.remove_file(filename)

        # fake uninstalled state
        sysupgrade.set_upgrade_state('custodia', 'installed', False)

        # Run install to create server keys and config. This will NOT create
        # new keys for services such as Lightweight CA keys (Dogtag). Cannot
        # use upgrade_instance() because it doesn't perform all steps on
        # FreeIPA 4.4 and 4.5.
        # create_instance() set upgrade state to installed
        logger.info("Running create_instance to regenerate config and keys.")
        custodia.create_instance()

        # start Custodia if it has been running before
        if is_running:
            logger.info("Starting %s", custodia.service_name)
            custodia.start()
        logger.warning(
            "It may take a couple of minutes until public keys are "
            "replicated to other LDAP servers."
        )
        self.parser.exit(0, "Keys have been regenerated.\n")


class IPACustodiaChecker(object):
    files = [
        paths.IPA_DEFAULT_CONF,
        paths.KRB5_KEYTAB,
        paths.IPA_CUSTODIA_CONF,
        IPA_CUSTODIA_KEYFILE
    ]

    def __init__(self, parser, options):
        self.parser = parser
        self.options = options
        if not api.isdone('bootstrap'):
            # bootstrap to initialize api.env
            api.bootstrap()
            self.debug("IPA API bootstrapped")
        self.realm = api.env.realm
        self.host = api.env.host
        if not self.host:
            raise admintool.ScriptError("api.env.host is not set")
        if not self.options.server:
            raise admintool.ScriptError("Remote server is not set")
        self.host_spn = 'host/{}@{}'.format(self.host, self.realm)
        self.server_spn = 'host/{}@{}'.format(self.options.server, self.realm)
        self.client = None
        self._errors = []

    def __call__(self):
        self.check()
        self.exit()

    def error(self, msg, fatal=False):
        self._errors.append(msg)
        logger.error(msg, exc_info=self.options.verbose)
        if fatal:
            self.exit()

    def exit(self):
        if self._errors:
            self.parser.exit(1, "[ERROR] One or more tests have failed.\n")
        else:
            self.parser.exit(0, "All tests have passed successfully.\n")

    def warning(self, msg):
        logger.warning(msg)

    def info(self, msg):
        logger.info(msg)

    def debug(self, msg):
        logger.debug(msg)

    def check(self):
        self.status()
        self.check_fqdn()
        self.check_files()
        self.check_client()
        self.check_jwk()
        self.check_keys()

    def status(self):
        self.info("Platform: {}".format(platform.platform()))
        self.info("IPA version: {}".format(
            ipapython.version.VERSION
        ))
        self.info("IPA vendor version: {}".format(
            ipapython.version.VENDOR_VERSION
        ))
        self.info("Realm: {}".format(self.realm))
        self.info("Host: {}".format(self.host))
        self.info("Remote server: {}".format(self.options.server))
        if self.host == self.options.server:
            self.warning("Performing self-test only.")

    def check_fqdn(self):
        fqdn = socket.getfqdn()
        if self.host != fqdn:
            self.warning(
                "socket.getfqdn() reports hostname '{}'".format(fqdn)
            )

    def check_files(self):
        for filename in self.files:
            if not os.path.isfile(filename):
                self.error("File '{0}' is missing.".format(filename))
            else:
                self.info("File '{0}' exists.".format(filename))

    def check_client(self):
        try:
            self.client = CustodiaClient(
                server=self.options.server,
                client_service='host@{}'.format(self.host),
                keyfile=IPA_CUSTODIA_KEYFILE,
                keytab=paths.KRB5_KEYTAB,
                realm=self.realm,
            )
        except Exception as e:
            return self.error(
                "Failed to create client: {}".format(e),
                fatal=True
            )
        else:
            self.info("Custodia client created.")

    def _check_jwk_single(self, usage_id):
        usage = KEY_USAGE_MAP[usage_id]
        with open(IPA_CUSTODIA_KEYFILE) as f:
            dictkeys = json_decode(f.read())

        try:
            pkey = JWK(**dictkeys[usage_id])
            local_pubkey = json_decode(pkey.export_public())
        except Exception:
            return self.error(
                "Failed to load and parse local JWK.",
                fatal=True
            )
        else:
            self.info("Loaded key for usage '{}' from '{}'.".format(
                usage, IPA_CUSTODIA_KEYFILE
            ))

        if pkey.key_id != self.host_spn:
            return self.error(
                "KID '{}' != host service principal name '{}' "
                "(usage: {})".format(pkey.key_id, self.host_spn, usage),
                fatal=True
            )
        else:
            self.info(
                "JWK KID matches host's service principal name '{}'.".format(
                    self.host_spn
                ))

        # LDAP doesn't contain KID
        local_pubkey.pop("kid", None)
        find_key = self.client.ikk.find_key
        try:
            host_pubkey = json_decode(find_key(self.host_spn, usage_id))
        except Exception:
            return self.error(
                "Fetching host keys {} (usage: {}) failed.".format(
                    self.host_spn, usage),
                fatal=True
            )
        else:
            self.info("Checked host LDAP keys '{}' for usage {}.".format(
                self.host_spn, usage
            ))

        if host_pubkey != local_pubkey:
            self.debug("LDAP: '{}'".format(host_pubkey))
            self.debug("Local: '{}'".format(local_pubkey))
            return self.error(
                "Host key in LDAP does not match local key.",
                fatal=True
            )
        else:
            self.info(
                "Local key for usage '{}' matches key in LDAP.".format(usage)
            )

        try:
            server_pubkey = json_decode(find_key(self.server_spn, usage_id))
        except Exception:
            return self.error(
                "Fetching server keys {} (usage: {}) failed.".format(
                    self.server_spn, usage),
                fatal=True
            )
        else:
            self.info("Checked server LDAP keys '{}' for usage {}.".format(
                self.server_spn, usage
            ))

        return local_pubkey, host_pubkey, server_pubkey

    def check_jwk(self):
        self._check_jwk_single(KEY_USAGE_SIG)
        self._check_jwk_single(KEY_USAGE_ENC)

    def check_keys(self):
        self.info("Retrieving keys from '{}'.".format(self.options.server))
        for key in self.options.keys:
            try:
                result = self.client.fetch_key(key, store=False)
            except Exception as e:
                self.error("Failed to retrieve key '{}': {}.".format(
                    key, e
                ))
            else:
                self.info("Successfully retrieved '{}'.".format(key))
                self.debug(result)


if __name__ == '__main__':
    IPACustodiaTool.run_cli()
