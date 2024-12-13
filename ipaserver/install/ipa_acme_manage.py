#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#


import enum
import pki.util
import logging

from ipalib import api, errors, x509
from ipalib import _
from ipalib.facts import is_ipa_configured
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython import cookie, dogtag, config
from ipapython.ipautil import run
from ipapython.certdb import NSSDatabase, EXTERNAL_CA_TRUST_FLAGS
from ipaserver.install import cainstance
from ipaserver.install.ca import lookup_random_serial_number_version

from ipaserver.plugins.dogtag import RestClient

logger = logging.getLogger(__name__)

default_pruning_options = {
    'certRetentionTime': '30',
    'certRetentionUnit': 'day',
    'certSearchSizeLimit': '1000',
    'certSearchTimeLimit': '0',
    'requestRetentionTime': 'day',
    'requestRetentionUnit': '30',
    'requestSearchSizeLimit': '1000',
    'requestSearchTimeLimit': '0',
    'cron': ''
}

pruning_labels = {
    'certRetentionTime': 'Certificate Retention Time',
    'certRetentionUnit': 'Certificate Retention Unit',
    'certSearchSizeLimit': 'Certificate Search Size Limit',
    'certSearchTimeLimit': 'Certificate Search Time Limit',
    'requestRetentionTime': 'Request Retention Time',
    'requestRetentionUnit': 'Request Retention Unit',
    'requestSearchSizeLimit': 'Request Search Size Limit',
    'requestSearchTimeLimit': 'Request Search Time Limit',
    'cron': 'cron Schedule'
}


def validate_range(val, min, max):
    """dogtag appears to have no error checking in the cron
       entry so do some minimum amount of validation. It is
       left as an exercise for the user to do month/day
       validation so requesting Feb 31 will be accepted.

       Only * and a number within a min/max range are allowed.
    """
    if val == '*':
        return

    if '-' in val or '/' in val:
        raise ValueError(f"{val} ranges are not supported")

    try:
        int(val)
    except ValueError:
        # raise a clearer error
        raise ValueError(f"{val} is not a valid integer")

    if int(val) < min or int(val) > max:
        raise ValueError(f"{val} not within the range {min}-{max}")


# Manages the FreeIPA ACME service on a per-server basis.
#
# This program is a stop-gap until the deployment-wide management of
# the ACME service is implemented.  So we will eventually have API
# calls for managing the ACME service, e.g. `ipa acme-enable'.
# After that is implemented, we can either deprecate and eventually
# remove this program, or make it a wrapper for the API commands.


class acme_state(RestClient):

    def _request(self, url, headers=None):
        headers = headers or {}
        return dogtag.https_request(
            self.ca_host, 8443,
            url=url,
            cafile=self.ca_cert,
            client_certfile=paths.RA_AGENT_PEM,
            client_keyfile=paths.RA_AGENT_KEY,
            headers=headers,
            method='POST'
        )

    def __enter__(self):
        status, resp_headers, _unused = self._request('/acme/login')
        cookies = cookie.Cookie.parse(resp_headers.get('set-cookie', ''))
        if status != 200 or len(cookies) == 0:
            raise errors.RemoteRetrieveError(
                reason=_('Failed to authenticate to CA REST API')
            )
        object.__setattr__(self, 'cookie', str(cookies[0]))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Log out of the REST API"""
        headers = dict(Cookie=self.cookie)
        status, unused, _unused = self._request('/acme/logout', headers=headers)
        object.__setattr__(self, 'cookie', None)
        if status != 204:
            raise RuntimeError('Failed to logout')

    def enable(self):
        headers = dict(Cookie=self.cookie)
        status, unused, _unused = self._request('/acme/enable', headers=headers)
        if status != 200:
            raise RuntimeError('Failed to enable ACME')

    def disable(self):
        headers = dict(Cookie=self.cookie)
        status, unused, _unused = self._request('/acme/disable',
                                                headers=headers)
        if status != 200:
            raise RuntimeError('Failed to disable ACME')


class Command(enum.Enum):
    ENABLE = 'enable'
    DISABLE = 'disable'
    STATUS = 'status'
    PRUNE = 'pruning'


class IPAACMEManage(AdminTool):
    command_name = "ipa-acme-manage"
    usage = "%prog [enable|disable|status|pruning]"
    description = "Manage the IPA ACME service"

    @classmethod
    def add_options(cls, parser):

        group = config.OptionGroup(parser, 'Pruning')
        group.add_option(
            "--enable", dest="enable", action="store_true",
            default=False, help="Enable certificate pruning")
        group.add_option(
            "--disable", dest="disable", action="store_true",
            default=False, help="Disable certificate pruning")
        group.add_option(
            "--cron", dest="cron", action="store",
            default=None, help="Configure the pruning cron job")
        group.add_option(
            "--certretention", dest="certretention", action="store",
            default=None, help="Certificate retention time", type=int)
        group.add_option(
            "--certretentionunit", dest="certretentionunit", action="store",
            choices=['minute', 'hour', 'day', 'year'],
            default=None, help="Certificate retention units")
        group.add_option(
            "--certsearchsizelimit", dest="certsearchsizelimit",
            action="store",
            default=None, help="LDAP search size limit", type=int)
        group.add_option(
            "--certsearchtimelimit", dest="certsearchtimelimit", action="store",
            default=None, help="LDAP search time limit", type=int)
        group.add_option(
            "--requestretention", dest="requestretention", action="store",
            default=None, help="Request retention time", type=int)
        group.add_option(
            "--requestretentionunit", dest="requestretentionunit",
            choices=['minute', 'hour', 'day', 'year'],
            action="store", default=None, help="Request retention units")
        group.add_option(
            "--requestsearchsizelimit", dest="requestsearchsizelimit",
            action="store",
            default=None, help="LDAP search size limit", type=int)
        group.add_option(
            "--requestsearchtimelimit", dest="requestsearchtimelimit",
            action="store",
            default=None, help="LDAP search time limit", type=int)
        group.add_option(
            "--config-show", dest="config_show", action="store_true",
            default=False, help="Show the current pruning configuration")
        group.add_option(
            "--run", dest="run", action="store_true",
            default=False, help="Run the pruning job now")
        parser.add_option_group(group)
        super(IPAACMEManage, cls).add_options(parser, debug_option=True)


    def validate_options(self):
        super(IPAACMEManage, self).validate_options(needs_root=True)

        if len(self.args) < 1:
            self.option_parser.error(f'missing command argument')

        if self.args[0] == "pruning":
            if self.options.enable and self.options.disable:
                self.option_parser.error("Cannot both enable and disable")
            elif (
                any(
                    [
                        self.options.enable,
                        self.options.disable,
                        self.options.cron,
                        self.options.certretention is not None,
                        self.options.certretentionunit,
                        self.options.requestretention is not None,
                        self.options.requestretentionunit,
                        self.options.certsearchsizelimit is not None,
                        self.options.certsearchtimelimit is not None,
                        self.options.requestsearchsizelimit is not None,
                        self.options.requestsearchtimelimit is not None,
                    ]
                )
                and (self.options.config_show or self.options.run)
            ):

                self.option_parser.error(
                    "Cannot change and show config or run at the same time"
                )
            elif self.options.cron:
                if len(self.options.cron.split()) != 5:
                    self.option_parser.error("Invalid format for --cron")
                # dogtag does no validation when setting this option so
                # do the minimum. The dogtag cron is limited compared to
                # crontab(5).
                opt = self.options.cron.split()
                validate_range(opt[0], 0, 59)
                validate_range(opt[1], 0, 23)
                validate_range(opt[2], 1, 31)
                validate_range(opt[3], 1, 12)
                validate_range(opt[4], 0, 6)

        try:
            self.command = Command(self.args[0])
        except ValueError:
            self.option_parser.error(f'unknown command "{self.args[0]}"')

    def check_san_status(self):
        """
        Require the Apache cert to have ipa-ca.$DOMAIN SAN
        """
        cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
        cainstance.check_ipa_ca_san(cert)

    def pruning(self):
        def run_pki_server(command, directive, prefix, value=None):
            """Take a set of arguments to append to pki-server"""
            args = [
                'pki-server', command,
                f'{prefix}.{directive}'
            ]
            if value is not None:
                args.extend([str(value)])
            logger.debug(args)
            result = run(args, raiseonerr=False, capture_output=True,
                         capture_error=True)
            if result.returncode != 0:
                # See if the parameter doesn't exist. If not then no
                # user-specified value has been set.
                # ERROR: No such parameter: jobsScheduler...
                if 'No such parameter' in result.error_output:
                    return ''
                raise RuntimeError(result.error_output)
            return result.output.strip()

        def ca_config_set(directive, value,
                          prefix='jobsScheduler.job.pruning'):
            run_pki_server('ca-config-set', directive, prefix, value)
            # ca-config-set always succeeds, even if the option is
            # not supported.
            newvalue = ca_config_show(directive)
            if str(value) != newvalue.strip():
                raise RuntimeError('Updating %s failed' % directive)

        def ca_config_show(directive):
            return run_pki_server('ca-config-show', directive,
                                  prefix='jobsScheduler.job.pruning')

        def config_show():
            status = ca_config_show('enabled')
            if status.strip() == 'true':
                print("Status: enabled")
            else:
                print("Status: disabled")
            for option in (
                'certRetentionTime', 'certRetentionUnit',
                'certSearchSizeLimit', 'certSearchTimeLimit',
                'requestRetentionTime', 'requestRetentionUnit',
                'requestSearchSizeLimit', 'requestSearchTimeLimit',
                'cron',
            ):
                value = ca_config_show(option)
                if value:
                    print("{}: {}".format(pruning_labels[option], value))
                else:
                    print("{}: {}".format(pruning_labels[option],
                                          default_pruning_options[option]))

        def run_pruning():
            """Run the pruning job manually"""

            with NSSDatabase() as tmpdb:
                print("Preparing...")
                tmpdb.create_db()
                tmpdb.import_files((paths.RA_AGENT_PEM, paths.RA_AGENT_KEY),
                                   import_keys=True)
                tmpdb.import_files((paths.IPA_CA_CRT,))
                for nickname, trust_flags in tmpdb.list_certs():
                    if trust_flags.has_key:
                        ra_nickname = nickname
                        continue
                    # external is suffucient for our purposes: C,,
                    tmpdb.trust_root_cert(nickname, EXTERNAL_CA_TRUST_FLAGS)
                print("Starting job...")
                args = ['pki', '-C', tmpdb.pwd_file, '-d', tmpdb.secdir,
                        '-n', ra_nickname,
                        'ca-job-start', 'pruning']
                logger.debug(args)
                run(args, stdin='y')

        pki_version = pki.util.Version(pki.specification_version())
        if pki_version < pki.util.Version("11.3.0"):
            raise RuntimeError(
                'Certificate pruning is not supported in PKI version %s'
                % pki_version
            )

        if lookup_random_serial_number_version(api) == 0:
            raise RuntimeError(
                'Certificate pruning requires random serial numbers'
            )

        if self.options.config_show:
            config_show()
            return

        if self.options.run:
            run_pruning()
            return

        # Don't play the enable/disable at the same time game
        if self.options.enable:
            ca_config_set('owner', 'ipara')
            ca_config_set('enabled', 'true')
            ca_config_set('enabled', 'true', 'jobsScheduler')
        elif self.options.disable:
            ca_config_set('enabled', 'false')

        # pki-server ca-config-set can only set one option at a time so
        # loop through all the options and set what is there.
        if self.options.certretention is not None:
            ca_config_set('certRetentionTime',
                          self.options.certretention)
        if self.options.certretentionunit:
            ca_config_set('certRetentionUnit',
                          self.options.certretentionunit)
        if self.options.certsearchtimelimit is not None:
            ca_config_set('certSearchTimeLimit',
                          self.options.certsearchtimelimit)
        if self.options.certsearchsizelimit is not None:
            ca_config_set('certSearchSizeLimit',
                          self.options.certsearchsizelimit)
        if self.options.requestretention is not None:
            ca_config_set('requestRetentionTime',
                          self.options.requestretention)
        if self.options.requestretentionunit:
            ca_config_set('requestRetentionUnit',
                          self.options.requestretentionunit)
        if self.options.requestsearchsizelimit is not None:
            ca_config_set('requestSearchSizeLimit',
                          self.options.requestsearchsizelimit)
        if self.options.requestsearchtimelimit is not None:
            ca_config_set('requestSearchTimeLimit',
                          self.options.requestsearchtimelimit)
        if self.options.cron:
            ca_config_set('cron', self.options.cron)

        config_show()

        print("The CA service must be restarted for changes to take effect")


    def run(self):
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        if not cainstance.is_ca_installed_locally():
            print("CA is not installed on this server.")
            return 3

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect()

        state = acme_state(api)
        with state as ca_api:
            if self.command == Command.ENABLE:
                self.check_san_status()
                ca_api.enable()
            elif self.command == Command.DISABLE:
                ca_api.disable()
            elif self.command == Command.STATUS:
                status = "enabled" if dogtag.acme_status() else "disabled"
                print("ACME is {}".format(status))
            elif self.command == Command.PRUNE:
                self.pruning()
            else:
                raise RuntimeError('programmer error: unhandled enum case')

        return 0
