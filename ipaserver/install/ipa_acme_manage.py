#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

import enum

from ipalib import api, errors, x509
from ipalib import _
from ipalib.facts import is_ipa_configured
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython import cookie, dogtag
from ipaserver.install import cainstance

from ipaserver.plugins.dogtag import RestClient

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
            raise RuntimeError('Failed to disble ACME')


class Command(enum.Enum):
    ENABLE = 'enable'
    DISABLE = 'disable'
    STATUS = 'status'


class IPAACMEManage(AdminTool):
    command_name = "ipa-acme-manage"
    usage = "%prog [enable|disable|status]"
    description = "Manage the IPA ACME service"

    def validate_options(self):
        # needs root now - if/when this program changes to an API
        # wrapper we will no longer need root.
        super(IPAACMEManage, self).validate_options(needs_root=True)

        if len(self.args) < 1:
            self.option_parser.error(f'missing command argument')
        else:
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
                return 0
            else:
                raise RuntimeError('programmer error: unhandled enum case')

        return 0
