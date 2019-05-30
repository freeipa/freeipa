# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2013  Red Hat
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

"""Host class for integration testing"""
import subprocess
import tempfile

import ldap
import pytest_multihost.host

from ipaplatform.paths import paths
from ipapython import ipaldap


class LDAPClientWithoutCertCheck(ipaldap.LDAPClient):
    """Adds an option to disable certificate check for TLS connection

    To disable certificate validity check create client with added option
    no_certificate_check:
    client = LDAPClientWithoutCertCheck(..., no_certificate_check=True)
    """
    def __init__(self, *args, **kwargs):
        self._no_certificate_check = kwargs.pop(
            'no_certificate_check', False)
        super(LDAPClientWithoutCertCheck, self).__init__(*args, **kwargs)

    def _connect(self):
        if (self._start_tls and self.protocol == 'ldap' and
                self._no_certificate_check):
            with self.error_handler():
                conn = ipaldap.ldap_initialize(
                    self.ldap_uri, cacertfile=self._cacert)
                conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT,
                                ldap.OPT_X_TLS_NEVER)
                conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
                conn.start_tls_s()
                return conn
        else:
            return super(LDAPClientWithoutCertCheck, self)._connect()


class Host(pytest_multihost.host.Host):
    """Representation of a remote IPA host"""

    @staticmethod
    def _make_host(domain, hostname, role, ip, external_hostname):
        # We need to determine the type of the host, this depends on the domain
        # type, as we assume all Unix machines are in the Unix domain and
        # all Windows machine in a AD domain

        if domain.type == 'AD':
            cls = WinHost
        else:
            cls = Host

        return cls(domain, hostname, role, ip, external_hostname)

    def ldap_connect(self):
        """Return an LDAPClient authenticated to this host as directory manager
        """
        self.log.info('Connecting to LDAP at %s', self.external_hostname)
        # get IPA CA cert to establish a secure connection
        cacert = self.get_file_contents(paths.IPA_CA_CRT)
        with tempfile.NamedTemporaryFile() as f:
            f.write(cacert)
            f.flush()

            hostnames_mismatch = self.hostname != self.external_hostname
            conn = LDAPClientWithoutCertCheck.from_hostname_secure(
                self.external_hostname,
                cacert=f.name,
                no_certificate_check=hostnames_mismatch)
            binddn = self.config.dirman_dn
            self.log.info('LDAP bind as %s', binddn)
            conn.simple_bind(binddn, self.config.dirman_password)

            # The CA cert file  has been loaded into the SSL_CTX and is no
            # longer required.

        return conn

    @classmethod
    def from_env(cls, env, domain, hostname, role, index, domain_index):
        from ipatests.pytest_ipa.integration.env_config import host_from_env
        return host_from_env(env, domain, hostname, role, index, domain_index)

    def to_env(self, **kwargs):
        from ipatests.pytest_ipa.integration.env_config import host_to_env
        return host_to_env(self, **kwargs)

    def run_command(self, argv, set_env=True, stdin_text=None,
                    log_stdout=True, raiseonerr=True,
                    cwd=None, bg=False, encoding='utf-8'):
        # Wrap run_command to log stderr on raiseonerr=True
        result = super().run_command(
            argv, set_env=set_env, stdin_text=stdin_text,
            log_stdout=log_stdout, raiseonerr=False, cwd=cwd, bg=bg,
            encoding=encoding
        )
        if result.returncode and raiseonerr:
            result.log.error('stderr: %s', result.stderr_text)
            raise subprocess.CalledProcessError(
                result.returncode, argv,
                result.stdout_text, result.stderr_text
            )
        else:
            return result


class WinHost(pytest_multihost.host.WinHost):
    """
    Representation of a remote Windows host.

    This serves as a sketch class once we move from manual preparation of
    Active Directory to the automated setup.
    """
