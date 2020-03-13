#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various certificate
related scenarios.
"""
import ipaddress
import re

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestInstallMasterClient(IntegrationTest):
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        # use master's DNS so nsupdate adds correct IP address for client
        tasks.config_host_resolvconf_with_master_data(
            cls.master, cls.clients[0]
        )
        tasks.install_client(cls.master, cls.clients[0])

    def test_cacert_file_appear_with_option_F(self):
        """Test if getcert creates cacert file with -F option

        It took longer to create the cacert file in older version.
        restarting the certmonger service creates the file at the location
        specified by -F option. This fix is to check that cacert file
        creates immediately after certificate goes into MONITORING state.

        related: https://pagure.io/freeipa/issue/8105
        """
        cmd_arg = ['ipa-getcert', 'request',
                   '-f', '/etc/pki/tls/certs/test.pem',
                   '-k', '/etc/pki/tls/private/test.key',
                   '-K', 'test/%s' % self.clients[0].hostname,
                   '-F', '/etc/pki/tls/test.CA']
        result = self.clients[0].run_command(cmd_arg)
        request_id = re.findall(r'\d+', result.stdout_text)

        # check if certificate is in MONITORING state
        status = tasks.wait_for_request(self.clients[0], request_id[0], 50)
        assert status == "MONITORING"

        self.clients[0].run_command(['ls', '-l', '/etc/pki/tls/test.CA'])

    def test_ipa_getcert_san_aci(self):
        """Test for DNS and IP SAN extensions + ACIs
        """
        hostname = self.clients[0].hostname
        certfile = '/etc/pki/tls/certs/test2.pem'

        tasks.kinit_admin(self.master)
        name, zone = hostname.split('.', 1)
        self.master.run_command(['ipa', 'dnsrecord-show', zone, name])
        tasks.kdestroy_all(self.master)

        cmd_arg = [
            'ipa-getcert', 'request', '-v', '-w',
            '-f', certfile,
            '-k', '/etc/pki/tls/private/test2.key',
            '-K', f'test/{hostname}',
            '-D', hostname,
            '-A', self.clients[0].ip,
        ]
        result = self.clients[0].run_command(cmd_arg)
        request_id = re.findall(r'\d+', result.stdout_text)

        # check if certificate is in MONITORING state
        status = tasks.wait_for_request(self.clients[0], request_id[0], 50)
        assert status == "MONITORING"

        certdata = self.clients[0].get_file_contents(certfile)
        cert = x509.load_pem_x509_certificate(
            certdata, default_backend()
        )
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        dnsnames = ext.value.get_values_for_type(x509.DNSName)
        assert dnsnames == [self.clients[0].hostname]
        ipaddrs = ext.value.get_values_for_type(x509.IPAddress)
        assert ipaddrs == [ipaddress.ip_address(self.clients[0].ip)]
