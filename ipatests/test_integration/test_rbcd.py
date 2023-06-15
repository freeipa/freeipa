#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for resource-based constrained delegation (RBCD)
   - check scenario between ipa_client and AD (use S4U2PRoxy)
    (FreeIPA currently does not have support for IPA to IPA trust and does not
    provide a working two-way trust with Active Directory)
"""

from __future__ import absolute_import

from functools import partial
import textwrap
import re
import os
import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

class TestRBCD(IntegrationTest):
    topology = 'star'
    num_clients = 1
    num_ad_domains = 1

    ipa_user1 = 'alice'
    ipa_user1_password = 'SecretUser123'
    ad_user_login = 'ad_testuser'
    ad_user_password = 'Secret123'
    ipa_test_group = 'ipa_testgroup'
    ad_test_group = 'testgroup'

    @classmethod
    def install(cls, mh):
        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level
        tasks.install_topo(cls.topology,
                           cls.master, cls.replicas,
                           cls.clients, domain_level,
                           clients_extra_args=('--mkhomedir',))

        cls.ad = cls.ads[0]
        cls.ipa-client = cls.clients[0]
        cls.ad_user = '{}@{}'.format(cls.ad_user_login, cls.ad.domain.name)

        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.configure_windows_dns_for_trust(cls.ad, cls.master)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name,
                                      extra_args=['--two-way=false'])

        tasks.create_active_user(cls.master, cls.ipa_user1,
                                 password=cls.ipa_user1_password)

    @pytest.fixture
    def ad_set_new_service(self,ad,master):
        """Create a new service on AD."""

        # Create service on AD
        service_name = service3
        service_paswd = 'Secret123'
        spn = 'service3/' + self.ad.domain.name
        ipa_service = "host" + "/" + self.master.hostname

        cmd = ('New-ADComputer -Name {} -AccountPassword (ConvertTo-SecureString -String {} -Force -AsPlainText) '
               '-ServicePrincipalNames {} -CannotChangePassword $true -PasswordNeverExpires $true '
               '-KerberosEncryptionType AES128,AES256 -TrustedForDelegation $true '
               '-Enabled $true -AccountNotDelegated $false').format(service_name, service_paswd, self.ad_domain)
        self.ad.run_command(['powershell', '-c', cmd])

        #Set RBCD
        cmd = ('Set-ADComputer -Identity {} -PrincipalsAllowedToDelegateToAccount '{}).format(service_name, ipa_service)
        self.ad.run_command(['powershell', '-c', cmd])

        #Check RBCD
        cmd = ('Get-ADComputer {} -Properties PrincipalsAllowedToDelegateToAccount').format(service_name)
        output = self.ad.run_command(['powershell', '-c', cmd])
        if ipa_service in output:
            print("PrincipalsAllowedToDelegateToAccount was set.")
        else:
            print("PrincipalsAllowedToDelegateToAccount was not set!.")

    def test_rbcd_ipa_client_AD(self):
        """ Test that host can handle resource-based constrained delegation of
        service on AD and IPA-client. """

        spn = 'service3/' + self.ad.domain.name
        keytab_file = '/etc/krb5.keytab'
        hostservice_name4 = "host" + "/" + self.master.hostname
        service_name4 = "testservice4" + '/' + self.master.hostname  # cifs

        # S4U2Self
        self.master.run_command(['kinit', '-kt', keytab_file])
        result = self.master.run_command(['klist', '-e'])
        assert hostservice_name4 in result

        # S4U2Proxy
        result = self.master.run_command(['kvno', '-U', 'admin',
                                          '-P', hostservice_name4,
                                          spn],
                                          raiseonerr=False)
        assert result.returncode == 0
