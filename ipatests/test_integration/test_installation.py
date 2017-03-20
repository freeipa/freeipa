#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various subsystems to be
installed.
"""

import pytest
from ipalib.constants import DOMAIN_LEVEL_0
from ipatests.pytest_plugins.integration.env_config import get_global_config
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks

config = get_global_config()

class InstallTestBase1(IntegrationTest):

    num_replicas = 3
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_replica0_ca_less_install(self):
        tasks.install_replica(self.master, self.replicas[0], setup_ca=False)

    def test_replica0_ipa_ca_install(self):
        tasks.install_ca(self.replicas[0])

    def test_replica0_ipa_kra_install(self):
        tasks.install_kra(self.replicas[0], first_instance=True)

    def test_replica0_ipa_dns_install(self):
        tasks.install_dns(self.replicas[0])

    def test_replica1_with_ca_install(self):
        tasks.install_replica(self.master, self.replicas[1], setup_ca=True)

    def test_replica1_ipa_kra_install(self):
        tasks.install_kra(self.replicas[1])

    def test_replica1_ipa_dns_install(self):
        tasks.install_dns(self.replicas[1])

    def test_replica2_with_ca_kra_install(self):
        tasks.install_replica(self.master, self.replicas[2], setup_ca=True,
                              setup_kra=True)

    def test_replica2_ipa_dns_install(self):
        tasks.install_dns(self.replicas[2])


class InstallTestBase2(IntegrationTest):

    num_replicas = 3
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def test_replica0_with_ca_kra_dns_install(self):
        tasks.install_replica(self.master, self.replicas[0], setup_ca=True,
                              setup_kra=True, setup_dns=True)

    def test_replica1_with_ca_dns_install(self):
        tasks.install_replica(self.master, self.replicas[1], setup_ca=True,
                              setup_dns=True)

    def test_replica1_ipa_kra_install(self):
        tasks.install_kra(self.replicas[1])

    def test_replica2_with_dns_install(self):
        tasks.install_replica(self.master, self.replicas[2], setup_ca=False,
                              setup_dns=True)

    def test_replica2_ipa_ca_install(self):
        tasks.install_ca(self.replicas[2])

    def test_replica2_ipa_kra_install(self):
        tasks.install_kra(self.replicas[2])


class ADTrustInstallTestBase(IntegrationTest):
    """
    Base test for builtin AD trust installation im combination with other
    components
    """
    num_replicas = 2
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    def install_replica(self, replica, **kwargs):
        tasks.install_replica(self.master, replica, setup_adtrust=True,
                              **kwargs)

    def test_replica0_only_adtrust(self):
        self.install_replica(self.replicas[0], setup_ca=False)

    def test_replica1_all_components_adtrust(self):
        self.install_replica(self.replicas[1], setup_ca=True)


##
# Master X Replicas installation tests
##

class TestInstallWithCA1(InstallTestBase1):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica1_ipa_kra_install(self):
        super(TestInstallWithCA1, self).test_replica1_ipa_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_with_ca_kra_install(self):
        super(TestInstallWithCA1, self).test_replica2_with_ca_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_ipa_dns_install(self):
        super(TestInstallWithCA1, self).test_replica2_ipa_dns_install()


class TestInstallWithCA2(InstallTestBase2):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False)

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica0_with_ca_kra_dns_install(self):
        super(TestInstallWithCA2, self).test_replica0_with_ca_kra_dns_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica1_ipa_kra_install(self):
        super(TestInstallWithCA2, self).test_replica1_ipa_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_ipa_kra_install(self):
        super(TestInstallWithCA2, self).test_replica2_ipa_kra_install()


class TestInstallWithCA_KRA1(InstallTestBase1):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False, setup_kra=True)

    def test_replica0_ipa_kra_install(self):
        tasks.install_kra(self.replicas[0], first_instance=False)


class TestInstallWithCA_KRA2(InstallTestBase2):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=False, setup_kra=True)


class TestInstallWithCA_DNS1(InstallTestBase1):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica1_ipa_kra_install(self):
        super(TestInstallWithCA_DNS1, self).test_replica1_ipa_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_with_ca_kra_install(self):
        super(TestInstallWithCA_DNS1, self).test_replica2_with_ca_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_ipa_dns_install(self):
        super(TestInstallWithCA_DNS1, self).test_replica2_ipa_dns_install()


class TestInstallWithCA_DNS2(InstallTestBase2):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica0_with_ca_kra_dns_install(self):
        super(
            TestInstallWithCA_DNS2, self
        ).test_replica0_with_ca_kra_dns_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica1_ipa_kra_install(self):
        super(TestInstallWithCA_DNS2, self).test_replica1_ipa_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_ipa_kra_install(self):
        super(TestInstallWithCA_DNS2, self).test_replica2_ipa_kra_install()


@pytest.mark.cs_acceptance
class TestInstallWithCA_KRA_DNS1(InstallTestBase1):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)

    def test_replica0_ipa_kra_install(self):
        tasks.install_kra(self.replicas[0], first_instance=False)


class TestInstallWithCA_KRA_DNS2(InstallTestBase2):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)


class TestADTrustInstall(ADTrustInstallTestBase):
    """
    Tests built-in AD trust installation in various combinations (see the base
    class for more details) against plain IPA master (no DNS, no KRA, no AD
    trust)
    """
    pass


class TestADTrustInstallWithDNS_KRA_ADTrust(ADTrustInstallTestBase):
    """
    Tests built-in AD trust installation in various combinations (see the base
    class for more details) against fully equipped (DNS, CA, KRA, ADtrust)
    master. Additional two test cases were added to test interplay including
    KRA installer
    """

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True,
                             setup_adtrust=True)

    def test_replica1_all_components_adtrust(self):
        self.install_replica(self.replicas[1], setup_ca=True, setup_kra=True)


##
# Rest of master installation tests
##

class TestInstallMaster(IntegrationTest):

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        pass

    def test_install_master(self):
        tasks.install_master(self.master, setup_dns=False)

    def test_install_kra(self):
        tasks.install_kra(self.master, first_instance=True)

    def test_install_dns(self):
        tasks.install_dns(self.master)


class TestInstallMasterKRA(IntegrationTest):

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        pass

    def test_install_master(self):
        tasks.install_master(self.master, setup_dns=False, setup_kra=True)

    def test_install_dns(self):
        tasks.install_dns(self.master)


class TestInstallMasterDNS(IntegrationTest):

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        pass

    def test_install_master(self):
        tasks.install_master(self.master, setup_dns=True)

    def test_install_kra(self):
        tasks.install_kra(self.master, first_instance=True)
