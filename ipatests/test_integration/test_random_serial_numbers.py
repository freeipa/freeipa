#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

import pytest
import textwrap

from ipaplatform.paths import paths

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_installation import (
    TestInstallWithCA_DNS1,
    TestInstallWithCA_KRA1,
)
from ipatests.test_integration.test_caless import TestServerCALessToExternalCA
from ipatests.test_integration.test_vault import TestInstallKRA
from ipatests.test_integration.test_commands import TestIPACommand


def pki_supports_RSNv3(host):
    """
    Return whether the host supports RNSv3 based on the pki version
    """
    script = ("from ipaserver.install.ca import "
              "random_serial_numbers_version; "
              "print(random_serial_numbers_version(True))")
    result = host.run_command(['python3', '-c', script])
    if 'true' in result.stdout_text.strip().lower():
        return True
    return False


def check_pki_config_params(host):
    # Check CS.cfg
    try:
        cs_cfg = host.get_file_contents(paths.CA_CS_CFG_PATH)
        kra_cfg = host.get_file_contents(paths.KRA_CS_CFG_PATH)
        assert "dbs.cert.id.generator=random".encode() in cs_cfg
        assert "dbs.request.id.generator=random".encode() in cs_cfg
        assert "dbs.key.id.generator=random".encode() in kra_cfg
    except IOError:
        pytest.skip("PKI config not present.Skipping test")


class TestInstallWithCA_DNS1_RSN(TestInstallWithCA_DNS1):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestInstallWithCA_DNS1_RSN, cls).install(mh)


class TestInstallWithCA_KRA1_RSN(TestInstallWithCA_KRA1):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestInstallWithCA_KRA1_RSN, cls).install(mh)


class TestIPACommand_RSN(TestIPACommand):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestIPACommand_RSN, cls).install(mh)


class TestServerCALessToExternalCA_RSN(TestServerCALessToExternalCA):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        super(TestServerCALessToExternalCA_RSN, cls).install(mh)

    @classmethod
    def uninstall(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RSNv3 not supported")
        super(TestServerCALessToExternalCA_RSN, cls).uninstall(mh)


class TestRSNPKIConfig(TestInstallWithCA_KRA1):
    random_serial = True
    num_replicas = 3

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RSNv3 not supported")
        super(TestRSNPKIConfig, cls).install(mh)

    def test_check_pki_config(self):
        check_pki_config_params(self.master)
        check_pki_config_params(self.replicas[0])
        check_pki_config_params(self.replicas[1])

    def test_check_rsn_version(self):
        tasks.kinit_admin(self.master)
        res = self.master.run_command(['ipa', 'ca-find'])
        assert 'RSN Version: 3' in res.stdout_text
        tasks.kinit_admin(self.replicas[0])
        res = self.replicas[0].run_command(['ipa', 'ca-find'])
        assert 'RSN Version: 3' in res.stdout_text


class TestRSNVault(TestInstallKRA):
    random_serial = True

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RSNv3 not supported")
        super(TestRSNVault, cls).install(mh)


class TestInstall_RSN_MDB(IntegrationTest):
    """
    Test installation when the 389-ds mdb backend is used. This has
    poor performance for VLV compared to the older bdb backend so
    RSN will be required.
    """
    num_replicas = 1

    def disable_rsn(self):
        """Mark RSN as disabled in the topology by setting
           ipaCaRandomSerialNumberVersion to 0.
        """
        entry_ldif = textwrap.dedent("""
            dn: cn=ipa,cn=cas,cn=ca,{base_dn}
            changetype: modify
            replace: ipaCaRandomSerialNumberVersion
            ipaCaRandomSerialNumberVersion: 0
        """).format(base_dn=str(self.master.domain.basedn))
        tasks.ldapmodify_dm(self.master, entry_ldif)

    def check_rsn_status(self, host):
        """Verify that RSN is enabled on a host"""
        base_dn = str(host.domain.basedn)
        result = tasks.ldapsearch_dm(
            host,
            'cn=ipa,cn=cas,cn=ca,{base_dn}'.format(
                base_dn=base_dn),
            ['ipacarandomserialnumberversion',],
            scope='base'
        )
        output = result.stdout_text.lower()
        assert 'ipacarandomserialnumberversion: 3' in output

        cs_cfg = host.get_file_contents(paths.CA_CS_CFG_PATH)
        assert "dbs.cert.id.generator=random".encode() in cs_cfg

    @classmethod
    def install(cls, mh):
        if not pki_supports_RSNv3(mh.master):
            raise pytest.skip("RNSv3 not supported")
        result = cls.replicas[0].run_command(
            "python -c 'from lib389.utils import get_default_db_lib; "
            "print(get_default_db_lib())'"
        )
        if 'mdb' not in result.stdout_text:
            raise pytest.skip("MDB not supported")
        tasks.install_master(cls.master, setup_dns=True)

    def test_replica_install(self):
        self.disable_rsn()
        tasks.install_replica(
            self.master, self.replicas[0], setup_ca=True)
        self.check_rsn_status(self.replicas[0])
        tasks.run_server_del(
            self.master, self.replicas[0].hostname, force=True,
            ignore_topology_disconnect=True, ignore_last_of_role=True)
        tasks.uninstall_replica(
            master=self.master,
            replica=self.replicas[0]
        )

    def test_replica_install_noca(self):
        self.disable_rsn()
        tasks.install_replica(
            self.master, self.replicas[0], setup_ca=False)
        tasks.install_ca(self.replicas[0])
        self.check_rsn_status(self.replicas[0])
