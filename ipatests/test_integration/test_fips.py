#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""Smoke tests for FreeIPA installation in (fake) userspace FIPS mode
"""
import pytest

from ipapython.ipautil import ipa_generate_password

from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration import fips
from ipatests.test_integration.base import IntegrationTest

from .test_dnssec import (
    test_zone,
    dnssec_install_master,
    dnszone_add_dnssec,
    wait_until_record_is_signed,
)


def check_version(host):
    if tasks.get_pki_version(host) < tasks.parse_version('11.6.0'):
        raise pytest.skip("PKI replica FIPS support is not available, "
                          "https://github.com/dogtagpki/pki/issues/4847")


class TestInstallFIPS(IntegrationTest):
    num_replicas = 1
    num_clients = 1
    fips_mode = True

    @classmethod
    def install(cls, mh):
        check_version(cls.replicas[0])
        super(TestInstallFIPS, cls).install(mh)
        # sanity check
        for host in cls.get_all_hosts():
            assert host.is_fips_mode
            assert fips.is_fips_enabled(host)
        # master with CA, KRA, DNS+DNSSEC
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        # replica with CA, KRA, DNS
        tasks.install_replica(
            cls.master,
            cls.replicas[0],
            setup_dns=True,
            setup_ca=True,
            setup_kra=True,
        )
        tasks.install_clients([cls.master] + cls.replicas, cls.clients)

    @classmethod
    def uninstall(cls, mh):
        check_version(cls.replicas[0])
        super(TestInstallFIPS, cls).uninstall(mh)

    def test_basic(self):
        client = self.clients[0]
        tasks.kinit_admin(client)
        client.run_command(["ipa", "ping"])

    def test_dnssec(self):
        dnssec_install_master(self.master)
        # DNSSEC zone
        dnszone_add_dnssec(self.master, test_zone)
        assert wait_until_record_is_signed(
            self.master.ip, test_zone, timeout=100
        ), ("Zone %s is not signed (master)" % test_zone)

        # test replica
        assert wait_until_record_is_signed(
            self.replicas[0].ip, test_zone, timeout=200
        ), ("DNS zone %s is not signed (replica)" % test_zone)

    def test_vault_basic(self):
        vault_name = "testvault"
        vault_password = ipa_generate_password()
        vault_data = "SSBsb3ZlIENJIHRlc3RzCg=="
        # create vault
        self.master.run_command(
            [
                "ipa",
                "vault-add",
                vault_name,
                "--password",
                vault_password,
                "--type",
                "symmetric",
            ]
        )

        # archive secret
        self.master.run_command(
            [
                "ipa",
                "vault-archive",
                vault_name,
                "--password",
                vault_password,
                "--data",
                vault_data,
            ]
        )
        self.master.run_command(
            [
                "ipa",
                "vault-retrieve",
                vault_name,
                "--password",
                vault_password,
            ]
        )
