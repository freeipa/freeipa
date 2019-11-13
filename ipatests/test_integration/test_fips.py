#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""Smoke tests for FreeIPA installation in (fake) userspace FIPS mode
"""
from ipapython.dn import DN
from ipapython.ipautil import ipa_generate_password, realm_to_suffix

from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration import fips
from ipatests.test_integration.base import IntegrationTest

from .test_dnssec import (
    test_zone,
    dnssec_install_master,
    dnszone_add_dnssec,
    wait_until_record_is_signed,
)


class TestInstallFIPS(IntegrationTest):
    num_replicas = 1
    num_clients = 1
    fips_mode = True

    @classmethod
    def install(cls, mh):
        super(TestInstallFIPS, cls).install(mh)
        # sanity check
        for host in cls.get_all_hosts():
            assert host.is_fips_mode
            assert fips.is_fips_enabled(host)
        # patch named-pkcs11 crypto policy
        # see RHBZ#1772111
        for host in [cls.master] + cls.replicas:
            host.run_command(
                [
                    "sed",
                    "-i",
                    "-E",
                    "s/RSAMD5;//g",
                    "/etc/crypto-policies/back-ends/bind.config",
                ]
            )
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

    def test_krb_enctypes(self):
        realm = self.master.domain.realm
        suffix = realm_to_suffix(realm)
        dn = DN(("cn", realm), ("cn", "kerberos")) + suffix
        args = ["krbSupportedEncSaltTypes", "krbDefaultEncSaltTypes"]
        for host in [self.master] + self.replicas:
            result = tasks.ldapsearch_dm(host, str(dn), args, scope="base")
            assert "camellia" not in result.stdout_text
            assert "aes256-cts" in result.stdout_text
            assert "aes128-cts" in result.stdout_text
        # test that update does not add camellia
        self.master.run_command(["ipa-server-upgrade"])
        result = tasks.ldapsearch_dm(self.master, str(dn), args, scope="base")
        assert "camellia" not in result.stdout_text
