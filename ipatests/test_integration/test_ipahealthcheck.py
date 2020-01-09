# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Tests to verify that the ipa-healthcheck scenarios
"""

from __future__ import absolute_import

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipalib import api
from ipapython.ipaldap import realm_to_serverid

import json

HEALTHCHECK_LOG = "/var/log/ipa/healthcheck/healthcheck.log"
HEALTHCHECK_SYSTEMD_FILE = (
    "/etc/systemd/system/multi-user.target.wants/ipa-healthcheck.timer"
)
HEALTHCHECK_LOG_ROTATE_CONF = "/etc/logrotate.d/ipahealthcheck"
HEALTHCHECK_LOG_DIR = "/var/log/ipa/healthcheck"
HEALTHCHECK_OUTPUT_FILE = "/tmp/output.json"
HEALTHCHECK_PKG = ['freeipa-healthcheck']
TOMCAT_CFG = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg"


sources = [
    "ipahealthcheck.dogtag.ca",
    "ipahealthcheck.ds.replication",
    "ipahealthcheck.dogtag.ca",
    "ipahealthcheck.ipa.certs",
    "ipahealthcheck.ipa.dna",
    "ipahealthcheck.ipa.idns",
    "ipahealthcheck.ipa.files",
    "ipahealthcheck.ipa.host",
    "ipahealthcheck.ipa.roles",
    "ipahealthcheck.ipa.topology",
    "ipahealthcheck.ipa.trust",
    "ipahealthcheck.meta.services",
]

ipa_cert_checks = [
    "IPACertmongerExpirationCheck",
    "IPACertfileExpirationCheck",
    "IPACertTracking",
    "IPACertNSSTrust",
    "IPANSSChainValidation",
    "IPAOpenSSLChainValidation",
    "IPARAAgent",
    "IPACertRevocation",
    "IPACertmongerCA",
    "IPACAChainExpirationCheck",
]

ipatrust_checks = [
    "IPATrustAgentCheck",
    "IPATrustDomainsCheck",
    "IPADomainCheck",
    "IPATrustCatalogCheck",
    "IPAsidgenpluginCheck",
    "IPATrustAgentMemberCheck",
    "IPATrustControllerPrincipalCheck",
    "IPATrustControllerServiceCheck",
    "IPATrustControllerConfCheck",
    "IPATrustControllerGroupSIDCheck",
    "IPATrustPackageCheck",
]

metaservices_checks = [
    "certmonger",
    "dirsrv",
    "gssproxy",
    "httpd",
    "ipa_custodia",
    "ipa_dnskeysyncd",
    "ipa_otpd",
    "kadmin",
    "krb5kdc",
    "named",
    "pki_tomcatd",
    "sssd",
]

ipafiles_checks = ["IPAFileNSSDBCheck", "IPAFileCheck", "TomcatFileCheck"]
dogtag_checks = ["DogtagCertsConfigCheck", "DogtagCertsConnectivityCheck"]
iparoles_checks = ["IPACRLManagerCheck", "IPARenewalMasterCheck"]
replication_checks = ["ReplicationConflictCheck"]
ruv_checks = ["RUVCheck"]
dna_checks = ["IPADNARangeCheck"]
idns_checks = ["IPADNSSystemRecordsCheck"]
ipahost_checks = ["IPAHostKeytab"]
ipatopology_checks = ["IPATopologyDomainCheck"]
filesystem_checks = ["FileSystemSpaceCheck"]
metacore_checks = ["MetaCheck"]

DEFAULT_PKI_CA_CERTS = [
    "caSigningCert cert-pki-ca",
    "ocspSigningCert cert-pki-ca",
    "subsystemCert cert-pki-ca",
    "auditSigningCert cert-pki-ca",
    "Server-Cert cert-pki-ca",
]
DEFAULT_PKI_KRA_CERTS = [
    "transportCert cert-pki-kra",
    "storageCert cert-pki-kra",
    "auditSigningCert cert-pki-kra",
]


class TestIpaHealthCheck(IntegrationTest):
    """
    Tier-1 test for ipa-healthcheck tool with IPA Master setup with
    dns and IPA Replica with dns enabled
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)

    def test_ipa_healthcheck_install_on_master(self):
        """
        Testcase to check healthcheck package is installed
        succesfully on IPA master.
        """
        tasks.install_packages(self.master, HEALTHCHECK_PKG)

    def test_ipa_healthcheck_install_on_replica(self):
        """
        Testcase to check healthcheck package is installed
        succesfully on IPA replica.
        """
        tasks.install_packages(self.replicas[0], HEALTHCHECK_PKG)

    def test_run_ipahealthcheck_list_source(self):
        """
        Testcase to verify sources available in healthcheck tool.
        """
        result = self.master.run_command(["ipa-healthcheck", "--list-sources"])
        for source in sources:
            assert source in result.stdout_text

    def test_dogtag_ca_check_exists(self):
        """
        Testcase to verify checks available in
        ipahealthcheck.dogtag.ca source
        """
        result = self.master.run_command(
            ["ipa-healthcheck", "--source", "ipahealthcheck.dogtag.ca"]
        )
        for check in dogtag_checks:
            assert check in result.stdout_text

    def test_replication_check_exists(self):
        """
        Testcase to verify checks available in
        ipahealthcheck.ds.replication source
        """
        result = self.master.run_command(
            ["ipa-healthcheck", "--source", "ipahealthcheck.ds.replication"]
        )
        for check in replication_checks:
            assert check in result.stdout_text

    def test_ipa_cert_check_exists(self):
        """
        Testcase to verify checks available in
        ipahealthcheck.ipa.certs source
        """
        result = self.master.run_command(
            ["ipa-healthcheck", "--source", "ipahealthcheck.ipa.certs"]
        )
        for check in ipa_cert_checks:
            assert check in result.stdout_text

    def test_ipa_trust_check_exists(self):
        """
        Testcase to verify checks available in
        ipahealthcheck.ipa.trust source
        """
        result = self.master.run_command(
            ["ipa-healthcheck", "--source", "ipahealthcheck.ipa.trust"]
        )
        for check in ipatrust_checks:
            assert check in result.stdout_text

    def test_source_ipahealthcheck_meta_services_check_sssd(self):
        """
        Testcase checks behaviour of check sssd in
        ipahealthcheck.meta.services when service is stopped and started
        respectively
        """
        self.master.run_command(["systemctl", "stop", "sssd"])
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.meta.services",
                "--check",
                "sssd",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == "sssd: not running"
            assert check["kw"]["status"] is False
        self.master.run_command(["systemctl", "start", "sssd"])
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.meta.services",
                "--check",
                "sssd",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        assert data[0]["check"] == "sssd"
        assert data[0]["result"] == "SUCCESS"
        assert data[0]["kw"]["status"] is True

    def test_source_ipahealthcheck_dogtag_ca_dogtagcertsconfigcheck(self):
        """
        Testcase checks behaviour of check DogtagCertsConfigCheck in
        ipahealthcheck.dogtag.ca when tomcat config file is removed
        """
        result = self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.dogtag.ca",
                "--check",
                "DogtagCertsConfigCheck",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["configfile"] == TOMCAT_CFG
            assert check["kw"]["key"] in DEFAULT_PKI_CA_CERTS
        self.master.run_command(["mv", TOMCAT_CFG, TOMCAT_CFG + ".old"])
        result = self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.dogtag.ca",
                "--check",
                "DogtagCertsConfigCheck",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        assert result.returncode == 1
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        assert data[0]["result"] == "CRITICAL"
        self.master.run_command(["mv", TOMCAT_CFG + ".old", TOMCAT_CFG])
        self.master.run_command(["ipactl", "restart"])

    def test_source_ipahealthcheck_meta_core_metacheck(self):
        """
        Testcase checks behaviour of check MetaCheck in source
        ipahealthcheck.meta.core when run on IPA master
        """
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.meta.core",
                "--check",
                "MetaCheck",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        assert data[0]["result"] == "SUCCESS"
        result = self.master.run_command(
            [
                "python3",
                "-c",
                'from ipapython import version; '
                'print("%s\t%s" % (version.VERSION, version.API_VERSION))',
            ]
        )
        assert data[0]["kw"]["ipa_version"] in result.stdout_text
        assert data[0]["kw"]["ipa_api_version"] in result.stdout_text

    def test_source_ipahealthcheck_ipa_host_check_ipahostkeytab(self):
        """
        Testcase checks behaviour of check IPAHostKeytab in source
        ipahealthcheck.ipa.host when dirsrv service is stopped and
        running on IPA master
        """
        msg = (
            "Failed to obtain host TGT: Major (851968): "
            "Unspecified GSS failure.  "
            "Minor code may provide more information, "
            "Minor (2529638972): Generic error (see e-text)"
        )
        dirsrv_ipactl_status = 'Directory Service: STOPPED'
        api.env.realm = self.master.domain.name
        serverid = (realm_to_serverid(api.env.realm)).upper()
        dirsrv_service = "dirsrv@%s.service" % serverid
        self.master.run_command(["systemctl", "stop", dirsrv_service])
        result = self.master.run_command(
            ["ipactl", "status"])
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.ipa.host",
                "--check",
                "IPAHostKeytab",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        if dirsrv_ipactl_status in result.stdout_text:
            assert data[0]["result"] == "ERROR"
            assert data[0]["kw"]["msg"] == msg
        else:
            assert data[0]["result"] == "SUCCESS"
        self.master.run_command(["systemctl", "start", dirsrv_service])

    def test_source_ipahealthcheck_topology_IPATopologyDomainCheck(self):
        """
        Testcase checks default behaviour of check IPATopologyDomainCheck in
        source ipahealthcheck.ipa.topology on IPA Master
        """
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.ipa.topology",
                "--check",
                "IPATopologyDomainCheck",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        for check in data:
            assert check["result"] == "SUCCESS"
            assert (
                check["kw"]["suffix"] == "domain" or
                check["kw"]["suffix"] == "ca"
            )

    def test_source_ipa_roles_check_crlmanager(self):
        """
        This testcase checks the status of healthcheck tool
        reflects correct information when crlgen is disabled
        using ipa-crl-manage disable
        """
        self.master.run_command(["ipa-crlgen-manage", "disable"])
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.ipa.roles",
                "--check",
                "IPACRLManagerCheck",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "crl_manager"
            assert check["kw"]["crlgen_enabled"] is False

    def test_ipa_healthcheck_remove(self):
        """
        This testcase checks the removal of of healthcheck tool
        on replica and master
        """
        tasks.uninstall_packages(self.master, HEALTHCHECK_PKG)
        tasks.uninstall_packages(self.replicas[0], HEALTHCHECK_PKG)


class TestIpaHealthCheckWithoutDNS(IntegrationTest):
    """
    Test for ipa-healthcheck tool with IPA Master without DNS installed
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.uninstall_replica(cls.master, cls.replicas[0])
        tasks.uninstall_master(cls.master)
        tasks.install_master(cls.master, setup_dns=False)

    def test_ipa_dns_systemrecords_check(self):
        """
        Test checks the result of IPADNSSystemRecordsCheck
        when ipa-server is configured without DNS.
        """
        msg1 = "Expected SRV record missing"
        msg2 = "Got {count} ipa-ca A records, expected {expected}"
        tasks.install_packages(self.master, HEALTHCHECK_PKG)
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.ipa.idns",
                "--check",
                "IPADNSSystemRecordsCheck",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["msg"] == msg1 or check["kw"]["msg"] == msg2

    def test_ipa_certs_check_ipacertnsstrust(self):
        """
        Test checks the output for IPACertNSSTrust when kra is installed
        on the IPA system using ipa-kra-install
        """
        cmd = tasks.install_kra(self.master)
        assert cmd.returncode == 0
        tasks.install_packages(self.master, HEALTHCHECK_PKG)
        self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.ipa.certs",
                "--check",
                "IPACertNSSTrust",
                "--output-file",
                HEALTHCHECK_OUTPUT_FILE,
            ],
            raiseonerr=False,
        )
        contents = self.master.get_file_contents(
            HEALTHCHECK_OUTPUT_FILE, encoding="utf-8"
        )
        data = json.loads(contents)
        for check in data:
            assert check["result"] == "SUCCESS"
            assert (
                check["kw"]["key"] in DEFAULT_PKI_CA_CERTS or
                check["kw"]["key"] in DEFAULT_PKI_KRA_CERTS
            )
        tasks.uninstall_master(self.master)
