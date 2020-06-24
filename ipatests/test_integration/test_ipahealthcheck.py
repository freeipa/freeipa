# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Tests to verify that the ipa-healthcheck scenarios
"""

from __future__ import absolute_import

import json
import re

import pytest

from ipalib import api
from ipapython.ipaldap import realm_to_serverid
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest

HEALTHCHECK_LOG = "/var/log/ipa/healthcheck/healthcheck.log"
HEALTHCHECK_SYSTEMD_FILE = (
    "/etc/systemd/system/multi-user.target.wants/ipa-healthcheck.timer"
)
HEALTHCHECK_LOG_ROTATE_CONF = "/etc/logrotate.d/ipahealthcheck"
HEALTHCHECK_LOG_DIR = "/var/log/ipa/healthcheck"
HEALTHCHECK_OUTPUT_FILE = "/tmp/output.json"
HEALTHCHECK_PKG = ["*ipa-healthcheck"]
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

TOMCAT_CONFIG_FILES = (
    paths.PKI_TOMCAT_PASSWORD_CONF,
    paths.PKI_TOMCAT_SERVER_XML,
    paths.CA_CS_CFG_PATH,
)


def run_healthcheck(host, source=None, check=None, output_type="json",
                    failures_only=False):
    """
    Run ipa-healthcheck on the remote host and return the result

    Returns: the tuple returncode, output

    output is:
        json data if output_type == "json"
        stdout if output_type == "human"
    """
    data = None
    cmd = ["ipa-healthcheck"]
    if source:
        cmd.append("--source")
        cmd.append(source)

        if check:
            cmd.append("--check")
            cmd.append(check)

    cmd.append("--output-type")
    cmd.append(output_type)

    if failures_only:
        cmd.append("--failures-only")

    result = host.run_command(cmd, raiseonerr=False)

    if result.stdout_text:
        if output_type == "json":
            data = json.loads(result.stdout_text)
        else:
            data = result.stdout_text.strip()

    return result.returncode, data


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

    def test_human_output(self):
        """
        Test that in human output the severity value is correct

        Only the SUCCESS (0) value was being translated, otherwise
        the numeric value was being shown (BZ 1752849)
        """
        self.master.run_command(["systemctl", "stop", "sssd"])
        try:
            returncode, output = run_healthcheck(
                self.master,
                "ipahealthcheck.meta.services",
                "sssd",
                "human",
            )
        finally:
            self.master.run_command(["systemctl", "start", "sssd"])

        assert returncode == 1
        assert output == \
            "ERROR: ipahealthcheck.meta.services.sssd: sssd: not running"

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
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.meta.services",
            "sssd",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == "sssd: not running"
            assert check["kw"]["status"] is False
        self.master.run_command(["systemctl", "start", "sssd"])
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.meta.services",
            "sssd",
        )
        assert returncode == 0
        assert data[0]["check"] == "sssd"
        assert data[0]["result"] == "SUCCESS"
        assert data[0]["kw"]["status"] is True

    def test_source_ipahealthcheck_dogtag_ca_dogtagcertsconfigcheck(self):
        """
        Testcase checks behaviour of check DogtagCertsConfigCheck in
        ipahealthcheck.dogtag.ca when tomcat config file is removed
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.dogtag.ca",
            "DogtagCertsConfigCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["configfile"] == TOMCAT_CFG
            assert check["kw"]["key"] in DEFAULT_PKI_CA_CERTS
        self.master.run_command(["mv", TOMCAT_CFG, TOMCAT_CFG + ".old"])
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.dogtag.ca",
            "DogtagCertsConfigCheck",
        )
        assert returncode == 1
        assert data[0]["result"] == "CRITICAL"
        self.master.run_command(["mv", TOMCAT_CFG + ".old", TOMCAT_CFG])
        self.master.run_command(["ipactl", "restart"])

    @pytest.fixture
    def restart_tomcat(self):
        """Fixture to Stop and then start tomcat instance during test"""
        self.master.run_command(
            ["systemctl", "stop", "pki-tomcatd@pki-tomcat"]
        )
        yield
        self.master.run_command(
            ["systemctl", "start", "pki-tomcatd@pki-tomcat"]
        )

    def test_ipahealthcheck_dogtag_ca_connectivity_check(self, restart_tomcat):
        """
        This testcase checks that when the pki-tomcat service is stopped,
        DogtagCertsConnectivityCheck displays the result as ERROR.
        """
        error_msg = (
            "Request for certificate failed, "
            "Certificate operation cannot be completed: "
            "Unable to communicate with CMS (503)"
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.dogtag.ca",
            "DogtagCertsConnectivityCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == error_msg

    def test_source_ipahealthcheck_meta_core_metacheck(self):
        """
        Testcase checks behaviour of check MetaCheck in source
        ipahealthcheck.meta.core when run on IPA master
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.meta.core",
            "MetaCheck",
        )
        assert returncode == 0
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
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.host",
            "IPAHostKeytab",
        )
        assert returncode == 1
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
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.topology",
            "IPATopologyDomainCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert (
                check["kw"]["suffix"] == "domain" or
                check["kw"]["suffix"] == "ca"
            )

    @pytest.fixture
    def disable_crlgen(self):
        """Fixture to disable crlgen then enable it once test is done"""
        self.master.run_command(["ipa-crlgen-manage", "disable"])
        yield
        self.master.run_command(["ipa-crlgen-manage", "enable"])

    def test_source_ipa_roles_check_crlmanager(self, disable_crlgen):
        """
        This testcase checks the status of healthcheck tool
        reflects correct information when crlgen is disabled
        using ipa-crl-manage disable
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.roles",
            "IPACRLManagerCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "crl_manager"
            assert check["kw"]["crlgen_enabled"] is False

    def test_ipa_healthcheck_no_errors(self):
        """
        Ensure that on a default installation with KRA and DNS
        installed ipa-healthcheck runs with no errors.
        """
        cmd = tasks.install_kra(self.master)
        assert cmd.returncode == 0
        returncode, _unused = run_healthcheck(
            self.master,
            failures_only=True
        )
        assert returncode == 0

    def test_ipa_healthcheck_dna_plugin_returns_warning_pagure_issue_60(self):
        """
        This testcase checks that the status for IPADNARangeCheck on replica
        changes from WARNING to SUCCESS when user is added on the replica
        as the DNA range is set.
        Issue: freeipa/freeipa-healthcheck#60
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.dna",
            "IPADNARangeCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
        # Install ipa-healthcheck rpm on replica
        tasks.install_packages(self.replicas[0], HEALTHCHECK_PKG)
        returncode, data = run_healthcheck(
            self.replicas[0],
            "ipahealthcheck.ipa.dna",
            "IPADNARangeCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert (
                check["kw"]["msg"] == "No DNA range defined. If no masters "
                "define a range then users and groups cannot be created."
            )

        # Now kinit as admin and add a user on replica which will create a
        # DNA configuration.
        tasks.kinit_admin(self.replicas[0])
        tasks.user_add(
            self.replicas[0], 'ipauser1', first='Test', last='User',
        )
        # Now run the ipa-healthcheck command again
        returncode, data = run_healthcheck(
            self.replicas[0],
            "ipahealthcheck.ipa.dna",
            "IPADNARangeCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"

    def test_ipa_healthcheck_log_rotate_file_exist_issue35(self):
        """
        This test checks if log rotation has been added
        for ipa-healthcheck tool so that logs are rotated
        in /var/log/ipa/healthcheck folder.
        The test also checks that the logrotate configuration
        file is syntactically correct by calling logrotate --debug
        This is a testcase for below pagure issue
        https://github.com/freeipa/freeipa-healthcheck/issues/35
        """
        msg = "error: {}:".format(HEALTHCHECK_LOG_ROTATE_CONF)
        tasks.uninstall_packages(self.master, HEALTHCHECK_PKG)
        assert not self.master.transport.file_exists(
            HEALTHCHECK_LOG_ROTATE_CONF
        )
        tasks.install_packages(self.master, HEALTHCHECK_PKG)
        assert self.master.transport.file_exists(HEALTHCHECK_LOG_ROTATE_CONF)
        cmd = self.master.run_command(
            ['logrotate', '--debug', HEALTHCHECK_LOG_ROTATE_CONF]
        )
        assert msg not in cmd.stdout_text

    def test_ipa_dns_systemrecords_check(self):
        """
        This test ensures that the ipahealthcheck.ipa.idns check
        displays the correct result when master and replica is setup
        with integrated DNS.
        """
        SRV_RECORDS = [
            "_ldap._tcp." + self.replicas[0].domain.name + ".:" +
            self.replicas[0].hostname + ".",
            "_ldap._tcp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "_kerberos._tcp." + self.replicas[0].domain.name + ".:" +
            self.replicas[0].hostname + ".",
            "_kerberos._tcp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "_kerberos._udp." + self.replicas[0].domain.name + ".:" +
            self.replicas[0].hostname + ".",
            "_kerberos._udp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "_kerberos-master._tcp." + self.replicas[0].domain.name +
            ".:" + self.replicas[0].hostname + ".",
            "_kerberos-master._tcp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "_kerberos-master._udp." + self.replicas[0].domain.name +
            ".:" + self.replicas[0].hostname + ".",
            "_kerberos-master._udp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "_kpasswd._tcp." + self.replicas[0].domain.name + ".:" +
            self.replicas[0].hostname + ".",
            "_kpasswd._tcp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "_kpasswd._udp." + self.replicas[0].domain.name + ".:" +
            self.replicas[0].hostname + ".",
            "_kpasswd._udp." + self.master.domain.name + ".:" +
            self.master.hostname + ".",
            "\"" + self.master.domain.realm.upper() + "\"",
            self.master.ip,
            self.replicas[0].ip
        ]
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.idns",
            "IPADNSSystemRecordsCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] in SRV_RECORDS

    def test_ipa_healthcheck_ds_ruv_check(self):
        """
        This testcase checks that ipa-healthcheck tool with RUVCheck
        discovers the same RUV entries as the ipa-replica-manage list-ruv
        command
        """
        result = self.master.run_command(
            [
                "ipa-replica-manage",
                "list-ruv",
                "-p",
                self.master.config.dirman_password,
            ]
        )
        output = re.findall(
            r"\w+.+.\w+.\w:\d+", result.stdout_text.replace("389: ", "")
        )
        ruvs = []
        for r in output:
            (host, r) = r.split(":")
            if host == self.master.hostname:
                ruvs.append(r)
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ds.ruv", "RUVCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] in (self.master.domain.basedn, "o=ipaca")
            assert check["kw"]["ruv"] in ruvs
            ruvs.remove(check["kw"]["ruv"])
        assert not ruvs

    @pytest.fixture
    def change_tomcat_mode(self):
        for files in TOMCAT_CONFIG_FILES:
            self.master.run_command(["chmod", "600", files])
        yield
        for files in TOMCAT_CONFIG_FILES:
            self.master.run_command(["chmod", "660", files])

    def test_ipa_healthcheck_tomcatfilecheck(self, change_tomcat_mode):
        """
        This testcase changes the permissions of the tomcat configuration file
        on an IPA Master and then checks if healthcheck tools reports the ERROR
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.files", "TomcatFileCheck"
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["type"] == "mode":
                assert check["kw"]["expected"] == "0660"
                assert check["kw"]["got"] == "0600"
                assert check["result"] == "ERROR"
                assert check["kw"]["path"] in TOMCAT_CONFIG_FILES
                assert (
                    check["kw"]["msg"]
                    == "Permissions of %s are too restrictive: "
                       "0600 and should be 0660"
                    % check["kw"]["path"]
                )

    @pytest.fixture
    def change_tomcat_owner(self):
        """Fixture to change owner of tomcat config during test"""
        for file in TOMCAT_CONFIG_FILES:
            self.master.run_command(["chown", "root.root", file])
        yield
        for file in TOMCAT_CONFIG_FILES:
            self.master.run_command(["chown", "pkiuser.pkiuser", file])

    def test_ipa_healthcheck_tomcatfile_owner(self, change_tomcat_owner):
        """
        This testcase changes the ownership of the tomcat config files
        on an IPA Master and then checks if healthcheck tools
        reports the status as WARNING
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.files", "TomcatFileCheck"
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["type"] == "owner":
                assert check["kw"]["expected"] == "pkiuser"
                assert check["kw"]["got"] == "root"
                assert check["result"] == "WARNING"
                assert check["kw"]["path"] in TOMCAT_CONFIG_FILES
                assert (
                    check["kw"]["msg"]
                    == "Ownership of %s is root and should be pkiuser"
                    % check["kw"]["path"]
                )
            elif check["kw"]["type"] == "group":
                assert check["kw"]["expected"] == "pkiuser"
                assert check["kw"]["got"] == "root"
                assert check["result"] == "WARNING"
                assert check["kw"]["path"] in TOMCAT_CONFIG_FILES
                assert (
                    check["kw"]["msg"]
                    == "Group of %s is root and should be pkiuser"
                    % check["kw"]["path"]
                )

    def test_ipa_healthcheck_without_trust_setup(self):
        """
        This testcase checks that when trust isn't setup between IPA
        server and Windows AD, IPADomainCheck displays key value as
        domain-check and result is SUCCESS
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPADomainCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "domain-check"

    def test_ipa_healthcheck_output_indent(self):
        """
        This test case checks whether default (2) indentation is applied
        to output without it being implicitly stated
        """
        cmd = self.master.run_command(["ipa-healthcheck",
                                       "--source",
                                       "ipahealthcheck.meta.services"],
                                      raiseonerr=False)
        output_str = cmd.stdout_text
        output_json = json.loads(output_str)
        assert output_str == "{}\n".format(json.dumps(output_json, indent=2))

    @pytest.fixture
    def ipactl(self):
        """Stop and start IPA during test"""
        self.master.run_command(["ipactl", "stop"])
        yield
        self.master.run_command(["ipactl", "start"])

    def test_run_with_stopped_master(self, ipactl):
        """
        Test output of healthcheck where master IPA services are stopped
        contains only errors regarding master being stopped and no other false
        positives.
        """
        returncode, output = run_healthcheck(
            self.master,
            output_type="human",
            failures_only=True)
        assert returncode == 1
        errors = re.findall("ERROR: .*: not running", output)
        assert len(errors) == len(output.split('\n'))

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
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.idns",
            "IPADNSSystemRecordsCheck",
        )
        assert returncode == 1
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
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPACertNSSTrust",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert (
                check["kw"]["key"] in DEFAULT_PKI_CA_CERTS or
                check["kw"]["key"] in DEFAULT_PKI_KRA_CERTS
            )
        tasks.uninstall_master(self.master)


class TestIpaHealthCheckWithADtrust(IntegrationTest):
    """
    Test for ipa-healthcheck tool with IPA Master with trust setup
    with AD system
    """
    topology = "line"
    num_ad_domains = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        cls.ad = cls.ads[0]
        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

    def test_ipahealthcheck_trust_domainscheck(self):
        """
        This testcase checks when trust between IPA-AD is established,
        IPATrustDomainsCheck displays result as SUCCESS and also
        displays ADREALM as sssd/trust domains
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.trust", "IPATrustDomainsCheck"
        )
        assert returncode == 0
        for check in data:
            if check["kw"]["key"] == "domain-list":
                assert check["result"] == "SUCCESS"
                assert (
                    check["kw"]["sssd_domains"] == self.ad.domain.name
                    and check["kw"]["trust_domains"] == self.ad.domain.name
                )
            elif check["kw"]["key"] == "domain-status":
                assert check["result"] == "SUCCESS"
                assert check["kw"]["domain"] == self.ad.domain.name

    def test_ipahealthcheck_trust_catalogcheck(self):
        """
        This testcase checks when trust between IPA-AD is established,
        IPATrustCatalogCheck displays result as SUCCESS and also
        domain value is displayed as ADREALM
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.trust", "IPATrustCatalogCheck"
        )
        assert returncode == 0
        for check in data:
            if check["kw"]["key"] == "AD Global Catalog":
                assert check["result"] == "SUCCESS"
                assert check["kw"]["domain"] == self.ad.domain.name
            elif check["kw"]["key"] == "AD Domain Controller":
                assert check["result"] == "SUCCESS"
                assert check["kw"]["domain"] == self.ad.domain.name

    def test_ipahealthcheck_trustcontoller_conf_check(self):
        """
        This testcase checks when trust between IPA-AD is established,
        IPATrustControllerConfCheck displays result as SUCCESS and also
        displays key as 'net conf list'
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPATrustControllerConfCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "net conf list"

    def test_ipahealthcheck_sidgenpluginCheck(self):
        """
        This testcase checks when trust between IPA-AD is established,
        IPAsidgenpluginCheck displays result as SUCCESS and also
        displays key value as 'ipa-sidgen-task'
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.trust", "IPAsidgenpluginCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert (
                check["kw"]["key"] == "IPA SIDGEN"
                or check["kw"]["key"] == "ipa-sidgen-task"
            )

    def test_ipahealthcheck_controller_service_check(self):
        """
        This testcase checks when trust between IPA-AD is established,
        IPATrustControllerServiceCheck displays result as SUCCESS and also
        displays key value as 'ADTRUST'
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPATrustControllerServiceCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "ADTRUST"

    def test_ipahealthcheck_trust_agent_member_check(self):
        """
        This testcase checks when trust between IPA-AD is established,
        IPATrustAgentMemberCheck displays result as SUCCESS.
        """
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPATrustAgentMemberCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == self.master.hostname


class TestIpaHealthCheckWithExternalCAStep1(IntegrationTest):
    """
    Tests to run and check whether ipa-healthcheck tool reports correct status when
    IPA Master has only Step1 of installation done with external CA.
    """

    topology = 'line'
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(
            cls.master, setup_dns=False, extra_args=["--external-ca"]
        )

    def test_ipahealthcheck_domaincheck(self):
        """
        Test for IPADomainCheck
        """
        error_msg1 = "[Errno 2] No such file or directory: '{}'".format(
            paths.SSSD_CONF
        )
        error_msg2 = "Unable to parse sssd.conf: {error}"
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.trust", "IPADomainCheck"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["key"] == "domain-check"
            assert check["kw"]["error"] == error_msg1
            assert check["kw"]["msg"] == error_msg2

    def test_ipahealthcheck_crlmanagercheck(self):
        """
        Test for IPACRLManagerCheck
        """
        error_msg = "Unable to read {}".format(paths.HTTPD_IPA_PKI_PROXY_CONF)
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.roles", "IPACRLManagerCheck"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["exception"] == error_msg

    def test_ipahealthcheck_ipafilecheck(self):
        """
        Test for IPAFileCheck
        """
        error_msg = "[Errno 2] No such file or directory: '{}'".format(
            paths.RA_AGENT_PEM
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.files", "IPAFileCheck"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["exception"] == error_msg

    def test_ipahealthcheck_ipadnarange(self):
        """
        Test for IPADNARangeCheck
        """
        error_msg = "[Errno 2] {}".format(paths.IPA_CA_CRT)
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.dna", "IPADNARangeCheck"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["exception"] == error_msg

    def test_ipahealthcheck_ipacachainexpiration(self):
        """
        Test for IPACAChainExpirationCheck
        """
        error_msg = (
            "Error opening IPA CA chain at /etc/ipa/ca.crt: "
            "[Errno 2] No such file or directory: "
            "'/etc/ipa/ca.crt'"
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPACAChainExpirationCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == error_msg
            assert check["kw"]["key"] == paths.IPA_CA_CRT

    def test_ipahealthcheck_ipacertrevocation(self):
        """
        Test for IPACertRevocation
        """
        error_msg = "[Errno 2] No such file or directory: '{}'".format(
            paths.HTTPD_CERT_FILE
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPACertRevocation"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["exception"] == error_msg

    def test_ipahealthcheck_iparaagent(self):
        """
        Test for IPARAAgent
        """
        error_msg = "Unable to load RA cert: [Errno 2] No such file or directory: '{}'".format(
            paths.RA_AGENT_PEM
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPARAAgent"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == error_msg

    def test_ipahealthcheck_dogtagcertsconnectivitycheck(self):
        """
        Test for DogtagCertsConnectivityCheck
        """
        error_msg = "Request for certificate failed, CA is not configured"
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.dogtag.ca",
            "DogtagCertsConnectivityCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == error_msg

    def test_ipahealthcheck_ipacertracking(self):
        """
        Test for IPACertTracking
        """
        error_msg = "[Errno 2] No such file or directory: '{}'".format(
            paths.HTTPD_CERT_FILE
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPACertTracking",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["exception"] == error_msg

    def test_ipahealthcheck_ipacertnsstrust(self):
        """
        Test for IPACertNSSTrust
        """
        msg1 = "Certificate ocspSigningCert cert-pki-ca missing while verifying trust"
        msg2 = "Certificate subsystemCert cert-pki-ca missing while verifying trust"
        msg3 = "Certificate auditSigningCert cert-pki-ca missing while verifying trust"
        msg4 = (
            "Certificate Server-Cert cert-pki-ca missing while verifying trust"
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPACertNSSTrust",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            if check["kw"]["key"] == "ocspSigningCert cert-pki-ca":
                assert check["kw"]["msg"] == msg1
            elif check["kw"]["key"] == "subsystemCert cert-pki-ca":
                assert check["kw"]["msg"] == msg2
            elif check["kw"]["key"] == "auditSigningCert cert-pki-ca":
                assert check["kw"]["msg"] == msg3
            elif check["kw"]["key"] == "Server-Cert cert-pki-ca":
                assert check["kw"]["msg"] == msg4

    def test_ipahealthcheck_ipansschainvalidation(self):
        """
        Test for IPANSSChainValidation
        """
        instance = realm_to_serverid(self.master.domain.realm)
        error_msg = (
            "Validation of Server-Cert cert-pki-ca in /etc/pki/pki-tomcat/alias failed:  "
            'certutil: could not find certificate named "Server-Cert cert-pki-ca": '
            "PR_FILE_NOT_FOUND_ERROR: File not found\n"
        )
        reason_msg = (
            ': certutil: could not find certificate named "Server-Cert cert-pki-ca": '
            "PR_FILE_NOT_FOUND_ERROR: File not found\n"
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPANSSChainValidation",
        )
        assert returncode == 1
        for check in data:
            if (
                check["kw"]["dbdir"]
                == paths.PKI_TOMCAT_ALIAS_DIR:
            ):
                assert check["result"] == "ERROR"
                assert check["kw"]["key"] ==  paths.PKI_TOMCAT_ALIAS_DIR +':Server-Cert cert-pki-ca'
                assert check["kw"]["reason"] == reason_msg
                assert check["kw"]["msg"] == error_msg
            elif (
                check["kw"]["dbdir"]
                == paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
            ):
                assert check["result"] == "SUCCESS"
                assert (
                    check["kw"]["key"] == paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance +':Server-Cert'
                )
                assert check["kw"]["nickname"] == "Server-Cert"

    def test_ipahealthcheck_ipaopensslchainvalidatin(self):
        """
        Test for IPAOpenSSLChainValidation
        """
        error_msg1 = (
            "Certificate validation for /var/lib/ipa/certs/httpd.crt failed: "
            "Error loading file /etc/ipa/ca.crt\n"
        error_msg2 = (
            "Certificate validation for /var/lib/ipa/ra-agent.pem failed: "
            "Error loading file /etc/ipa/ca.crt\n"
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPAOpenSSLChainValidation",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            if check["kw"]["key"] == paths.HTTPD_CERT_FILE:
                assert check["kw"]["msg"] == error_msg1
                assert check["kw"][
                    "reason"
                ] == "Error loading file {}\n".format(paths.IPA_CA_CRT)
            elif check["kw"]["key"] == paths.RA_AGENT_PEM:
                assert check["kw"]["msg"] == error_msg2
                assert check["kw"][
                    "reason"
                ] == "Error loading file {}\n".format(paths.IPA_CA_CRT)

    def test_ipahealthcheck_ipacertmongerca(self):
        """
        Test for IPACertmongerCA
        """
        msg1 = "Certmonger CA 'dogtag-ipa-ca-renew-agent' missing"
        msg2 = "Certmonger CA 'dogtag-ipa-ca-renew-agent-reuse' missing"
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPACertmongerCA",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["key"] == "dogtag-ipa-ca-renew-agent":
                assert check["kw"]["msg"] == msg1
                assert check["result"] == "ERROR"
            elif check["kw"]["key"] == "dogtag-ipa-ca-renew-agent-reuse":
                assert check["kw"]["msg"] == msg2
                assert check["result"] == "ERROR"
