# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Tests to verify that the ipa-healthcheck scenarios
"""

from __future__ import absolute_import

from datetime import datetime, timedelta
import json
import os
import re

import pytest

from ipalib import api
from ipalib import x509
from ipapython.ipaldap import realm_to_serverid
from ipapython.certdb import NSS_SQL_FILES
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

    @pytest.fixture
    def move_ipa_ca_crt(self):
        """
        Fixture to move ipa_ca_crt and revert
        """
        self.master.run_command(
            ["mv", paths.IPA_CA_CRT, "%s.old" % paths.CA_CRT]
        )
        yield
        self.master.run_command(
            ["mv", "%s.old" % paths.CA_CRT, paths.IPA_CA_CRT]
        )

    def test_chainexpiration_check_without_cert(self, move_ipa_ca_crt):
        """
        Testcase checks that ERROR message is displayed
        when ipa ca crt file is not renamed
        """
        error_text = (
            "[Errno 2] No such file or directory: '{}'"
            .format(paths.IPA_CA_CRT)
        )
        msg_text = (
            "Error opening IPA CA chain at {key}: {error}"
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPACAChainExpirationCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["key"] == paths.IPA_CA_CRT
            assert check["kw"]["error"] == error_text
            assert check["kw"]["msg"] == msg_text

    @pytest.fixture
    def modify_cert_trust_attr(self):
        """
        Fixture to modify trust attribute for Server-cert and
        revert the change.
        """
        self.master.run_command(
            [
                "certutil",
                "-M",
                "-d", paths.PKI_TOMCAT_ALIAS_DIR,
                "-n", "Server-Cert cert-pki-ca",
                "-t", "CTu,u,u",
                "-f", paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
            ]
        )
        yield
        self.master.run_command(
            [
                "certutil",
                "-M",
                "-d", paths.PKI_TOMCAT_ALIAS_DIR,
                "-n", "Server-Cert cert-pki-ca",
                "-t", "u,u,u",
                "-f", paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
            ]
        )

    def test_ipacertnsstrust_check(self, modify_cert_trust_attr):
        """
        Test for IPACertNSSTrust when trust attribute is modified
        for Server-Cert
        """
        error_msg = (
            "Incorrect NSS trust for {nickname} in {dbdir}. "
            "Got {got} expected {expected}."
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPACertNSSTrust",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["key"] == "Server-Cert cert-pki-ca":
                assert check["result"] == "ERROR"
                assert check["kw"]["expected"] == "u,u,u"
                assert check["kw"]["got"] == "CTu,u,u"
                assert check["kw"]["dbdir"] == paths.PKI_TOMCAT_ALIAS_DIR
                assert check["kw"]["msg"] == error_msg

    def test_ipa_healthcheck_expiring(self):
        """
        There are two overlapping tests for expiring certs, check both.
        """

        def execute_expiring_check(check):
            """
            Test that certmonger will report warnings if expiration is near
            """

            returncode, data = run_healthcheck(
                self.master,
                "ipahealthcheck.ipa.certs",
                check,
            )

            assert returncode == 1
            assert len(data) == 9  # non-KRA is 9 tracked certs

            for check in data:
                if check["result"] == "SUCCESS":
                    # The CA is not expired
                    request = self.master.run_command(
                        ["getcert", "list", "-i", check["kw"]["key"]]
                    )
                    assert "caSigningCert cert-pki-ca" in request.stdout_text
                else:
                    assert check["result"] == "WARNING"
                    if check["kw"]["days"] == 21:
                        # the httpd, 389-ds and KDC renewal dates are later
                        certs = (paths.HTTPD_CERT_FILE, paths.KDC_CERT,
                                 '/etc/dirsrv/slapd-',)
                        request = self.master.run_command(
                            ["getcert", "list", "-i", check["kw"]["key"]]
                        )
                        assert any(cert in request.stdout_text
                                   for cert in certs)
                    else:
                        assert check["kw"]["days"] == 10

        # Pick a cert to find the upcoming expiration
        certfile = self.master.get_file_contents(paths.RA_AGENT_PEM)
        cert = x509.load_certificate_list(certfile)
        cert_expiry = cert[0].not_valid_after

        # move date to the grace period
        self.master.run_command(['systemctl', 'stop', 'chronyd'])
        grace_date = cert_expiry - timedelta(days=10)
        grace_date = datetime.strftime(grace_date, "%Y-%m-%d 00:00:01 Z")
        self.master.run_command(['date', '-s', grace_date])

        for check in ("IPACertmongerExpirationCheck",
                      "IPACertfileExpirationCheck",):
            execute_expiring_check(check)

        self.master.run_command(['systemctl', 'start', 'chronyd'])

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


@pytest.fixture
def modify_permissions():
    """Fixture to change owner, group and/or mode

       This can run against multiple files at once but only one host.
    """

    state = dict()

    def _modify_permission(host, path, owner=None, group=None, mode=None):
        """Change the ownership or mode of a path"""
        if 'host' not in state:
            state['host'] = host
        if path not in state:
            cmd = ["/usr/bin/stat", "-c", "%U:%G:%a", path]
            result = host.run_command(cmd)
            state[path] = result.stdout_text.strip()
        if owner is not None:
            host.run_command(["chown", owner, path])
        if group is not None:
            host.run_command(["chgrp", group, path])
        if mode is not None:
            host.run_command(["chmod", mode, path])

    yield _modify_permission

    # Restore the previous state
    host = state.pop('host')
    for path in state:
        (owner, group, mode) = state[path].split(':')
        host.run_command(["chown", "%s:%s" % (owner, group), path])
        host.run_command(["chmod", mode, path])


class TestIpaHealthCheckFileCheck(IntegrationTest):
    """
    Test for the ipa-healthcheck IPAFileCheck source
    """

    num_replicas = 1

    nssdb_testfiles = []
    for filename in NSS_SQL_FILES:
        testfile = os.path.join(paths.PKI_TOMCAT_ALIAS_DIR, filename)
        nssdb_testfiles.append(testfile)

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

    def test_ipa_filecheck_bad_owner(self, modify_permissions):
        modify_permissions(self.master, path=paths.RESOLV_CONF, owner='admin')
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] == '_etc_resolv.conf_owner'
            assert check["kw"]["type"] == 'owner'
            assert check["kw"]["expected"] == 'root'
            assert check["kw"]["got"] == 'admin'
            assert (
                check["kw"]["msg"]
                == "Ownership of %s is admin and should be root"
                % paths.RESOLV_CONF
            )

    def test_ipa_filecheck_bad_group(self, modify_permissions):
        modify_permissions(self.master, path=paths.RESOLV_CONF, group='admins')
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] == '_etc_resolv.conf_group'
            assert check["kw"]["type"] == 'group'
            assert check["kw"]["expected"] == 'root'
            assert check["kw"]["got"] == 'admins'
            assert (
                check["kw"]["msg"]
                == "Group of %s is admins and should be root"
                % paths.RESOLV_CONF
            )

    def test_ipa_filecheck_bad_too_restrictive(self, modify_permissions):
        modify_permissions(self.master, path=paths.RESOLV_CONF, mode="0400")
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["key"] == '_etc_resolv.conf_mode'
            assert check["kw"]["type"] == 'mode'
            assert check["kw"]["expected"] == '0644'
            assert check["kw"]["got"] == '0400'
            assert (
                check["kw"]["msg"]
                == "Permissions of %s are too restrictive: "
                   "0400 and should be 0644"
                % paths.RESOLV_CONF
            )

    def test_ipa_filecheck_too_permissive(self, modify_permissions):
        modify_permissions(self.master, path=paths.RESOLV_CONF, mode="0666")
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] == '_etc_resolv.conf_mode'
            assert check["kw"]["type"] == 'mode'
            assert check["kw"]["expected"] == '0644'
            assert check["kw"]["got"] == '0666'
            assert (
                check["kw"]["msg"]
                == "Permissions of %s are too permissive: "
                   "0666 and should be 0644"
                % paths.RESOLV_CONF
            )

    def test_nssdb_filecheck_bad_owner(self, modify_permissions):
        for testfile in self.nssdb_testfiles:
            modify_permissions(self.master, path=testfile, owner='root')
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileNSSDBCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["path"] in self.nssdb_testfiles
            assert check["kw"]["type"] == 'owner'
            assert check["kw"]["expected"] == 'pkiuser'
            assert check["kw"]["got"] == 'root'
            assert (
                check["kw"]["msg"]
                == "Ownership of %s is root and should be pkiuser"
                % check["kw"]["path"]
            )

    def test_nssdb_filecheck_bad_group(self, modify_permissions):
        for testfile in self.nssdb_testfiles:
            modify_permissions(self.master, testfile, group='root')

        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileNSSDBCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["path"] in self.nssdb_testfiles
            assert check["kw"]["type"] == 'group'
            assert check["kw"]["expected"] == 'pkiuser'
            assert check["kw"]["got"] == 'root'
            assert (
                check["kw"]["msg"]
                == "Group of %s is root and should be pkiuser"
                % check["kw"]["path"]
            )

    def test_nssdb_filecheck_too_restrictive(self, modify_permissions):
        for testfile in self.nssdb_testfiles:
            modify_permissions(self.master, path=testfile, mode="0400")

        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileNSSDBCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["path"] in self.nssdb_testfiles
            assert check["kw"]["type"] == 'mode'
            assert check["kw"]["expected"] == '0600'
            assert check["kw"]["got"] == '0400'
            assert (
                check["kw"]["msg"]
                == "Permissions of %s are too restrictive: "
                   "0400 and should be 0600"
                % check["kw"]["path"]
            )

    def test_nssdb_filecheck_too_permissive(self, modify_permissions):
        for testfile in self.nssdb_testfiles:
            modify_permissions(self.master, path=testfile, mode="0640")

        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "IPAFileNSSDBCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["path"] in self.nssdb_testfiles
            assert check["kw"]["type"] == 'mode'
            assert check["kw"]["expected"] == '0600'
            assert check["kw"]["got"] == '0640'
            assert (
                check["kw"]["msg"]
                == "Permissions of %s are too permissive: "
                   "0640 and should be 0600"
                % check["kw"]["path"]
            )

    def test_tomcat_filecheck_bad_owner(self, modify_permissions):
        modify_permissions(self.master, path=paths.CA_CS_CFG_PATH,
                           owner='root')
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "TomcatFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] == \
                '_var_lib_pki_pki-tomcat_conf_ca_CS.cfg_owner'
            assert check["kw"]["type"] == 'owner'
            assert check["kw"]["expected"] == 'pkiuser'
            assert check["kw"]["got"] == 'root'
            assert (
                check["kw"]["msg"]
                == "Ownership of %s is root and should be pkiuser"
                % check["kw"]["path"]
            )

    def test_tomcat_filecheck_bad_group(self, modify_permissions):
        modify_permissions(self.master, path=paths.CA_CS_CFG_PATH,
                           group='root')
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "TomcatFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] == \
                '_var_lib_pki_pki-tomcat_conf_ca_CS.cfg_group'
            assert check["kw"]["type"] == 'group'
            assert check["kw"]["expected"] == 'pkiuser'
            assert check["kw"]["got"] == 'root'
            assert (
                check["kw"]["msg"]
                == "Group of %s is root and should be pkiuser"
                % check["kw"]["path"]
            )

    def test_tomcat_filecheck_too_restrictive(self, modify_permissions):
        modify_permissions(self.master, path=paths.CA_CS_CFG_PATH,
                           mode="0600")
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "TomcatFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["key"] == \
                '_var_lib_pki_pki-tomcat_conf_ca_CS.cfg_mode'
            assert check["kw"]["type"] == 'mode'
            assert check["kw"]["expected"] == '0660'
            assert check["kw"]["got"] == '0600'
            assert (
                check["kw"]["msg"]
                == "Permissions of %s are too restrictive: "
                   "0600 and should be 0660"
                % check["kw"]["path"]
            )

    def test_tomcat_filecheck_too_permissive(self, modify_permissions):
        modify_permissions(self.master, path=paths.CA_CS_CFG_PATH,
                           mode="0666")
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.files",
            "TomcatFileCheck",
            failures_only=True,
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] == \
                '_var_lib_pki_pki-tomcat_conf_ca_CS.cfg_mode'
            assert check["kw"]["type"] == 'mode'
            assert check["kw"]["expected"] == '0660'
            assert check["kw"]["got"] == '0666'
            assert (
                check["kw"]["msg"]
                == "Permissions of %s are too permissive: "
                   "0666 and should be 0660"
                % check["kw"]["path"]
            )
