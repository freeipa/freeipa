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
import uuid

import pytest

from ipalib import x509
from ipapython.dn import DN
from ipapython.ipaldap import realm_to_serverid
from ipapython.certdb import NSS_SQL_FILES
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths
from ipaplatform.osinfo import osinfo
from ipatests.test_integration.base import IntegrationTest
from pkg_resources import parse_version
from ipatests.test_integration.test_cert import get_certmonger_fs_id
from ipatests.test_integration.test_external_ca import (
    install_server_external_ca_step1,
    install_server_external_ca_step2,
    ISSUER_CN,
)

HEALTHCHECK_LOG = "/var/log/ipa/healthcheck/healthcheck.log"
HEALTHCHECK_SYSTEMD_FILE = (
    "/etc/systemd/system/multi-user.target.wants/ipa-healthcheck.timer"
)
HEALTHCHECK_LOG_ROTATE_CONF = "/etc/logrotate.d/ipahealthcheck"
HEALTHCHECK_LOG_DIR = "/var/log/ipa/healthcheck"
HEALTHCHECK_OUTPUT_FILE = "/tmp/output.json"
HEALTHCHECK_PKG = ["*ipa-healthcheck"]

IPA_CA = "ipa_ca.crt"
ROOT_CA = "root_ca.crt"

sources = [
    "ipahealthcheck.dogtag.ca",
    "ipahealthcheck.ds.replication",
    "ipahealthcheck.ipa.certs",
    "ipahealthcheck.ipa.dna",
    "ipahealthcheck.ipa.idns",
    "ipahealthcheck.ipa.files",
    "ipahealthcheck.ipa.host",
    "ipahealthcheck.ipa.roles",
    "ipahealthcheck.ipa.topology",
    "ipahealthcheck.ipa.trust",
    "ipahealthcheck.ipa.meta",
    "ipahealthcheck.meta.core",
    "ipahealthcheck.meta.services",
    "ipahealthcheck.system.filesystemspace",
]

sources_0_4 = [
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
    "ipahealthcheck.meta.core",
    "ipahealthcheck.system.filesystemspace",
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
replication_checks = ["ReplicationCheck"]
replication_checks_0_4 = ["ReplicationConflictCheck"]
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


@pytest.fixture
def restart_service():
    """Shut down and restart a service as a fixture"""

    service = dict()

    def _stop_service(host, service_name):
        service_name = service_name.replace('_', '-')
        if service_name == 'pki-tomcatd':
            service_name = 'pki-tomcatd@pki-tomcat'
        elif service_name == 'dirsrv':
            serverid = (realm_to_serverid(host.domain.realm)).upper()
            service_name = 'dirsrv@%s.service' % serverid
        elif service_name == 'named':
            # The service name may differ depending on the host OS
            script = ("from ipaplatform.services import knownservices; "
                      "print(knownservices.named.systemd_name)")
            result = host.run_command(['python3', '-c', script])
            service_name = result.stdout_text.strip()
        if 'host' not in service:
            service['host'] = host
            service['name'] = [service_name]
        else:
            service['name'].append(service_name)
        host.run_command(["systemctl", "stop", service_name])

    yield _stop_service

    if service.get('name'):
        service.get('name', []).reverse()
        for name in service.get('name', []):
            service.get('host').run_command(["systemctl", "start", name])


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
        version = tasks.get_healthcheck_version(self.master)
        result = self.master.run_command(["ipa-healthcheck", "--list-sources"])
        if parse_version(version) >= parse_version("0.6"):
            sources_avail = sources
        else:
            sources_avail = sources_0_4
        for source in sources_avail:
            assert source in result.stdout_text

    def test_human_output(self, restart_service):
        """
        Test that in human output the severity value is correct

        Only the SUCCESS (0) value was being translated, otherwise
        the numeric value was being shown (BZ 1752849)
        """
        restart_service(self.master, "sssd")

        returncode, output = run_healthcheck(
            self.master,
            "ipahealthcheck.meta.services",
            "sssd",
            "human",
        )

        assert returncode == 1
        assert output == \
            "ERROR: ipahealthcheck.meta.services.sssd: sssd: not running"

    def test_ipa_healthcheck_after_certupdate(self):
        """
        Verify that ipa-certupdate hasn't messed up tracking

        ipa-certupdate was dropping the profile value from the CA
        signing cert tracking. ipa-healthcheck discovered this.

        Run ipa-healthcheck after ipa-certupdate to ensure that
        no problems are discovered.
        """
        self.master.run_command([paths.IPA_CERTUPDATE])
        returncode, _data = run_healthcheck(self.master)
        assert returncode == 0

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
        version = tasks.get_healthcheck_version(self.master)
        result = self.master.run_command(
            ["ipa-healthcheck", "--source", "ipahealthcheck.ds.replication"]
        )
        if parse_version(version) >= parse_version("0.6"):
            checks = replication_checks
        else:
            checks = replication_checks_0_4
        for check in checks:
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

    def test_source_ipahealthcheck_meta_services_check(self, restart_service):
        """
        Testcase checks behaviour of check configured services in
        ipahealthcheck.meta.services when service is stopped and started
        respectively
        """
        svc_list = ('certmonger', 'gssproxy', 'httpd', 'ipa_custodia',
                    'ipa_dnskeysyncd', 'kadmin', 'krb5kdc',
                    'named', 'pki_tomcatd', 'sssd', 'dirsrv')

        for service in svc_list:
            returncode, data = run_healthcheck(
                self.master,
                "ipahealthcheck.meta.services",
                service,
            )
            assert returncode == 0
            assert data[0]["check"] == service
            assert data[0]["result"] == "SUCCESS"
            assert data[0]["kw"]["status"] is True

        for service in svc_list:
            restart_service(self.master, service)
            returncode, data = run_healthcheck(
                self.master,
                "ipahealthcheck.meta.services",
                service,
            )
            assert returncode == 1
            service_found = False
            for check in data:
                if check["check"] != service:
                    continue
                if service != 'pki_tomcatd':
                    service = service.replace('_', '-')
                assert check["result"] == "ERROR"
                assert check["kw"]["msg"] == "%s: not running" % service
                assert check["kw"]["status"] is False
                service_found = True
            assert service_found

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
            assert check["kw"]["configfile"] == paths.CA_CS_CFG_PATH
            assert check["kw"]["key"] in DEFAULT_PKI_CA_CERTS
        self.master.run_command(["mv", paths.CA_CS_CFG_PATH,
                                 "%s.old" % paths.CA_CS_CFG_PATH])
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.dogtag.ca",
            "DogtagCertsConfigCheck",
        )
        assert returncode == 1
        assert data[0]["result"] == "CRITICAL"
        self.master.run_command(["mv", "%s.old" % paths.CA_CS_CFG_PATH,
                                 paths.CA_CS_CFG_PATH])
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

    def test_source_ipahealthcheck_ipa_host_check_ipahostkeytab(
        self, restart_service
    ):
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
        restart_service(self.master, "dirsrv")
        dirsrv_ipactl_status = 'Directory Service: STOPPED'
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

    def test_ipa_healthcheck_revocation(self):
        """
        Ensure that healthcheck reports when IPA certs are revoked.
        """
        error_msg = (
            "Certificate tracked by {key} is revoked {revocation_reason}"
        )
        error_msg_0_4 = (
            "Certificate is revoked, unspecified"
        )

        result = self.master.run_command(
            ["getcert", "list", "-f", paths.HTTPD_CERT_FILE]
        )
        request_id = get_certmonger_fs_id(result.stdout_text)

        # Revoke the web cert
        certfile = self.master.get_file_contents(paths.HTTPD_CERT_FILE)
        cert = x509.load_certificate_list(certfile)
        serial = cert[0].serial_number
        self.master.run_command(["ipa", "cert-revoke", str(serial)])

        # re-run to confirm
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPACertRevocation"
        )

        assert returncode == 1
        assert len(data) == 12

        version = tasks.get_healthcheck_version(self.master)
        for check in data:
            if check["kw"]["key"] == request_id:
                assert check["result"] == "ERROR"
                assert check["kw"]["revocation_reason"] == "unspecified"
                if (parse_version(version) >= parse_version('0.6')):
                    assert check["kw"]["msg"] == error_msg
                else:
                    assert (
                        check["kw"]["msg"]
                        == error_msg_0_4
                    )
            else:
                assert check["result"] == "SUCCESS"

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
        version = tasks.get_healthcheck_version(self.master)
        if (parse_version(version) >= parse_version('0.6')):
            returncode, output = run_healthcheck(
                self.master,
                "ipahealthcheck.meta",
                output_type="human",
                failures_only=True,
            )
        else:
            returncode, output = run_healthcheck(
                self.master,
                "ipahealthcheck.meta.services",
                output_type="human",
                failures_only=True,
            )
        assert returncode == 1
        errors = re.findall("ERROR: .*: not running", output)
        assert len(errors) == len(output.split("\n"))

    def test_ipahealthcheck_topology_with_ipactl_stop(self, ipactl):
        """
        This testcase checks that ipahealthcheck.ipa.topology check
        doesnot display 'source not found' on a system when ipactl
        stop is run
        """
        error_msg = "Source 'ipahealthcheck.ipa.topology' not found"
        msg = (
            "Source 'ipahealthcheck.ipa.topology' is missing "
            "one or more requirements 'dirsrv'"
        )
        result = self.master.run_command(
            [
                "ipa-healthcheck",
                "--source",
                "ipahealthcheck.ipa.topology",
                "--debug",
            ],
            raiseonerr=False,
        )
        assert result.returncode == 1
        assert msg in result.stdout_text
        assert error_msg not in result.stdout_text

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
        version = tasks.get_healthcheck_version(self.master)
        error_text = (
            "[Errno 2] No such file or directory: '{}'"
            .format(paths.IPA_CA_CRT)
        )
        msg_text = (
            "Error opening IPA CA chain at {key}: {error}"
        )
        error_4_0_text = (
            "[Errno 2] No such file or directory: '{}'"
            .format(paths.IPA_CA_CRT)
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
            if parse_version(version) >= parse_version("0.6"):
                assert check["kw"]["error"] == error_text
                assert check["kw"]["msg"] == msg_text
            else:
                assert error_4_0_text in check["kw"]["msg"]

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
        version = tasks.get_healthcheck_version(self.master)
        error_msg = (
            "Incorrect NSS trust for {nickname} in {dbdir}. "
            "Got {got} expected {expected}."
        )
        error_msg_4_0 = (
            "Incorrect NSS trust for Server-Cert cert-pki-ca. "
            "Got CTu,u,u expected u,u,u"
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
                if (parse_version(version) >= parse_version('0.6')):
                    assert check["kw"]["msg"] == error_msg
                else:
                    assert check["kw"]["msg"] == error_msg_4_0

    @pytest.fixture
    def update_logging(self):
        """
        Fixture disables nsslapd-logging-hr-timestamps-enabled
        parameter and reverts it back
        """
        ldap = self.master.ldap_connect()
        dn = DN(
            ("cn", "config"),
        )
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value["nsslapd-logging-hr-timestamps-enabled"] = 'off'
        ldap.update_entry(entry)  # pylint: disable=no-member

        yield

        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value["nsslapd-logging-hr-timestamps-enabled"] = 'on'
        ldap.update_entry(entry)  # pylint: disable=no-member

    def test_ipahealthcheck_ds_configcheck(self, update_logging):
        """
        This testcase ensures that ConfigCheck displays warning
        when high resolution timestamp is disabled.
        """
        warn_msg = (
            "nsslapd-logging-hr-timestamps-enabled changes the "
            "log format in directory server "
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ds.config",
            "ConfigCheck",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["key"] == "DSCLE0001":
                assert check["result"] == "WARNING"
                assert 'cn=config' in check["kw"]["items"]
                assert warn_msg in check["kw"]["msg"]

    @pytest.fixture
    def rename_ldif(self):
        """Fixture to rename dse.ldif file and revert after test"""
        instance = realm_to_serverid(self.master.domain.realm)
        self.master.run_command(
            [
                "mv", "-v",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
                + "/dse.ldif",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
                + "/dse.ldif.renamed",
            ]
        )
        yield
        self.master.run_command(
            [
                "mv", "-v",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
                + "/dse.ldif.renamed",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
                + "/dse.ldif",
            ]
        )

    def test_source_ipahealthcheck_ds_backends(self, rename_ldif):
        """
        This test ensures that BackendsCheck check displays the correct
        status when the dse.ldif file is renamed in the DS instance
        directory
        """
        exception_msg = "Could not find configuration for instance:"
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ds.backends", "BackendsCheck"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert exception_msg in check["kw"]["exception"]

    @pytest.fixture
    def modify_tls(self, restart_service):
        """
        Fixture to modify DS tls version to TLS1.0 using dsconf tool and
        revert back to the default TLS1.2
        """
        instance = realm_to_serverid(self.master.domain.realm)
        cmd = ["systemctl", "restart", "dirsrv@{}".format(instance)]
        self.master.run_command(
            [
                "dsconf",
                "slapd-{}".format(instance),
                "security",
                "set",
                "--tls-protocol-min=TLS1.0",
            ]
        )
        self.master.run_command(cmd)
        yield
        self.master.run_command(
            [
                "dsconf",
                "slapd-{}".format(instance),
                "security",
                "set",
                "--tls-protocol-min=TLS1.2",
            ]
        )
        self.master.run_command(cmd)

    def test_ipahealthcheck_ds_encryption(self, modify_tls):
        """
        This testcase modifies the default TLS version of
        DS instance to 1.0 and ensures that EncryptionCheck
        reports ERROR
        """
        enc_msg = (
            "This Directory Server may not be using strong TLS protocol "
            "versions. TLS1.0 is known to\nhave a number of issues with "
            "the protocol. "
            "Please see:\n\nhttps://tools.ietf.org/html/rfc7457\n\n"
            "It is advised you set this value to the maximum possible."
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ds.encryption", "EncryptionCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["key"] == "DSELE0001"
            assert "cn=encryption,cn=config" in check["kw"]["items"]
            assert check["kw"]["msg"] == enc_msg

    @pytest.fixture
    def update_riplugin(self):
        """
        Fixture modifies the value of update delay for RI plugin to -1
        and reverts it back
        """
        ldap = self.master.ldap_connect()
        dn = DN(
            ("cn", "referential integrity postoperation"),
            ("cn", "plugins"),
            ("cn", "config"),
        )
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value["referint-update-delay"] = -1
        ldap.update_entry(entry)  # pylint: disable=no-member

        yield

        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value["referint-update-delay"] = 0
        ldap.update_entry(entry)  # pylint: disable=no-member

    def test_ipahealthcheck_ds_riplugincheck(self, update_riplugin):
        """
        This testcase ensures that RIPluginCheck displays warning
        when update value is set.
        """
        warn_msg = (
            "We advise that you set this value to 0, and enable referint "
            "on all masters as it provides a more predictable behaviour.\n"
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ds.ds_plugins",
            "RIPluginCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert warn_msg in check["kw"]["msg"]

    @pytest.fixture
    def modify_pwdstoragescheme(self):
        """
        Fixture modifies the nsslapd-rootpwstoragescheme to
        MD5 and reverts it back
        """
        ldap = self.master.ldap_connect()
        dn = DN(("cn", "config"),)
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value["nsslapd-rootpwstoragescheme"] = "MD5"
        ldap.update_entry(entry)  # pylint: disable=no-member

        yield

        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value["nsslapd-rootpwstoragescheme"] = "PBKDF2_SHA256"
        ldap.update_entry(entry)  # pylint: disable=no-member

    def test_ds_configcheck_passwordstorage(self, modify_pwdstoragescheme):
        """
        This testcase ensures that ConfigCheck reports CRITICAL
        status when nsslapd-rootpwstoragescheme is set to MD5
        from the required PBKDF2_SHA256
        """
        error_msg = (
            "\n\nIn Directory Server, we offer one hash suitable for this "
            "(PBKDF2_SHA256) and one hash\nfor \"legacy\" support (SSHA512)."
            "\n\nYour configuration does not use these for password storage "
            "or the root password storage\nscheme.\n"
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ds.config", "ConfigCheck",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["key"] == "DSCLE0002":
                assert check["result"] == "CRITICAL"
                assert "cn=config" in check["kw"]["items"]
                assert error_msg in check["kw"]["msg"]

    @pytest.fixture
    def expire_cert_critical(self):
        """
        Fixture to expire the cert by moving the system date using
        date -s command and revert it back
        """
        self.master.run_command(['date','-s', '+3Years'])
        yield
        self.master.run_command(['date','-s', '-3Years'])
        self.master.run_command(['ipactl', 'restart'])

    def test_nsscheck_cert_expired(self, expire_cert_critical):
        """
        This test checks that critical message is displayed
        for NssCheck when Server-Cert has expired
        """
        msg = "The certificate (Server-Cert) has expired"
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ds.nss_ssl", "NssCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["key"] == "DSCERTLE0002"
            assert "Expired Certificate" in check["kw"]["items"]
            assert check["kw"]["msg"] == msg


    def test_ipa_healthcheck_expiring(self, restart_service):
        """
        There are two overlapping tests for expiring certs, check both.
        """

        def execute_nsscheck_cert_expiring(check):
            """
            This test checks that error message is displayed
            for NssCheck when 'Server-Cert' is about to expire
            """
            msg = (
                "The certificate (Server-Cert) will "
                "expire in less than 30 days"
            )
            returncode, data = run_healthcheck(
                self.master, "ipahealthcheck.ds.nss_ssl", "NssCheck",
            )
            assert returncode == 1
            for check in data:
                assert check["result"] == "ERROR"
                assert check["kw"]["key"] == "DSCERTLE0001"
                assert "Expiring Certificate" in check["kw"]["items"]
                assert check["kw"]["msg"] == msg

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
            assert len(data) == 12  # KRA is 12 tracked certs

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

        # Store the current date to restore at the end of the test
        now = datetime.utcnow()
        now_str = datetime.strftime(now, "%Y-%m-%d %H:%M:%S Z")

        # Pick a cert to find the upcoming expiration
        certfile = self.master.get_file_contents(paths.RA_AGENT_PEM)
        cert = x509.load_certificate_list(certfile)
        cert_expiry = cert[0].not_valid_after

        for service in ('chronyd', 'pki_tomcatd',):
            restart_service(self.master, service)

        try:
            # move date to the grace period
            grace_date = cert_expiry - timedelta(days=10)
            grace_date = datetime.strftime(grace_date, "%Y-%m-%d 00:00:01 Z")
            self.master.run_command(['date', '-s', grace_date])

            for check in ("IPACertmongerExpirationCheck",
                          "IPACertfileExpirationCheck",):
                execute_expiring_check(check)

            execute_nsscheck_cert_expiring(check)

        finally:
            # After restarting chronyd, the date may need some time to get
            # synced. Help chrony by resetting the date
            self.master.run_command(['date', '-s', now_str])

    """
    IMPORTANT: Do not add tests after test_ipa_healthcheck_expiring
    as the system may be unstable after the date modification.
    """

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
        msg3 = "Got {count} ipa-ca AAAA records, expected {expected}"
        tasks.install_packages(self.master, HEALTHCHECK_PKG)
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.idns",
            "IPADNSSystemRecordsCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert (
                check["kw"]["msg"] == msg1
                or check["kw"]["msg"] == msg2
                or check["kw"]["msg"] == msg3
            )

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
    with Windows AD.
    """
    topology = "line"
    num_ad_domains = 1
    num_ad_treedomains = 1
    num_ad_subdomains = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        cls.ad = cls.ads[0]
        cls.child_ad = cls.ad_subdomains[0]
        cls.tree_ad = cls.ad_treedomains[0]
        cls.ad_domain = cls.ad.domain.name
        cls.ad_subdomain = cls.child_ad.domain.name
        cls.ad_treedomain = cls.tree_ad.domain.name
        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

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
        trust_domains = ', '.join((self.ad_domain, self.ad_subdomain,))
        for check in data:
            if check["kw"]["key"] == "domain-list":
                assert check["result"] == "SUCCESS"
                assert (
                    check["kw"]["sssd_domains"] == trust_domains
                    and check["kw"]["trust_domains"] == trust_domains
                )
            elif check["kw"]["key"] == "domain-status":
                assert check["result"] == "SUCCESS"
                assert check["kw"]["domain"] in trust_domains

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
        trust_domains = ', '.join((self.ad_domain, self.ad_subdomain,))
        for check in data:
            if check["kw"]["key"] == "AD Global Catalog":
                assert check["result"] == "SUCCESS"
                assert check["kw"]["domain"] in trust_domains
            elif check["kw"]["key"] == "AD Domain Controller":
                assert check["result"] == "SUCCESS"
                assert check["kw"]["domain"] in trust_domains

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

    def test_ipahealthcheck_with_external_ad_trust(self):
        """
        This testcase checks that when external trust is configured
        between IPA and AD tree domain, IPATrustDomainsCheck
        doesnot display ERROR
        """
        tasks.configure_dns_for_trust(self.master, self.tree_ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_treedomain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])
        trust_domains = ', '.join((self.ad_domain, self.ad_subdomain,
                                  self.ad_treedomain,))
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPATrustDomainsCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["kw"]["key"] in ('domain-list', 'domain-status',)
            assert check["result"] == "SUCCESS"
            assert check["kw"].get("msg") is None
            if check["kw"]["key"] == 'domain-list':
                assert check["kw"]["sssd_domains"] == trust_domains
                assert check["kw"]["trust_domains"] == trust_domains
            else:
                assert check["kw"]["domain"] in trust_domains

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
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.6"):
            pytest.skip("Skipping test for 0.4 healthcheck version")
        modify_permissions(self.master, path=paths.RESOLV_CONF, owner="admin")
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
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.6"):
            pytest.skip("Skipping test for 0.4 healthcheck version")
        modify_permissions(self.master, path=paths.RESOLV_CONF, group="admins")
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
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.6"):
            pytest.skip("Skipping test for 0.4 healthcheck version")
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
                "0400 and should be 0644" % paths.RESOLV_CONF
            )

    def test_ipa_filecheck_too_permissive(self, modify_permissions):
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.6"):
            pytest.skip("Skipping test for 0.4 healthcheck version")
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
                "0666 and should be 0644" % paths.RESOLV_CONF
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
        version = tasks.get_healthcheck_version(self.master)
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
            if (parse_version(version) >= parse_version('0.5')):
                assert (
                    check["kw"]["msg"]
                    == "Permissions of %s are too permissive: "
                       "0666 and should be 0660"
                    % check["kw"]["path"]
                )
            else:
                assert (
                    check["kw"]["msg"]
                    == "Permissions of %s are 0666 and should "
                       "be 0660"
                    % check["kw"]["path"]
                )

    def test_ipahealthcheck_ds_fschecks(self, modify_permissions):
        """
        This testcase ensures that FSCheck displays CRITICAL
        status when permission of pin.txt is modified.
        """
        instance = realm_to_serverid(self.master.domain.realm)
        error_msg = (
            "does not have the expected permissions (400).  "
            "The\nsecurity database pin/password files should only "
            "be readable by Directory Server user."
        )
        modify_permissions(
            self.master,
            path=paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
            + "/pin.txt",
            mode="0000",
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ds.fs_checks", "FSCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "CRITICAL"
            assert check["kw"]["key"] == "DSPERMLE0002"
            assert error_msg in check["kw"]["msg"]


class TestIpaHealthCheckFilesystemSpace(IntegrationTest):
    """
    ipa-healthcheck tool test for running low on disk space.
    """

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

    @pytest.fixture
    def create_jumbo_file(self):
        """Calculate the free space and create a humongous file to fill it
        within the threshold without using all available space."""

        path = os.path.join('/tmp', str(uuid.uuid4()))
        # CI has a single big disk so we may end up allocating most of it.
        result = self.master.run_command(['df', '--output=avail', '/tmp'])
        free = (int(result.stdout_text.split('\n')[1]) // 1000) - 50
        self.master.run_command(['fallocate', '-l', '%dMiB' % free, path])

        yield

        self.master.run_command(['rm', path])

    def test_ipa_filesystemspace_check(self, create_jumbo_file):
        """
        Create a large file in /tmp and verify that it reports low space

        This should raise 2 errors. One that the available space is
        below a size threshold and another that it is below a
        percentage threshold.
        """

        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.system.filesystemspace",
            "FileSystemSpaceCheck",
            failures_only=True,
        )
        assert returncode == 1

        errors_found = 0
        # Because PR-CI has a single filesystem more filesystems will
        # report as full. Let's only consider /tmp since this will work
        # with discrete /tmp as well.
        for check in data:
            if check["kw"]["store"] != "/tmp":
                continue

            assert check["result"] == "ERROR"
            assert check["kw"]["store"] == "/tmp"
            if "percent_free" in check["kw"]:
                assert "/tmp: free space percentage under threshold" in \
                    check["kw"]["msg"]
                assert check["kw"]["threshold"] == 20
            else:
                assert "/tmp: free space under threshold" in \
                    check["kw"]["msg"]
                assert check["kw"]["threshold"] == 512
            errors_found += 1

        # Make sure we found the two errors we expected
        assert errors_found == 2


class TestIpaHealthCLI(IntegrationTest):
    """
    Validate the command-line options

    An attempt is made to not overlap tests done in other classes.
    Run as a separate class so there is a "clean" system to test
    against.
    """

    # In freeipa-healtcheck >= 0.6 the default tty output is
    # --failures-only. To show all output use --all. This will
    # tell us whether --all is available.
    all_option = osinfo.id in ['fedora',]
    if all_option:
        base_cmd = ["ipa-healthcheck", "--all"]
    else:
        base_cmd = ["ipa-healthcheck"]

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

    def test_indent(self):
        """
        Use illegal values for indent
        """
        for option in ('a', '9.0'):
            cmd = self.base_cmd + ["--indent", option]
            result = self.master.run_command(cmd, raiseonerr=False)
            assert result.returncode == 2
            assert 'invalid int value' in result.stderr_text

        # unusual success, arguably odd but not invalid :-)
        for option in ('-1', '5000'):
            cmd = self.base_cmd + ["--indent", option]
            result = self.master.run_command(cmd)

    def test_severity(self):
        """
        Valid and invalid --severity
        """
        # Baseline, there should be no errors
        cmd = ["ipa-healthcheck", "--severity", "SUCCESS"]
        result = self.master.run_command(cmd)
        data = json.loads(result.stdout_text)
        for check in data:
            assert check["result"] == "SUCCESS"

        # All the other's should return nothing
        for severity in ('WARNING', 'ERROR', 'CRITICAL'):
            cmd = ["ipa-healthcheck", "--severity", severity]
            result = self.master.run_command(cmd)
            data = json.loads(result.stdout_text)
            assert len(data) == 0

        # An unknown severity
        cmd = ["ipa-healthcheck", "--severity", "BAD"]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 2
        assert 'invalid choice' in result.stderr_text

    @pytest.mark.xfail(reason='BZ 1866558', strict=False)
    def test_input_file(self):
        """
        Verify the --input-file option
        """
        # ipa-healthcheck overwrites output file, no need to generate
        # a randomized name.
        outfile = "/tmp/healthcheck.out"

        # create our output file
        cmd = ["ipa-healthcheck", "--output-file", outfile]
        result = self.master.run_command(cmd)

        # load the file
        cmd = ["ipa-healthcheck", "--failures-only", "--input-file", outfile]
        result = self.master.run_command(cmd)
        data = json.loads(result.stdout_text)
        for check in data:
            assert check["result"] == "SUCCESS"

        # input file doesn't exist
        cmd = self.base_cmd + ["--input-file", "/tmp/enoent"]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        assert 'No such file or directory' in result.stderr_text

        # Invalid input file
        cmd = ["ipa-healthcheck", "--input-file", paths.IPA_CA_CRT]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        assert 'Expecting value' in result.stderr_text

    def test_output_type(self):
        """
        Check invalid output types.

        The supported json and human types are checked in other classes.
        """
        cmd = self.base_cmd + ["--output-type", "hooman"]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 2
        assert 'invalid choice' in result.stderr_text

    def test_source_and_check(self):
        """
        Verify that invalid --source and/or --check are handled.
        """
        cmd = self.base_cmd + ["--source", "nonexist"]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        assert "Source 'nonexist' not found" in result.stdout_text

        cmd = self.base_cmd + ["--source", "ipahealthcheck.ipa.certs",
                               "--check", "nonexist"]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        assert "Check 'nonexist' not found in Source" in result.stdout_text

    def test_pki_healthcheck(self):
        """
        Ensure compatibility with pki-healthcheck

        Running on a clean system should produce no errors. This will
        ensure ABI compatibility.
        """
        self.master.run_command(["pki-healthcheck"])

    def test_append_arguments_to_list_sources(self):
        """
        Verify that when arguments are specified to --list-sources
        option, error is displayed on the console.
        """
        cmd = self.base_cmd + ["--list-sources", "source"]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 2
        assert (
            "ipa-healthcheck: error: unrecognized arguments: source"
            in result.stderr_text
        )


class TestIpaHealthCheckWithExternalCA(IntegrationTest):
    """
    Tests to run and check whether ipa-healthcheck tool
    reports correct status when IPA server is configured
    with external CA.
    """

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        result = install_server_external_ca_step1(cls.master)
        assert result.returncode == 0
        root_ca_fname, ipa_ca_fname = tasks.sign_ca_and_transport(
            cls.master, paths.ROOT_IPA_CSR, ROOT_CA, IPA_CA
        )

        install_server_external_ca_step2(
            cls.master, ipa_ca_fname, root_ca_fname
        )
        tasks.kinit_admin(cls.master)
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)
        tasks.install_packages(cls.replicas[0], HEALTHCHECK_PKG)
        tasks.install_replica(cls.master, cls.replicas[0])

    def test_ipahealthcheck_crlmanagercheck(self):
        """
        Test for IPACRLManagerCheck
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.roles", "IPACRLManagerCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "crl_manager"
            assert check["kw"]["crlgen_enabled"] is True

        # Run again on another server to verify it is False
        returncode, data = run_healthcheck(
            self.replicas[0], "ipahealthcheck.ipa.roles", "IPACRLManagerCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == "crl_manager"
            assert check["kw"]["crlgen_enabled"] is False

    @pytest.fixture()
    def getcert_ca(self):
        """
        Fixture to remove and add ca using getcert command.
        """
        self.master.run_command(
            ["getcert", "remove-ca", "-c", "dogtag-ipa-ca-renew-agent"]
        )
        yield
        self.master.run_command(
            [
                "getcert",
                "add-ca",
                "-c",
                "dogtag-ipa-ca-renew-agent",
                "-e",
                paths.DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT,
            ]
        )

    def test_ipahealthcheck_certmongerca(self, getcert_ca):
        """
        Test that healthcheck detects that a certmonger-defined
        CA is missing
        """
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPACertmongerCA",
        )
        assert returncode == 1
        version = tasks.get_healthcheck_version(self.master)
        for check in data:
            if check["kw"]["key"] == "dogtag-ipa-ca-renew-agent":
                assert check["result"] == "ERROR"
                if (parse_version(version) >= parse_version('0.6')):
                    assert (
                        check["kw"]["msg"] == "Certmonger CA '{key}' missing"
                    )
                else:
                    assert (
                        check["kw"]["msg"]
                        == "Certmonger CA 'dogtag-ipa-ca-renew-agent' missing"
                    )

    @pytest.fixture()
    def rename_httpd_cert(self):
        """
        Fixture to rename http cert and revert the change.
        """
        self.master.run_command(
            ["mv", paths.HTTPD_CERT_FILE, "%s.old" % paths.HTTPD_CERT_FILE]
        )
        yield
        self.master.run_command(
            ["mv", "%s.old" % paths.HTTPD_CERT_FILE, paths.HTTPD_CERT_FILE]
        )

    def test_ipahealthcheck_ipaopensslchainvalidation(self, rename_httpd_cert):
        """
        Test for IPAOpenSSLChainValidation when httpd cert is moved.
        """
        error_msg = "Can't open {} for reading".format(paths.HTTPD_CERT_FILE)
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPAOpenSSLChainValidation",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["key"] == paths.HTTPD_CERT_FILE:
                assert check["result"] == "ERROR"
                assert error_msg in check["kw"]["reason"]

    @pytest.fixture()
    def replace_ipa_chain(self):
        """
        Fixture to drop the external CA from the IPA chain
        """
        self.master.run_command(
            ["cp", paths.IPA_CA_CRT, "%s.old" % paths.IPA_CA_CRT]
        )
        self.master.run_command(
            [paths.CERTUTIL,
             "-d", paths.PKI_TOMCAT_ALIAS_DIR,
             "-L",
             "-a",
             "-n", "caSigningCert cert-pki-ca",
             "-o", paths.IPA_CA_CRT]
        )
        yield
        self.master.run_command(
            ["mv", "%s.old" % paths.IPA_CA_CRT, paths.IPA_CA_CRT]
        )

    def test_opensslchainvalidation_ipa_ca_cert(self, replace_ipa_chain):
        """
        Test for IPAOpenSSLChainValidation when /etc/ipa/ca.crt
        contains IPA CA cert but not the external CA
        """
        version = tasks.get_healthcheck_version(self.master)
        error_msg = "Certificate validation for {key} failed: {reason}"
        error_reason = (
            "CN = Certificate Authority\nerror 2 at 1 depth "
            "lookup: unable to get issuer certificate\n"
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPAOpenSSLChainValidation",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            if parse_version(version) >= parse_version("0.6"):
                if check["kw"]["key"] == paths.HTTPD_CERT_FILE:
                    assert error_msg in check["kw"]["msg"]
                    assert error_reason in check["kw"]["reason"]
                elif check["kw"]["key"] == paths.RA_AGENT_PEM:
                    assert error_msg in check["kw"]["msg"]
                    assert error_reason in check["kw"]["reason"]
            else:
                assert error_reason in check["kw"]["reason"]
                assert error_reason in check["kw"]["msg"]

    @pytest.fixture
    def remove_server_cert(self):
        """
        Fixture to remove Server cert and revert the change.
        """
        instance = realm_to_serverid(self.master.domain.realm)
        self.master.run_command(
            [
                "certutil",
                "-L",
                "-d",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
                "-n",
                "Server-Cert",
                "-a",
                "-o",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
                + "/Server-Cert.pem",
            ]
        )
        self.master.run_command(
            [
                "certutil",
                "-d",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
                "-D",
                "-n",
                "Server-Cert",
            ]
        )
        yield
        self.master.run_command(
            [
                "certutil",
                "-d",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
                "-A",
                "-i",
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
                + "/Server-Cert.pem",
                "-t",
                "u,u,u",
                "-f",
                paths.IPA_NSSDB_PWDFILE_TXT,
                "-n",
                "Server-Cert",
            ]
        )

    def test_ipahealthcheck_ipansschainvalidation(self, remove_server_cert):
        """
        Test for IPANSSChainValidation check
        """
        error_msg = (
            ': certutil: could not find certificate named "Server-Cert": '
            "PR_FILE_NOT_FOUND_ERROR: File not found\n"
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPANSSChainValidation",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["nickname"] == "Server-Cert":
                assert check["result"] == "ERROR"
                assert check["kw"]["reason"] == error_msg

    @pytest.fixture()
    def modify_nssdb_chain_trust(self):
        """
        Fixture to modify trust in the dirsrv NSS database
        """
        instance = realm_to_serverid(self.master.domain.realm)
        for nickname in ('CN={}'.format(ISSUER_CN),
                         '%s IPA CA' % self.master.domain.realm):
            cmd = [
                paths.CERTUTIL,
                "-M",
                "-d", paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
                "-n", nickname,
                "-t", ",,",
                "-f",
                "%s/pwdfile.txt" %
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
            ]
            self.master.run_command(cmd)
        yield
        for nickname in ('CN={}'.format(ISSUER_CN),
                         '%s IPA CA' % self.master.domain.realm):
            cmd = [
                paths.CERTUTIL,
                "-M",
                "-d", paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
                "-n", nickname,
                "-t", "CT,C,C",
                "-f",
                "%s/pwdfile.txt" %
                paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance,
            ]
            self.master.run_command(cmd)

    def test_nsschainvalidation_ipa_invalid_chain(self,
                                                  modify_nssdb_chain_trust):
        """
        Test for IPANSSChainValidation when external CA is not trusted
        """
        version = tasks.get_healthcheck_version(self.master)
        instance = realm_to_serverid(self.master.domain.realm)
        instance_dir = paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
        error_msg = "Validation of {nickname} in {dbdir} failed: {reason}"
        error_msg_40_txt = (
            "certificate is invalid: Peer's certificate issuer "
            "has been marked as not trusted by the user"
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPANSSChainValidation",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["nickname"] != "Server-Cert":
                assert check["result"] == "SUCCESS"
                continue
            assert check["result"] == "ERROR"
            assert check["kw"]["dbdir"] == "%s/" % instance_dir
            assert "marked as not trusted" in check["kw"]["reason"]
            assert check["kw"]["key"] == "%s:Server-Cert" % instance_dir
            if parse_version(version) >= parse_version("0.6"):
                assert check["kw"]["msg"] == error_msg
            else:
                assert error_msg_40_txt in check["kw"]["msg"]

    @pytest.fixture
    def rename_raagent_cert(self):
        """
        Fixture to rename IPA RA CRT and revert
        """
        self.master.run_command(
            ["mv", paths.RA_AGENT_PEM, "%s.old" % paths.RA_AGENT_PEM]
        )
        yield
        self.master.run_command(
            ["mv", "%s.old" % paths.RA_AGENT_PEM, paths.RA_AGENT_PEM]
        )

    def test_ipahealthcheck_iparaagent(self, rename_raagent_cert):
        """
        Testcase checks that ERROR message is displayed
        when IPA RA crt file is renamed
        """
        version = tasks.get_healthcheck_version(self.master)
        error_msg = (
            "[Errno 2] No such file or directory: '{}'"
            .format(paths.RA_AGENT_PEM)
        )
        error_msg_40_txt = (
            "Unable to load RA cert: [Errno 2] "
            "No such file or directory: '{}'".format(paths.RA_AGENT_PEM)
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs", "IPARAAgent"
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            if parse_version(version) >= parse_version("0.6"):
                assert check["kw"]["error"] == error_msg
            else:
                assert check["kw"]["msg"] == error_msg_40_txt

    @pytest.fixture
    def update_ra_cert_desc(self):
        """
        Fixture to modify description of RA cert in ldap
        and revert
        """
        ldap = self.master.ldap_connect()
        dn = DN(("uid", "ipara"), ("ou", "People"), ("o", "ipaca"))
        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        ldap_cert_desc = entry.single_value.get("description")

        def _update_entry(description):
            entry = ldap.get_entry(dn)  # pylint: disable=no-member
            entry.single_value['description'] = description
            ldap.update_entry(entry)  # pylint: disable=no-member

        yield _update_entry

        entry = ldap.get_entry(dn)  # pylint: disable=no-member
        entry.single_value['description'] = ldap_cert_desc
        ldap.update_entry(entry)  # pylint: disable=no-member

    def test_ipahealthcheck_iparaagent_ldap(self, update_ra_cert_desc):
        """
        Test to check that when description of RA cert in ldap
        is modified, healthcheck tool reports the correct message
        """
        error_msg = 'RA agent not found in LDAP'
        update_ra_cert_desc('200,12,CN=abc,CN=test')
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPARAAgent",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["msg"] == error_msg

    def test_ipahealthcheck_iparaagent_bad_serial(self, update_ra_cert_desc):
        """
        Test to check cert description doesnt match the expected
        """
        version = tasks.get_healthcheck_version(self.master)
        error_msg = 'RA agent description does not match. Found {got} ' \
                    'in LDAP and expected {expected}'
        error_reason = (
            "RA agent description does not match"
        )
        update_ra_cert_desc(
            '2;16;CN=Certificate Authority,O=%s;CN=IPA RA,O=%s' %
            (self.master.domain.realm, self.master.domain.realm)
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPARAAgent",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert (
                check["kw"]["expected"] == "2;6;"
                "CN=Certificate Authority,O=%s;CN=IPA RA,"
                "O=%s" % (self.master.domain.realm, self.master.domain.realm)
            )
            assert (
                check["kw"]["got"] == "2;16;"
                "CN=Certificate Authority,O=%s;CN=IPA RA,"
                "O=%s" % (self.master.domain.realm, self.master.domain.realm)
            )
            if parse_version(version) >= parse_version("0.6"):
                assert check["kw"]["msg"] == error_msg
            else:
                assert error_reason in check["kw"]["msg"]
