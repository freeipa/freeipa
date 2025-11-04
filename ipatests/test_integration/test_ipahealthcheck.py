# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Tests to verify that the ipa-healthcheck scenarios
"""

from __future__ import absolute_import

from configparser import RawConfigParser, NoOptionError
from datetime import datetime, timedelta, timezone
UTC = timezone.utc
import io
import json
import os
import re
import uuid

import pytest

from ipalib import errors, x509
from ipapython.dn import DN
from ipapython.ipaldap import realm_to_serverid
from ipapython.certdb import NSS_SQL_FILES
from ipatests.pytest_ipa.integration import tasks
from ipaplatform.paths import paths
from ipaplatform.osinfo import osinfo
from ipaserver.install.installutils import resolve_ip_addresses_nss
from ipatests.test_integration.test_caless import CALessBase
from ipatests.test_integration.base import IntegrationTest
from packaging.version import parse as parse_version
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
SOS_CMD = "/usr/sbin/sos"
SOS_PKG = ["sos"]

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
    "IPATrustControllerAdminSIDCheck",
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
pki_clone_checks = ["ClonesConnectivyAndDataCheck"]
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
                    failures_only=False, config=None):
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

    if config:
        config_data = host.get_file_contents(config, encoding='utf-8')
        cfg = RawConfigParser()
        cfg.read_string(config_data)
        # The config file value overrides the CLI so if human or
        # some other option is overridden, don't import as json.
        try:
            output_type = cfg.get('default', 'output_type')
        except NoOptionError:
            pass
        cmd.append("--config")
        cmd.append(config)

    result = host.run_command(cmd, raiseonerr=False)

    if result.stdout_text:
        if output_type == "json":
            data = json.loads(result.stdout_text)
        else:
            data = result.stdout_text.strip()

    return result.returncode, data


def set_excludes(host, option, value,
                 config_file='/etc/ipahealthcheck/ipahealthcheck.conf'):
    """Mark checks that should be excluded from the results

       This will set in the [excludes] section on host:
           option=value
    """
    EXCLUDES = "excludes"

    conf = host.get_file_contents(config_file, encoding='utf-8')
    cfg = RawConfigParser()
    cfg.read_string(conf)
    if not cfg.has_section(EXCLUDES):
        cfg.add_section(EXCLUDES)
    if not cfg.has_option(EXCLUDES, option):
        cfg.set(EXCLUDES, option, value)
    out = io.StringIO()
    cfg.write(out)
    out.seek(0)
    host.put_file_contents(config_file, out.read())


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
    num_clients = 1

    @classmethod
    def install(cls, mh):
        if not cls.master.transport.file_exists(SOS_CMD):
            tasks.install_packages(cls.master, SOS_PKG)
        tasks.install_master(
            cls.master, setup_dns=True, extra_args=['--no-dnssec-validation']
        )
        tasks.install_client(cls.master, cls.clients[0])
        tasks.install_replica(
            cls.master,
            cls.replicas[0],
            setup_dns=True,
            extra_args=['--no-dnssec-validation']
        )
        set_excludes(cls.master, "key", "DSCLE0004")

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

    def test_running_ipahealthcheck_ipaclient(self):
        """
        Testcase checks that when ipa-healthcheck command is
        run on ipaclient it displays "IPA is not configured"
        """
        valid_msg = (
            'IPA is not configured\n', 'IPA server is not configured\n'
        )
        tasks.install_packages(self.clients[0], HEALTHCHECK_PKG)
        cmd = self.clients[0].run_command(
            ["ipa-healthcheck"], raiseonerr=False
        )
        assert cmd.returncode == 1
        assert cmd.stdout_text in valid_msg

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

    def test_human_severity(self, restart_service):
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

    def test_human_output(self):
        """
        Test if in case no  failures were found, informative string is printed
        in human output.

        https://pagure.io/freeipa/issue/8892
        """
        returncode, output = run_healthcheck(self.master, output_type="human",
                                             failures_only=True)
        assert returncode == 0
        assert output == "No issues found."

    def test_ipa_healthcheck_fips_enabled(self):
        """
        Test if FIPS is enabled and the check exists.

        https://pagure.io/freeipa/issue/8951
        """
        healthcheck_version = tasks.get_healthcheck_version(self.master)
        if (
            parse_version(healthcheck_version) < parse_version("0.17")
            and osinfo.id == 'rhel'
            and osinfo.version_number == (10,0)
        ):
            # Patch: https://github.com/freeipa/freeipa-healthcheck/pull/349
            pytest.skip("Patch is unavailable for RHEL 10.0 "
                        "freeipa-healthcheck version 0.16 or less")

        returncode, check = run_healthcheck(self.master,
                                            source="ipahealthcheck.meta.core",
                                            check="MetaCheck",
                                            output_type="json",
                                            failures_only=False)
        assert returncode == 0

        is_fips_enabled = tasks.is_fips_enabled(self.master)

        assert "fips" in check[0]["kw"]

        if check[0]["kw"]["fips"] == "disabled":
            assert not is_fips_enabled
        elif check[0]["kw"]["fips"] == "enabled":
            assert is_fips_enabled
        else:
            raise ValueError("File %s doesn't exist or contains unexpected "
                             "value, this is a kernel issue!"
                             % paths.PROC_FIPS_ENABLED)

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
        # earlier trust check used to return an empty SUCCESS message when
        # trust is not configured.But now it actually returns a message
        not_a_trust_agent = ["IPATrustAgentCheck", "IPATrustCatalogCheck",
                             "IPAsidgenpluginCheck", "IPATrustAgentMemberCheck",
                             "IPATrustDomainsCheck", "IPATrustPackageCheck"]

        not_a_trust_controller = ["IPATrustControllerPrincipalCheck",
                                  "IPATrustControllerServiceCheck",
                                  "IPATrustControllerConfCheck",
                                  "IPATrustControllerGroupSIDCheck",
                                  "IPATrustControllerAdminSIDCheck"]

        _returncode, data = run_healthcheck(
            self.master, source="ipahealthcheck.ipa.trust")

        for check in data:
            if check["check"] in not_a_trust_agent:
                assert "Skipped. Not a trust agent" in check["kw"]["msg"]
            elif check["check"] in not_a_trust_controller:
                assert "Skipped. Not a trust controller" in check["kw"]["msg"]

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

        version = tasks.get_healthcheck_version(self.master)
        # With healthcheck newer versions, the error msg for PKI tomcat
        # contains the string pki-tomcatd instead of pki_tomcatd
        always_replace = parse_version(version) >= parse_version("0.13")

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
                if service != 'pki_tomcatd' or always_replace:
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
        version = tasks.get_pki_version(self.master)
        if version >= parse_version("11.5"):
            pytest.skip("Skipping test for 11.5 pki version, since the "
                        "check CADogtagCertsConfigCheck itself is skipped "
                        "See ipa-healthcheck ticket 317")
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
        error_msg = "Request for certificate failed"
        additional_msg = (
            "Certificate operation cannot be completed: "
            "Request failed with status 503: "
            "Non-2xx response from CA REST API: 503.  (503)"
        )
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.dogtag.ca",
            "DogtagCertsConnectivityCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert error_msg in check["kw"]["msg"]
            # pre ipa-healthcheck 0.11, the additional msg was in msg
            # but moved to "error" with 0.11+
            assert additional_msg in check["kw"]["msg"] or \
                   additional_msg == check["kw"]["error"]

    def test_ipahealthcheck_ca_not_configured(self):
        """
        Test if the healthcheck ignores pki-tomcat errors
        when CA is not configured on the machine
        Related: https://github.com/freeipa/freeipa-healthcheck/issues/201
        """
        # uninstall replica installed by class' install method
        tasks.uninstall_replica(self.master, self.replicas[0])

        # install it again without CA
        tasks.install_replica(self.master,
                              self.replicas[0],
                              setup_ca=False,
                              setup_dns=True,
                              extra_args=['--no-dnssec-validation']
                              )
        set_excludes(self.replicas[0], "key", "DSCLE0004")

        # Init a user on replica to assign a DNA range
        tasks.kinit_admin(self.replicas[0])
        tasks.user_add(
            self.replicas[0], 'ipauser1', first='Test', last='User',
        )

        returncode, data = run_healthcheck(self.replicas[0],
                                           failures_only=True)
        assert returncode == 0
        assert len(data) == 0

        # restore the replica original configuration
        tasks.user_del(self.replicas[0], 'ipauser1')
        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.install_replica(
            self.master,
            self.replicas[0],
            setup_dns=True,
            extra_args=['--no-dnssec-validation']
        )


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
        ipahealthcheck.ipa.host when GSSAPI credentials cannot be obtained
        from host's keytab.
        """
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) >= parse_version("0.15"):
            msg = (
                "Service {service} keytab {path} does not exist."
            )
        else:
            msg = (
                "Minor (2529639107): No credentials cache found"
            )

        with tasks.FileBackup(self.master, paths.KRB5_KEYTAB):
            self.master.run_command(["rm", "-f", paths.KRB5_KEYTAB])
            returncode, data = run_healthcheck(
                self.master,
                source="ipahealthcheck.ipa.host",
                check="IPAHostKeytab",
            )
            assert returncode == 1
            assert data[0]["result"] == "ERROR"
            assert msg in data[0]["kw"]["msg"]

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

    def test_ipa_healthcheck_no_errors_with_overrides(self):
        """
        Test overriding command-line options in a configuration file.
        """
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.10"):
            pytest.skip("Skipping test for 0.10 healthcheck version")
        tmpcmd = self.master.run_command(['mktemp'])
        config_file = tmpcmd.stdout_text.strip()
        HC_LOG = "/tmp/hc.log"

        self.master.put_file_contents(
            config_file,
            '\n'.join([
                '[default]',
                'output_type=human'
            ])
        )
        set_excludes(self.master, "key", "DSCLE0004", config_file)
        returncode, output = run_healthcheck(
            self.master, failures_only=True, config=config_file
        )
        assert returncode == 0
        assert output == "No issues found."

        # Setting an output file automatically enables all=True
        self.master.put_file_contents(
            config_file,
            '\n'.join([
                '[default]',
                'output_type=human',
                'output_file=%s' % HC_LOG,
            ])
        )
        set_excludes(self.master, "key", "DSCLE0004")
        returncode, _unused = run_healthcheck(
            self.master, config=config_file
        )
        logsize = len(self.master.get_file_contents(HC_LOG, encoding='utf-8'))
        self.master.run_command(['rm', '-f', HC_LOG])
        self.master.run_command(['rm', '-f', config_file])
        assert logsize > 0  # run afterward to ensure cleanup

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
        SYSTEM_RECORDS = [
            rr
            for h in [self.master, self.replicas[0]]
            for rr in [
                # SRV rrs
                f"_ldap._tcp.{h.domain.name}.:{h.hostname}.",
                f"_kerberos._tcp.{h.domain.name}.:{h.hostname}.",
                f"_kerberos._udp.{h.domain.name}.:{h.hostname}.",
                f"_kerberos-master._tcp.{h.domain.name}.:{h.hostname}.",
                f"_kerberos-master._udp.{h.domain.name}.:{h.hostname}.",
                f"_kpasswd._tcp.{h.domain.name}.:{h.hostname}.",
                f"_kpasswd._udp.{h.domain.name}.:{h.hostname}.",
                # URI rrs
                f"_kerberos.{h.domain.name}.:krb5srv:m:tcp:{h.hostname}.",
                f"_kerberos.{h.domain.name}.:krb5srv:m:udp:{h.hostname}.",
                f"_kpasswd.{h.domain.name}.:krb5srv:m:tcp:{h.hostname}.",
                f"_kpasswd.{h.domain.name}.:krb5srv:m:udp:{h.hostname}.",
            ]
            + [str(ip) for ip in resolve_ip_addresses_nss(h.external_hostname)]
        ]
        SYSTEM_RECORDS.append(f'"{self.master.domain.realm.upper()}"')
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) >= parse_version("0.12"):
            SYSTEM_RECORDS.append('ipa_ca_check')

        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.idns",
            "IPADNSSystemRecordsCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] in SYSTEM_RECORDS

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
        entry = ldap.get_entry(dn)
        entry.single_value["nsslapd-logging-hr-timestamps-enabled"] = 'off'
        try:
            ldap.update_entry(entry)
        except errors.DatabaseError as e:
            expected_msg = "Unknown attribute " \
                           "nsslapd-logging-hr-timestamps-enabled"
            if expected_msg in e.message:
                pytest.skip(
                    "389-ds removed nsslapd-logging-hr-timestamps-enabled")
        yield

        entry = ldap.get_entry(dn)
        entry.single_value["nsslapd-logging-hr-timestamps-enabled"] = 'on'
        ldap.update_entry(entry)

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

    def test_source_pki_server_clones_connectivity_and_data(self):
        """
        This testcase checks that when ClonesConnectivyAndDataCheck
        is run it doesn't display source not found error
        """
        if (tasks.get_pki_version(
                self.master) >= tasks.parse_version('11.5.5')):
            raise pytest.skip("PKI dropped ClonesConnectivyAndDataCheck")
        error_msg = (
            "Source 'pki.server.healthcheck.clones.connectivity_and_data' "
            "not found"
        )
        result = self.master.run_command(
            ["ipa-healthcheck", "--source",
             "pki.server.healthcheck.clones.connectivity_and_data"]
        )
        assert error_msg not in result.stdout_text
        for check in pki_clone_checks:
            assert check in result.stdout_text

    @pytest.fixture
    def modify_tls(self, restart_service):
        """
        Fixture to modify DS tls version to TLS1.0 using dsconf tool and
        revert back to the default TLS1.2
        """
        instance = realm_to_serverid(self.master.domain.realm)
        # The crypto policy must be set to LEGACY otherwise 389ds
        # combines crypto policy amd minSSLVersion and removes
        # TLS1.0 on fedora>=33 as the DEFAULT policy forbids TLS1.0
        self.master.run_command(['update-crypto-policies', '--set', 'LEGACY'])
        self.master.run_command(
            [
                "dsconf",
                "slapd-{}".format(instance),
                "security",
                "set",
                "--tls-protocol-min=TLS1.0",
            ]
        )
        tasks.service_control_dirsrv(self.master)
        yield
        self.master.run_command(['update-crypto-policies', '--set', 'DEFAULT'])
        self.master.run_command(
            [
                "dsconf",
                "slapd-{}".format(instance),
                "security",
                "set",
                "--tls-protocol-min=TLS1.2",
            ]
        )
        tasks.service_control_dirsrv(self.master)

    @pytest.mark.skipif((osinfo.id == 'rhel'
                         and osinfo.version_number >= (9,0)),
                        reason=" TLS versions below 1.2 are not "
                        "supported anymore in RHEL9.0 and above.")
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
        entry = ldap.get_entry(dn)
        entry.single_value["referint-update-delay"] = -1
        ldap.update_entry(entry)

        yield

        entry = ldap.get_entry(dn)
        entry.single_value["referint-update-delay"] = 0
        ldap.update_entry(entry)

    def test_ipahealthcheck_ds_riplugincheck(self, update_riplugin):
        """
        This testcase ensures that RIPluginCheck displays warning
        when update value is set.
        """
        warn_msg = (
            "We advise that you set this value to 0, and enable referint "
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
        entry = ldap.get_entry(dn)
        entry.single_value["nsslapd-rootpwstoragescheme"] = "MD5"
        ldap.update_entry(entry)

        yield

        entry = ldap.get_entry(dn)
        entry.single_value["nsslapd-rootpwstoragescheme"] = "PBKDF2_SHA256"
        ldap.update_entry(entry)

    def test_ds_configcheck_passwordstorage(self, modify_pwdstoragescheme):
        """
        This testcase ensures that ConfigCheck reports CRITICAL
        status when nsslapd-rootpwstoragescheme is set to MD5
        from the required PBKDF2_SHA256
        """
        error_msg = (
            "\n\nIn Directory Server, we offer one hash suitable for this "
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
    def create_logfile(self):
        """
        The fixture calls ipa-healthcheck command in order to
        create /var/log/ipa/healthcheck/healthcheck.log if file
        doesn't already exist.
        File is deleted once the test is finished.
        """
        if not self.master.transport.file_exists(HEALTHCHECK_LOG):
            self.master.run_command(
                ["ipa-healthcheck", "--output-file", HEALTHCHECK_LOG],
                raiseonerr=False,
            )
        yield
        self.master.run_command(["rm", "-f", HEALTHCHECK_LOG])

    def test_sosreport_includes_healthcheck(self, create_logfile):
        """
        This testcase checks that sosreport command
        when run on IPA system with healthcheck installed
        collects healthcheck.log file
        """
        caseid = "123456"
        msg = "[plugin:ipa] collecting path '{}'".format(HEALTHCHECK_LOG)
        cmd = self.master.run_command(
            [
                "sos", "report",
                "-o",
                "ipa",
                "--case-id",
                caseid,
                "--batch",
                "-vv",
                "--build",
            ]
        )
        assert msg in cmd.stdout_text

    def modify_perms_run_healthcheck(self, filename, modify_permissions,
                                     expected_permissions):
        """
        Modify the ipa logfile permissions and run
        healthcheck command to check the status.
        """
        modify_permissions(self.master, path=filename, mode="0644")
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.files", failures_only=True
        )
        assert returncode == 1
        assert len(data) == 1
        assert data[0]["result"] == "WARNING"
        assert data[0]["kw"]["path"] == filename
        assert data[0]["kw"]["type"] == "mode"
        assert data[0]["kw"]["expected"] == expected_permissions

    def test_ipahealthcheck_verify_perms_for_source_files(self,
                                                          modify_permissions):
        """
        This tests checks if files in /var/log are checked with ipa.files
        source.
        The test modifies permissions of ipainstall log file and checks the
        response from healthcheck.
        https://pagure.io/freeipa/issue/8949
        """
        self.modify_perms_run_healthcheck(
            paths.IPASERVER_INSTALL_LOG, modify_permissions,
            expected_permissions="0600"
        )

    def test_ipahealthcheck_verify_perms_upgrade_log_file(self,
                                                          modify_permissions):
        """
        This testcase creates /var/log/ipaupgrade.log file.
        Once the file is generated the permissions are modified
        to check that correct status message is displayed
        by healthcheck tool
        """
        self.master.run_command(["touch", paths.IPAUPGRADE_LOG])
        self.modify_perms_run_healthcheck(
            paths.IPAUPGRADE_LOG, modify_permissions,
            expected_permissions="0600"
        )

    def test_ipa_healthcheck_renew_internal_cert(self):
        """
        This testcase checks that CADogtagCertsConfigCheck can handle
        cert renewal, when there can be two certs with the same nickname
        """
        if (tasks.get_pki_version(
                self.master) < tasks.parse_version('11.4.0')):
            raise pytest.skip("PKI known issue #2022561")
        elif (tasks.get_pki_version(
                self.master) >= tasks.parse_version('11.5.0')):
            raise pytest.skip("Skipping test for 11.5 pki version, since "
                              "check CADogtagCertsConfigCheck is "
                              "not present in source "
                              "pki.server.healthcheck.meta.csconfig")
        self.master.run_command(
            ['ipa-cacert-manage', 'renew', '--self-signed']
        )
        returncode, data = run_healthcheck(
            self.master, "pki.server.healthcheck.meta.csconfig",
            "CADogtagCertsConfigCheck"
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"

    @pytest.fixture
    def remove_healthcheck(self):
        """
        This fixture uninstalls healthcheck package on IPA
        and deletes /var/log/ipa/healthcheck/healthcheck.log
        file and reinstalls healthcheck package once test is
        finished
        """
        tasks.uninstall_packages(self.master, HEALTHCHECK_PKG)
        self.master.run_command(["rm", "-f", HEALTHCHECK_LOG])
        yield
        tasks.install_packages(self.master, HEALTHCHECK_PKG)

    def test_sosreport_without_healthcheck_installed(self, remove_healthcheck):
        """
        This testcase checks that sosreport completes successfully
        even if there is no healthcheck log file to collect
        """
        caseid = "123456"
        self.master.run_command(
            [
                "sos", "report",
                "-o",
                "ipa",
                "--case-id",
                caseid,
                "--batch",
                "-v",
                "--build",
            ]
        )

    @pytest.fixture
    def change_pwd_plugin_default(self):
        """
        Fixture to change the password plugin feature
        to AllowNThash and change it to default
        """
        self.master.run_command(
            [
                "ipa", "config-mod", "--delattr",
                "ipaconfigstring=KDC:Disable Last Success"
            ]
        )
        yield
        self.master.run_command(
            [
                "ipa", "config-mod", "--addattr",
                "ipaconfigstring=KDC:Disable Last Success"
            ]
        )

    def test_krbLastSuccessfulAuth_warning(self, change_pwd_plugin_default):
        """
        This test checks that warning message is displayed
        when password plugin feature is modified to
        AllowNThash
        """
        err_msg = (
            "Last Successful Auth is enabled. "
            "It may cause performance problems."
        )
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.18"):
            pytest.skip("Check does not exist in ipa-healthcheck < 0.18")
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.config",
            "IPAkrbLastSuccessfulAuth",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["msg"] == err_msg

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

        # Remove the replica now since it will be out of sync with the
        # updated certificates and replication will break.
        tasks.uninstall_replica(self.master, self.replicas[0])

        # Store the current date to restore at the end of the test
        now = datetime.now(tz=UTC)
        now_str = datetime.strftime(now, "%Y-%m-%d %H:%M:%S Z")

        # Pick a cert to find the upcoming expiration
        certfile = self.master.get_file_contents(paths.RA_AGENT_PEM)
        cert = x509.load_certificate_list(certfile)
        cert_expiry = cert[0].not_valid_after_utc

        # Stop chronyd so it doesn't freak out with time so off
        restart_service(self.master, 'chronyd')

        # Stop pki_tomcatd so certs are not renewable. Don't restart
        # it because by the time the test is done the server is gone.
        self.master.run_command(
            ["systemctl", "stop", "pki-tomcatd@pki-tomcat"]
        )

        try:
            # move date to the grace period
            grace_date = cert_expiry - timedelta(days=10)
            grace_date = datetime.strftime(grace_date, "%Y-%m-%d 00:00:01 Z")
            self.master.run_command(['date', '-s', grace_date])

            # Restart dirsrv as it doesn't like time jumps
            tasks.service_control_dirsrv(self.master)

            for check in ("IPACertmongerExpirationCheck",
                          "IPACertfileExpirationCheck",):
                execute_expiring_check(check)

            execute_nsscheck_cert_expiring(check)

        finally:
            # Prior to uninstall remove all the cert tracking to prevent
            # errors from certmonger trying to check the status of certs
            # that don't matter because we are uninstalling.
            self.master.run_command(['systemctl', 'stop', 'certmonger'])
            # Important: run_command with a str argument is able to
            # perform shell expansion but run_command with a list of
            # arguments is not
            self.master.run_command(
                "rm -fv " + paths.CERTMONGER_REQUESTS_DIR + "*"
            )
            # Delete the renewal lock file to make sure the helpers don't block
            self.master.run_command("rm -fv " + paths.IPA_RENEWAL_LOCK)
            self.master.run_command(['systemctl', 'start', 'certmonger'])
            # Uninstall the master here so that the certs don't try
            # to renew after the CA is running again.
            tasks.uninstall_master(self.master)

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
        tasks.install_master(
            cls.master, setup_dns=False)

    def test_ipa_dns_systemrecords_check(self):
        """
        Test checks the result of IPADNSSystemRecordsCheck
        when ipa-server is configured without DNS.
        """
        version = tasks.get_healthcheck_version(self.master)
        if (parse_version(version) < parse_version('0.12')):
            expected_msgs = {
                "Expected SRV record missing",
                "Got {count} ipa-ca A records, expected {expected}",
                "Got {count} ipa-ca AAAA records, expected {expected}",
                "Expected URI record missing",
            }
        elif (parse_version(version) < parse_version('0.13')):
            expected_msgs = {
                "Expected SRV record missing",
                "Unexpected ipa-ca address {ipaddr}",
                "expected ipa-ca to contain {ipaddr} for {server}",
                "Expected URI record missing",
            }
        else:
            expected_msgs = {
                "Expected SRV record missing",
                "Expected URI record missing",
                "missing IP address for ipa-ca server {server}",
            }

        tasks.install_packages(self.master, HEALTHCHECK_PKG)
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.idns",
            "IPADNSSystemRecordsCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["msg"] in expected_msgs

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
        tasks.install_master(
            cls.master, setup_dns=True, extra_args=['--no-dnssec-validation']
        )
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

    @pytest.fixture
    def modify_cifs_princ(self):
        """
        This fixture removes the cifs principal from the
        cn=adtrust agents and adds it back
        """
        ldap = self.master.ldap_connect()
        basedn = self.master.domain.basedn
        dn = DN(
            ("cn", "adtrust agents"),
            ("cn", "sysaccounts"),
            ("cn", "etc"),
            basedn,
        )
        entry = ldap.get_entry(dn)
        krbprinc = entry['member']
        entry['member'] = ''
        ldap.update_entry(entry)

        yield

        # Add the entry back
        entry['member'] = krbprinc
        ldap.update_entry(entry)

    def test_trustcontroller_principalcheck(self, modify_cifs_princ):
        """
        This testcase checks when trust between IPA-AD is established
        without any errors, IPATrustControllerPrincipalCheck displays
        result as ERROR and when cifs principal is removed
        """
        error_msg = "{key} is not a member of {group}"
        keyname = "cifs/{}@{}".format(
            self.master.hostname, self.master.domain.realm
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPATrustControllerPrincipalCheck",
        )
        assert returncode == 1
        for check in data:
            assert check["result"] == "ERROR"
            assert check["kw"]["key"] == keyname
            assert check["kw"]["group"] == "adtrust agents"
            assert check["kw"]["msg"] == error_msg

    def test_principalcheck_with_cifs_entry(self):
        """
        This testcase checks IPATrustControllerPrincipalCheck
        displays result as SUCCESS when cifs principal is present
        in cn=adtrust agents group
        """
        keyname = "cifs/{}@{}".format(
            self.master.hostname, self.master.domain.realm
        )
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.trust",
            "IPATrustControllerPrincipalCheck",
        )
        assert returncode == 0
        for check in data:
            assert check["result"] == "SUCCESS"
            assert check["kw"]["key"] == keyname

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
            cmd = ["/usr/bin/stat", "-L", "-c", "%U:%G:%a", path]
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
    for path, path_state in state.items():
        (owner, group, mode) = path_state.split(":", maxsplit=2)
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
        tasks.install_master(
            cls.master, setup_dns=True, extra_args=['--no-dnssec-validation']
        )
        tasks.install_replica(
            cls.master,
            cls.replicas[0],
            setup_dns=True,
            extra_args=['--no-dnssec-validation']
        )
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

    def test_ipa_filecheck_bad_owner(self, modify_permissions):
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.6"):
            pytest.skip("Skipping test for 0.4 healthcheck version")

        # ipa-healthcheck 0.8 returns a list of possible owners instead
        # of a single value
        if parse_version(version) >= parse_version("0.8"):
            expected_owner = 'root,systemd-resolve'
            expected_msg = ("Ownership of %s is admin "
                            "and should be one of root,systemd-resolve"
                            % paths.RESOLV_CONF)
        else:
            expected_owner = 'root'
            expected_msg = ("Ownership of %s is admin and should be root"
                            % paths.RESOLV_CONF)

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
            assert check["kw"]["expected"] == expected_owner
            assert check["kw"]["got"] == 'admin'
            assert check["kw"]["msg"] == expected_msg

    def test_ipa_filecheck_bad_group(self, modify_permissions):
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.6"):
            pytest.skip("Skipping test for 0.4 healthcheck version")

        # ipa-healthcheck 0.8 returns a list of possible groups instead
        # of a single value
        if parse_version(version) >= parse_version("0.8"):
            expected_group = 'root,systemd-resolve'
            expected_msg = ("Group of %s is admins and should be one of "
                            "root,systemd-resolve"
                            % paths.RESOLV_CONF)
        else:
            expected_group = 'root'
            expected_msg = ("Group of %s is admins and should be root"
                            % paths.RESOLV_CONF)

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
            assert check["kw"]["expected"] == expected_group
            assert check["kw"]["got"] == 'admins'
            assert check["kw"]["msg"] == expected_msg

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
        tasks.install_master(
            cls.master, setup_dns=True, extra_args=['--no-dnssec-validation']
        )
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

    @pytest.fixture
    def create_jumbo_file(self):
        """Calculate the free space and create a humongous file to fill it
        within the threshold without using all available space."""

        path = os.path.join('/tmp', str(uuid.uuid4()))
        # CI has a single big disk so we may end up allocating most of it.
        result = self.master.run_command(
            ['df', '--block-size=1024', '--output=avail', '/tmp']
        )
        free = (int(result.stdout_text.split('\n')[1]) // 1024) - 50
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
        tasks.install_master(
            cls.master, setup_dns=True, extra_args=['--no-dnssec-validation']
        )
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)
        set_excludes(cls.master, "key", "DSCLE0004")
        # Because of issue PKI#4906, skip the check ipahealthcheck.ipa.files
        # TomcatFileCheck if random serial numbers are enabled
        cs_cfg = cls.master.get_file_contents(paths.CA_CS_CFG_PATH,
                                              encoding='utf-8')
        if "dbs.cert.id.generator=random" in cs_cfg:
            set_excludes(cls.master, "check", "TomcatFileCheck")

    def test_indent(self):
        """
        Use illegal values for indent
        """
        for option in ('a', '9.0'):
            cmd = self.base_cmd + ["--indent", option]
            result = self.master.run_command(cmd, raiseonerr=False)
            assert result.returncode == 2
            assert ('invalid int value' in result.stderr_text
                    or 'is not an integer' in result.stderr_text)

        version = tasks.get_healthcheck_version(self.master)
        for option in ('-1', '5000'):
            cmd = self.base_cmd + ["--indent", option]
            result = self.master.run_command(cmd, raiseonerr=False)
            if parse_version(version) >= parse_version('0.13'):
                assert result.returncode == 2
                assert 'is not in the range 0-32' in result.stderr_text
            else:
                # Older versions did not check for a given allowed range
                assert result.returncode == 0

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
        assert 'No such file or directory' in result.stdout_text

        # Invalid input file
        cmd = ["ipa-healthcheck", "--input-file", paths.IPA_CA_CRT]
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        assert 'Expecting value' in result.stdout_text

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
        tasks.install_replica(cls.master, cls.replicas[0], nameservers=None)

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
        error_msg1 = "Can't open {} for reading".format(paths.HTTPD_CERT_FILE)
        # OpenSSL3 has a different error message
        error_msg3 = "Could not open file or uri for loading certificate " \
                     "file from {}".format(paths.HTTPD_CERT_FILE)
        returncode, data = run_healthcheck(
            self.master,
            "ipahealthcheck.ipa.certs",
            "IPAOpenSSLChainValidation",
        )
        assert returncode == 1
        for check in data:
            if check["kw"]["key"] == paths.HTTPD_CERT_FILE:
                assert check["result"] == "ERROR"
                assert (error_msg1 in check["kw"]["reason"]
                        or error_msg3 in check["kw"]["reason"])

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
                if check["kw"]["key"] in (
                    paths.HTTPD_CERT_FILE,
                    paths.RA_AGENT_PEM,
                ):
                    assert error_msg in check["kw"]["msg"]
                    assert error_reason.replace(" ", "") in check["kw"][
                        "reason"
                    ].replace(" ", "")
            else:
                assert error_reason in check["kw"]["reason"]
                assert error_reason in check["kw"]["msg"]

    @pytest.fixture
    def remove_server_cert(self):
        """
        Fixture to remove Server cert and revert the change.
        """
        instance = realm_to_serverid(self.master.domain.realm)
        instance_dir = paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance
        self.master.run_command(
            [
                "certutil",
                "-L",
                "-d",
                instance_dir,
                "-n",
                "Server-Cert",
                "-a",
                "-o",
                instance_dir
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
                instance_dir,
                "-A",
                "-i",
                instance_dir
                + "/Server-Cert.pem",
                "-t",
                "u,u,u",
                "-f",
                "%s/pwdfile.txt" % instance_dir,
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
        entry = ldap.get_entry(dn)
        ldap_cert_desc = entry.single_value.get("description")

        def _update_entry(description):
            entry = ldap.get_entry(dn)
            entry.single_value['description'] = description
            ldap.update_entry(entry)

        yield _update_entry

        entry = ldap.get_entry(dn)
        entry.single_value['description'] = ldap_cert_desc
        ldap.update_entry(entry)

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
        ldap = self.master.ldap_connect()
        dn = DN(("uid", "ipara"), ("ou", "People"), ("o", "ipaca"))
        entry = ldap.get_entry(dn)
        ldap_cert_desc = entry.single_value.get("description")

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
                check["kw"]["expected"] == ldap_cert_desc
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


class TestIpaHealthCheckSingleMaster(IntegrationTest):

    @classmethod
    def install(cls, mh):
        # Nota Bene: The ipa server is not installed
        tasks.install_packages(cls.master, HEALTHCHECK_PKG)

    def test_ipahealthcheck_mismatching_certificates_subject(self):
        """
        Test if healthcheck uses cert subject base from IPA and not from
        REALM. This prevents false-positive errors when the subject base is
        customized.

        Related: https://github.com/freeipa/freeipa-healthcheck/issues/253
        """
        # install master with custom cert subject base
        tasks.install_master(
            self.master,
            setup_dns=True,
            extra_args=[
                '--no-dnssec-validation',
                '--subject-base=O=LINUX.IS.GREAT,C=EU'
            ]
        )
        try:
            returncode, data = run_healthcheck(
                self.master,
                source="ipahealthcheck.ipa.certs",
                check="IPADogtagCertsMatchCheck",
                failures_only=True)

            assert returncode == 0
            assert len(data) == 0
        finally:
            # uninstall server for the next step
            tasks.uninstall_master(self.master)

        # install master with custom CA certificate subject DN
        tasks.install_master(
            self.master,
            setup_dns=True,
            extra_args=[
                '--no-dnssec-validation',
                '--ca-subject=CN=Healthcheck test,O=LINUX.IS.GREAT'
            ]
        )

        try:
            returncode, data = run_healthcheck(
                self.master,
                source="ipahealthcheck.ipa.certs",
                check="IPADogtagCertsMatchCheck",
                failures_only=True)

            assert returncode == 0
            assert len(data) == 0

        finally:
            # cleanup
            tasks.uninstall_master(self.master)


class TestIPAHealthcheckWithCALess(CALessBase):
    """
    Install CALess server with user provided certificate.
    """
    num_replicas = 0

    @classmethod
    def install(cls, mh):
        super(TestIPAHealthcheckWithCALess, cls).install(mh)
        cls.create_pkcs12('ca1/server')
        cls.prepare_cacert('ca1')
        result = cls.install_server()
        assert result.returncode == 0

    @pytest.fixture
    def expire_cert_warn(self):
        """
        Fixture to move the cert to about to expire, by moving the
        system date using date -s command and revert it back
        """
        self.master.run_command(['date','-s', '+11Months10Days'])
        yield
        self.master.run_command(['date','-s', '-11Months10Days'])
        self.master.run_command(['ipactl', 'restart'])

    def test_ipahealthcheck_warns_on_expired_user_certs(self, expire_cert_warn):
        """
        This testcase checks that ipa-healthcheck warns
        on expiring user-provided certificates.
        """
        msg = (
            'Request id {key} expires in {days} days. '
            'You need to manually renew this certificate.'
        )
        version = tasks.get_healthcheck_version(self.master)
        if parse_version(version) < parse_version("0.18"):
            pytest.skip("Check does not exist in ipa-healthcheck < 0.18")
        returncode, data = run_healthcheck(
            self.master, "ipahealthcheck.ipa.certs",
            "IPAUserProvidedExpirationCheck",
        )
        assert returncode == 1
        certs = [d["kw"]["key"] for d in data]
        assert set(certs) == {'HTTP', 'LDAP', 'KDC'}
        for check in data:
            assert check["result"] == "WARNING"
            assert check["kw"]["key"] in ("LDAP", "HTTP", "KDC")
            assert check["kw"]["msg"] == msg
