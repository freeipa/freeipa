#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests which testing ability of various subsystems to be
installed.
"""

from __future__ import absolute_import

import os
import re
import textwrap
import time
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography import x509 as crypto_x509

from ipalib import x509
from ipalib.constants import DOMAIN_LEVEL_0, KRA_TRACKING_REQS
from ipalib.constants import IPA_CA_RECORD
from ipalib.constants import ALLOWED_NETBIOS_CHARS
from ipalib.sysrestore import SYSRESTORE_STATEFILE, SYSRESTORE_INDEXFILE
from ipapython.dn import DN
from ipaplatform.constants import constants
from ipaplatform.osinfo import osinfo
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks as platformtasks
from ipapython import ipautil
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_caless import CALessBase, ipa_certs_cleanup
from ipatests.test_integration.test_cert import get_certmonger_fs_id
from ipatests.pytest_ipa.integration import skip_if_fips
from ipaplatform import services


config = get_global_config()


def create_broken_resolv_conf(master):
    # Force a broken resolv.conf to simulate a bad response to
    # reverse zone lookups
    master.resolver.backup()
    master.resolver.setup_resolver('127.0.0.2')


def server_install_setup(func):
    def wrapped(*args):
        master = args[0].master
        create_broken_resolv_conf(master)
        try:
            func(*args)
        finally:
            tasks.uninstall_master(master, clean=False)
            ipa_certs_cleanup(master)
    return wrapped


@pytest.fixture
def server_cleanup(request):
    """
    Fixture to uninstall ipa server before and after the test
    """
    host = request.cls.master
    tasks.uninstall_master(host)
    yield
    tasks.uninstall_master(host)


def create_netbios_name(host):
    """
    Create a NetBIOS name based on the provided host
    """
    netbios = ''.join(
        c for c in host.domain.name.split('.')[0].upper() \
        if c in ALLOWED_NETBIOS_CHARS
    )[:15]
    return netbios


class InstallTestBase1(IntegrationTest):

    num_replicas = 3
    topology = 'star'
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns)

    def test_replica0_ca_less_install(self):
        tasks.install_replica(
            self.master, self.replicas[0], setup_ca=False,
            nameservers='master' if self.master_with_dns else None)

    def test_replica0_ipa_ca_install(self):
        tasks.install_ca(self.replicas[0])

    def test_replica0_ipa_kra_install(self):
        tasks.install_kra(self.replicas[0], first_instance=True)

    def test_replica0_ipa_dns_install(self):
        tasks.install_dns(self.replicas[0])

    def test_replica1_with_ca_install(self):
        tasks.install_replica(
            self.master, self.replicas[1], setup_ca=True,
            nameservers='master' if self.master_with_dns else None)

    def test_replica1_ipa_kra_install(self):
        tasks.install_kra(self.replicas[1])

    def test_replica1_ipa_dns_install(self):
        tasks.install_dns(self.replicas[1])

    def test_replica2_with_ca_kra_install(self):
        tasks.install_replica(
            self.master, self.replicas[2], setup_ca=True, setup_kra=True,
            nameservers='master' if self.master_with_dns else None)

    def test_replica2_ipa_dns_install(self):
        tasks.install_dns(self.replicas[2])


class InstallTestBase2(IntegrationTest):

    num_replicas = 3
    topology = 'star'
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns)

    def test_replica1_with_ca_dns_install(self):
        tasks.install_replica(
            self.master, self.replicas[1], setup_ca=True, setup_dns=True,
            nameservers='master' if self.master_with_dns else None)

    def test_replica1_ipa_kra_install(self):
        tasks.install_kra(self.replicas[1])

    def test_replica2_with_dns_install(self):
        tasks.install_replica(
            self.master, self.replicas[2], setup_ca=False, setup_dns=True,
            nameservers='master' if self.master_with_dns else None)

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
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns)

    def install_replica(self, replica, **kwargs):
        tasks.install_replica(self.master, replica, setup_adtrust=True,
                              **kwargs)

    def test_replica0_only_adtrust(self):
        self.install_replica(
            self.replicas[0], setup_ca=False,
            nameservers='master' if self.master_with_dns else None)

    def test_replica1_all_components_adtrust(self):
        self.install_replica(
            self.replicas[1], setup_ca=True,
            nameservers='master' if self.master_with_dns else None)


##
# Master X Replicas installation tests
##

class TestInstallWithCA1(InstallTestBase1):
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns)

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

    def test_install_with_bad_ldap_conf(self):
        """
        Test a client install with a non standard ldap.config
        https://pagure.io/freeipa/issue/7418
        """
        ldap_conf = paths.OPENLDAP_LDAP_CONF
        base_dn = self.master.domain.basedn
        client = self.replicas[0]
        tasks.uninstall_replica(self.master, client)
        expected_msg1 = "contains deprecated and unsupported " \
                        "entries: HOST, PORT"
        file_backup = client.get_file_contents(ldap_conf, encoding='utf-8')
        constants = "URI ldaps://{}\nBASE {}\nHOST {}\nPORT 636".format(
            self.master.hostname, base_dn,
            self.master.hostname)
        modifications = "{}\n{}".format(file_backup, constants)
        client.put_file_contents(paths.OPENLDAP_LDAP_CONF, modifications)
        result = client.run_command(['ipa-client-install', '-U',
                                     '--domain', client.domain.name,
                                     '--realm', client.domain.realm,
                                     '-p', client.config.admin_name,
                                     '-w', client.config.admin_password,
                                     '--server', self.master.hostname],
                                    raiseonerr=False)
        assert expected_msg1 in result.stderr_text
        client.put_file_contents(ldap_conf, file_backup)


class TestInstallWithCA2(InstallTestBase2):
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns)

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica1_ipa_kra_install(self):
        super(TestInstallWithCA2, self).test_replica1_ipa_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_ipa_kra_install(self):
        super(TestInstallWithCA2, self).test_replica2_ipa_kra_install()


class TestInstallCA(IntegrationTest):
    """
    Tests for CA installation on a replica
    """

    num_replicas = 2

    @classmethod
    def install(cls, mh):
        cls.master.put_file_contents(
            os.path.join(paths.IPA_CCACHES, 'foo'),
            'somerandomstring'
        )
        cls.master.run_command(
            ['mkdir', os.path.join(paths.IPA_CCACHES, 'bar')]
        )
        tasks.install_master(cls.master, setup_dns=False)

    def test_ccaches_cleanup(self):
        """
        The IPA ccaches directory is cleaned up on install. Verify
        that the file we created is now gone.
        """
        assert os.path.exists(os.path.join(paths.IPA_CCACHES, 'foo')) is False
        assert os.path.exists(os.path.join(paths.IPA_CCACHES, 'bar')) is False

    def test_replica_ca_install_with_no_host_dns(self):
        """
        Test for ipa-ca-install --no-host-dns on a replica
        """

        tasks.install_replica(self.master, self.replicas[0], setup_ca=False)
        tasks.install_ca(self.replicas[0], extra_args=["--no-host-dns"])

    def test_replica_ca_install_with_skip_schema_check(self):
        """
        Test for ipa-ca-install --skip-schema-check on a replica
        """

        tasks.install_replica(self.master, self.replicas[1], setup_ca=False)
        tasks.install_ca(self.replicas[1], extra_args=["--skip-schema-check"])

    @skip_if_fips()
    def test_certmonger_reads_token_HSM(self):
        """Test if certmonger reads the token in HSM

        This is to ensure added HSM support for FreeIPA. This test adds
        certificate with sofhsm token and checks if certmonger is tracking
        it.

        related : https://pagure.io/certmonger/issue/125
        """
        test_service = 'test/%s' % self.master.hostname
        pkcs_passwd = 'Secret123'
        pin = '123456'
        noisefile = '/tmp/noisefile'
        self.master.put_file_contents(noisefile, os.urandom(64))

        tasks.kinit_admin(self.master)
        tasks.install_dns(self.master)
        self.master.run_command(['ipa', 'service-add', test_service])

        # create a csr
        cmd_args = ['certutil', '-d', paths.NSS_DB_DIR, '-R', '-a',
                    '-o', '/root/ipa.csr',
                    '-s', "CN=%s" % self.master.hostname,
                    '-z', noisefile]
        self.master.run_command(cmd_args)

        # request certificate
        cmd_args = ['ipa', 'cert-request', '--principal', test_service,
                    '--certificate-out', '/root/test.pem', '/root/ipa.csr']
        self.master.run_command(cmd_args)

        # adding trust flag
        cmd_args = ['certutil', '-A', '-d', paths.NSS_DB_DIR, '-n',
                    'test', '-a', '-i', '/root/test.pem', '-t', 'u,u,u']
        self.master.run_command(cmd_args)

        # export pkcs12 file
        cmd_args = ['pk12util', '-o', '/root/test.p12',
                    '-d', paths.NSS_DB_DIR, '-n', 'test', '-W', pkcs_passwd]
        self.master.run_command(cmd_args)

        # add softhsm lib
        cmd_args = ['modutil', '-dbdir', paths.NSS_DB_DIR, '-add',
                    'softhsm', '-libfile', '/usr/lib64/softhsm/libsofthsm.so']
        self.master.run_command(cmd_args, stdin_text="\n\n")

        # create a token
        cmd_args = ['softhsm2-util', '--init-token', '--label', 'test',
                    '--pin', pin, '--so-pin', pin, '--free']
        self.master.run_command(cmd_args)

        self.master.run_command(['softhsm2-util', '--show-slots'])

        cmd_args = ['certutil', '-F', '-d', paths.NSS_DB_DIR, '-n', 'test']
        self.master.run_command(cmd_args)

        cmd_args = ['pk12util', '-i', '/root/test.p12',
                    '-d', paths.NSS_DB_DIR, '-h', 'test',
                    '-W', pkcs_passwd, '-K', pin]
        self.master.run_command(cmd_args)

        cmd_args = ['certutil', '-A', '-d', paths.NSS_DB_DIR, '-n', 'IPA CA',
                    '-t', 'CT,,', '-a', '-i', paths.IPA_CA_CRT]
        self.master.run_command(cmd_args)

        # validate the certificate
        self.master.put_file_contents('/root/pinfile', pin)
        cmd_args = ['certutil', '-V', '-u', 'V', '-e', '-d', paths.NSS_DB_DIR,
                    '-h', 'test', '-n', 'test:test', '-f', '/root/pinfile']
        result = self.master.run_command(cmd_args)
        assert 'certificate is valid' in result.stdout_text

        # add certificate tracking to certmonger
        cmd_args = ['ipa-getcert', 'start-tracking', '-d', paths.NSS_DB_DIR,
                    '-n', 'test', '-t', 'test', '-P', pin,
                    '-K', test_service]
        result = self.master.run_command(cmd_args)
        request_id = re.findall(r'\d+', result.stdout_text)

        # check if certificate is tracked by certmonger
        status = tasks.wait_for_request(self.master, request_id[0], 300)
        assert status == "MONITORING"

        # ensure if key and token are re-usable
        cmd_args = ['getcert', 'resubmit', '-i', request_id[0]]
        self.master.run_command(cmd_args)

        status = tasks.wait_for_request(self.master, request_id[0], 300)
        assert status == "MONITORING"

    def test_ipa_ca_crt_permissions(self):
        """Verify that /etc/ipa/ca.cert is mode 0644 root:root"""
        result = self.master.run_command(
            ["/usr/bin/stat", "-c", "%U:%G:%a", paths.IPA_CA_CRT]
        )
        out = str(result.stdout_text.strip())
        (owner, group, mode) = out.split(':')
        assert mode == "644"
        assert owner == "root"
        assert group == "root"

    def test_cert_install_with_IPA_issued_cert(self):
        """
        Test replacing an IPA-issued server cert

        ipa-server-certinstall can replace the web and LDAP certs.
        A slightly different code path is taken when the replacement
        certs are issued by IPA. Exercise that path by replacing the
        web cert with itself.
        """
        self.master.run_command(['cp', '-p', paths.HTTPD_CERT_FILE, '/tmp'])
        self.master.run_command(['cp', '-p', paths.HTTPD_KEY_FILE, '/tmp'])

        passwd = self.master.get_file_contents(
            paths.HTTPD_PASSWD_FILE_FMT.format(host=self.master.hostname)
        )
        self.master.run_command([
            'ipa-server-certinstall',
            '-p', self.master.config.dirman_password,
            '-w',
            '--pin', passwd,
            '/tmp/httpd.crt',
            '/tmp/httpd.key',
        ])

    def test_is_ipa_configured(self):
        """Verify that the old and new methods of is_ipa_installed works

           If there is an installation section then it is the status.

           If not then it will fall back to looking for configured
           services and files and use that for determination.
        """
        def set_installation_state(host, state):
            """
            Update the complete value in the installation section
            """
            host.run_command(
                ['python3', '-c',
                 'from ipalib.install import sysrestore; '
                 'from ipaplatform.paths import paths;'
                 'sstore = sysrestore.StateFile(paths.SYSRESTORE); '
                 'sstore.backup_state("installation", "complete", '
                 '{state})'.format(state=state)])

        def get_installation_state(host):
            """
            Retrieve the installation state from new install method
            """
            result = host.run_command(
                ['python3', '-c',
                 'from ipalib.install import sysrestore; '
                 'from ipaplatform.paths import paths;'
                 'sstore = sysrestore.StateFile(paths.SYSRESTORE); '
                 'print(sstore.get_state("installation", "complete"))'])
            return result.stdout_text.strip()  # a string

        # This comes from freeipa.spec and is used to determine whether
        # an upgrade is required.
        cmd = ['python3', '-c',
               'import sys; from ipalib import facts; sys.exit(0 '
               'if facts.is_ipa_configured() else 1);']

        # This will use the new method since this is a fresh install,
        # verify that it is true.
        self.master.run_command(cmd)
        assert get_installation_state(self.master) == 'True'

        # Set complete to False which should cause the command to fail
        # This tests the state of a failed or in-process installation.
        set_installation_state(self.master, False)
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1
        set_installation_state(self.master, True)

        # Tweak sysrestore.state to drop installation section
        self.master.run_command(
            ['sed', '-i', r's/\[installation\]/\[badinstallation\]/',
             os.path.join(paths.SYSRESTORE, SYSRESTORE_STATEFILE)])

        # Re-run installation check and it should fall back to old method
        # and be successful.
        self.master.run_command(cmd)
        assert get_installation_state(self.master) == 'None'

        # Restore installation section.
        self.master.run_command(
            ['sed', '-i', r's/\[badinstallation\]/\[installation\]/',
             os.path.join(paths.SYSRESTORE, SYSRESTORE_STATEFILE)])

        # Uninstall and confirm that the old method reports correctly
        # on uninstalled servers. It will exercise the old method since
        # there is no state.
        tasks.uninstall_master(self.master)

        # ensure there is no stale state
        result = self.master.run_command(r'test -f {}'.format(
            os.path.join(paths.SYSRESTORE, SYSRESTORE_STATEFILE)),
            raiseonerr=False
        )
        assert result.returncode == 1
        result = self.master.run_command(r'test -f {}'.format(
            os.path.join(paths.SYSRESTORE, SYSRESTORE_INDEXFILE)),
            raiseonerr=False
        )
        assert result.returncode == 1

        # Now run is_ipa_configured() and it should be False
        result = self.master.run_command(cmd, raiseonerr=False)
        assert result.returncode == 1


class TestInstallWithCA_KRA1(InstallTestBase1):
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns,
                             setup_kra=True,
                             random_serial=cls.random_serial)

    def test_replica0_ipa_kra_install(self):
        tasks.install_kra(self.replicas[0], first_instance=False)


class TestInstallWithCA_KRA2(InstallTestBase2):
    master_with_dns = False

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns,
                             setup_kra=True)


class TestInstallWithCA_DNS1(InstallTestBase1):
    master_with_dns = True

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns,
                             random_serial=cls.random_serial)

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
    master_with_dns = True

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns)

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica1_ipa_kra_install(self):
        super(TestInstallWithCA_DNS2, self).test_replica1_ipa_kra_install()

    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_ipa_kra_install(self):
        super(TestInstallWithCA_DNS2, self).test_replica2_ipa_kra_install()


class TestInstallWithCA_DNS3(CALessBase):
    """
    Test an install with a bad DNS resolver configured to force a
    timeout trying to verify the existing zones. In the case of a reverse
    zone it is skipped unless --allow-zone-overlap is set regardless of
    the value of --auto-reverse. Confirm that --allow-zone-overlap
    lets the reverse zone be created.

    ticket 7239
    """

    @pytest.mark.xfail(
        osinfo.id == 'fedora' and osinfo.version_number >= (36,),
        reason='freeipa ticket 9135', strict=True)
    @server_install_setup
    def test_number_of_zones(self):
        """There should be two zones: one forward, one reverse"""

        self.create_pkcs12('ca1/server')
        self.prepare_cacert('ca1')

        self.install_server(extra_args=['--allow-zone-overlap'])

        result = self.master.run_command([
            'ipa', 'dnszone-find'])

        assert "in-addr.arpa." in result.stdout_text

        assert "returned 2" in result.stdout_text


class TestInstallWithCA_DNS4(CALessBase):
    """
    Test an install with a bad DNS resolver configured to force a
    timeout trying to verify the existing zones. In the case of a reverse
    zone it is skipped unless --allow-zone-overlap is set regardless of
    the value of --auto-reverse. Confirm that without --allow-reverse-zone
    only the forward zone is created.

    ticket 7239
    """

    @server_install_setup
    def test_number_of_zones(self):
        """There should be one zone, a forward because rev timed-out"""

        self.create_pkcs12('ca1/server')
        self.prepare_cacert('ca1')

        # no zone overlap by default
        self.install_server()

        result = self.master.run_command([
            'ipa', 'dnszone-find'])

        assert "in-addr.arpa." not in result.stdout_text

        assert "returned 1" in result.stdout_text


@pytest.mark.cs_acceptance
class TestInstallWithCA_KRA_DNS1(InstallTestBase1):
    master_with_dns = True

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns,
                             setup_kra=True)

    def test_replica0_ipa_kra_install(self):
        tasks.install_kra(self.replicas[0], first_instance=False)


class TestInstallWithCA_KRA_DNS2(InstallTestBase2):
    master_with_dns = True

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns,
                             setup_kra=True)


class TestADTrustInstall(ADTrustInstallTestBase):
    """
    Tests built-in AD trust installation in various combinations (see the base
    class for more details) against plain IPA master (no DNS, no KRA, no AD
    trust)
    """


class TestADTrustInstallWithDNS_KRA_ADTrust(ADTrustInstallTestBase):
    """
    Tests built-in AD trust installation in various combinations (see the base
    class for more details) against fully equipped (DNS, CA, KRA, ADtrust)
    master. Additional two test cases were added to test interplay including
    KRA installer
    """
    master_with_dns = True

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=cls.master_with_dns,
                             setup_kra=True, setup_adtrust=True)

    def test_replica1_all_components_adtrust(self):
        self.install_replica(self.replicas[1], setup_ca=True, setup_kra=True)


def get_pki_tomcatd_pid(host):
    pid = ''
    cmd = host.run_command(['systemctl', 'status', 'pki-tomcatd@pki-tomcat'])
    for line in cmd.stdout_text.split('\n'):
        if "Main PID" in line:
            pid = line.split()[2]
            break
    return(pid)


def get_ipa_services_pids(host):
    ipa_services_name = [
        "krb5kdc", "kadmin", "named", "httpd", "ipa-custodia",
        "pki_tomcatd"
    ]
    pids_of_ipa_services = {}
    for name in ipa_services_name:
        service_name = services.knownservices[name].systemd_name
        result = host.run_command(
            ["systemctl", "-p", "MainPID", "--value", "show", service_name]
        )
        pids_of_ipa_services[service_name] = int(result.stdout_text.strip())
    return pids_of_ipa_services


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

    @pytest.mark.skip_if_platform(
        "debian", reason="This test hardcodes the httpd service name"
    )
    def test_smoke_test_for_debug_mode(self):
        """Test if an IPA server works in debug mode.
        Related: https://pagure.io/freeipa/issue/8891

        Note: this test hardcodes the "httpd" service name.
        """

        target_fname = paths.IPA_SERVER_CONF
        assert not self.master.transport.file_exists(target_fname)

        # set the IPA server in debug mode
        server_conf = "[global]\ndebug=True"
        self.master.put_file_contents(target_fname, server_conf)
        self.master.run_command(["systemctl", "restart", "httpd"])

        # smoke test in debug mode
        tasks.kdestroy_all(self.master)
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "user-show", "admin"])

        # rollback
        self.master.run_command(["rm", target_fname])
        self.master.run_command(["systemctl", "restart", "httpd"])

    def test_schema_compat_attribute_and_tree_disable(self):
        """Test if schema-compat-entry-attribute is set

        This is to ensure if said entry is set after installation.
        It also checks if compat tree is disable.

        related: https://pagure.io/freeipa/issue/8193
        """
        conn = self.master.ldap_connect()
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))

        entry_list = list(entry['schema-compat-entry-attribute'])
        value = (r'ipaexternalmember=%deref_r('
                 '"member","ipaexternalmember")')
        assert value in entry_list
        assert 'schema-compat-lookup-nsswitch' not in entry_list

    def test_install_kra(self):
        tasks.install_kra(self.master, first_instance=True)

    def test_install_dns(self):
        tasks.install_dns(
            self.master,
            extra_args=['--dnssec-master', '--no-dnssec-validation']
        )

    def test_ipactl_restart_pki_tomcat(self):
        """ Test if ipactl restart restarts the pki-tomcatd

        Wrong logic was triggering the start instead of restart
        for pki-tomcatd. This test validates that restart
        called on pki-tomcat properly.

        related ticket : https://pagure.io/freeipa/issue/7927
        """
        # get process id of pki-tomcatd
        pki_pid = get_pki_tomcatd_pid(self.master)

        # check if pki-tomcad restarted
        cmd = self.master.run_command(['ipactl', 'restart'])
        assert "Restarting pki-tomcatd Service" in cmd.stdout_text

        # check if pid for pki-tomcad changed
        pki_pid_after_restart = get_pki_tomcatd_pid(self.master)
        assert pki_pid != pki_pid_after_restart

        # check if pki-tomcad restarted
        cmd = self.master.run_command(['ipactl', 'restart'])
        assert "Restarting pki-tomcatd Service" in cmd.stdout_text

        # check if pid for pki-tomcad changed
        pki_pid_after_restart_2 = get_pki_tomcatd_pid(self.master)
        assert pki_pid_after_restart != pki_pid_after_restart_2

    def test_ipactl_scenario_check(self):
        """ Test if ipactl starts services stopped by systemctl
        This will first check if all services are running then it will stop
        few service. After that it will restart all services and then check
        the status and pid of services.It will also compare pid after ipactl
        start and restart in case of start it will remain unchanged on the
        other hand in case of restart it will change.
        """
        # listing all services
        ipa_services_name = [
            "Directory", "krb5kdc", "kadmin", "named", "httpd", "ipa-custodia",
            "pki-tomcatd", "ipa-otpd", "ipa-dnskeysyncd"
        ]

        # checking the service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in ipa_services_name:
            assert f"{service} Service: RUNNING" in cmd.stdout_text

        # stopping few services
        service_stop = ["krb5kdc", "kadmin", "httpd"]
        for service in service_stop:
            service_name = services.knownservices[service].systemd_name
            self.master.run_command(['systemctl', 'stop', service_name])

        # checking service status
        service_start = [
            svcs for svcs in ipa_services_name if svcs not in service_stop
        ]
        cmd = self.master.run_command(['ipactl', 'status'], raiseonerr=False)
        assert cmd.returncode == 3
        for service in service_start:
            assert f"{service} Service: RUNNING" in cmd.stdout_text
        for service in service_stop:
            assert f'{service} Service: STOPPED' in cmd.stdout_text

        # starting all services again
        self.master.run_command(['ipactl', 'start'])

        # checking service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in ipa_services_name:
            assert f"{service} Service: RUNNING" in cmd.stdout_text

        # get process id of services
        ipa_services_pids = get_ipa_services_pids(self.master)

        # restarting all services again
        self.master.run_command(['ipactl', 'restart'])

        # checking service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in ipa_services_name:
            assert f"{service} Service: RUNNING" in cmd.stdout_text

        # check if pid for services are different
        svcs_pids_after_restart = get_ipa_services_pids(self.master)
        assert ipa_services_pids != svcs_pids_after_restart

        # starting all services again
        self.master.run_command(['ipactl', 'start'])

        # checking service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in ipa_services_name:
            assert f"{service} Service: RUNNING" in cmd.stdout_text

        # check if pid for services are same
        svcs_pids_after_start = get_ipa_services_pids(self.master)
        assert svcs_pids_after_restart == svcs_pids_after_start

    def test_WSGI_worker_process(self):
        """ Test if WSGI worker process count is set to 4

        related ticket : https://pagure.io/freeipa/issue/7587
        """
        # check process count in httpd conf file i.e expected string
        exp = b'WSGIDaemonProcess ipa processes=%d' % constants.WSGI_PROCESSES
        httpd_conf = self.master.get_file_contents(paths.HTTPD_IPA_CONF)
        assert exp in httpd_conf

        # check the process count
        cmd = self.master.run_command('ps -eF')
        wsgi_count = cmd.stdout_text.count('wsgi:ipa')
        assert constants.WSGI_PROCESSES == wsgi_count

    def test_error_for_yubikey(self):
        """ Test error when yubikey hardware not present

        In order to work with IPA and Yubikey, libyubikey is required.
        Before the fix, if yubikey added without having packages, it used to
        result in traceback. Now it the exception is handeled properly.
        It needs Yubikey hardware to make command successfull. This test
        just check of proper error thrown when hardware is not attached.

        related ticket : https://pagure.io/freeipa/issue/6979
        """
        # try to add yubikey to the user
        args = ['ipa', 'otptoken-add-yubikey', '--owner=admin']
        cmd = self.master.run_command(args, raiseonerr=False)
        assert cmd.returncode != 0
        exp_str = ("ipa: ERROR: No YubiKey found")
        assert exp_str in cmd.stderr_text

    def test_pki_certs(self):
        certs, keys = tasks.certutil_certs_keys(
            self.master,
            paths.PKI_TOMCAT_ALIAS_DIR,
            paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT
        )

        expected_certs = {
            # CA
            'caSigningCert cert-pki-ca': 'CTu,Cu,Cu',
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',  # why P?
            # KRA
            'transportCert cert-pki-kra': 'u,u,u',
            'storageCert cert-pki-kra': 'u,u,u',
            'auditSigningCert cert-pki-kra': 'u,u,Pu',
            # server
            'Server-Cert cert-pki-ca': 'u,u,u',
        }
        assert certs == expected_certs
        assert len(certs) == len(keys)

        for nickname in sorted(certs):
            cert = tasks.certutil_fetch_cert(
                self.master,
                paths.PKI_TOMCAT_ALIAS_DIR,
                paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
                nickname
            )
            key_size = cert.public_key().key_size
            if nickname == 'caSigningCert cert-pki-ca':
                assert key_size == 3072
            else:
                assert key_size == 2048
            assert cert.signature_hash_algorithm.name == hashes.SHA256.name

    def test_http_cert(self):
        """
        Test that HTTP certificate contains ipa-ca.$DOMAIN
        DNS name.

        """
        data = self.master.get_file_contents(paths.HTTPD_CERT_FILE)
        cert = x509.load_pem_x509_certificate(data)
        name = f'ipa-ca.{self.master.domain.name}'
        assert crypto_x509.DNSName(name) in cert.san_general_names

    def test_ipa_cert_in_store(self):
        """
        Test that IPA cert has been added to trust store.
        """

        assert "IPA CA" in self.master.run_command(
            ['trust', 'list'],
            raiseonerr=False).stdout_text

    def test_p11_kit_softhsm2(self):
        # check that p11-kit-proxy does not inject SoftHSM2
        result = self.master.run_command([
            "modutil", "-dbdir", paths.PKI_TOMCAT_ALIAS_DIR, "-list"
        ])
        assert "softhsm" not in result.stdout_text.lower()
        assert "opendnssec" not in result.stdout_text.lower()

    @pytest.mark.skipif(
        not platformtasks.is_selinux_enabled(),
        reason="Test needs SELinux enabled")
    def test_selinux_avcs(self):
        # Use journalctl instead of ausearch. The ausearch command is not
        # installed by default and journalctl gives us all AVCs.
        result = self.master.run_command([
            "journalctl", "--full", "--grep=AVC", "--since=yesterday"
        ], raiseonerr=False)
        avcs = list(
            line.strip() for line in result.stdout_text.split('\n')
            if "AVC avc:" in line
        )
        if avcs:
            print('\n'.join(avcs))
            # Use expected failure until all SELinux violations are fixed
            pytest.xfail("{} AVCs found".format(len(avcs)))

    def test_file_permissions(self):
        args = [
            "rpm", "-V",
            "python3-ipaclient",
            "python3-ipalib",
            "python3-ipaserver"
        ]

        if osinfo.id == 'fedora':
            args.extend([
                "freeipa-client",
                "freeipa-client-common",
                "freeipa-common",
                "freeipa-server",
                "freeipa-server-common",
                "freeipa-server-dns",
                "freeipa-server-trust-ad"
            ])
        else:
            args.extend([
                "ipa-client",
                "ipa-client-common",
                "ipa-common",
                "ipa-server",
                "ipa-server-common",
                "ipa-server-dns"
            ])

        result = self.master.run_command(args, raiseonerr=False)
        if result.returncode != 0:
            # Check the mode errors
            mode_warnings = re.findall(
                r"^.M.......  [cdglr ]+ (?P<filename>.*)$",
                result.stdout_text, re.MULTILINE)
            msg = "rpm -V found mode issues for the following files: {}"
            assert mode_warnings == [], msg.format(mode_warnings)
            # Check the owner errors
            user_warnings = re.findall(
                r"^.....U...  [cdglr ]+ (?P<filename>.*)$",
                result.stdout_text, re.MULTILINE)
            msg = "rpm -V found ownership issues for the following files: {}"
            assert user_warnings == [], msg.format(user_warnings)
            # Check the group errors
            group_warnings = re.findall(
                r"^......G..  [cdglr ]+ (?P<filename>.*)$",
                result.stdout_text, re.MULTILINE)
            msg = "rpm -V found group issues for the following files: {}"
            assert group_warnings == [], msg.format(group_warnings)

    def test_ds_disable_upgrade_hash(self):
        # Test case for https://pagure.io/freeipa/issue/8315
        # Disable password schema migration on LDAP bind
        result = tasks.ldapsearch_dm(
            self.master,
            "cn=config",
            ldap_args=["nsslapd-enable-upgrade-hash"],
            scope="base"
        )
        assert "nsslapd-enable-upgrade-hash: off" in result.stdout_text

    def test_ldbm_tuning(self):
        # check db-locks in new cn=bdb subentry (1.4.3+)
        result = tasks.ldapsearch_dm(
            self.master,
            "cn=bdb,cn=config,cn=ldbm database,cn=plugins,cn=config",
            ["nsslapd-db-locks"],
            scope="base"
        )
        assert "nsslapd-db-locks: 50000" in result.stdout_text

        # no db-locks configuration in old global entry
        result = tasks.ldapsearch_dm(
            self.master,
            "cn=config,cn=ldbm database,cn=plugins,cn=config",
            ["nsslapd-db-locks"],
            scope="base"
        )
        assert "nsslapd-db-locks" not in result.stdout_text

    def test_nsslapd_sizelimit(self):
        """ Test for default value of nsslapd-sizelimit.

        Related : https://pagure.io/freeipa/issue/8962
        """
        result = tasks.ldapsearch_dm(
            self.master,
            "cn=config",
            ["nsslapd-sizelimit"],
            scope="base"
        )
        assert "nsslapd-sizelimit: 100000" in result.stdout_text

    def test_admin_root_alias_CVE_2020_10747(self):
        # Test for CVE-2020-10747 fix
        # https://bugzilla.redhat.com/show_bug.cgi?id=1810160
        rootprinc = "root@{}".format(self.master.domain.realm)
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc in result.stdout_text

        result = self.master.run_command(
            ["ipa", "user-add", "root", "--first", "root", "--last", "root"],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert 'user with name "root" already exists' in result.stderr_text

    def test_dirsrv_no_ssca(self):
        # verify that lib389 installer no longer creates self-signed CA
        result = self.master.run_command(
            ["stat", "/etc/dirsrv/ssca"],
            raiseonerr=False
        )
        assert result.returncode != 0

    def test_ipa_custodia_check(self):
        # check local key retrieval
        self.master.run_command(
            [paths.IPA_CUSTODIA_CHECK, self.master.hostname]
        )

    @pytest.mark.skipif(
        paths.SEMODULE is None, reason="test requires semodule command"
    )
    def test_ipa_selinux_policy(self):
        # check that freeipa-selinux's policy module is loaded and
        # not disabled
        result = self.master.run_command(
            [paths.SEMODULE, "-lfull"]
        )
        # prio module pp [disabled]
        # 100: default priority
        # 200: decentralized SELinux policy priority
        entries = {
            tuple(line.split())
            for line in result.stdout_text.split('\n')
            if line.strip()
        }
        assert ('200', 'ipa', 'pp') in entries

    def test_ipaca_no_redirect(self):
        """Test that ipa-ca.$DOMAIN does not redirect

           ipa-ca is a valid name for an IPA server. It should not
           require a redirect.

           CRL generation does not need to be enabled for this test.
           We aren't exactly testing that a CRL can be retrieved, just
           that the redirect doesn't happen.
        """

        def run_request(url, expected_stdout=None, expected_stderr=None):
            result = self.master.run_command(['curl', '-s', '-v', url])
            if expected_stdout:
                assert expected_stdout in result.stdout_text
            if expected_stderr:
                assert expected_stderr in result.stderr_text

        # CRL publishing on start-up is disabled so drop a file there
        crlfile = os.path.join(paths.PKI_CA_PUBLISH_DIR, 'MasterCRL.bin')
        self.master.put_file_contents(crlfile, 'secret')

        hosts = (
            f'{IPA_CA_RECORD}.{self.master.domain.name}',
            self.master.hostname,
        )

        # Positive tests. Both hosts can serve these.
        urls = (
            'http://{host}/ipa/crl/MasterCRL.bin',
            'http://{host}/ca/ocsp',
            'https://{host}/ca/admin/ca/getCertChain',
            'https://{host}/acme/',
        )
        for url in urls:
            for host in hosts:
                run_request(
                    url.format(host=host),
                    expected_stderr='HTTP/1.1 200'
                )

        # Negative tests. ipa-ca cannot serve these and will redirect and
        # test that existing redirect for unencrypted still works
        urls = (
            'http://{host}/',
            'http://{host}/ipa/json',
            'http://{carecord}.{domain}/ipa/json',
            'https://{carecord}.{domain}/ipa/json',
            'http://{carecord}.{domain}/ipa/config/ca.crt',
        )
        for url in urls:
            run_request(
                url.format(host=self.master.hostname,
                           domain=self.master.domain.name,
                           carecord=IPA_CA_RECORD),
                expected_stdout=f'href="https://{self.master.hostname}/'
            )

    def test_pac_configuration_enabled(self):
        """
        This testcase checks that the default PAC type
        is added to configuration.
        """
        base_dn = str(self.master.domain.basedn)
        dn = DN(
            ("cn", "ipaConfig"),
            ("cn", "etc"),
            base_dn
        )
        result = tasks.ldapsearch_dm(self.master, str(dn),
                                     ["ipaKrbAuthzData"])
        assert 'ipaKrbAuthzData: MS-PAC' in result.stdout_text

    def test_hostname_parameter(self, server_cleanup):
        """
        Test that --hostname parameter is respected in interactive mode.

        https://pagure.io/freeipa/issue/2692
        """
        original_hostname = self.master.hostname
        new_hostname = 'new.' + original_hostname
        # New hostname is added into /etc/hosts as the installer
        # is looking for it for resolution. Without it, an installation
        # fails with `Unable to resolve host name, check /etc/hosts or DNS
        # name resolution`.
        hosts = self.master.get_file_contents(paths.HOSTS, encoding='utf-8')
        new_hosts = hosts.replace(original_hostname, new_hostname)
        self.master.put_file_contents(paths.HOSTS, new_hosts)
        netbios = create_netbios_name(self.master)

        try:
            cmd = ['ipa-server-install', '--hostname', new_hostname]
            with self.master.spawn_expect(cmd, default_timeout=100) as e:
                e.expect_exact('Do you want to configure integrated '
                               'DNS (BIND)? [no]: ')
                e.sendline('no')
                e.expect_exact('Please confirm the domain name [{}]: '.format(
                    original_hostname  # DN is computed from new hostname
                ))
                e.sendline(self.master.domain.name)
                e.expect_exact('Please provide a realm name [{}]: '.format(
                    self.master.domain.realm
                ))
                e.sendline(self.master.domain.realm)
                e.expect_exact('Directory Manager password: ')
                e.sendline(self.master.config.dirman_password)
                e.expect_exact('Password (confirm): ')
                e.sendline(self.master.config.dirman_password)
                e.expect_exact('IPA admin password: ')
                e.sendline(self.master.config.admin_password)
                e.expect_exact('Password (confirm): ')
                e.sendline(self.master.config.admin_password)
                e.expect_exact('NetBIOS domain name [{}]: '.format(netbios))
                e.sendline(netbios)
                e.expect_exact('Do you want to configure chrony with '
                               'NTP server or pool address? [no]: ')
                e.sendline('no')
                e.expect_exact('Continue to configure the system '
                               'with these values? [no]: ')
                e.sendline('yes')
                e.expect_exit(ignore_remaining_output=True, timeout=720)
            hostname = self.master.run_command([
                'hostname', '-f']).stdout_text.strip()
            assert hostname == new_hostname
        finally:
            # no need to restore the hostname as the installer
            # does it during uninstallation
            self.master.put_file_contents(paths.HOSTS, hosts)

    def test_ad_subpackage_dependency(self, server_cleanup):
        """
        Test if the installer is not dependant on trust-ad package and
        succeeds even when AD subpackage is not installed

        https://pagure.io/freeipa/issue/4011
        """
        if osinfo.id == 'fedora':
            package_name = 'freeipa-server-trust-ad'
        else:
            package_name = 'ipa-server-trust-ad'
        reinstall = False
        if tasks.is_package_installed(self.master, package_name):
            tasks.uninstall_packages(self.master, [package_name])
            reinstall = True
        try:
            # Disable dnssec-validation as the test is calling dnf install
            # and mirrors.fedoraproject.org have a broken trust chain
            tasks.install_master(self.master,
                                 extra_args=['--no-dnssec-validation'])
        finally:
            if reinstall:
                tasks.install_packages(self.master, [package_name])

    def test_backup_of_cs_cfg_is_created(self, server_cleanup):
        """
        Test that the installer backs up CS.cfg configuration before it's
        being modified.

        https://pagure.io/freeipa/issue/4166
        """
        bcp_location = paths.CA_CS_CFG_PATH + '.ipabkp'
        original_cfg_content = None
        if self.master.transport.file_exists(paths.CA_CS_CFG_PATH):
            original_cfg_content = self.master.get_file_contents(
                paths.CA_CS_CFG_PATH, encoding='utf-8')

        time_before_install = int(self.master.run_command(
            ['date', '+%s']).stdout_text.strip())
        tasks.install_master(self.master)
        ipaserver_install_log = self.master.get_file_contents(
            paths.IPASERVER_INSTALL_LOG, encoding='utf-8')
        assert 'backing up CS.cfg' in ipaserver_install_log
        assert self.master.transport.file_exists(bcp_location)

        cfg_mod_time = int(self.master.run_command(
            ['stat', '-c', '%Y', paths.CA_CS_CFG_PATH]).stdout_text.strip())
        bcp_mod_time = int(self.master.run_command(
            ['stat', '-c', '%Y', bcp_location]).stdout_text.strip())

        # check if the backup file was modified/created during the installation
        # and before the original file was modified
        assert time_before_install <= bcp_mod_time <= cfg_mod_time
        bcp_cfg_content = self.master.get_file_contents(
            paths.CA_CS_CFG_PATH + '.ipabkp', encoding='utf-8')
        if original_cfg_content is not None:
            assert original_cfg_content == bcp_cfg_content


class TestInstallMasterKRA(IntegrationTest):

    num_replicas = 1

    @classmethod
    def install(cls, mh):
        pass

    def test_install_master(self):
        tasks.install_master(self.master, setup_dns=False, setup_kra=True)

    def test_ipa_ccache_sweep_timer_enabled(self):
        """Test ipa-ccache-sweep.timer enabled by default during installation

        This test checks that ipa-ccache-sweep.timer is enabled by default
        during the ipa installation.

        related: https://pagure.io/freeipa/issue/9107
        """
        result = self.master.run_command(
            ['systemctl', 'is-enabled', 'ipa-ccache-sweep.timer'],
            raiseonerr=False
        )
        assert 'enabled' in result.stdout_text

    def test_install_dns(self):
        tasks.install_dns(self.master)

    def test_kra_certs_renewal(self):
        """
        Test that the KRA subsystem certificates renew properly
        """
        for nickname in KRA_TRACKING_REQS:
            cert = tasks.certutil_fetch_cert(
                self.master,
                paths.PKI_TOMCAT_ALIAS_DIR,
                paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
                nickname
            )
            starting_serial = int(cert.serial_number)
            cmd_arg = [
                'ipa-getcert', 'resubmit', '-v', '-w',
                '-d', paths.PKI_TOMCAT_ALIAS_DIR,
                '-n', nickname,
            ]
            result = self.master.run_command(cmd_arg)
            request_id = re.findall(r'\d+', result.stdout_text)

            status = tasks.wait_for_request(self.master, request_id[0], 120)
            assert status == "MONITORING"

            cert = tasks.certutil_fetch_cert(
                self.master,
                paths.PKI_TOMCAT_ALIAS_DIR,
                paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
                nickname
            )
            assert starting_serial != int(cert.serial_number)

    def test_install_replica_after_kracert_renewal(self):
        """
        Test replica installation with CA after the KRA certs renewal
        """
        tasks.install_replica(self.master, self.replicas[0],
                              setup_ca=True)
        tasks.install_kra(self.replicas[0])


class TestInstallMasterDNS(IntegrationTest):

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        pass

    def test_install_master(self):
        tasks.install_master(
            self.master,
            setup_dns=True,
            extra_args=['--zonemgr', 'me@example.org'],
        )

        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ['ipa', 'dnszone-show', self.master.domain.name]
        ).stdout_text

        assert "Administrator e-mail address: me.example.org" in result

    def test_server_install_lock_bind_recursion(self):
        """Test if server installer lock Bind9 recursion

        This test is to check if recursion can be configured.
        It checks if newly added file /etc/named/ipa-ext.conf
        exists and /etc/named.conf should not have
        'allow-recursion { any; };'. It also checks if ipa-backup
        command backup the /etc/named/ipa-ext.conf file as well

        related : https://pagure.io/freeipa/issue/8079
        """
        # check of /etc/named/ipa-ext.conf exist
        assert self.master.transport.file_exists(paths.NAMED_CUSTOM_CONF)

        # check if /etc/named.conf does not contain 'allow-recursion { any; };'
        string_to_check = 'allow-recursion { any; };'
        named_contents = self.master.get_file_contents(paths.NAMED_CONF,
                                                       encoding='utf-8')
        assert string_to_check not in named_contents

        # check if ipa-backup command backups the /etc/named/ipa-ext.conf
        result = self.master.run_command(['ipa-backup', '-v'])
        assert paths.NAMED_CUSTOM_CONF in result.stderr_text

    def test_install_kra(self):
        tasks.install_kra(self.master, first_instance=True)

    def test_installer_wizard_prompts_for_DNS(self, server_cleanup):
        """
        Installer wizard should prompt for DNS even if --setup-dns is not
        provided as an argument.

        https://pagure.io/freeipa/issue/2575
        """
        cmd = ['ipa-server-install']
        netbios = create_netbios_name(self.master)
        with self.master.spawn_expect(cmd, default_timeout=100) as e:
            e.expect_exact('Do you want to configure integrated '
                           'DNS (BIND)? [no]: ')
            e.sendline('yes')
            e.expect_exact('Server host name [{}]: '.format(
                self.master.hostname))
            e.sendline(self.master.hostname)
            e.expect_exact('Please confirm the domain name [{}]: '.format(
                self.master.domain.name))
            e.sendline(self.master.domain.name)
            e.expect_exact('Please provide a realm name [{}]: '.format(
                self.master.domain.realm
            ))
            e.sendline(self.master.domain.realm)

            e.expect_exact('Directory Manager password: ')
            e.sendline(self.master.config.dirman_password)
            e.expect_exact('Password (confirm): ')
            e.sendline(self.master.config.dirman_password)

            e.expect_exact('IPA admin password: ')
            e.sendline(self.master.config.admin_password)
            e.expect_exact('Password (confirm): ')
            e.sendline(self.master.config.admin_password)

            e.expect_exact(
                'Do you want to configure DNS forwarders? [yes]: ')
            e.sendline('no')  # irrelevant for this test
            e.expect_exact('Do you want to search for missing reverse '
                           'zones? [yes]: ')
            e.sendline('no')  # irrelevant for this test
            e.expect_exact('NetBIOS domain name [{}]: '.format(netbios))
            e.sendline(netbios)
            e.expect_exact('Do you want to configure chrony with NTP '
                           'server or pool address? [no]: ')
            e.sendline('no')  # irrelevant for this test
            e.expect_exact('Continue to configure the system with these '
                           'values? [no]: ')
            e.sendline('yes')
            e.expect_exit(ignore_remaining_output=True, timeout=720)

        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ['ipa', 'dnszone-show', self.master.domain.name]
        ).stdout_text

        assert 'Active zone: True' in result


class TestInstallMasterDNSRepeatedly(IntegrationTest):
    """ Test that a repeated installation of the primary with DNS enabled
    will lead to a already installed message and not in "DNS zone X
    already exists in DNS" in check_zone_overlap.
    The error is only occuring if domain is set explicitly in the command
    line installer as check_zone_overlap is used in the domain_name
    validator.
    """

    num_replicas = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_install_master_releatedly(self):
        cmd = tasks.install_master(self.master,
                                   setup_dns=True,
                                   raiseonerr=False)
        exp_str = ("already exists in DNS")
        assert (exp_str not in cmd.stderr_text and cmd.returncode != 2)


class TestInstallMasterReservedIPasForwarder(IntegrationTest):
    """Test to check if IANA reserved IP doesn't accepted as DNS forwarder

    IANA reserved IP address can not be used as a forwarder.
    This test checks if ipa server installation throws an error when
    0.0.0.0 is specified as forwarder IP address.

    related ticket: https://pagure.io/freeipa/issue/6894
    """

    def test_reserved_ip_as_forwarder(self):
        args = [
            'ipa-server-install',
            '-n', self.master.domain.name,
            '-r', self.master.domain.realm,
            '-p', self.master.config.dirman_password,
            '-a', self.master.config.admin_password,
            '--setup-dns',
            '--forwarder', '0.0.0.0',
            '--auto-reverse']
        cmd = self.master.run_command(args, raiseonerr=False)
        assert cmd.returncode == 2
        exp_str = ("error: option --forwarder: invalid IP address 0.0.0.0: "
                   "cannot use IANA reserved IP address 0.0.0.0")
        assert exp_str in cmd.stderr_text

        server_install_options = (
                "yes\n"
                "{hostname}\n"
                "{dmname}\n\n"
                "{dm_pass}\n{dm_pass}"
                "\n{admin_pass}\n{admin_pass}\n"
                "yes\nyes\n0.0.0.0\n".format(
                    dm_pass=self.master.config.dirman_password,
                    admin_pass=self.master.config.admin_password,
                    dmname=self.master.domain.name,
                    hostname=self.master.hostname))

        cmd = self.master.run_command(['ipa-server-install'],
                                      stdin_text=server_install_options,
                                      raiseonerr=False)
        exp_str = ("Invalid IP Address 0.0.0.0: cannot use IANA reserved "
                   "IP address 0.0.0.0")
        assert exp_str in cmd.stdout_text


class TestKRAinstallAfterCertRenew(IntegrationTest):
    """ Test KRA installtion after ca agent cert renewal

    KRA installation was failing after ca-agent cert gets renewed.
    This test checks if the symptoms no longer exist.

    related ticket: https://pagure.io/freeipa/issue/7288
    """

    def test_KRA_install_after_cert_renew(self):

        tasks.install_master(self.master)

        # get ca-agent cert and load as pem
        dm_pass = self.master.config.dirman_password
        admin_pass = self.master.config.admin_password
        args = [paths.OPENSSL, "pkcs12", "-in",
                paths.DOGTAG_ADMIN_P12, "-nodes",
                "-passin", "pass:{}".format(dm_pass)]
        cmd = self.master.run_command(args)

        certs = x509.load_certificate_list(cmd.stdout_text.encode('utf-8'))

        # get expiry date of agent cert
        cert_expiry = certs[0].not_valid_after_utc

        # move date to grace period so that certs get renewed
        self.master.run_command(['systemctl', 'stop', 'chronyd'])
        grace_date = cert_expiry - timedelta(days=10)
        grace_date = datetime.strftime(grace_date, "%Y-%m-%d %H:%M:%S")
        self.master.run_command(['date', '-s', grace_date])
        # restart service after date change
        self.master.run_command(['ipactl', 'restart'])

        # get the count of certs track by certmonger
        cmd = self.master.run_command(['getcert', 'list'])
        cert_count = cmd.stdout_text.count('Request ID')
        timeout = 600
        count = 0
        start = time.time()
        # wait sometime for cert renewal
        while time.time() - start < timeout:
            cmd = self.master.run_command(['getcert', 'list'])
            count = cmd.stdout_text.count('status: MONITORING')
            if count == cert_count:
                break
            time.sleep(100)
        else:
            # timeout
            raise AssertionError('TimeOut: Failed to renew all the certs')

        # move date after 3 days of actual expiry
        cert_expiry = cert_expiry + timedelta(days=3)
        cert_expiry = datetime.strftime(cert_expiry, "%Y-%m-%d %H:%M:%S")
        self.master.run_command(['date', '-s', cert_expiry])
        # restart service after date change
        self.master.run_command(['ipactl', 'restart'])

        passwd = "{passwd}\n{passwd}\n{passwd}".format(passwd=admin_pass)
        self.master.run_command(['kinit', 'admin'], stdin_text=passwd)
        cmd = self.master.run_command(['ipa-kra-install', '-p', dm_pass, '-U'])
        self.master.run_command(['systemctl', 'start', 'chronyd'])


class TestKRAinstallOnReplicaWithCAHost(IntegrationTest):
    """ Test that KRA install on replica with ca_host overriden fails

    KRA install on a replica should fail
    if the ca_host line in /etc/ipa/default.conf is present

    Related: https://pagure.io/freeipa/issue/8245
    """

    num_replicas = 1

    def test_kra_install_on_replica_with_ca_host_overriden(self):
        tasks.install_master(self.master)
        tasks.install_replica(self.master, self.replicas[0])

        content = self.replicas[0].get_file_contents(paths.IPA_DEFAULT_CONF,
                                                     encoding='utf-8')
        ca_host_line = "ca_host = %s" % self.master.hostname
        new_content = content + '\n' + ca_host_line
        self.replicas[0].put_file_contents(paths.IPA_DEFAULT_CONF,
                                           new_content)

        self.master.run_command(['firewall-cmd', '--add-port=8443/tcp'])

        result = tasks.install_kra(self.replicas[0], raiseonerr=False)

        err_str = "KRA can not be installed when 'ca_host' is overriden in IPA"
        "configuration file."
        assert result.returncode == 1
        assert err_str in result.stderr_text


class TestMaskInstall(IntegrationTest):
    """ Test master and replica installation with wrong mask

    This test checks that master/replica installation fails (expectedly) if
    mask > 022.

    related ticket: https://pagure.io/freeipa/issue/7193
    """
    topology = 'star'

    @classmethod
    def install(cls, mh):
        super(TestMaskInstall, cls).install(mh)
        cls.bashrc_file = cls.master.get_file_contents('/root/.bashrc')

    def test_install_master(self):
        self.master.run_command('echo "umask 0027" >> /root/.bashrc')
        result = self.master.run_command(['umask'])
        assert '0027' in result.stdout_text

        cmd = tasks.install_master(
            self.master, setup_dns=False, raiseonerr=False
        )
        exp_str = ("Unexpected system mask")
        assert (exp_str in cmd.stderr_text and cmd.returncode != 0)

    def test_install_replica(self):
        result = self.master.run_command(['umask'])
        assert '0027' in result.stdout_text

        cmd = self.master.run_command([
            'ipa-replica-install', '-w', self.master.config.admin_password,
            '-n', self.master.domain.name, '-r', self.master.domain.realm,
            '--server', 'dummy_master.%s' % self.master.domain.name,
            '-U'], raiseonerr=False
        )
        exp_str = ("Unexpected system mask")
        assert (exp_str in cmd.stderr_text and cmd.returncode != 0)

    def test_files_ownership_and_permission_teardown(self):
        """ Method to restore the default bashrc contents"""
        if self.bashrc_file is not None:
            self.master.put_file_contents('/root/.bashrc', self.bashrc_file)


class TestInstallMasterReplica(IntegrationTest):
    """https://pagure.io/freeipa/issue/7929
    Problem:
    If a replica installation fails before all the services
    have been enabled then
    it could leave things in a bad state.

    ipa-replica-manage del --cleanup --force
    invalid 'PKINIT enabled server': all masters must have
    IPA master role enabled

    Root cause was that configuredServices were being
    considered when determining what masters provide
    what services, so a partially installed master
    could cause operations to fail on other masters,
    to the point where a broken master couldn't be removed.
    """
    num_replicas = 1
    topology = 'star'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_kra=True)
        # do not install KRA on replica, it is part of test
        tasks.install_replica(cls.master, cls.replicas[0], setup_kra=False)

    def test_replicamanage_del(self):
        """Test Steps:
        1. Setup server
        2. Setup replica
        3. modify the replica entry on Master:
           ldapmodify -D cn="Directory Manager"-w <passwd>
           dn: cn=KDC,cn=<replicaFQDN>,cn=masters,cn=ipa,cn=etc,<baseDN>
           changetype: modify
           delete: ipaconfigstring
           ipaconfigstring: enabledService

           dn: cn=KDC,cn=<replicaFQDN>,cn=masters,cn=ipa,cn=etc,<baseDN>
           add: ipaconfigstring
           ipaconfigstring: configuredService
        4. On master,
           run ipa-replica-manage del <replicaFQDN> --cleanup --force
        """
        # https://pagure.io/freeipa/issue/7929
        # modify the replica entry on Master
        cmd_output = None
        dn_entry = 'dn: cn=KDC,cn=%s,cn=masters,cn=ipa,' \
                   'cn=etc,%s' % \
                   (self.replicas[0].hostname,
                    ipautil.realm_to_suffix(
                        self.replicas[0].domain.realm).ldap_text())
        entry_ldif = textwrap.dedent("""
            {dn}
            changetype: modify
            delete: ipaconfigstring
            ipaconfigstring: enabledService

            {dn}
            add: ipaconfigstring
            ipaconfigstring: configuredService
        """).format(dn=dn_entry)
        cmd_output = tasks.ldapmodify_dm(self.master, entry_ldif)
        assert 'modifying entry' in cmd_output.stdout_text

        cmd_output = self.master.run_command([
            'ipa-replica-manage', 'del',
            self.replicas[0].hostname, '--cleanup', '--force'
        ])

        assert_text = 'Deleted IPA server "%s"' % self.replicas[0].hostname
        assert assert_text in cmd_output.stdout_text


class TestInstallReplicaAgainstSpecificServer(IntegrationTest):
    """Installation of replica against a specific server

    Test to check replica install against specific server. It uses master and
    replica1 without CA and having custodia service stopped. Then try to
    install replica2 from replica1 and expect it to get fail as specified
    server is not providing all the services.

    related ticket: https://pagure.io/freeipa/issue/7566
    """

    num_replicas = 2

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_kra=True)

        # install replica1 without CA
        cmd = tasks.install_replica(cls.master, cls.replicas[0],
                                    setup_ca=False, setup_dns=True,
                                    promote=False)

        # check for warning that CA is not installed on server
        warn = 'WARNING: The CA service is only installed on one server'
        assert warn in cmd.stderr_text

    def test_replica_install_against_server_without_ca(self):
        """Replica install will fail complaining about CA role
        and exit code 4"""

        # stop custodia service on replica1
        self.replicas[0].run_command('systemctl stop ipa-custodia.service')

        # check if custodia service is stopped
        cmd = self.replicas[0].run_command('ipactl status', raiseonerr=False)
        assert 'ipa-custodia Service: STOPPED' in cmd.stdout_text

        try:
            # install replica2 against replica1, as CA is not installed on
            # replica1, installation on replica2 should fail
            cmd = tasks.install_replica(self.replicas[0], self.replicas[1],
                                        promote=False, raiseonerr=False)
            assert cmd.returncode == 4
            error = "please provide a server with the CA role"
            assert error in cmd.stderr_text

        finally:
            tasks.uninstall_master(self.replicas[1],
                                   ignore_topology_disconnect=True,
                                   ignore_last_of_role=True)

    def test_replica_install_against_server_without_kra(self):
        """Replica install will fail complaining about KRA role
        and exit code 4"""

        # install ca on replica1
        tasks.install_ca(self.replicas[0])
        try:
            # install replica2 against replica1, as KRA is not installed on
            # replica1(CA installed), installation should fail on replica2
            cmd = tasks.install_replica(self.replicas[0], self.replicas[1],
                                        promote=False, setup_kra=True,
                                        raiseonerr=False)
            assert cmd.returncode == 4
            error = "please provide a server with the KRA role"
            assert error in cmd.stderr_text

        finally:
            tasks.uninstall_master(self.replicas[1],
                                   ignore_topology_disconnect=True,
                                   ignore_last_of_role=True)

    def test_replica_install_against_server(self):
        """Replica install should succeed if specified server provide all
        the services"""

        tasks.install_replica(self.master, self.replicas[1],
                              setup_dns=True, promote=False)

        # check if replication agreement stablished between master
        # and replica2 only.
        cmd = self.replicas[1].run_command(['ipa-replica-manage', 'list',
                                            self.replicas[0].hostname])
        assert self.replicas[0].hostname not in cmd.stdout_text

        dirman_password = self.master.config.dirman_password
        cmd = self.replicas[1].run_command(['ipa-csreplica-manage', 'list',
                                            self.replicas[0].hostname],
                                           stdin_text=dirman_password)
        assert self.replicas[0].hostname not in cmd.stdout_text

    def test_replica_install_existing_agreement(self):
        """When the replication agreement already exists, the installer
        should print an error message with the information on where
        and how to remove it"""
        # master and replica_1 already installed by class' install() method

        # stop the main server in order to preserve the replication agreement
        # when removing the replica
        tasks.stop_ipa_server(self.master)

        # intentionally using ipa-server-install --uninstall
        # instead of replica-manage
        self.replicas[0].run_command(['ipa-server-install',
                                      '--uninstall',
                                      '--force',
                                      '-U'])
        tasks.start_ipa_server(self.master)

        result = tasks.install_replica(self.master,
                                       self.replicas[0],
                                       setup_ca=False,
                                       setup_dns=True,
                                       promote=False,
                                       raiseonerr=False,
                                       extra_args=('--force-join',))
        assert result.returncode != 0
        assert self.replicas[0].hostname in result.stderr_text
        assert "server-del" in result.stderr_text

        # delete the agreement based on the error message
        # and retry the installation
        self.master.run_command(['ipa',
                                 'server-del',
                                 self.replicas[0].hostname,
                                 '--force'])
        result = tasks.install_replica(self.master,
                                       self.replicas[0],
                                       setup_ca=False,
                                       setup_dns=True,
                                       promote=False)
        assert result.returncode == 0


class TestInstallWithoutSudo(IntegrationTest):

    num_clients = 1
    num_replicas = 1
    no_sudo_str = "The sudo binary does not seem to be present on this"
    sudo_version_str = "Sudo version"

    @classmethod
    def install(cls, mh):
        pass

    def test_sudo_removal(self):
        # ipa-client makes sudo depend on libsss_sudo.

        # --nodeps is mandatory because dogtag uses sudo at install
        # time until commit 49585867207922479644a03078c29548de02cd03
        # which is scheduled to land in 10.10.

        # This also means sudo+libsss_sudo cannot be uninstalled on
        # IPA servers with a CA.
        assert tasks.is_package_installed(self.clients[0], 'sudo')
        assert tasks.is_package_installed(self.clients[0], 'libsss_sudo')
        tasks.uninstall_packages(
            self.clients[0], ['sudo', 'libsss_sudo'], nodeps=True
        )

    def test_ipa_installation_without_sudo(self):
        # FixMe: When Dogtag 10.10 is out, test installation without sudo
        tasks.install_master(self.master, setup_dns=True)

    def test_replica_installation_without_sudo(self):
        # FixMe: When Dogtag 10.10 is out, test replica installation
        # without sudo and with CA
        tasks.uninstall_packages(
            self.replicas[0], ['sudo', 'libsss_sudo'], nodeps=True
        )
        # One-step install is needed.
        # With promote=True, two-step install is done and that only captures
        # the ipa-replica-install stdout/stderr, not ipa-client-install's.
        result = tasks.install_replica(
            self.master, self.replicas[0], promote=False,
            setup_dns=True, setup_ca=False
        )
        assert self.no_sudo_str in result.stderr_text

    def test_client_installation_without_sudo(self):
        result = tasks.install_client(self.master, self.clients[0])
        assert self.no_sudo_str in result.stderr_text

    def test_remove_sudo_on_ipa(self):
        tasks.uninstall_packages(
            self.master, ['sudo', 'libsss_sudo'], nodeps=True
        )
        self.master.run_command(
            ['ipactl', 'restart']
        )

    def test_install_sudo_on_client(self):
        """ Check that installing sudo pulls libsss_sudo in"""
        for pkg in ('sudo', 'libsss_sudo'):
            assert tasks.is_package_installed(self.clients[0], pkg) is False
        tasks.uninstall_client(self.clients[0])
        tasks.install_packages(self.clients[0], ['sudo'])
        for pkg in ('sudo', 'libsss_sudo'):
            assert tasks.is_package_installed(self.clients[0], pkg)
        result = tasks.install_client(self.master, self.clients[0])
        assert self.no_sudo_str not in result.stderr_text
        assert self.sudo_version_str not in result.stdout_text


class TestInstallWithoutNamed(IntegrationTest):
    num_replicas = 1

    @classmethod
    def remove_named(cls, host):
        # remove the bind package and make sure the named user does not exist.
        # https://pagure.io/freeipa/issue/8936
        result = host.run_command(['id', 'named'], raiseonerr=False)
        if result.returncode == 0:
            tasks.uninstall_packages(host, ['bind'])
            host.run_command(['userdel', constants.NAMED_USER])
        assert host.run_command(
            ['id', 'named'], raiseonerr=False
        ).returncode == 1

    @classmethod
    def install(cls, mh):
        for tgt in (cls.master, cls.replicas[0]):
            cls.remove_named(tgt)
        tasks.install_master(cls.master, setup_dns=False)

    def test_replica0_install(self):
        tasks.install_replica(
            self.master, self.replicas[0], setup_ca=False, setup_dns=False
        )


class TestInstallwithSHA384withRSA(IntegrationTest):
    num_replicas = 0

    def test_install_master_withalgo_sha384withrsa(self, server_cleanup):
        tasks.install_master(
            self.master,
            extra_args=['--ca-signing-algorithm=SHA384withRSA'],
        )

        # check Signing Algorithm post installation
        dashed_domain = self.master.domain.realm.replace(".", '-')
        cmd_args = ['certutil', '-L', '-d',
                    '/etc/dirsrv/slapd-{}/'.format(dashed_domain),
                    '-n', 'Server-Cert']
        result = self.master.run_command(cmd_args)
        assert 'SHA-384 With RSA Encryption' in result.stdout_text

    def test_install_master_modify_existing(self, server_cleanup):
        """
        Setup a master
        Stop services
        Modify default.params.signingAlg in CS.cfg
        Restart services
        Resubmit cert (Resubmitted cert should have new Algorithm)
        """
        tasks.install_master(self.master)
        self.master.run_command(['ipactl', 'stop'])
        cs_cfg_content = self.master.get_file_contents(paths.CA_CS_CFG_PATH,
                                                       encoding='utf-8')
        new_lines = []
        replace_str = "ca.signing.defaultSigningAlgorithm=SHA384withRSA"
        ocsp_rep_str = "ca.ocsp_signing.defaultSigningAlgorithm=SHA384withRSA"
        for line in cs_cfg_content.split('\n'):
            if line.startswith('ca.signing.defaultSigningAlgorithm'):
                new_lines.append(replace_str)
            elif line.startswith('ca.ocsp_signing.defaultSigningAlgorithm'):
                new_lines.append(ocsp_rep_str)
            else:
                new_lines.append(line)
        self.master.put_file_contents(paths.CA_CS_CFG_PATH,
                                      '\n'.join(new_lines))
        self.master.run_command(['ipactl', 'start'])

        cmd = ['getcert', 'list', '-f', paths.RA_AGENT_PEM]
        result = self.master.run_command(cmd)
        request_id = get_certmonger_fs_id(result.stdout_text)

        # resubmit RA Agent cert
        cmd = ['getcert', 'resubmit', '-f', paths.RA_AGENT_PEM]
        self.master.run_command(cmd)

        tasks.wait_for_certmonger_status(self.master,
                                         ('CA_WORKING', 'MONITORING'),
                                         request_id)

        cmd_args = ['openssl', 'x509', '-in',
                    paths.RA_AGENT_PEM, '-noout', '-text']
        result = self.master.run_command(cmd_args)
        assert_str = 'Signature Algorithm: sha384WithRSAEncryption'
        assert assert_str in result.stdout_text


class TestHostnameValidator(IntegrationTest):
    """Test installer hostname validator."""

    num_replicas = 0

    def get_args(self, host):
        return [
            'ipa-server-install',
            '-n', host.domain.name,
            '-r', host.domain.realm,
            '-p', host.config.dirman_password,
            '-a', host.config.admin_password,
            '--setup-dns',
            '--forwarder', host.config.dns_forwarder,
            '--auto-reverse',
            '--netbios-name', 'EXAMPLE',
        ]

    def test_user_input_hostname(self):
        # https://pagure.io/freeipa/issue/9111
        # Validate the user-provided hostname
        self.master.run_command(['hostname', 'fedora'])
        result = self.master.run_command(
            self.get_args(self.master), raiseonerr=False,
            stdin_text=self.master.hostname + '\nn\nn\nn\n',
        )

        # Scrape the output for the summary which is only displayed
        # if the hostname is validated.
        hostname = None
        for line in result.stdout_text.split('\n'):
            print(line)
            m = re.match(
                r"Hostname:\s+({})".format(self.master.hostname), line
            )
            if m:
                hostname = m.group(1)
                break
        assert hostname == self.master.hostname

    def test_hostname_with_dot(self):
        # https://pagure.io/freeipa/issue/9111
        # Validate the user-provided hostname
        self.master.run_command(['hostname', 'fedora'])
        result = self.master.run_command(
            self.get_args(self.master), raiseonerr=False,
            stdin_text=self.master.hostname + '.\nn\nn\nn\n',
        )

        # Scrape the output for the summary which is only displayed
        # if the hostname is validated.
        hostname = None
        for line in result.stdout_text.split('\n'):
            print(line)
            m = re.match(
                r"Hostname:\s+({})".format(self.master.hostname), line
            )
            if m:
                hostname = m.group(1)
                break
        assert hostname == self.master.hostname

    def test_hostname_matching_domain(self):
        # https://pagure.io/freeipa/issue/9003
        # Prevent hostname from matching the domain
        self.master.run_command(['hostname', self.master.hostname])
        args = self.get_args(self.master)
        args.extend(['--hostname', self.master.domain.name])
        result = self.master.run_command(
            args, raiseonerr=False,
        )

        assert result.returncode == 1
        assert 'hostname cannot be the same as the domain name' \
            in result.stderr_text


class TestNsslapdIgnoreTimeSkew(IntegrationTest):
    """
    Test to check nsslapd-ignore-time-skew is not disabled.
    """
    num_replicas = 1
    topology = 'line'

    @pytest.fixture
    def update_time_skew(self):
        """
        Fixture enables nsslapd-ignore-time-skew
        parameter and reverts it back
        """
        ldap = self.replicas[0].ldap_connect()
        dn = DN(
            ("cn", "config"),
        )
        entry = ldap.get_entry(dn)
        entry.single_value["nsslapd-ignore-time-skew"] = 'on'
        ldap.update_entry(entry)

        yield

        entry = ldap.get_entry(dn)
        entry.single_value["nsslapd-ignore-time-skew"] = 'off'
        ldap.update_entry(entry)

    def test_check_nsslapd_ignore_time_skew(self):
        """
        This testcase checks that the ignore time skew parameter
        is set to on during the directory server replica
        installation (replication of the suffix) and during
        the CA replica (replication of o=ipaca).
        It also checks that the time skew is reverted during
        pki_tomcat setup stage.
        """
        DIRSRV_LOG = (
            "ignore time skew for initial replication"
        )
        PKI_TOMCAT_LOG = (
            "revert time skew after initial replication"
        )
        install_msg = self.replicas[0].get_file_contents(
            paths.IPAREPLICA_INSTALL_LOG, encoding="utf-8"
        )
        dirsrv_msg = re.findall(DIRSRV_LOG, install_msg)
        assert len(dirsrv_msg) == 2
        assert PKI_TOMCAT_LOG in install_msg

    def test_forcesync_does_not_overwrite_ignore_time_skew(
            self, update_time_skew):
        """
        This testcase checks that calling ipa-replica-manage
        force-sync does not overwrite the value of ignore
        time skew
        """
        result = self.replicas[0].run_command(
            ["ipa-replica-manage", "force-sync",
             "--from", self.master.hostname,
             "--no-lookup", "-v"])
        assert result.returncode == 0
        conn = self.replicas[0].ldap_connect()
        ldap_entry = conn.get_entry(DN("cn=config"))
        assert ldap_entry.single_value['nsslapd-ignore-time-skew'] == "on"
