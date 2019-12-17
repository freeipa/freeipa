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

import pytest
from ipalib.constants import DOMAIN_LEVEL_0
import ipaplatform
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_caless import CALessBase, ipa_certs_cleanup
from ipaplatform import services

config = get_global_config()


def create_broken_resolv_conf(master):
    # Force a broken resolv.conf to simulate a bad response to
    # reverse zone lookups
    master.run_command([
        '/usr/bin/mv',
        paths.RESOLV_CONF,
        '%s.sav' % paths.RESOLV_CONF
    ])

    contents = "# Set as broken by ipatests\nnameserver 127.0.0.2\n"
    master.put_file_contents(paths.RESOLV_CONF, contents)


def restore_resolv_conf(master):
    if os.path.exists('%s.sav' % paths.RESOLV_CONF):
        master.run_command([
            '/usr/bin/mv',
            '%s.sav' % paths.RESOLV_CONF,
            paths.RESOLV_CONF
        ])


def server_install_setup(func):
    def wrapped(*args):
        master = args[0].master
        create_broken_resolv_conf(master)
        try:
            func(*args)
        finally:
            tasks.uninstall_master(master, clean=False)
            restore_resolv_conf(master)
            ipa_certs_cleanup(master)
    return wrapped


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

    @pytest.mark.xfail
    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_with_ca_kra_install(self):
        super(TestInstallWithCA1, self).test_replica2_with_ca_kra_install()

    @pytest.mark.xfail
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
        tasks.install_master(cls.master, setup_dns=False)

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


@pytest.mark.xfail
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

    @pytest.mark.xfail
    @pytest.mark.skipif(config.domain_level == DOMAIN_LEVEL_0,
                        reason='does not work on DOMAIN_LEVEL_0 by design')
    def test_replica2_with_ca_kra_install(self):
        super(TestInstallWithCA_DNS1, self).test_replica2_with_ca_kra_install()

    @pytest.mark.xfail
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
@pytest.mark.xfail
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
        "pki_tomcatd", "ipa-dnskeysyncd"
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

    def test_install_kra(self):
        tasks.install_kra(self.master, first_instance=True)

    def test_install_dns(self):
        tasks.install_dns(self.master)

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
        services = [
            "Directory", "krb5kdc", "kadmin", "named", "httpd", "ipa-custodia",
            "pki-tomcatd", "ipa-otpd", "ipa-dnskeysyncd"
        ]

        # checking the service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in services:
            assert "{} Service: RUNNING".format(service) in cmd.stdout_text

        # stopping few services
        service_stop = ["krb5kdc", "kadmin", "httpd"]
        for service in service_stop:
            self.master.run_command(['systemctl', 'stop', service])

        # checking service status
        service_start = [
            svcs for svcs in services if svcs not in service_stop
        ]
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in service_start:
            assert "{} Service: RUNNING".format(service) in cmd.stdout_text
        for service in service_stop:
            assert '{} Service: STOPPED'.format(service) in cmd.stdout_text

        # starting all services again
        self.master.run_command(['ipactl', 'start'])

        # checking service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in services:
            assert "{} Service: RUNNING".format(service) in cmd.stdout_text

        # get process id of services
        ipa_services_pids = get_ipa_services_pids(self.master)

        # restarting all services again
        self.master.run_command(['ipactl', 'restart'])

        # checking service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in services:
            assert "{} Service: RUNNING".format(service) in cmd.stdout_text

        # check if pid for services are different
        svcs_pids_after_restart = get_ipa_services_pids(self.master)
        assert ipa_services_pids != svcs_pids_after_restart

        # starting all services again
        self.master.run_command(['ipactl', 'start'])

        # checking service status
        cmd = self.master.run_command(['ipactl', 'status'])
        for service in services:
            assert "{} Service: RUNNING".format(service) in cmd.stdout_text

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

    def test_file_permissions(self):
        args = [
            "rpm", "-V",
            "python3-ipaclient",
            "python3-ipalib",
            "python3-ipaserver",
            "python2-ipaclient",
            "python2-ipalib",
            "python2-ipaserver"
        ]

        if ipaplatform.NAME == 'fedora':
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
        tasks.install_master(
            self.master,
            setup_dns=True,
            extra_args=['--zonemgr', 'me@example.org'],
        )

    def test_install_kra(self):
        tasks.install_kra(self.master, first_instance=True)


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
                "yes\n\n\n\n"
                "{dm_pass}\n{dm_pass}"
                "\n{admin_pass}\n{admin_pass}\n"
                "yes\nyes\n0.0.0.0\n".format(
                    dm_pass=self.master.config.dirman_password,
                    admin_pass=self.master.config.admin_password))

        cmd = self.master.run_command(['ipa-server-install'],
                                      stdin_text=server_install_options,
                                      raiseonerr=False)
        exp_str = ("Invalid IP Address 0.0.0.0: cannot use IANA reserved "
                   "IP address 0.0.0.0")
        assert exp_str in cmd.stdout_text


class TestMaskInstall(IntegrationTest):
    """ Test master and replica installation with wrong mask

    This test checks that master/replica installation fails (expectedly) if
    mask > 022.

    related ticket: https://pagure.io/freeipa/issue/7193
    """

    num_replicas = 0

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
        cmd = self.replicas[0].run_command('ipactl status')
        assert 'ipa-custodia Service: STOPPED' in cmd.stdout_text

        try:
            # install replica2 against replica1, as CA is not installed on
            # replica1, installation on replica2 should fail
            cmd = tasks.install_replica(self.replicas[0], self.replicas[1],
                                        raiseonerr=False, promote=False)
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
                                        setup_kra=True, raiseonerr=False,
                                        promote=False)
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

        tasks.install_replica(self.master, self.replicas[1], setup_dns=True,
                              promote=False)

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
