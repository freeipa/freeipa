#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import os
import time
import re
import textwrap

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_ipahealthcheck import (
    run_healthcheck, set_excludes, HEALTHCHECK_PKG
)
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.tasks import (
    assert_error, replicas_cleanup
)
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipalib.constants import (
    DOMAIN_LEVEL_1, IPA_CA_NICKNAME, CA_SUFFIX_NAME
)
from ipaplatform.paths import paths
from ipapython import certdb
from ipatests.test_integration.test_cert import get_certmonger_fs_id
from ipatests.test_integration.test_dns_locations import (
    resolve_records_from_server, IPA_DEFAULT_MASTER_SRV_REC
)
from ipapython.dnsutil import DNSName
from ipalib.constants import IPA_CA_RECORD
from ipatests.util import xfail_context

config = get_global_config()


class ReplicaPromotionBase(IntegrationTest):

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    def test_kra_install_master(self):
        result1 = tasks.install_kra(self.master,
                                    first_instance=True,
                                    raiseonerr=False)
        assert result1.returncode == 0, result1.stderr_text
        tasks.kinit_admin(self.master)
        result2 = self.master.run_command(["ipa", "vault-find"],
                                          raiseonerr=False)
        found = result2.stdout_text.find("0 vaults matched")
        assert(found > 0), result2.stdout_text


def sssd_config_allows_ipaapi_access_to_ifp(host):
    """Checks that the sssd configuration allows the ipaapi user to access
    ifp

    :param host the machine on which to check that sssd allows ipaapi
    access to ifp
    """
    with tasks.remote_sssd_config(host) as sssd_conf:
        ifp = sssd_conf.get_service('ifp')
        uids = [
            uid.strip() for uid in ifp.get_option('allowed_uids').split(',')
        ]
        assert 'ipaapi' in uids


class TestReplicaPromotionLevel1(ReplicaPromotionBase):
    """
    TestCase: http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan#
    Test_case:_Make_sure_the_old_workflow_is_disabled_at_domain_level_1
    """

    topology = 'star'
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_1

    @replicas_cleanup
    def test_one_step_install_pwd_and_admin_pwd(self):
        """--password and --admin-password options are mutually exclusive

        Test for ticket 6353
        """
        # Configure firewall first
        Firewall(self.replicas[0]).enable_services(["freeipa-ldap",
                                                    "freeipa-ldaps"])
        expected_err = "--password and --admin-password options are " \
                       "mutually exclusive"
        result = self.replicas[0].run_command([
            'ipa-replica-install', '-w',
            self.master.config.admin_password,
            '-p', 'OTPpwd',
            '-n', self.master.domain.name,
            '-r', self.master.domain.realm,
            '--server', self.master.hostname,
            '-U'],
            raiseonerr=False)
        assert result.returncode == 1
        assert expected_err in result.stderr_text

    @replicas_cleanup
    def test_install_with_host_auth_ind_set(self):
        """ A client shouldn't be able to be promoted if it has
        any auth indicator set in the host principal.
        https://pagure.io/freeipa/issue/8206
        """

        client = self.replicas[0]
        # Configure firewall first
        Firewall(client).enable_services(["freeipa-ldap",
                                          "freeipa-ldaps"])

        client.run_command(['ipa-client-install', '-U',
                            '--domain', self.master.domain.name,
                            '--realm', self.master.domain.realm,
                            '-p', 'admin',
                            '-w', self.master.config.admin_password,
                            '--server', self.master.hostname,
                            '--force-join'])

        tasks.kinit_admin(client)

        client.run_command(['ipa', 'host-mod', '--auth-ind=otp',
                            client.hostname])

        res = client.run_command(['ipa-replica-install', '-U', '-w',
                                  self.master.config.dirman_password],
                                 raiseonerr=False)

        client.run_command(['ipa', 'host-mod', '--auth-ind=',
                            client.hostname])

        expected_err = ("Client cannot be promoted to a replica if the host "
                        "principal has an authentication indicator set.")
        assert res.returncode == 1
        assert expected_err in res.stderr_text

    @replicas_cleanup
    def test_one_command_installation(self):
        """
        TestCase:
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
        #Test_case:_Replica_can_be_installed_using_one_command
        """
        # Configure firewall first
        Firewall(self.replicas[0]).enable_services(["freeipa-ldap",
                                                    "freeipa-ldaps"])
        self.replicas[0].run_command(['ipa-replica-install', '-w',
                                      self.master.config.admin_password,
                                      '-n', self.master.domain.name,
                                      '-r', self.master.domain.realm,
                                      '--server', self.master.hostname,
                                      '-U'])
        # Ensure that pkinit is properly configured, test for 7566
        result = self.replicas[0].run_command(['ipa-pkinit-manage', 'status'])
        assert "PKINIT is enabled" in result.stdout_text

        # Verify that the sssd configuration allows the ipaapi user to
        # access ifp
        sssd_config_allows_ipaapi_access_to_ifp(self.replicas[0])


class TestUnprivilegedUserPermissions(IntegrationTest):
    """
    TestCase:
    http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
    #Test_case:_Unprivileged_users_are_not_allowed_to_enroll
    _and_promote_clients
    """
    num_replicas = 1
    domain_level = DOMAIN_LEVEL_1

    @classmethod
    def install(cls, mh):
        cls.username = 'testuser'
        tasks.install_master(cls.master, domain_level=cls.domain_level)
        password = cls.master.config.dirman_password
        cls.new_password = '$ome0therPaaS'
        adduser_stdin_text = "%s\n%s\n" % (cls.master.config.admin_password,
                                           cls.master.config.admin_password)
        user_kinit_stdin_text = "%s\n%s\n%s\n" % (password, cls.new_password,
                                                  cls.new_password)
        tasks.kinit_admin(cls.master)
        cls.master.run_command(['ipa', 'user-add', cls.username, '--password',
                                '--first', 'John', '--last', 'Donn'],
                               stdin_text=adduser_stdin_text)
        # Now we need to change the password for the user
        cls.master.run_command(['kinit', cls.username],
                               stdin_text=user_kinit_stdin_text)
        # And again kinit admin
        tasks.kinit_admin(cls.master)

    def test_client_enrollment_by_unprivileged_user(self):
        replica = self.replicas[0]
        result1 = replica.run_command(['ipa-client-install',
                                       '-p', self.username,
                                       '-w', self.new_password,
                                       '--domain', replica.domain.name,
                                       '--realm', replica.domain.realm, '-U',
                                       '--server', self.master.hostname],
                                      raiseonerr=False)
        assert_error(result1, "No permission to join this host", 1)

    def test_replica_promotion_by_unprivileged_user(self):
        replica = self.replicas[0]
        tasks.install_client(self.master, replica)
        # Configure firewall first
        Firewall(replica).enable_services(["freeipa-ldap",
                                           "freeipa-ldaps"])
        result2 = replica.run_command(['ipa-replica-install',
                                       '-P', self.username,
                                       '-p', self.new_password,
                                       '-n', self.master.domain.name,
                                       '-r', self.master.domain.realm],
                                      raiseonerr=False)
        assert_error(result2,
                     "Insufficient privileges to promote the server", 1)

    def test_replica_promotion_after_adding_to_admin_group(self):
        self.master.run_command(['ipa', 'group-add-member', 'admins',
                                 '--users=%s' % self.username])

        # Configure firewall first
        Firewall(self.replicas[0]).enable_services(["freeipa-ldap",
                                                    "freeipa-ldaps"])
        self.replicas[0].run_command(['ipa-replica-install',
                                      '-P', self.username,
                                      '-p', self.new_password,
                                      '-n', self.master.domain.name,
                                      '-r', self.master.domain.realm,
                                      '-U'])

    def test_sssd_config_allows_ipaapi_access_to_ifp(self):
        sssd_config_allows_ipaapi_access_to_ifp(self.replicas[0])


class TestProhibitReplicaUninstallation(IntegrationTest):
    topology = 'line'
    num_replicas = 2
    domain_level = DOMAIN_LEVEL_1

    def test_replica_uninstallation_prohibited(self):
        """
        http://www.freeipa.org/page/V4/Replica_Promotion/Test_plan
        #Test_case:_Prohibit_ipa_server_uninstallation_from_disconnecting
        _topology_segment
        """
        result = self.replicas[0].run_command(['ipa-server-install',
                                               '--uninstall', '-U'],
                                              raiseonerr=False)
        assert_error(result, "Removal of '%s' leads to disconnected"
                             " topology" % self.replicas[0].hostname, 1)
        self.replicas[0].run_command(['ipa-server-install', '--uninstall',
                                      '-U', '--ignore-topology-disconnect'])
        Firewall(self.replicas[0]).disable_services(["freeipa-ldap",
                                                     "freeipa-ldaps"])


class TestWrongClientDomain(IntegrationTest):
    topology = "star"
    num_replicas = 1
    domain_name = 'exxample.test'
    domain_level = DOMAIN_LEVEL_1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    @pytest.fixture(autouse=True)
    def wrong_client_dom_setup(self, request):
        def fin():
            if len(config.domains) == 0:
                # No YAML config was set
                return
            self.replicas[0].run_command(['ipa-client-install',
                                         '--uninstall', '-U'],
                                         raiseonerr=False)
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'host-del',
                                     self.replicas[0].hostname],
                                    raiseonerr=False)
        request.addfinalizer(fin)

    def test_wrong_client_domain(self):
        client = self.replicas[0]
        client.run_command(['ipa-client-install', '-U',
                            '--domain', self.domain_name,
                            '--realm', self.master.domain.realm,
                            '-p', 'admin',
                            '-w', self.master.config.admin_password,
                            '--server', self.master.hostname,
                            '--force-join'])
        # Configure firewall first
        Firewall(client).enable_services(["freeipa-ldap",
                                          "freeipa-ldaps"])
        result = client.run_command(['ipa-replica-install', '-U', '-w',
                                     self.master.config.dirman_password],
                                    raiseonerr=False)
        assert_error(result,
                     "Cannot promote this client to a replica. Local domain "
                     "'%s' does not match IPA domain "
                     "'%s'" % (self.domain_name, self.master.domain.name))

    def test_upcase_client_domain(self):
        client = self.replicas[0]
        result = client.run_command(['ipa-client-install', '-U', '--domain',
                                     self.master.domain.name.upper(), '-w',
                                     self.master.config.admin_password,
                                     '-p', 'admin',
                                     '--server', self.master.hostname,
                                     '--force-join'], raiseonerr=False)
        assert(result.returncode == 0), (
            'Failed to setup client with the upcase domain name')
        # Configure firewall first
        Firewall(self.replicas[0]).enable_services(["freeipa-ldap",
                                                    "freeipa-ldaps"])
        result1 = client.run_command(['ipa-replica-install', '-U', '-w',
                                      self.master.config.dirman_password],
                                     raiseonerr=False)
        assert (result1.returncode == 0), (
            'Failed to promote the client installed with the upcase domain name')

    def test_client_rollback(self):
        """Test that bogus error msgs are not in output on rollback.

           FIXME: including in this suite to avoid setting up a
                  master just to test a client install failure. If
                  a pure client install suite is added this can be
                  moved.

           Ticket https://pagure.io/freeipa/issue/7729
        """
        client = self.replicas[0]

        # Cleanup previous run
        client.run_command(['ipa-server-install',
                            '--uninstall', '-U'], raiseonerr=False)

        result = client.run_command(['ipa-client-install', '-U',
                                     '--server', self.master.hostname,
                                     '--domain', client.domain.name,
                                     '-w', 'foo'], raiseonerr=False)

        assert(result.returncode == 1)

        assert("Unconfigured automount client failed" not in
               result.stdout_text)

        assert("WARNING: Unable to revert" not in result.stdout_text)

        assert("An error occurred while removing SSSD" not in
               result.stdout_text)

    def test_hostname_domain_matching(self):
        client = self.replicas[0]
        client.run_command(['ipa-client-install', '-U', '--domain',
                            self.master.domain.name, '-w',
                            self.master.config.admin_password,
                            '-p', 'admin',
                            '--server', self.master.hostname,
                            '--hostname', self.master.domain.name])
        Firewall(self.replicas[0]).enable_services(["freeipa-ldap",
                                                    "freeipa-ldaps"])
        result = client.run_command(['ipa-replica-install', '-U', '-w',
                                     self.master.config.dirman_password],
                                    raiseonerr=False)
        assert result.returncode == 1
        assert 'hostname cannot be the same as the domain name' \
            in result.stderr_text


class TestRenewalMaster(IntegrationTest):

    topology = 'star'
    num_replicas = 1

    def assertCARenewalMaster(self, host, expected):
        """ Ensure there is only one CA renewal master set """
        result = host.run_command(["ipa", "config-show"]).stdout_text
        matches = list(re.finditer('IPA CA renewal master: (.*)', result))
        assert len(matches), 1
        assert matches[0].group(1) == expected

    def test_replica_not_marked_as_renewal_master(self):
        """
        https://fedorahosted.org/freeipa/ticket/5902
        """
        master = self.master
        replica = self.replicas[0]
        result = master.run_command(["ipa", "config-show"]).stdout_text
        assert("IPA CA renewal master: %s" % master.hostname in result), (
            "Master hostname not found among CA renewal masters"
        )
        assert("IPA CA renewal master: %s" % replica.hostname not in result), (
            "Replica hostname found among CA renewal masters"
        )

    def test_renewal_replica_with_ipa_ca_cert_manage(self):
        """Make replica as IPA CA renewal master using
        ipa-cacert-manage --renew"""
        master = self.master
        replica = self.replicas[0]
        self.assertCARenewalMaster(master, master.hostname)
        replica.run_command([paths.IPA_CACERT_MANAGE, 'renew'])
        self.assertCARenewalMaster(replica, replica.hostname)
        # set master back to ca-renewal-master
        master.run_command([paths.IPA_CACERT_MANAGE, 'renew'])
        self.assertCARenewalMaster(master, master.hostname)
        self.assertCARenewalMaster(replica, master.hostname)

    def test_manual_renewal_master_transfer(self):
        replica = self.replicas[0]
        replica.run_command(['ipa', 'config-mod',
                             '--ca-renewal-master-server', replica.hostname])
        # wait for replication to complete before checking on the master
        tasks.wait_for_replication(replica.ldap_connect())

        result = self.master.run_command(["ipa", "config-show"]).stdout_text
        assert("IPA CA renewal master: %s" % replica.hostname in result), (
            "Replica hostname not found among CA renewal masters"
        )
        # additional check e.g. to see if there is only one renewal master
        self.assertCARenewalMaster(replica, replica.hostname)

    def test_renewal_master_with_csreplica_manage(self):
        master = self.master
        replica = self.replicas[0]

        self.assertCARenewalMaster(master, replica.hostname)
        self.assertCARenewalMaster(replica, replica.hostname)

        master.run_command(['ipa-csreplica-manage', 'set-renewal-master',
                            '-p', master.config.dirman_password])
        result = master.run_command(["ipa", "config-show"]).stdout_text

        assert("IPA CA renewal master: %s" % master.hostname in result), (
            "Master hostname not found among CA renewal masters"
        )

        # lets give replication some time
        time.sleep(60)

        self.assertCARenewalMaster(master, master.hostname)
        self.assertCARenewalMaster(replica, master.hostname)

        replica.run_command(['ipa-csreplica-manage', 'set-renewal-master',
                             '-p', replica.config.dirman_password])
        result = replica.run_command(["ipa", "config-show"]).stdout_text

        assert("IPA CA renewal master: %s" % replica.hostname in result), (
            "Replica hostname not found among CA renewal masters"
        )

        self.assertCARenewalMaster(master, replica.hostname)
        self.assertCARenewalMaster(replica, replica.hostname)

    def test_replica_concheck(self):
        """Test cases for ipa-replica-conncheck command

        Following test cases would be checked:
        - when called with --principal (it should then prompt for a password)
        - when called with --principal / --password
        - when called without principal and password but with a kerberos TGT,
          kinit admin done before calling ipa-replica-conncheck
        - when called without principal and password, and without any kerberos
          TGT (it should default to principal=admin and prompt for a password)

          related: https://pagure.io/freeipa/issue/9047
        """
        exp_str1 = "Connection from replica to master is OK."
        exp_str2 = "Connection from master to replica is OK"
        tasks.kdestroy_all(self.replicas[0])
        # when called with --principal (it should then prompt for a password)
        result = self.replicas[0].run_command(
            ['ipa-replica-conncheck', '--auto-master-check',
             '--master', self.master.hostname,
             '-r', self.replicas[0].domain.realm,
             '-p', self.replicas[0].config.admin_name],
            stdin_text=self.master.config.admin_password
        )
        assert result.returncode == 0
        assert (
            exp_str1 in result.stderr_text and exp_str2 in result.stderr_text
        )

        # when called with --principal / --password
        result = self.replicas[0].run_command([
            'ipa-replica-conncheck', '--auto-master-check',
            '--master', self.master.hostname,
            '-r', self.replicas[0].domain.realm,
            '-p', self.replicas[0].config.admin_name,
            '-w', self.master.config.admin_password
        ])
        assert result.returncode == 0
        assert (
            exp_str1 in result.stderr_text and exp_str2 in result.stderr_text
        )

        # when called without principal and password, and without
        # any kerberos TGT, it should default to principal=admin
        # and prompt for a password
        result = self.replicas[0].run_command(
            ['ipa-replica-conncheck', '--auto-master-check',
             '--master', self.master.hostname,
             '-r', self.replicas[0].domain.realm],
            stdin_text=self.master.config.admin_password
        )
        assert result.returncode == 0
        assert (
            exp_str1 in result.stderr_text and exp_str2 in result.stderr_text
        )

        # when called without principal and password but with a kerberos TGT,
        # kinit admin done before calling ipa-replica-conncheck
        tasks.kinit_admin(self.replicas[0])
        result = self.replicas[0].run_command(
            ['ipa-replica-conncheck', '--auto-master-check',
             '--master', self.master.hostname,
             '-r', self.replicas[0].domain.realm]
        )
        assert result.returncode == 0
        assert (
            exp_str1 in result.stderr_text and exp_str2 in result.stderr_text
        )
        tasks.kdestroy_all(self.replicas[0])

    def test_automatic_renewal_master_transfer_ondelete(self):
        # Test that after replica uninstallation, master overtakes the cert
        # renewal master role from replica (which was previously set there)
        tasks.uninstall_replica(self.master, self.replicas[0])
        result = self.master.run_command(['ipa', 'config-show']).stdout_text
        assert("IPA CA renewal master: %s" % self.master.hostname in result), (
            "Master hostname not found among CA renewal masters"
        )


class TestReplicaInstallWithExistingEntry(IntegrationTest):
    """replica install might fail because of existing entry for replica like
    `cn=ipa-http-delegation,cn=s4u2proxy,cn=etc,$SUFFIX` etc. The situation
    may arise due to incorrect uninstall of replica.

    https://pagure.io/freeipa/issue/7174"""

    num_replicas = 1

    def test_replica_install_with_existing_entry(self):
        master = self.master
        tasks.install_master(master)
        replica = self.replicas[0]
        base_dn = "dc=%s" % (",dc=".join(replica.domain.name.split(".")))
        # adding entry for replica on master so that master will have it before
        # replica installtion begins and creates a situation for pagure-7174
        entry_ldif = textwrap.dedent("""
            dn: cn=ipa-http-delegation,cn=s4u2proxy,cn=etc,{base_dn}
            changetype: modify
            add: memberPrincipal
            memberPrincipal: HTTP/{hostname}@{realm}

            dn: cn=ipa-ldap-delegation-targets,cn=s4u2proxy,cn=etc,{base_dn}
            changetype: modify
            add: memberPrincipal
            memberPrincipal: ldap/{hostname}@{realm}""").format(
            base_dn=base_dn, hostname=replica.hostname,
            realm=replica.domain.name.upper())
        tasks.ldapmodify_dm(master, entry_ldif)

        tasks.install_replica(master, replica)


AUTH_ID_RE = re.compile(
    'Authority ID: '
    '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
)


class TestSubCAkeyReplication(IntegrationTest):
    """
    Test if subca key replication is not failing.
    """
    topology = 'line'
    num_replicas = 1

    SUBCA_DESC = 'subca'

    SUBCA_MASTER = 'test_subca_master'
    SUBCA_MASTER_CN = 'cn=' + SUBCA_MASTER

    SUBCA_REPLICA = 'test_subca_replica'
    SUBCA_REPLICA_CN = 'cn=' + SUBCA_REPLICA

    PKI_DEBUG_PATH = '/var/log/pki/pki-tomcat/ca/debug'

    ERR_MESS = 'Caught exception during cert/key import'

    SERVER_CERT_NICK = 'Server-Cert cert-pki-ca'
    SERVER_KEY_NICK = 'NSS Certificate DB:Server-Cert cert-pki-ca'
    SERVER_KEY_NICK_FIPS = (
        'NSS FIPS 140-2 Certificate DB:Server-Cert cert-pki-ca'
    )
    EXPECTED_CERTS = {
        IPA_CA_NICKNAME: 'CTu,Cu,Cu',
        'ocspSigningCert cert-pki-ca': 'u,u,u',
        'subsystemCert cert-pki-ca': 'u,u,u',
        'auditSigningCert cert-pki-ca': 'u,u,Pu',
        SERVER_CERT_NICK: 'u,u,u',
    }

    def add_subca(self, host, name, subject, raiseonerr=True):
        result = host.run_command([
            'ipa', 'ca-add', name,
            '--subject', subject,
            '--desc', self.SUBCA_DESC],
            raiseonerr=raiseonerr
        )
        if raiseonerr:
            assert "ipa: ERROR:" not in result.stderr_text
            auth_id = "".join(re.findall(AUTH_ID_RE, result.stdout_text))
            return '{} {}'.format(IPA_CA_NICKNAME, auth_id)
        else:
            assert "ipa: ERROR:" in result.stderr_text
            assert result.returncode != 0
            return result

    def del_subca(self, host, name):
        host.run_command([
            'ipa', 'ca-disable', name
        ])
        result = host.run_command([
            'ipa', 'ca-del', name
        ])
        assert "Deleted CA \"{}\"".format(name) in result.stdout_text

    def check_subca(self, host, name, cert_nick):
        result = host.run_command(['ipa', 'ca-show', name])
        # ipa ca-show returns 0 even if the cert cannot be found locally.
        if "ipa: ERROR:" in result.stderr_text:
            return False
        tasks.run_certutil(
            host, ['-L', '-n', cert_nick], paths.PKI_TOMCAT_ALIAS_DIR
        )
        host.run_command([
            paths.CERTUTIL, '-d', paths.PKI_TOMCAT_ALIAS_DIR,
            '-f', paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
            '-K', '-n', cert_nick
        ])
        return True

    def get_certinfo(self, host):
        result = tasks.run_certutil(
            host,
            ['-L', '-f', paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT],
            paths.PKI_TOMCAT_ALIAS_DIR
        )
        certs = {}
        for line in result.stdout_text.splitlines():
            mo = certdb.CERT_RE.match(line)
            if mo:
                # Strip out any token
                nick = mo.group('nick')
                if ':' in nick:
                    nick = nick.split(':', maxsplit=1)[1]
                certs[nick] = mo.group('flags')

        result = tasks.run_certutil(
            host,
            ['-K', '-f', paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT],
            paths.PKI_TOMCAT_ALIAS_DIR
        )
        keys = {}
        for line in result.stdout_text.splitlines():
            mo = certdb.KEY_RE.match(line)
            if mo:
                # Strip out any token
                nick = mo.group('nick')
                if ':' in nick:
                    nick = nick.split(':', maxsplit=1)[1]
                keys[nick] = mo.group('keyid')
        return certs, keys

    def check_certdb(self, master, replica):
        expected_certs = self.EXPECTED_CERTS.copy()
        # find and add sub CAs to expected certs
        result = master.run_command(
            ['ipa', 'ca-find', '--desc', self.SUBCA_DESC]
        )
        for auth_id in re.findall(AUTH_ID_RE, result.stdout_text):
            nick = '{} {}'.format(IPA_CA_NICKNAME, auth_id)
            expected_certs[nick] = 'u,u,u'

        if master.is_fips_mode:
            # Mixed FIPS/non-FIPS installations are not supported
            assert replica.is_fips_mode

        expected_keys = set(expected_certs)

        # get certs and keys from Dogtag's NSSDB
        master_certs, master_keys = self.get_certinfo(master)
        replica_certs, replica_keys = self.get_certinfo(replica)

        assert master_certs == expected_certs
        assert replica_certs == expected_certs

        assert set(master_keys) == expected_keys
        assert set(replica_keys) == expected_keys

        # The Server-Cert keys are unique per-machine
        master_server_key = master_keys.pop('Server-Cert cert-pki-ca')
        replica_server_key = replica_keys.pop('Server-Cert cert-pki-ca')
        assert master_server_key != replica_server_key
        # but key ids of other keys are equal
        assert master_keys == replica_keys

    def check_pki_error(self, host):
        pki_log_filename = "{0}.{1}.log".format(
            self.PKI_DEBUG_PATH,
            time.strftime("%Y-%m-%d")
        )
        pki_debug_log = host.get_file_contents(
            pki_log_filename, encoding='utf-8'
        )
        # check for cert/key import error message
        assert self.ERR_MESS not in pki_debug_log

    def test_subca_master(self):
        master = self.master
        replica = self.replicas[0]

        master_nick = self.add_subca(
            master, self.SUBCA_MASTER, self.SUBCA_MASTER_CN
        )
        # give replication some time, up to 60 seconds
        for _i in range(0,6):
            time.sleep(10)
            m = self.check_subca(master, self.SUBCA_MASTER, master_nick)
            r = self.check_subca(replica, self.SUBCA_MASTER, master_nick)

            if m and r:
                break
        else:
            assert m, "master doesn't have the subCA"
            assert r, "replica doesn't have the subCA"

        self.check_pki_error(replica)
        self.check_certdb(master, replica)

    def test_subca_replica(self):
        master = self.master
        replica = self.replicas[0]

        replica_nick = self.add_subca(
            replica, self.SUBCA_REPLICA, self.SUBCA_REPLICA_CN
        )
        # give replication some time, up to 60 seconds
        for _i in range(0,6):
            time.sleep(10)
            r = self.check_subca(replica, self.SUBCA_REPLICA, replica_nick)
            m = self.check_subca(master, self.SUBCA_REPLICA, replica_nick)

            if m and r:
                break
        else:
            assert m, "master doesn't have the subCA"
            assert r, "replica doesn't have the subCA"

        # replica.run_command(['ipa-certupdate'])
        self.check_pki_error(master)
        self.check_certdb(master, replica)

    def test_sign_with_subca_on_replica(self):
        master = self.master
        replica = self.replicas[0]

        TEST_KEY_FILE = os.path.join(
            paths.OPENSSL_PRIVATE_DIR, 'test_subca.key'
        )
        TEST_CRT_FILE = os.path.join(
            paths.OPENSSL_PRIVATE_DIR, 'test_subca.crt'
        )

        caacl_cmd = [
            'ipa', 'caacl-add-ca', 'hosts_services_caIPAserviceCert',
            '--cas', self.SUBCA_MASTER
        ]
        master.run_command(caacl_cmd)

        request_cmd = [
            paths.IPA_GETCERT, 'request', '-w', '-k', TEST_KEY_FILE,
            '-f', TEST_CRT_FILE, '-X', self.SUBCA_MASTER
        ]
        replica.run_command(request_cmd)

        status_cmd = [paths.IPA_GETCERT, 'status', '-v', '-f', TEST_CRT_FILE]
        status = replica.run_command(status_cmd)
        assert 'State MONITORING, stuck: no' in status.stdout_text

        ssl_cmd = ['openssl', 'x509', '-text', '-in', TEST_CRT_FILE,
                   '-nameopt', 'space_eq']
        ssl = replica.run_command(ssl_cmd)
        assert 'Issuer: CN = {}'.format(self.SUBCA_MASTER) in ssl.stdout_text

    def test_del_subca_master_on_replica(self):
        self.del_subca(self.replicas[0], self.SUBCA_MASTER)

    def test_del_subca_replica(self):
        self.del_subca(self.replicas[0], self.SUBCA_REPLICA)

    def test_scale_add_subca(self):
        master = self.master
        replica = self.replicas[0]

        subcas = {}
        for i in range(0, 16):
            name = "_".join((self.SUBCA_MASTER, str(i)))
            cn = "_".join((self.SUBCA_MASTER_CN, str(i)))
            subcas[name] = self.add_subca(master, name, cn)
            self.add_subca(master, name, cn, raiseonerr=False)

        # give replication some time
        time.sleep(15)

        for name, cert_nick in subcas.items():
            self.check_subca(replica, name, cert_nick)
            self.del_subca(replica, name)


class TestReplicaInstallCustodia(IntegrationTest):
    """
    Pagure Reference: https://pagure.io/freeipa/issue/7518
    """

    topology = 'line'
    num_replicas = 2
    domain_level = DOMAIN_LEVEL_1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, domain_level=cls.domain_level)

    def test_replica_install_for_custodia(self):
        master = self.master
        replica1 = self.replicas[0]
        replica2 = self.replicas[1]

        # Install Replica1 without CA and stop ipa-custodia
        tasks.install_replica(master, replica1, setup_ca=False)
        replica1.run_command(['ipactl', 'status'])
        replica1.run_command(['systemctl', 'stop', 'ipa-custodia'])
        replica1.run_command(['ipactl', 'status'], raiseonerr=False)

        # Install Replica2 with CA with source as Replica1.
        tasks.install_replica(replica1, replica2, setup_ca=True,
                              nameservers='master')
        result = replica2.run_command(['ipactl', 'status'])
        assert 'ipa-custodia Service: RUNNING' in result.stdout_text


def update_etc_hosts(host, ip, old_hostname, new_hostname):
    '''Adds or update /etc/hosts

    If /etc/hosts contains an entry for old_hostname, replace it with
    new_hostname.
    If /etc/hosts did not contain the entry, create one for new_hostname with
    the provided ip.
    The function makes a backup in /etc/hosts.sav

    :param host the machine on which /etc/hosts needs to be update_dns_records
    :param ip the ip address for the new record
    :param old_hostname the hostname to replace
    :param new_hostname the new hostname to put in /etc/hosts
    '''
    # Make a backup
    host.run_command(['/bin/cp',
                      paths.HOSTS,
                      '%s.sav' % paths.HOSTS])
    contents = host.get_file_contents(paths.HOSTS, encoding='utf-8')
    # If /etc/hosts already contains old_hostname, simply replace
    pattern = r'^(.*\s){}(\s)'.format(old_hostname)
    new_contents, mods = re.subn(pattern, r'\1{}\2'.format(new_hostname),
                                 contents, flags=re.MULTILINE)
    # If it didn't contain any entry for old_hostname, just add new_hostname
    if mods == 0:
        short = new_hostname.split(".", 1)[0]
        new_contents = new_contents + "\n{}\t{} {}\n".format(ip,
                                                             new_hostname,
                                                             short)
    host.put_file_contents(paths.HOSTS, new_contents)


def restore_etc_hosts(host):
    '''Restores /etc/hosts.sav into /etc/hosts
    '''
    host.run_command(['/bin/mv',
                      '%s.sav' % paths.HOSTS,
                      paths.HOSTS],
                     raiseonerr=False)


class TestReplicaInForwardZone(IntegrationTest):
    """
    Pagure Reference: https://pagure.io/freeipa/issue/7369

    Scenario: install a replica whose name is in a forwarded zone
    """

    forwardzone = 'forward.test'
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_replica_install_in_forward_zone(self):
        master = self.master
        replica = self.replicas[0]

        # Create a forward zone on the master
        master.run_command(['ipa', 'dnsforwardzone-add', self.forwardzone,
                            '--skip-overlap-check',
                            '--forwarder', master.config.dns_forwarder])

        # Configure the client with a name in the forwardzone
        r_shortname = replica.hostname.split(".", 1)[0]
        r_new_hostname = '{}.{}'.format(r_shortname,
                                        self.forwardzone)

        # Update /etc/hosts on the master with an entry for the replica
        # otherwise replica conncheck would fail
        update_etc_hosts(master, replica.ip, replica.hostname,
                         r_new_hostname)
        # Remove the replica previous hostname from /etc/hosts
        # and add the replica new hostname
        # otherwise replica install will complain because
        # hostname does not match
        update_etc_hosts(replica, replica.ip, replica.hostname,
                         r_new_hostname)

        try:
            # install client with a hostname in the forward zone
            tasks.install_client(self.master, replica,
                                 extra_args=['--hostname', r_new_hostname])

            # Configure firewall first
            Firewall(replica).enable_services(["freeipa-ldap",
                                               "freeipa-ldaps"])
            replica.run_command(['ipa-replica-install',
                                 '--principal', replica.config.admin_name,
                                 '--admin-password',
                                 replica.config.admin_password,
                                 '--setup-dns',
                                 '--forwarder', master.config.dns_forwarder,
                                 '-U'])
        finally:
            # Restore /etc/hosts on master and replica
            restore_etc_hosts(master)
            restore_etc_hosts(replica)


class TestHiddenReplicaPromotion(IntegrationTest):
    """Test hidden replica features
    """
    topology = None
    num_replicas = 2

    @classmethod
    def install(cls, mh):
        for srv in (cls.master, cls.replicas[0]):
            tasks.install_packages(srv, HEALTHCHECK_PKG)
        # master with DNSSEC master
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        cls.master.run_command([
            "ipa-dns-install",
            "--dnssec-master",
            "--forwarder", cls.master.config.dns_forwarder,
            "-U",
        ])
        # hidden replica with CA and DNS
        tasks.install_replica(
            cls.master, cls.replicas[0],
            setup_dns=True, setup_kra=False,
            extra_args=('--hidden-replica',)
        )
        # manually install KRA to verify that hidden state is synced
        tasks.install_kra(cls.replicas[0])

        set_excludes(cls.master, "key", "DSCLE0004")
        set_excludes(cls.replicas[0], "key", "DSCLE0004")

    def _check_dnsrecords(self, hosts_expected, hosts_unexpected=()):
        domain = DNSName(self.master.domain.name).make_absolute()
        rset = [
            (rname, 'SRV')
            for rname, _port in IPA_DEFAULT_MASTER_SRV_REC
        ]
        rset.append((DNSName(IPA_CA_RECORD), 'A'))

        for rname, rtype in rset:
            name_abs = rname.derelativize(domain)
            query = resolve_records_from_server(
                name_abs, rtype, self.master.ip
            )
            if rtype == 'SRV':
                records = [q.target.to_text() for q in query]
            else:
                records = [q.address for q in query]
            for host in hosts_expected:
                value = host.hostname + "." if rtype == 'SRV' else host.ip
                assert value in records
            for host in hosts_unexpected:
                value = host.hostname + "." if rtype == 'SRV' else host.ip
                assert value not in records

    def _check_server_role(self, host, status, kra=True, dns=True):
        roles = [u'IPA master', u'CA server']
        if kra:
            roles.append(u'KRA server')
        if dns:
            roles.append(u'DNS server')
        for role in roles:
            result = self.replicas[0].run_command([
                'ipa', 'server-role-find',
                '--server', host.hostname,
                '--role', role
            ])
            expected = 'Role status: {}'.format(status)
            assert expected in result.stdout_text

    def _check_config(self, enabled=(), hidden=()):
        enabled = {host.hostname for host in enabled}
        hidden = {host.hostname for host in hidden}
        services = [
            'IPA masters', 'IPA CA servers', 'IPA KRA servers',
            'IPA DNS servers'
        ]

        result = self.replicas[0].run_command(['ipa', 'config-show'])
        values = {}
        for line in result.stdout_text.split('\n'):
            if ':' not in line:
                continue
            k, v = line.split(':', 1)
            values[k.strip()] = {item.strip() for item in v.split(',')}

        for service in services:
            hservice = 'Hidden {}'.format(service)
            assert values.get(service, set()) == enabled
            assert values.get(hservice, set()) == hidden

    def test_hidden_replica_install(self):
        self._check_server_role(self.master, 'enabled')
        self._check_server_role(self.replicas[0], 'hidden')
        self._check_dnsrecords([self.master], [self.replicas[0]])
        self._check_config([self.master], [self.replicas[0]])

    def test_ipahealthcheck_hidden_replica(self):
        """Ensure that ipa-healthcheck runs successfully on all members
        of an IPA cluster that includes a hidden replica.
        """
        os_version = (tasks.get_platform(self.master),
                      tasks.get_platform_version(self.master))
        pki_version = tasks.get_pki_version(self.master)

        # verify state
        self._check_config([self.master], [self.replicas[0]])
        # A DNA range is needed on the replica for ipa-healthcheck to work.
        # Create a user so that the replica gets a range.
        tasks.user_add(self.replicas[0], 'testuser')
        tasks.user_del(self.replicas[0], 'testuser')
        for srv in (self.master, self.replicas[0]):
            returncode, _unused = run_healthcheck(
                srv,
                failures_only=True
            )
            pki_too_old = \
                (os_version[0] == 'fedora'
                    and pki_version < tasks.parse_version('11.1.0'))\
                or (os_version[0] == 'rhel'
                    and os_version[1][0] == 8
                    and pki_version < tasks.parse_version('10.12.0'))\
                or (os_version[0] == 'rhel'
                    and os_version[1][0] == 9
                    and pki_version < tasks.parse_version('11.0.4'))
            with xfail_context(pki_too_old,
                               'https://pagure.io/freeipa/issue/8582'):
                assert returncode == 0

    def test_hide_last_visible_server_fails(self):
        # verify state
        self._check_config([self.master], [self.replicas[0]])
        # nothing to do
        result = self.master.run_command([
            'ipa', 'server-state',
            self.master.hostname, '--state=enabled'
        ], raiseonerr=False)
        assert result.returncode == 1
        assert "no modifications to be performed" in result.stderr_text
        # hiding the last master fails
        result = self.master.run_command([
            'ipa', 'server-state',
            self.master.hostname, '--state=hidden'
        ], raiseonerr=False)
        assert result.returncode == 1
        keys = [
            "CA renewal master", "DNSSec key master", "CA server",
            "KRA server", "DNS server", "IPA server"
        ]
        for key in keys:
            assert key in result.stderr_text

    def test_hidden_replica_promote(self):
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=enabled'
        ])
        self._check_server_role(self.replicas[0], 'enabled')
        tasks.wait_for_replication(
            self.replicas[0].ldap_connect()
        )
        tasks.dns_update_system_records(self.master)
        tasks.wait_for_replication(
            self.master.ldap_connect()
        )
        self._check_config([self.master, self.replicas[0]])
        self._check_dnsrecords([self.master, self.replicas[0]])

    def test_promote_twice_fails(self):
        result = self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=enabled'
        ], raiseonerr=False)
        assert result.returncode == 1
        assert 'no modifications to be performed' in result.stderr_text

    def test_hidden_replica_demote(self):
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=hidden'
        ])
        self._check_server_role(self.replicas[0], 'hidden')
        tasks.wait_for_replication(
            self.replicas[0].ldap_connect()
        )
        tasks.dns_update_system_records(self.master)
        tasks.wait_for_replication(
            self.master.ldap_connect()
        )
        self._check_config([self.master], [self.replicas[0]])
        self._check_dnsrecords([self.master], [self.replicas[0]])

    def test_replica_from_hidden(self):
        # install a replica from a hidden replica
        self._check_server_role(self.replicas[0], 'hidden')
        tasks.install_replica(
            master=self.replicas[0],
            replica=self.replicas[1],
            setup_dns=True
        )
        self._check_server_role(self.replicas[0], 'hidden')
        self._check_server_role(
            self.replicas[1], 'enabled', kra=False, dns=False
        )
        self._check_dnsrecords(
            [self.master, self.replicas[1]], [self.replicas[0]]
        )
        # hide the new replica
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[1].hostname, '--state=hidden'
        ])
        # and establish replication agreements from master
        tasks.connect_replica(
            master=self.master,
            replica=self.replicas[1],
        )
        tasks.connect_replica(
            master=self.master,
            replica=self.replicas[1],
            database=CA_SUFFIX_NAME,
        )
        # remove replication agreements again
        tasks.disconnect_replica(
            master=self.master,
            replica=self.replicas[1],
        )
        tasks.disconnect_replica(
            master=self.master,
            replica=self.replicas[1],
            database=CA_SUFFIX_NAME,
        )
        # and uninstall
        tasks.uninstall_replica(
            master=self.replicas[0],
            replica=self.replicas[1],
        )

    def test_hidden_replica_backup_and_restore(self):
        """Exercises backup+restore and hidden replica uninstall
        """
        self._check_server_role(self.replicas[0], 'hidden')
        # backup
        backup_path = tasks.get_backup_dir(self.replicas[0])
        # uninstall
        tasks.uninstall_master(self.replicas[0])
        # restore
        dirman_password = self.master.config.dirman_password
        self.replicas[0].run_command(
            ['ipa-restore', backup_path],
            stdin_text=dirman_password + '\nyes'
        )

        tasks.kinit_admin(self.master)
        tasks.kinit_admin(self.replicas[0])

        # restore turns a hidden replica into an enabled replica
        # https://pagure.io/freeipa/issue/7894
        self._check_config([self.master, self.replicas[0]])
        self._check_server_role(self.replicas[0], 'enabled')

    def test_hidden_replica_automatic_crl(self):
        """Exercises if automatic CRL configuration works with
           hidden replica.
        """
        # Demoting Replica to be hidden.
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=hidden'
        ])
        self._check_server_role(self.replicas[0], 'hidden')

        # check CRL status
        result = self.replicas[0].run_command([
            'ipa-crlgen-manage', 'status'])
        assert "CRL generation: disabled" in result.stdout_text

        # Enbable CRL status on hidden replica
        self.replicas[0].run_command([
            'ipa-crlgen-manage', 'enable'])

        # check CRL status
        result = self.replicas[0].run_command([
            'ipa-crlgen-manage', 'status'])
        assert "CRL generation: enabled" in result.stdout_text

    def test_hidden_replica_renew_pkinit_cert(self):
        """Renew the PKINIT cert on a hidden replica.

        Test for https://pagure.io/freeipa/issue/9611
        """
        # Get Request ID
        cmd = ['getcert', 'list', '-f', paths.KDC_CERT]
        result = self.replicas[0].run_command(cmd)
        req_id = get_certmonger_fs_id(result.stdout_text)

        self.replicas[0].run_command([
            'getcert', 'resubmit', '-f', paths.KDC_CERT
        ])
        tasks.wait_for_certmonger_status(
            self.replicas[0], ('MONITORING'), req_id, timeout=600
        )


class TestHiddenReplicaKRA(IntegrationTest):
    """Test KRA & hidden replica features.
    """
    topology = 'star'
    num_replicas = 2

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=False)
        # hidden replica with CA and DNS
        tasks.install_replica(
            cls.master, cls.replicas[0],
            setup_dns=True, setup_kra=False,
            extra_args=('--hidden-replica',)
        )
        # normal replica with CA and DNS
        tasks.install_replica(
            cls.replicas[0], cls.replicas[1],
            setup_dns=True, setup_kra=False
        )

    def test_install_kra_on_hidden_replica(self):
        # manually install KRA on hidden replica.
        tasks.install_kra(self.replicas[0])

    @pytest.mark.xfail(reason='freeipa ticket 8240', strict=True)
    def test_kra_hidden_no_preconfig(self):
        """Test installing KRA on a replica when all KRAs are hidden.
           https://pagure.io/freeipa/issue/8240
        """

        result = tasks.install_kra(self.replicas[1], raiseonerr=False)

        if result.returncode == 0:
            # If KRA installation was successful, the only clean-up possible is
            # uninstalling the whole replica as hiding the last visible KRA
            # member is inhibited by design.
            # This step is necessary so that the next test runs with all KRA
            # members hidden too.
            tasks.uninstall_replica(self.master, self.replicas[1])

        assert "Failed to find an active KRA server!" not in result.stderr_text
        assert result.returncode == 0

    def test_kra_hidden_temp(self):
        """Test for workaround: temporarily un-hide the hidden replica.
           https://pagure.io/freeipa/issue/8240
        """
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=enabled'
        ])
        result = tasks.install_kra(self.master, raiseonerr=False)
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=hidden'
        ])
        assert result.returncode == 0


class TestReplicaConn(IntegrationTest):
    num_replicas = 1
    num_ad_domains = 1

    @classmethod
    def install(cls, mh):
        cls.replica = cls.replicas[0]
        cls.ad = cls.ads[0]
        ad_domain = cls.ad.domain.name
        cls.ad_admin = 'Administrator@{}'.format(ad_domain.upper())
        cls.adview = 'Default Trust View'
        tasks.install_master(cls.master, setup_adtrust=True)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)
        tasks.install_client(cls.master, cls.replica)

    def test_replica_conncheck_ad_admin(self):
        """
        Test to verify that replica installation is not failing for
        replica connection check when AD administrator
        Administrator@AD.EXAMPLE.COM is used for the deployment
        or promotion of a replica.

        Related : https://pagure.io/freeipa/issue/9542
        """
        self.master.run_command(
            ['ipa', 'idoverrideuser-add', self.adview, self.ad_admin]
        )
        self.master.run_command(
            ["ipa", "group-add-member", "admins", "--idoverrideusers",
             self.ad_admin]
        )
        tasks.clear_sssd_cache(self.master)

        self.replica.run_command(
            ["ipa-replica-install", "--setup-ca", "-U", "--ip-address",
             self.replica.ip, "--realm", self.replica.domain.realm,
             "--domain", self.replica.domain.name,
             "--principal={0}".format(self.ad_admin),
             "--password", self.master.config.ad_admin_password]
        )
        logs = self.replica.get_file_contents(paths.IPAREPLICA_CONNCHECK_LOG)
        error = "not allowed to perform server connection check"
        assert error.encode() not in logs
