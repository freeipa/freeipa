#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import time
import re
import textwrap
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.tasks import (
    assert_error, replicas_cleanup)
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipatests.pytest_ipa.integration.env_config import get_global_config
from ipalib.constants import (
    DOMAIN_LEVEL_1, IPA_CA_NICKNAME)
from ipaplatform.paths import paths
from ipapython import certdb
from ipatests.test_integration.test_backup_and_restore import backup
from ipatests.test_integration.test_dns_locations import (
    resolve_records_from_server, IPA_DEFAULT_MASTER_SRV_REC
)
from ipapython.dnsutil import DNSName
from ipalib.constants import IPA_CA_RECORD

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

    def teardown_method(self, method):
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
        assert(result1.returncode == 0), (
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

class TestRenewalMaster(IntegrationTest):

    topology = 'star'
    num_replicas = 1

    @classmethod
    def uninstall(cls, mh):
        super(TestRenewalMaster, cls).uninstall(mh)

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

    def test_automatic_renewal_master_transfer_ondelete(self):
        # Test that after replica uninstallation, master overtakes the cert
        # renewal master role from replica (which was previously set there)
        tasks.uninstall_master(self.replicas[0])
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


class TestSubCAkeyReplication(IntegrationTest):
    """
    Test if subca key replication is not failing.
    """
    topology = 'line'
    num_replicas = 1

    SUBCA = 'test_subca'
    SUBCA_CN = 'cn=' + SUBCA

    PKI_DEBUG_PATH = '/var/log/pki/pki-tomcat/ca/debug'

    ERR_MESS = 'Caught exception during cert/key import'

    def test_sub_ca_key_replication(self):
        master = self.master
        replica = self.replicas[0]

        result = master.run_command(['ipa', 'ca-add', self.SUBCA, '--subject',
                                     self.SUBCA_CN])

        uuid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        auth_id_re = re.compile('Authority ID: ({})'.format(uuid),
                                re.IGNORECASE)
        auth_id = "".join(re.findall(auth_id_re, result.stdout_text))

        cert_nick = '{} {}'.format(IPA_CA_NICKNAME, auth_id)

        # give replication some time
        time.sleep(30)

        replica.run_command(['ipa-certupdate'])
        replica.run_command(['ipa', 'ca-show', self.SUBCA])

        tasks.run_certutil(replica, ['-L', '-n', cert_nick],
                           paths.PKI_TOMCAT_ALIAS_DIR)

        pki_log_filename = ("{path}.{date}.log"
                            .format(path=self.PKI_DEBUG_PATH,
                                    date=time.strftime("%Y-%m-%d")))
        pki_debug_log = replica.get_file_contents(pki_log_filename,
                                                  encoding='utf-8')
        # check for cert/key import error message
        assert self.ERR_MESS not in pki_debug_log

    def test_sign_with_subca_on_replica(self):
        master = self.master
        replica = self.replicas[0]

        TEST_KEY_FILE = '/etc/pki/tls/private/test_subca.key'
        TEST_CRT_FILE = '/etc/pki/tls/private/test_subca.crt'

        caacl_cmd = ['ipa', 'caacl-add-ca', 'hosts_services_caIPAserviceCert',
                     '--cas', self.SUBCA]
        master.run_command(caacl_cmd)

        request_cmd = [paths.IPA_GETCERT, 'request', '-w', '-k',
                       TEST_KEY_FILE, '-f', TEST_CRT_FILE, '-X', self.SUBCA]
        replica.run_command(request_cmd)

        status_cmd = [paths.IPA_GETCERT, 'status', '-v', '-f', TEST_CRT_FILE]
        status = replica.run_command(status_cmd)
        assert 'State MONITORING, stuck: no' in status.stdout_text

        ssl_cmd = ['openssl', 'x509', '-text', '-in', TEST_CRT_FILE]
        ssl = replica.run_command(ssl_cmd)
        assert 'Issuer: CN = {}'.format(self.SUBCA) in ssl.stdout_text


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
        replica1.run_command(['ipactl', 'status'])

        # Install Replica2 with CA with source as Replica1.
        tasks.install_replica(replica1, replica2, setup_ca=True)
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
    host.run_command(['/usr/bin/cp',
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
    host.run_command(['/usr/bin/mv',
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
    topology = 'star'
    num_replicas = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True, setup_kra=True)
        tasks.install_replica(
            cls.master, cls.replicas[0],
            setup_dns=True, setup_kra=True,
            extra_args=('--hidden-replica',)
        )

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
            txt = query.to_text()
            for host in hosts_expected:
                value = host.hostname if rtype == 'SRV' else host.ip
                assert value in txt
            for host in hosts_unexpected:
                value = host.hostname if rtype == 'SRV' else host.ip
                assert value not in txt

    def _check_server_role(self, host, status):
        roles = [u'IPA master', u'CA server', u'KRA server', u'DNS server']
        for role in roles:
            result = self.master.run_command([
                'ipa', 'server-role-find',
                '--server', host.hostname,
                '--role', role
            ])
            expected = 'Role status: {}'.format(status)
            assert expected in result.stdout_text

    def test_hidden_replica_install(self):
        # TODO: check that all services are running on hidden replica
        self._check_server_role(self.master, 'enabled')
        self._check_server_role(self.replicas[0], 'hidden')
        self._check_dnsrecords([self.master], [self.replicas[0]])

    def test_hidden_replica_promote(self):
        self.replicas[0].run_command([
            'ipa', 'server-state',
            self.replicas[0].hostname, '--state=enabled'
        ])
        self._check_server_role(self.replicas[0], 'enabled')
        self._check_dnsrecords([self.master, self.replicas[0]])
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
        self._check_dnsrecords([self.master], [self.replicas[0]])

    def test_hidden_replica_backup_and_restore(self):
        """Exercises backup+restore and hidden replica uninstall
        """
        self._check_server_role(self.replicas[0], 'hidden')
        # backup
        backup_path = backup(self.replicas[0])
        # uninstall
        tasks.uninstall_replica(self.master, self.replicas[0])
        # restore
        dirman_password = self.master.config.dirman_password
        self.replicas[0].run_command(
            ['ipa-restore', backup_path],
            stdin_text=dirman_password + '\nyes'
        )
        # check that role is still hidden
        self._check_server_role(self.replicas[0], 'hidden')
        self._check_dnsrecords([self.master], [self.replicas[0]])
        # check that the resulting server can be promoted to enabled
        self.replicas[0].run_command([
            'ipa', 'server-mod', self.replicas[0].hostname, '--state=enabled'
        ])
        self._check_server_role(self.replicas[0], 'enabled')
        self._check_dnsrecords([self.master, self.replicas[0]])
