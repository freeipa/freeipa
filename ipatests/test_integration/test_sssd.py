#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for SSSD as used in IPA"""

from __future__ import absolute_import

from contextlib import contextmanager
import re
import time
import os

import ipaplatform
import pytest
import subprocess
import textwrap

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.pytest_ipa.integration.tasks import clear_sssd_cache
from ipatests.util import xfail_context
from ipaplatform.tasks import tasks as platform_tasks
from ipaplatform.paths import paths
from ipapython.dn import DN


class TestSSSDWithAdTrust(IntegrationTest):

    topology = 'star'
    num_ad_domains = 1
    num_ad_subdomains = 1
    num_clients = 1

    users = {
        'ipa': {
            'name': 'user1',
            'password': 'SecretUser1',
            'group': 'user1',
        },
        'ad': {
            'name_tmpl': 'testuser@{domain}',
            'password': 'Secret123',
            'group_tmpl': 'testgroup@{domain}',
        },
        'child_ad': {
            'name_tmpl': 'subdomaintestuser@{domain}',
            'password': 'Secret123',
        },
        'fakeuser': {
            'name': 'some_user@some.domain'
        },
    }
    ipa_user = 'user1'
    ipa_user_password = 'SecretUser1'
    ad_user_tmpl = 'testuser@{domain}'

    @classmethod
    def install(cls, mh):
        super(TestSSSDWithAdTrust, cls).install(mh)

        cls.ad = cls.ads[0]  # pylint: disable=no-member
        cls.child_ad = cls.ad_subdomains[0]  # pylint: disable=no-member

        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.establish_trust_with_ad(cls.master, cls.ad.domain.name)

        cls.users['ad']['name'] = cls.users['ad']['name_tmpl'].format(
            domain=cls.ad.domain.name)
        cls.users['ad']['group'] = cls.users['ad']['group_tmpl'].format(
            domain=cls.ad.domain.name)
        cls.users['child_ad']['name'] = (
            cls.users['child_ad']['name_tmpl'].format(
                domain=cls.child_ad.domain.name))
        tasks.create_active_user(cls.master, cls.ipa_user,
                                 cls.ipa_user_password)

    @contextmanager
    def filter_user_setup(self, user):
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        try:
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(self.master.domain,
                                      'filter_users', self.users[user]['name'])
            tasks.clear_sssd_cache(self.master)
            yield
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

    @pytest.mark.xfail(
        ipaplatform.NAME == 'fedora',
        reason='https://pagure.io/SSSD/sssd/issue/3978', strict=True)
    @pytest.mark.parametrize('user', ['ad', 'fakeuser'])
    def test_is_user_filtered(self, user):
        """No lookup in data provider from 'filter_users' config option.

        Test for https://bugzilla.redhat.com/show_bug.cgi?id=1685472
        https://bugzilla.redhat.com/show_bug.cgi?id=1724088

        When there are users in filter_users in domain section then no look
        up should be in data provider.
        """
        with self.filter_user_setup(user=user):
            log_file = '{0}/sssd_nss.log'.format(paths.VAR_LOG_SSSD_DIR)
            logsize = tasks.get_logsize(self.master, log_file)
            self.master.run_command(
                ['getent', 'passwd', self.users[user]['name']],
                ok_returncode=2)
            sssd_log = self.master.get_file_contents(log_file)[logsize:]
            dp_req = ("Looking up [{0}] in data provider".format(
                self.users[user]['name']))
            assert not dp_req.encode() in sssd_log

    def test_extdom_group(self):
        """ipa-extdom-extop plugin should allow @ in group name.

        Test for : https://bugzilla.redhat.com/show_bug.cgi?id=1746951

        If group contains @ in group name from AD, eg. abc@pqr@AD.DOMAIN
        then it should fetch successfully on ipa-client.
        """
        client = self.clients[0]
        hosts = [self.master, client]
        ad_group = 'group@group@{0}'.format(self.ad.domain.name)
        expression = '((?P<name>.+)@(?P<domain>[^@]+$))'
        master_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        client_conf_backup = tasks.FileBackup(client, paths.SSSD_CONF)
        for host in hosts:
            with tasks.remote_sssd_config(host) as sssd_conf:
                sssd_conf.edit_service('sssd', 're_expression', expression)
            tasks.clear_sssd_cache(host)
        try:
            cmd = ['getent', 'group', ad_group]
            result = self.master.run_command(cmd)
            assert ad_group in result.stdout_text
            result2 = client.run_command(cmd)
            assert ad_group in result2.stdout_text
        finally:
            master_conf_backup.restore()
            client_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)
            tasks.clear_sssd_cache(client)

    def test_external_group_paging(self):
        """SSSD should fetch external groups without any limit.

        Regression test for https://pagure.io/SSSD/sssd/issue/4058
        1: Add external groups more than limit.
        2: Run the command id aduser@ADDOMAIN.COM
        3: sssd should retrieve all the external groups.
        """
        cmd = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.parse_ipa_version(
            cmd.stdout_text.strip())
        if sssd_version <= platform_tasks.parse_ipa_version('1.16.3'):
            pytest.xfail("Fix for https://pagure.io/SSSD/sssd/issue/4058 "
                         "unavailable with sssd-1.16.3")
        new_limit = 50
        master = self.master
        conn = master.ldap_connect()
        dn = DN(('cn', 'config'))
        entry = conn.get_entry(dn)  # pylint: disable=no-member
        orig_limit = entry.single_value.get('nsslapd-sizelimit')
        ldap_query = textwrap.dedent("""
            dn: cn=config
            changetype: modify
            replace: nsslapd-sizelimit
            nsslapd-sizelimit: {limit}
        """)
        tasks.ldapmodify_dm(master, ldap_query.format(limit=new_limit))
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        ldap_page_size = new_limit - 1
        group_count = new_limit + 2
        # default ldap_page_size is '1000', adding workaround as
        # ldap_page_size < nsslapd-sizelimit in sssd.conf
        # Related issue : https://pagure.io/389-ds-base/issue/50888
        with tasks.remote_sssd_config(self.master) as sssd_conf:
            sssd_conf.edit_domain(
                self.master.domain, 'ldap_page_size', ldap_page_size)
        tasks.clear_sssd_cache(master)
        tasks.kinit_admin(master)
        for i in range(group_count):
            master.run_command(['ipa', 'group-add', '--external',
                                'ext-ipatest{0}'.format(i)])
        try:
            log_file = '{0}/sssd_{1}.log'.format(
                paths.VAR_LOG_SSSD_DIR, master.domain.name)
            group_entry = b'[%d] external groups found' % group_count
            logsize = tasks.get_logsize(master, log_file)
            master.run_command(['id', self.users['ad']['name']])
            sssd_logs = master.get_file_contents(log_file)[logsize:]
            assert group_entry in sssd_logs
        finally:
            for i in range(group_count):
                master.run_command(['ipa', 'group-del',
                                    'ext-ipatest{0}'.format(i)])
            # reset to original limit
            tasks.ldapmodify_dm(master, ldap_query.format(limit=orig_limit))
            sssd_conf_backup.restore()

    def test_ext_grp_with_ldap(self):
        """User and group with same name should not break reading AD user data.

        Regression test for https://pagure.io/SSSD/sssd/issue/4073

        When aduser is added in extrnal group and this group is added
        in group with same name of nonprivate ipa user and possix id, then
        lookup of aduser and group should be successful when cache is empty.
        """
        cmd = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.parse_ipa_version(
            cmd.stdout_text.strip())
        if sssd_version <= platform_tasks.parse_ipa_version('1.16.3'):
            pytest.skip("Fix for https://pagure.io/SSSD/sssd/issue/4073 "
                        "unavailable with sssd-1.16.3")
        client = self.clients[0]
        user = 'ipatest'
        userid = '100996'
        ext_group = 'ext-ipatest'
        tasks.kinit_admin(self.master)
        # add user with same uid and gidnumber
        tasks.user_add(self.master, user, extra_args=[
            '--noprivate', '--uid', userid, '--gidnumber', userid])
        # add group with same as user_name and user_id.
        tasks.group_add(self.master, user, extra_args=['--gid', userid])
        tasks.group_add(self.master, ext_group, extra_args=['--external'])
        self.master.run_command(
            ['ipa', 'group-add-member', '--group', ext_group, user])
        self.master.run_command([
            'ipa', '-n', 'group-add-member', '--external',
            self.users['ad']['name'], ext_group])
        tasks.clear_sssd_cache(self.master)
        tasks.clear_sssd_cache(client)
        try:
            result = client.run_command(['id', self.users['ad']['name']])
            assert '{uid}({name})'.format(uid=userid,
                                          name=user) in result.stdout_text
        finally:
            self.master.run_command(['ipa', 'user-del', user])
            self.master.run_command(['ipa', 'group-del', user, ext_group])

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_external_group_member_mismatch(self, user_origin):
        """Prevent adding IPA objects as external group external members

        External groups must only allow adding non-IPA objects as external
        members in 'ipa group-add-member foo --external bar'.
        """
        master = self.master
        tasks.clear_sssd_cache(master)
        tasks.kinit_admin(master)
        master.run_command(['ipa', 'group-add', '--external',
                            'ext-ipatest'])
        try:
            master.run_command(['ipa', '-n', 'group-add-member',
                                'ext-ipatest',
                                '--external',
                                self.users[user_origin]['name']])
        except subprocess.CalledProcessError:
            # Only 'ipa' origin should throw a validation error
            assert user_origin == 'ipa'
        finally:
            master.run_command(['ipa', 'group-del', 'ext-ipatest'])

    @contextmanager
    def disabled_trustdomain(self):
        ad_domain_name = self.ad.domain.name
        ad_subdomain_name = self.child_ad.domain.name
        self.master.run_command(['ipa', 'trustdomain-disable',
                                 ad_domain_name, ad_subdomain_name])
        tasks.clear_sssd_cache(self.master)
        try:
            yield
        finally:
            self.master.run_command(['ipa', 'trustdomain-enable',
                                     ad_domain_name, ad_subdomain_name])
            tasks.clear_sssd_cache(self.master)

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_trustdomain_disable_does_not_disable_root_domain(self,
                                                              user_origin):
        """Test that disabling trustdomain does not affect other domains."""
        user = self.users[user_origin]['name']
        with self.disabled_trustdomain():
            self.master.run_command(['id', user])

    def test_aduser_with_idview(self):
        """Test that trusted AD users should not lose their AD domains.

        This is a regression test for sssd bug:
        https://pagure.io/SSSD/sssd/issue/4173
        1. Override AD user's UID, GID by adding it in ID view on IPA server.
        2. Stop the SSSD, and clear SSSD cache and restart SSSD on a IPA client
        3. getent with UID from ID view should return AD domain
        after default memcache_timeout.
        """
        client = self.clients[0]
        user = self.users['ad']['name']
        idview = 'testview'

        def verify_retrieved_users_domain():
            # Wait for the record to expire in SSSD's cache
            # (memcache_timeout default value is 300s).
            test_user = ['su', user, '-c', 'sleep 360; getent passwd 10001']
            result = client.run_command(test_user)
            assert user in result.stdout_text

        # verify the user can be retrieved initially
        tasks.clear_sssd_cache(self.master)
        self.master.run_command(['id', user])
        self.master.run_command(['ipa', 'idview-add', idview])
        self.master.run_command(['ipa', 'idoverrideuser-add', idview, user])
        self.master.run_command(['ipa', 'idview-apply', idview,
                                 '--hosts={0}'.format(client.hostname)])
        self.master.run_command(['ipa', 'idoverrideuser-mod', idview, user,
                                 '--uid=10001', '--gid=10000'])
        try:
            clear_sssd_cache(client)
            sssd_version = tasks.get_sssd_version(client)
            with xfail_context(sssd_version < tasks.parse_version('2.3.0'),
                               'https://pagure.io/SSSD/sssd/issue/4173'):
                verify_retrieved_users_domain()
        finally:
            self.master.run_command(['ipa', 'idview-del', idview])

    def test_trustdomain_disable_disables_subdomain(self):
        """Test that users from disabled trustdomains can not use ipa resources

        This is a regression test for sssd bug:
        https://pagure.io/SSSD/sssd/issue/4078
        """
        user = self.users['child_ad']['name']
        # verify the user can be retrieved initially
        self.master.run_command(['id', user])
        with self.disabled_trustdomain():
            res = self.master.run_command(['id', user], raiseonerr=False)
            sssd_version = tasks.get_sssd_version(self.master)
            with xfail_context(sssd_version < tasks.parse_version('2.2.3'),
                               'https://pagure.io/SSSD/sssd/issue/4078'):
                assert res.returncode == 1
                assert 'no such user' in res.stderr_text
        # verify the user can be retrieved after re-enabling trustdomain
        self.master.run_command(['id', user])

    @pytest.mark.parametrize('user_origin', ['ipa', 'ad'])
    def test_sssd_cache_refresh(self, user_origin):
        """Check SSSD updates expired cache items for domain and its subdomains

        Regression test for https://pagure.io/SSSD/sssd/issue/4012
        """
        def get_cache_update_time(obj_kind, obj_name):
            res = self.master.run_command(
                ['sssctl', '{}-show'.format(obj_kind), obj_name])
            m = re.search(r'Cache entry last update time:\s+([^\n]+)',
                          res.stdout_text)
            update_time = m.group(1).strip()
            assert update_time
            return update_time

        # by design, sssd does first update of expired records in 30 seconds
        # since start
        refresh_time = 30
        user = self.users[user_origin]['name']
        group = self.users[user_origin]['group']
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        try:
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(
                    self.master.domain, 'refresh_expired_interval', 1)
                sssd_conf.edit_domain(
                    self.master.domain, 'entry_cache_timeout', 1)
            tasks.clear_sssd_cache(self.master)

            start = time.time()
            self.master.run_command(['id', user])
            user_update_time = get_cache_update_time('user', user)
            group_update_time = get_cache_update_time('group', group)
            time.sleep(start + refresh_time - time.time() + 5)
            sssd_version = tasks.get_sssd_version(self.master)
            with xfail_context(
                    (user_origin == 'ad' and sssd_version <
                     tasks.parse_version('2.2.2')),
                'https://pagure.io/SSSD/sssd/issue/4012'):
                assert get_cache_update_time('user', user) != user_update_time
                assert (get_cache_update_time('group', group) !=
                        group_update_time)
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

    @pytest.mark.xfail(
        ipaplatform.NAME == 'fedora',
        reason='https://pagure.io/SSSD/sssd/issue/3721',
    )
    def test_subdomain_lookup_with_certmaprule_containing_dn(self):
        """DN names on certmaprules should not break AD Trust lookups.

        Regression test for https://pagure.io/SSSD/sssd/issue/3721
        """
        tasks.kinit_admin(self.master)

        # verify the user can be retrieved initially
        first_res = self.master.run_command(['id', self.users['ad']['name']])

        cert_cn = 'CN=adca'
        cert_dcs = 'DC=' + ',DC='.join(self.ad.domain.name.split('.'))
        cert_subject = cert_cn + ',' + cert_dcs

        self.master.run_command([
            'ipa',
            'certmaprule-add',
            "'{}'".format(cert_subject),
            "--maprule='(userCertificate;binary={cert!bin})'",
            "--matchrule='<ISSUER>{}'".format(cert_subject),
            "--domain={}".format(self.master.domain.name)
        ])
        try:
            tasks.clear_sssd_cache(self.master)
            # verify the user can be retrieved after the certmaprule is added
            second_res = self.master.run_command(
                ['id', self.users['ad']['name']])
            assert first_res.stdout_text == second_res.stdout_text
            verify_in_stdout = ['gid', 'uid', 'groups',
                                self.users['ad']['name']]
            for text in verify_in_stdout:
                assert text in second_res.stdout_text
        finally:
            self.master.run_command(
                ['ipa', 'certmaprule-del', "'{}'".format(cert_subject)])

    @contextmanager
    def override_gid_setup(self, gid):
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        try:
            with tasks.remote_sssd_config(self.master) as sssd_conf:
                sssd_conf.edit_domain(self.master.domain,
                                      'override_gid', gid)
            tasks.clear_sssd_cache(self.master)
            yield
        finally:
            sssd_conf_backup.restore()
            tasks.clear_sssd_cache(self.master)

    def test_override_gid_subdomain(self):
        """Test that override_gid is working for subdomain

        This is a regression test for sssd bug:
        https://pagure.io/SSSD/sssd/issue/4061
        """
        tasks.clear_sssd_cache(self.master)
        user = self.users['child_ad']['name']
        gid = 10264
        # verify the user can be retrieved initially
        self.master.run_command(['id', user])
        with self.override_gid_setup(gid):
            test_gid = self.master.run_command(['id', user])
            sssd_version = tasks.get_sssd_version(self.master)
            with xfail_context(sssd_version < tasks.parse_version('2.3.0'),
                               'https://pagure.io/SSSD/sssd/issue/4061'):
                assert 'gid={id}'.format(id=gid) in test_gid.stdout_text


@pytest.mark.skip(reason="SSSD fix is not available on Fedora 27")
class TestNestedMembers(IntegrationTest):
    num_clients = 1
    username = "testuser001"
    userpasswd = 'Secret123'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_client(cls.master, cls.clients[0])

    @pytest.fixture
    def nested_group_setup(self, tmpdir):
        """Setup and Clean up groups and user created"""
        master = self.master
        client = self.clients[0]

        # add a user and set password
        tasks.create_active_user(master, self.username, self.userpasswd)
        tasks.kinit_admin(master)

        privkey, pubkey = tasks.generate_ssh_keypair()
        with open(os.path.join(
                str(tmpdir), 'ssh_priv_key'), 'w') as fp:
            fp.write(privkey)

        master.run_command([
            'ipa', 'user-mod', self.username, '--ssh', "{}".format(pubkey)
        ])

        master.put_file_contents('/tmp/user_ssh_priv_key', privkey)
        master.run_command(['chmod', '600', '/tmp/user_ssh_priv_key'])

        # add group groupa
        cmd_output = master.run_command(['ipa', 'group-add', 'groupa'])
        assert 'Added group "groupa"' in cmd_output.stdout_text

        # add group groupb
        cmd_output = master.run_command(['ipa', 'group-add', 'groupb'])
        assert 'Added group "groupb"' in cmd_output.stdout_text

        # add group groupc
        cmd_output = master.run_command(['ipa', 'group-add', 'groupc'])
        assert 'Added group "groupc"' in cmd_output.stdout_text

        client.put_file_contents('/tmp/user_ssh_priv_key',
                                 privkey)
        client.run_command(['chmod', '600', '/tmp/user_ssh_priv_key'])
        yield
        # test cleanup
        for group in ['groupa', 'groupb', 'groupc']:
            self.master.run_command(['ipa', 'group-del', group, '--continue'])
        self.master.run_command(['ipa', 'user-del', self.username,
                                 '--no-preserve', '--continue'])
        tasks.kdestroy_all(self.master)
        tasks.kdestroy_all(self.clients[0])

    def test_nested_group_members(self, tmpdir, nested_group_setup):
        """Nested group memberships should be honoured

        "groupc" should be a child of "groupb"
        so that parent child relationship is as follows:
        "groupa"->"groupb"->"groupc"

        testuser001 is direct member of "groupa" and as a result
        member of "groupb" and "groupc"".
        Now if one adds a direct membership to "groupb"
        nothing will change.

        Now if one removes the direct membership to "groupb"
        nothing should change, the memberships should be honored
        Linked Issue: https://pagure.io/SSSD/sssd/issue/3636
        """
        master = self.master
        client = self.clients[0]

        # add group members
        cmd_output = master.run_command(['ipa', 'group-add-member',
                                         'groupb', '--groups', 'groupa'])
        assert 'Group name: groupb' in cmd_output.stdout_text
        assert 'Member groups: groupa' in cmd_output.stdout_text
        assert 'Number of members added 1' in cmd_output.stdout_text

        cmd_output = master.run_command(['ipa', 'group-add-member',
                                         'groupc', '--groups', 'groupb'])
        assert 'Group name: groupc' in cmd_output.stdout_text
        assert 'Member groups: groupb' in cmd_output.stdout_text
        assert 'Indirect Member groups: groupa' in cmd_output.stdout_text

        # add user to group 'groupa'
        cmd_output = master.run_command(['ipa', 'group-add-member',
                                         'groupa', '--users', self.username])
        assert 'Group name: groupa' in cmd_output.stdout_text
        assert_str = 'Member users: {}'.format(self.username)
        assert assert_str in cmd_output.stdout_text
        assert 'Member of groups: groupb' in cmd_output.stdout_text
        assert 'Indirect Member of group: groupc' in cmd_output.stdout_text

        # clear sssd_cache
        clear_sssd_cache(master)

        # user lookup
        # at this point, testuser001 has the following group memberships
        # Member of groups: groupa, ipausers
        # Indirect Member of group: groupb, groupc
        cmd_output = master.run_command(['ipa', 'user-show', self.username])
        assert 'groupa' in cmd_output.stdout_text
        assert 'ipausers' in cmd_output.stdout_text
        assert 'groupb' in cmd_output.stdout_text
        assert 'groupc' in cmd_output.stdout_text

        clear_sssd_cache(client)

        cmd = ['ssh', '-i', '/tmp/user_ssh_priv_key',
               '-q', '{}@{}'.format(self.username, client.hostname),
               'groups']
        cmd_output = master.run_command(cmd)
        assert self.username in cmd_output.stdout_text
        assert 'groupa' in cmd_output.stdout_text
        assert 'groupb' in cmd_output.stdout_text
        assert 'groupc' in cmd_output.stdout_text

        # add member
        cmd_output = master.run_command(['ipa', 'group-add-member',
                                         'groupb', '--users', self.username])
        assert 'Group name: groupb' in cmd_output.stdout_text
        assert_str = 'Member users: {}'.format(self.username)
        assert assert_str in cmd_output.stdout_text
        assert 'Member groups: groupa' in cmd_output.stdout_text
        assert 'Member of groups: groupc' in cmd_output.stdout_text
        assert 'Number of members added 1' in cmd_output.stdout_text

        # now check ssh on the client
        clear_sssd_cache(client)

        # after adding testuser001 to b group
        # testuser001 will have the following memberships
        # Member of groups: groupa, ipausers, groupb
        # Indirect Member of group: groupc
        cmd = ['ssh', '-i', '/tmp/user_ssh_priv_key',
               '-q', '{}@{}'.format(self.username, client.hostname),
               'groups']
        cmd_output = client.run_command(cmd)
        assert self.username in cmd_output.stdout_text
        assert 'groupa' in cmd_output.stdout_text
        assert 'groupb' in cmd_output.stdout_text
        assert 'groupc' in cmd_output.stdout_text

        # now back to server to remove member
        cmd_output = master.run_command(['ipa', 'group-remove-member',
                                         'groupb', '--users', self.username])
        assert_str = 'Indirect Member users: {}'.format(self.username)
        assert 'Group name: groupb' in cmd_output.stdout_text
        assert 'Member groups: groupa' in cmd_output.stdout_text
        assert 'Member of groups: groupc' in cmd_output.stdout_text
        assert assert_str in cmd_output.stdout_text
        assert 'Number of members removed 1' in cmd_output.stdout_text

        clear_sssd_cache(master)

        # now check ssh on the client again
        # after removing testuser001 from b group
        # testuser001 will have the following memberships
        # Member of groups: groupa, ipausers
        # Indirect Member of group: groupb, groupc
        clear_sssd_cache(client)
        cmd = ['ssh', '-i', '/tmp/user_ssh_priv_key',
               '-q', '{}@{}'.format(self.username, client.hostname),
               'groups']
        cmd_output = client.run_command(cmd)
        assert self.username in cmd_output.stdout_text
        assert 'groupa' in cmd_output.stdout_text
        assert 'groupb' in cmd_output.stdout_text
        assert 'groupc' in cmd_output.stdout_text
