#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""This covers tests for automemberfeature."""

from __future__ import absolute_import
import uuid

from ipapython.dn import DN

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

msg = ('IMPORTANT: In case of a high number of users, hosts or '
       'groups, the operation may require high CPU usage.')


class TestAutounmembership(IntegrationTest):
    """Tests for autounmembership feature.

    This test class covers the tests for this feature described in
    https://pagure.io/389-ds-base/issue/50077 .
    """
    topology = 'line'
    dn = DN(
        ('cn', 'Auto Membership Plugin'), ('cn', 'plugins'),
        ('cn', 'config')
    )

    def automember_group_add(self, group):
        """Add group/automember entry."""
        cmdlist = [['ipa', 'group-add', '--desc=%s' % group, group],
                   ['ipa', 'automember-add', '--type=group', group],
                   ['ipa', 'automember-add-condition',
                    '--key=destinationindicator', '--type=group',
                    '--inclusive-regex=%s' % group, group]]
        for cmd in cmdlist:
            self.master.run_command(cmd)

    def user_automember_setup(self, group, user, first, last):
        """Add user entry."""
        self.master.run_command(['ipa', 'user-add', '--first=%s' % first,
                                 '--last=%s' % last, user,
                                 '--setattr=destinationindicator=%s' % group])

    def user_automember_mod(self, group, user):
        """Modify user entry."""
        self.master.run_command(['ipa', 'user-mod', user,
                                 '--setattr=destinationindicator=%s' % group])

    def remove_user_automember(self, user, raiseonerr=True):
        """Delete user entry."""
        self.master.run_command(['ipa', 'user-del', user],
                                raiseonerr=raiseonerr)

    def automember_group_cleanup(self, group):
        """Cleanup of automember/group entry."""
        cmdlist = [['ipa', 'automember-del', '--type=group', group],
                   ['ipa', 'group-del', group]]
        for cmd in cmdlist:
            self.master.run_command(cmd, raiseonerr=False)

    def is_user_member_of_group(self, user, group):
        """Check membership of user in the group."""
        result = self.master.run_command(['ipa', 'group-show', group])
        return user in result.stdout_text

    def automember_hostgroup_add(self, hostgroup):
        """Add hostgroup/automember entry."""
        cmdlist = [['ipa', 'hostgroup-add', '--desc=%s' % hostgroup,
                   hostgroup],
                   ['ipa', 'automember-add', '--type=hostgroup', hostgroup],
                   ['ipa', 'automember-add-condition',
                    '--key=nshostlocation', '--type=hostgroup',
                    '--inclusive-regex=%s' % hostgroup, hostgroup]]
        for cmd in cmdlist:
            self.master.run_command(cmd)

    def host_automember_setup(self, hostgroup, host):
        """Add host entry."""
        self.master.run_command(['ipa', 'host-add', host, '--location=%s'
                                 % hostgroup, '--force'])

    def host_automember_mod(self, hostgroup, host):
        """Modify host entry."""
        self.master.run_command(['ipa', 'host-mod', host, '--location=%s'
                                 % hostgroup])

    def remove_host_automember(self, host, raiseonerr=True):
        """Delete host entry."""
        self.master.run_command(['ipa', 'host-del', host],
                                raiseonerr=raiseonerr)

    def automember_hostgroup_cleanup(self, hostgroup):
        """Cleanup of automember/hostgroup entry."""
        cmdlist = [['ipa', 'automember-del', '--type=hostgroup', hostgroup],
                   ['ipa', 'hostgroup-del', hostgroup]]
        for cmd in cmdlist:
            self.master.run_command(cmd, raiseonerr=False)

    def is_host_member_of_hostgroup(self, host, hostgroup):
        """Check membership of host in the hostgroup."""
        result = self.master.run_command(['ipa', 'hostgroup-show', hostgroup])
        return host in result.stdout_text

    def check_autounmembership_in_ldap(self, state='on'):
        """Check autounmembership state."""
        conn = self.master.ldap_connect()
        entry = conn.get_entry(self.dn)
        assert state == entry.single_value['automemberprocessmodifyops']

    def disable_autounmembership_in_ldap(self):
        """Disable autounmembership."""
        conn = self.master.ldap_connect()
        entry = conn.get_entry(self.dn)
        entry.single_value['automemberprocessmodifyops'] = 'off'
        conn.update_entry(entry)
        self.master.run_command(['ipactl', 'restart'])

    def test_modify_user_entry_unmembership(self):
        """Test when autounmembership feature is enabled.

        Test that an update on a user entry triggers a re-evaluation of the
        user's automember groups when auto-unmembership is active.
        """
        try:
            # testcase setup
            tasks.kinit_admin(self.master)
            self.check_autounmembership_in_ldap(state='on')
            group1 = 'DallasUsers'
            group2 = 'HoustonUsers'
            user1 = 'user1'
            first = 'first'
            last = 'user'
            self.automember_group_add(group1)
            self.automember_group_add(group2)
            self.user_automember_setup(group1, user1, first, last)
            assert self.is_user_member_of_group(user1, group1)

            # Modifying the user group so that it becomes part of new group
            self.user_automember_mod(group2, user1)
            assert self.is_user_member_of_group(user1, group2)
            assert not self.is_user_member_of_group(user1, group1)

            # Deleting the user entry and checking its not part of group now
            self.remove_user_automember(user1)
            assert not self.is_user_member_of_group(user1, group2)

        finally:
            # testcase cleanup
            self.remove_user_automember(user1, raiseonerr=False)
            self.automember_group_cleanup(group1)
            self.automember_group_cleanup(group2)

    def test_modify_host_entry_unmembership(self):
        """Test when autounmembership feature is enabled.

        Test that an update on a host entry triggers a re-evaluation of the
        host's automember groups when auto-unmembership is active.
        """
        try:
            # testcase setup
            self.check_autounmembership_in_ldap(state='on')
            hostgroup1 = 'Brno'
            hostgroup2 = 'Boston'
            host1 = 'host1.example.com'
            self.automember_hostgroup_add(hostgroup1)
            self.automember_hostgroup_add(hostgroup2)
            self.host_automember_setup(hostgroup1, host1)
            assert self.is_host_member_of_hostgroup(host1, hostgroup1)

            # Modifying the user group so that it becomes part of new group
            self.host_automember_mod(hostgroup2, host1)
            assert self.is_host_member_of_hostgroup(host1, hostgroup2)
            assert not self.is_host_member_of_hostgroup(host1, hostgroup1)

            # Deleting the user entry and checking its not part of group now
            self.remove_host_automember(host1)
            assert not self.is_host_member_of_hostgroup(host1, hostgroup2)

        finally:
            # testcase cleanup
            self.remove_host_automember(host1, raiseonerr=False)
            self.automember_hostgroup_cleanup(hostgroup1)
            self.automember_hostgroup_cleanup(hostgroup2)

    def test_modify_user_entry_unmembership_disabled(self):
        """Test when autounmembership feature is disabled.

        Test that an update on a user entry does not triggers re-evaluation of
        the user's automember groups when auto-unmembership is disabled.
        """
        try:
            # testcase setup
            self.disable_autounmembership_in_ldap()
            self.check_autounmembership_in_ldap(state='off')
            group1 = 'PuneUsers'
            group2 = 'BrnoUsers'
            user2 = 'user2'
            first = 'second'
            last = 'user'
            self.automember_group_add(group1)
            self.automember_group_add(group2)
            self.user_automember_setup(group1, user2, first, last)
            assert self.is_user_member_of_group(user2, group1)

            # Modifying the user group so that it becomes part of new group
            self.user_automember_mod(group2, user2)
            assert not self.is_user_member_of_group(user2, group2)
            assert self.is_user_member_of_group(user2, group1)

            # Running automember-build so that user is part of correct group
            result = self.master.run_command(['ipa', 'automember-rebuild',
                                              '--users=%s' % user2])
            assert msg in result.stdout_text

            # The additional --cleanup argument is required
            cleanup_ldif = (
                "dn: cn={cn},cn=automember rebuild membership,"
                "cn=tasks,cn=config\n"
                "changetype: add\n"
                "objectclass: top\n"
                "objectclass: extensibleObject\n"
                "basedn: cn=users,cn=accounts,{suffix}\n"
                "filter: (uid={user})\n"
                "cleanup: yes\n"
                "scope: sub"
            ).format(cn=str(uuid.uuid4()),
                     suffix=str(self.master.domain.basedn),
                     user=user2)
            tasks.ldapmodify_dm(self.master, cleanup_ldif)

            assert self.is_user_member_of_group(user2, group2)
            assert not self.is_user_member_of_group(user2, group1)

        finally:
            # testcase cleanup
            self.remove_user_automember(user2, raiseonerr=False)
            self.automember_group_cleanup(group1)
            self.automember_group_cleanup(group2)

    def test_modify_host_entry_unmembership_disabled(self):
        """Test when autounmembership feature is disabled.

        Test that an update on a host entry does not triggers re-evaluation of
        the host's automember groups when auto-unmembership is disabled.
        """
        try:
            # testcase setup
            self.check_autounmembership_in_ldap(state='off')
            hostgroup1 = 'Pune'
            hostgroup2 = 'Raleigh'
            host2 = 'host2.example.com'
            self.automember_hostgroup_add(hostgroup1)
            self.automember_hostgroup_add(hostgroup2)
            self.host_automember_setup(hostgroup1, host2)
            assert self.is_host_member_of_hostgroup(host2, hostgroup1)

            # Modifying the user group so that it becomes part of new group
            self.host_automember_mod(hostgroup2, host2)
            assert not self.is_host_member_of_hostgroup(host2, hostgroup2)
            assert self.is_host_member_of_hostgroup(host2, hostgroup1)

            # Running the automember-build so host is part of correct hostgroup
            result = self.master.run_command(
                ['ipa', 'automember-rebuild', '--hosts=%s' % host2]
            )
            assert msg in result.stdout_text

            # The additional --cleanup argument is required
            cleanup_ldif = (
                "dn: cn={cn},cn=automember rebuild membership,"
                "cn=tasks,cn=config\n"
                "changetype: add\n"
                "objectclass: top\n"
                "objectclass: extensibleObject\n"
                "basedn: cn=computers,cn=accounts,{suffix}\n"
                "filter: (fqdn={fqdn})\n"
                "cleanup: yes\n"
                "scope: sub"
            ).format(cn=str(uuid.uuid4()),
                     suffix=str(self.master.domain.basedn),
                     fqdn=host2)
            tasks.ldapmodify_dm(self.master, cleanup_ldif)

            assert self.is_host_member_of_hostgroup(host2, hostgroup2)
            assert not self.is_host_member_of_hostgroup(host2, hostgroup1)

        finally:
            # testcase cleanup
            self.remove_host_automember(host2, raiseonerr=False)
            self.automember_hostgroup_cleanup(hostgroup1)
            self.automember_hostgroup_cleanup(hostgroup2)
