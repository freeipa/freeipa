#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""This module provides tests for ipa-adtrust-install utility"""

from __future__ import absolute_import

import re
import textwrap

from ipaplatform.paths import paths
from ipapython.dn import DN
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


class TestIpaAdTrustInstall(IntegrationTest):
    topology = 'line'
    num_replicas = 1

    def unconfigure_replica_as_agent(self, host):
        """ Remove a replica from the list of agents.

        cn=adtrust agents,cn=sysaccounts,cn=etc,$BASEDN contains a list
        of members representing the agents. Remove the replica principal
        from this list.
        This is a hack allowing to run multiple times
        ipa-adtrust-install --add-agents
        (otherwise if the replica is in the list of agents, it won't be seen
        as a possible agent to be added).
        """
        remove_agent_ldif = textwrap.dedent("""
             dn: cn=adtrust agents,cn=sysaccounts,cn=etc,{base_dn}
             changetype: modify
             delete: member
             member: fqdn={hostname},cn=computers,cn=accounts,{base_dn}
             """.format(base_dn=host.domain.basedn, hostname=host.hostname))
        # ok_returncode =16 if the attribute is not present
        tasks.ldapmodify_dm(self.master, remove_agent_ldif,
                            ok_returncode=[0, 16])

    def test_samba_config_file(self):
        """Check that ipa-adtrust-install generates sane smb.conf
        This is regression test for issue
        https://pagure.io/freeipa/issue/6951
        """
        self.master.run_command(
            ['ipa-adtrust-install', '-a', self.master.config.admin_password,
             '--add-sids', '-U'])
        res = self.master.run_command(['testparm', '-s'])
        assert 'ERROR' not in (res.stdout_text + res.stderr_text)

    def test_add_agent_not_allowed(self):
        """Check that add-agents can be run only by Admins."""
        user = "nonadmin"
        passwd = "Secret123"
        host = self.replicas[0].hostname
        data_fmt = '{{"method":"trust_enable_agent","params":[["{}"],{{}}]}}'

        try:
            # Create a nonadmin user that will be used by curl
            tasks.create_active_user(self.master, user, passwd,
                                     first=user, last=user)
            tasks.kinit_as_user(self.master, user, passwd)
            # curl --negotiate -u : is using GSS-API i.e. nonadmin user
            cmd_args = [
                paths.BIN_CURL,
                '-H', 'referer:https://{}/ipa'.format(host),
                '-H', 'Content-Type:application/json',
                '-H', 'Accept:applicaton/json',
                '--negotiate', '-u', ':',
                '--cacert', paths.IPA_CA_CRT,
                '-d', data_fmt.format(host),
                '-X', 'POST', 'https://{}/ipa/json'.format(host)]
            res = self.master.run_command(cmd_args)
            expected = 'Insufficient access: not allowed to remotely add agent'
            assert expected in res.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    def test_add_agent_on_stopped_replica(self):
        """ Check ipa-adtrust-install --add-agents when the replica is stopped.

        Scenario: stop a replica
        Call ipa-adtrust-install --add-agents and configure the stopped replica
        as a new agent.
        The tool must detect that the replica is stopped and warn that
        a part of the configuration failed.

        Test for https://pagure.io/freeipa/issue/8148
        """
        self.unconfigure_replica_as_agent(self.replicas[0])
        self.replicas[0].run_command(['ipactl', 'stop'])

        cmd_input = (
            # admin password:
            self.master.config.admin_password + '\n' +
            # WARNING: The smb.conf already exists. Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            'yes\n'
            # Enable trusted domains support in slapi-nis? [no]:
            '\n' +
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            'yes\n'
        )
        try:
            res = self.master.run_command(['ipa-adtrust-install',
                                           '--add-agents'],
                                          stdin_text=cmd_input)
            expected_re = '"ipactl restart".+"systemctl restart sssd"'
            assert re.search(expected_re, res.stdout_text, re.DOTALL)
        finally:
            self.replicas[0].run_command(['ipactl', 'start'])

    def test_add_agent_on_running_replica_without_compat(self):
        """ Check ipa-adtrust-install --add-agents when the replica is running

        Scenario: replica up and running
        Call ipa-adtrust-install --add-agents and configure the replica as
        a new agent.
        The Schema Compat plugin must be automatically configured on the
        replica.
        """
        self.unconfigure_replica_as_agent(self.replicas[0])
        cmd_input = (
            # admin password:
            self.master.config.admin_password + '\n' +
            # WARNING: The smb.conf already exists. Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            'yes\n'
            # Enable trusted domains support in slapi-nis? [no]:
            '\n' +
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            'yes\n'
        )
        expected = '"ipactl restart"'
        res = self.master.run_command(['ipa-adtrust-install', '--add-agents'],
                                      stdin_text=cmd_input)
        # The replica must have been restarted automatically, no msg required
        assert expected not in res.stdout_text

    def test_add_agent_on_running_replica_with_compat(self):
        """ Check ipa-addtrust-install --add-agents when the replica is running

        Scenario: replica up and running
        Call ipa-adtrust-install --add-agents --enable-compat and configure
        the replica as a new agent.
        The Schema Compat plugin must be automatically configured on the
        replica.
        """
        self.unconfigure_replica_as_agent(self.replicas[0])

        cmd_input = (
            # admin password:
            self.master.config.admin_password + '\n' +
            # WARNING: The smb.conf already exists. Running ipa-adtrust-install
            # will break your existing samba configuration.
            # Do you wish to continue? [no]:
            'yes\n'
            # Enable trusted domains support in slapi-nis? [no]:
            'yes\n' +
            # WARNING: 1 IPA masters are not yet able to serve information
            # about users from trusted forests.
            # Installer can add them to the list of IPA masters allowed to
            # access information about trusts.
            # If you choose to do so, you also need to restart LDAP service on
            # those masters.
            # Refer to ipa-adtrust-install(1) man page for details.
            # IPA master[replica1.testrelm.test]?[no]:
            'yes\n'
        )
        expected = '"ipactl restart"'
        res = self.master.run_command(['ipa-adtrust-install', '--add-agents'],
                                      stdin_text=cmd_input)
        # The replica must have been restarted automatically, no msg required
        assert expected not in res.stdout_text

        # Ensure that the schema compat plugin is configured:
        conn = self.replicas[0].ldap_connect()
        entry = conn.get_entry(DN(
            "cn=users,cn=Schema Compatibility,cn=plugins,cn=config"))
        assert entry.single_value['schema-compat-lookup-nsswitch'] == "user"
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))
        assert entry.single_value['schema-compat-lookup-nsswitch'] == "group"

    def test_schema_compat_attribute(self):
        """Test if schema-compat-entry-attribute is set

        This is to ensure if said entry is set after installation with AD.

        related: https://pagure.io/freeipa/issue/8193
        """
        conn = self.replicas[0].ldap_connect()
        entry = conn.get_entry(DN(
            "cn=groups,cn=Schema Compatibility,cn=plugins,cn=config"))
        entry_list = list(entry['schema-compat-entry-attribute'])
        value = (r'ipaexternalmember=%deref_r('
                 '"member","ipaexternalmember")')
        assert value in entry_list
