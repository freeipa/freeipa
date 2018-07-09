#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import


from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_plugins.integration import tasks


class TestUserPermissions(IntegrationTest):
    topology = 'star'
    altadmin = "altadmin"

    @classmethod
    def install(cls, mh):
        super(TestUserPermissions, cls).install(mh)
        tasks.kinit_admin(cls.master)

        # Create a new user altadmin
        password_confirmation = "%s\n%s\n" % (cls.master.config.admin_password,
                                              cls.master.config.admin_password)
        cls.master.run_command(['ipa', 'user-add', cls.altadmin,
                                '--first', cls.altadmin,
                                '--last', cls.altadmin,
                                '--password'],
                               stdin_text=password_confirmation)

        # Add altadmin to the group cn=admins
        cls.master.run_command(['ipa', 'group-add-member', 'admins',
                                '--users', cls.altadmin])

        # kinit as altadmin to initialize the password
        altadmin_kinit = "%s\n%s\n%s\n" % (cls.master.config.admin_password,
                                           cls.master.config.admin_password,
                                           cls.master.config.admin_password)
        cls.master.run_command(['kinit', cls.altadmin],
                               stdin_text=altadmin_kinit)
        cls.master.run_command(['kdestroy', '-A'])

    def test_delete_preserve_as_alternate_admin(self):
        """
        Test that a user member of admins group can call delete --preserve.

        This is a test case for issue 7342
        """

        # kinit admin
        tasks.kinit_admin(self.master)

        # Create a new user 'testuser' with a password
        testuser = 'testuser'
        password = 'Secret123'
        testuser_password_confirmation = "%s\n%s\n" % (password,
                                                       password)
        self.master.run_command(['ipa', 'user-add', testuser,
                                 '--first', testuser,
                                 '--last', testuser,
                                 '--password'],
                                stdin_text=testuser_password_confirmation)

        # kinit as altadmin
        self.master.run_command(['kinit', self.altadmin],
                                stdin_text=self.master.config.admin_password)

        # call ipa user-del --preserve
        self.master.run_command(['ipa', 'user-del', '--preserve', testuser])

    def test_stageuser_show_as_alternate_admin(self):
        """
        Test that a user member of admins group can call stageuser-show
        and read the 'Kerberos Keys available' information.

        This is a test case for issue 7342
        """
        # kinit admin
        tasks.kinit_admin(self.master)

        # Create a new stage user 'stageuser' with a password
        stageuser = 'stageuser'
        password = 'Secret123'
        stageuser_password_confirmation = "%s\n%s\n" % (password,
                                                        password)
        self.master.run_command(['ipa', 'stageuser-add', stageuser,
                                 '--first', stageuser,
                                 '--last', stageuser,
                                 '--password'],
                                stdin_text=stageuser_password_confirmation)

        # kinit as altadmin
        self.master.run_command(['kinit', self.altadmin],
                                stdin_text=self.master.config.admin_password)

        # call ipa stageuser-show
        # the field Kerberos Keys available must contain True
        result = self.master.run_command(['ipa', 'stageuser-show', stageuser])
        assert 'Kerberos keys available: True' in result.stdout_text


class TestInstallClientNoAdmin(IntegrationTest):
    num_clients = 1

    def test_installclient_as_user_admin(self):
        """ipa-client-install should not use hardcoded admin for principal

        In ipaclient-install.log it should use the username that was entered
        earlier in the install process at the prompt.
        Related to : https://pagure.io/freeipa/issue/5406
        """
        client = self.clients[0]
        tasks.install_master(self.master)
        tasks.kinit_admin(self.master)
        username = 'testuser1'
        password = 'userSecretPassword123'
        password_confirmation = "%s\n%s\n" % (password,
                                              password)

        self.master.run_command(['ipa', 'user-add', username,
                                 '--first', username,
                                 '--last', username,
                                 '--password'],
                                stdin_text=password_confirmation)

        role_add = ['ipa', 'role-add', 'useradmin']
        self.master.run_command(role_add)
        self.master.run_command(['ipa', 'privilege-add', 'Add Hosts'])
        self.master.run_command(['ipa', 'privilege-add-permission',
                                 '--permissions', 'System: Add Hosts',
                                 'Add Hosts'])

        self.master.run_command(['ipa', 'role-add-privilege', 'useradmin',
                                 '--privileges', 'Host Enrollment'])

        self.master.run_command(['ipa', 'role-add-privilege', 'useradmin',
                                 '--privileges', 'Add Hosts'])

        role_member_add = ['ipa', 'role-add-member', 'useradmin',
                           '--users={}'.format(username)]
        self.master.run_command(role_member_add)
        user_kinit = "%s\n%s\n%s\n" % (password, password, password)
        self.master.run_command(['kinit', username],
                                stdin_text=user_kinit)
        tasks.install_client(
            self.master, client,
            extra_args=['--request-cert'],
            user=username, password=password
        )
        msg = "args=['/usr/bin/getent', 'passwd', '%s@%s']" % \
              (username, client.domain.name)
        install_log = client.get_file_contents(paths.IPACLIENT_INSTALL_LOG,
                                               encoding='utf-8')
        assert msg in install_log

        # check that user is able to request a host cert, too
        result = tasks.run_certutil(client, ['-L'], paths.IPA_NSSDB_DIR)
        assert 'Local IPA host' in result.stdout_text
        result = tasks.run_certutil(
            client,
            ['-K', '-f', paths.IPA_NSSDB_PWDFILE_TXT],
            paths.IPA_NSSDB_DIR
        )
        assert 'Local IPA host' in result.stdout_text
