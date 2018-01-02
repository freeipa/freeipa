#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

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
