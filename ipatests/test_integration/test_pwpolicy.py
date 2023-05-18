#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Misc test for 'ipa' CLI regressions
"""
from __future__ import absolute_import

import pytest

from ipatests.test_integration.base import IntegrationTest

from ipatests.pytest_ipa.integration import tasks

USER = 'tuser'
PASSWORD = 'Secret123'
POLICY = 'test'


class TestPWPolicy(IntegrationTest):
    """
    Test password policy in action.
    """
    num_replicas = 1

    topology = 'line'

    @classmethod
    def install(cls, mh):
        super(TestPWPolicy, cls).install(mh)

        tasks.kinit_admin(cls.master)
        cls.master.run_command(['ipa', 'user-add', USER,
                                '--first', 'Test',
                                '--last', 'User'])
        cls.master.run_command(['ipa', 'group-add', POLICY])
        cls.master.run_command(['ipa', 'group-add-member', POLICY,
                                '--users', USER])
        cls.master.run_command(['ipa', 'pwpolicy-add', POLICY,
                                '--priority', '1',
                                '--gracelimit', '-1',
                                '--minlength', '6'])
        cls.master.run_command(['ipa', 'passwd', USER],
                               stdin_text='{password}\n{password}\n'.format(
                               password=PASSWORD
                               ))

    def kinit_as_user(self, host, old_password, new_password, user=USER,
                      raiseonerr=True):
        """kinit to an account with an expired password"""
        return host.run_command(
            ['kinit', user],
            raiseonerr=raiseonerr,
            stdin_text='{old}\n{new}\n{new}\n'.format(
                old=old_password, new=new_password
            ),
        )

    def reset_password(self, host, user=USER, password=PASSWORD):
        tasks.kinit_admin(host)
        host.run_command(
            ['ipa', 'passwd', user],
            stdin_text='{password}\n{password}\n'.format(password=password),
        )

    def set_pwpolicy(self, minlength=None, maxrepeat=None, maxsequence=None,
                     dictcheck=None, usercheck=None, minclasses=None):
        tasks.kinit_admin(self.master)
        args = ["ipa", "pwpolicy-mod", POLICY]
        if minlength is not None:
            args.append("--minlength={}".format(minlength))
        if maxrepeat is not None:
            args.append("--maxrepeat={}".format(maxrepeat))
        if maxsequence is not None:
            args.append("--maxsequence={}".format(maxsequence))
        if dictcheck is not None:
            args.append("--dictcheck={}".format(dictcheck))
        if usercheck is not None:
            args.append("--usercheck={}".format(usercheck))
        if minclasses is not None:
            args.append("--minclasses={}".format(minclasses))
        self.master.run_command(args)

        self.reset_password(self.master)

    def clean_pwpolicy(self):
        """Set all policy values we care about to zero/false"""
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--maxrepeat", "0",
             "--maxsequence", "0",
             "--usercheck", "false",
             "--dictcheck" ,"false",
             "--minlife", "0",
             "--minlength", "0",
             "--minclasses", "0",],
        )
        # minlength => 6 is required for any of the libpwquality settings
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--minlength", "6"],
            raiseonerr=False,
        )

    @pytest.fixture
    def reset_pwpolicy(self):
        """Fixture to ensure policy is reset between tests"""
        yield
        tasks.kinit_admin(self.master)
        self.clean_pwpolicy()

    def test_maxrepeat(self, reset_pwpolicy):
        self.set_pwpolicy(maxrepeat=2)
        # good passwords
        for password in ('Secret123', 'Password'):
            self.reset_password(self.master)
            self.kinit_as_user(self.master, PASSWORD, password)
            self.reset_password(self.master)
            tasks.ldappasswd_user_change(USER, PASSWORD, password, self.master)

        self.reset_password(self.master)

        # bad passwords
        for password in ('Secret1111', 'passsword'):
            result = self.kinit_as_user(self.master, PASSWORD, password,
                                        raiseonerr=False)
            assert result.returncode == 1
            result = tasks.ldappasswd_user_change(USER, PASSWORD, password,
                                                  self.master,
                                                  raiseonerr=False)
            assert result.returncode == 1
            assert 'Password has too many consecutive characters' in \
                result.stdout_text

    def test_maxsequence(self, reset_pwpolicy):
        self.set_pwpolicy(maxsequence=3)
        # good passwords
        for password in ('Password123', 'Passwordabc'):
            self.reset_password(self.master)
            self.kinit_as_user(self.master, PASSWORD, password)
            self.reset_password(self.master)
            tasks.ldappasswd_user_change(USER, PASSWORD, password, self.master)

        self.reset_password(self.master)

        # bad passwords
        for password in ('Password1234', 'Passwordabcde'):
            result = self.kinit_as_user(self.master, PASSWORD, password,
                                        raiseonerr=False)
            assert result.returncode == 1
            result = tasks.ldappasswd_user_change(USER, PASSWORD, password,
                                                  self.master,
                                                  raiseonerr=False)
            assert result.returncode == 1
            assert 'Password contains a monotonic sequence' in \
                result.stdout_text

    def test_usercheck(self, reset_pwpolicy):
        self.set_pwpolicy(usercheck=True)
        for password in ('tuserpass', 'passoftuser'):
            result = self.kinit_as_user(self.master, PASSWORD, password,
                                        raiseonerr=False)
            assert result.returncode == 1
            result = tasks.ldappasswd_user_change(USER, PASSWORD, password,
                                                  self.master,
                                                  raiseonerr=False)
            assert result.returncode == 1
            assert 'Password contains username' in \
                result.stdout_text

        # test with valid password
        self.kinit_as_user(self.master, PASSWORD, 'bamOncyftAv0')

    def test_dictcheck(self, reset_pwpolicy):
        self.set_pwpolicy(dictcheck=True)
        for password in ('password', 'bookends', 'BaLtim0re'):
            result = self.kinit_as_user(self.master, PASSWORD, password,
                                        raiseonerr=False)
            assert result.returncode == 1
            result = tasks.ldappasswd_user_change(USER, PASSWORD, password,
                                                  self.master,
                                                  raiseonerr=False)
            assert result.returncode == 1
            assert 'Password is based on a dictionary word' in \
                result.stdout_text

        # test with valid password
        self.kinit_as_user(self.master, PASSWORD, 'bamOncyftAv0')

    def test_minclasses(self, reset_pwpolicy):
        self.set_pwpolicy(minclasses=2)
        for password in ('password', 'bookends'):
            result = self.kinit_as_user(self.master, PASSWORD, password,
                                        raiseonerr=False)
            assert result.returncode == 1
            assert 'Password does not contain enough character' in \
                result.stdout_text
            result = tasks.ldappasswd_user_change(USER, PASSWORD, password,
                                                  self.master,
                                                  raiseonerr=False)
            assert result.returncode == 1
            assert 'Password is too simple' in \
                result.stdout_text

        # test with valid password
        for valid in ('Password', 'password1', 'password!'):
            self.kinit_as_user(self.master, PASSWORD, valid)
            self.reset_password(self.master)

        self.set_pwpolicy(minclasses=3)
        for password in ('password1', 'Bookends'):
            result = self.kinit_as_user(self.master, PASSWORD, password,
                                        raiseonerr=False)
            assert result.returncode == 1
            assert 'Password does not contain enough character' in \
                result.stdout_text
            result = tasks.ldappasswd_user_change(USER, PASSWORD, password,
                                                  self.master,
                                                  raiseonerr=False)
            assert result.returncode == 1
            assert 'Password is too simple' in \
                result.stdout_text

        self.reset_password(self.master)
        # test with valid password
        for valid in ('Passw0rd', 'password1!', 'Password!'):
            self.kinit_as_user(self.master, PASSWORD, valid)
            self.reset_password(self.master)

    def test_minlength_mod(self, reset_pwpolicy):
        """Test that the pwpolicy minlength overrides our policy
        """

        # With a minlength of 4 all settings of pwq should fail
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--minlength", "4",]
        )
        for values in (('--maxrepeat', '4'),
                       ('--maxsequence', '4'),
                       ('--dictcheck', 'true'),
                       ('--usercheck', 'true')):
            args = ["ipa", "pwpolicy-mod", POLICY]
            args.extend(values)
            result = self.master.run_command(args, raiseonerr=False)
            assert result.returncode != 0
            assert 'minlength' in result.stderr_text

        # With any pwq value set, setting minlife < 6 should fail
        for values in (('--maxrepeat', '4'),
                       ('--maxsequence', '4'),
                       ('--dictcheck', 'true'),
                       ('--usercheck', 'true')):
            self.clean_pwpolicy()
            args = ["ipa", "pwpolicy-mod", POLICY]
            args.extend(values)
            self.master.run_command(args)
            result = self.master.run_command(
                ["ipa", "pwpolicy-mod", POLICY,
                 "--minlength", "4",], raiseonerr=False
            )
            assert result.returncode != 0
            assert 'minlength' in result.stderr_text

    def test_minlength_empty(self, reset_pwpolicy):
        """Test that the pwpolicy minlength can be blank
        """
        # Ensure it is set to a non-zero value to avoid EmptyModlist
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--minlength", "10",]
        )
        # Enable one of the libpwquality options, removing minlength
        # should fail.
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--maxrepeat", "4",]
        )
        result = self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--minlength", "",], raiseonerr=False
        )
        assert result.returncode != 0

        # Remove the blocking value
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--maxrepeat", "",]
        )

        # Now erase it
        result = self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY,
             "--minlength", "",]
        )
        assert result.returncode == 0
        assert 'minlength' not in result.stderr_text

    def test_minlength_add(self):
        """Test that adding a new policy with minlength is caught.
        """
        result = self.master.run_command(
            ["ipa", "pwpolicy-add", "test_add",
             "--maxrepeat", "4", "--minlength", "4", "--priority", "2"],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert 'minlength' in result.stderr_text

    def test_graceperiod_expired(self):
        """Test the LDAP bind grace period"""
        dn = "uid={user},cn=users,cn=accounts,{base_dn}".format(
             user=USER, base_dn=str(self.master.domain.basedn))

        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY, "--gracelimit", "3", ],
        )

        # Resetting the password will mark it as expired
        self.reset_password(self.master)

        for i in range(2, -1, -1):
            result = self.master.run_command(
                ["ldapsearch", "-e", "ppolicy", "-D", dn,
                 "-w", PASSWORD, "-b", dn], raiseonerr=False
            )
            # We're in grace, this will succeed
            assert result.returncode == 0

            # verify that we get the expected ppolicy output
            assert 'Password expired, {} grace logins remain'.format(i) \
                in result.stderr_text

        # Now grace is done and binds should fail.
        result = self.master.run_command(
            ["ldapsearch", "-e", "ppolicy", "-D", dn,
             "-w", PASSWORD, "-b", dn], raiseonerr=False
        )
        assert result.returncode == 49

        assert 'Password is expired' in result.stderr_text
        assert 'Password expired, 0 grace logins remain' in result.stderr_text

        # Test that resetting the password resets the grace counter
        self.reset_password(self.master)
        result = tasks.ldapsearch_dm(
            self.master, dn, ['passwordgraceusertime',],
        )

        assert 'passwordgraceusertime: 0' in result.stdout_text.lower()

    def test_graceperiod_not_replicated(self):
        """Test that the grace period is reset on password reset"""
        dn = "uid={user},cn=users,cn=accounts,{base_dn}".format(
             user=USER, base_dn=str(self.master.domain.basedn))

        # Resetting the password will mark it as expired
        self.reset_password(self.master)

        # Generate some logins but don't exceed the limit
        for _i in range(2, -1, -1):
            result = self.master.run_command(
                ["ldapsearch", "-e", "ppolicy", "-D", dn,
                 "-w", PASSWORD, "-b", dn], raiseonerr=False
            )

        # Verify that passwordgraceusertime is not replicated
        result = tasks.ldapsearch_dm(
            self.master, dn, ['passwordgraceusertime',],
        )
        assert 'passwordgraceusertime: 3' in result.stdout_text.lower()

        result = tasks.ldapsearch_dm(
            self.replicas[0], dn, ['passwordgraceusertime',],
        )
        # Never been set at all so won't return
        assert 'passwordgraceusertime' not in result.stdout_text.lower()

        # Resetting the password should reset passwordgraceusertime
        self.reset_password(self.master)
        result = tasks.ldapsearch_dm(
            self.master, dn, ['passwordgraceusertime',],
        )
        assert 'passwordgraceusertime: 0' in result.stdout_text.lower()
        self.reset_password(self.master)

    def test_graceperiod_zero(self):
        """Test the LDAP bind with zero grace period"""
        dn = "uid={user},cn=users,cn=accounts,{base_dn}".format(
             user=USER, base_dn=str(self.master.domain.basedn))

        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY, "--gracelimit", "0", ],
        )

        # Resetting the password will mark it as expired
        self.reset_password(self.master)

        # Now grace is done and binds should fail.
        result = self.master.run_command(
            ["ldapsearch", "-e", "ppolicy", "-D", dn,
             "-w", PASSWORD, "-b", dn], raiseonerr=False
        )
        assert result.returncode == 49

        assert 'Password is expired' in result.stderr_text
        assert 'Password expired, 0 grace logins remain' in result.stderr_text

    def test_graceperiod_disabled(self):
        """Test the LDAP bind with grace period disabled (-1)"""
        str(self.master.domain.basedn)
        dn = "uid={user},cn=users,cn=accounts,{base_dn}".format(
             user=USER, base_dn=str(self.master.domain.basedn))

        # This can fail if gracelimit is already -1 so ignore it
        self.master.run_command(
            ["ipa", "pwpolicy-mod", POLICY, "--gracelimit", "-1",],
            raiseonerr=False,
        )

        # Ensure the password is expired
        self.reset_password(self.master)

        result = self.kinit_as_user(self.master, PASSWORD, PASSWORD)

        for _i in range(0, 10):
            result = self.master.run_command(
                ["ldapsearch", "-e", "ppolicy", "-D", dn,
                 "-w", PASSWORD, "-b", dn]
            )

        # With graceperiod disabled it should not increment
        result = tasks.ldapsearch_dm(
            self.master, dn, ['passwordgraceusertime',],
        )
        assert 'passwordgraceusertime: 0' in result.stdout_text.lower()
