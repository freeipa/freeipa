#
# Copyright (C) 2019,2020  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for Kerberos ticket policy options
and password expiration enforcement in the kdcpolicy plugin.
"""

from __future__ import absolute_import

import pytest
import time
from datetime import datetime

from ipalib.constants import IPAAPI_USER
from ipaplatform.paths import paths

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_otp import add_otptoken, del_otptoken
from ipatests.pytest_ipa.integration import tasks

PASSWORD = "Secret123"
ALT_PASSWORD = "AltSecret456"
USER1 = "testuser1"
USER2 = "testuser2"
MAXLIFE = 86400
LANG_PKG = ["langpacks-en"]
PAST_EXPIRATION = "20200101000000Z"
FUTURE_EXPIRATION = "29991231235959Z"

def maxlife_within_policy(input, maxlife, slush=3600):
    """Given klist output of the TGT verify that it is within policy

       Ensure that the validity period is somewhere within the
       absolute maxlife and a slush value, maxlife - slush.

       Returns True if within policy.

       Input should be a string like:
       11/19/2019 16:37:40  11/20/2019 16:37:39  krbtgt/...

       slush defaults to 1 * 60 * 60 matching the jitter window.
    """
    data = input.split()
    start = datetime.strptime(data[0] + ' ' + data[1], '%m/%d/%Y %H:%M:%S')
    end = datetime.strptime(data[2] + ' ' + data[3], '%m/%d/%Y %H:%M:%S')
    diff = int((end - start).total_seconds())

    return maxlife >= diff >= maxlife - slush

@pytest.fixture
def reset_to_default_policy():
    """Reset default user authentication and user authentication type"""

    state = dict()

    def _reset_to_default_policy(host, user=None):
        state['host'] = host
        state['user'] = user

    yield _reset_to_default_policy

    host = state['host']
    user = state['user']
    tasks.kinit_admin(host)
    host.run_command(['ipa', 'krbtpolicy-reset'])
    if user:
        host.run_command(['ipa', 'user-mod', user, '--user-auth-type='])
        host.run_command(['ipa', 'krbtpolicy-reset', user])


def kinit_check_life(master, user):
    """Acquire a TGT and check if it's within the lifetime window"""
    master.run_command(["kinit", user], stdin_text=f"{PASSWORD}\n")
    result = master.run_command("LANG=en_US.utf-8 klist | grep krbtgt")
    assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True


class TestPWPolicy(IntegrationTest):
    """Tests password custom and default password policies.
    """
    num_replicas = 0

    @classmethod
    def install(cls, mh):
        tasks.install_packages(cls.master, LANG_PKG)
        tasks.install_master(cls.master)
        tasks.create_active_user(cls.master, USER1, PASSWORD)
        tasks.create_active_user(cls.master, USER2, PASSWORD)

    @pytest.fixture(autouse=True, scope="function")
    def with_admin(self):
        tasks.kinit_admin(self.master)
        yield
        tasks.kdestroy_all(self.master)

    def test_krbtpolicy_default(self):
        """Test the default kerberos ticket policy 24-hr tickets"""
        master = self.master
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--maxlife', str(MAXLIFE)])
        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER1],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command("LANG=en_US.utf-8 klist | grep krbtgt")
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_password_and_hardended(self):
        """Test a pwd and hardened kerberos ticket policy with 10min tickets"""
        if self.master.is_fips_mode:
            pytest.skip("SPAKE pre-auth is not compatible with FIPS mode")

        master = self.master
        master.run_command(['ipa', 'user-mod', USER1,
                            '--user-auth-type', 'password',
                            '--user-auth-type', 'hardened'])
        master.run_command(['ipa', 'config-mod',
                            '--user-auth-type', 'password',
                            '--user-auth-type', 'hardened'])
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--hardened-maxlife', '600'])

        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER1],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('LANG=en_US.utf-8 klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 600,
                                     slush=600) is True

        tasks.kdestroy_all(master)

        # Verify that the short policy only applies to USER1
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('LANG=en_US.utf-8 klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_hardended(self):
        """Test a hardened kerberos ticket policy with 30min tickets"""
        if self.master.is_fips_mode:
            pytest.skip("SPAKE pre-auth is not compatible with FIPS mode")

        master = self.master
        master.run_command(['ipa', 'user-mod', USER1,
                            '--user-auth-type', 'hardened'])
        master.run_command(['ipa', 'config-mod',
                            '--user-auth-type', 'hardened'])
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--hardened-maxlife', '1800'])

        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER1],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('LANG=en_US.utf-8 klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 1800,
                                     slush=1800) is True

        tasks.kdestroy_all(master)

        # Verify that the short policy only applies to USER1
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('LANG=en_US.utf-8 klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_password(self):
        """Test the kerberos ticket policy which issues 20 min tickets"""
        master = self.master
        master.run_command(['ipa', 'krbtpolicy-mod', USER2,
                            '--maxlife', '1200'])

        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('LANG=en_US.utf-8 klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 1200,
                                     slush=1200) is True

    def test_krbtpolicy_reset(self):
        """Test a hardened kerberos ticket policy reset"""
        master = self.master
        master.run_command(['ipa', 'krbtpolicy-reset', USER2])
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('LANG=en_US.utf-8 klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

    def test_krbtpolicy_otp(self, reset_to_default_policy):
        """Test otp ticket policy"""
        master = self.master
        master.run_command(['ipa', 'user-mod', USER1,
                            '--user-auth-type', 'otp'])
        master.run_command(['ipa', 'config-mod',
                            '--user-auth-type', 'otp'])
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--otp-maxrenew=90', '--otp-maxlife=60'])
        armor = tasks.create_temp_file(self.master, create_file=False)
        otpuid, totp = add_otptoken(master, USER1, otptype="totp")
        otpvalue = totp.generate(int(time.time())).decode("ascii")
        reset_to_default_policy(master, USER1)
        try:
            tasks.kdestroy_all(master)
            # create armor for FAST
            master.run_command(['kinit', '-n', '-c', armor])
            # expect ticket expire in otp-maxlife=60 seconds
            master.run_command(
                ['kinit', '-T', armor, USER1, '-r', '90'],
                stdin_text='{0}{1}\n'.format(PASSWORD, otpvalue))
            master.run_command(['ipa', 'user-find', USER1])
            time.sleep(30)
            # when user kerberos ticket expired but still within renew time,
            #  kinit -R should give user new life
            master.run_command(['kinit', '-R', USER1])
            master.run_command(['ipa', 'user-find', USER1])
            time.sleep(60)
            # when renew time expires, kinit -R should fail
            result1 = master.run_command(['kinit', '-R', USER1],
                                         raiseonerr=False)
            tasks.assert_error(
                result1,
                "kinit: Ticket expired while renewing credentials", 1)
            master.run_command(['ipa', 'user-find', USER1],
                               ok_returncode=1)
        finally:
            del_otptoken(master, otpuid)
            self.master.run_command(['rm', '-f', armor])
            master.run_command(['ipa', 'config-mod', '--user-auth-type='])

    def test_krbtpolicy_jitter(self):
        """Test jitter lifetime with no auth indicators"""
        kinit_check_life(self.master, USER1)

    def test_krbtpolicy_jitter_otp(self, reset_to_default_policy):
        """Test jitter lifetime with OTP"""
        reset_to_default_policy(self.master, USER1)
        self.master.run_command(["ipa", "user-mod", USER1,
                                 "--user-auth-type", "otp"])
        kinit_check_life(self.master, USER1)

    def test_ccache_sweep_expired(self, reset_to_default_policy):
        """Test that the ccache sweeper works on expired ccaches

           - Force wipe all existing ccaches
           - Set the ticket policy to a short value, 20 seconds.
           - Do a series of kinit, ipa command, kdestroy to generate ccaches
           - sleep() for expiration
           - Run the sweeper
           - Verify that all expired ccaches are gone
        """
        MAXLIFE = 20
        reset_to_default_policy(self.master)  # this will reset at END of test
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ['ipa', 'krbtpolicy-mod', '--maxlife', str(MAXLIFE)]
        )
        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ['find', paths.IPA_CCACHES, '-type', 'f', '-delete']
        )
        for _i in range(5):
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-show', 'admin'])
            tasks.kdestroy_all(self.master)

        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(paths.IPA_CCACHES)
        )
        assert int(result.stdout_text.strip()) == 5

        # let ccache expire
        time.sleep(MAXLIFE)
        ccache_sweep_cmd = ["/usr/libexec/ipa/ipa-ccache-sweeper", "-m", "0"]

        # should be run as ipaapi for GSSProxy
        self.master.run_command(
            ["runuser", "-u", IPAAPI_USER, "--"] + ccache_sweep_cmd
        )

        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(paths.IPA_CCACHES)
        )
        assert int(result.stdout_text.strip()) == 0

    def test_ccache_sweep_valid(self):
        """Test that the ccache sweeper doesn't remove valid ccaches
           - Force wipe all existing ccaches
           - Run the sweeper
           - Verify that all valid ccaches weren't removed
           Note: assumed that ccache expiration doesn't happen during test
        """
        tasks.kdestroy_all(self.master)
        self.master.run_command(
            ["find", paths.IPA_CCACHES, "-type", "f", "-delete"]
        )

        for _i in range(5):
            tasks.kinit_admin(self.master)
            self.master.run_command(["ipa", "user-show", "admin"])
            tasks.kdestroy_all(self.master)

        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(paths.IPA_CCACHES)
        )
        assert int(result.stdout_text.strip()) == 5

        ccache_sweep_cmd = ["/usr/libexec/ipa/ipa-ccache-sweeper", "-m", "0"]

        # should be run as ipaapi for GSSProxy
        self.master.run_command(
            ["runuser", "-u", IPAAPI_USER, "--"] + ccache_sweep_cmd
        )
        result = self.master.run_command(
            "ls -1 {0} | wc -l".format(paths.IPA_CCACHES)
        )
        assert int(result.stdout_text.strip()) == 5

    # ----------------------------------------------------------------
    # Password expiration enforcement in ipa_kdcpolicy_check_as()
    #
    # The IPA KDB plugin clears entry->pw_expiration for users with
    # passwordless methods (PKINIT, etc.) so that validate_as_request()
    # does not reject the AS-REQ before pre-auth.  The kdcpolicy plugin
    # re-checks expiration after pre-auth using ied->pw_expiration.
    # ----------------------------------------------------------------

    @pytest.fixture
    def pkinituser(self):
        """Create a user with password + PKINIT auth types."""
        user = "pkinitexpuser"
        tasks.kinit_admin(self.master)
        tasks.create_active_user(
            self.master, user, PASSWORD,
            extra_args=["--user-auth-type=password",
                        "--user-auth-type=pkinit"])
        yield user
        tasks.kinit_admin(self.master)
        tasks.user_del(self.master, user, raiseonerr=False)

    def expire_user_password(self, user):
        """Set password expiration to the past and clear SSSD cache."""
        tasks.kinit_admin(self.master)
        self.master.run_command([
            "ipa", "user-mod", user,
            "--password-expiration", PAST_EXPIRATION,
        ])
        tasks.clear_sssd_cache(self.master)

    def unexpire_user_password(self, user):
        """Set password expiration to the far future."""
        tasks.kinit_admin(self.master)
        self.master.run_command([
            "ipa", "user-mod", user,
            "--password-expiration", FUTURE_EXPIRATION,
        ])
        tasks.clear_sssd_cache(self.master)

    def test_pw_expiration_pwonly_valid(self):
        """Password-only user with valid password can kinit."""
        tasks.kdestroy_all(self.master)
        result = tasks.kinit_as_user(self.master, USER1, PASSWORD,
                                     raiseonerr=False)
        assert result.returncode == 0

    def test_pw_expiration_pwonly_expired(self):
        """Password-only user with expired password cannot kinit.

        validate_as_request() enforces pw_expiration directly.
        """
        self.expire_user_password(USER1)
        try:
            tasks.kdestroy_all(self.master)
            result = tasks.kinit_as_user(self.master, USER1, PASSWORD,
                                         raiseonerr=False)
            assert result.returncode != 0
        finally:
            self.unexpire_user_password(USER1)

    def test_pw_expiration_pkinit_user_password_rejected(self, pkinituser):
        """Passwordless-capable user with expired password cannot kinit
        using password.

        validate_as_request() skips the check (pw_expiration cleared to
        0 by ipadb_parse_ldap_entry), but ipa_kdcpolicy_check_as()
        enforces it using ied->pw_expiration.
        """
        self.expire_user_password(pkinituser)
        tasks.kdestroy_all(self.master)
        result = tasks.kinit_as_user(self.master, pkinituser, PASSWORD,
                                     raiseonerr=False)
        assert result.returncode != 0, (
            "kinit should fail for pkinit+password user with expired password"
        )

    def test_pw_expiration_pkinit_user_valid(self, pkinituser):
        """Passwordless-capable user with valid password can kinit."""
        tasks.kdestroy_all(self.master)
        result = tasks.kinit_as_user(self.master, pkinituser, PASSWORD,
                                     raiseonerr=False)
        assert result.returncode == 0

    def test_pw_expiration_pwonly_kpasswd(self):
        """Password-only user with expired password can change it via
        kpasswd.

        validate_as_request() exempts KRB5_KDB_PWCHANGE_SERVICE.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=0"],
                                raiseonerr=False)
        self.expire_user_password(USER1)
        try:
            tasks.kdestroy_all(self.master)
            with self.master.spawn_expect(
                ["kpasswd", USER1], default_timeout=30
            ) as e:
                e.expect("Password for .+:")
                e.sendline(PASSWORD)
                e.expect_exact("Enter new password:")
                e.sendline(ALT_PASSWORD)
                e.expect_exact("Enter it again:")
                e.sendline(ALT_PASSWORD)
                e.expect_exit(ignore_remaining_output=True)

            # Verify new password works
            self.unexpire_user_password(USER1)
            tasks.kdestroy_all(self.master)
            result = tasks.kinit_as_user(self.master, USER1, ALT_PASSWORD,
                                         raiseonerr=False)
            assert result.returncode == 0
        finally:
            # Restore original password
            tasks.kinit_admin(self.master)
            self.master.run_command(
                ["ipa", "passwd", USER1],
                stdin_text="{0}\n{0}\n".format(PASSWORD),
            )
            self.unexpire_user_password(USER1)

    def test_pw_expiration_pkinit_user_kpasswd(self, pkinituser):
        """Passwordless-capable user with expired password can change it
        via kpasswd.

        validate_as_request() skips the check (pw_expiration cleared),
        and ipa_kdcpolicy_check_as() must exempt PWCHANGE_SERVICE.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=0"],
                                raiseonerr=False)
        self.expire_user_password(pkinituser)
        tasks.kdestroy_all(self.master)
        with self.master.spawn_expect(
            ["kpasswd", pkinituser], default_timeout=30
        ) as e:
            e.expect("Password for .+:")
            e.sendline(PASSWORD)
            e.expect_exact("Enter new password:")
            e.sendline(ALT_PASSWORD)
            e.expect_exact("Enter it again:")
            e.sendline(ALT_PASSWORD)
            e.expect_exit(ignore_remaining_output=True)

        # Verify new password works
        self.unexpire_user_password(pkinituser)
        tasks.kdestroy_all(self.master)
        result = tasks.kinit_as_user(self.master, pkinituser, ALT_PASSWORD,
                                     raiseonerr=False)
        assert result.returncode == 0

    def test_min_pwd_life_admin_reset_pwonly(self):
        """Admin password reset bypasses min_pwd_life for password-only
        user.

        When an admin resets a password, krbPasswordExpiration equals
        krbLastPwdChange, signalling that minimum password age should
        not apply.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=1"],
                                raiseonerr=False)
        try:
            self.master.run_command(
                ["ipa", "passwd", USER1],
                stdin_text="{0}\n{0}\n".format(ALT_PASSWORD),
            )
            tasks.kdestroy_all(self.master)
            # User can change password immediately despite minlife
            with self.master.spawn_expect(
                ["kinit", USER1], default_timeout=30
            ) as e:
                e.expect("Password for .+:")
                e.sendline(ALT_PASSWORD)
                e.expect("Password expired")
                e.expect("Enter new password:")
                e.sendline(PASSWORD)
                e.expect("Enter it again:")
                e.sendline(PASSWORD)
                e.expect_exit(ignore_remaining_output=True)
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=0"],
                                    raiseonerr=False)

    def test_min_pwd_life_admin_reset_pkinit_user(self, pkinituser):
        """Admin password reset bypasses min_pwd_life for
        passwordless-capable user.

        ipadb_check_pw_policy() must use ied->pw_expiration (real value
        from LDAP) rather than db_entry->pw_expiration (cleared to 0
        for passwordless-capable users) for admin-reset detection.
        """
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=1"],
                                raiseonerr=False)
        try:
            self.master.run_command(
                ["ipa", "passwd", pkinituser],
                stdin_text="{0}\n{0}\n".format(ALT_PASSWORD),
            )
            tasks.kdestroy_all(self.master)
            # User can change password immediately despite minlife
            with self.master.spawn_expect(
                ["kinit", pkinituser], default_timeout=30
            ) as e:
                e.expect("Password for .+:")
                e.sendline(ALT_PASSWORD)
                e.expect("Password expired")
                e.expect("Enter new password:")
                e.sendline(PASSWORD)
                e.expect("Enter it again:")
                e.sendline(PASSWORD)
                e.expect_exit(ignore_remaining_output=True)
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=0"],
                                    raiseonerr=False)

    def test_pw_expiration_cleanup(self):
        """Restore state after password expiration tests."""
        tasks.kinit_admin(self.master)
        self.master.run_command(["ipa", "pwpolicy-mod", "--minlife=0"],
                                raiseonerr=False)
        self.master.run_command(
            ["ipa", "passwd", USER1],
            stdin_text="{0}\n{0}\n".format(PASSWORD),
            raiseonerr=False,
        )
        self.unexpire_user_password(USER1)
