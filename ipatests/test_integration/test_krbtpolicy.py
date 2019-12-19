#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests for Kerberos ticket policy options
"""

from __future__ import absolute_import

import time
from datetime import datetime

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_otp import add_otptoken, del_otptoken
from ipatests.pytest_ipa.integration import tasks

PASSWORD = "Secret123"
USER1 = "testuser1"
USER2 = "testuser2"
MAXLIFE = 86400


def maxlife_within_policy(input, maxlife, slush=5):
    """Given klist output of the TGT verify that it is within policy

       Ensure that the validity period is somewhere within the
       absolute maxlife and a slush value, maxlife - slush.

       Returns True if within policy.

       Input should be a string like:
       11/19/2019 16:37:40  11/20/2019 16:37:39  krbtgt/...
    """
    data = input.split()
    start = datetime.strptime(data[0] + ' ' + data[1], '%m/%d/%Y %H:%M:%S')
    end = datetime.strptime(data[2] + ' ' + data[3], '%m/%d/%Y %H:%M:%S')
    diff = int((end - start).total_seconds())

    return maxlife >= diff >= maxlife - slush


def reset_to_default_policy(host, user):
    """Reset default user authentication and user authentication type"""
    tasks.kinit_admin(host)
    host.run_command(['ipa', 'user-mod', user, '--user-auth-type='])
    host.run_command(['ipa', 'krbtpolicy-reset'])
    host.run_command(['ipa', 'krbtpolicy-reset', user])


class TestPWPolicy(IntegrationTest):
    """Tests password custom and default password policies.
    """
    num_replicas = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.create_active_user(cls.master, USER1, PASSWORD)
        tasks.create_active_user(cls.master, USER2, PASSWORD)

    def test_krbtpolicy_default(self):
        """Test the default kerberos ticket policy 24-hr tickets"""
        master = self.master

        tasks.kinit_admin(master)
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--maxlife', str(MAXLIFE)])
        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER1],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

        tasks.kdestroy_all(master)

    def test_krbtpolicy_hardended(self):
        """Test a hardened kerberos ticket policy with 10 min tickets"""
        master = self.master

        tasks.kinit_admin(master)
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
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 600) is True

        tasks.kdestroy_all(master)

        # Verify that the short policy only applies to USER1
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

        tasks.kdestroy_all(master)

    def test_krbtpolicy_password(self):
        """Test the kerberos ticket policy which issues 20 min tickets"""
        master = self.master

        tasks.kinit_admin(master)
        master.run_command(['ipa', 'krbtpolicy-mod', USER2,
                            '--maxlife', '1200'])

        tasks.kdestroy_all(master)

        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, 1200) is True

        tasks.kdestroy_all(master)

    def test_krbtpolicy_reset(self):
        """Test a hardened kerberos ticket policy reset"""
        master = self.master

        tasks.kinit_admin(master)
        master.run_command(['ipa', 'krbtpolicy-reset', USER2])
        master.run_command(['kinit', USER2],
                           stdin_text=PASSWORD + '\n')
        result = master.run_command('klist | grep krbtgt')
        assert maxlife_within_policy(result.stdout_text, MAXLIFE) is True

        tasks.kdestroy_all(master)

    def test_krbtpolicy_otp(self):
        """Test otp ticket policy"""
        master = self.master
        tasks.kinit_admin(self.master)
        master.run_command(['ipa', 'user-mod', USER1,
                            '--user-auth-type', 'otp'])
        master.run_command(['ipa', 'config-mod',
                            '--user-auth-type', 'otp'])
        master.run_command(['ipa', 'krbtpolicy-mod', USER1,
                            '--otp-maxrenew=90', '--otp-maxlife=60'])
        armor = tasks.create_temp_file(self.master, create_file=False)
        otpuid, totp = add_otptoken(master, USER1, otptype="totp")
        otpvalue = totp.generate(int(time.time())).decode("ascii")
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
            reset_to_default_policy(master, USER1)
            self.master.run_command(['rm', '-f', armor])
            master.run_command(['ipa', 'config-mod', '--user-auth-type='])
