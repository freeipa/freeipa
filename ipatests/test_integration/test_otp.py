#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_plugins.integration import tasks


class TestOTPTokenCommand(IntegrationTest):
    """Test functionality of the ipa otptoken-* commands"""

    topology = 'line'

    def test_delete_last_active_otp_token(self):
        """Test if a user is able to delete their last token"""

        pwd = '12345678'
        new_pwd = 'Secret123'
        user_login = 'test1'

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-add', user_login,
                                 '--first', 'test', '--last', 'user',
                                 '--password'],
                                stdin_text=pwd)

        self.master.run_command(['ipa', 'passwd', user_login],
                                stdin_text=new_pwd)

        # set the global configs
        self.master.run_command(['ipa', 'config-mod',
                                 '--user-auth-type', 'otp'])

        self.master.run_command(['kdestroy', '-A'])

        # write the password down three times as it's needed when
        # doing "kinit" for the first time
        user_kinit_stdin_text = "%s\n%s\n%s\n" % (new_pwd, new_pwd, new_pwd)
        self.master.run_command(['kinit', user_login],
                                stdin_text=user_kinit_stdin_text)

        result = self.master.run_command(['ipa', 'otptoken-add'])
        assert 'Added OTP token' in result.stdout_text

        otp_result = self.master.run_command(['ipa', 'otptoken-find'])

        # example of output from otptoken-find command:
        # ['-----', '1 OTP token matched', '-----',
        # Unique ID: 7a09e308-e6ab-4318-aaf4-f00d57ed32de',
        token = otp_result.stdout_text.split('\n')[3].split('ID:')[1].strip()

        result = self.master.run_command(['ipa', 'otptoken-del', token],
                                         raiseonerr=False)
        assert "Can't delete last active token" in result.stderr_text
