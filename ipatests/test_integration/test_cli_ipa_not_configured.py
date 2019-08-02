from ipapython.admintool import SERVER_NOT_CONFIGURED
from ipatests.test_integration.base import IntegrationTest


class TestIPANotConfigured(IntegrationTest):
    """
    Test class for CLI commands with ipa server not configured.
    Topology parameter is omitted in order to prevent IPA from configuring.
    """

    def test_var_log_message_with_ipa_backup(self):
        """
        Test for PG6843: ipa-backup does not create log file at /var/log
        Launches ipa backup command on system with ipa server not configured.
        As the server is not configured yet, command should fail and stderr
        should not contain link to /var/log, as no such log is created.
        Issue URl: https://pagure.io/freeipa/issue/6843
        """
        exp_str = "not configured on this system"
        unexp_str = "/var/log"
        cmd = self.master.run_command(["ipa-backup"], raiseonerr=False)
        assert (exp_str in cmd.stderr_text and
                cmd.returncode == SERVER_NOT_CONFIGURED and
                unexp_str not in cmd.stderr_text)
