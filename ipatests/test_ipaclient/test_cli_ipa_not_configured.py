import subprocess


class TestIPANotConfigured:
    """
    Test class for CLI commands with ipa server not configured.
    """

    @staticmethod
    def run_command(args, return_code, expected_output, expected_error, unexpected_error=None):
        """
        Run command with ipa server not configured.
        Launch the command specified in args.
        Check that the exit code is as expected and that stdout and stderr
        contain the expected strings.
        """
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        assert return_code == p.returncode
        if expected_output:
            assert expected_output in out
        if expected_error:
            assert expected_error in err
        if unexpected_error:
            assert unexpected_error not in err

    def test_var_log_message_with_ipa_backup(self):
        """
        Test for BZ1428690: ipa-backup does not create log file at /var/log
        Launches ipa backup command on system with ipa server not configured.
        As the server is not configured yet, command should fail and stderr should not
        contain link to /var/log, as no such log is created
        """
        self.run_command("ipa backup", 1, None, "not configured on this system", "/var/log")