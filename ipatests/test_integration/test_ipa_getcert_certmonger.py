"""Module provides bugzilla regression tests for certmonger."""

import os
import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_ipa_getcert import create_pem_dir


class TestCertmongerBugzillas(IntegrationTest):
    """Certmonger bugzilla regression tests."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def test_bz1104138_no_sysv_convert(self):
        """certmonger does not require systemd-sysv-convert

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1104138
        """
        triggers = self.master.run_command(
            ['rpm', '-q', '--triggers', 'certmonger'],
            raiseonerr=False
        )
        assert 'systemd-sysv-convert' not in triggers.stdout_text

        scripts = self.master.run_command(
            ['rpm', '-q', '--scripts', 'certmonger'],
            raiseonerr=False
        )
        assert 'systemd-sysv-convert' not in scripts.stdout_text

    def test_bz1103090_dbus_restart(self):
        """certmonger should not crash on D-Bus service restart

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1103090
        """
        self.master.run_command(
            ['systemctl', 'start', 'certmonger'], raiseonerr=False
        )
        self.master.run_command(['systemctl', 'restart', 'dbus'])
        time.sleep(5)
        cmd = self.master.run_command(
            ['systemctl', 'is-active', 'certmonger'], raiseonerr=False
        )
        assert cmd.stdout_text.strip() == 'active'

    def test_bz1098208_request_invalid_f(self):
        """request with -F to invalid location should fail

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            cmd = self.master.run_command(
                ['ipa-getcert', 'request', '-w', '-v',
                 '-f', certpath, '-k', keypath,
                 '-F', '/tmp/non-existent/test-root.crt'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No such file or directory' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_request_empty_f(self):
        """request with empty -F should show usage

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            cmd = self.master.run_command(
                'ipa-getcert request -w -v '
                '-f %s -k %s -F 2>&1' % (certpath, keypath),
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert request' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_request_invalid_a(self):
        """request with -a to invalid NSS DB should fail

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_pem_dir(self.master)
        try:
            cmd = self.master.run_command(
                ['ipa-getcert', 'request', '-w', '-v',
                 '-d', tmpdir, '-n', 'test',
                 '-a', '/tmp/nonexistent/'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No such file or directory' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_request_empty_a(self):
        """request with empty -a should show usage

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_pem_dir(self.master)
        try:
            cmd = self.master.run_command(
                'ipa-getcert request -w -v -d %s -n test -a 2>&1' % tmpdir,
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert request' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_resubmit_invalid_f(self):
        """resubmit with -F to invalid location should fail

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'resubmit', '-w', '-v',
                 '-f', certpath,
                 '-F', '/tmp/non-existent/test-root.crt'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No such file or directory' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', certpath, '-k', keypath], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_resubmit_empty_f(self):
        """resubmit with empty -F should show usage

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(
                'ipa-getcert resubmit -w -v -f %s -F 2>&1' % certpath,
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert resubmit' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', certpath, '-k', keypath], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)
