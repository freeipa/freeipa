"""Module provides extended tests for ipa-getcert CLI operations."""

import os
import time

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.test_ipa_getcert import (
    create_pem_dir, create_nss_db_with_pin, setup_nss_cert_with_password,
)


class TestGetcertRequestExtended(IntegrationTest):
    """Extended request tests with PIN/password-file scenarios."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def test_request_ext_with_correct_pin(self):
        """request using NSS database with correct PIN"""
        tmpdir = create_pem_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-P', 'temp123#', '-I', 'testing'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_with_password_file(self):
        """request using NSS database with password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-p', passwd_file,
                '-I', 'testing'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'newpasswd.txt' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_empty_or_incorrect_pin(self):
        """request using NSS db with empty or incorrect PIN"""
        tmpdir = create_pem_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            self.master.run_command(
                'ipa-getcert request -d %s -n certtest -I testing -P wrong'
                % tmpdir, raiseonerr=False
            )
            time.sleep(5)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_incorrect_password_file(self):
        """request using NSS db with incorrect password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-I', 'testing',
                '-p', passwd_file
            ])
            time.sleep(20)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_empty_request_name(self):
        """request with empty request name should show usage"""
        tmpdir = create_pem_dir(self.master)
        try:
            cmd = self.master.run_command(
                'ipa-getcert request -d %s -n certtest -I 2>&1' % tmpdir,
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert request' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_nonexistent_token(self):
        """request with non-existent token"""
        tmpdir = create_pem_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-I', 'testing', '-t', 'non-existent'
            ])
            time.sleep(6)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)


class TestGetcertListExtended(IntegrationTest):
    """Extended list tests."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def test_list_by_system_bus(self):
        """list certificates by listening on System bus"""
        tmpdir = create_pem_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir, '-n', 'certtest'
            ])
            tasks.wait_for_request(self.master, 'certtest', 120)
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-S']
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_by_nss_db_and_nickname(self):
        """list only one cert on providing NSS db and nickname"""
        tmpdir = create_pem_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir, '-n', 'certtest'
            ])
            tasks.wait_for_request(self.master, 'certtest', 120)
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-d', tmpdir, '-n', 'certtest']
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_by_file_storage(self):
        """list only one cert on providing file storage path"""
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-f', certpath, '-k', keypath
            ])
            time.sleep(10)
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-f', certpath]
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', os.path.join(tmpdir, 'test.crt'),
                 '-k', os.path.join(tmpdir, 'test.key')],
                raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_by_request_identifier(self):
        """list only one cert on providing request identifier"""
        tmpdir = create_pem_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-I', 'testing'
            ])
            tasks.wait_for_request(self.master, 'testing', 120)
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-i', 'testing'],
                raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_nonexistent_request_identifier(self):
        """list output on providing nonexistent request identifier"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'non-existent'],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert 'No request found' in combined

    def test_list_nonexistent_file_path(self):
        """list output on providing nonexistent file storage path"""
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-f', certpath, '-k', keypath
            ])
            time.sleep(6)
            cmd = self.master.run_command(
                ['ipa-getcert', 'list',
                 '-f', os.path.join(tmpdir, 'non-existent.crt')],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', certpath, '-k', keypath], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_incorrect_nss_db(self):
        """list output on providing incorrect NSS db and correct nickname"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list',
             '-d', '/tmp/non-existent', '-n', 'certtest'],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        assert 'No such file or directory' in (
            cmd.stdout_text + cmd.stderr_text)

    def test_list_incorrect_nickname(self):
        """list output on providing correct NSS db and incorrect nickname"""
        tmpdir = create_pem_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-I', 'testing'
            ])
            time.sleep(10)
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-d', tmpdir, '-n', 'non-existent'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-i', 'testing'],
                raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)


class TestGetcertStopTrackingExtended(IntegrationTest):
    """Extended stop-tracking tests."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def test_stop_tracking_by_nss_db_nickname(self):
        """stop-tracking with NSS database path and certificate nickname"""
        tmpdir = create_pem_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-I', 'testing'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            self.master.run_command([
                'ipa-getcert', 'stop-tracking',
                '-d', tmpdir, '-n', 'certtest'
            ])
            cmd = self.master.run_command(['ipa-getcert', 'list'])
            assert ('Number of certificates and requests being tracked: 0'
                    in cmd.stdout_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_stop_tracking_by_cert_key_files(self):
        """stop-tracking with certificate and key file path"""
        tmpdir = create_pem_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'certtest')
            keypath = os.path.join(tmpdir, 'certtest.key')
            self.master.run_command([
                'ipa-getcert', 'request',
                '-f', certpath, '-k', keypath, '-I', 'testing'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            self.master.run_command([
                'ipa-getcert', 'stop-tracking',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(['ipa-getcert', 'list'])
            assert ('Number of certificates and requests being tracked: 0'
                    in cmd.stdout_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_stop_tracking_with_token(self):
        """stop-tracking with NSS database path, nickname, and token"""
        tmpdir = create_pem_dir(self.master)
        try:
            token = ("NSS FIPS 140-2 Certificate DB"
                     if self.master.is_fips_mode
                     else "NSS Certificate DB")
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-t', token, '-I', 'testing'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            self.master.run_command([
                'ipa-getcert', 'stop-tracking', '-d', tmpdir,
                '-n', 'certtest', '-t', token
            ])
            cmd = self.master.run_command(['ipa-getcert', 'list'])
            assert ('Number of certificates and requests being tracked: 0'
                    in cmd.stdout_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_stop_tracking_invalid_token(self):
        """stop-tracking with invalid token name"""
        tmpdir = create_pem_dir(self.master)
        try:
            cmd = self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest', '-t', 'non-existent'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)


class TestGetcertStartTrackingExtended(IntegrationTest):
    """Extended start-tracking tests with PIN/password-file scenarios."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def _setup_tracking_with_password(self, tmpdir, pin="temp123#"):
        """Request a cert, wait for MONITORING, then set NSS DB password
        and resubmit with wrong PIN to get into NEED_CSR_GEN_PIN state.
        """
        setup_nss_cert_with_password(self.master, tmpdir, pin)
        self.master.run_command([
            'ipa-getcert', 'resubmit', '-d', tmpdir,
            '-n', 'certtest', '-P', 'temp123'
        ])
        time.sleep(30)

    def test_start_tracking_ext_correct_pin(self):
        """start-tracking with correct PIN"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-d', tmpdir,
                '-n', 'certtest', '-P', 'temp123#'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in result.stdout_text
            assert 'track: yes' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin(self):
        """start-tracking with incorrect PIN"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-d', tmpdir,
                '-n', 'certtest', '-P', 'temp123'
            ])
            time.sleep(20)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_correct_password_file(self):
        """start-tracking with correct password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123#" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-d', tmpdir,
                '-n', 'certtest', '-p', passwd_file
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_wrong_pin_in_file(self):
        """start-tracking with wrong PIN in password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123#@" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-d', tmpdir,
                '-n', 'certtest', '-p', passwd_file
            ])
            time.sleep(15)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin_file(self):
        """start-tracking with non-existent PIN file"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-d', tmpdir,
                '-n', 'certtest',
                '-p', os.path.join(tmpdir, 'non-existentfile.txt')
            ])
            time.sleep(15)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_correct_pin_by_id(self):
        """start-tracking with correct PIN using request identifier"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-i', 'testing',
                '-P', 'temp123#'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in result.stdout_text
            assert 'track: yes' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin_by_id(self):
        """start-tracking with incorrect PIN using request identifier"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-i', 'testing',
                '-P', 'temp123'
            ])
            time.sleep(20)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_correct_password_file_by_id(self):
        """start-tracking with correct password file using request id"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123#" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-i', 'testing',
                '-p', passwd_file
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin_file_by_id(self):
        """start-tracking with non-existent PIN file using request id"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-i', 'testing',
                '-p', os.path.join(tmpdir, 'non-existentfile.txt')
            ])
            time.sleep(15)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_wrong_pin_in_file_by_id(self):
        """start-tracking with wrong PIN in file using request id"""
        tmpdir = create_pem_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-i', 'testing',
                '-p', passwd_file
            ])
            time.sleep(15)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)


class TestGetcertResubmitExtended(IntegrationTest):
    """Extended resubmit tests with PIN/password-file scenarios."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def test_resubmit_ext_correct_pin(self):
        """resubmit with correct PIN"""
        tmpdir = create_pem_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-d', tmpdir,
                '-n', 'certtest', '-P', 'temp123#'
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_incorrect_pin(self):
        """resubmit with incorrect PIN"""
        tmpdir = create_pem_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-d', tmpdir,
                '-n', 'certtest', '-P', 'temp123'
            ])
            time.sleep(20)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_correct_password_file(self):
        """resubmit with correct password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123#" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-d', tmpdir,
                '-n', 'certtest', '-p', passwd_file
            ])
            status = tasks.wait_for_request(self.master, 'testing', 120)
            assert status == 'MONITORING'
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_incorrect_password_file(self):
        """resubmit with non-existent password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-d', tmpdir,
                '-n', 'certtest',
                '-p', os.path.join(tmpdir, 'non-existentfile.txt')
            ])
            time.sleep(20)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_incorrect_token(self):
        """resubmit with incorrect token name"""
        tmpdir = create_pem_dir(self.master)
        try:
            token = ("NSS FIPS 140-2 Certificate DB"
                     if self.master.is_fips_mode
                     else "NSS Certificate DB")
            self.master.run_command([
                'ipa-getcert', 'request', '-d', tmpdir,
                '-n', 'certtest', '-t', token, '-I', 'testing'
            ])
            tasks.wait_for_request(self.master, 'testing', 120)
            setup_nss_cert_with_password(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            cmd = self.master.run_command(
                ['ipa-getcert', 'resubmit', '-d', tmpdir,
                 '-n', 'certtest',
                 '-p', passwd_file,
                 '-t', 'non-existent'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_wrong_pin_in_file(self):
        """resubmit with incorrect password in password file"""
        tmpdir = create_pem_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'newpasswd.txt')
            self.master.run_command(
                'echo "temp123" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-d', tmpdir,
                '-n', 'certtest', '-p', passwd_file
            ])
            time.sleep(10)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(['rm', '-rf', tmpdir], raiseonerr=False)
