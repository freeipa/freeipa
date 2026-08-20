"""Module provides tests for ipa-getcert CLI operations."""

import os
import re
import uuid

import pytest

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


def get_cert_subject_base(host):
    """Retrieve the IPA certificate subject base."""
    tasks.kinit_admin(host)
    cmd = host.run_command(['ipa', 'config-show'])
    for line in cmd.stdout_text.splitlines():
        if 'Certificate Subject base' in line:
            return line.split(':', 1)[1].strip()
    raise RuntimeError("Could not determine certificate subject base")


def clean_requests(host):
    """Stop certmonger, purge all requests, restart certmonger."""
    host.run_command(['systemctl', 'stop', 'certmonger'])
    host.run_command(
        ['find', paths.CERTMONGER_REQUESTS_DIR,
         '-type', 'f', '-delete'],
        raiseonerr=False
    )
    host.run_command(['systemctl', 'start', 'certmonger'])


def create_file_dir(host):
    """Create a temp directory with cert_t SELinux context."""
    tmpdir = host.run_command(['mktemp', '-d']).stdout_text.strip()
    host.run_command(['chcon', '-t', 'cert_t', tmpdir])
    return tmpdir


def prepare_file_keyfile(host, file_dir, test_id,
                         keytype='RSA'):
    """Generate a key in file_dir."""
    keyfile = os.path.join(file_dir, '%s.key.pem' % test_id)
    host.run_command([
        'openssl', 'genpkey',
        '-algorithm', keytype, '-out', keyfile
    ])
    return keyfile


def prepare_file_certfile(host, file_dir, test_id):
    """Create an empty cert file in file_dir."""
    certfile = os.path.join(file_dir, '%s.cert.pem' % test_id)
    host.run_command(['touch', certfile])
    return certfile


def prepare_pin(host, file_dir, test_id):
    """Create a PIN file in file_dir."""
    pinfile = os.path.join(file_dir, '%s.pin' % test_id)
    host.put_file_contents(
        pinfile, 'random-pin-string-%s\n' % test_id
    )
    return pinfile


def prepare_certrequest(host, test_id):
    """Create a cert request for start-tracking -i tests."""
    host.run_command([
        'ipa-getcert', 'request', '-w', '-v',
        '-n', test_id, '-d', NSSDB_VALID, '-I', test_id
    ])


def create_nss_db_with_pin(host, tmpdir, pin="temp123#"):
    """Create NSS DB with a password in tmpdir."""
    passwd_file = os.path.join(tmpdir, 'passwd.txt')
    host.put_file_contents(passwd_file, '%s\n' % pin)
    host.run_command([
        'certutil', '-N', '-d', tmpdir, '-f', passwd_file,
    ])


def request_nss_cert_with_password(host, tmpdir, pin="temp123#"):
    """Request cert in NSS DB, wait for MONITORING, set DB password."""
    oldpw = os.path.join(tmpdir, 'oldpasswd.txt')
    newpw = os.path.join(tmpdir, 'passwd.txt')
    host.put_file_contents(oldpw, '\n')
    host.put_file_contents(newpw, '%s\n%s\n' % (pin, pin))
    host.run_command([
        'ipa-getcert', 'request', '-w', '-v',
        '-d', tmpdir, '-n', 'certtest', '-I', 'testing'
    ])
    host.run_command([
        'certutil', '-W', '-d', tmpdir,
        '-f', oldpw, '-@', newpw,
    ])


NSSDB_ERR_MSGS = [
    'must be a directory',
    'is not a directory',
    'No such file or directory',
    'No request found that matched arguments',
]

FILE_KEY_ERR_MSGS = [
    'is not a directory',
    'No such file or directory',
    'must be a valid directory',
    'No request found that matched arguments',
]

FILE_CERT_ERR_MSGS = ['is not absolute']

EKU_ERR_MSGS = ['Could not evaluate OID']

TOKEN_VERIFY = ['NEED_KEY_PAIR', 'NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN']

KEYSIZE_VERIFY = ['NEED_KEY_PAIR', 'CA_UNREACHABLE']

PINFILE_VERIFY = ['NEWLY_ADDED_NEED_KEYINFO_READ_PIN']

PRINCIPAL_VERIFY = [
    'CA_UNREACHABLE', 'CA_UNCONFIGURED', 'NEED_KEY_PAIR',
]

FILE_PRINCIPAL_VERIFY = [
    'CA_UNREACHABLE', 'CA_UNCONFIGURED',
    'NEED_KEY_PAIR', 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN',
]

NSSDB_VALID = "/etc/pki/nssdb"
NSSDB_INVALID = "/tmp/nonexistent_nssdb"
EKU_VALID = "1.3.6.1.5.5.7.3.1"
TOKEN_VALID = "NSS Certificate DB"
EMAIL_VALID = "testqa@redhat.com"


class GetcertTestMixin:
    """Shared helpers for ipa-getcert request / start-tracking tests."""

    getcert_command = None   # 'request' or 'start-tracking'
    id_prefix = None         # 'CertReq' or 'TrackReq'

    def _assert_negative(self, cmd, err_msgs):
        """Assert negative test: rc=1, error message present, no request."""
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in err_msgs), (
            "Expected one of %r in: %s" % (err_msgs, combined))
        cmd = self.master.run_command(
            ['ls', paths.CERTMONGER_REQUESTS_DIR],
            raiseonerr=False
        )
        if cmd.stdout_text.strip():
            clean_requests(self.master)
            pytest.fail("Unexpected request was created")

    def _assert_verify(self, cmd, expected_statuses):
        """Assert verify test: rc=0, certmonger status checked."""
        assert cmd.returncode == 0
        try:
            match = re.search(
                r'New .* (?:signing|tracking|) ?request'
                r' "([^"]+)" added',
                cmd.stdout_text
            )
            if match:
                status = tasks.wait_for_certmonger_status(
                    self.master,
                    tuple(expected_statuses),
                    match.group(1), timeout=120
                )
                assert status in expected_statuses, (
                    "Expected status in %r, got %s"
                    % (expected_statuses, status))
        finally:
            clean_requests(self.master)

    def _assert_positive(self, cmd):
        """Assert positive test: rc=0, cleanup."""
        try:
            assert cmd.returncode == 0
        finally:
            clean_requests(self.master)

    def _setup_file(self, test_id, need_key=True,
                    need_cert=True, need_pin=False):
        """Prepare FILE storage test artifacts."""
        if need_key:
            prepare_file_keyfile(self.master, self.file_dir, test_id)
        if need_cert:
            prepare_file_certfile(self.master, self.file_dir, test_id)
        if need_pin:
            prepare_pin(self.master, self.file_dir, test_id)

    def _file_cmd(self, test_id, extra_args,
                  key_invalid=False, cert_invalid=False):
        """Build ipa-getcert command with FILE storage."""
        if key_invalid:
            keyfile = os.path.join(
                '/root', test_id, 'no.such.pem.key.file.')
        else:
            keyfile = os.path.join(
                self.file_dir, '%s.key.pem' % test_id)
        if cert_invalid:
            certfile = os.path.join(test_id, 'NoSuchFileCertFile')
        else:
            certfile = os.path.join(
                self.file_dir, '%s.cert.pem' % test_id)
        return ['ipa-getcert', self.getcert_command,
                '-k', keyfile, '-f', certfile] + extra_args

    def _file_extra_args(self, test_id, renewal,
                         pin_mode=None, use_keysize=False,
                         principal_invalid=False,
                         eku_invalid=False,
                         keysize_invalid=False,
                         pinfile_invalid=False):
        """Build FILE storage extra arguments."""
        args = []
        if pin_mode == 'inline':
            args += ['-P', '%sjfkdlaj2920jgajfklda290' % test_id]
        elif pin_mode == 'file':
            if pinfile_invalid:
                args += ['-p', os.path.join(
                    '/root', test_id, 'no.such.pin.file')]
            else:
                args += ['-p', os.path.join(
                    self.file_dir, '%s.pin' % test_id)]
        args += ['-I', '%s_%s' % (self.id_prefix, test_id)]
        if use_keysize:
            if keysize_invalid:
                args += ['-g', 'shouldBEnumber%s' % test_id]
            else:
                args += ['-g', '2048']
        args.append(renewal)
        if self.getcert_command == 'request':
            args += ['-N', self.cert_subject]
        if principal_invalid:
            args += ['-K', 'NoSuchPrincipal%s' % test_id]
        else:
            args += ['-K', '%s/%s@%s'
                     % (test_id, self.fqdn, self.realm)]
        if eku_invalid:
            args += ['-U', 'in.valid.ext.usage.%s' % test_id]
        else:
            args += ['-U', EKU_VALID]
        args += ['-D', self.fqdn, '-E', EMAIL_VALID]
        return args


class TestGetcertRequest(GetcertTestMixin, IntegrationTest):
    """Tests for ipa-getcert request command."""

    num_replicas = 0
    num_clients = 0
    topology = 'line'
    getcert_command = 'request'
    id_prefix = 'CertReq'

    @classmethod
    def install(cls, mh):
        super(TestGetcertRequest, cls).install(mh)
        cls.cert_subject = get_cert_subject_base(cls.master)
        cls.fqdn = cls.master.hostname
        cls.realm = cls.master.domain.realm
        cls.file_dir = create_file_dir(cls.master)
        clean_requests(cls.master)

    def _nss_cmd(self, test_id, extra_args):
        """Build ipa-getcert request command with NSS storage."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'request', '-d', NSSDB_VALID,
                '-n', nickname] + extra_args

    def _nss_invalid_cmd(self, test_id, extra_args):
        """Build ipa-getcert request command with invalid NSSDBDIR."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'request',
                '-d', NSSDB_INVALID,
                '-n', nickname] + extra_args

    def _full_nss_args(self, test_id, renewal,
                       use_keysize=False,
                       principal_invalid=False,
                       eku_invalid=False,
                       token_invalid=False,
                       keysize_invalid=False):
        """Build the -t -I/-g -R/-r -N -K -U -D -E arguments."""
        args = []
        if token_invalid:
            args += ['-t', ' NoSuchToken%s' % test_id]
        else:
            args += ['-t', TOKEN_VALID]
        args += ['-I', 'CertReq_%s' % test_id]
        if use_keysize:
            if keysize_invalid:
                args += ['-g', 'shouldBEnumber%s' % test_id]
            else:
                args += ['-g', '2048']
        args.append(renewal)
        args += ['-N', self.cert_subject]
        if principal_invalid:
            args += ['-K', 'NoSuchPrincipal%s' % test_id]
        else:
            args += ['-K', '%s/%s@%s'
                     % (test_id, self.fqdn, self.realm)]
        if eku_invalid:
            args += ['-U', 'in.valid.ext.usage.%s' % test_id]
        else:
            args += ['-U', EKU_VALID]
        args += ['-D', self.fqdn, '-E', EMAIL_VALID]
        return args

    def test_request_nss_invalid_nssdbdir_basic(self):
        """request with invalid NSSDBDIR, no extra args"""
        test_id = "req_nssdb_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_invalid_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_invalid_nssdbdir_full(self):
        """request with invalid NSSDBDIR and full args"""
        test_id = "req_nssdb_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_invalid_cmd(
                test_id,
                self._full_nss_args(
                    test_id, renewal="-R",
                    use_keysize=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_invalid_token(self):
        """request with invalid token"""
        test_id = "req_tok_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal="-R",
                              token_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_nss_invalid_eku(self):
        """request with invalid EKU"""
        test_id = "req_eku_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal="-R",
                              eku_invalid=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    @pytest.mark.xfail(
        reason="Non-numeric key size causes certmonger to "
        "retry indefinitely. "
        "https://pagure.io/certmonger/issue/305"
    )
    def test_request_nss_invalid_keysize(self):
        """request with invalid key size"""
        test_id = "req_ks_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal="-R",
                              use_keysize=True,
                              keysize_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, KEYSIZE_VERIFY)

    def test_request_nss_positive_basic(self):
        """request with minimal valid parameters"""
        test_id = "req_pos_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_nss_positive_full(self):
        """request with all valid parameters and renewal"""
        test_id = "req_pos_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal="-R",
                              use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE storage tests --

    def test_request_file_invalid_keyfile_basic(self):
        """request with invalid key file path, no extra args"""
        test_id = "req_fk_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id, [], key_invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_full(self):
        """request with invalid key file path and full args"""
        test_id = "req_fk_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, renewal="-R",
                    pin_mode='file',
                    use_keysize=True),
                key_invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_certfile_basic(self):
        """request with invalid cert file path, no extra args"""
        test_id = "req_fc_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id, [], cert_invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_full(self):
        """request with invalid cert file path and full args"""
        test_id = "req_fc_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, renewal="-R",
                    pin_mode='file',
                    use_keysize=True),
                cert_invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_positive_basic(self):
        """request with valid FILE storage, minimal args"""
        test_id = "req_fp_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    @pytest.mark.parametrize("pin_mode", ['inline', 'file'])
    def test_request_file_invalid_eku(self, pin_mode):
        """request with invalid EKU in FILE mode"""
        test_id = "req_fe_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(
                               test_id, renewal="-R",
                               pin_mode=pin_mode,
                               eku_invalid=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_invalid_keysize_fallback(self):
        """invalid key size falls back to RSA:2048 in FILE mode

        certmonger ignores the non-numeric key size and falls
        back to the default key type and size (RSA:2048).
        https://pagure.io/certmonger/issue/305
        """
        test_id = "req_fks_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        keyfile = os.path.join(
            self.file_dir, '%s.key.pem' % test_id)
        certfile = os.path.join(
            self.file_dir, '%s.cert.pem' % test_id)
        cmd = self.master.run_command([
            'ipa-getcert', 'request', '-w', '-v',
            '-k', keyfile, '-f', certfile,
            '-g', 'shouldBEnumber%s' % test_id,
        ], raiseonerr=False)
        try:
            assert cmd.returncode == 0, (
                "Expected request to succeed with fallback "
                "key size, got rc=%d" % cmd.returncode)
            result = self.master.run_command(
                ['openssl', 'pkey', '-in', keyfile,
                 '-text', '-noout']
            )
            assert '2048' in result.stdout_text
        finally:
            clean_requests(self.master)

    def test_request_file_invalid_pinfile(self):
        """request with non-existent PIN file"""
        test_id = "req_fpf_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(
                               test_id, renewal="-R",
                               pin_mode='file',
                               pinfile_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    @pytest.mark.parametrize("pin_mode", ['inline', 'file'])
    def test_request_file_positive_full(self, pin_mode):
        """request with all valid FILE storage parameters"""
        test_id = "req_fp_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id,
                         need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(
                               test_id, renewal="-R",
                               pin_mode=pin_mode,
                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- Extended request tests --

    @pytest.fixture
    def nssdb_tmpdir(self):
        """Create a temp NSS DB dir and clean up after test."""
        tmpdir = create_file_dir(self.master)
        yield tmpdir
        self.master.run_command(
            ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
             '-n', 'certtest'], raiseonerr=False
        )
        self.master.run_command(
            ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_with_correct_pin(self, nssdb_tmpdir):
        """request using NSS database with correct PIN"""
        create_nss_db_with_pin(self.master, nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'request', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-P', 'temp123#', '-I', 'testing'
        ])
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'pin set' in cmd.stdout_text

    def test_request_ext_with_password_file(self,
                                            nssdb_tmpdir):
        """request using NSS database with password file"""
        create_nss_db_with_pin(self.master, nssdb_tmpdir)
        passwd_file = os.path.join(
            nssdb_tmpdir, 'passwd.txt')
        self.master.run_command([
            'ipa-getcert', 'request', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-p', passwd_file, '-I', 'testing'
        ])
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'passwd.txt' in cmd.stdout_text

    def test_request_ext_empty_or_incorrect_pin(
            self, nssdb_tmpdir):
        """request using NSS db with incorrect PIN"""
        create_nss_db_with_pin(self.master, nssdb_tmpdir)
        cmd = self.master.run_command([
            'ipa-getcert', 'request', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-I', 'testing', '-P', 'wrong'
        ], raiseonerr=False)
        assert cmd.returncode != 0, (
            "Expected non-zero exit with wrong PIN")
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN' in (
            result.stdout_text)

    def test_request_ext_incorrect_password_file(
            self, nssdb_tmpdir):
        """request using NSS db with incorrect password"""
        create_nss_db_with_pin(self.master, nssdb_tmpdir)
        passwd_file = os.path.join(
            nssdb_tmpdir, 'passwd.txt')
        self.master.put_file_contents(
            passwd_file, 'temp123\n'
        )
        cmd = self.master.run_command([
            'ipa-getcert', 'request', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-I', 'testing', '-p', passwd_file
        ], raiseonerr=False)
        assert cmd.returncode != 0, (
            "Expected non-zero exit with wrong password")
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN' in (
            result.stdout_text)

    def test_request_ext_empty_request_name(self,
                                            nssdb_tmpdir):
        """request with empty request name shows usage"""
        cmd = self.master.run_command(
            'ipa-getcert request -d %s -n certtest -I 2>&1'
            % nssdb_tmpdir, raiseonerr=False
        )
        assert cmd.returncode == 1
        assert 'Usage: ipa-getcert request' in (
            cmd.stdout_text + cmd.stderr_text)

    def test_request_ext_nonexistent_token(self,
                                           nssdb_tmpdir):
        """request with non-existent token"""
        cmd = self.master.run_command([
            'ipa-getcert', 'request', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-I', 'testing', '-t', 'non-existent'
        ], raiseonerr=False)
        assert cmd.returncode != 0, (
            "Expected non-zero exit with bad token")
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN' in (
            result.stdout_text)


class TestGetcertStartTracking(GetcertTestMixin,
                               IntegrationTest):
    """Tests for ipa-getcert start-tracking command."""

    num_replicas = 0
    num_clients = 0
    topology = 'line'
    getcert_command = 'start-tracking'
    id_prefix = 'TrackReq'

    @classmethod
    def install(cls, mh):
        super(TestGetcertStartTracking, cls).install(mh)
        cls.cert_subject = get_cert_subject_base(cls.master)
        cls.fqdn = cls.master.hostname
        cls.realm = cls.master.domain.realm
        cls.file_dir = create_file_dir(cls.master)
        clean_requests(cls.master)

    def _nss_cmd(self, test_id, extra_args):
        """Build start-tracking with NSS storage."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'start-tracking',
                '-d', NSSDB_VALID, '-n', nickname,
                '-t', TOKEN_VALID] + extra_args

    def _nss_invalid_cmd(self, test_id, extra_args):
        """Build start-tracking with invalid NSSDBDIR."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'start-tracking',
                '-d', NSSDB_INVALID, '-n', nickname,
                '-t', TOKEN_VALID] + extra_args

    def _nss_token_invalid_cmd(self, test_id, extra_args):
        """Build start-tracking with invalid CertTokenName."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'start-tracking',
                '-d', NSSDB_VALID, '-n', nickname,
                '-t', ' NoSuchToken%s' % test_id
                ] + extra_args

    def _tracking_args(self, test_id, renewal='-R',
                       principal_invalid=False,
                       eku_invalid=False):
        """Build -I -U -K -D -E -R/-r arguments."""
        args = ['-I', 'TrackReq_%s' % test_id]
        if eku_invalid:
            args += ['-U', 'in.valid.ext.usage.%s'
                     % test_id]
        else:
            args += ['-U', EKU_VALID]
        if principal_invalid:
            args += ['-K', 'NoSuchPrincipal%s' % test_id]
        else:
            args += ['-K', '%s/%s@%s'
                     % (test_id, self.fqdn, self.realm)]
        args += ['-D', self.fqdn, '-E', EMAIL_VALID]
        args.append(renewal)
        return args

    def _req_nick_cmd(self, test_id, extra_args,
                      invalid=False):
        """Build start-tracking with -i (request id)."""
        if invalid:
            nick = "ReqDoesNotExist_%s" % test_id
        else:
            nick = test_id
        return ['ipa-getcert', 'start-tracking',
                '-i', nick] + extra_args

    # -- NSS NSSDBDIR tests --

    def test_start_tracking_nss_invalid_nssdbdir_basic(
            self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_invalid_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_nss_invalid_nssdbdir_full(
            self, renewal):
        """start-tracking with invalid NSSDBDIR and args"""
        test_id = "st_nssdb_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_invalid_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal)),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    # -- NSS CertTokenName tests --

    def test_start_tracking_nss_invalid_token_basic(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_004_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_token_invalid_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_nss_invalid_token_full(
            self, renewal):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_tok_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_token_invalid_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    # -- NSS positive and EKU/principal tests --

    def test_start_tracking_nss_positive_basic(self):
        """start-tracking with options d n t - all positive"""
        test_id = "st_007_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_nss_invalid_eku(
            self, renewal):
        """start-tracking with invalid EXTUSAGE"""
        test_id = "st_eku_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal,
                    eku_invalid=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_nss_invalid_principal(
            self, renewal):
        """start-tracking with invalid CertPrincipalName"""
        test_id = "st_pri_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal,
                    principal_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_nss_positive_full(
            self, renewal):
        """start-tracking all positive"""
        test_id = "st_pos_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- Request identifier (-i) tests --

    def test_start_tracking_id_invalid_nickname_basic(
            self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_014_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id, [],
                               invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found', 'not allowed',
            'None of database directory',
        ])

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_id_invalid_nickname_full(
            self, renewal):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_idn_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal),
                invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found', 'not allowed',
            'None of database directory',
        ])

    def test_start_tracking_id_positive_basic(self):
        """start-tracking -i all positive"""
        test_id = "st_017_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_id_invalid_eku(
            self, renewal):
        """start-tracking -i with invalid EXTUSAGE"""
        test_id = "st_ide_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            self._req_nick_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal,
                    eku_invalid=True)),
            raiseonerr=False
        )
        try:
            assert cmd.returncode == 1
            combined = cmd.stdout_text + cmd.stderr_text
            assert any(
                m in combined for m in EKU_ERR_MSGS
            ), ("Expected one of %r in: %s"
                % (EKU_ERR_MSGS, combined))
        finally:
            clean_requests(self.master)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_id_invalid_principal(
            self, renewal):
        """start-tracking -i with invalid principal"""
        test_id = "st_idp_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            self._req_nick_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal,
                    principal_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_id_positive_full(
            self, renewal):
        """start-tracking -i all positive"""
        test_id = "st_idf_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            self._req_nick_cmd(
                test_id,
                self._tracking_args(
                    test_id, renewal=renewal)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE key-file invalid tests --

    @pytest.mark.parametrize(
        "pin_mode,renewal",
        [(None, '-R'), (None, '-r'),
         ('inline', '-R'), ('inline', '-r'),
         ('file', '-R'), ('file', '-r')])
    def test_start_tracking_file_invalid_keyfile(
            self, pin_mode, renewal):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_kf_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False,
                         need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, pin_mode=pin_mode,
                    renewal=renewal),
                key_invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    # -- FILE cert-file invalid tests --

    @pytest.mark.parametrize(
        "pin_mode,renewal",
        [(None, '-R'), (None, '-r'),
         ('inline', '-R'), ('inline', '-r'),
         ('file', '-R'), ('file', '-r')])
    def test_start_tracking_file_invalid_certfile(
            self, pin_mode, renewal):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_cf_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False,
                         need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, pin_mode=pin_mode,
                    renewal=renewal),
                cert_invalid=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    # -- FILE positive + full args tests --

    def test_start_tracking_file_positive_basic(self):
        """start-tracking -k -f all positive"""
        test_id = "st_042_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    @pytest.mark.parametrize(
        "pin_mode,renewal",
        [(None, '-R'), (None, '-r'),
         ('inline', '-R'), ('inline', '-r'),
         ('file', '-R'), ('file', '-r')])
    def test_start_tracking_file_invalid_eku(
            self, pin_mode, renewal):
        """start-tracking FILE with invalid EXTUSAGE"""
        test_id = "st_fek_%s" % uuid.uuid4().hex[:8]
        self._setup_file(
            test_id,
            need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, pin_mode=pin_mode,
                    renewal=renewal,
                    eku_invalid=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    @pytest.mark.parametrize(
        "pin_mode,renewal",
        [(None, '-R'), (None, '-r'),
         ('inline', '-R'), ('inline', '-r'),
         ('file', '-R'), ('file', '-r')])
    def test_start_tracking_file_invalid_principal(
            self, pin_mode, renewal):
        """start-tracking FILE invalid CertPrincipalName"""
        test_id = "st_fpr_%s" % uuid.uuid4().hex[:8]
        self._setup_file(
            test_id,
            need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, pin_mode=pin_mode,
                    renewal=renewal,
                    principal_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    @pytest.mark.parametrize(
        "pin_mode,renewal",
        [(None, '-R'), (None, '-r'),
         ('inline', '-R'), ('inline', '-r'),
         ('file', '-R'), ('file', '-r')])
    def test_start_tracking_file_positive_full(
            self, pin_mode, renewal):
        """start-tracking FILE all positive"""
        test_id = "st_fpo_%s" % uuid.uuid4().hex[:8]
        self._setup_file(
            test_id,
            need_pin=(pin_mode == 'file'))
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, pin_mode=pin_mode,
                    renewal=renewal)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE pinfile invalid tests --

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_start_tracking_file_invalid_pinfile(
            self, renewal):
        """start-tracking with invalid PINFILE"""
        test_id = "st_fpn_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(
                test_id,
                self._file_extra_args(
                    test_id, pin_mode='file',
                    renewal=renewal,
                    pinfile_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    # -- Extended start-tracking tests --

    @pytest.fixture
    def nssdb_tmpdir(self):
        """Create a temp NSS DB dir and clean up."""
        tmpdir = create_file_dir(self.master)
        yield tmpdir
        self.master.run_command(
            ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
             '-n', 'certtest'], raiseonerr=False
        )
        self.master.run_command(
            ['rm', '-rf', tmpdir], raiseonerr=False)

    def _setup_tracking_with_password(self, tmpdir,
                                      pin="temp123#"):
        """Request cert, set NSS DB password, resubmit with
        wrong PIN to get into NEED_CSR_GEN_PIN state.
        """
        request_nss_cert_with_password(
            self.master, tmpdir, pin)
        cmd = self.master.run_command([
            'ipa-getcert', 'resubmit', '-w', '-v',
            '-d', tmpdir, '-n', 'certtest',
            '-P', 'temp123'
        ], raiseonerr=False)
        assert cmd.returncode == 4, (
            "Expected resubmit with wrong PIN to exit 4 "
            "(stuck), got rc=%d" % cmd.returncode)
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text, (
            "Expected NEED_CSR_GEN_PIN state after "
            "resubmit with wrong PIN")

    def test_start_tracking_ext_correct_pin(
            self, nssdb_tmpdir):
        """start-tracking with correct PIN"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-P', 'temp123#'
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'pin set' in result.stdout_text
        assert 'track: yes' in result.stdout_text

    def test_start_tracking_ext_incorrect_pin(
            self, nssdb_tmpdir):
        """start-tracking with incorrect PIN"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-P', 'temp123'
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text

    def test_start_tracking_ext_correct_password_file(
            self, nssdb_tmpdir):
        """start-tracking with correct password file"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        passwd_file = os.path.join(
            nssdb_tmpdir, 'passwd.txt')
        self.master.put_file_contents(
            passwd_file, 'temp123#\n')
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-p', passwd_file
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'pinfile=' in result.stdout_text
        assert 'track: yes' in result.stdout_text

    def test_start_tracking_ext_wrong_pin_in_file(
            self, nssdb_tmpdir):
        """start-tracking with wrong PIN in password file"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        passwd_file = os.path.join(
            nssdb_tmpdir, 'passwd.txt')
        self.master.put_file_contents(
            passwd_file, 'temp123#@\n')
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-p', passwd_file
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text

    def test_start_tracking_ext_incorrect_pin_file(
            self, nssdb_tmpdir):
        """start-tracking with non-existent PIN file"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-d', nssdb_tmpdir, '-n', 'certtest',
            '-p', os.path.join(
                nssdb_tmpdir, 'non-existentfile.txt')
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text

    def test_start_tracking_ext_correct_pin_by_id(
            self, nssdb_tmpdir):
        """start-tracking with correct PIN using request id"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-i', 'testing', '-P', 'temp123#'
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'pin set' in result.stdout_text
        assert 'track: yes' in result.stdout_text

    def test_start_tracking_ext_incorrect_pin_by_id(
            self, nssdb_tmpdir):
        """start-tracking with incorrect PIN using request id"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-i', 'testing', '-P', 'temp123'
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text

    def test_start_tracking_ext_correct_pwfile_by_id(
            self, nssdb_tmpdir):
        """start-tracking with correct password file by id"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        passwd_file = os.path.join(
            nssdb_tmpdir, 'passwd.txt')
        self.master.put_file_contents(
            passwd_file, 'temp123#\n')
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-i', 'testing', '-p', passwd_file
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'pinfile=' in result.stdout_text
        assert 'track: yes' in result.stdout_text

    def test_start_tracking_ext_bad_pin_file_by_id(
            self, nssdb_tmpdir):
        """start-tracking with non-existent PIN file by id"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-i', 'testing',
            '-p', os.path.join(
                nssdb_tmpdir, 'non-existentfile.txt')
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text

    def test_start_tracking_ext_wrong_pin_file_by_id(
            self, nssdb_tmpdir):
        """start-tracking with wrong PIN in file by id"""
        self._setup_tracking_with_password(nssdb_tmpdir)
        passwd_file = os.path.join(
            nssdb_tmpdir, 'passwd.txt')
        self.master.put_file_contents(
            passwd_file, 'temp123\n')
        self.master.run_command([
            'ipa-getcert', 'start-tracking', '-w', '-v',
            '-i', 'testing', '-p', passwd_file
        ])
        result = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'testing']
        )
        assert 'NEED_CSR_GEN_PIN' in result.stdout_text
