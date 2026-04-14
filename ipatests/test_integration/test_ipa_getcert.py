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

PRINCIPAL_VERIFY = ['CA_UNREACHABLE', 'CA_UNCONFIGURED', 'NEED_KEY_PAIR']

KEYSIZE_VERIFY = ['NEED_KEY_PAIR', 'CA_UNREACHABLE']

PINFILE_VERIFY = ['NEWLY_ADDED_NEED_KEYINFO_READ_PIN']

FILE_PRINCIPAL_VERIFY = [
    'CA_UNREACHABLE', 'CA_UNCONFIGURED',
    'NEED_KEY_PAIR', 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN',
]

FILE_KEYSIZE_VERIFY = [
    'NEED_KEY_PAIR', 'CA_UNREACHABLE',
    'NEWLY_ADDED_NEED_KEYINFO_READ_PIN',
]

NSSDB_VALID = "/etc/pki/nssdb"
NSSDB_INVALID = "/etc/pki/nssdb/cert8.db"
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
        match = re.search(
            r'New .* (?:signing|tracking|) ?request "([^"]+)" added',
            cmd.stdout_text
        )
        if match:
            status = tasks.wait_for_request(
                self.master, match.group(1), 120
            )
            assert status in expected_statuses, (
                "Expected status in %r, got %s"
                % (expected_statuses, status))
        clean_requests(self.master)

    def _assert_positive(self, cmd):
        """Assert positive test: rc=0, cleanup."""
        assert cmd.returncode == 0
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

    def _file_extra_args(self, test_id, pin_mode=None,
                         renewal='-R', use_keysize=False,
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
        if use_keysize:
            if keysize_invalid:
                args += ['-g', 'shouldBEnumber%s' % test_id]
            else:
                args += ['-g', '2048']
        else:
            args += ['-I', '%s_%s' % (self.id_prefix, test_id)]
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

    def _full_nss_args(self, test_id, renewal='-R',
                       use_keysize=False,
                       principal_invalid=False,
                       eku_invalid=False,
                       token_invalid=False,
                       keysize_invalid=False):
        """Build the -h -I/-g -R/-r -N -K -U -D -E arguments."""
        args = []
        if token_invalid:
            args += ['-h', ' NoSuchToken%s' % test_id]
        else:
            args += ['-h', TOKEN_VALID]
        if use_keysize:
            if keysize_invalid:
                args += ['-g', 'shouldBEnumber%s' % test_id]
            else:
                args += ['-g', '2048']
        else:
            args += ['-I', 'CertReq_%s' % test_id]
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

    @pytest.mark.parametrize("renewal,use_keysize", [
        (None, False),
        ("-R", False),
        ("-r", False),
        ("-R", True),
        ("-r", True),
    ])
    def test_request_nss_invalid_nssdbdir(self, renewal,
                                          use_keysize):
        """request with invalid NSSDBDIR"""
        test_id = "req_nssdb_%s" % uuid.uuid4().hex[:8]
        extra = (self._full_nss_args(
            test_id, renewal=renewal,
            use_keysize=use_keysize) if renewal else [])
        cmd = self.master.run_command(
            self._nss_invalid_cmd(test_id, extra),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    @pytest.mark.parametrize("renewal,use_keysize", [
        ("-R", False),
        ("-r", False),
        ("-R", True),
        ("-r", True),
    ])
    def test_request_nss_invalid_token(self, renewal,
                                       use_keysize):
        """request with invalid token"""
        test_id = "req_tok_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal=renewal,
                              use_keysize=use_keysize,
                              token_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    @pytest.mark.parametrize("renewal,use_keysize", [
        ("-R", False),
        ("-r", False),
        ("-R", True),
        ("-r", True),
    ])
    def test_request_nss_invalid_principal(self, renewal,
                                           use_keysize):
        """request with invalid principal"""
        test_id = "req_princ_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal=renewal,
                              use_keysize=use_keysize,
                              principal_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    @pytest.mark.parametrize("renewal,use_keysize", [
        ("-R", False),
        ("-r", False),
        ("-R", True),
        ("-r", True),
    ])
    def test_request_nss_invalid_eku(self, renewal,
                                     use_keysize):
        """request with invalid EKU"""
        test_id = "req_eku_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal=renewal,
                              use_keysize=use_keysize,
                              eku_invalid=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    @pytest.mark.parametrize("renewal", ["-R", "-r"])
    def test_request_nss_invalid_keysize(self, renewal):
        """request with invalid key size"""
        test_id = "req_ks_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(
                              test_id, renewal=renewal,
                              use_keysize=True,
                              keysize_invalid=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, KEYSIZE_VERIFY)

    @pytest.mark.parametrize("renewal,use_keysize", [
        (None, False),
        ("-R", False),
        ("-r", False),
        ("-R", True),
        ("-r", True),
    ])
    def test_request_nss_positive(self, renewal,
                                  use_keysize):
        """request with all valid parameters"""
        test_id = "req_pos_%s" % uuid.uuid4().hex[:8]
        if renewal is None:
            cmd = self.master.run_command(
                self._nss_cmd(test_id, []),
                raiseonerr=False
            )
        else:
            cmd = self.master.run_command(
                self._nss_cmd(test_id,
                              self._full_nss_args(
                                  test_id, renewal=renewal,
                                  use_keysize=use_keysize)),
                raiseonerr=False
            )
        self._assert_positive(cmd)
