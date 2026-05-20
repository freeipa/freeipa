"""Module provides tests for ipa-getcert CLI operations."""

import os
import re
import time
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


def check_request(host):
    """Check if any certmonger requests exist."""
    cmd = host.run_command(
        ['ls', paths.CERTMONGER_REQUESTS_DIR], raiseonerr=False
    )
    return cmd.stdout_text.strip()


def create_file_dir(host):
    """Create a temp directory with cert_t SELinux context."""
    tmpdir = host.run_command(['mktemp', '-d']).stdout_text.strip()
    host.run_command(['chcon', '-t', 'cert_t', tmpdir])
    return tmpdir


def prepare_file_keyfile(host, file_dir, test_id):
    """Generate an RSA key in file_dir."""
    keyfile = os.path.join(file_dir, '%s.key.pem' % test_id)
    host.run_command([
        'openssl', 'genpkey', '-algorithm', 'RSA', '-out', keyfile
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
    host.run_command(
        'echo "random-pin-string-%s" > %s' % (test_id, pinfile)
    )
    return pinfile


def prepare_certrequest(host, test_id):
    """Create a cert request for subsequent tests."""
    nssdb = "/etc/pki/nssdb"
    host.run_command([
        'ipa-getcert', 'request', '-w', '-v',
        '-n', test_id, '-d', nssdb, '-I', test_id
    ])


def create_nss_db_with_pin(host, tmpdir, pin="temp123#"):
    """Create NSS DB with a password in tmpdir."""
    passwd_file = os.path.join(tmpdir, 'passwd.txt')
    host.run_command(
        'printf "%s\\n" > %s' % (pin, passwd_file)
    )
    host.run_command([
        'certutil', '-N', '-d', tmpdir, '-f', passwd_file,
    ])


def setup_nss_cert_with_password(host, tmpdir, pin="temp123#"):
    """Request cert in NSS DB, wait for MONITORING, set DB password."""
    oldpw = os.path.join(tmpdir, 'oldpasswd.txt')
    newpw = os.path.join(tmpdir, 'passwd.txt')
    host.run_command('echo "" > %s' % oldpw)
    host.run_command(
        'printf "%s\\n%s\\n" > %s' % (pin, pin, newpw)
    )
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

NSSDB_POS = "/etc/pki/nssdb"
NSSDB_NEG = "/etc/pki/nssdb/cert8.db"
EKU_POS = "1.3.6.1.5.5.7.3.1"
TOKEN_POS = "NSSCertificateDB"
EMAIL_POS = "testqa@redhat.com"


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
        if check_request(self.master):
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
        if check_request(self.master):
            clean_requests(self.master)

    def _assert_positive(self, cmd):
        """Assert positive test: rc=0, cleanup."""
        assert cmd.returncode == 0
        if check_request(self.master):
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

    def _file_cmd(self, test_id, extra_args, key_neg=False, cert_neg=False):
        """Build ipa-getcert command with FILE storage."""
        if key_neg:
            keyfile = os.path.join(
                '/root', test_id, 'no.such.pem.key.file.')
        else:
            keyfile = os.path.join(
                self.file_dir, '%s.key.pem' % test_id)
        if cert_neg:
            certfile = os.path.join(test_id, 'NoSuchFileCertFile')
        else:
            certfile = os.path.join(
                self.file_dir, '%s.cert.pem' % test_id)
        return ['ipa-getcert', self.getcert_command,
                '-k', keyfile, '-f', certfile] + extra_args

    def _file_extra_args(self, test_id, pin_mode=None,
                         renewal='-R', use_keysize=False,
                         principal_neg=False, eku_neg=False,
                         keysize_neg=False, pinfile_neg=False):
        """Build FILE storage extra arguments."""
        args = []
        if pin_mode == 'inline':
            args += ['-P', '%sjfkdlaj2920jgajfklda290' % test_id]
        elif pin_mode == 'file':
            if pinfile_neg:
                args += ['-p', os.path.join(
                    '/root', test_id, 'no.such.pin.file')]
            else:
                args += ['-p', os.path.join(
                    self.file_dir, '%s.pin' % test_id)]
        if use_keysize:
            if keysize_neg:
                args += ['-g', 'shouldBEnumber%s' % test_id]
            else:
                args += ['-g', '1024']
        else:
            args += ['-I', '%s_%s' % (self.id_prefix, test_id)]
        args.append(renewal)
        args += ['-N', self.cert_subject]
        if principal_neg:
            args += ['-K', 'NoSuchPrincipal%s' % test_id]
        else:
            args += ['-K', '%s/%s@%s'
                     % (test_id, self.fqdn, self.realm)]
        if eku_neg:
            args += ['-U', 'in.valid.ext.usage.%s' % test_id]
        else:
            args += ['-U', EKU_POS]
        args += ['-D', self.fqdn, '-E', EMAIL_POS]
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
        return ['ipa-getcert', 'request', '-d', NSSDB_POS,
                '-n', nickname] + extra_args

    def _nss_neg_cmd(self, test_id, extra_args):
        """Build ipa-getcert request command with invalid NSSDBDIR."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'request',
                '-d', NSSDB_NEG,
                '-n', nickname] + extra_args

    def _full_nss_args(self, test_id, renewal='-R', use_keysize=False,
                       principal_neg=False, eku_neg=False, token_neg=False,
                       keysize_neg=False):
        """Build the -t -I/-g -R/-r -N -K -U -D -E arguments."""
        args = []
        if token_neg:
            args += ['-t', ' NoSuchToken%s' % test_id]
        else:
            args += ['-t', TOKEN_POS]
        if use_keysize:
            if keysize_neg:
                args += ['-g', 'shouldBEnumber%s' % test_id]
            else:
                args += ['-g', '1024']
        else:
            args += ['-I', 'CertReq_%s' % test_id]
        args.append(renewal)
        args += ['-N', self.cert_subject]
        if principal_neg:
            args += ['-K', 'NoSuchPrincipal%s' % test_id]
        else:
            args += ['-K', '%s/%s@%s'
                     % (test_id, self.fqdn, self.realm)]
        if eku_neg:
            args += ['-U', 'in.valid.ext.usage.%s' % test_id]
        else:
            args += ['-U', EKU_POS]
        args += ['-D', self.fqdn, '-E', EMAIL_POS]
        return args

    def test_request_nss_invalid_nssdbdir_basic(self):
        """request with options d n with invalid NSSDBDIR"""
        test_id = "req_001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_invalid_nssdbdir_full_renewal(self):
        """request with options d n t I R N K U D E with invalid NSSDBDIR"""
        test_id = "req_002_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_invalid_nssdbdir_full_norenewal(self):
        """request with options d n t I r N K U D E with invalid NSSDBDIR"""
        test_id = "req_003_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_invalid_nssdbdir_keysize_renewal(self):
        """request with options d n t g R N K U D E with invalid NSSDBDIR"""
        test_id = "req_004_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-R",
                                                  use_keysize=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_invalid_nssdbdir_keysize_norenewal(self):
        """request with options d n t g r N K U D E with invalid NSSDBDIR"""
        test_id = "req_005_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-r",
                                                  use_keysize=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_nss_positive_basic(self):
        """request with options d n - all positive"""
        test_id = "req_006_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_nss_invalid_token_renewal(self):
        """request with invalid CertTokenName"""
        test_id = "req_007_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_nss_invalid_token_norenewal(self):
        """request with invalid CertTokenName"""
        test_id = "req_008_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_nss_invalid_token_keysize_renewal(self):
        """request with invalid CertTokenName"""
        test_id = "req_009_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_nss_invalid_token_keysize_norenewal(self):
        """request with invalid CertTokenName"""
        test_id = "req_010_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_nss_invalid_principal_renewal(self):
        """request with invalid CertPrincipalName"""
        test_id = "req_011_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_nss_invalid_eku_renewal(self):
        """request with invalid EXTUSAGE"""
        test_id = "req_012_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_nss_positive_full_renewal(self):
        """request all positive"""
        test_id = "req_013_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_nss_invalid_principal_norenewal(self):
        """request with invalid CertPrincipalName"""
        test_id = "req_014_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_nss_invalid_eku_norenewal(self):
        """request with invalid EXTUSAGE"""
        test_id = "req_015_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_nss_positive_full_norenewal(self):
        """request all positive"""
        test_id = "req_016_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_nss_invalid_keysize_renewal(self):
        """request with invalid CertKeySize"""
        test_id = "req_017_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, KEYSIZE_VERIFY)

    def test_request_nss_invalid_keysize_norenewal(self):
        """request with invalid CertKeySize"""
        test_id = "req_018_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, KEYSIZE_VERIFY)

    def test_request_nss_invalid_principal_keysize_renewal(self):
        """request with invalid CertPrincipalName"""
        test_id = "req_019_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_nss_invalid_eku_keysize_renewal(self):
        """request with invalid EXTUSAGE"""
        test_id = "req_020_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_nss_positive_keysize_renewal(self):
        """request all positive"""
        test_id = "req_021_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_nss_invalid_principal_keysize_norenewal(self):
        """request with invalid CertPrincipalName"""
        test_id = "req_022_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_nss_invalid_eku_keysize_norenewal(self):
        """request with invalid EXTUSAGE"""
        test_id = "req_023_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_nss_positive_keysize_norenewal(self):
        """request all positive"""
        test_id = "req_024_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE key-file negative tests 1027-1035 --

    def test_request_file_invalid_keyfile_basic(self):
        """request -k f with invalid FileKeyFile"""
        test_id = "req_025_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id, [], key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pin_renewal(self):
        """request -k f P I R with invalid FileKeyFile"""
        test_id = "req_026_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal="-R"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pin_norenewal(self):
        """request -k f P I r with invalid FileKeyFile"""
        test_id = "req_027_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal="-r"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pin_keysize_renewal(self):
        """request -k f P g R with invalid FileKeyFile"""
        test_id = "req_028_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 use_keysize=True,
                                                 renewal="-R"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pin_keysize_norenewal(self):
        """request -k f P g r with invalid FileKeyFile"""
        test_id = "req_029_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 use_keysize=True,
                                                 renewal="-r"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pinfile_renewal(self):
        """request -k f p I R with invalid FileKeyFile"""
        test_id = "req_030_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal="-R"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pinfile_norenewal(self):
        """request -k f p I r with invalid FileKeyFile"""
        test_id = "req_031_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal="-r"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pinfile_keysize_renewal(self):
        """request -k f p g R with invalid FileKeyFile"""
        test_id = "req_032_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 use_keysize=True,
                                                 renewal="-R"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_request_file_invalid_keyfile_pinfile_keysize_norenewal(self):
        """request -k f p g r with invalid FileKeyFile"""
        test_id = "req_033_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 use_keysize=True,
                                                 renewal="-r"),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    # -- FILE cert-file negative tests 1036-1044 --

    def test_request_file_invalid_certfile_basic(self):
        """request -k f with invalid FileCertFile"""
        test_id = "req_034_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id, [], cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pin_renewal(self):
        """request -k f P I R with invalid FileCertFile"""
        test_id = "req_035_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal="-R"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pin_norenewal(self):
        """request -k f P I r with invalid FileCertFile"""
        test_id = "req_036_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal="-r"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pin_keysize_renewal(self):
        """request -k f P g R with invalid FileCertFile"""
        test_id = "req_037_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 use_keysize=True,
                                                 renewal="-R"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pin_keysize_norenewal(self):
        """request -k f P g r with invalid FileCertFile"""
        test_id = "req_038_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 use_keysize=True,
                                                 renewal="-r"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pinfile_renewal(self):
        """request -k f p I R with invalid FileCertFile"""
        test_id = "req_039_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal="-R"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pinfile_norenewal(self):
        """request -k f p I r with invalid FileCertFile"""
        test_id = "req_040_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal="-r"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pinfile_keysize_renewal(self):
        """request -k f p g R with invalid FileCertFile"""
        test_id = "req_041_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 use_keysize=True,
                                                 renewal="-R"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_request_file_invalid_certfile_pinfile_keysize_norenewal(self):
        """request -k f p g r with invalid FileCertFile"""
        test_id = "req_042_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 use_keysize=True,
                                                 renewal="-r"),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    # -- FILE positive 1045 --

    def test_request_file_positive_basic(self):
        """request with options k f - all positive"""
        test_id = "req_043_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE with -P (inline PIN) 1048-1061 --

    def test_request_file_pin_invalid_principal_renewal(self):
        """FILE -P CertPrincipalName neg"""
        test_id = "req_044_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pin_invalid_eku_renewal(self):
        """FILE -P EXTUSAGE neg"""
        test_id = "req_045_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pin_positive_renewal(self):
        """FILE -P all positive"""
        test_id = "req_046_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_file_pin_invalid_principal_norenewal(self):
        """FILE -P CertPrincipalName neg"""
        test_id = "req_047_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pin_invalid_eku_norenewal(self):
        """FILE -P EXTUSAGE neg"""
        test_id = "req_048_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pin_positive_norenewal(self):
        """FILE -P all positive"""
        test_id = "req_049_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_file_pin_invalid_keysize_renewal(self):
        """FILE -P CertKeySize neg"""
        test_id = "req_050_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 use_keysize=True,
                                                 keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_KEYSIZE_VERIFY)

    def test_request_file_pin_invalid_keysize_norenewal(self):
        """FILE -P CertKeySize neg"""
        test_id = "req_051_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 use_keysize=True,
                                                 keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_KEYSIZE_VERIFY)

    def test_request_file_pin_invalid_principal_keysize_renewal(self):
        """FILE -P CertPrincipalName neg"""
        test_id = "req_052_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 use_keysize=True,
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pin_invalid_eku_keysize_renewal(self):
        """FILE -P EXTUSAGE neg"""
        test_id = "req_053_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 use_keysize=True,
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pin_positive_keysize_renewal(self):
        """FILE -P all positive"""
        test_id = "req_054_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_file_pin_invalid_principal_keysize_norenewal(self):
        """FILE -P CertPrincipalName neg"""
        test_id = "req_055_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 use_keysize=True,
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pin_invalid_eku_keysize_norenewal(self):
        """FILE -P EXTUSAGE neg"""
        test_id = "req_056_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 use_keysize=True,
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pin_positive_keysize_norenewal(self):
        """FILE -P all positive"""
        test_id = "req_057_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE PINFILE negative tests 1062-1065 --

    def test_request_file_invalid_pinfile_renewal(self):
        """request with invalid PINFILE - -p I R"""
        test_id = "req_058_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_request_file_invalid_pinfile_norenewal(self):
        """request with invalid PINFILE - -p I r"""
        test_id = "req_059_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_request_file_invalid_pinfile_keysize_renewal(self):
        """request with invalid PINFILE - -p g R"""
        test_id = "req_060_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 pinfile_neg=True,
                                                 use_keysize=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_request_file_invalid_pinfile_keysize_norenewal(self):
        """request with invalid PINFILE - -p g r"""
        test_id = "req_061_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 pinfile_neg=True,
                                                 use_keysize=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    # -- FILE with -p (PIN file) 1068-1081 --

    def test_request_file_pinfile_invalid_principal_renewal(self):
        """FILE -p CertPrincipalName neg"""
        test_id = "req_062_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pinfile_invalid_eku_renewal(self):
        """FILE -p EXTUSAGE neg"""
        test_id = "req_063_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pinfile_positive_renewal(self):
        """FILE -p all positive"""
        test_id = "req_064_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_file_pinfile_invalid_principal_norenewal(self):
        """FILE -p CertPrincipalName neg"""
        test_id = "req_065_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pinfile_invalid_eku_norenewal(self):
        """FILE -p EXTUSAGE neg"""
        test_id = "req_066_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pinfile_positive_norenewal(self):
        """FILE -p all positive"""
        test_id = "req_067_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_file_pinfile_invalid_keysize_renewal(self):
        """FILE -p CertKeySize neg"""
        test_id = "req_068_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 use_keysize=True,
                                                 keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_KEYSIZE_VERIFY)

    def test_request_file_pinfile_invalid_keysize_norenewal(self):
        """FILE -p CertKeySize neg"""
        test_id = "req_069_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 use_keysize=True,
                                                 keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_KEYSIZE_VERIFY)

    def test_request_file_pinfile_invalid_principal_keysize_renewal(self):
        """FILE -p CertPrincipalName neg"""
        test_id = "req_070_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 use_keysize=True,
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pinfile_invalid_eku_keysize_renewal(self):
        """FILE -p EXTUSAGE neg"""
        test_id = "req_071_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 use_keysize=True,
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pinfile_positive_keysize_renewal(self):
        """FILE -p all positive"""
        test_id = "req_072_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_file_pinfile_invalid_principal_keysize_norenewal(self):
        """FILE -p CertPrincipalName neg"""
        test_id = "req_073_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 use_keysize=True,
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_request_file_pinfile_invalid_eku_keysize_norenewal(self):
        """FILE -p EXTUSAGE neg"""
        test_id = "req_074_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 use_keysize=True,
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_file_pinfile_positive_keysize_norenewal(self):
        """FILE -p all positive"""
        test_id = "req_075_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- Extended request tests --

    def test_request_ext_with_correct_pin(self):
        """request using NSS database with correct PIN"""
        tmpdir = create_file_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v', '-d', tmpdir,
                '-n', 'certtest', '-P', 'temp123#', '-I', 'testing'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_with_password_file(self):
        """request using NSS database with password file"""
        tmpdir = create_file_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v', '-d', tmpdir,
                '-n', 'certtest', '-p', passwd_file,
                '-I', 'testing'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'passwd.txt' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_empty_or_incorrect_pin(self):
        """request using NSS db with empty or incorrect PIN"""
        tmpdir = create_file_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            self.master.run_command(
                'ipa-getcert request -w -v'
                ' -d %s -n certtest -I testing -P wrong'
                % tmpdir, raiseonerr=False
            )
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN' in (
                result.stdout_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_incorrect_password_file(self):
        """request using NSS db with incorrect password file"""
        tmpdir = create_file_dir(self.master)
        try:
            create_nss_db_with_pin(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest', '-I', 'testing',
                '-p', passwd_file
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN' in (
                result.stdout_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_empty_request_name(self):
        """request with empty request name should show usage"""
        tmpdir = create_file_dir(self.master)
        try:
            cmd = self.master.run_command(
                'ipa-getcert request -d %s -n certtest -I 2>&1'
                % tmpdir, raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert request' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_request_ext_nonexistent_token(self):
        """request with non-existent token"""
        tmpdir = create_file_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-I', 'testing', '-t', 'non-existent'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN' in (
                result.stdout_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)


class TestGetcertStartTracking(GetcertTestMixin, IntegrationTest):
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
                '-d', NSSDB_POS, '-n', nickname,
                '-t', TOKEN_POS] + extra_args

    def _nss_neg_cmd(self, test_id, extra_args):
        """Build start-tracking with invalid NSSDBDIR."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'start-tracking',
                '-d', NSSDB_NEG, '-n', nickname,
                '-t', TOKEN_POS] + extra_args

    def _nss_token_neg_cmd(self, test_id, extra_args):
        """Build start-tracking with invalid CertTokenName."""
        nickname = "GetcertTest-%s" % test_id
        return ['ipa-getcert', 'start-tracking',
                '-d', NSSDB_POS, '-n', nickname,
                '-t', ' NoSuchToken%s' % test_id] + extra_args

    def _tracking_args(self, test_id, renewal='-R', principal_neg=False,
                       eku_neg=False):
        """Build -I -U -K -D -E -R/-r arguments."""
        args = ['-I', 'TrackReq_%s' % test_id]
        if eku_neg:
            args += ['-U', 'in.valid.ext.usage.%s' % test_id]
        else:
            args += ['-U', EKU_POS]
        if principal_neg:
            args += ['-K', 'NoSuchPrincipal%s' % test_id]
        else:
            args += ['-K', '%s/%s@%s'
                     % (test_id, self.fqdn, self.realm)]
        args += ['-D', self.fqdn, '-E', EMAIL_POS]
        args.append(renewal)
        return args

    def _req_nick_cmd(self, test_id, extra_args, neg=False):
        """Build start-tracking with -i (request identifier)."""
        if neg:
            nick = "ReqDoesNotExist_%s" % test_id
        else:
            nick = test_id
        return ['ipa-getcert', 'start-tracking',
                '-i', nick] + extra_args

    def test_start_tracking_nss_invalid_nssdbdir_basic(self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_start_tracking_nss_invalid_nssdbdir_renewal(self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_002_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._tracking_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_start_tracking_nss_invalid_nssdbdir_norenewal(self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_003_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._tracking_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_start_tracking_nss_invalid_token_basic(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_004_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_token_neg_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found that matched arguments',
            'must be a directory', 'is not a directory',
        ])

    def test_start_tracking_nss_invalid_token_renewal(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_005_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_token_neg_cmd(test_id,
                                    self._tracking_args(test_id,
                                                        renewal="-R")),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found that matched arguments',
            'must be a directory', 'is not a directory',
        ])

    def test_start_tracking_nss_invalid_token_norenewal(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_006_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_token_neg_cmd(test_id,
                                    self._tracking_args(test_id,
                                                        renewal="-r")),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found that matched arguments',
            'must be a directory', 'is not a directory',
        ])

    def test_start_tracking_nss_positive_basic(self):
        """start-tracking with options d n t - all positive"""
        test_id = "st_007_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_nss_invalid_eku_renewal(self):
        """start-tracking with invalid EXTUSAGE"""
        test_id = "st_008_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-R",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_nss_invalid_eku_norenewal(self):
        """start-tracking with invalid EXTUSAGE"""
        test_id = "st_009_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-r",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_nss_invalid_principal_renewal(self):
        """start-tracking with invalid CertPrincipalName"""
        test_id = "st_010_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-R",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_nss_invalid_principal_norenewal(self):
        """start-tracking with invalid CertPrincipalName"""
        test_id = "st_011_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-r",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_nss_positive_full_renewal(self):
        """start-tracking all positive"""
        test_id = "st_012_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_nss_positive_full_norenewal(self):
        """start-tracking all positive"""
        test_id = "st_013_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- Request identifier (-i) tests 1016-1027 --

    def test_start_tracking_id_invalid_nickname_basic(self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_014_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id, [], neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found', 'not allowed',
            'None of database directory',
        ])

    def test_start_tracking_id_invalid_nickname_renewal(self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_015_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R"),
                               neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found', 'not allowed',
            'None of database directory',
        ])

    def test_start_tracking_id_invalid_nickname_norenewal(self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_016_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r"),
                               neg=True),
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

    def test_start_tracking_id_invalid_eku_renewal(self):
        """start-tracking -i with invalid EXTUSAGE"""
        test_id = "st_018_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R",
                                                   eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_id_invalid_eku_norenewal(self):
        """start-tracking -i with invalid EXTUSAGE"""
        test_id = "st_019_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r",
                                                   eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_id_invalid_principal_renewal(self):
        """start-tracking -i with invalid CertPrincipalName"""
        test_id = "st_020_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R",
                                                   principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_id_invalid_principal_norenewal(self):
        """start-tracking -i with invalid CertPrincipalName"""
        test_id = "st_021_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r",
                                                   principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_id_positive_full_renewal(self):
        """start-tracking -i all positive"""
        test_id = "st_022_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_id_positive_full_norenewal(self):
        """start-tracking -i all positive"""
        test_id = "st_023_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- FILE key-file negative 1028-1036 --

    def test_start_tracking_file_invalid_keyfile_basic(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_024_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_renewal_a(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_025_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_norenewal(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_026_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-r'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_pin_basic(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_027_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_pin_renewal(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_028_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_pin_norenewal(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_029_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_pinfile_basic(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_030_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_pinfile_renewal(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_031_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    def test_start_tracking_file_invalid_keyfile_pinfile_norenewal(self):
        """start-tracking with invalid FileKeyFile"""
        test_id = "st_032_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r'),
                           key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_KEY_ERR_MSGS)

    # -- FILE cert-file negative 1037-1045 --

    def test_start_tracking_file_invalid_certfile_basic(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_033_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_renewal_a(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_034_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_norenewal(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_035_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-r'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_pin_basic(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_036_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_pin_renewal(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_037_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_pin_norenewal(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_038_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_pinfile_basic(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_039_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_pinfile_renewal(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_040_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    def test_start_tracking_file_invalid_certfile_pinfile_norenewal(self):
        """start-tracking with invalid FileCertFile"""
        test_id = "st_041_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r'),
                           cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, FILE_CERT_ERR_MSGS)

    # -- FILE positive + full args 1046-1075 --

    def test_start_tracking_file_positive_basic(self):
        """start-tracking -k -f all positive"""
        test_id = "st_042_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_invalid_eku_renewal(self):
        """start-tracking FILE with invalid EXTUSAGE"""
        test_id = "st_043_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_file_invalid_eku_norenewal(self):
        """start-tracking FILE with invalid EXTUSAGE"""
        test_id = "st_044_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-r',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_file_invalid_principal_renewal(self):
        """start-tracking FILE with invalid CertPrincipalName"""
        test_id = "st_045_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_start_tracking_file_invalid_principal_norenewal(self):
        """start-tracking FILE with invalid CertPrincipalName"""
        test_id = "st_046_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-r',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_start_tracking_file_positive_full_renewal(self):
        """start-tracking FILE all positive"""
        test_id = "st_047_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_positive_full_norenewal(self):
        """start-tracking FILE all positive"""
        test_id = "st_048_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id, renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_pin_positive_basic(self):
        """start-tracking FILE -P all positive"""
        test_id = "st_049_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_pin_invalid_eku_renewal(self):
        """start-tracking FILE -P with invalid EXTUSAGE"""
        test_id = "st_050_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_file_pin_invalid_eku_norenewal(self):
        """start-tracking FILE -P with invalid EXTUSAGE"""
        test_id = "st_051_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_file_pin_invalid_principal_renewal(self):
        """start-tracking FILE -P with invalid CertPrincipalName"""
        test_id = "st_052_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_start_tracking_file_pin_invalid_principal_norenewal(self):
        """start-tracking FILE -P with invalid CertPrincipalName"""
        test_id = "st_053_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_start_tracking_file_pin_positive_renewal(self):
        """start-tracking FILE -P all positive"""
        test_id = "st_054_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_pin_positive_norenewal(self):
        """start-tracking FILE -P all positive"""
        test_id = "st_055_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='inline',
                                                 renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_invalid_pinfile_renewal_a(self):
        """start-tracking with invalid PINFILE"""
        test_id = "st_056_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_start_tracking_file_invalid_pinfile_renewal_b(self):
        """start-tracking with invalid PINFILE"""
        test_id = "st_057_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_start_tracking_file_invalid_pinfile_norenewal(self):
        """start-tracking with invalid PINFILE"""
        test_id = "st_058_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_start_tracking_file_pinfile_positive_basic(self):
        """start-tracking -k -f -p all positive"""
        test_id = "st_059_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_pinfile_invalid_eku_renewal(self):
        """start-tracking -p with invalid EXTUSAGE"""
        test_id = "st_060_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_file_pinfile_invalid_eku_norenewal(self):
        """start-tracking -p with invalid EXTUSAGE"""
        test_id = "st_061_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_file_pinfile_invalid_principal_renewal(self):
        """start-tracking -p with invalid CertPrincipalName"""
        test_id = "st_062_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_start_tracking_file_pinfile_invalid_principal_norenewal(self):
        """start-tracking -p with invalid CertPrincipalName"""
        test_id = "st_063_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r',
                                                 principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, FILE_PRINCIPAL_VERIFY)

    def test_start_tracking_file_pinfile_positive_renewal(self):
        """start-tracking -p all positive"""
        test_id = "st_064_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_file_pinfile_positive_norenewal(self):
        """start-tracking -p all positive"""
        test_id = "st_065_%s" % uuid.uuid4().hex[:8]
        self._setup_file(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._file_cmd(test_id,
                           self._file_extra_args(test_id,
                                                 pin_mode='file',
                                                 renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- Extended start-tracking tests --

    def _setup_tracking_with_password(self, tmpdir,
                                      pin="temp123#"):
        """Request cert, set NSS DB password, resubmit with
        wrong PIN to get into NEED_CSR_GEN_PIN state.
        """
        setup_nss_cert_with_password(self.master, tmpdir, pin)
        self.master.run_command([
            'ipa-getcert', 'resubmit', '-w', '-v',
            '-d', tmpdir, '-n', 'certtest', '-P', 'temp123'
        ])

    def test_start_tracking_ext_correct_pin(self):
        """start-tracking with correct PIN"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-P', 'temp123#'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in result.stdout_text
            assert 'track: yes' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin(self):
        """start-tracking with incorrect PIN"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-P', 'temp123'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_correct_password_file(self):
        """start-tracking with correct password file"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123#" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-p', passwd_file
            ])
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_wrong_pin_in_file(self):
        """start-tracking with wrong PIN in password file"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123#@" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-p', passwd_file
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin_file(self):
        """start-tracking with non-existent PIN file"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-p', os.path.join(
                    tmpdir, 'non-existentfile.txt')
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_correct_pin_by_id(self):
        """start-tracking with correct PIN using request id"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-i', 'testing', '-P', 'temp123#'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in result.stdout_text
            assert 'track: yes' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_incorrect_pin_by_id(self):
        """start-tracking with incorrect PIN using request id"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-i', 'testing', '-P', 'temp123'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_correct_pwfile_by_id(self):
        """start-tracking with correct password file by id"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123#" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-i', 'testing', '-p', passwd_file
            ])
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_bad_pin_file_by_id(self):
        """start-tracking with non-existent PIN file by id"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-i', 'testing',
                '-p', os.path.join(
                    tmpdir, 'non-existentfile.txt')
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_start_tracking_ext_wrong_pin_file_by_id(self):
        """start-tracking with wrong PIN in file by id"""
        tmpdir = create_file_dir(self.master)
        try:
            self._setup_tracking_with_password(tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'start-tracking', '-w', '-v',
                '-i', 'testing', '-p', passwd_file
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)


class TestGetcertOther(IntegrationTest):
    """Tests for stop-tracking, resubmit, list, and bugzilla regressions."""

    num_replicas = 0
    num_clients = 0
    topology = 'line'

    @classmethod
    def install(cls, mh):
        super(TestGetcertOther, cls).install(mh)
        cls.cert_subject = get_cert_subject_base(cls.master)
        cls.fqdn = cls.master.hostname
        cls.realm = cls.master.domain.realm
        cls.file_dir = create_file_dir(cls.master)
        clean_requests(cls.master)

    def test_stop_tracking_nss_invalid_nssdbdir(self):
        """stop-tracking with invalid NSSDBDIR"""
        test_id = "stop_001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-d', NSSDB_NEG, '-n', test_id],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in NSSDB_ERR_MSGS)

    def test_stop_tracking_nss_invalid_nickname(self):
        """stop-tracking with invalid CertNickName"""
        test_id = "stop_002_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-d', NSSDB_POS, '-n', 'NoSuchNick_%s' % test_id],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in [
            'No request found that matched arguments',
        ])

    def test_stop_tracking_nss_positive(self):
        """stop-tracking with options d n t - all positive"""
        test_id = "stop_003_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-d', NSSDB_POS, '-n', test_id,
             '-t', TOKEN_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_stop_tracking_id_invalid_nickname(self):
        """stop-tracking -i with invalid request nickname"""
        test_id = "stop_004_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-i', 'ReqDoesNotExist_%s' % test_id],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in [
            'No request found', 'None of database directory',
        ])

    def test_stop_tracking_id_positive(self):
        """stop-tracking -i all positive"""
        test_id = "stop_005_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking', '-i', test_id],
            raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_stop_tracking_file_invalid_keyfile(self):
        """stop-tracking with invalid FileKeyFile"""
        test_id = "stop_006_%s" % uuid.uuid4().hex[:8]
        prepare_file_certfile(self.master, self.file_dir, test_id)
        certfile = os.path.join(self.file_dir, '%s.cert.pem' % test_id)
        keyfile = os.path.join('/root', test_id, 'no.such.pem.key.file.')
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-k', keyfile, '-f', certfile],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in FILE_KEY_ERR_MSGS)

    def test_stop_tracking_file_invalid_certfile(self):
        """stop-tracking with invalid FileCertFile"""
        test_id = "stop_007_%s" % uuid.uuid4().hex[:8]
        prepare_file_keyfile(self.master, self.file_dir, test_id)
        keyfile = os.path.join(self.file_dir, '%s.key.pem' % test_id)
        certfile = os.path.join(test_id, 'NoSuchFileCertFile')
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-k', keyfile, '-f', certfile],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in FILE_CERT_ERR_MSGS)

    def test_stop_tracking_file_positive(self):
        """stop-tracking -k -f all positive"""
        test_id = "stop_008_%s" % uuid.uuid4().hex[:8]
        prepare_file_keyfile(self.master, self.file_dir, test_id)
        prepare_file_certfile(self.master, self.file_dir, test_id)
        keyfile = os.path.join(self.file_dir, '%s.key.pem' % test_id)
        certfile = os.path.join(self.file_dir, '%s.cert.pem' % test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-k', keyfile, '-f', certfile],
            raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_stop_tracking_by_nss_db_nickname(self):
        """stop-tracking with NSS db path and certificate nickname"""
        tmpdir = create_file_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest', '-I', 'testing'
            ])
            self.master.run_command([
                'ipa-getcert', 'stop-tracking',
                '-d', tmpdir, '-n', 'certtest'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list'])
            assert (
                'Number of certificates and requests'
                ' being tracked: 0' in cmd.stdout_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_stop_tracking_by_cert_key_files(self):
        """stop-tracking with certificate and key file path"""
        tmpdir = create_file_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'certtest')
            keypath = os.path.join(tmpdir, 'certtest.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-f', certpath, '-k', keypath,
                '-I', 'testing'
            ])
            self.master.run_command([
                'ipa-getcert', 'stop-tracking',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list'])
            assert (
                'Number of certificates and requests'
                ' being tracked: 0' in cmd.stdout_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_stop_tracking_with_token(self):
        """stop-tracking with NSS db path, nickname, and token"""
        tmpdir = create_file_dir(self.master)
        try:
            token = ("NSS FIPS 140-2 Certificate DB"
                     if self.master.is_fips_mode
                     else "NSS Certificate DB")
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-t', token, '-I', 'testing'
            ])
            self.master.run_command([
                'ipa-getcert', 'stop-tracking',
                '-d', tmpdir, '-n', 'certtest', '-t', token
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list'])
            assert (
                'Number of certificates and requests'
                ' being tracked: 0' in cmd.stdout_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_stop_tracking_invalid_token(self):
        """stop-tracking with invalid token name"""
        tmpdir = create_file_dir(self.master)
        try:
            cmd = self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest',
                 '-t', 'non-existent'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_nss_invalid_nssdbdir_a(self):
        """resubmit with invalid NSSDBDIR"""
        test_id = "resub_001_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-d', NSSDB_NEG, '-n', test_id,
             '-N', self.cert_subject,
             '-U', EKU_POS,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in NSSDB_ERR_MSGS)

    def test_resubmit_nss_invalid_nssdbdir_b(self):
        """resubmit with invalid NSSDBDIR"""
        test_id = "resub_002_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-d', NSSDB_NEG, '-n', test_id,
             '-N', self.cert_subject,
             '-U', EKU_POS,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in NSSDB_ERR_MSGS)

    def test_resubmit_nss_invalid_eku(self):
        """resubmit with invalid EXTUSAGE"""
        test_id = "resub_003_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-d', NSSDB_POS, '-n', test_id,
             '-N', self.cert_subject,
             '-U', 'in.valid.ext.usage.%s' % test_id,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in EKU_ERR_MSGS)

    def test_resubmit_nss_positive(self):
        """resubmit all positive"""
        test_id = "resub_004_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-d', NSSDB_POS, '-n', test_id,
             '-N', self.cert_subject,
             '-U', EKU_POS,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_resubmit_nss_invalid_eku_with_token_a(self):
        """resubmit with invalid EXTUSAGE"""
        test_id = "resub_005_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-d', NSSDB_POS, '-n', test_id,
             '-t', TOKEN_POS,
             '-N', self.cert_subject,
             '-U', 'in.valid.ext.usage.%s' % test_id,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in EKU_ERR_MSGS)

    def test_resubmit_nss_invalid_eku_with_token_b(self):
        """resubmit with invalid EXTUSAGE"""
        test_id = "resub_006_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-d', NSSDB_POS, '-n', test_id,
             '-t', TOKEN_POS,
             '-N', self.cert_subject,
             '-U', 'in.valid.ext.usage.%s' % test_id,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in EKU_ERR_MSGS)

    def test_resubmit_file_invalid_certfile(self):
        """resubmit -f with invalid FileCertFile"""
        test_id = "resub_007_%s" % uuid.uuid4().hex[:8]
        certfile = os.path.join(test_id, 'NoSuchFileCertFile')
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit', '-f', certfile,
             '-N', self.cert_subject,
             '-U', EKU_POS,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in FILE_CERT_ERR_MSGS)

    def test_resubmit_file_invalid_certfile_with_pin(self):
        """resubmit -f -P with invalid FileCertFile"""
        test_id = "resub_008_%s" % uuid.uuid4().hex[:8]
        certfile = os.path.join(test_id, 'NoSuchFileCertFile')
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit', '-f', certfile,
             '-P', '%sjfkdlaj2920' % test_id,
             '-N', self.cert_subject,
             '-U', EKU_POS,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in FILE_CERT_ERR_MSGS)

    @pytest.mark.parametrize(
        "test_num",
        [1016, 1020, 1022, 1028, 1029, 1033],
        ids=["resubmit_%d" % n
             for n in (1016, 1020, 1022, 1028, 1029, 1033)],
    )
    def test_resubmit_eku_negative_via_tracking_id(self, test_num):
        """resubmit with invalid EXTUSAGE via tracking request ID"""
        test_id = "resub_%d_%s" % (test_num, uuid.uuid4().hex[:8])
        cmd = self.master.run_command(
            ['ipa-getcert', 'resubmit',
             '-i', 'TracReq_%s' % test_id,
             '-N', self.cert_subject,
             '-U', 'in.valid.ext.usage.%s' % test_id,
             '-K', '%s/%s@%s' % (test_id, self.fqdn, self.realm),
             '-D', self.fqdn, '-E', EMAIL_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in EKU_ERR_MSGS)

    def test_resubmit_ext_correct_pin(self):
        """resubmit with correct PIN"""
        tmpdir = create_file_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-P', 'temp123#'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'pin set' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_incorrect_pin(self):
        """resubmit with incorrect PIN"""
        tmpdir = create_file_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-P', 'temp123'
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_correct_password_file(self):
        """resubmit with correct password file"""
        tmpdir = create_file_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123#" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-p', passwd_file
            ])
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_incorrect_password_file(self):
        """resubmit with non-existent password file"""
        tmpdir = create_file_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-p', os.path.join(
                    tmpdir, 'non-existentfile.txt')
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_incorrect_token(self):
        """resubmit with incorrect token name"""
        tmpdir = create_file_dir(self.master)
        try:
            token = ("NSS FIPS 140-2 Certificate DB"
                     if self.master.is_fips_mode
                     else "NSS Certificate DB")
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-t', token, '-I', 'testing'
            ])
            setup_nss_cert_with_password(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            cmd = self.master.run_command(
                ['ipa-getcert', 'resubmit', '-w', '-v',
                 '-d', tmpdir, '-n', 'certtest',
                 '-p', passwd_file, '-t', 'non-existent'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_resubmit_ext_wrong_pin_in_file(self):
        """resubmit with incorrect password in password file"""
        tmpdir = create_file_dir(self.master)
        try:
            setup_nss_cert_with_password(self.master, tmpdir)
            passwd_file = os.path.join(tmpdir, 'passwd.txt')
            self.master.run_command(
                'echo "temp123" > %s' % passwd_file
            )
            self.master.run_command([
                'ipa-getcert', 'resubmit', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-p', passwd_file
            ])
            result = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'NEED_CSR_GEN_PIN' in result.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-d', tmpdir, '-n', 'certtest'],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_no_options(self):
        """list with no options"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_with_r(self):
        """list with -r option"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-r'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_with_t(self):
        """list with -t option"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-t'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_cas_no_options(self):
        """list-cas with no options"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list-cas'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_by_system_bus(self):
        """list certificates by listening on System bus"""
        tmpdir = create_file_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-S']
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_by_nss_db_and_nickname(self):
        """list one cert on providing NSS db and nickname"""
        tmpdir = create_file_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list',
                 '-d', tmpdir, '-n', 'certtest']
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking', '-d', tmpdir,
                 '-n', 'certtest'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_by_file_storage(self):
        """list one cert on providing file storage path"""
        tmpdir = create_file_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-f', certpath]
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', certpath, '-k', keypath],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_by_request_identifier(self):
        """list one cert on providing request identifier"""
        tmpdir = create_file_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest', '-I', 'testing'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-i', 'testing']
            )
            assert 'MONITORING' in cmd.stdout_text
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-i', 'testing'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_nonexistent_request_identifier(self):
        """list with nonexistent request identifier"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-i', 'non-existent'],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        assert 'No request found' in (
            cmd.stdout_text + cmd.stderr_text)

    def test_list_nonexistent_file_path(self):
        """list with nonexistent file storage path"""
        tmpdir = create_file_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list', '-f',
                 os.path.join(tmpdir, 'non-existent.crt')],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', certpath, '-k', keypath],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_list_incorrect_nss_db(self):
        """list with incorrect NSS db and correct nickname"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list',
             '-d', '/tmp/non-existent', '-n', 'certtest'],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        assert 'No such file or directory' in (
            cmd.stdout_text + cmd.stderr_text)

    def test_list_incorrect_nickname(self):
        """list with correct NSS db and incorrect nickname"""
        tmpdir = create_file_dir(self.master)
        try:
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-d', tmpdir, '-n', 'certtest',
                '-I', 'testing'
            ])
            cmd = self.master.run_command(
                ['ipa-getcert', 'list',
                 '-d', tmpdir, '-n', 'non-existent'],
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'No request found' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-i', 'testing'], raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1103090_dbus_restart(self):
        """certmonger should not crash on D-Bus service restart

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1103090
        """
        self.master.run_command(
            ['systemctl', 'start', 'certmonger'],
            raiseonerr=False
        )
        self.master.run_command(
            ['systemctl', 'restart', 'dbus'])
        time.sleep(5)
        cmd = self.master.run_command(
            ['systemctl', 'is-active', 'certmonger'],
            raiseonerr=False
        )
        assert cmd.stdout_text.strip() == 'active'

    def test_bz1098208_request_invalid_f(self):
        """request with -F to invalid location should fail

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_file_dir(self.master)
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
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_request_empty_f(self):
        """request with empty -F should show usage

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_file_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            cmd = self.master.run_command(
                'ipa-getcert request -w -v '
                '-f %s -k %s -F 2>&1'
                % (certpath, keypath),
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert request' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_request_invalid_a(self):
        """request with -a to invalid NSS DB should fail

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_file_dir(self.master)
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
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_request_empty_a(self):
        """request with empty -a should show usage

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_file_dir(self.master)
        try:
            cmd = self.master.run_command(
                'ipa-getcert request -w -v '
                '-d %s -n test -a 2>&1' % tmpdir,
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert request' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_resubmit_invalid_f(self):
        """resubmit with -F to invalid location should fail

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_file_dir(self.master)
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
                 '-f', certpath, '-k', keypath],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)

    def test_bz1098208_resubmit_empty_f(self):
        """resubmit with empty -F should show usage

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1098208
        """
        tmpdir = create_file_dir(self.master)
        try:
            certpath = os.path.join(tmpdir, 'test.crt')
            keypath = os.path.join(tmpdir, 'test.key')
            self.master.run_command([
                'ipa-getcert', 'request', '-w', '-v',
                '-f', certpath, '-k', keypath
            ])
            cmd = self.master.run_command(
                'ipa-getcert resubmit -w -v '
                '-f %s -F 2>&1' % certpath,
                raiseonerr=False
            )
            assert cmd.returncode == 1
            assert 'Usage: ipa-getcert resubmit' in (
                cmd.stdout_text + cmd.stderr_text)
        finally:
            self.master.run_command(
                ['ipa-getcert', 'stop-tracking',
                 '-f', certpath, '-k', keypath],
                raiseonerr=False
            )
            self.master.run_command(
                ['rm', '-rf', tmpdir], raiseonerr=False)
