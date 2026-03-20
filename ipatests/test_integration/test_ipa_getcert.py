"""Module provides tests for ipa-getcert CLI operations."""

import os
import re
import time
import uuid

import pytest

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


def get_cert_subject(host):
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
    result = cmd.stdout_text.strip()
    if result:
        time.sleep(5)
    return result


def create_pem_dir(host):
    """Create a temp directory with cert_t SELinux context."""
    tmpdir = host.run_command(['mktemp', '-d']).stdout_text.strip()
    host.run_command(['chcon', '-t', 'cert_t', tmpdir])
    return tmpdir


def prepare_pem_keyfile(host, pem_dir, test_id):
    """Generate an RSA key in pem_dir."""
    keyfile = os.path.join(pem_dir, '%s.key.pem' % test_id)
    host.run_command([
        'openssl', 'genpkey', '-algorithm', 'RSA', '-out', keyfile
    ])
    return keyfile


def prepare_pem_certfile(host, pem_dir, test_id):
    """Create an empty cert file in pem_dir."""
    certfile = os.path.join(pem_dir, '%s.cert.pem' % test_id)
    host.run_command(['touch', certfile])
    return certfile


def prepare_pin(host, pem_dir, test_id):
    """Create a PIN file in pem_dir."""
    pinfile = os.path.join(pem_dir, '%s.pin' % test_id)
    host.run_command(
        'echo "random-pin-string-%s" > %s' % (test_id, pinfile)
    )
    return pinfile


def prepare_certrequest(host, test_id):
    """Create a cert request and start tracking for subsequent tests."""
    nssdb = "/etc/pki/nssdb"
    host.run_command([
        'ipa-getcert', 'request', '-n', test_id, '-d', nssdb
    ])
    host.run_command([
        'ipa-getcert', 'start-tracking',
        '-d', nssdb, '-n', test_id, '-I', test_id
    ])


def create_nss_db_with_pin(host, tmpdir, pin="temp123#"):
    """Create NSS DB with a password in tmpdir."""
    host.run_command(
        'echo "" > %s' % os.path.join(tmpdir, 'oldpasswd.txt')
    )
    host.run_command(
        'printf "%s\\n%s\\n" > %s'
        % (pin, pin, os.path.join(tmpdir, 'newpasswd.txt'))
    )
    host.run_command([
        'certutil', '-N', '-d', tmpdir,
        '-f', os.path.join(tmpdir, 'oldpasswd.txt'),
        '-@', os.path.join(tmpdir, 'newpasswd.txt'),
    ])


def setup_nss_cert_with_password(host, tmpdir, pin="temp123#"):
    """Request cert in NSS DB, wait for MONITORING, set DB password."""
    host.run_command(
        'echo "" > %s' % os.path.join(tmpdir, 'oldpasswd.txt')
    )
    host.run_command(
        'printf "%s\\n%s\\n" > %s'
        % (pin, pin, os.path.join(tmpdir, 'newpasswd.txt'))
    )
    host.run_command([
        'ipa-getcert', 'request', '-d', tmpdir,
        '-n', 'certtest', '-I', 'testing'
    ])
    tasks.wait_for_request(host, 'testing', 120)
    host.run_command([
        'certutil', '-W', '-d', tmpdir,
        '-f', os.path.join(tmpdir, 'oldpasswd.txt'),
        '-@', os.path.join(tmpdir, 'newpasswd.txt'),
    ])


NSSDB_ERR_MSGS = [
    'must be a directory',
    'is not a directory',
    'No such file or directory',
    'No request found that matched arguments',
]

PEMKEY_ERR_MSGS = [
    'is not a directory',
    'No such file or directory',
    'must be a valid directory',
    'No request found that matched arguments',
]

PEMCERT_ERR_MSGS = ['is not absolute']

EKU_ERR_MSGS = ['Could not evaluate OID']

TOKEN_VERIFY = ['NEED_KEY_PAIR', 'NEWLY_ADDED_NEED_KEYINFO_READ_TOKEN']

PRINCIPAL_VERIFY = ['CA_UNREACHABLE', 'CA_UNCONFIGURED', 'NEED_KEY_PAIR']

KEYSIZE_VERIFY = ['NEED_KEY_PAIR', 'CA_UNREACHABLE']

PINFILE_VERIFY = ['NEWLY_ADDED_NEED_KEYINFO_READ_PIN']

PEM_PRINCIPAL_VERIFY = [
    'CA_UNREACHABLE', 'CA_UNCONFIGURED',
    'NEED_KEY_PAIR', 'NEWLY_ADDED_NEED_KEYINFO_READ_PIN',
]

PEM_KEYSIZE_VERIFY = [
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

    def _setup_pem(self, test_id, need_key=True, need_cert=True,
                   need_pin=False):
        """Prepare PEM test artifacts."""
        if need_key:
            prepare_pem_keyfile(self.master, self.pem_dir, test_id)
        if need_cert:
            prepare_pem_certfile(self.master, self.pem_dir, test_id)
        if need_pin:
            prepare_pin(self.master, self.pem_dir, test_id)

    def _pem_cmd(self, test_id, extra_args, key_neg=False, cert_neg=False):
        """Build ipa-getcert command with PEM storage."""
        if key_neg:
            keyfile = os.path.join(
                '/root', test_id, 'no.such.pem.key.file.')
        else:
            keyfile = os.path.join(
                self.pem_dir, '%s.key.pem' % test_id)
        if cert_neg:
            certfile = os.path.join(test_id, 'NoSuchPemCertFile')
        else:
            certfile = os.path.join(
                self.pem_dir, '%s.cert.pem' % test_id)
        return ['ipa-getcert', self.getcert_command,
                '-k', keyfile, '-f', certfile] + extra_args

    def _pem_extra_args(self, test_id, pin_mode=None, renewal='-R',
                        use_keysize=False, principal_neg=False,
                        eku_neg=False, keysize_neg=False,
                        pinfile_neg=False):
        """Build PEM extra arguments."""
        args = []
        if pin_mode == 'inline':
            args += ['-P', '%sjfkdlaj2920jgajfklda290' % test_id]
        elif pin_mode == 'file':
            if pinfile_neg:
                args += ['-p', os.path.join(
                    '/root', test_id, 'no.such.pin.file')]
            else:
                args += ['-p', os.path.join(
                    self.pem_dir, '%s.pin' % test_id)]
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
    getcert_command = 'request'
    id_prefix = 'CertReq'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)
        cls.cert_subject = get_cert_subject(cls.master)
        cls.fqdn = cls.master.hostname
        cls.realm = cls.master.domain.realm
        cls.pem_dir = create_pem_dir(cls.master)
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

    # -- NSS tests 1001-1026 --

    def test_request_1001(self):
        """request with options d n with invalid NSSDBDIR"""
        test_id = "request_1001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_1002(self):
        """request with options d n t I R N K U D E with invalid NSSDBDIR"""
        test_id = "request_1002_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_1003(self):
        """request with options d n t I r N K U D E with invalid NSSDBDIR"""
        test_id = "request_1003_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_1004(self):
        """request with options d n t g R N K U D E with invalid NSSDBDIR"""
        test_id = "request_1004_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-R",
                                                  use_keysize=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_1005(self):
        """request with options d n t g r N K U D E with invalid NSSDBDIR"""
        test_id = "request_1005_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._full_nss_args(test_id, renewal="-r",
                                                  use_keysize=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_request_1006(self):
        """request with options d n - all positive"""
        test_id = "request_1006_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1007(self):
        """request with invalid CertTokenName"""
        test_id = "request_1007_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_1008(self):
        """request with invalid CertTokenName"""
        test_id = "request_1008_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_1009(self):
        """request with invalid CertTokenName"""
        test_id = "request_1009_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_1010(self):
        """request with invalid CertTokenName"""
        test_id = "request_1010_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              token_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, TOKEN_VERIFY)

    def test_request_1013(self):
        """request with invalid CertPrincipalName"""
        test_id = "request_1013_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_1014(self):
        """request with invalid EXTUSAGE"""
        test_id = "request_1014_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1015(self):
        """request all positive"""
        test_id = "request_1015_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1016(self):
        """request with invalid CertPrincipalName"""
        test_id = "request_1016_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_1017(self):
        """request with invalid EXTUSAGE"""
        test_id = "request_1017_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1018(self):
        """request all positive"""
        test_id = "request_1018_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1019(self):
        """request with invalid CertKeySize"""
        test_id = "request_1019_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, KEYSIZE_VERIFY)

    def test_request_1020(self):
        """request with invalid CertKeySize"""
        test_id = "request_1020_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, KEYSIZE_VERIFY)

    def test_request_1021(self):
        """request with invalid CertPrincipalName"""
        test_id = "request_1021_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_1022(self):
        """request with invalid EXTUSAGE"""
        test_id = "request_1022_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True,
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1023(self):
        """request all positive"""
        test_id = "request_1023_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-R",
                                              use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1024(self):
        """request with invalid CertPrincipalName"""
        test_id = "request_1024_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_request_1025(self):
        """request with invalid EXTUSAGE"""
        test_id = "request_1025_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True,
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1026(self):
        """request all positive"""
        test_id = "request_1026_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._full_nss_args(test_id, renewal="-r",
                                              use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- PEM key-file negative tests 1027-1035 --

    def test_request_1027(self):
        """request -k f with invalid PemKeyFile"""
        test_id = "request_1027_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id, [], key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1028(self):
        """request -k f P I R with invalid PemKeyFile"""
        test_id = "request_1028_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal="-R"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1029(self):
        """request -k f P I r with invalid PemKeyFile"""
        test_id = "request_1029_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal="-r"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1030(self):
        """request -k f P g R with invalid PemKeyFile"""
        test_id = "request_1030_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               use_keysize=True,
                                               renewal="-R"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1031(self):
        """request -k f P g r with invalid PemKeyFile"""
        test_id = "request_1031_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               use_keysize=True,
                                               renewal="-r"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1032(self):
        """request -k f p I R with invalid PemKeyFile"""
        test_id = "request_1032_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal="-R"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1033(self):
        """request -k f p I r with invalid PemKeyFile"""
        test_id = "request_1033_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal="-r"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1034(self):
        """request -k f p g R with invalid PemKeyFile"""
        test_id = "request_1034_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               use_keysize=True,
                                               renewal="-R"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_request_1035(self):
        """request -k f p g r with invalid PemKeyFile"""
        test_id = "request_1035_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_key=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               use_keysize=True,
                                               renewal="-r"),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    # -- PEM cert-file negative tests 1036-1044 --

    def test_request_1036(self):
        """request -k f with invalid PemCertFile"""
        test_id = "request_1036_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id, [], cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1037(self):
        """request -k f P I R with invalid PemCertFile"""
        test_id = "request_1037_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal="-R"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1038(self):
        """request -k f P I r with invalid PemCertFile"""
        test_id = "request_1038_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal="-r"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1039(self):
        """request -k f P g R with invalid PemCertFile"""
        test_id = "request_1039_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               use_keysize=True,
                                               renewal="-R"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1040(self):
        """request -k f P g r with invalid PemCertFile"""
        test_id = "request_1040_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               use_keysize=True,
                                               renewal="-r"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1041(self):
        """request -k f p I R with invalid PemCertFile"""
        test_id = "request_1041_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal="-R"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1042(self):
        """request -k f p I r with invalid PemCertFile"""
        test_id = "request_1042_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal="-r"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1043(self):
        """request -k f p g R with invalid PemCertFile"""
        test_id = "request_1043_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               use_keysize=True,
                                               renewal="-R"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_request_1044(self):
        """request -k f p g r with invalid PemCertFile"""
        test_id = "request_1044_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               use_keysize=True,
                                               renewal="-r"),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    # -- PEM positive 1045 --

    def test_request_1045(self):
        """request with options k f - all positive"""
        test_id = "request_1045_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- PEM with -P (inline PIN) 1048-1061 --

    def test_request_1048(self):
        """PEM -P CertPrincipalName neg"""
        test_id = "request_1048_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1049(self):
        """PEM -P EXTUSAGE neg"""
        test_id = "request_1049_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1050(self):
        """PEM -P all positive"""
        test_id = "request_1050_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1051(self):
        """PEM -P CertPrincipalName neg"""
        test_id = "request_1051_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1052(self):
        """PEM -P EXTUSAGE neg"""
        test_id = "request_1052_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1053(self):
        """PEM -P all positive"""
        test_id = "request_1053_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1054(self):
        """PEM -P CertKeySize neg"""
        test_id = "request_1054_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               use_keysize=True,
                                               keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_KEYSIZE_VERIFY)

    def test_request_1055(self):
        """PEM -P CertKeySize neg"""
        test_id = "request_1055_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               use_keysize=True,
                                               keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_KEYSIZE_VERIFY)

    def test_request_1056(self):
        """PEM -P CertPrincipalName neg"""
        test_id = "request_1056_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               use_keysize=True,
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1057(self):
        """PEM -P EXTUSAGE neg"""
        test_id = "request_1057_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               use_keysize=True,
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1058(self):
        """PEM -P all positive"""
        test_id = "request_1058_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1059(self):
        """PEM -P CertPrincipalName neg"""
        test_id = "request_1059_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               use_keysize=True,
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1060(self):
        """PEM -P EXTUSAGE neg"""
        test_id = "request_1060_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               use_keysize=True,
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1061(self):
        """PEM -P all positive"""
        test_id = "request_1061_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- PEM PINFILE negative tests 1062-1065 --

    def test_request_1062(self):
        """request with invalid PINFILE - -p I R"""
        test_id = "request_1062_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_request_1063(self):
        """request with invalid PINFILE - -p I r"""
        test_id = "request_1063_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_request_1064(self):
        """request with invalid PINFILE - -p g R"""
        test_id = "request_1064_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               pinfile_neg=True,
                                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_request_1065(self):
        """request with invalid PINFILE - -p g r"""
        test_id = "request_1065_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               pinfile_neg=True,
                                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    # -- PEM with -p (PIN file) 1068-1081 --

    def test_request_1068(self):
        """PEM -p CertPrincipalName neg"""
        test_id = "request_1068_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1069(self):
        """PEM -p EXTUSAGE neg"""
        test_id = "request_1069_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1070(self):
        """PEM -p all positive"""
        test_id = "request_1070_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1071(self):
        """PEM -p CertPrincipalName neg"""
        test_id = "request_1071_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1072(self):
        """PEM -p EXTUSAGE neg"""
        test_id = "request_1072_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1073(self):
        """PEM -p all positive"""
        test_id = "request_1073_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1074(self):
        """PEM -p CertKeySize neg"""
        test_id = "request_1074_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               use_keysize=True,
                                               keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_KEYSIZE_VERIFY)

    def test_request_1075(self):
        """PEM -p CertKeySize neg"""
        test_id = "request_1075_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               use_keysize=True,
                                               keysize_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_KEYSIZE_VERIFY)

    def test_request_1076(self):
        """PEM -p CertPrincipalName neg"""
        test_id = "request_1076_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               use_keysize=True,
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1077(self):
        """PEM -p EXTUSAGE neg"""
        test_id = "request_1077_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               use_keysize=True,
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1078(self):
        """PEM -p all positive"""
        test_id = "request_1078_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_request_1079(self):
        """PEM -p CertPrincipalName neg"""
        test_id = "request_1079_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               use_keysize=True,
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_request_1080(self):
        """PEM -p EXTUSAGE neg"""
        test_id = "request_1080_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               use_keysize=True,
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_request_1081(self):
        """PEM -p all positive"""
        test_id = "request_1081_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               use_keysize=True)),
            raiseonerr=False
        )
        self._assert_positive(cmd)


class TestGetcertStartTracking(GetcertTestMixin, IntegrationTest):
    """Tests for ipa-getcert start-tracking command."""

    num_replicas = 0
    num_clients = 0
    getcert_command = 'start-tracking'
    id_prefix = 'TrackReq'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)
        cls.cert_subject = get_cert_subject(cls.master)
        cls.fqdn = cls.master.hostname
        cls.realm = cls.master.domain.realm
        cls.pem_dir = create_pem_dir(cls.master)
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

    # -- NSS tests 1001-1015 --

    def test_start_tracking_1001(self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_1001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_start_tracking_1002(self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_1002_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._tracking_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_start_tracking_1003(self):
        """start-tracking with invalid NSSDBDIR"""
        test_id = "st_1003_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_neg_cmd(test_id,
                              self._tracking_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_negative(cmd, NSSDB_ERR_MSGS)

    def test_start_tracking_1004(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_1004_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_token_neg_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found that matched arguments',
            'must be a directory', 'is not a directory',
        ])

    def test_start_tracking_1005(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_1005_%s" % uuid.uuid4().hex[:8]
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

    def test_start_tracking_1006(self):
        """start-tracking with invalid CertTokenName"""
        test_id = "st_1006_%s" % uuid.uuid4().hex[:8]
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

    def test_start_tracking_1007(self):
        """start-tracking with options d n t - all positive"""
        test_id = "st_1007_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1010(self):
        """start-tracking with invalid EXTUSAGE"""
        test_id = "st_1010_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-R",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1011(self):
        """start-tracking with invalid EXTUSAGE"""
        test_id = "st_1011_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-r",
                                              eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1012(self):
        """start-tracking with invalid CertPrincipalName"""
        test_id = "st_1012_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-R",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_1013(self):
        """start-tracking with invalid CertPrincipalName"""
        test_id = "st_1013_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-r",
                                              principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_1014(self):
        """start-tracking all positive"""
        test_id = "st_1014_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1015(self):
        """start-tracking all positive"""
        test_id = "st_1015_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._nss_cmd(test_id,
                          self._tracking_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- Request identifier (-i) tests 1016-1027 --

    def test_start_tracking_1016(self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_1016_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id, [], neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, [
            'No request found', 'not allowed',
            'None of database directory',
        ])

    def test_start_tracking_1017(self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_1017_%s" % uuid.uuid4().hex[:8]
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

    def test_start_tracking_1018(self):
        """start-tracking -i with invalid request nickname"""
        test_id = "st_1018_%s" % uuid.uuid4().hex[:8]
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

    def test_start_tracking_1019(self):
        """start-tracking -i all positive"""
        test_id = "st_1019_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1022(self):
        """start-tracking -i with invalid EXTUSAGE"""
        test_id = "st_1022_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R",
                                                   eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1023(self):
        """start-tracking -i with invalid EXTUSAGE"""
        test_id = "st_1023_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r",
                                                   eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1024(self):
        """start-tracking -i with invalid CertPrincipalName"""
        test_id = "st_1024_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R",
                                                   principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_1025(self):
        """start-tracking -i with invalid CertPrincipalName"""
        test_id = "st_1025_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r",
                                                   principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PRINCIPAL_VERIFY)

    def test_start_tracking_1026(self):
        """start-tracking -i all positive"""
        test_id = "st_1026_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-R")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1027(self):
        """start-tracking -i all positive"""
        test_id = "st_1027_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            self._req_nick_cmd(test_id,
                               self._tracking_args(test_id, renewal="-r")),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    # -- PEM key-file negative 1028-1036 --

    def test_start_tracking_1028(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1028_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1029(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1029_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1030(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1030_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-r'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1031(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1031_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1032(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1032_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1033(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1033_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1034(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1034_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1035(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1035_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    def test_start_tracking_1036(self):
        """start-tracking with invalid PemKeyFile"""
        test_id = "st_1036_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r'),
                          key_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMKEY_ERR_MSGS)

    # -- PEM cert-file negative 1037-1045 --

    def test_start_tracking_1037(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1037_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1038(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1038_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1039(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1039_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-r'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1040(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1040_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1041(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1041_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1042(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1042_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1043(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1043_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1044(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1044_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    def test_start_tracking_1045(self):
        """start-tracking with invalid PemCertFile"""
        test_id = "st_1045_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_cert=False, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r'),
                          cert_neg=True),
            raiseonerr=False
        )
        self._assert_negative(cmd, PEMCERT_ERR_MSGS)

    # -- PEM positive + full args 1046-1075 --

    def test_start_tracking_1046(self):
        """start-tracking -k -f all positive"""
        test_id = "st_1046_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id, []),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1049(self):
        """start-tracking PEM with invalid EXTUSAGE"""
        test_id = "st_1049_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1050(self):
        """start-tracking PEM with invalid EXTUSAGE"""
        test_id = "st_1050_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-r',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1051(self):
        """start-tracking PEM with invalid CertPrincipalName"""
        test_id = "st_1051_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_start_tracking_1052(self):
        """start-tracking PEM with invalid CertPrincipalName"""
        test_id = "st_1052_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-r',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_start_tracking_1053(self):
        """start-tracking PEM all positive"""
        test_id = "st_1053_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1054(self):
        """start-tracking PEM all positive"""
        test_id = "st_1054_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id, renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1055(self):
        """start-tracking PEM -P all positive"""
        test_id = "st_1055_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1058(self):
        """start-tracking PEM -P with invalid EXTUSAGE"""
        test_id = "st_1058_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1059(self):
        """start-tracking PEM -P with invalid EXTUSAGE"""
        test_id = "st_1059_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1060(self):
        """start-tracking PEM -P with invalid CertPrincipalName"""
        test_id = "st_1060_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_start_tracking_1061(self):
        """start-tracking PEM -P with invalid CertPrincipalName"""
        test_id = "st_1061_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_start_tracking_1062(self):
        """start-tracking PEM -P all positive"""
        test_id = "st_1062_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1063(self):
        """start-tracking PEM -P all positive"""
        test_id = "st_1063_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='inline',
                                               renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1064(self):
        """start-tracking with invalid PINFILE"""
        test_id = "st_1064_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_start_tracking_1065(self):
        """start-tracking with invalid PINFILE"""
        test_id = "st_1065_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_start_tracking_1066(self):
        """start-tracking with invalid PINFILE"""
        test_id = "st_1066_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               pinfile_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PINFILE_VERIFY)

    def test_start_tracking_1067(self):
        """start-tracking -k -f -p all positive"""
        test_id = "st_1067_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1070(self):
        """start-tracking -p with invalid EXTUSAGE"""
        test_id = "st_1070_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1071(self):
        """start-tracking -p with invalid EXTUSAGE"""
        test_id = "st_1071_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               eku_neg=True)),
            raiseonerr=False
        )
        self._assert_negative(cmd, EKU_ERR_MSGS)

    def test_start_tracking_1072(self):
        """start-tracking -p with invalid CertPrincipalName"""
        test_id = "st_1072_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_start_tracking_1073(self):
        """start-tracking -p with invalid CertPrincipalName"""
        test_id = "st_1073_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r',
                                               principal_neg=True)),
            raiseonerr=False
        )
        self._assert_verify(cmd, PEM_PRINCIPAL_VERIFY)

    def test_start_tracking_1074(self):
        """start-tracking -p all positive"""
        test_id = "st_1074_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-R')),
            raiseonerr=False
        )
        self._assert_positive(cmd)

    def test_start_tracking_1075(self):
        """start-tracking -p all positive"""
        test_id = "st_1075_%s" % uuid.uuid4().hex[:8]
        self._setup_pem(test_id, need_pin=True)
        cmd = self.master.run_command(
            self._pem_cmd(test_id,
                          self._pem_extra_args(test_id,
                                               pin_mode='file',
                                               renewal='-r')),
            raiseonerr=False
        )
        self._assert_positive(cmd)


class TestGetcertStopTracking(IntegrationTest):
    """Tests for ipa-getcert stop-tracking command."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)
        cls.pem_dir = create_pem_dir(cls.master)
        clean_requests(cls.master)

    def test_stop_tracking_1001(self):
        """stop-tracking with invalid NSSDBDIR"""
        test_id = "st_stop_1001_%s" % uuid.uuid4().hex[:8]
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-d', NSSDB_NEG, '-n', test_id],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in NSSDB_ERR_MSGS)

    def test_stop_tracking_1002(self):
        """stop-tracking with invalid CertNickName"""
        test_id = "st_stop_1002_%s" % uuid.uuid4().hex[:8]
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

    def test_stop_tracking_1004(self):
        """stop-tracking with options d n t - all positive"""
        test_id = "st_stop_1004_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-d', NSSDB_POS, '-n', test_id,
             '-t', TOKEN_POS],
            raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_stop_tracking_1005(self):
        """stop-tracking -i with invalid request nickname"""
        test_id = "st_stop_1005_%s" % uuid.uuid4().hex[:8]
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

    def test_stop_tracking_1006(self):
        """stop-tracking -i all positive"""
        test_id = "st_stop_1006_%s" % uuid.uuid4().hex[:8]
        prepare_certrequest(self.master, test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking', '-i', test_id],
            raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_stop_tracking_1007(self):
        """stop-tracking with invalid PemKeyFile"""
        test_id = "st_stop_1007_%s" % uuid.uuid4().hex[:8]
        prepare_pem_certfile(self.master, self.pem_dir, test_id)
        certfile = os.path.join(self.pem_dir, '%s.cert.pem' % test_id)
        keyfile = os.path.join('/root', test_id, 'no.such.pem.key.file.')
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-k', keyfile, '-f', certfile],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in PEMKEY_ERR_MSGS)

    def test_stop_tracking_1008(self):
        """stop-tracking with invalid PemCertFile"""
        test_id = "st_stop_1008_%s" % uuid.uuid4().hex[:8]
        prepare_pem_keyfile(self.master, self.pem_dir, test_id)
        keyfile = os.path.join(self.pem_dir, '%s.key.pem' % test_id)
        certfile = os.path.join(test_id, 'NoSuchPemCertFile')
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-k', keyfile, '-f', certfile],
            raiseonerr=False
        )
        assert cmd.returncode == 1
        combined = cmd.stdout_text + cmd.stderr_text
        assert any(m in combined for m in PEMCERT_ERR_MSGS)

    def test_stop_tracking_1009(self):
        """stop-tracking -k -f all positive"""
        test_id = "st_stop_1009_%s" % uuid.uuid4().hex[:8]
        prepare_pem_keyfile(self.master, self.pem_dir, test_id)
        prepare_pem_certfile(self.master, self.pem_dir, test_id)
        keyfile = os.path.join(self.pem_dir, '%s.key.pem' % test_id)
        certfile = os.path.join(self.pem_dir, '%s.cert.pem' % test_id)
        cmd = self.master.run_command(
            ['ipa-getcert', 'stop-tracking',
             '-k', keyfile, '-f', certfile],
            raiseonerr=False
        )
        assert cmd.returncode == 0


class TestGetcertResubmit(IntegrationTest):
    """Tests for ipa-getcert resubmit command."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)
        cls.cert_subject = get_cert_subject(cls.master)
        cls.fqdn = cls.master.hostname
        cls.realm = cls.master.domain.realm
        cls.pem_dir = create_pem_dir(cls.master)
        clean_requests(cls.master)

    def test_resubmit_1001(self):
        """resubmit with invalid NSSDBDIR"""
        test_id = "resub_1001_%s" % uuid.uuid4().hex[:8]
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

    def test_resubmit_1002(self):
        """resubmit with invalid NSSDBDIR"""
        test_id = "resub_1002_%s" % uuid.uuid4().hex[:8]
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

    def test_resubmit_1004(self):
        """resubmit with invalid EXTUSAGE"""
        test_id = "resub_1004_%s" % uuid.uuid4().hex[:8]
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

    def test_resubmit_1006(self):
        """resubmit all positive"""
        test_id = "resub_1006_%s" % uuid.uuid4().hex[:8]
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

    def test_resubmit_1009(self):
        """resubmit with invalid EXTUSAGE"""
        test_id = "resub_1009_%s" % uuid.uuid4().hex[:8]
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

    def test_resubmit_1011(self):
        """resubmit with invalid EXTUSAGE"""
        test_id = "resub_1011_%s" % uuid.uuid4().hex[:8]
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

    def test_resubmit_1013(self):
        """resubmit -f with invalid PemCertFile"""
        test_id = "resub_1013_%s" % uuid.uuid4().hex[:8]
        certfile = os.path.join(test_id, 'NoSuchPemCertFile')
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
        assert any(m in combined for m in PEMCERT_ERR_MSGS)

    def test_resubmit_1014(self):
        """resubmit -f -P with invalid PemCertFile"""
        test_id = "resub_1014_%s" % uuid.uuid4().hex[:8]
        certfile = os.path.join(test_id, 'NoSuchPemCertFile')
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
        assert any(m in combined for m in PEMCERT_ERR_MSGS)

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


class TestGetcertListCommands(IntegrationTest):
    """Tests for ipa-getcert list and list-cas commands."""

    num_replicas = 0
    num_clients = 0

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.kinit_admin(cls.master)

    def test_list_1001(self):
        """list with no options"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_1002(self):
        """list with -r option"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-r'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_1003(self):
        """list with -t option"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list', '-t'], raiseonerr=False
        )
        assert cmd.returncode == 0

    def test_list_cas_1001(self):
        """list-cas with no options"""
        cmd = self.master.run_command(
            ['ipa-getcert', 'list-cas'], raiseonerr=False
        )
        assert cmd.returncode == 0
