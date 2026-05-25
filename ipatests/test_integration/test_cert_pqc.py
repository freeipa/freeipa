#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
ML-DSA (post-quantum) certificate integration tests.

Reuses :class:`~ipatests.test_integration.test_cert.TestInstallMasterClient`
for legacy certmonger/profile scenarios. All PQC install options, helpers,
and ML-DSA-specific test classes live in this module; ``test_cert.py`` is
unchanged for RSA/default reference.
"""
import os
import random
import string

import pytest

from ipaplatform.paths import paths
from ipapython.dn import DN

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_cert import TestInstallMasterClient


def _expected_ml_dsa_httpd_public_key_label(ipa_key_type):
    """Substring expected on ``openssl x509 ... | grep Public-Key`` for httpd."""
    if not ipa_key_type:
        return None
    kt = ipa_key_type.strip().lower()
    if not kt.startswith('mldsa'):
        return None
    if kt == 'mldsa':
        return 'ML-DSA-65'
    if ':' in ipa_key_type:
        strength = ipa_key_type.split(':', 1)[1].strip()
        if strength.isdigit():
            return 'ML-DSA-{}'.format(strength)
    return None


def _mldsa_openssl_algorithm(ipa_key_type, mldsa_cert_keygen=None):
    """OpenSSL ``genpkey -algorithm`` name for ML-DSA CSRs."""
    if mldsa_cert_keygen:
        return mldsa_cert_keygen
    label = _expected_ml_dsa_httpd_public_key_label(ipa_key_type)
    return label or 'ML-DSA-65'


class PQCMasterClientInstallMixin:
    """PQC ``ipa-server-install`` for master + one client (line topology)."""

    ipa_key_type = None
    ca_key_type = None
    mldsa_cert_keygen = None

    @classmethod
    def _install_line_master_client_with_pqc(cls, mh):
        extra_args = []
        if cls.domain_level is not None:
            domain_level = cls.domain_level
        else:
            domain_level = cls.master.config.domain_level

        if cls.token_password:
            extra_args.extend(('--token-password', cls.token_password,))
        if cls.ipa_key_type:
            extra_args.extend(['--key-type-size', cls.ipa_key_type])
        if cls.ca_key_type:
            extra_args.extend(['--ca-key-type', cls.ca_key_type])

        tasks.install_master(
            cls.master,
            setup_dns=True,
            domain_level=domain_level,
            random_serial=cls.random_serial,
            extra_args=extra_args,
        )
        tasks.add_a_records_for_hosts_in_master_domain(cls.master)
        tasks.install_clients([cls.master], cls.clients)

    @classmethod
    def install(cls, mh):
        cls._install_line_master_client_with_pqc(mh)
        result = cls.clients[0].run_command(['date', '+%Y-%m-%d %H:%M:%S'])
        cls.since = result.stdout_text.strip()

    def test_getcert_list_profile(self):
        """Profile listing plus ML-DSA httpd public key when applicable."""
        super().test_getcert_list_profile()
        ml_label = _expected_ml_dsa_httpd_public_key_label(self.ipa_key_type)
        if ml_label:
            pk = self.master.run_command(
                'openssl x509 -text -noout -in %s | grep Public-Key'
                % paths.HTTPD_CERT_FILE
            ).stdout_text
            assert ml_label in pk


class PQCCertEnrollmentHelpersMixin:
    """CSR generation and certmonger enrollment helpers."""

    mldsa_cert_keygen = 'ML-DSA-65'

    def _mldsa_algorithm(self):
        return _mldsa_openssl_algorithm(self.ipa_key_type, self.mldsa_cert_keygen)

    def _require_openssl_mldsa(self, host=None):
        host = host or self.master
        probe = os.path.join(paths.OPENSSL_PRIVATE_DIR, '.mldsa-probe.key')
        algo = self._mldsa_algorithm()
        try:
            gen = host.run_command(
                ['openssl', 'genpkey', '-algorithm', algo, '-out', probe],
                raiseonerr=False,
            )
            if gen.returncode != 0:
                pytest.skip(
                    'OpenSSL on %s cannot generate %s keys (need OpenSSL '
                    'with ML-DSA support).' % (host.hostname, algo)
                )
        finally:
            host.run_command(['rm', '-f', probe], raiseonerr=False)

    def _generate_user_csr(self, user, stem, key_type='rsa'):
        csr_file = '%s.csr' % stem
        key_file = '%s.key' % stem
        if key_type == 'rsa':
            self.master.run_command([
                'openssl', 'req', '-newkey', 'rsa:2048', '-keyout', key_file,
                '-nodes', '-out', csr_file, '-subj', '/CN=' + user,
            ])
        elif key_type == 'mldsa':
            self._require_openssl_mldsa(self.master)
            algo = self._mldsa_algorithm()
            self.master.run_command(
                ['openssl', 'genpkey', '-algorithm', algo, '-out', key_file]
            )
            self.master.run_command([
                'openssl', 'req', '-new', '-key', key_file, '-out', csr_file,
                '-subj', '/CN=' + user,
            ])
        else:
            raise ValueError(key_type)
        return csr_file, key_file

    def _ipa_user_cert_request(self, user, csr_file, cert_file):
        self.master.run_command([
            'ipa', 'cert-request', '--principal', user,
            '--certificate-out', cert_file, csr_file,
        ])

    def _assert_user_cert_public_key(self, cert_file, key_type):
        pk = self.master.run_command(
            'openssl x509 -in %s -noout -text | grep Public-Key' % cert_file
        ).stdout_text
        if key_type == 'rsa':
            assert 'RSA Public-Key' in pk or '2048 bit' in pk, pk
        elif key_type == 'mldsa':
            assert self._mldsa_algorithm() in pk, pk
        else:
            raise ValueError(key_type)

    def _issue_user_certs(self, user, key_specs):
        ldap = self.master.ldap_connect()
        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user)
        for stem, key_type in key_specs:
            csr_file, key_file = self._generate_user_csr(user, stem, key_type)
            cert_file = '%s.crt' % stem
            self._ipa_user_cert_request(user, csr_file, cert_file)
            self._assert_user_cert_public_key(cert_file, key_type)
            self.master.run_command(
                ['rm', '-f', csr_file, key_file, cert_file], raiseonerr=False
            )
        entry = ldap.get_entry(DN(('uid', user), ('cn', 'users'),
                                  ('cn', 'accounts'), self.master.domain.basedn))
        assert len(entry.get('usercertificate')) == len(key_specs)

    def _getcert_request_host_cert(self, host, req_id, keygen=None):
        certfile = os.path.join(paths.OPENSSL_CERTS_DIR, '%s.pem' % req_id)
        keyfile = os.path.join(paths.OPENSSL_PRIVATE_DIR, '%s.key' % req_id)
        hostname = host.hostname
        host.run_command(['rm', '-f', certfile, keyfile], raiseonerr=False)
        cmd_arg = [
            'getcert', 'request', '-c', 'ipa', '-I', req_id,
            '-k', keyfile, '-f', certfile,
            '-D', hostname, '-K', 'host/%s' % hostname,
            '-N', 'CN={}'.format(hostname),
            '-U', 'id-kp-clientAuth', '-T', 'caIPAserviceCert',
        ]
        if keygen:
            cmd_arg.extend(['-G', keygen])
        result = host.run_command(cmd_arg)
        assert (
            'New signing request "%s" added.\n' % req_id in result.stdout_text
        )
        status = tasks.wait_for_request(host, req_id, 300)
        assert status == 'MONITORING', (
            'certmonger request %s is in state %s' % (req_id, status)
        )
        list_out = host.run_command(
            ['getcert', 'list', '-i', req_id]
        ).stdout_text
        assert 'profile: caIPAserviceCert' in list_out
        return certfile

    def _cleanup_getcert_request(self, host, req_id):
        host.run_command(
            ['getcert', 'stop-tracking', '-i', req_id], raiseonerr=False)
        host.run_command(
            ['rm', '-f',
             os.path.join(paths.OPENSSL_CERTS_DIR, '%s.pem' % req_id),
             os.path.join(paths.OPENSSL_PRIVATE_DIR, '%s.key' % req_id)],
            raiseonerr=False,
        )


class TestInstallMasterClientMLDSA(PQCMasterClientInstallMixin,
                                   PQCCertEnrollmentHelpersMixin,
                                   TestInstallMasterClient):
    """``TestInstallMasterClient`` scenarios with ML-DSA IPA keys (RSA CA)."""

    ipa_key_type = 'mldsa'
    ca_key_type = None
    mldsa_cert_keygen = 'ML-DSA-65'

    def test_user_cert_mldsa_csr_signed_by_rsa_ca(self):
        """ML-DSA user CSRs are signed by the default RSA CA."""
        self._issue_user_certs(
            'user-mldsa-rsa-ca',
            [('mldsa0', 'mldsa'), ('mldsa1', 'mldsa')],
        )

    def test_getcert_mldsa_key_signed_by_rsa_ca(self):
        """Host cert via ``caIPAserviceCert`` with ML-DSA key, RSA CA."""
        req_id = 'mldsa-host-rsa-ca'
        try:
            certfile = self._getcert_request_host_cert(
                self.master, req_id, keygen=self.mldsa_cert_keygen,
            )
            pk_out = self.master.run_command(
                'openssl x509 -in %s -noout -text | grep Public-Key' % certfile
            ).stdout_text
            assert self.mldsa_cert_keygen in pk_out
        finally:
            self._cleanup_getcert_request(self.master, req_id)


class TestInstallMasterClientMLDSACA(PQCMasterClientInstallMixin,
                                     PQCCertEnrollmentHelpersMixin,
                                     TestInstallMasterClient):
    """``TestInstallMasterClient`` scenarios with ML-DSA IPA keys and CA."""

    ipa_key_type = 'mldsa'
    ca_key_type = 'mldsa'
    mldsa_cert_keygen = 'ML-DSA-65'

    def test_ca_signing_keys_are_mldsa(self):
        """Dogtag CA signing keys use ML-DSA."""
        result = self.master.run_command(
            'certutil -K -d %s -f %s | grep -c mldsa' % (
                paths.PKI_TOMCAT_ALIAS_DIR,
                paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
            )
        )
        assert '5' in result.stdout_text

    def test_user_cert_rsa_csr_signed_by_mldsa_ca(self):
        """RSA user CSRs are signed by an ML-DSA CA."""
        self._issue_user_certs(
            'user-rsa-mldsa-ca',
            [('rsa0', 'rsa'), ('rsa1', 'rsa')],
        )

    def test_user_cert_mldsa_csr_signed_by_mldsa_ca(self):
        """ML-DSA user CSRs are signed by an ML-DSA CA."""
        self._issue_user_certs(
            'user-mldsa-mldsa-ca',
            [('mldsa0', 'mldsa'), ('mldsa1', 'mldsa')],
        )

    def test_getcert_mldsa_key_signed_by_mldsa_ca(self):
        """Host cert with ML-DSA key via ML-DSA CA."""
        req_id = 'mldsa-host-mldsa-ca'
        try:
            certfile = self._getcert_request_host_cert(
                self.master, req_id, keygen=self.mldsa_cert_keygen,
            )
            pk_out = self.master.run_command(
                'openssl x509 -in %s -noout -text | grep Public-Key' % certfile
            ).stdout_text
            assert self.mldsa_cert_keygen in pk_out
        finally:
            self._cleanup_getcert_request(self.master, req_id)

    def test_getcert_rsa_key_signed_by_mldsa_ca(self):
        """Default RSA host key enrollment against an ML-DSA CA."""
        req_id = 'rsa-host-mldsa-ca'
        try:
            certfile = self._getcert_request_host_cert(self.master, req_id)
            pk_out = self.master.run_command(
                'openssl x509 -in %s -noout -text | grep Public-Key' % certfile
            ).stdout_text
            assert 'RSA Public-Key' in pk_out or '2048 bit' in pk_out, pk_out
        finally:
            self._cleanup_getcert_request(self.master, req_id)

    def test_getcert_mldsa_key_client_signed_by_mldsa_ca(self):
        """Client host cert with ML-DSA key via ML-DSA CA."""
        self._require_openssl_mldsa(self.clients[0])
        req_id = 'mldsa-client-mldsa-ca'
        host = self.clients[0]
        try:
            certfile = self._getcert_request_host_cert(
                host, req_id, keygen=self.mldsa_cert_keygen,
            )
            pk_out = host.run_command(
                'openssl x509 -in %s -noout -text | grep Public-Key' % certfile
            ).stdout_text
            assert self.mldsa_cert_keygen in pk_out
        finally:
            self._cleanup_getcert_request(host, req_id)


class PQCCertEnrollmentInstallMixin:
    """PQC install for master + replica (enrollment-focused topology)."""

    num_replicas = 1
    master_with_dns = True
    ipa_key_type = None
    ca_key_type = None
    mldsa_cert_keygen = 'ML-DSA-65'

    @classmethod
    def install(cls, mh):
        extra_args = []
        if cls.ipa_key_type:
            extra_args.extend(['--key-type-size', cls.ipa_key_type])
        if cls.ca_key_type:
            extra_args.extend(['--ca-key-type', cls.ca_key_type])
        tasks.install_master(cls.master, setup_dns=True, extra_args=extra_args)
        tasks.install_replica(
            cls.master, cls.replicas[0], setup_ca=True,
        )

    def _cleanup_mldsa_enroll_files(self, host, req_id):
        certfile = os.path.join(paths.OPENSSL_CERTS_DIR, '%s.pem' % req_id)
        keyfile = os.path.join(paths.OPENSSL_PRIVATE_DIR, '%s.key' % req_id)
        host.run_command(
            ['getcert', 'stop-tracking', '-i', req_id], raiseonerr=False)
        host.run_command(['rm', '-f', certfile, keyfile], raiseonerr=False)

    def _request_mldsa_caIPAservice_cert(self, host, req_id):
        """Issue a host cert via Dogtag profile ``caIPAserviceCert``."""
        certfile = os.path.join(paths.OPENSSL_CERTS_DIR, '%s.pem' % req_id)
        keyfile = os.path.join(paths.OPENSSL_PRIVATE_DIR, '%s.key' % req_id)
        hostname = host.hostname
        host.run_command(['rm', '-f', certfile, keyfile], raiseonerr=False)
        cmd_arg = [
            'getcert', 'request', '-c', 'ipa', '-I', req_id,
            '-k', keyfile, '-f', certfile,
            '-D', hostname, '-K', 'host/%s' % hostname,
            '-N', 'CN={}'.format(hostname),
            '-U', 'id-kp-clientAuth', '-T', 'caIPAserviceCert',
            '-G', self.mldsa_cert_keygen,
        ]
        result = host.run_command(cmd_arg)
        assert (
            'New signing request "%s" added.\n' % req_id in result.stdout_text
        )
        status = tasks.wait_for_request(host, req_id, 300)
        assert status == 'MONITORING', (
            'certmonger request %s is in state %s' % (req_id, status)
        )
        list_out = host.run_command(
            ['getcert', 'list', '-i', req_id]
        ).stdout_text
        assert 'profile: caIPAserviceCert' in list_out
        pk_out = host.run_command(
            'openssl x509 -in %s -noout -text | grep Public-Key' % certfile
        ).stdout_text
        assert self.mldsa_cert_keygen in pk_out

    def _request_mldsa_via_ipa_cert_request(self, host, stem, service_suffix):
        """Issue a cert with ``ipa cert-request`` (PKCS#10 CSR)."""
        csr = os.path.join(paths.OPENSSL_CERTS_DIR, '%s.csr' % stem)
        key = os.path.join(paths.OPENSSL_PRIVATE_DIR, '%s.key' % stem)
        cert = os.path.join(paths.OPENSSL_CERTS_DIR, '%s.crt' % stem)
        algo = self.mldsa_cert_keygen
        principal = 'mldsaenr{}/{}'.format(service_suffix, host.hostname)

        host.run_command(['rm', '-f', csr, key, cert], raiseonerr=False)
        gen = host.run_command(
            ['openssl', 'genpkey', '-algorithm', algo, '-out', key],
            raiseonerr=False,
        )
        if gen.returncode != 0:
            host.run_command(['rm', '-f', key], raiseonerr=False)
            pytest.skip(
                'OpenSSL on %s cannot generate %s keys (need OpenSSL with '
                'ML-DSA support).' % (host.hostname, algo)
            )
        cn = host.hostname
        try:
            host.run_command([
                'openssl', 'req', '-new', '-key', key, '-out', csr,
                '-subj', '/CN={}'.format(cn),
            ])
            tasks.kinit_admin(host)
            try:
                host.run_command([
                    'ipa', 'cert-request', '--add', '--principal', principal,
                    '--certificate-out', cert, '--profile-id',
                    'caIPAserviceCert', csr,
                ])
            finally:
                tasks.kdestroy_all(host)

            pk_out = host.run_command(
                'openssl x509 -in %s -noout -text | grep Public-Key' % cert
            ).stdout_text
            assert algo in pk_out
        finally:
            host.run_command(
                ['ipa', 'service-del', principal], raiseonerr=False)
            host.run_command(['rm', '-f', csr, key, cert], raiseonerr=False)


class TestPQCCertEnrollmentIPACerts(PQCCertEnrollmentInstallMixin,
                                    IntegrationTest):
    """Certmonger enrollment with ML-DSA service keys (RSA CA)."""

    ipa_key_type = 'mldsa'
    ca_key_type = None
    mldsa_cert_keygen = 'ML-DSA-65'

    def test_getcert_enroll_caIPAserviceCert_mldsa_key_master(self):
        req_id = 'pqc-mldsa-enroll-master'
        try:
            self._request_mldsa_caIPAservice_cert(self.master, req_id)
        finally:
            self._cleanup_mldsa_enroll_files(self.master, req_id)

    def test_getcert_enroll_caIPAserviceCert_mldsa_key_replica(self):
        req_id = 'pqc-mldsa-enroll-replica'
        try:
            self._request_mldsa_caIPAservice_cert(self.replicas[0], req_id)
        finally:
            self._cleanup_mldsa_enroll_files(self.replicas[0], req_id)

    def test_ipa_cert_request_mldsa_caIPAservice_profile_master(self):
        suffix = ''.join(
            random.choice(string.ascii_lowercase) for _ in range(8)
        )
        stem = 'pqc-ipa-cr-%s' % suffix
        self._request_mldsa_via_ipa_cert_request(self.master, stem, suffix)


class TestPQCCertEnrollmentCACerts(PQCCertEnrollmentInstallMixin,
                                   IntegrationTest):
    """Enrollment when both IPA service keys and the CA use ML-DSA."""

    ipa_key_type = 'mldsa:44'
    ca_key_type = 'mldsa'
    mldsa_cert_keygen = 'ML-DSA-44'

    def test_getcert_enroll_caIPAserviceCert_mldsa_key_master(self):
        req_id = 'pqc-mldsa44-enroll-master'
        try:
            self._request_mldsa_caIPAservice_cert(self.master, req_id)
        finally:
            self._cleanup_mldsa_enroll_files(self.master, req_id)

    def test_getcert_enroll_caIPAserviceCert_mldsa_key_replica(self):
        req_id = 'pqc-mldsa44-enroll-replica'
        try:
            self._request_mldsa_caIPAservice_cert(self.replicas[0], req_id)
        finally:
            self._cleanup_mldsa_enroll_files(self.replicas[0], req_id)

    def test_ipa_cert_request_mldsa_caIPAservice_profile_master(self):
        suffix = ''.join(
            random.choice(string.ascii_lowercase) for _ in range(8)
        )
        stem = 'pqc-ipa-cr44-%s' % suffix
        self._request_mldsa_via_ipa_cert_request(self.master, stem, suffix)
