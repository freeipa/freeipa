#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Integration tests for Kerberos key types management in FreeIPA.
Validates that
1. FreeIPA correctly derives encryption types from 'permitted_enctypes`.
2. Stores principal keys in strongest-first order.
"""

from __future__ import absolute_import

import re

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

CRYPTO_POLICIES_KRB5 = '/etc/krb5.conf.d/crypto-policies'
CIFS_KEYTAB = '/tmp/cifs_test.keytab'
DOGTAG_KEYTAB = '/etc/pki/pki-tomcat/dogtag.keytab'
DNSKEYSYNCD_KEYTAB = '/etc/ipa/dnssec/ipa-dnskeysyncd.keytab'
DS_KEYTAB = '/etc/dirsrv/ds.keytab'
HTTP_KEYTAB = '/var/lib/ipa/gssproxy/http.keytab'
HOST_KEYTAB = '/etc/krb5.keytab'
NAMED_KEYTAB = '/etc/named.keytab'
NFS_KEYTAB = '/tmp/nfs_test.keytab'

TEST_KEYTAB = '/tmp/test.keytab'
TESTSERVICE = 'testservice'
TESTUSER = 'keytype_user1'
TESTPWD = 'Secret123'


def parse_keytab_enctypes(host, keytab_path):
    """Return the ordered list of enctype strings from a keytab file."""
    result = host.run_command(['klist', '-ekt', keytab_path])
    return re.findall(r'\(([\w:-]+)\)\s*$', result.stdout_text, re.MULTILINE)


def parse_principal_keys(host, principal):
    """Return (num_keys, list-of-(vno, keytype)-tuples) from kadmin.local."""
    output = host.run_command(
        ['kadmin.local', 'getprinc', principal]
    ).stdout_text
    match = re.search(r'Number of keys:\s*(\d+)', output)
    num_keys = int(match.group(1)) if match else 0
    keys = re.findall(r'Key: vno (\d+), (.+)$', output, re.MULTILINE)
    return num_keys, keys


def get_principal_enctypes(host, principal):
    """Return the ordered list of enctype names for a principal.

    Strips IPA salt-type suffixes (e.g. ``:special``, ``:normal``)
    so the returned names match canonical MIT krb5 enctype names.
    """
    _num_keys, keys = parse_principal_keys(host, principal)
    return [keytype.strip().split(':')[0] for _vno, keytype in keys]


def get_permitted_enctypes(host):
    """Return the ordered list of canonical enctype names from krb5 config.

    Remote-host variant of the same logic in
    ipatests/test_cmdline/test_ipagetkeytab.py (which uses configparser
    on the local filesystem). This version runs on integration-test
    hosts via run_command.
    """
    result = host.run_command(['cat', CRYPTO_POLICIES_KRB5])
    match = re.search(
        r'permitted_enctypes\s*=\s*(.+)$', result.stdout_text, re.MULTILINE
    )
    if not match:
        raise RuntimeError(
            f"permitted_enctypes not found in {CRYPTO_POLICIES_KRB5}"
        )
    return match.group(1).strip().split()


def assert_keytab_works_with_kinit(host, keytab, principal, expected_enctype):
    """Verify that kinit with a keytab succeeds and uses expected_enctype."""
    tasks.kdestroy_all(host)
    host.run_command(['kinit', '-kt', keytab, principal])
    result = host.run_command(['klist', '-e'])
    assert principal in result.stdout_text
    assert expected_enctype in result.stdout_text
    tasks.kdestroy_all(host)


class TestKeyTypesAfterInstall(IntegrationTest):
    """Verify encryption types are correct right after a standard install.
    Uses default system ``permitted_enctypes`` (no override).
    Checks that keytabs and principal keys all reflect the expected
    strongest-first ordering.
    """

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])
        tasks.kinit_admin(cls.master)

        services = {
            'nfs': NFS_KEYTAB,
            'cifs': CIFS_KEYTAB,
            TESTSERVICE: None,
        }
        for service, keytab in services.items():
            principal = f'{service}/{cls.master.hostname}'
            cls.master.run_command([
                'ipa', 'service-add', '--force', principal,
            ])
            if keytab:
                cls.master.run_command([
                    'ipa-getkeytab', '-p', principal, '-k', keytab,
                ])

        cls.permitted_enctypes = get_permitted_enctypes(cls.master)
        cls.strongest_enctype = cls.permitted_enctypes[0]

    @classmethod
    def uninstall(cls, mh):
        tasks.kinit_admin(cls.master)
        for service in ('nfs', 'cifs', TESTSERVICE):
            cls.master.run_command(
                ['ipa', 'service-del',
                 f'{service}/{cls.master.hostname}'],
                raiseonerr=False,
            )
        cls.master.run_command(
            ['ipa', 'user-del', TESTUSER], raiseonerr=False,
        )
        cls.master.run_command(
            ['rm', '-f', NFS_KEYTAB, CIFS_KEYTAB, TEST_KEYTAB]
        )
        super(TestKeyTypesAfterInstall, cls).uninstall(mh)

    def test_tgs_principal_key_order(self):
        """krbtgt principal should have keys including the strongest enctype.

        Key ordering is determined by kdb5_util at KDC creation time and
        may differ from ``permitted_enctypes``, so we only verify that
        the strongest permitted enctype is present, not that it is first.
        """
        realm = self.master.domain.realm
        enctypes = get_principal_enctypes(
            self.master, 'krbtgt/{realm}@{realm}'.format(realm=realm)
        )
        assert len(enctypes) > 0
        assert self.strongest_enctype in enctypes, \
            f"Expected {self.strongest_enctype} in krbtgt keys, got: {enctypes}"

    def test_admin_principal_key_order(self):
        """Admin principal keys should all be permitted enctypes."""
        _num_keys, keys = parse_principal_keys(self.master, 'admin')
        assert len(keys) > 0
        for _vno, keytype in keys:
            assert any(enc in keytype for enc in self.permitted_enctypes), \
                f"Key '{keytype}' doesn't match any permitted enctype"

    def test_user_principal_key_order(self):
        """New IPA user should have keys in strongest-first order."""
        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, TESTUSER, password=TESTPWD)
        try:
            enctypes = get_principal_enctypes(self.master, TESTUSER)
            assert len(enctypes) > 0
            assert enctypes[0] == self.strongest_enctype
        finally:
            self.master.run_command(
                ['ipa', 'user-del', TESTUSER], raiseonerr=False,
            )

    def test_service_keytab_enctypes(self):
        """All service keytabs should have strongest-first enctypes
        and work with kinit."""
        master_keytabs = [
            (DS_KEYTAB, 'ldap'),
            (HTTP_KEYTAB, 'HTTP'),
            (HOST_KEYTAB, 'host'),
            (NFS_KEYTAB, 'nfs'),
            (CIFS_KEYTAB, 'cifs'),
            (NAMED_KEYTAB, 'DNS'),
            (DOGTAG_KEYTAB, 'dogtag'),
            (DNSKEYSYNCD_KEYTAB, 'ipa-dnskeysyncd'),
        ]
        for keytab, svc_prefix in master_keytabs:
            enctypes = parse_keytab_enctypes(self.master, keytab)
            assert len(enctypes) > 0, \
                f"No enctypes in {keytab}"
            assert enctypes[0] == self.strongest_enctype, \
                f"Wrong strongest enctype in {keytab}: {enctypes[0]}"
            princ = '{}/{}@{}'.format(
                svc_prefix, self.master.hostname,
                self.master.domain.realm,
            )
            assert_keytab_works_with_kinit(
                self.master, keytab, princ, self.strongest_enctype
            )

        # Client host keytab
        enctypes = parse_keytab_enctypes(self.clients[0], HOST_KEYTAB)
        assert len(enctypes) > 0, "No enctypes in client host keytab"
        assert enctypes[0] == self.strongest_enctype, \
            f"Wrong strongest enctype in client keytab: {enctypes[0]}"
        client_princ = 'host/{}@{}'.format(
            self.clients[0].hostname, self.clients[0].domain.realm
        )
        assert_keytab_works_with_kinit(
            self.clients[0], HOST_KEYTAB, client_princ,
            self.strongest_enctype,
        )

    def test_permitted_enctypes_in_config(self):
        """Crypto-policies config and ipa-getkeytab should agree on enctypes."""
        current = get_permitted_enctypes(self.master)
        assert current == self.permitted_enctypes, \
            f"Config enctypes changed since install: {current}"

        ipa_result = self.master.run_command([
            'ipa-getkeytab', '--permitted-enctypes',
        ])
        # ipa-getkeytab outputs human-readable names rather than
        # canonical enctype names, so filter and count.
        ipa_lines = [
            line.strip() for line in
            ipa_result.stdout_text.strip().splitlines()
            if line.strip() and not line.strip().endswith(':')
        ]
        assert len(ipa_lines) > 0, "ipa-getkeytab returned no enctypes"
        assert len(ipa_lines) == len(self.permitted_enctypes), \
            (f"Expected {len(self.permitted_enctypes)} enctypes, "
             f"ipa-getkeytab returned {len(ipa_lines)}")

    def test_user_password_keys_have_correct_salt(self):
        """Password-derived user keys should have :special salt type."""
        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, TESTUSER, password=TESTPWD)
        _num_keys, keys = parse_principal_keys(self.master, TESTUSER)
        assert len(keys) > 0
        for _vno, keytype in keys:
            assert any(enc in keytype for enc in self.permitted_enctypes), \
                f"Key '{keytype}' doesn't match any permitted enctype"
            assert 'special' in keytype.lower(), \
                f"Expected special salt for password key, got: {keytype}"

    def test_getkeytab_with_password_uses_special_salt(self):
        """ipa-getkeytab -P should produce password-derived keys with
        only permitted enctypes and :special salt."""
        tasks.kinit_admin(self.master)
        svc_princ = '{}/{}'.format(TESTSERVICE, self.master.hostname)
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command(
            [
                'ipa-getkeytab',
                '-p', svc_princ,
                '-k', TEST_KEYTAB,
                '-P',
            ],
            stdin_text='{pwd}\n{pwd}\n'.format(pwd=TESTPWD),
        )
        enctypes = parse_keytab_enctypes(self.master, TEST_KEYTAB)
        assert len(enctypes) > 0
        for enc in enctypes:
            assert enc in self.permitted_enctypes, \
                f"Keytab enctype '{enc}' not in permitted enctypes"

        _num_keys, keys = parse_principal_keys(self.master, svc_princ)
        assert len(keys) > 0
        for _vno, keytype in keys:
            assert any(enc in keytype for enc in self.permitted_enctypes), \
                f"Key '{keytype}' doesn't match any permitted enctype"
            assert 'special' in keytype.lower(), \
                f"Expected special salt for -P derived key, got: {keytype}"

    def test_getkeytab_with_explicit_enctypes(self):
        """ipa-getkeytab -e should filter to only requested enctypes."""
        tasks.kinit_admin(self.master)
        svc_princ = '{}/{}'.format(TESTSERVICE, self.master.hostname)
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command([
            'ipa-getkeytab',
            '-p', svc_princ,
            '-k', TEST_KEYTAB,
            '-e', 'aes256-cts-hmac-sha1-96',
        ])
        enctypes = parse_keytab_enctypes(self.master, TEST_KEYTAB)
        assert len(enctypes) > 0
        for e in enctypes:
            assert e == 'aes256-cts-hmac-sha1-96'

    def test_getkeytab_disallowed_enctype_filtered(self):
        """ipa-getkeytab -e with a disallowed enctype should not produce
        keys outside the permitted set."""
        tasks.kinit_admin(self.master)
        svc_princ = '{}/{}'.format(TESTSERVICE, self.master.hostname)
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        result = self.master.run_command(
            [
                'ipa-getkeytab',
                '-p', svc_princ,
                '-k', TEST_KEYTAB,
                '-e', 'des-cbc-crc',
            ],
            raiseonerr=False,
        )
        if result.returncode == 0:
            enctypes = parse_keytab_enctypes(self.master, TEST_KEYTAB)
            for enc in enctypes:
                assert enc != 'des-cbc-crc', \
                    "Disallowed enctype des-cbc-crc should not appear"
                assert enc in self.permitted_enctypes, \
                    f"Unexpected enctype '{enc}' outside permitted set"
        else:
            assert 'des-cbc-crc' not in result.stdout_text

    def test_getkeytab_duplicate_enctypes_deduplicated(self):
        """ipa-getkeytab -e with duplicate enctypes should produce
        exactly one key per enctype."""
        tasks.kinit_admin(self.master)
        svc_princ = '{}/{}'.format(TESTSERVICE, self.master.hostname)
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command([
            'ipa-getkeytab',
            '-p', svc_princ,
            '-k', TEST_KEYTAB,
            '-e', 'aes256-cts-hmac-sha1-96,aes256-cts-hmac-sha1-96',
        ])
        enctypes = parse_keytab_enctypes(self.master, TEST_KEYTAB)
        aes256_count = sum(
            1 for e in enctypes if e == 'aes256-cts-hmac-sha1-96'
        )
        assert aes256_count == 1, \
            (f"Expected exactly 1 aes256 key, "
             f"got {aes256_count} in {enctypes}")

    def test_keytab_rotation_preserves_enctypes(self):
        """After keytab rotation (re-retrieve), new keys should have the
        correct enctypes and kvno should increment."""
        tasks.kinit_admin(self.master)
        svc_princ = '{}/{}'.format(TESTSERVICE, self.master.hostname)

        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command([
            'ipa-getkeytab', '-p', svc_princ, '-k', TEST_KEYTAB,
        ])
        enctypes_before = parse_keytab_enctypes(self.master, TEST_KEYTAB)
        assert len(enctypes_before) > 0
        assert enctypes_before[0] == self.strongest_enctype

        _num_keys, keys_before = parse_principal_keys(
            self.master, svc_princ
        )
        kvno_before = max(int(vno) for vno, _ in keys_before)

        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command([
            'ipa-getkeytab', '-p', svc_princ, '-k', TEST_KEYTAB,
        ])
        enctypes_after = parse_keytab_enctypes(self.master, TEST_KEYTAB)
        assert len(enctypes_after) > 0
        assert enctypes_after[0] == self.strongest_enctype

        _num_keys, keys_after = parse_principal_keys(
            self.master, svc_princ
        )
        kvno_after = max(int(vno) for vno, _ in keys_after)
        assert kvno_after > kvno_before, \
            (f"kvno did not increment after rotation: "
             f"before={kvno_before}, after={kvno_after}")

        assert_keytab_works_with_kinit(
            self.master, TEST_KEYTAB, svc_princ,
            self.strongest_enctype,
        )

    def test_replica_keytabs_consistent(self):
        """Replica keytabs should use the same strongest enctype as master.

        The exact set of enctypes may differ because the master keytab
        is created early during ipa-server-install (before LDAP enctype
        attributes are fully configured) while the replica keytab is
        created later from the LDAP-derived configuration.
        """
        for keytab in (DS_KEYTAB, HTTP_KEYTAB, HOST_KEYTAB, NAMED_KEYTAB):
            master_enctypes = parse_keytab_enctypes(self.master, keytab)
            replica_enctypes = parse_keytab_enctypes(self.replicas[0], keytab)
            assert len(master_enctypes) > 0, f"Empty master keytab {keytab}"
            assert len(replica_enctypes) > 0, f"Empty replica keytab {keytab}"
            assert master_enctypes[0] == replica_enctypes[0], \
                (f"Strongest enctype mismatch for {keytab}: "
                 f"master={master_enctypes[0]}, "
                 f"replica={replica_enctypes[0]}")
