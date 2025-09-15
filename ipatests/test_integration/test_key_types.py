#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#

import inspect
import pytest
import re
import sys

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest

KRB5CONF_PATH = '/etc/krb5.conf.d/00-permitted-enctypes.conf'
KRB5CONF_ALLOW_RC4_PATH = '/etc/krb5.conf.d/01-allow-rc4.conf'
KDCCONF_PATH = '/var/kerberos/krb5kdc/kdc.conf'
TEST_KEYTAB = '/tmp/test.keytab'
CIFS_KEYTAB = '/tmp/cifs.keytab'

TESTUSER = 'testuser'
TESTPWD = 'Secret123'

AES_SHA1_LONG = ['aes256-cts-hmac-sha1-96', 'aes128-cts-hmac-sha1-96']
AES_SHA1_SHORT = ['aes256-cts', 'aes128-cts']
AES_SHA2_LONG = ['aes256-cts-hmac-sha384-192', 'aes128-cts-hmac-sha256-128']
AES_SHA2_SHORT = ['aes256-sha2', 'aes128-sha2']
AES_GROUP = ['aes']
RC4_LONG = ['arcfour-hmac']
RC4_SHORT = ['rc4']
CAMELLIA_LONG = ['camellia256-cts-cmac', 'camellia128-cts-cmac']
CAMELLIA_SHORT = ['camellia256-cts', 'camellia128-cts']
CAMELLIA = ['camellia']


def set_legacy_adsupport_cryptopol(host, enabled):
    host.run_command(['update-crypto-policies', '--set',
                      'LEGACY:AD-SUPPORT' if enabled else 'DEFAULT'])


def default_keytypes(expected_enctypes):
    return [e + ':special' for e in expected_enctypes]


def randkey_keytypes(expected_enctypes):
    return [e + ':normal' for e in expected_enctypes]


def supported_keytypes(expected_enctypes):
    return [e + ':' + s for e in expected_enctypes
            for s in ['special', 'normal']]


def set_permitted_enctypes(host, enctypes):
    host.put_file_contents(
        KRB5CONF_PATH,
        '[libdefaults]\npermitted_enctypes = {}'.format(' '.join(enctypes)))


def allow_rc4_session_if_needed(host, unabridged_enctypes):
    if unabridged_enctypes == RC4_LONG:
        # If RC4 is the only enctype, it must be allowed as session key for the
        # domain to work
        host.put_file_contents(KRB5CONF_ALLOW_RC4_PATH,
                               '[libdefaults]\nallow_rc4 = true')
    else:
        host.run_command(['rm', '-f', KRB5CONF_ALLOW_RC4_PATH])


def set_kdcconf_supported_enctypes(host, unabridged_enctypes):
    supptypes = supported_keytypes(unabridged_enctypes)
    host.run_command([
        'sed', '-i',
        r's/^\( *supported_enctypes *=\).*$/\1 %s/' % (' '.join(supptypes)),
        KDCCONF_PATH
    ])
    allow_rc4_session_if_needed(host, unabridged_enctypes)


def check_kadmin_log(host, attr, expected_enctypes):
    res = host.run_command(['tail', '-n100', '/var/log/kadmind.log'])
    p = re.compile(r'\(info\): ' + attr + r' = (.+)$', flags=re.MULTILINE)
    found_enctypes = p.findall(res.stdout_text)[-1].split(' ')
    assert found_enctypes == expected_enctypes


class KvnoState:

    def __init__(self):
        self.user = 0
        self.service = 0


@pytest.fixture(scope="class")
def kvnos():
    return KvnoState()


class KeyTypeTest(IntegrationTest):
    configured = []  # May contain abridged or family alias enctype names
    expected = []    # Only unabridged and single enctype names

    @classmethod
    def default_keytypes(cls):
        return default_keytypes(cls.expected)

    @classmethod
    def supported_keytypes(cls):
        return supported_keytypes(cls.expected)

    def check_keytab(self, path, expected_enctypes):
        res = self.master.run_command(['klist', '-ekt', path])
        p = re.compile(r'\(([\w:-]+)\) $', flags=re.MULTILINE)
        found_enctypes = p.findall(res.stdout_text)
        found_enctypes = [re.sub('^DEPRECATED:', '', e) for e in found_enctypes]
        assert found_enctypes == expected_enctypes

    def check_ipagkt_permitted_enctypes(self, expected_enctypes):
        res = self.master.run_command(['ipa-getkeytab', '--permitted-enctypes'])
        res.stdout_text.index('\n'.join(expected_enctypes))

    def check_kadmin_princ_keys(self, princname, kvno, expected_keytypes):
        res = self.master.run_command(['kadmin.local', 'getprinc', princname])
        displayed_keytypes = []
        for e in expected_keytypes:
            prefix = 'DEPRECATED:' if e.startswith('arcfour-hmac') else ''
            keytype = re.sub(r':normal$', '', e)
            displayed_keytypes.append(prefix + keytype)
        expected_output = '\n'.join(['Number of keys: '
                                     + str(len(displayed_keytypes))]
                                    + [f'Key: vno {kvno}, {e}'
                                       for e in displayed_keytypes])
        assert expected_output in res.stdout_text

    @classmethod
    def install(cls, mh):
        set_legacy_adsupport_cryptopol(cls.master,
                                       'arcfour-hmac' in cls.expected)
        set_permitted_enctypes(cls.master, cls.configured)
        allow_rc4_session_if_needed(cls.master, cls.expected)
        tasks.install_master(cls.master, setup_dns=False)

    def test_initial_tgs_keytypes(self):
        realm = self.master.domain.realm
        self.check_kadmin_princ_keys(f'krbtgt/{realm}@{realm}', 1,
                                     self.expected)

    def test_initial_admin_keytypes(self):
        self.check_kadmin_princ_keys('admin', 1, self.default_keytypes())

    def test_initial_ipagetkeytab_permitted_enctypes(self):
        self.check_ipagkt_permitted_enctypes(self.expected)

    def test_initial_ds_keytab(self):
        self.check_keytab('/etc/dirsrv/ds.keytab', self.expected)

    def test_initial_http_keytab(self):
        self.check_keytab('/var/lib/ipa/gssproxy/http.keytab', self.expected)

    # The list of default and supported key types is logged in the kadmind or
    # krb5kdc logs when a krb5 context is initialized.
    def test_initial_kdb_keytypes(self):
        self.master.run_command(['kadmin.local', 'quit'])
        check_kadmin_log(self.master, 'Default key types',
                         self.default_keytypes())
        check_kadmin_log(self.master, 'Supported key types',
                         self.supported_keytypes())

    def test_user_creation(self, kvnos):
        self.master.run_command(['ipa', 'user-add', '--first', 'Test',
                                 '--last', 'User', TESTUSER])
        self.master.run_command(['ipa', 'passwd', TESTUSER],
                                stdin_text=f'{TESTPWD}\n{TESTPWD}\n')
        kvnos.user += 1
        self.check_kadmin_princ_keys(TESTUSER, kvnos.user,
                                     self.default_keytypes())

    def test_gkt_created_service(self, kvnos):
        fqdn = self.master.hostname
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command(['ipa', 'service-add', '--force',
                                 f'test/{fqdn}'])
        self.master.run_command(['ipa-getkeytab', '-p', f'test/{fqdn}', '-k',
                                 TEST_KEYTAB])
        kvnos.service += 1
        self.check_keytab(TEST_KEYTAB, self.expected)
        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service,
                                     self.expected)

    # When randomizing keys using kadmin, ipadb_change_pwd() is not called.
    # kadmin will though a different execution flow where the list of types is
    # fetched from the "supported_enctypes" setting from kdc.conf for the realm.
    # It will use a NULL salt, which will be displayed as ":normal".
    def test_service_after_kadmin_cpw(self, kvnos):
        fqdn = self.master.hostname
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command(['kadmin.local', 'change_password', '-randkey',
                                 f'test/{fqdn}'])
        kvnos.service += 1
        self.master.run_command(['kadmin.local', 'ktadd', '-norandkey', '-k',
                                 TEST_KEYTAB, f'test/{fqdn}'])
        self.check_keytab(TEST_KEYTAB, self.expected)
        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service,
                                     self.expected)

    def test_service_after_gkt_cpw_w_pw(self, kvnos):
        fqdn = self.master.hostname
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command(['ipa-getkeytab', '-p', f'test/{fqdn}', '-k',
                                 TEST_KEYTAB, '-P'],
                                stdin_text=f'{TESTPWD}\n{TESTPWD}\n')
        kvnos.service += 1
        self.check_keytab(TEST_KEYTAB, self.expected)
        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service,
                                     self.default_keytypes())

    def test_service_after_gkt_cpw_wo_pw(self, kvnos):
        fqdn = self.master.hostname
        self.master.run_command(['rm', '-f', TEST_KEYTAB])
        self.master.run_command(['ipa-getkeytab', '-p', f'test/{fqdn}', '-k',
                                 TEST_KEYTAB])
        kvnos.service += 1
        self.check_keytab(TEST_KEYTAB, self.expected)
        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service,
                                     self.expected)

    # For CIFS principals, RC4 should be allowed even if not explicitly allowed
    # in permitted_enctypes
    def test_cifs_princ_rc4_allowed(self):
        if 'arcfour-hmac' in self.expected:
            return

        fqdn = self.master.hostname
        self.master.run_command(['ipa', 'service-add', '--force',
                                 f'cifs/{fqdn}'])
        self.master.run_command([
            'ipa-getkeytab', '-e',
            'arcfour-hmac,' + ','.join(self.expected), '-p',
            f'cifs/{fqdn}', '-k', CIFS_KEYTAB])
        self.check_keytab(CIFS_KEYTAB, self.expected + RC4_LONG)
        self.check_kadmin_princ_keys(
            f'cifs/{fqdn}', 1, self.expected + RC4_LONG)

    # If no multiple-enctypes aliases are used, then it should be possible to
    # reverse the list of permitted enctypes and the order of default/supported
    # keytypes and of keys themselves should be modified accordingly
    def test_reverse_keys_order(self, kvnos):
        if len(self.configured) == 1:
            return

        if len(self.configured) != len(self.expected):
            return

        fqdn = self.master.hostname
        rexpected = list(reversed(self.expected))

        self.master.run_command(['rm', '-f', TEST_KEYTAB])

        reversed_configured = list(reversed(self.configured))
        reversed_expected = list(reversed(self.expected))
        set_permitted_enctypes(self.master, reversed_configured)
        set_kdcconf_supported_enctypes(self.master, reversed_expected)
        tasks.restart_ipa_server(self.master)

        self.check_ipagkt_permitted_enctypes(rexpected)

        self.master.run_command(['kadmin.local', 'quit'])
        check_kadmin_log(self.master, 'Default key types',
                         default_keytypes(rexpected))
        check_kadmin_log(self.master, 'Supported key types',
                         supported_keytypes(rexpected))

        self.check_kadmin_princ_keys('admin', 1, default_keytypes(rexpected))

        self.check_kadmin_princ_keys(TESTUSER, kvnos.user,
                                     default_keytypes(rexpected))
        self.master.run_command(['ipa', 'passwd', TESTUSER],
                                stdin_text=f'{TESTPWD}\n{TESTPWD}\n')
        kvnos.user += 1
        self.check_kadmin_princ_keys(TESTUSER, kvnos.user,
                                     default_keytypes(rexpected))

        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service, rexpected)
        self.master.run_command(['ipa-getkeytab', '-p', f'test/{fqdn}', '-k',
                                 TEST_KEYTAB])
        kvnos.service += 1
        self.check_keytab(TEST_KEYTAB, rexpected)
        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service, rexpected)

        set_permitted_enctypes(self.master, self.configured)
        set_kdcconf_supported_enctypes(self.master, self.expected)
        tasks.restart_ipa_server(self.master)

        self.check_kadmin_princ_keys('admin', 1, self.default_keytypes())
        self.check_kadmin_princ_keys(TESTUSER, kvnos.user,
                                     self.default_keytypes())
        self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service,
                                     self.expected)

    # Try the other test configuration to confirm it affects the order of
    # default/ supported key types and keys accordingly
    def test_different_permitted_enctypes(self, kvnos):
        fqdn = self.master.hostname
        # pylint: disable-next=unused-variable
        for _, cls in inspect.getmembers(
                sys.modules[__name__],
                lambda c: (inspect.isclass(c)
                           and c is not KeyTypeTest
                           and issubclass(c, KeyTypeTest)
                           and set(self.expected).intersection(c.expected))):

            if 'arcfour-hmac' not in self.expected:
                set_legacy_adsupport_cryptopol(self.master,
                                               'arcfour-hmac' in cls.expected)
            set_permitted_enctypes(self.master, cls.configured)
            set_kdcconf_supported_enctypes(self.master, cls.expected)
            tasks.restart_ipa_server(self.master)

            self.check_ipagkt_permitted_enctypes(cls.expected)

            self.master.run_command(['kadmin.local', 'quit'])
            check_kadmin_log(self.master, 'Default key types',
                             cls.default_keytypes())
            check_kadmin_log(self.master, 'Supported key types',
                             cls.supported_keytypes())

            if set(self.expected) == set(cls.expected):
                self.check_kadmin_princ_keys('admin', 1, cls.default_keytypes())
                self.check_kadmin_princ_keys(TESTUSER, kvnos.user,
                                             cls.default_keytypes())
                self.check_kadmin_princ_keys(f'test/{fqdn}', kvnos.service,
                                             cls.expected)

        if 'arcfour-hmac' not in self.expected:
            set_legacy_adsupport_cryptopol(self.master, False)
        set_permitted_enctypes(self.master, self.configured)
        set_kdcconf_supported_enctypes(self.master, self.expected)
        tasks.restart_ipa_server(self.master)

    @classmethod
    def uninstall(cls, mh):
        set_legacy_adsupport_cryptopol(cls.master,
                                       'arcfour-hmac' in cls.expected)
        set_permitted_enctypes(cls.master, cls.configured)
        set_kdcconf_supported_enctypes(cls.master, cls.expected)
        try:
            tasks.restart_ipa_server(cls.master)
        except Exception:
            # In case of a broken install, it will likely not be able to restart
            pass
        cls.master.run_command(['rm', '-f', KRB5CONF_PATH, TEST_KEYTAB,
                                CIFS_KEYTAB])
        try:
            super().uninstall(mh)
        finally:
            set_legacy_adsupport_cryptopol(cls.master, False)


class TestKeyTypeAesSha1Long(KeyTypeTest):
    configured = AES_SHA1_LONG
    expected = AES_SHA1_LONG


class TestKeyTypeAesSha1Short(KeyTypeTest):
    configured = AES_SHA1_SHORT
    expected = AES_SHA1_LONG


class TestKeyTypeAesSha2Long(KeyTypeTest):
    configured = AES_SHA2_LONG
    expected = AES_SHA2_LONG


class TestKeyTypeAesSha2Short(KeyTypeTest):
    configured = AES_SHA2_SHORT
    expected = AES_SHA2_LONG


class TestKeyTypeAes(KeyTypeTest):
    configured = AES_GROUP
    expected = AES_SHA1_LONG + AES_SHA2_LONG


class TestKeyTypeRc4Long(KeyTypeTest):
    configured = RC4_LONG
    expected = RC4_LONG


class TestKeyTypeRc4Short(KeyTypeTest):
    configured = RC4_SHORT
    expected = RC4_LONG


class TestKeyTypeCamelliaLong(KeyTypeTest):
    configured = CAMELLIA_LONG
    expected = CAMELLIA_LONG


class TestKeyTypeCamelliaShort(KeyTypeTest):
    configured = CAMELLIA_SHORT
    expected = CAMELLIA_LONG


class TestKeyTypeCamellia(KeyTypeTest):
    configured = CAMELLIA
    expected = CAMELLIA_LONG


class TestKeyTypeAesSha2LongAesSha1LongCamelliaLong(KeyTypeTest):
    configured = AES_SHA2_LONG + AES_SHA1_LONG + CAMELLIA_LONG
    expected = AES_SHA2_LONG + AES_SHA1_LONG + CAMELLIA_LONG


class TestKeyTypeAesSha2LongAesSha1LongCamelliaLongRc4Long(KeyTypeTest):
    configured = AES_SHA2_LONG + AES_SHA1_LONG + CAMELLIA_LONG + RC4_LONG
    expected = AES_SHA2_LONG + AES_SHA1_LONG + CAMELLIA_LONG + RC4_LONG


class TestKeyTypeAesCamellia(KeyTypeTest):
    configured = AES_GROUP + CAMELLIA
    expected = AES_SHA1_LONG + AES_SHA2_LONG + CAMELLIA_LONG


class TestKeyTypeAesCamelliaRc4(KeyTypeTest):
    configured = AES_GROUP + CAMELLIA + RC4_SHORT
    expected = AES_SHA1_LONG + AES_SHA2_LONG + CAMELLIA_LONG + RC4_LONG


class TestKeyTypeAesSha2ShortAesSha1ShortRc4(KeyTypeTest):
    configured = AES_SHA2_SHORT + AES_SHA1_SHORT + RC4_SHORT
    expected = AES_SHA2_LONG + AES_SHA1_LONG + RC4_LONG
