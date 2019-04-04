#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""HSM support for Dogtag PKI
"""
from __future__ import absolute_import

import os
import logging

from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaplatform.tasks import tasks as platformtasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

logger = logging.getLogger(__name__)

SELINUX_ENABLED = platformtasks.is_selinux_enabled()
SOFTHSM_DIR = '/var/lib/softhsm'
TOKEN_DIR = os.path.join(SOFTHSM_DIR, 'tokens')

TOKEN_NAME = "softhsm_token"
TOKEN_PIN = "TokenSecret123"
TOKEN_SO_PIN = "TokenSOSecret123"

SOFTHSM2_PKI_INI = """\
[DEFAULT]
pki_hsm_enable=True
pki_hsm_libfile={libfile}
pki_hsm_modulename=softhsm2
pki_token_name={name}
pki_token_password={pin}
""".format(
    libfile=paths.LIBSOFTHSM2_SO,
    name=TOKEN_NAME,
    pin=TOKEN_PIN
)

SOFTHSM_CMD = [
    'runuser', '-u', constants.PKI_USER, '--', paths.SOFTHSM2_UTIL,
]


def prepare_softhsm(host, token_name=TOKEN_NAME, token_pin=TOKEN_PIN,
                    token_so_pin=TOKEN_SO_PIN):
    """Prepare host for softhsm2
    """
    # HACK: patch Dogtag
    # https://github.com/frasertweedale/pki/commit/443bfa1f20a0fa0d020893f0e827d7cf3e76e2f4
    host.run_command([
        'sed', '-i',
        r's,token = pki\.nssdb\.normalize_token(token),,',
        '/usr/lib/python3.7/site-packages/pki/server/deployment/pkiparser.py'
    ])
    # HACK: Workaround for https://pagure.io/dogtagpki/issue/3091, disable
    # p11-kit-proxy so that Dogtag is able to install SoftHSM2 PKCS#11.
    # host.run_command([
    #     'rm', '-f', '/etc/crypto-policies/local.d/nss-p11-kit.config'
    # ])
    # host.run_command(['update-crypto-policies'])

    # HACK: add pkiuser to ods group, so it can create softhsm tokens
    # see https://bugzilla.redhat.com/show_bug.cgi?id=1625548
    host.run_command([
        'usermod', '-G', constants.ODS_GROUP, '-a', constants.PKI_USER
    ])
    # HACK: remove existing dummy token for DNSSEC to reduce SELinux noise
    # IPA uses different token directory for its DNSSEC keys.
    # use sh for wildcard expansion.
    host.run_command([
        'sh', '-c', 'rm -rf {}'.format(os.path.join(TOKEN_DIR, '*'))
    ])
    # HACK: change SELinux context from default named_cache_t to pki_tomcat_t
    # to avoid AVCs for certutil and pkitool
    host.run_command(['restorecon', '-rv', SOFTHSM_DIR])
    # chcon_cmd = [
    #     'chcon', '--recursive', '--verbose',
    #     'unconfined_u:object_r:pki_tomcat_var_lib_t:s0',
    #     SOFTHSM_DIR
    # ]
    # host.run_command(chcon_cmd)

    # create softhsm token as pkiuser
    cmd = list(SOFTHSM_CMD)
    cmd.extend([
        '--init-token', '--free',
        '--pin', token_pin,
        '--so-pin', token_so_pin,
        '--label', token_name,
    ])
    host.run_command(cmd)
    # HACK: chcon again
    host.run_command(['restorecon', '-rv', SOFTHSM_DIR])
    # host.run_command(chcon_cmd)

    # verify the softhsm token
    cmd = list(SOFTHSM_CMD)
    cmd.append('--show-slots')
    result = host.run_command(cmd)
    assert token_name in result.stdout_text
    host.run_command(['ls', '-laRZ', SOFTHSM_DIR])

    # collect more files for debugging
    host.collect_log(SOFTHSM_DIR)
    host.collect_log(paths.CA_CS_CFG_PATH)

    # upload ini override
    pki_ini = tasks.upload_temp_contents(host, SOFTHSM2_PKI_INI)
    return pki_ini


class TestHSMSupport(IntegrationTest):
    @classmethod
    def install(cls, mh):
        cls.pki_ini = prepare_softhsm(cls.master)
        extra_args = [
            '--pki-config-override', cls.pki_ini,
        ]
        result = tasks.install_master(
            cls.master, setup_dns=False, extra_args=extra_args,
            raiseonerr=False
        )
        cls.debug_softhsm2(cls.master)
        assert result.returncode == 0

    @classmethod
    def debug_softhsm2(cls, host):
        cls.master.run_command([
            'ls', '-laRZ', SOFTHSM_DIR
        ])
        cls.master.run_command([paths.SOFTHSM2_UTIL, '--show-slots'])
        certs, keys = tasks.certutil_certs_keys(
            host,
            paths.PKI_TOMCAT_ALIAS_DIR,
            TOKEN_PIN,
            token_name=TOKEN_NAME
        )
        print(certs)
        print(keys)
        result = tasks.run_certutil(host, ['-L'], paths.PKI_TOMCAT_ALIAS_DIR)
        print(result.stdout_text)

    def test_hsm_certutil(self):
        certs, keys = tasks.certutil_certs_keys(
            self.master,
            paths.PKI_TOMCAT_ALIAS_DIR,
            paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT
        )
        assert certs == {
            'caSigningCert cert-pki-ca': 'CT,C,C',
            'auditSigningCert cert-pki-ca': ',,P',  # why P?
            'Server-Cert cert-pki-ca': 'u,u,u'
        }
        assert len(keys) == 1
        serverkey = list(keys)[0]
        assert 'Server-Cert cert-pki-ca' in serverkey

        certs, keys = tasks.certutil_certs_keys(
            self.master,
            paths.PKI_TOMCAT_ALIAS_DIR,
            TOKEN_PIN,
            token_name=TOKEN_NAME
        )
        assert certs == {
            TOKEN_NAME + ':ocspSigningCert cert-pki-ca': 'u,u,u',
            TOKEN_NAME + ':caSigningCert cert-pki-ca': 'CTu,Cu,Cu',
            TOKEN_NAME + ':subsystemCert cert-pki-ca': 'u,u,u',
            TOKEN_NAME + ':auditSigningCert cert-pki-ca': 'u,u,Pu',
        }
        assert set(keys) == {
            'ocspSigningCert cert-pki-ca',
            'caSigningCert cert-pki-ca',
            'subsystemCert cert-pki-ca',
            'auditSigningCert cert-pki-ca',
        }

        self.master.run_command([paths.GETCERT, 'list'])
