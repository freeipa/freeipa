#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

import os
import shutil
import tempfile

import pytest

from ipaplatform.paths import paths

import ipatests.util
ipatests.util.check_ipaclient_unittests()  # noqa: E402

from ipaclient.install.client import configure_openldap_conf

# with single URI and space
LDAP_CONF_1 = """
#
# LDAP Defaults
#

BASE dc=example,dc=com
URI ldap://ldap.example.com

# Turning this off breaks GSSAPI used with krb5 when rdns = false
SASL_NOCANON    on
"""

# URI with two entries and tabs
LDAP_CONF_2 = """
#
# LDAP Defaults
#

BASE\tdc=example,dc=com
URI\tldap://ldap.example.com ldap://ldap-master.example.com:666

# Turning this off breaks GSSAPI used with krb5 when rdns = false
SASL_NOCANON    on
"""

BASEDN = 'cn=ipa,cn=example'
SERVER = 'ldap.ipa.example'


class DummyFStore:
    def backup_file(self, fname):
        pass


def ldap_conf(content):
    # fixture tmp_path is pytest >= 3.9
    tmp_path = tempfile.mkdtemp()
    cfgfile = os.path.join(tmp_path, 'ldap.conf')
    if content is not None:
        with open(cfgfile, 'w') as f:
            f.write(content)
    orig_ldap_conf = paths.OPENLDAP_LDAP_CONF
    try:
        paths.OPENLDAP_LDAP_CONF = cfgfile
        configure_openldap_conf(DummyFStore(), BASEDN, [SERVER])

        with open(cfgfile) as f:
            text = f.read()

        settings = {}
        for line in text.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            k, v = line.split(None, 1)
            settings.setdefault(k, []).append(v)
    finally:
        paths.OPENLDAP_LDAP_CONF = orig_ldap_conf
        shutil.rmtree(tmp_path)
    return text, settings


def test_openldap_conf_empty():
    text, settings = ldap_conf("")
    assert '# File modified by ipa-client-install' in text
    assert settings == {
        'BASE': [BASEDN],
        'URI': ['ldaps://{}'.format(SERVER)],
        'TLS_CACERT': ['/etc/ipa/ca.crt'],
        'SASL_MECH': ['GSSAPI']
    }


def test_openldap_conf_spaces():
    text, settings = ldap_conf(LDAP_CONF_1)
    assert '# File modified by ipa-client-install' in text
    assert settings == {
        'BASE': ['dc=example,dc=com'],
        'URI': ['ldap://ldap.example.com'],
        'SASL_NOCANON': ['on'],
        'TLS_CACERT': ['/etc/ipa/ca.crt'],
        'SASL_MECH': ['GSSAPI']
    }


@pytest.mark.xfail(reason="freeipa ticket 7838", strict=True)
def test_openldap_conf_mixed():
    text, settings = ldap_conf(LDAP_CONF_2)
    assert '# File modified by ipa-client-install' in text
    assert settings == {
        'BASE': ['dc=example,dc=com'],
        'URI': ['ldap://ldap.example.com ldap://ldap-master.example.com:666'],
        'SASL_NOCANON': ['on'],
        'TLS_CACERT': ['/etc/ipa/ca.crt'],
        'SASL_MECH': ['GSSAPI']
    }
