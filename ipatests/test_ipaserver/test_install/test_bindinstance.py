#
# Copyright (C) 2018  FreeIPA Contributors.  See COPYING for license
#

import tempfile

import pytest

from ipaplatform.paths import paths
from ipaserver.install.server.upgrade import named_add_crypto_policy

try:
    from unittest.mock import patch  # pylint: disable=import-error
except ImportError:
    from mock import patch  # pylint: disable=import-error


TEST_CONFIG = """
options {
\tdnssec-enable yes;
\tdnssec-validation yes;
};

include "random/file";
"""


EXPECTED_CONFIG = """
options {
\tdnssec-enable yes;
\tdnssec-validation yes;
\tinclude "/etc/crypto-policies/back-ends/bind.config";
};

include "random/file";
"""

POLICY_FILE = "/etc/crypto-policies/back-ends/bind.config"


@pytest.fixture
def namedconf():
    with tempfile.NamedTemporaryFile('w+') as f:
        with patch.multiple(paths,
                            NAMED_CONF=f.name,
                            NAMED_CRYPTO_POLICY_FILE=POLICY_FILE):
            yield f.name


@patch('ipaserver.install.sysupgrade.get_upgrade_state')
@patch('ipaserver.install.sysupgrade.set_upgrade_state')
def test_add_crypto_policy(m_set, m_get, namedconf):
    m_get.return_value = False
    with open(namedconf, 'w') as f:
        f.write(TEST_CONFIG)

    named_add_crypto_policy()
    m_get.assert_called_with('named.conf', 'add_crypto_policy')
    m_set.assert_called_with('named.conf', 'add_crypto_policy', True)

    with open(namedconf) as f:
        content = f.read()
    assert content == EXPECTED_CONFIG

    m_get.reset_mock()
    m_set.reset_mock()

    m_get.return_value = True
    named_add_crypto_policy()
    m_get.assert_called_with('named.conf', 'add_crypto_policy')
    m_set.assert_not_called()
