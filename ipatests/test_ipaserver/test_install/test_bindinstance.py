#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Test the BIND version detection of `ipaserver.install.bindinstance`.
"""

import os
from unittest import mock

import pytest

from ipaplatform.paths import paths
from ipapython import ipautil
from ipaserver.install import bindinstance

pytestmark = pytest.mark.tier0

DELEGATION_ONLY = "category delegation-only { named; };"
_real_exists = os.path.exists


def named_installed(installed):
    """Patch os.path.exists for the named binary only."""
    def exists(path):
        if path == paths.NAMED:
            return installed
        return _real_exists(path)
    return mock.patch('os.path.exists', side_effect=exists)


@pytest.fixture
def bind():
    instance = bindinstance.BindInstance(fstore=mock.Mock(), api=mock.Mock())
    with mock.patch.object(bindinstance.BindInstance,
                           '_get_dnssec_validation', return_value='yes'):
        yield instance


def setup(instance):
    instance.setup_templating(
        fqdn='ipa.example.test', realm_name='EXAMPLE.TEST',
        domain_name='example.test')
    return instance.sub_dict


def test_named_not_installed(bind):
    """Servers without the DNS role have no named binary (upgrade)."""
    with named_installed(False), mock.patch.object(ipautil, 'run') as run:
        sub_dict = setup(bind)
    run.assert_not_called()
    assert sub_dict['FQDN'] == 'ipa.example.test'
    assert sub_dict['NAMED_DELEGATION_ONLY_CATEGORY'] == DELEGATION_ONLY


@pytest.mark.parametrize('version,category', [
    ('9.18.30', DELEGATION_ONLY),
    ('9.20.4', ''),
])
def test_named_version(bind, version, category):
    output = 'BIND {} (Extended Support Version) <id:>\n'.format(version)
    with named_installed(True), mock.patch.object(
            ipautil, 'run', return_value=mock.Mock(output=output)):
        sub_dict = setup(bind)
    assert sub_dict['NAMED_DELEGATION_ONLY_CATEGORY'] == category


def test_named_version_unparsable(bind):
    with named_installed(True), mock.patch.object(
            ipautil, 'run', return_value=mock.Mock(output='garbage')):
        with pytest.raises(RuntimeError, match="Couldn't parse BIND version"):
            setup(bind)
