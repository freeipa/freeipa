#
# Copyright (C) 2018  FreeIPA Contributors.  See COPYING for license
#

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from ipalib import api
from ipaplatform.paths import paths
from ipaserver.install import bindinstance as bind_i
from ipaserver.install.server.upgrade import named_add_ipa_ext_conf_file

share_dir = Path(api.env.ipalib).parent / 'install/share'


@pytest.fixture
def namedconf():
    custom_conf_src = paths.NAMED_CUSTOM_CFG_SRC
    custom_options_conf_src = paths.NAMED_CUSTOM_OPTIONS_CFG_SRC
    if api.env.in_tree:
        custom_conf_src = share_dir / 'bind.ipa-ext.conf'
        custom_options_conf_src = \
            share_dir / 'bind.ipa-options-ext.conf.template'

    tmp_f1 = tempfile.NamedTemporaryFile('w', delete=False)
    os.unlink(tmp_f1.name)

    tmp_f2 = tempfile.NamedTemporaryFile('w', delete=False)
    os.unlink(tmp_f2.name)

    with patch.multiple(
            paths,
            NAMED_CUSTOM_CFG_SRC=custom_conf_src,
            NAMED_CUSTOM_OPTIONS_CFG_SRC=custom_options_conf_src,
            NAMED_CUSTOM_CONFIG=tmp_f1.name,
            NAMED_CUSTOM_OPTIONS_CONFIG=tmp_f2.name,
    ):
        yield tmp_f1.name

    tmp_f1.close()
    if os.path.exists(tmp_f1.name):
        os.unlink(tmp_f1.name)

    tmp_f2.close()
    if os.path.exists(tmp_f2.name):
        os.unlink(tmp_f2.name)


@patch('pwd.getpwnam')
@patch('os.chmod')
@patch('os.chown')
def test_named_ipa_ext_config(_chown, _chmod, _getpwnam, namedconf):
    res = bind_i.named_add_ext_conf_file(paths.NAMED_CUSTOM_CFG_SRC,
                                         paths.NAMED_CUSTOM_CONFIG)

    assert res


@patch('pwd.getpwnam')
@patch('os.chmod')
@patch('os.chown')
def test_named_ipa_options_ext_config(_chmod, _chown, _getpwnam, namedconf):
    required_params = {'NAMED_DNSSEC_VALIDATION': 'yes'}
    res = bind_i.named_add_ext_conf_file(paths.NAMED_CUSTOM_OPTIONS_CFG_SRC,
                                         paths.NAMED_CUSTOM_OPTIONS_CONFIG,
                                         required_params)

    assert res


@patch('ipaserver.install.bindinstance.named_conf_exists')
@patch('pwd.getpwnam')
@patch('os.chmod')
@patch('os.chown')
def test_named_add_ipa_ext_conf_file(_chown, _chmod, _getpwnam,
                                     named_conf_exists,
                                     namedconf):
    named_conf_exists.return_value = True

    named_conf_state = {
        'dnssec-validation': 'yes'
    }

    res = named_add_ipa_ext_conf_file(named_conf_state)

    assert res
