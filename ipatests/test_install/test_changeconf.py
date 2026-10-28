# Copyright (C) 2018  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import pytest
from ipapython.ipachangeconf import IPAChangeConf


@pytest.fixture(scope='function')
def config_filename(tmpdir):
    filename = tmpdir.mkdir('data').join('config_file.conf')
    filename.write('SOME_CONF /some/user/defined/path\n')
    return filename


def test_addifnotset_action(config_filename):
    """Test if addifnotset action adds a comment about the modified conf.

    IPA doesn't want to break existing configuration, if a value already exists
    it adds a comment to the modified setting and a note about that on the line
    above.

    New settings will be added without any note.
    """
    ipa_conf = IPAChangeConf('IPA Installer Test')
    ipa_conf.setOptionAssignment(' ')

    opts = [
        {
            'action': 'addifnotset',
            'name': 'SOME_CONF',
            'type': 'option',
            'value': '/path/defined/by/ipa',
        },
        {
            'action': 'addifnotset',
            'name': 'NEW_CONF',
            'type': 'option',
            'value': '/path/to/somewhere',
        },
    ]

    ipa_conf.changeConf(str(config_filename), opts)

    assert config_filename.readlines() == [
        '# SOME_CONF modified by IPA\n',
        '#SOME_CONF /path/defined/by/ipa\n',
        'SOME_CONF /some/user/defined/path\n',
        'NEW_CONF /path/to/somewhere\n',
    ]
