#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
import os
import sys

import pytest

import ipaplatform.constants
import ipaplatform.paths
import ipaplatform.services
import ipaplatform.tasks
from ipaplatform._importhook import metaimporter
try:
    from ipaplatform.override import OVERRIDE
except ImportError:
    OVERRIDE = None


HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')


@pytest.mark.skipif(OVERRIDE is None,
                    reason='test requires override')
def test_override():
    assert OVERRIDE == metaimporter.platform_ids[0]
    assert OVERRIDE == metaimporter.platform


@pytest.mark.parametrize('mod, name', [
    (ipaplatform.constants, 'ipaplatform.constants'),
    (ipaplatform.paths, 'ipaplatform.paths'),
    (ipaplatform.services, 'ipaplatform.services'),
    (ipaplatform.tasks, 'ipaplatform.tasks'),
])
def test_importhook(mod, name):
    assert name in metaimporter.modules
    prefix, suffix = name.split('.')
    assert prefix == 'ipaplatform'
    override = '.'.join((prefix, metaimporter.platform, suffix))
    assert mod.__name__ == override
    # dicts are equal, modules may not be identical
    assert mod.__dict__ == sys.modules[override].__dict__


@pytest.mark.parametrize('filename, expected_platforms', [
    (os.path.join(DATA, 'os-release-centos'), ['centos', 'rhel', 'fedora']),
    (os.path.join(DATA, 'os-release-fedora'), ['fedora']),
    (os.path.join(DATA, 'os-release-ubuntu'), ['ubuntu', 'debian']),
])
def test_parse_os_release(filename, expected_platforms):
    parsed = metaimporter._parse_osrelease(filename)
    assert parsed == expected_platforms
