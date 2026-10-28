#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import os
import sys

import pytest

import ipaplatform.constants
import ipaplatform.paths
import ipaplatform.services
import ipaplatform.tasks
from ipaplatform._importhook import metaimporter
from ipaplatform.osinfo import osinfo, _parse_osrelease
try:
    from ipaplatform.override import OVERRIDE
except ImportError:
    OVERRIDE = None


HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, 'data')


@pytest.mark.skipif(OVERRIDE is None,
                    reason='test requires override')
def test_override():
    assert OVERRIDE == osinfo.platform_ids[0]
    assert OVERRIDE == osinfo.platform


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


@pytest.mark.parametrize('filename, id_, id_like', [
    (os.path.join(DATA, 'os-release-centos'), 'centos', ('rhel', 'fedora')),
    (os.path.join(DATA, 'os-release-fedora'), 'fedora', ()),
    (os.path.join(DATA, 'os-release-ubuntu'), 'ubuntu', ('debian',)),
])
def test_parse_os_release(filename, id_, id_like):
    parsed = _parse_osrelease(filename)
    assert parsed['ID'] == id_
    assert parsed['ID_LIKE'] == id_like
