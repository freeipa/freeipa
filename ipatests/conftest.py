#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import print_function

import os
import pprint
import shutil
import sys
import tempfile

import pytest

from ipalib import api
from ipalib.cli import cli_plugins
import ipatests.util

try:
    import ipaplatform  # pylint: disable=unused-import
except ImportError:
    ipaplatform = None


HERE = os.path.dirname(os.path.abspath(__file__))

pytest_plugins = [
    'ipatests.pytest_ipa.additional_config',
    'ipatests.pytest_ipa.slicing',
    'ipatests.pytest_ipa.beakerlib',
    'ipatests.pytest_ipa.declarative',
    'ipatests.pytest_ipa.nose_compat',
    'ipatests.pytest_ipa.integration',
    'pytester',
]


MARKERS = [
    'tier0: basic unit tests and critical functionality',
    'tier1: functional API tests',
    'cs_acceptance: Acceptance test suite for Dogtag Certificate Server',
    'ds_acceptance: Acceptance test suite for 389 Directory Server',
    'skip_ipaclient_unittest: Skip in ipaclient unittest mode',
    'needs_ipaapi: Test needs IPA API',
]


NO_RECURSE_DIRS = [
    # build directories
    'ipaclient/build',
    'ipalib/build',
    'ipaplatform/build',
    'ipapython/build',
    'ipaserver/build',
    'ipatests/build',
    # install/share/wsgi.py
    'install/share',
    # integration plugin imports from ipaplatform
    'ipatests/pytest_ipa',
]


INIVALUES = {
    'python_classes': ['test_', 'Test'],
    'python_files': ['test_*.py'],
    'python_functions': ['test_*'],
}


def pytest_configure(config):
    # add pytest markers
    for marker in MARKERS:
        config.addinivalue_line('markers', marker)

    # do not recurse into build directories or install/share directory.
    for norecursedir in NO_RECURSE_DIRS:
        config.addinivalue_line('norecursedirs', norecursedir)

    # addinivalue_line() adds duplicated entries and does not remove existing.
    for name, values in INIVALUES.items():
        current = config.getini(name)
        current[:] = values

    # set default JUnit prefix
    if config.option.junitprefix is None:
        config.option.junitprefix = 'ipa'

    # always run doc tests
    config.option.doctestmodules = True

    # apply global options
    ipatests.util.SKIP_IPAAPI = config.option.skip_ipaapi
    ipatests.util.IPACLIENT_UNITTESTS = config.option.ipaclient_unittests
    ipatests.util.PRETTY_PRINT = config.option.pretty_print


def pytest_addoption(parser):
    group = parser.getgroup("IPA integration tests")
    group.addoption(
        '--ipaclient-unittests',
        help='Run ipaclient unit tests only (no RPC and ipaserver)',
        action='store_true'
    )
    group.addoption(
        '--skip-ipaapi',
        help='Do not run tests that depends on IPA API',
        action='store_true',
    )


def pytest_cmdline_main(config):
    kwargs = dict(
        context=u'cli', in_server=False, in_tree=True, fallback=False
    )
    if not os.path.isfile(os.path.expanduser('~/.ipa/default.conf')):
        # dummy domain/host for machines without ~/.ipa/default.conf
        kwargs.update(domain=u'ipa.test', server=u'master.ipa.test')

    api.bootstrap(**kwargs)
    for klass in cli_plugins:
        api.add_plugin(klass)

    # XXX workaround until https://fedorahosted.org/freeipa/ticket/6408 has
    # been resolved.
    if os.path.isfile(api.env.conf_default):
        api.finalize()

    if config.option.verbose:
        print('api.env: ')
        pprint.pprint({k: api.env[k] for k in api.env})
        print("uname: {}".format(os.uname()))
        print("euid: {}, egid: {}".format(os.geteuid(), os.getegid()))
        print("working dir: {}".format(os.path.abspath(os.getcwd())))
        print('sys.version: {}'.format(sys.version))


def pytest_runtest_setup(item):
    if isinstance(item, pytest.Function):
        # pytest 3.6 has deprecated get_marker in 3.6. The method was
        # removed in 4.x and replaced with get_closest_marker.
        if hasattr(item, 'get_closest_marker'):
            get_marker = item.get_closest_marker  # pylint: disable=no-member
        else:
            get_marker = item.get_marker  # pylint: disable=no-member
        if get_marker('skip_ipaclient_unittest'):
            # pylint: disable=no-member
            if item.config.option.ipaclient_unittests:
                pytest.skip("Skip in ipaclient unittest mode")
        if get_marker('needs_ipaapi'):
            # pylint: disable=no-member
            if item.config.option.skip_ipaapi:
                pytest.skip("Skip tests that needs an IPA API")


@pytest.fixture
def tempdir(request):
    tempdir = tempfile.mkdtemp()

    def fin():
        shutil.rmtree(tempdir)

    request.addfinalizer(fin)
    return tempdir
