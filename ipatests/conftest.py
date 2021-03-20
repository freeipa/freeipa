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
    osinfo = None
else:
    from ipaplatform.osinfo import osinfo


HERE = os.path.dirname(os.path.abspath(__file__))


class PytestIPADeprecationWarning(pytest.PytestWarning, DeprecationWarning):
    """Warning class for features that will be removed in a future version."""

pytest_plugins = [
    'ipatests.pytest_ipa.additional_config',
    'ipatests.pytest_ipa.deprecated_frameworks',
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
    ('skip_if_platform(platform, reason): Skip test on platform '
     '(ID and ID_LIKE)'),
    ('skip_if_container(type, reason): Skip test on container '
     '("any" or specific type)'),
    # markers only for integration tests
    (
        "skip_if_hostplatform("
        "host attribute name within IntegrationTest, "
        "index of host within hosts list if required, "
        "platform name, "
        "reason): "
        "Skip integration test on remote platform (ID and ID_LIKE)"
    ),
    (
        "skip_if_hostcontainer("
        "host attribute name within IntegrationTest, "
        "index of host within hosts list if required, "
        "container type, "
        "reason): "
        "Skip integration test on remote container ('any' or specific type)"
    ),
    (
        "skip_if_hostfips("
        "host attribute name within IntegrationTest, "
        "index of host within hosts list if required, "
        "reason): "
        "Skip integration test on remote host in FIPS mode"
    ),
    (
        "skip_if_not_hostselinux("
        "host attribute name within IntegrationTest, "
        "index of host within hosts list if required, "
        "reason): "
        "Skip integration test on remote host not in SELinux mode"
    ),
    (
        "skip_if_host("
        "host attribute name within IntegrationTest, "
        "index of host within hosts list if required, "
        "condition callback, "
        "reason): "
        "Skip integration test on remote host based on condition callback "
        "result"
    ),
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
    'ipatests/azure',
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
        context=u'cli', in_server=False, fallback=False
    )
    # FIXME: workaround for https://pagure.io/freeipa/issue/8317
    kwargs.update(in_tree=True)
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
        if item.get_closest_marker('skip_ipaclient_unittest'):
            if item.config.option.ipaclient_unittests:
                pytest.skip("Skip in ipaclient unittest mode")
        if item.get_closest_marker('needs_ipaapi'):
            if item.config.option.skip_ipaapi:
                pytest.skip("Skip tests that needs an IPA API")
    if osinfo is not None:
        tests_dir = item.nodeid.split(os.sep, 1)[0]
        for mark in item.iter_markers(name="skip_if_platform"):
            if tests_dir in {"test_integration"}:
                raise ValueError(
                    f"Marker '{mark.name}' is not intended for "
                    f"test_integration. Please, consider host markers:\n"
                    "ipa-run-tests --markers"
                )
            platform = mark.kwargs.get("platform")
            if platform is None:
                platform = mark.args[0]
            reason = mark.kwargs["reason"]
            if platform in osinfo.platform_ids:
                pytest.skip(f"Skip test on platform {platform}: {reason}")
        for mark in item.iter_markers(name="skip_if_container"):
            if tests_dir in {"test_integration"}:
                raise ValueError(
                    f"Marker '{mark.name}' is not intended for "
                    f"test_integration. Please, consider host markers:\n"
                    "ipa-run-tests --markers"
                )
            container = mark.kwargs.get("container")
            if container is None:
                container = mark.args[0]
            reason = mark.kwargs["reason"]
            if osinfo.container is not None:
                if container in ('any', osinfo.container):
                    pytest.skip(
                        f"Skip test on '{container}' container type: {reason}")


def process_hostmarker(pytest_mark, pytest_nodeid, pytest_cls):
    tests_dir = pytest_nodeid.split(os.sep, 1)[0]
    if tests_dir not in {"test_integration"}:
        raise ValueError(
            f"Marker '{pytest_mark.name}' is intended only for "
            f"integration tests and can't be applied for '{tests_dir}'"
        )
    hostattr = pytest_mark.kwargs.get("host")
    if hostattr is None:
        hostattr = pytest_mark.args[0]

    hostattr_value = getattr(pytest_cls, hostattr)
    hostindex = pytest_mark.kwargs.get("hostindex")
    if hostindex is not None:
        host = hostattr_value[int(hostindex)]
    else:
        host = hostattr_value

    reason = pytest_mark.kwargs["reason"]

    if pytest_mark.name == "skip_if_hostplatform":
        platform = pytest_mark.kwargs["platform"]
        if platform in host.osinfo.platform_ids:
            pytest.skip(
                f"{pytest_nodeid}: {host.hostname}: {platform}: {reason}"
            )

    elif pytest_mark.name == "skip_if_hostcontainer":
        container = pytest_mark.kwargs["container"]
        if container in ["any", host.osinfo.container]:
            pytest.skip(
                f"{pytest_nodeid}: {host.hostname}: {container}: {reason}"
            )

    elif pytest_mark.name == "skip_if_hostfips":
        if host.is_fips_mode:
            pytest.skip(f"{pytest_nodeid}: {host.hostname}: {reason}")

    elif pytest_mark.name == "skip_if_not_hostselinux":
        if not host.is_selinux_enabled:
            pytest.skip(f"{pytest_nodeid}: {host.hostname}: {reason}")

    elif pytest_mark.name == "skip_if_host":
        condition_cb = pytest_mark.kwargs["condition_cb"]
        if condition_cb(host):
            pytest.skip(f"{pytest_nodeid}: {host.hostname}: {reason}")
    else:
        raise ValueError(f"Unsupported Pytest marker '{pytest_mark.name}'")


def pytest_runtest_call(item):
    """
    'mh' fixture is not ready for processing at 'pytest_runtest_setup' hook,
    but it is too late at 'pytest_runtest_call' one because the time-expensive
    `install` call has been done for class level fixtures/markers. Thus, the
    host markers should be handled *before* the installation phase of
    integration tests to be applied on class level (see 'process_hostmarkers' of
    'mh' fixture). The method level markers are processed here.
    """
    # process only own_markers to avoid double checking.
    for mark in item.own_markers:
        if mark.name in {
            "skip_if_hostplatform",
            "skip_if_hostcontainer",
            "skip_if_hostfips",
            "skip_if_not_hostselinux",
            "skip_if_host",
        }:
            process_hostmarker(
                mark, pytest_nodeid=item.nodeid, pytest_cls=item.cls
            )


@pytest.fixture
def tempdir(request):
    tempdir = tempfile.mkdtemp()

    def fin():
        shutil.rmtree(tempdir)

    request.addfinalizer(fin)
    return tempdir
