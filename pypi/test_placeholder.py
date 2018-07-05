# Copyright (C) 2017  FreeIPA Contributors see COPYING for license

import importlib

import pkg_resources

import pytest

@pytest.mark.parametrize("modname", [
    # placeholder packages raise ImportError
    'ipaserver',
    'ipatests',
    # PyPI packages do not have install subpackage
    'ipaclient.install',
    'ipalib.install',
    'ipapython.install',
    # override module should not be shipped in wheels
    'ipaplatform.override',
])
def test_fail_import(modname):
    try:
        importlib.import_module(modname)
    except ImportError:
        pass
    else:
        pytest.fail("'import {}' does not fail".format(modname))


@pytest.mark.parametrize("modname", [
    'ipaclient',
    'ipalib',
    'ipaplatform',
    'ipapython',
])
def test_import(modname):
    importlib.import_module(modname)


@pytest.mark.parametrize("pkgname", [
    'ipaclient',
    'ipalib',
    'ipaplatform',
    'ipapython',
    'ipaserver',
    'ipatests',
])
def test_package_installed(pkgname):
    pkg_resources.require(pkgname)
