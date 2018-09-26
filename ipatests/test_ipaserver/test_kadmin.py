#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

"""
Test suite for creating principals via kadmin.local and modifying their keys
"""

import os
import pytest
import tempfile

from ipalib import api

from ipaserver.install import installutils
from ipatests.test_util import yield_fixture


@yield_fixture()
def keytab():
    fd, keytab_path = tempfile.mkstemp(suffix='.keytab')
    os.close(fd)

    try:
        yield keytab_path
    finally:
        try:
            os.remove(keytab_path)
        except OSError:
            pass


@pytest.fixture()
def service_in_kerberos_subtree(request):
    princ = u'svc1/{0.host}@{0.realm}'.format(api.env)
    installutils.kadmin_addprinc(princ)

    def fin():
        try:
            installutils.kadmin(
                'delprinc -force {}'.format(princ))
        except Exception:
            pass
    request.addfinalizer(fin)
    return princ


@pytest.fixture()
def service_in_service_subtree(request):
    princ = u'svc2/{0.host}@{0.realm}'.format(api.env)
    rpcclient = api.Backend.rpcclient
    was_connected = rpcclient.isconnected()

    if not was_connected:
        rpcclient.connect()

    api.Command.service_add(princ)

    def fin():
        try:
            api.Command.service_del(princ)
        except Exception:
            pass

        try:
            if not was_connected:
                rpcclient.disconnect()
        except Exception:
            pass

    request.addfinalizer(fin)
    return princ


@pytest.fixture(params=[service_in_kerberos_subtree,
                        service_in_service_subtree])
def service(request):
    return request.param(request)


@pytest.mark.skipif(
    os.getuid() != 0, reason="kadmin.local is accesible only to root")
class TestKadmin:
    def assert_success(self, command, *args):
        """
        Since kadmin.local returns 0 also when internal errors occur, we have
        to catch the command's stderr and check that it is empty
        """
        result = command(*args)
        assert not result.error_output

    def test_create_keytab(self, service, keytab):
        """
        tests that ktadd command works for both types of services
        """
        self.assert_success(
            installutils.create_keytab,
            keytab,
            service)

    def test_change_key(self, service, keytab):
        """
        tests that both types of service can have passwords changed using
        kadmin
        """
        self.assert_success(
            installutils.create_keytab,
            keytab,
            service)
        self.assert_success(
            installutils.kadmin,
            'change_password -randkey {}'.format(service))

    def test_append_key(self, service, keytab):
        """
        Tests that we can create a new keytab for both service types and then
        append new keys to it
        """
        self.assert_success(
            installutils.create_keytab,
            keytab,
            service)
        self.assert_success(
            installutils.create_keytab,
            keytab,
            service)
