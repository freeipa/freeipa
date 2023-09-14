#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

import pytest

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test, raises_exact
from ipatests.test_xmlrpc.tracker.passkey_plugin import PasskeyconfigTracker
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.stageuser_plugin import StageUserTracker


@pytest.fixture(scope='class')
def passkey_config(request, xmlrpc_setup):
    tracker = PasskeyconfigTracker()
    return tracker.make_fixture(request)


class TestPasskeyconfig(XMLRPC_test):
    @pytest.mark.parametrize("userverification", [False, True])
    def test_config_mod(self, passkey_config, userverification):
        """
        Test the passkeyconfig-mod CLI with possible values for
        --require-user-verification parameter.
        """
        passkey_config.update(
            {'iparequireuserverification': userverification},
            {'iparequireuserverification': [userverification]}
        )

    def test_config_mod_invalid_requireverif(self, passkey_config):
        """
        Test the passkeyconfig-mod CLI with invalid values for
        --require-user-verification parameter.
        """
        cmd = passkey_config.make_update_command(
            updates={'iparequireuserverification': 'Invalid'}
        )

        with pytest.raises(errors.ConversionError):
            cmd()

    def test_config_show(self, passkey_config):
        """
        Test the passkeyconfig-show command.
        """
        passkey_config.retrieve()


PASSKEY_USER = 'passkeyuser'
PASSKEY_KEY = ("passkey:"
               "E8Zay6UJm6PG/GcQnej2WMyUrWqijejBCqPWFX6THPrx"
               "ab01Z59bUgutipn5MIk8/zMU6RBlp7jSbkNJsZtomw==,"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgryfr3YR"
               "M9OVdWHEDrbvcSyT5D0b/8Ks+fMp8MM0BXV/FOo436ZP"
               "jUqSU+2LOXVGdKkJU1XBiwl+n/X+vGD1vw==")
PASSKEY_DISCOVERABLEKEY = (
    "passkey:"
    "pP2z07ygq36HkNabd79ki9H6rfYEIVdluSHjY1YykUbVECXJ3ZDZ3n1EZ9G8HhMv,"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpP2z07ygq36HkNabd1H9Knqqghjv"
    "vhlW0+FcNzOoXP+49tC/Ee2TbjC3x2dIzJEBFi7iDPSc+OCM+WmD1AfPLQ==,"
    "P6GjSqAo+RoQRJhGFA3lKcvtpKTGETjCdtVIyLX0KcY=")


@pytest.fixture
def passkeyuser(request):
    user = UserTracker(PASSKEY_USER, 'passkey', 'user')
    return user.make_fixture(request)


class TestAddRemovePasskey(XMLRPC_test):
    @pytest.mark.parametrize("key", [PASSKEY_KEY, PASSKEY_DISCOVERABLEKEY])
    def test_add_passkey(self, passkeyuser,key):
        passkeyuser.ensure_exists()
        passkeyuser.add_passkey(ipapasskey=key)
        passkeyuser.ensure_missing()

    @pytest.mark.parametrize("key", [PASSKEY_KEY, PASSKEY_DISCOVERABLEKEY])
    def test_remove_passkey(self, passkeyuser, key):
        passkeyuser.ensure_exists()
        passkeyuser.add_passkey(ipapasskey=key)
        passkeyuser.remove_passkey(ipapasskey=key)

    @pytest.mark.parametrize("key", ['wrongval', 'passkey:123', 'passkey,123'])
    def test_add_passkey_invalid(self, passkeyuser, key):
        passkeyuser.ensure_exists()
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error='"{}" is not a valid passkey mapping'.format(key))):
            cmd(key)

    def test_add_passkey_invalidid(self, passkeyuser):
        passkeyuser.ensure_exists()
        key = ("passkey:123,"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgryfr3YRM9OVdWHEDrbvc"
               "SyT5D0b/8Ks+fMp8MM0BXV/FOo436ZPjUqSU+2LOXVGdKkJU1XBiwl+n/X"
               "+vGD1vw==")
        msg = '"{}" is not a valid passkey mapping, invalid id'
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error=msg.format(key))):
            cmd(key)

    def test_add_passkey_invalidpem(self, passkeyuser):
        passkeyuser.ensure_exists()
        key = ("passkey:"
               "E8Zay6UJm6PG/GcQnej2WMyUrWqijejBCqPWFX6THPrxab01Z59bUguti"
               "pn5MIk8/zMU6RBlp7jSbkNJsZtomw==,"
               "wrongpem")
        msg = '"{}" is not a valid passkey mapping, invalid key'
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error=msg.format(key))):
            cmd(key)

    def test_add_passkey_invaliduserid(self, passkeyuser):
        passkeyuser.ensure_exists()
        key = ("passkey:"
               "E8Zay6UJm6PG/GcQnej2WMyUrWqijejBCqPWFX6THPrxab01Z59bUguti"
               "pn5MIk8/zMU6RBlp7jSbkNJsZtomw==,"
               "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgryfr3YRM9OVdWHEDrbvc"
               "SyT5D0b/8Ks+fMp8MM0BXV/FOo436ZPjUqSU+2LOXVGdKkJU1XBiwl+n/X"
               "+vGD1vw==,"
               "wrongid")
        msg = '"{}" is not a valid passkey mapping, invalid userid'
        cmd = passkeyuser.make_command('user_add_passkey',
                                       passkeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error=msg.format(key))):
            cmd(key)


STAGEPASSKEY_USER = 'stagepasskeyuser'


@pytest.fixture
def stagepasskeyuser(request):
    user = StageUserTracker(STAGEPASSKEY_USER, 'stagepasskey', 'user')
    return user.make_fixture(request)


class TestStageAddRemovePassKey(XMLRPC_test):
    def test_add_passkey(self, stagepasskeyuser):
        stagepasskeyuser.ensure_exists()
        stagepasskeyuser.add_passkey(ipapasskey=PASSKEY_KEY)
        stagepasskeyuser.ensure_missing()

    def test_remove_passkey(self, stagepasskeyuser):
        stagepasskeyuser.ensure_exists()
        stagepasskeyuser.add_passkey(ipapasskey=PASSKEY_KEY)
        stagepasskeyuser.remove_passkey(ipapasskey=PASSKEY_KEY)

    @pytest.mark.parametrize("key", ['wrongval', 'passkey:123', 'passkey,123'])
    def test_add_passkey_invalid(self, stagepasskeyuser, key):
        stagepasskeyuser.ensure_exists()
        cmd = stagepasskeyuser.make_command('user_add_passkey',
                                            stagepasskeyuser.name)
        with raises_exact(errors.ValidationError(
                name='passkey',
                error='"{}" is not a valid passkey mapping'.format(key))):
            cmd(key)
