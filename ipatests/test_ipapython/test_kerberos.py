#
# Copyright (C) 2016 FreeIPA Project Contributors - see LICENSE file
#

import pytest

from ipapython.kerberos import Principal

valid_principals = {
    'tuser@REALM.TEST': {
        'components': ('tuser',),
        'realm': 'REALM.TEST',
        'username': 'tuser'
    },
    'tuser\\@tupn.test@REALM.TEST': {
        'components': ('tuser@tupn.test',),
        'realm': 'REALM.TEST',
        'username': 'tuser@tupn.test',
        'upn_suffix': 'tupn.test'
    },
    'test/host.ipa.test@REALM.TEST': {
        'components': ('test', 'host.ipa.test'),
        'realm': 'REALM.TEST',
        'hostname': 'host.ipa.test'
    },
    'test/service/host.ipa.test@REALM.TEST': {
        'components': ('test', 'service', 'host.ipa.test'),
        'realm': 'REALM.TEST',
        'service_name': 'test/service'

    },
    'tuser': {
        'components': ('tuser',),
        'realm': None,
        'username': 'tuser'
    },
    '$%user@REALM.TEST': {
        'components': ('$%user',),
        'realm': 'REALM.TEST',
        'username': '$%user'
    },
    'host/host.ipa.test': {
        'components': ('host', 'host.ipa.test'),
        'realm': None,
        'hostname': 'host.ipa.test'
    },
    's$c/$%^.ipa.t%$t': {
        'components': ('s$c', '$%^.ipa.t%$t'),
        'realm': None,
        'hostname': '$%^.ipa.t%$t',
        'service_name': 's$c'
    },
    'test\\/service/test\\/host@REALM\\@TEST': {
        'components': ('test/service', 'test/host'),
        'realm': 'REALM@TEST',
        'hostname': 'test/host',
        'service_name': r'test\/service'
    }
}


def valid_principal_iter(principals):
    for princ, data in principals.items():
        yield princ, data


@pytest.fixture(params=list(valid_principal_iter(valid_principals)))
def valid_principal(request):
    return request.param


def test_principals(valid_principal):
    principal_name, data = valid_principal

    princ = Principal(principal_name)

    for name, value in data.items():
        assert getattr(princ, name) == value

    assert str(princ) == principal_name
    assert repr(princ) == "ipapython.kerberos.Principal('{}')".format(
        principal_name)


def test_multiple_unescaped_ats_raise_error():
    pytest.raises(ValueError, Principal, 'too@many@realms')


principals_properties = {
    'user@REALM': {
        'property_true': ('is_user',),
        'property_raises': ('upn_suffix', 'hostname', 'service_name')
    },
    'host/m1.ipa.test@REALM': {
        'property_true': ('is_host', 'is_service'),
        'property_raises': ('username', 'upn_suffix')
    },
    'service/m1.ipa.test@REALM': {
        'property_true': ('is_service'),
        'property_raises': ('username', 'upn_suffix')
    },
    'user\\@domain@REALM': {
        'property_true': ('is_user', 'is_enterprise'),
        'property_raises': ('hostname', 'service_name')
    }
}


def principal_properties_iter(principals_properties):
    for p, data in principals_properties.items():
        yield p, data


@pytest.fixture(params=list(principal_properties_iter(principals_properties)))
def principal_properties(request):
    return request.param


def test_principal_properties(principal_properties):
    principal, data = principal_properties

    princ = Principal(principal)

    boolean_propertes = [prop for prop in dir(princ) if
                         prop.startswith('is_')]

    for b in boolean_propertes:
        if b in data['property_true']:
            assert getattr(princ, b)
        else:
            assert not getattr(princ, b)

    for property_raises in data['property_raises']:
        with pytest.raises(ValueError):
            getattr(princ, property_raises)
