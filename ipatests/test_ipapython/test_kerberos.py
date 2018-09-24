#
# Copyright (C) 2016 FreeIPA Project Contributors - see LICENSE file
#

import pytest
import six

from ipapython.kerberos import Principal

if six.PY3:
    unicode = str

valid_principals = {
    u'tuser@REALM.TEST': {
        'components': (u'tuser',),
        'realm': u'REALM.TEST',
        'username': u'tuser'
    },
    u'tuser\\@tupn.test@REALM.TEST': {
        'components': (u'tuser@tupn.test',),
        'realm': u'REALM.TEST',
        'username': u'tuser@tupn.test',
        'upn_suffix': u'tupn.test'
    },
    u'test/host.ipa.test@REALM.TEST': {
        'components': (u'test', u'host.ipa.test'),
        'realm': u'REALM.TEST',
        'hostname': u'host.ipa.test'
    },
    u'test/service/host.ipa.test@REALM.TEST': {
        'components': (u'test', u'service', u'host.ipa.test'),
        'realm': u'REALM.TEST',
        'service_name': u'test/service'

    },
    u'tuser': {
        'components': (u'tuser',),
        'realm': None,
        'username': u'tuser'
    },
    u'$%user@REALM.TEST': {
        'components': (u'$%user',),
        'realm': u'REALM.TEST',
        'username': u'$%user'
    },
    u'host/host.ipa.test': {
        'components': (u'host', u'host.ipa.test'),
        'realm': None,
        'hostname': u'host.ipa.test'
    },
    u's$c/$%^.ipa.t%$t': {
        'components': (u's$c', u'$%^.ipa.t%$t'),
        'realm': None,
        'hostname': u'$%^.ipa.t%$t',
        'service_name': u's$c'
    },
    u'test\\/service/test\\/host@REALM\\@TEST': {
        'components': (u'test/service', u'test/host'),
        'realm': u'REALM@TEST',
        'hostname': u'test/host',
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

    assert unicode(princ) == principal_name
    assert repr(princ) == "ipapython.kerberos.Principal('{}')".format(
        principal_name)


def test_multiple_unescaped_ats_raise_error():
    pytest.raises(ValueError, Principal, u'too@many@realms')


principals_properties = {
    u'user@REALM': {
        'property_true': ('is_user',),
        'property_raises': ('upn_suffix', 'hostname', 'service_name')
    },
    u'host/m1.ipa.test@REALM': {
        'property_true': ('is_host', 'is_service'),
        'property_raises': ('username', 'upn_suffix')
    },
    u'service/m1.ipa.test@REALM': {
        'property_true': ('is_service'),
        'property_raises': ('username', 'upn_suffix')
    },
    u'user\\@domain@REALM': {
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
