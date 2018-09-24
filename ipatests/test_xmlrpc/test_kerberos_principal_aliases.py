# coding: utf-8
#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

import copy
import ldap
import pytest

from ipalib import errors, api
from ipapython import ipautil
from ipaplatform.paths import paths

from ipatests.test_util import yield_fixture
from ipatests.util import MockLDAP
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.user_plugin import UserTracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.tracker.service_plugin import ServiceTracker
from ipatests.test_xmlrpc.tracker.stageuser_plugin import StageUserTracker
from ipatests.test_xmlrpc.mock_trust import (
    mocked_trust_containers, get_trust_dn, get_trusted_dom_dict,
    encode_mockldap_value)
from ipatests.util import unlock_principal_password, change_principal


# Shared values for the mocked trusted domain
TRUSTED_DOMAIN_MOCK = dict(
    name=u'trusted.domain.net',
    sid=u'S-1-5-21-2997650941-1802118864-3094776726'
)
TRUSTED_DOMAIN_MOCK['dn'] = get_trust_dn(TRUSTED_DOMAIN_MOCK['name'])
TRUSTED_DOMAIN_MOCK['ldif'] = get_trusted_dom_dict(
    TRUSTED_DOMAIN_MOCK['name'], TRUSTED_DOMAIN_MOCK['sid']
)

ADD_REMOVE_TEST_DATA = [
    u'testuser-alias',
    u'testhost-alias',
    u'teststageuser-alias',
]
TRACKER_INIT_DATA = [
    (UserTracker, (u'krbalias_user', u'krbalias', u'test',), {},),
    (HostTracker, (u'testhost-krb',), {},),
    (StageUserTracker, (u'krbalias_stageuser', u'krbalias', u'test',), {},),
]
TRACKER_DATA = [
    (ADD_REMOVE_TEST_DATA[i],) + TRACKER_INIT_DATA[i]
    for i in range(len(TRACKER_INIT_DATA))
]


@yield_fixture
def trusted_domain():
    """Fixture providing mocked AD trust entries

    The fixture yields after creating a mock of AD trust
    entries in the directory server. After the test, the entries
    are deleted from the directory.
    """

    trusted_dom = TRUSTED_DOMAIN_MOCK

    # Write the changes
    with mocked_trust_containers(), MockLDAP() as ldap:
        ldap.add_entry(trusted_dom['dn'], trusted_dom['ldif'])
        yield trusted_dom
        ldap.del_entry(trusted_dom['dn'])


@yield_fixture
def trusted_domain_with_suffix():
    """Fixture providing mocked AD trust entries

    The fixture yields after creating a mock of AD trust
    entries in the directory server. After the test, the entries
    are deleted from the directory.
    """
    trusted_dom = copy.deepcopy(TRUSTED_DOMAIN_MOCK)

    trusted_dom['ldif']['ipaNTAdditionalSuffixes'] = (
        encode_mockldap_value(trusted_dom['name'])
    )

    # Write the changes
    with mocked_trust_containers(), MockLDAP() as ldap:
        ldap.add_entry(trusted_dom['dn'], trusted_dom['ldif'])
        yield trusted_dom
        ldap.del_entry(trusted_dom['dn'])


@pytest.fixture(scope='function')
def krbalias_user(request):
    tracker = UserTracker(u'krbalias_user', u'krbalias', u'test')

    return tracker.make_fixture(request)


@pytest.fixture(scope='function')
def krbalias_user_c(request):
    tracker = UserTracker(u'krbalias_user_conflict', u'krbalias', u'test')

    return tracker.make_fixture(request)


@pytest.fixture
def krb_service_host(request):
    tracker = HostTracker(u'krb-srv-host')

    return tracker.make_fixture(request)


@pytest.fixture(scope='function')
def krbalias_service(request, krb_service_host):
    krb_service_host.ensure_exists()

    tracker = ServiceTracker(name=u'SRV1', host_fqdn=krb_service_host.name)

    return tracker.make_fixture(request)


@pytest.fixture(scope='function')
def krbalias(request, tracker_cls, tracker_args, tracker_kwargs):
    tracker = tracker_cls(*tracker_args, **tracker_kwargs)
    return tracker.make_fixture(request)


@pytest.fixture
def ldapservice(request):
    tracker = ServiceTracker(
        name=u'ldap', host_fqdn=api.env.host, options={'has_keytab': True})

    tracker.track_create()
    return tracker

class TestKerberosAliasManipulation(XMLRPC_test):

    @pytest.mark.parametrize('alias,tracker_cls,tracker_args,tracker_kwargs',
                             TRACKER_DATA)
    def test_add_principal_alias(self, alias, krbalias):
        krbalias.ensure_exists()
        krbalias.add_principal([alias])
        krbalias.retrieve()

    @pytest.mark.parametrize('alias,tracker_cls,tracker_args,tracker_kwargs',
                             TRACKER_DATA)
    def test_remove_principal_alias(self, alias, krbalias):
        krbalias.ensure_exists()
        krbalias.add_principal([alias])
        krbalias.remove_principal(alias)
        krbalias.retrieve()

    def test_add_service_principal_alias(self, krbalias_service):
        krbalias_service.ensure_exists()
        krbalias_service.add_principal(
            [u'SRV2/{}'.format(krbalias_service.host_fqdn)])
        krbalias_service.retrieve()

    def test_remove_service_principal_alias(self, krbalias_service):
        krbalias_service.ensure_exists()
        krbalias_service.add_principal(
            [u'SRV2/{}'.format(krbalias_service.host_fqdn)])
        krbalias_service.retrieve()
        krbalias_service.remove_principal(
            [u'SRV2/{}'.format(krbalias_service.host_fqdn)])
        krbalias_service.retrieve()

    def test_adding_alias_adds_canonical_name(self, krbalias_user):
        """Test adding alias on an entry without canonical name"""
        krbalias_user.ensure_exists()

        user_krb_principal = krbalias_user.attrs['krbprincipalname'][0]

        # Delete all values of krbcanonicalname from an LDAP entry
        dn = str(krbalias_user.dn)
        modlist = [(ldap.MOD_DELETE, 'krbcanonicalname', None)]

        with MockLDAP() as ldapconn:
            ldapconn.mod_entry(dn, modlist)

        # add new user principal alias
        krbalias_user.add_principal(u'krbalias_principal_canonical')

        # verify that the previous principal name is now krbcanonicalname
        cmd = krbalias_user.make_retrieve_command()

        new_canonical_name = cmd()['result']['krbcanonicalname'][0]
        assert new_canonical_name == user_krb_principal

    def test_authenticate_against_aliased_service(self, ldapservice):
        alias = u'ldap/{newname}.{host}'.format(
            newname='krbalias', host=api.env.host)
        ldapservice.add_principal(alias)

        rv = ipautil.run([paths.BIN_KVNO, alias],
                         capture_error=True, raiseonerr=False)
        ldapservice.remove_principal(alias)

        assert rv.returncode == 0, rv.error_output

    def test_authenticate_with_user_alias(self, krbalias_user):
        krbalias_user.ensure_exists()

        alias = u"{name}-alias".format(name=krbalias_user.name)

        krbalias_user.add_principal(alias)

        oldpw, newpw = u"Secret1234", u"Secret123"

        pwdmod = krbalias_user.make_update_command({'userpassword': oldpw})
        pwdmod()

        unlock_principal_password(krbalias_user.name, oldpw, newpw)

        with change_principal(alias, newpw, canonicalize=True):
            api.Command.ping()


class TestKerberosAliasExceptions(XMLRPC_test):

    def test_add_user_coliding_with_alias(self, krbalias_user):
        krbalias_user.ensure_exists()

        user_alias = u'conflicting_name'
        krbalias_user.add_principal([user_alias])

        conflict_user = UserTracker(user_alias, u'test', u'conflict')

        with pytest.raises(errors.DuplicateEntry):
            conflict_user.create()

    def test_add_alias_to_two_entries(self, krbalias_user, krbalias_user_c):
        krbalias_user.ensure_exists()
        krbalias_user_c.ensure_exists()

        user_alias = u'krbalias-test'

        krbalias_user.add_principal([user_alias])

        with pytest.raises(errors.DuplicateEntry):
            krbalias_user_c.add_principal([user_alias])

    def test_remove_alias_matching_canonical_name(self, krbalias_user):
        krbalias_user.ensure_exists()

        with pytest.raises(errors.ValidationError):
            krbalias_user.remove_principal(
                krbalias_user.attrs.get('krbcanonicalname'))

    def test_enterprise_principal_overlap_with_AD_realm(
            self, krbalias_user, trusted_domain):
        krbalias_user.ensure_exists()

        # Add an alias overlapping the trusted domain realm
        with pytest.raises(errors.ValidationError):
            krbalias_user.add_principal(
                u'{username}\\@{trusted_domain}@{realm}'.format(
                    username=krbalias_user.name,
                    trusted_domain=trusted_domain['name'],
                    realm=api.env.realm
                )
            )

    def test_enterprise_principal_UPN_overlap(
            self, krbalias_user, trusted_domain_with_suffix):
        krbalias_user.ensure_exists()

        # Add an alias overlapping the UPN of a trusted domain
        upn_suffix = (
            trusted_domain_with_suffix['ldif']['ipaNTAdditionalSuffixes']
        ).decode('utf-8')

        with pytest.raises(errors.ValidationError):
            krbalias_user.add_principal(
                u'{username}\\@{trusted_domain}@{realm}'.format(
                    username=krbalias_user.name,
                    trusted_domain=upn_suffix,
                    realm=api.env.realm
                )
            )

    def test_enterprise_principal_NETBIOS_overlap(
            self, krbalias_user, trusted_domain_with_suffix):
        krbalias_user.ensure_exists()

        # Add an alias overlapping the NETBIOS name of a trusted domain
        netbios_name = (
            trusted_domain_with_suffix['ldif']['ipaNTFlatName']
        ).decode('utf-8')

        with pytest.raises(errors.ValidationError):
            krbalias_user.add_principal(
                u'{username}\\@{trusted_domain}@{realm}'.format(
                    username=krbalias_user.name,
                    trusted_domain=netbios_name,
                    realm=api.env.realm
                )
            )
