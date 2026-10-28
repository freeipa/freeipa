#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipaserver.plugins.idp` module.
"""

import pytest

from ipalib import errors
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test, raises_exact)
from ipatests.test_xmlrpc.tracker.idp_plugin import IdpTracker

google_auth = "https://accounts.google.com/o/oauth2/auth"
google_devauth = "https://oauth2.googleapis.com/device/code"
google_token = "https://oauth2.googleapis.com/token"
google_userinfo = "https://openidconnect.googleapis.com/v1/userinfo"
google_jwks = "https://www.googleapis.com/oauth2/v3/certs"

idp_scope = "openid email"
idp_sub = "email"


@pytest.fixture(scope='class')
def idp(request, xmlrpc_setup):
    tracker = IdpTracker('idp1', ipaidpauthendpoint=google_auth,
                         ipaidpdevauthendpoint=google_devauth,
                         ipaidptokenendpoint=google_token,
                         ipaidpuserinfoendpoint=google_userinfo,
                         ipaidpkeysendpoint=google_jwks,
                         ipaidpclientid="idp1client",
                         ipaidpclientsecret="Secret123",
                         ipaidpscope=idp_scope)
    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def renamedidp(request, xmlrpc_setup):
    tracker = IdpTracker('idp2', ipaidpauthendpoint=google_auth,
                         ipaidpdevauthendpoint=google_devauth,
                         ipaidptokenendpoint=google_token,
                         ipaidpuserinfoendpoint=google_userinfo,
                         ipaidpkeysendpoint=google_jwks,
                         ipaidpclientid="idp1client",
                         ipaidpclientsecret="Secret123",
                         ipaidpscope=idp_scope)
    return tracker.make_fixture(request)


class TestNonexistentIdp(XMLRPC_test):
    def test_retrieve_nonexistent(self, idp):
        """ Try to retrieve a non-existent idp """
        idp.ensure_missing()
        command = idp.make_retrieve_command()
        with raises_exact(errors.NotFound(
                reason='%s: Identity Provider reference not found' % idp.cn)):
            command()

    def test_update_nonexistent(self, idp):
        """ Try to update a non-existent idp """
        idp.ensure_missing()
        command = idp.make_update_command(
            updates=dict(ipaidpclientid='idpclient2'))
        with raises_exact(errors.NotFound(
                reason='%s: Identity Provider reference not found' % idp.cn)):
            command()

    def test_delete_nonexistent(self, idp):
        """ Try to delete a non-existent idp """
        idp.ensure_missing()
        command = idp.make_delete_command()
        with raises_exact(errors.NotFound(
                reason='%s: Identity Provider reference not found' % idp.cn)):
            command()

    def test_rename_nonexistent(self, idp, renamedidp):
        """ Try to rename a non-existent idp """
        idp.ensure_missing()
        command = idp.make_update_command(
            updates=dict(setattr='cn=%s' % renamedidp.cn))
        with raises_exact(errors.NotFound(
                reason='%s: Identity Provider reference not found' % idp.cn)):
            command()


@pytest.mark.tier1
class TestIdP(XMLRPC_test):
    def test_retrieve(self, idp):
        """" Create idp and try to retrieve it """
        idp.ensure_exists()
        idp.retrieve()

    def test_delete(self, idp):
        """ Delete idp """
        idp.ensure_exists()
        idp.delete()


@pytest.mark.tier1
class TestFindIdp(XMLRPC_test):
    def test_find(self, idp):
        """ Basic check of idp-find """
        idp.ensure_exists()
        idp.find()

    def test_find_with_all(self, idp):
        """ Basic check of idp-find with --all """
        idp.ensure_exists()
        idp.find(all=True)

    def test_find_with_pkey_only(self, idp):
        """ Basic check of idp-find with primary keys only """
        idp.ensure_exists()
        command = idp.make_find_command(cn=idp.cn, pkey_only=True)
        result = command()
        idp.check_find(result, pkey_only=True)


@pytest.mark.tier1
class TestUpdateIdp(XMLRPC_test):
    def test_update(self, idp):
        """ Basic check of idp-mod """
        idp.ensure_exists()
        idp.update(
            updates=dict(ipaidpclientid='NewClientID')
        )

    def test_rename(self, idp, renamedidp):
        """ Rename idp and rename it back """
        idp.ensure_exists()
        renamedidp.ensure_missing()
        oldcn = idp.cn

        idp.update(updates=dict(rename=renamedidp.cn))
        idp.update(updates=dict(rename=oldcn))

    def test_rename_to_same_value(self, idp):
        """ Try to rename idp to the same value """
        idp.ensure_exists()
        command = idp.make_update_command(
            updates=dict(setattr=('cn=%s' % idp.cn))
        )
        with raises_exact(errors.EmptyModlist()):
            command()


@pytest.mark.tier1
class TestCreateIdp(XMLRPC_test):
    def test_create_idp_with_min_values(self):
        """ Creation with only mandatory parameters """
        idp_min = IdpTracker('min_idp', ipaidpauthendpoint=google_auth,
                             ipaidpdevauthendpoint=google_devauth,
                             ipaidptokenendpoint=google_token,
                             ipaidpuserinfoendpoint=google_userinfo,
                             ipaidpkeysendpoint=google_jwks,
                             ipaidpclientid="idp1client")
        idp_min.track_create()
        command = idp_min.make_create_command()
        result = command()
        idp_min.check_create(result)
        idp_min.delete()

    def test_create_idp_with_provider(self):
        """ Creation with --provider parameter """
        idp_with_provider = IdpTracker(
            'idp_with_provider', ipaidpprovider='google',
            ipaidpclientid="idpclient1")
        idp_with_provider.track_create()
        # the endpoints are automatically added
        idp_with_provider.attrs.update(ipaidpauthendpoint=[google_auth])
        idp_with_provider.attrs.update(ipaidpdevauthendpoint=[google_devauth])
        idp_with_provider.attrs.update(ipaidptokenendpoint=[google_token])
        idp_with_provider.attrs.update(ipaidpkeysendpoint=[google_jwks])
        idp_with_provider.attrs.update(ipaidpuserinfoendpoint=[google_userinfo])
        idp_with_provider.attrs.update(ipaidpscope=[idp_scope])
        idp_with_provider.attrs.update(ipaidpsub=[idp_sub])
        command = idp_with_provider.make_create_command()
        result = command()
        idp_with_provider.check_create(result)
        idp_with_provider.delete()

    def test_create_with_invalid_provider(self):
        """ Creation with invalid --provider parameter """
        idp_with_provider = IdpTracker(
            'idp_with_provider', ipaidpprovider='fake',
            ipaidpclientid="idpclient1")
        idp_with_provider.track_create()
        command = idp_with_provider.make_create_command()
        with raises_exact(errors.ValidationError(
            name='provider',
            error="must be one of 'google', 'github', 'microsoft', "
                  "'okta', 'keycloak'"
        )):
            command()

    def test_create_with_provider_and_authendpoint(self):
        """ Creation with --provider parameter and --auth-uri"""
        idp_with_provider = IdpTracker(
            'idp_with_provider', ipaidpprovider='google',
            ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidpclientid="idpclient1")
        idp_with_provider.track_create()
        command = idp_with_provider.make_create_command()
        with raises_exact(errors.MutuallyExclusiveError(
            reason='cannot specify both individual endpoints and IdP provider'
        )):
            command()

    def test_create_with_provider_and_tokenendpoint(self):
        """ Creation with --provider parameter and --token-uri"""
        idp_with_provider = IdpTracker(
            'idp_with_provider', ipaidpprovider='google',
            ipaidptokenendpoint=google_token,
            ipaidpdevauthendpoint=google_devauth,
            ipaidpclientid="idpclient1")
        idp_with_provider.track_create()
        command = idp_with_provider.make_create_command()
        with raises_exact(errors.MutuallyExclusiveError(
            reason='cannot specify both individual endpoints and IdP provider'
        )):
            command()

    def test_create_missing_authendpoint(self):
        """ Creation with missing --dev-auth-uri and --auth-uri"""
        idp_with_provider = IdpTracker(
            'idp_with_provider',
            ipaidptokenendpoint=google_token,
            ipaidpclientid="idpclient1")
        idp_with_provider.track_create()
        command = idp_with_provider.make_create_command()
        with raises_exact(errors.RequirementError(
            name='dev-auth-uri or provider'
        )):
            command()

    def test_create_missing_tokenendpoint(self):
        """ Creation with missing --token-uri"""
        idp_with_provider = IdpTracker(
            'idp_with_provider',
            ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidpclientid="idpclient1")
        idp_with_provider.track_create()
        command = idp_with_provider.make_create_command()
        with raises_exact(errors.RequirementError(
            name='token-uri or provider'
        )):
            command()

    def test_create_missing_clientid(self):
        """ Creation with missing --client-id"""
        idp_with_provider = IdpTracker(
            'idp_with_provider',
            ipaidptokenendpoint=google_token,
            ipaidpdevauthendpoint=google_devauth,
            ipaidpauthendpoint=google_auth)
        idp_with_provider.track_create()
        command = idp_with_provider.make_create_command()
        with raises_exact(errors.RequirementError(
            name='client_id'
        )):
            command()
