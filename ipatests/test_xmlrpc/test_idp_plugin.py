#
# Copyright (C) 2021  FreeIPA Contributors see COPYING for license
#

"""
Test the `ipaserver.plugins.idp` module.
"""

import datetime
import os
import pytest
import shutil
import tempfile

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from ipalib import api, errors
from ipatests.test_xmlrpc.xmlrpc_test import (
    XMLRPC_test, raises_exact)
from ipatests.test_xmlrpc.tracker.idp_plugin import IdpTracker
from ipapython import ipautil

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


PKCS12PASSWORD = "PKCS12Password"


def get_pkcs12_path(subject_cn, password):
    """
    Create a tempdir with various PKCS12 bundles

    client.p12 with cert and key
    onlycert.p12 with only the cert
    onlykey.p12 with only the key
    Returns the path to temp dir
    """
    tempdir = tempfile.mkdtemp(prefix="tmp-")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                            f"CN={subject_cn}"),])

    # Generate the key
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    # Generate self-signed cert with CN=ipa-oauth-client.example.com
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.issuer_name(subject)
    builder = builder.subject_name(subject)
    builder = builder.public_key(key.public_key())
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=365))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.DNSName(api.env.host)]),
        critical=False,
    )

    cert = builder.sign(
        private_key=key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode()),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    keyfile = os.path.join(tempdir, f'{subject_cn}.key')
    certfile = os.path.join(tempdir, f'{subject_cn}.crt')
    p12file = os.path.join(tempdir, 'client.p12')
    onlycertfile = os.path.join(tempdir, 'onlycert.p12')
    onlykeyfile = os.path.join(tempdir, 'onlykey.p12')

    with open(keyfile, 'wb') as f:
        f.write(key_pem)
    with open(certfile, 'wb') as f:
        f.write(cert_pem)

    # Export key + cert in .p12 file
    ipautil.run(['openssl', 'pkcs12', '-export', '-out', p12file,
                 '-inkey', keyfile, '-in', certfile,
                 '-passin', f'pass:{password}',
                 '-passout', f'pass:{password}'])

    # Export only cert in onlycert.p12
    ipautil.run(['openssl', 'pkcs12', '-export', '-out', onlycertfile,
                 '-in', certfile,
                 '-passin', f'pass:{password}',
                 '-passout', f'pass:{password}',
                 '-nokeys'])

    # Export only key in onlykey.p12
    ipautil.run(['openssl', 'pkcs12', '-export', '-out', onlykeyfile,
                 '-inkey', keyfile,
                 '-passin', f'pass:{password}',
                 '-passout', f'pass:{password}',
                 '-nocerts'])
    return tempdir


@pytest.fixture(scope='class')
def pkcs12_path():
    tmpdir = get_pkcs12_path("ipa-oauth-client", PKCS12PASSWORD)
    yield tmpdir
    shutil.rmtree(tmpdir)


@pytest.fixture(scope='class')
def pkcs12_new_path():
    tmpdir = get_pkcs12_path("ipa-new-oauth-client", PKCS12PASSWORD)
    yield tmpdir
    shutil.rmtree(tmpdir)


def read_pkcs12(p12file):
    """ Extract pkcs12 data and cert from pkcs12 file """
    with open(p12file, 'rb') as f:
        p12file_data = f.read()
    return p12file_data


@pytest.mark.tier1
class TestCreateIdpClientAuth(XMLRPC_test):
    """ Tests for client authentication with certificate """

    def test_create_idp_client_secret(self, pkcs12_path):
        """ Creation with client_secret and p12 file"""
        # Specify --client-cert-p12-file and --client-auth-method=client_secret
        idp = IdpTracker(
            'inconsistent_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod="client_secret",
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")))
        idp.track_create()
        command = idp.make_create_command()
        with raises_exact(errors.MutuallyExclusiveError(
            reason='cannot use client_secret authentication and '
                   'client-cert-p12-file'
        )):
            command()

        # Specify --client-cert-p12-file and no --client-auth-method
        # (defaults to client_secret)
        idp2 = IdpTracker(
            'inconsistent2_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")))
        idp2.track_create()
        command = idp2.make_create_command()
        with raises_exact(errors.MutuallyExclusiveError(
            reason='cannot use client_secret authentication and '
                   'client-cert-p12-file'
        )):
            command()

    @pytest.mark.parametrize("method", ['tls_client_auth', 'private_key_jwt'])
    def test_create_idp_missing_p12(self, method):
        """ Creation with cert auth and missing p12 file"""
        # Specify --client-auth-method=method but no p12 file
        idp = IdpTracker(
            'missingp12_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod=method)
        idp.track_create()
        command = idp.make_create_command()
        with raises_exact(errors.RequirementError(
            name="client-cert-p12-file"
        )):
            command()

    @pytest.mark.parametrize("method", ['tls_client_auth', 'private_key_jwt'])
    def test_create_idp_wrong_secret(self, method, pkcs12_path):
        """ Creation with cert auth and p12 file but wrong secret"""
        idp = IdpTracker(
            'bad_pass_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod=method,
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
            ipaidpclientsecret='WrongPassword')
        idp.track_create()
        command = idp.make_create_command()
        with raises_exact(errors.ValidationError(
            name='client_cert_p12_file',
            error="Cannot decode PKCS12 file: "
                  "Invalid password or PKCS12 data")):
            command()

    @pytest.mark.parametrize("method", ['tls_client_auth', 'private_key_jwt'])
    def test_create_idp_secret(self, method, pkcs12_path):
        """ Creation with cert auth and p12 file"""
        idp = IdpTracker(
            f'{method}_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod=method,
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
            ipaidpclientsecret=PKCS12PASSWORD)
        idp.create()
        idp.delete()

    @pytest.mark.parametrize("method", ['tls_client_auth', 'private_key_jwt'])
    def test_switch_to_client_secret(self, method, pkcs12_path):
        """ Switch to client secret"""
        idp = IdpTracker(
            f'{method}_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod=method,
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
            ipaidpclientsecret=PKCS12PASSWORD)
        idp.create()
        # Switch to client secret with a pkcs12file, expect error
        command = idp.make_update_command(updates=dict(
            ipaidpclientauthmethod='client_secret',
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
        ))
        with raises_exact(errors.MutuallyExclusiveError(
            reason='cannot use client_secret authentication and '
                   'client-cert-p12-file'
        )):
            command()
        # Switch to client secret without additional param, success
        idp.update(
            updates=dict(ipaidpclientauthmethod='client_secret')
        )
        # Re-run the update with no change, expect error
        command = idp.make_update_command(
            updates=dict(ipaidpclientauthmethod='client_secret')
        )
        with raises_exact(errors.EmptyModlist()):
            command()

        idp.delete()

    @pytest.mark.parametrize("method", ['tls_client_auth', 'private_key_jwt'])
    def test_switch_to_cert_auth(self, method, pkcs12_path):
        """ Switch to another auth method"""
        idp = IdpTracker(
            f'{method}_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
        )
        idp.create()
        # Switch to cert auth without a pkcs12file, expect error
        command = idp.make_update_command(updates=dict(
            ipaidpclientauthmethod=method,
        ))
        with raises_exact(errors.RequirementError(name="client-cert-p12-file")):
            command()

        # Switch to cert auth with pkcs12 file but wrong pwd, failure
        command = idp.make_update_command(updates=dict(
            ipaidpclientauthmethod=method,
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
            ipaidpclientsecret='WrongPass')
        )
        with raises_exact(errors.ValidationError(
            name='client_cert_p12_file',
            error="Cannot decode PKCS12 file: "
                  "Invalid password or PKCS12 data")):
            command()

        # Switch to cert auth with pkcs12 file and good pwd
        idp.update(
            updates=dict(
                ipaidpclientauthmethod=method,
                userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
                ipaidpclientsecret=PKCS12PASSWORD),
        )
        idp.delete()

    def test_switch_cert_auth(self, pkcs12_path):
        """
        Switch from tls_client_auth to private_key_jwt and back
        """
        idp = IdpTracker(
            'certauth_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod='tls_client_auth',
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
            ipaidpclientsecret=PKCS12PASSWORD
        )
        idp.create()
        # Switch to private_key_jwt
        idp.update(updates=dict(
            ipaidpclientauthmethod='private_key_jwt',
        ))
        # Switch back to tls_client_auth
        idp.update(updates=dict(
            ipaidpclientauthmethod='tls_client_auth',
        ))
        idp.delete()

    def test_replace_pkcs12file(self, pkcs12_path, pkcs12_new_path):
        """
        Update the PKCS12 data
        """
        method = 'tls_client_auth'
        idp = IdpTracker(
            'newpkcs12_idp', ipaidpauthendpoint=google_auth,
            ipaidpdevauthendpoint=google_devauth,
            ipaidptokenendpoint=google_token,
            ipaidpuserinfoendpoint=google_userinfo,
            ipaidpkeysendpoint=google_jwks,
            ipaidpclientid="idp1client",
            ipaidpclientauthmethod=method,
            userpkcs12=read_pkcs12(os.path.join(pkcs12_path,"client.p12")),
            ipaidpclientsecret=PKCS12PASSWORD
        )
        idp.create()
        # Use another pkcs12 file, wrong password
        command = idp.make_update_command(updates=dict(
            userpkcs12=read_pkcs12(os.path.join(pkcs12_new_path,"client.p12")),
            ipaidpclientsecret='WrongPass')
        )
        with raises_exact(errors.ValidationError(
            name='client_cert_p12_file',
            error="Cannot decode PKCS12 file: "
                  "Invalid password or PKCS12 data")):
            command()
        # Use another pkcs12 file, good password
        idp.update(updates=dict(
            userpkcs12=read_pkcs12(os.path.join(pkcs12_new_path,"client.p12")),
            ipaidpclientsecret=PKCS12PASSWORD)
        )
        idp.delete()
