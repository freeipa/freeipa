# -*- coding: utf-8 -*-
#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import os
import pytest
import tempfile

import six

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ipalib import api, errors
from ipaplatform.paths import paths
from ipatests.util import (
    prepare_config, unlock_principal_password, change_principal,
    host_keytab)
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.certprofile_plugin import CertprofileTracker
from ipatests.test_xmlrpc.tracker.caacl_plugin import CAACLTracker
from ipatests.test_xmlrpc.tracker.ca_plugin import CATracker
from ipatests.test_xmlrpc.tracker.host_plugin import HostTracker
from ipatests.test_xmlrpc.tracker.service_plugin import ServiceTracker

from ipapython.ipautil import run

if six.PY3:
    unicode = str

BASE_DIR = os.path.dirname(__file__)

SMIME_PROFILE_TEMPLATE = os.path.join(BASE_DIR, 'data/smime.cfg.tmpl')
SMIME_MOD_CONSTR_PROFILE_TEMPLATE = os.path.join(BASE_DIR, 'data/smime-mod.cfg.tmpl')
CERT_OPENSSL_CONFIG_TEMPLATE = os.path.join(BASE_DIR, 'data/usercert.conf.tmpl')
CERT_RSA_PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'data/usercert-priv-key.pem')

SMIME_USER_INIT_PW = u'Change123'
SMIME_USER_PW = u'Secret123'


def generate_user_csr(username, domain=None):
    csr_values = dict(
        ipadomain=domain if domain else api.env.domain,
        username=username)

    with tempfile.NamedTemporaryFile(mode='w') as csr_file:
        run([paths.OPENSSL, 'req', '-new', '-key', CERT_RSA_PRIVATE_KEY_PATH,
             '-out', csr_file.name,
             '-config', prepare_config(
                 CERT_OPENSSL_CONFIG_TEMPLATE, csr_values)])

        with open(csr_file.name, 'r') as f:
            csr = unicode(f.read())

    return csr


@pytest.fixture(scope='class')
def smime_profile(request):
    profile_path = prepare_config(
            SMIME_PROFILE_TEMPLATE,
            dict(ipadomain=api.env.domain, iparealm=api.env.realm))

    tracker = CertprofileTracker(u'smime', store=True,
                                 desc=u"S/MIME certificate profile",
                                 profile=profile_path)

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def smime_acl(request):
    tracker = CAACLTracker(u'smime_acl')

    return tracker.make_fixture(request)


# TODO: rewrite these into Tracker instances
# UserTracker has problems while setting passwords.
# Until fixed, will use this fixture.
@pytest.fixture(scope='class')
def smime_user(request):
    username = u'alice'
    api.Command.user_add(uid=username, givenname=u'Alice', sn=u'SMIME',
                         userpassword=SMIME_USER_INIT_PW)

    unlock_principal_password(username, SMIME_USER_INIT_PW, SMIME_USER_PW)

    def fin():
        api.Command.user_del(username)
    request.addfinalizer(fin)

    return username


@pytest.fixture(scope='class')
def smime_group(request):
    api.Command.group_add(u'smime_users')

    def fin():
        api.Command.group_del(u'smime_users')
    request.addfinalizer(fin)

    return u'smime_users'


@pytest.mark.tier1
class TestCertSignMIME(XMLRPC_test):

    def test_cert_import(self, smime_profile):
        smime_profile.ensure_exists()

    def test_create_acl(self, smime_acl):
        smime_acl.ensure_exists()

    def test_add_profile_to_acl(self, smime_acl, smime_profile):
        smime_acl.add_profile(certprofile=smime_profile.name)

    # rewrite to trackers, prepare elsewhere
    def test_add_user_to_group(self, smime_group, smime_user):
        api.Command.group_add_member(smime_group, user=smime_user)

    def test_add_group_to_acl(self, smime_group, smime_acl):
        smime_acl.add_user(group=smime_group)

    def test_sign_smime_csr(self, smime_profile, smime_user):
        csr = generate_user_csr(smime_user)
        with change_principal(smime_user, SMIME_USER_PW):
            api.Command.cert_request(csr, principal=smime_user,
                                     profile_id=smime_profile.name)

    def test_sign_smime_csr_full_principal(self, smime_profile, smime_user):
        csr = generate_user_csr(smime_user)
        smime_user_principal = '@'.join((smime_user, api.env.realm))
        with change_principal(smime_user, SMIME_USER_PW):
            api.Command.cert_request(csr, principal=smime_user_principal,
                                     profile_id=smime_profile.name)


@pytest.mark.tier1
class TestSignWithDisabledACL(XMLRPC_test):

    def test_import_profile_and_acl(self, smime_profile, smime_acl):
        smime_profile.ensure_exists()
        smime_acl.ensure_missing()
        smime_acl.ensure_exists()

    def test_add_profile_to_acl(self, smime_acl, smime_profile):
        smime_acl.add_profile(certprofile=smime_profile.name)

    # rewrite to trackers, prepare elsewhere
    def test_add_user_to_group(self, smime_group, smime_user):
        api.Command.group_add_member(smime_group, user=smime_user)

    def test_add_group_to_acl(self, smime_group, smime_acl):
        smime_acl.add_user(group=smime_group)

    def test_disable_acl(self, smime_acl):
        smime_acl.disable()

    def test_signing_with_disabled_acl(self, smime_acl, smime_profile,
                                       smime_user):
        csr = generate_user_csr(smime_user)
        with change_principal(smime_user, SMIME_USER_PW):
            with pytest.raises(errors.ACIError):
                api.Command.cert_request(
                    csr, profile_id=smime_profile.name,
                    principal=smime_user)

    def test_admin_overrides_disabled_acl(self, smime_acl, smime_profile,
                                          smime_user):
        csr = generate_user_csr(smime_user)
        api.Command.cert_request(
            csr, profile_id=smime_profile.name,
            principal=smime_user)


@pytest.mark.tier1
class TestSignWithoutGroupMembership(XMLRPC_test):

    def test_import_profile_and_acl(self, smime_profile, smime_acl):
        smime_profile.ensure_exists()
        smime_acl.ensure_missing()
        smime_acl.ensure_exists()

    def test_add_profile_to_acl(self, smime_acl, smime_profile):
        smime_acl.add_profile(certprofile=smime_profile.name)

    def test_add_group_to_acl(self, smime_group, smime_acl, smime_user):
        # smime user should not be a member of this group
        #
        # adding smime_user fixture to ensure it exists
        smime_acl.add_user(group=smime_group)

    def test_signing_with_non_member_principal(self, smime_acl, smime_profile,
                                               smime_user):

        csr = generate_user_csr(smime_user)
        with change_principal(smime_user, SMIME_USER_PW):
            with pytest.raises(errors.ACIError):
                api.Command.cert_request(
                    csr,
                    profile_id=smime_profile.name,
                    principal=smime_user)

    def test_admin_overrides_group_membership(self, smime_acl, smime_profile,
                                              smime_user):
        csr = generate_user_csr(smime_user)
        api.Command.cert_request(
            csr, profile_id=smime_profile.name,
            principal=smime_user)


@pytest.mark.tier1
class TestSignWithChangedProfile(XMLRPC_test):
    """ Test to verify that the updated profile is used.

    The profile change requires different CN in CSR
    than the one configured. This leads to rejection
    based on not meeting the profile constraints.
    """

    def test_prepare_env(self, smime_profile, smime_acl):
        smime_profile.ensure_exists()
        smime_acl.ensure_exists()

        smime_acl.add_profile(certprofile=smime_profile.name)

    def test_prepare_user_and_group(self, smime_group, smime_user, smime_acl):
        api.Command.group_add_member(smime_group, user=smime_user)
        smime_acl.add_user(group=smime_group)

    def test_modify_smime_profile(self, smime_profile):
        updated_profile_path = prepare_config(SMIME_MOD_CONSTR_PROFILE_TEMPLATE,
                                              dict(
                                                   ipadomain=api.env.domain,
                                                   iparealm=api.env.realm))

        with open(updated_profile_path) as f:
            updated_profile = unicode(f.read())

        updates = {u'file': updated_profile}
        update_smime_profile = smime_profile.make_update_command(updates)
        update_smime_profile()

    def test_sign_smime_csr(self, smime_profile, smime_user):
        csr = generate_user_csr(smime_user)
        with change_principal(smime_user, SMIME_USER_PW):
            with pytest.raises(errors.CertificateOperationError):
                api.Command.cert_request(csr, principal=smime_user,
                                         profile_id=smime_profile.name)


@pytest.fixture(scope='class')
def smime_signing_ca(request):
    name = u'smime-signing-ca'
    subject = u'CN=SMIME CA,O=test industries Inc.'
    return CATracker(name, subject).make_fixture(request)


@pytest.mark.tier1
class TestCertSignMIMEwithSubCA(XMLRPC_test):
    """ Test Certificate Signing with Sub CA

    The test covers following areas:

     * signing a CSR with custom certificate profile
       using a designated Sub CA
     * Verify that the Issuer of the signed certificate
       is the reqested CA
     * Verify that when not set, cert-request uses the default CA.
       This it verified by violating an ACL
     * Verify that when not set, cert-request uses the default
       certificate profile.

    The latter two test cases are implemented in this module
    as not to replicate the fixtures to cert plugin test module.
    """

    def test_cert_import(self, smime_profile):
        smime_profile.ensure_exists()

    def test_create_acl(self, smime_acl):
        smime_acl.ensure_exists()

    def test_create_subca(self, smime_signing_ca):
        smime_signing_ca.ensure_exists()

    def test_add_profile_to_acl(self, smime_acl, smime_profile):
        smime_acl.add_profile(certprofile=smime_profile.name)

    def test_add_subca_to_acl(self, smime_acl, smime_signing_ca):
        smime_acl.add_ca(smime_signing_ca.name)

    # rewrite to trackers, prepare elsewhere
    def test_add_user_to_group(self, smime_group, smime_user):
        api.Command.group_add_member(smime_group, user=smime_user)

    def test_add_group_to_acl(self, smime_group, smime_acl):
        smime_acl.add_user(group=smime_group)

    def test_sign_smime_csr(self, smime_profile, smime_user, smime_signing_ca):
        csr = generate_user_csr(smime_user)
        with change_principal(smime_user, SMIME_USER_PW):
            api.Command.cert_request(csr, principal=smime_user,
                                     profile_id=smime_profile.name,
                                     cacn=smime_signing_ca.name)

    def test_sign_smime_csr_full_principal(
            self, smime_profile, smime_user, smime_signing_ca):
        csr = generate_user_csr(smime_user)
        smime_user_principal = '@'.join((smime_user, api.env.realm))
        with change_principal(smime_user, SMIME_USER_PW):
            api.Command.cert_request(csr, principal=smime_user_principal,
                                     profile_id=smime_profile.name,
                                     cacn=smime_signing_ca.name)

    def test_verify_cert_issuer_dn_is_subca(
            self, smime_profile, smime_user, smime_signing_ca):
        csr = generate_user_csr(smime_user)
        smime_user_principal = '@'.join((smime_user, api.env.realm))
        with change_principal(smime_user, SMIME_USER_PW):
            cert_info = api.Command.cert_request(
                csr, principal=smime_user_principal,
                profile_id=smime_profile.name, cacn=smime_signing_ca.name)

        assert cert_info['result']['issuer'] == smime_signing_ca.ipasubjectdn

    def test_sign_smime_csr_fallback_to_default_CA(
            self, smime_profile, smime_user, smime_signing_ca):
        """ Attempt to sign a CSR without CA specified.

        The request will satisfy SMIME_ACL via the profile ID,
        however not specifying the CA will fallback to the IPA CA
        for which SMIME profile isn't enabled, thus violating ACL.
        """
        csr = generate_user_csr(smime_user)
        smime_user_principal = '@'.join((smime_user, api.env.realm))

        with pytest.raises(errors.ACIError):
            with change_principal(smime_user, SMIME_USER_PW):
                api.Command.cert_request(csr, principal=smime_user_principal,
                                         profile_id=smime_profile.name)

    def test_sign_smime_csr_fallback_to_default_cert_profile(
            self, smime_profile, smime_user, smime_signing_ca):
        """ Attempt to sign a CSR without certificate profile specified.

        Similar to previous test case.
        By specifying only the CA to use, profile will fallback to
        the default caIPAserviceCert profile which is not enabled
        via ACL to be used with the CA, thus failing the request.
        """
        csr = generate_user_csr(smime_user)
        smime_user_principal = '@'.join((smime_user, api.env.realm))

        with pytest.raises(errors.ACIError):
            with change_principal(smime_user, SMIME_USER_PW):
                api.Command.cert_request(csr, principal=smime_user_principal,
                                         cacn=smime_signing_ca.name)


@pytest.fixture(scope='class')
def santest_subca(request):
    name = u'default-profile-subca'
    subject = u'CN={},O=test'.format(name)
    tr = CATracker(name, subject)
    return tr.make_fixture(request)


@pytest.fixture(scope='class')
def santest_subca_acl(request):
    tr = CAACLTracker(u'default_profile_subca')
    return tr.make_fixture(request)


@pytest.fixture(scope='class')
def santest_host_1(request):
    tr = HostTracker(u'santest-host-1')
    return tr.make_fixture(request)


@pytest.fixture(scope='class')
def santest_host_2(request):
    tr = HostTracker(u'santest-host-2')
    return tr.make_fixture(request)


@pytest.fixture(scope='class')
def santest_service_host_1(request, santest_host_1):
    tr = ServiceTracker(u'srv', santest_host_1.name)
    return tr.make_fixture(request)


@pytest.fixture(scope='class')
def santest_service_host_2(request, santest_host_2):
    tr = ServiceTracker(u'srv', santest_host_2.name)
    return tr.make_fixture(request)


@pytest.fixture
def santest_csr(request, santest_host_1, santest_host_2):
    backend = default_backend()
    pkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=backend
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, santest_host_1.fqdn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, api.env.realm)
    ])).add_extension(x509.SubjectAlternativeName([
        x509.DNSName(santest_host_1.name),
        x509.DNSName(santest_host_2.name)
    ]), False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True, content_commitment=True,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False,
            decipher_only=False
        ),
        False
    ).sign(
        pkey, hashes.SHA256(), backend
    ).public_bytes(serialization.Encoding.PEM)

    return csr.decode('ascii')


class SubjectAltNameOneServiceBase(XMLRPC_test):
    """Base setup class for tests with SAN in CSR

    The class prepares an environment for test cases based
    on evaluation of ACLs and fields requested in a CSR.

    The class creates following entries:

        * host entry
            * santest-host-1
        * service entry
            * srv/santest-host-1
        * Sub CA
            * default-profile-subca

            This one is created in order not to need
            to re-import caIPAServiceCert profile
        * CA ACL
            * default_profile_subca

        After executing the methods the CA ACL should contain:

        CA ACL:
            * santest-host-1        -- host
            * srv/santest-host-1    -- service
            * default-profile-subca -- CA
            * caIPAServiceCert      -- profile
    """
    def test_prepare_caacl_hosts(self, santest_subca_acl, santest_host_1):
        santest_subca_acl.ensure_exists()
        santest_host_1.ensure_exists()
        santest_subca_acl.add_host(santest_host_1.name)

    def test_prepare_caacl_CA(self, santest_subca_acl, santest_subca):
        santest_subca.ensure_exists()
        santest_subca_acl.add_ca(santest_subca.name)

    def test_prepare_caacl_profile(self, santest_subca_acl):
        santest_subca_acl.add_profile(u'caIPAserviceCert')

    def test_prepare_caacl_services(self, santest_subca_acl,
                                    santest_service_host_1):
        santest_service_host_1.ensure_exists()
        santest_subca_acl.add_service(santest_service_host_1.name)


class CAACLEnforcementOnCertBase(SubjectAltNameOneServiceBase):
    """
    Base setup class for tests with SAN in CSR, where
    multiple hosts and services are in play.

    In addition to the host and service created in the base class,
    this class adds the following entries to the environment:

        * host entry
            * santest-host-2
        * service entry
            * srv/santest-host-2

    """
    def test_prepare_add_host_2(self, santest_host_2, santest_service_host_2):
        santest_host_2.ensure_exists()
        santest_service_host_2.ensure_exists()


@pytest.mark.tier1
class TestNoMatchForSubjectAltNameDnsName(SubjectAltNameOneServiceBase):
    """Sign certificate request with an invalid SAN dnsName.

    The CSR includes a DNS name that does not correspond to a
    principal alias or alternative principal.

    """
    def test_request_cert_with_not_allowed_SAN(
            self, santest_subca, santest_host_1,
            santest_service_host_1, santest_csr):

        with host_keytab(santest_host_1.name) as keytab_filename:
            with change_principal(santest_host_1.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                with pytest.raises(errors.NotFound):
                    api.Command.cert_request(
                        santest_csr,
                        principal=santest_service_host_1.name,
                        cacn=santest_subca.name
                    )


@pytest.mark.tier1
class TestPrincipalAliasForSubjectAltNameDnsName(SubjectAltNameOneServiceBase):
    """Test cert-request with SAN dnsName corresponding to a princpial alias.

    Request should succeed.

    """
    def test_add_principal_alias(
            self, santest_service_host_1, santest_service_host_2):
        api.Command.service_add_principal(
            santest_service_host_1.name,
            santest_service_host_2.name)

    def test_request_cert_with_SAN_matching_principal_alias(
            self, santest_subca, santest_host_1,
            santest_service_host_1, santest_csr):
        with host_keytab(santest_host_1.name) as keytab_filename:
            with change_principal(
                    santest_host_1.attrs['krbcanonicalname'][0],
                    keytab=keytab_filename):
                api.Command.cert_request(
                    santest_csr,
                    principal=santest_service_host_1.name,
                    cacn=santest_subca.name
                )


@pytest.mark.tier1
class TestSignCertificateWithInvalidSAN(CAACLEnforcementOnCertBase):
    """Sign certificate request witn an invalid SAN entry

    Using the environment prepared by the base class, ask to sign
    a certificate request for a service managed by one host only.
    The CSR contains another domain name in SAN extension that should
    be refused as the host does not have rights to manage the service.
    """
    def test_request_cert_with_not_allowed_SAN(
            self, santest_subca, santest_host_1, santest_host_2,
            santest_service_host_1, santest_csr):

        with host_keytab(santest_host_1.name) as keytab_filename:
            with change_principal(santest_host_1.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                with pytest.raises(errors.ACIError):
                    api.Command.cert_request(
                        santest_csr,
                        principal=santest_service_host_1.name,
                        cacn=santest_subca.name
                    )


@pytest.mark.tier1
class TestSignServiceCertManagedByMultipleHosts(CAACLEnforcementOnCertBase):
    """ Sign certificate request with multiple subject alternative names

    Using the environment of the base class, modify the service to be managed
    by the second host. Then request a certificate for the service with SAN
    of the second host in CSR. The certificate should be issued.
    """
    def test_make_service_managed_by_each_host(self,
                                               santest_host_1,
                                               santest_service_host_1,
                                               santest_host_2,
                                               santest_service_host_2):
        api.Command['service_add_host'](
            santest_service_host_1.name, host=[santest_host_2.fqdn]
        )
        api.Command['service_add_host'](
            santest_service_host_2.name, host=[santest_host_1.fqdn]
        )

    def test_extend_the_ca_acl(self, santest_subca_acl, santest_host_2,
                               santest_service_host_2):
        santest_subca_acl.add_host(santest_host_2.name)
        santest_subca_acl.add_service(santest_service_host_2.name)

    def test_request_cert_with_additional_host(
            self, santest_subca, santest_host_1, santest_host_2,
            santest_service_host_1, santest_csr):

        with host_keytab(santest_host_1.name) as keytab_filename:
            with change_principal(santest_host_1.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                api.Command.cert_request(
                    santest_csr,
                    principal=santest_service_host_1.name,
                    cacn=santest_subca.name
                )


@pytest.mark.tier1
class TestSignServiceCertWithoutSANServiceInACL(CAACLEnforcementOnCertBase):
    """ Sign certificate request with multiple subject alternative names

    This test case doesn't have the service hosted on a host in SAN
    in the CA ACL. The assumption is that the issuance will fail.
    """
    def test_make_service_managed_by_each_host(self,
                                               santest_host_1,
                                               santest_service_host_1,
                                               santest_host_2,
                                               santest_service_host_2):
        api.Command['service_add_host'](
            santest_service_host_1.name, host=[santest_host_2.fqdn]
        )
        api.Command['service_add_host'](
            santest_service_host_2.name, host=[santest_host_1.fqdn]
        )

    def test_extend_the_ca_acl(self, santest_subca_acl, santest_host_2,
                               santest_service_host_2):
        santest_subca_acl.add_host(santest_host_2.name)

    def test_request_cert_with_additional_host(
            self, santest_subca, santest_host_1, santest_host_2,
            santest_service_host_1, santest_csr):

        with host_keytab(santest_host_1.name) as keytab_filename:
            with change_principal(santest_host_1.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                with pytest.raises(errors.ACIError):
                    api.Command.cert_request(
                        santest_csr,
                        principal=santest_service_host_1.name,
                        cacn=santest_subca.name
                    )


@pytest.mark.tier1
class TestManagedByACIOnCertRequest(CAACLEnforcementOnCertBase):
    """Test issuence of a certificate by external host

    The test verifies that the managed by attribute of a service
    is enforced on certificate signing.

    The two test cases test the issuance of a service certificate
    to a service by a second host.

    In one of them the service is not managed by the principal
    requesting the certificate, thus the issuance should fail.

    The second one makes the service managed, thus the certificate
    should be issued.
    """
    def test_update_the_caacl(self,
                              santest_subca_acl,
                              santest_host_2,
                              santest_service_host_2):
        santest_subca_acl.add_host(santest_host_2.name)
        santest_subca_acl.add_service(santest_service_host_2.name)

    def test_issuing_service_cert_by_unrelated_host(self,
                                                    santest_subca,
                                                    santest_host_1,
                                                    santest_host_2,
                                                    santest_service_host_1,
                                                    santest_csr):

        with host_keytab(santest_host_2.name) as keytab_filename:
            with change_principal(santest_host_2.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                with pytest.raises(errors.ACIError):
                    api.Command.cert_request(
                        santest_csr,
                        principal=santest_service_host_1.name,
                        cacn=santest_subca.name
                    )

    def test_issuing_service_cert_by_related_host(self,
                                                  santest_subca,
                                                  santest_host_1,
                                                  santest_host_2,
                                                  santest_service_host_1,
                                                  santest_csr):
        # The test case alters the previous state by making
        # the service managed by the second host.
        # Then it attempts to request the certificate again
        api.Command['service_add_host'](
            santest_service_host_1.name, host=[santest_host_2.fqdn]
        )

        with host_keytab(santest_host_2.name) as keytab_filename:
            with change_principal(santest_host_2.attrs['krbcanonicalname'][0],
                                  keytab=keytab_filename):
                api.Command.cert_request(
                    santest_csr,
                    principal=santest_service_host_1.name,
                    cacn=santest_subca.name
                )
