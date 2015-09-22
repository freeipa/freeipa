# -*- coding: utf-8 -*-
#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import os
import pytest
import tempfile

from ipalib import api, errors
from ipatests.util import (
    prepare_config, unlock_principal_password, change_principal)
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.test_certprofile_plugin import CertprofileTracker
from ipatests.test_xmlrpc.test_caacl_plugin import CAACLTracker

from ipapython.ipautil import run

BASE_DIR = os.path.dirname(__file__)

SMIME_PROFILE_TEMPLATE = os.path.join(BASE_DIR, 'data/smime.cfg.tmpl')
SMIME_MOD_CONSTR_PROFILE_TEMPLATE = os.path.join(BASE_DIR, 'data/smime-mod.cfg.tmpl')
CERT_OPENSSL_CONFIG_TEMPLATE = os.path.join(BASE_DIR, 'data/usercert.conf.tmpl')
CERT_RSA_PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'data/usercert-priv-key.pem')


CERT_SUBJECT_BASE = (
    api.Command.config_show()
    ['result']['ipacertificatesubjectbase'][0]
)

SMIME_USER_INIT_PW = u'Change123'
SMIME_USER_PW = u'Secret123'


def generate_user_csr(username, domain=None):
    csr_values = dict(
        ipacertbase=CERT_SUBJECT_BASE,
        ipadomain=domain if domain else api.env.domain,
        username=username)

    with tempfile.NamedTemporaryFile(mode='w') as csr_file:
        run(['openssl', 'req', '-new', '-key', CERT_RSA_PRIVATE_KEY_PATH,
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
