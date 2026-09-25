# -*- coding: utf-8 -*-
#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Tests for the profile ``keyConstraintImpl`` ``allowedKeys.*`` config.

These tests exercise the granular per-key ``allowedKeys.<ALGO>.<param>``
key-constraint configuration format introduced on the Dogtag CA side (see
dogtagpki/pki#5338, IDM-5708), which replaces the legacy comma separated
``keyType`` / ``keyParameters`` pair, e.g.::

    policyset.<set>.3.constraint.params.allowedKeys.RSA.2048=true
    policyset.<set>.3.constraint.params.allowedKeys.RSA.4096=false

FreeIPA does not implement this constraint itself -- it imports the profile
into Dogtag via ``certprofile-import`` and the constraint is enforced by the
CA at ``cert-request`` time.  The tests therefore verify the end to end
behaviour that FreeIPA users observe:

* a key size explicitly allowed by ``allowedKeys`` is issued,
* a key size not allowed by ``allowedKeys`` is rejected,
* a profile that mixes the legacy and the new format is rejected on import.

They require a live CA (like the sibling ``test_caacl_profile_enforcement``
module) and a Dogtag build that understands the ``allowedKeys.*`` format.
"""

from __future__ import absolute_import

import os
import re

import pytest

import six

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ipalib import api, errors
from ipatests.util import (
    prepare_config, unlock_principal_password, change_principal)
from ipatests.test_xmlrpc.xmlrpc_test import XMLRPC_test
from ipatests.test_xmlrpc.tracker.certprofile_plugin import CertprofileTracker
from ipatests.test_xmlrpc.tracker.caacl_plugin import CAACLTracker

if six.PY3:
    unicode = str

BASE_DIR = os.path.dirname(__file__)

RSA_PROFILE_TEMPLATE = os.path.join(
    BASE_DIR, 'data/smime_allowedkeys_rsa.cfg.tmpl')
MIXED_PROFILE_TEMPLATE = os.path.join(
    BASE_DIR, 'data/smime_allowedkeys_mixed.cfg.tmpl')

# Sizes chosen to match smime_allowedkeys_rsa.cfg.tmpl, where
# allowedKeys.RSA.2048=true and allowedKeys.RSA.4096=false.
ALLOWED_RSA_KEY_SIZE = 2048
DISALLOWED_RSA_KEY_SIZE = 4096

USER_INIT_PW = u'Change123'
USER_PW = u'Secret123'

# Wording Dogtag uses when a keyConstraintImpl refuses a request or an
# ambiguous configuration.  Matching only on the exception class is not
# enough: an unrelated CA failure (CMS unreachable, CA ACL violation,
# unknown profile) raises the same classes and would look like a
# successful rejection.
KEY_CONSTRAINT_ERROR = re.compile(
    r'allowedkeys|keyparameters|keytype|'
    r'key\s+(constraint|length|size|type|parameters)',
    re.IGNORECASE,
)


def assert_key_constraint_error(exc):
    """Fail unless ``exc`` blames the key constraint for the failure."""
    assert KEY_CONSTRAINT_ERROR.search(str(exc)), (
        'expected a key constraint violation to be reported, got: '
        '{}'.format(exc))


def generate_user_csr(username, key_size):
    """Build a PEM CSR for ``username`` signed with a fresh RSA key.

    The subject only needs a CN; the profile's subjectNameDefault rebuilds
    the final DN.  An e-mail SAN is added so the CSR is meaningful for the
    S/MIME style profile used here.
    """
    backend = default_backend()
    pkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=backend,
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, unicode(username))])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.RFC822Name(u'{}@{}'.format(username, api.env.domain))
        ]),
        False,
    ).sign(pkey, hashes.SHA256(), backend)

    return csr.public_bytes(serialization.Encoding.PEM).decode('ascii')


@pytest.fixture(scope='class')
def rsa_profile(request, xmlrpc_setup):
    profile_path = prepare_config(
        RSA_PROFILE_TEMPLATE,
        dict(ipadomain=api.env.domain, iparealm=api.env.realm))

    tracker = CertprofileTracker(
        u'smime_allowedkeys_rsa', store=True,
        desc=u"S/MIME profile with allowedKeys RSA constraint",
        profile=profile_path)

    return tracker.make_fixture(request)


@pytest.fixture(scope='class')
def keyconstraint_acl(request, xmlrpc_setup):
    tracker = CAACLTracker(u'smime_allowedkeys_acl')

    return tracker.make_fixture(request)


# Mirrors the user fixture in test_caacl_profile_enforcement: UserTracker
# has problems while setting passwords, so a plain fixture is used instead.
# The uid is prefixed so it cannot collide with the users other xmlrpc
# suites create.
@pytest.fixture(scope='class')
def keyconstraint_user(request, xmlrpc_setup):
    username = u'keyconstraint_bob'
    api.Command.user_add(uid=username, givenname=u'Bob', sn=u'Keys',
                         userpassword=USER_INIT_PW)

    unlock_principal_password(username, USER_INIT_PW, USER_PW)

    def fin():
        api.Command.user_del(username)
    request.addfinalizer(fin)

    return username


@pytest.fixture(scope='class')
def keyconstraint_group(request, xmlrpc_setup):
    api.Command.group_add(u'smime_allowedkeys_users')

    def fin():
        api.Command.group_del(u'smime_allowedkeys_users')
    request.addfinalizer(fin)

    return u'smime_allowedkeys_users'


def setup_for_issuance(profile, acl, group, user):
    """Make sure ``user`` may request ``profile`` through ``acl``.

    The ordered setup tests below already do this, but a test that is run
    on its own must not depend on them, so every step is re-applied
    idempotently here.  The re-application is untracked so that it cannot
    record a member twice in the tracker.
    """
    profile.ensure_exists()
    acl.ensure_exists()

    try:
        acl.add_profile(certprofile=profile.name, track=False)
    except errors.AlreadyGroupMember:
        pass

    try:
        api.Command.group_add_member(group, user=user)
    except errors.AlreadyGroupMember:
        pass

    try:
        acl.add_user(group=group, track=False)
    except errors.AlreadyGroupMember:
        pass


@pytest.mark.tier1
class TestAllowedKeysRSAConstraint(XMLRPC_test):
    """Enforcement of an ``allowedKeys.RSA.*`` key constraint.

    The imported profile allows RSA 2048/3072 and explicitly disallows
    RSA 1024/4096.  A request with an allowed key size must be issued and
    a request with a disallowed key size must be refused by the CA.
    """

    def test_import_profile(self, rsa_profile):
        rsa_profile.ensure_exists()

    def test_create_acl(self, keyconstraint_acl):
        keyconstraint_acl.ensure_exists()

    def test_add_profile_to_acl(self, keyconstraint_acl, rsa_profile):
        keyconstraint_acl.add_profile(certprofile=rsa_profile.name)

    def test_add_user_to_group(self, keyconstraint_group, keyconstraint_user):
        api.Command.group_add_member(keyconstraint_group,
                                     user=keyconstraint_user)

    def test_add_group_to_acl(self, keyconstraint_group, keyconstraint_acl):
        keyconstraint_acl.add_user(group=keyconstraint_group)

    def test_request_with_allowed_key_size(self, rsa_profile,
                                           keyconstraint_user,
                                           keyconstraint_group,
                                           keyconstraint_acl):
        setup_for_issuance(rsa_profile, keyconstraint_acl,
                           keyconstraint_group, keyconstraint_user)

        csr = generate_user_csr(keyconstraint_user, ALLOWED_RSA_KEY_SIZE)
        with change_principal(keyconstraint_user, USER_PW):
            api.Command.cert_request(csr, principal=keyconstraint_user,
                                     profile_id=rsa_profile.name)

    def test_request_with_disallowed_key_size(self, rsa_profile,
                                              keyconstraint_user,
                                              keyconstraint_group,
                                              keyconstraint_acl):
        setup_for_issuance(rsa_profile, keyconstraint_acl,
                           keyconstraint_group, keyconstraint_user)

        csr = generate_user_csr(keyconstraint_user, DISALLOWED_RSA_KEY_SIZE)
        with change_principal(keyconstraint_user, USER_PW):
            with pytest.raises(errors.CertificateOperationError) as excinfo:
                api.Command.cert_request(csr, principal=keyconstraint_user,
                                         profile_id=rsa_profile.name)

        # The CA reports a great many failures as CertificateOperationError;
        # make sure this request was rejected because of the key, not for
        # some unrelated reason that the allowed key size would have hit too.
        assert_key_constraint_error(excinfo.value)


@pytest.mark.tier1
class TestMixedKeyConstraintConfigRejected(XMLRPC_test):
    """A profile mixing legacy and ``allowedKeys`` config must be rejected.

    dogtagpki/pki#5338 makes the CA raise an error when a keyConstraintImpl
    entry combines the legacy ``keyType`` / ``keyParameters`` params with the
    new ``allowedKeys.*`` params.  FreeIPA should surface this as a failed
    ``certprofile-import`` rather than silently importing an ambiguous
    profile.
    """

    def test_import_mixed_profile_fails(self, xmlrpc_setup):
        profile_path = prepare_config(
            MIXED_PROFILE_TEMPLATE,
            dict(ipadomain=api.env.domain, iparealm=api.env.realm))

        with open(profile_path) as f:
            profile = unicode(f.read())

        # The exception class depends on how Dogtag reports the rejection
        # (a BadRequestException surfaces as NotFound, anything else as
        # CertificateOperationError), so the class is not pinned here.  The
        # error text is what the assertion rests on: it has to name the key
        # constraint, otherwise an unrelated import failure would pass.
        with pytest.raises(errors.PublicError) as excinfo:
            api.Command.certprofile_import(
                u'smime_allowedkeys_mixed',
                description=u"mixed key constraint profile",
                ipacertprofilestoreissued=False,
                file=profile)

        assert_key_constraint_error(excinfo.value)

        # Ensure a partial/ambiguous profile was not left behind.
        with pytest.raises(errors.NotFound):
            api.Command.certprofile_show(u'smime_allowedkeys_mixed')
