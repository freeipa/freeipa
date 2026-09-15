#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Integration tests for the ``keyConstraintImpl`` ``allowedKeys.*`` config.

The Dogtag CA gained a granular, per-key certificate profile key-constraint
format (see dogtagpki/pki#5338, IDM-5708) that replaces the legacy comma
separated ``keyType`` / ``keyParameters`` pair::

    # legacy
    policyset.<set>.3.constraint.params.keyType=RSA
    policyset.<set>.3.constraint.params.keyParameters=2048,3072,4096
    # new
    policyset.<set>.3.constraint.params.allowedKeys.RSA.2048=true
    policyset.<set>.3.constraint.params.allowedKeys.RSA.4096=false

FreeIPA imports such profiles with ``ipa certprofile-import`` and the CA
enforces the constraint at ``ipa cert-request`` time.  These tests drive the
real CLI on a live server to verify:

* a profile using the new ``allowedKeys`` format imports successfully,
* a request with an allowed RSA key size is issued,
* a request with a key size not allowed by ``allowedKeys`` is refused,
* a profile mixing the legacy and the new format is rejected on import.

Note: this exercises behaviour implemented by Dogtag; the environment must
run a PKI build that understands the ``allowedKeys.*`` format.
"""

from __future__ import absolute_import

import os
import re

import pytest

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest


# Profile template modelled on the shipped caIPAserviceCert profile, with the
# key constraint block (policy #3) left as a substitution point and all
# install-time template variables replaced by concrete values.
PROFILE_TEMPLATE = """\
profileId={profile_id}
classId=caEnrollImpl
desc={desc}
visible=false
enable=true
enableBy=admin
auth.instance_id=raCertAuth
name={name}
input.list=i1,i2
input.i1.class_id=certReqInputImpl
input.i2.class_id=submitterInfoInputImpl
output.list=o1
output.o1.class_id=certOutputImpl
policyset.list=serverCertSet
policyset.serverCertSet.list=1,2,3,4,5,6,7,8,9,10,11,12
policyset.serverCertSet.1.constraint.class_id=subjectNameConstraintImpl
policyset.serverCertSet.1.constraint.name=Subject Name Constraint
policyset.serverCertSet.1.constraint.params.pattern=CN=[^,]+,.+
policyset.serverCertSet.1.constraint.params.accept=true
policyset.serverCertSet.1.default.class_id=subjectNameDefaultImpl
policyset.serverCertSet.1.default.name=Subject Name Default
policyset.serverCertSet.1.default.params.name=\
CN=$request.req_subject_name.cn$, O={realm}
policyset.serverCertSet.2.constraint.class_id=validityConstraintImpl
policyset.serverCertSet.2.constraint.name=Validity Constraint
policyset.serverCertSet.2.constraint.params.range=740
policyset.serverCertSet.2.constraint.params.notBeforeCheck=false
policyset.serverCertSet.2.constraint.params.notAfterCheck=false
policyset.serverCertSet.2.default.class_id=validityDefaultImpl
policyset.serverCertSet.2.default.name=Validity Default
policyset.serverCertSet.2.default.params.range=731
policyset.serverCertSet.2.default.params.startTime=0
{key_constraint}
policyset.serverCertSet.4.constraint.class_id=noConstraintImpl
policyset.serverCertSet.4.constraint.name=No Constraint
policyset.serverCertSet.4.default.class_id=authorityKeyIdentifierExtDefaultImpl
policyset.serverCertSet.4.default.name=Authority Key Identifier Default
policyset.serverCertSet.5.constraint.class_id=noConstraintImpl
policyset.serverCertSet.5.constraint.name=No Constraint
policyset.serverCertSet.5.default.class_id=authInfoAccessExtDefaultImpl
policyset.serverCertSet.5.default.name=AIA Extension Default
policyset.serverCertSet.5.default.params.authInfoAccessADEnable_0=true
policyset.serverCertSet.5.default.params.authInfoAccessADLocationType_0=URIName
policyset.serverCertSet.5.default.params.authInfoAccessADLocation_0=http://ipa-ca.{domain}/ca/ocsp
policyset.serverCertSet.5.default.params.authInfoAccessADMethod_0=1.3.6.1.5.5.7.48.1
policyset.serverCertSet.5.default.params.authInfoAccessCritical=false
policyset.serverCertSet.5.default.params.authInfoAccessNumADs=1
policyset.serverCertSet.6.constraint.class_id=keyUsageExtConstraintImpl
policyset.serverCertSet.6.constraint.name=Key Usage Extension Constraint
policyset.serverCertSet.6.constraint.params.keyUsageCritical=true
policyset.serverCertSet.6.constraint.params.keyUsageDigitalSignature=true
policyset.serverCertSet.6.constraint.params.keyUsageNonRepudiation=true
policyset.serverCertSet.6.constraint.params.keyUsageDataEncipherment=true
policyset.serverCertSet.6.constraint.params.keyUsageKeyEncipherment=true
policyset.serverCertSet.6.constraint.params.keyUsageKeyAgreement=false
policyset.serverCertSet.6.constraint.params.keyUsageKeyCertSign=false
policyset.serverCertSet.6.constraint.params.keyUsageCrlSign=false
policyset.serverCertSet.6.constraint.params.keyUsageEncipherOnly=false
policyset.serverCertSet.6.constraint.params.keyUsageDecipherOnly=false
policyset.serverCertSet.6.default.class_id=keyUsageExtDefaultImpl
policyset.serverCertSet.6.default.name=Key Usage Default
policyset.serverCertSet.6.default.params.keyUsageCritical=true
policyset.serverCertSet.6.default.params.keyUsageDigitalSignature=true
policyset.serverCertSet.6.default.params.keyUsageNonRepudiation=true
policyset.serverCertSet.6.default.params.keyUsageDataEncipherment=true
policyset.serverCertSet.6.default.params.keyUsageKeyEncipherment=true
policyset.serverCertSet.6.default.params.keyUsageKeyAgreement=false
policyset.serverCertSet.6.default.params.keyUsageKeyCertSign=false
policyset.serverCertSet.6.default.params.keyUsageCrlSign=false
policyset.serverCertSet.6.default.params.keyUsageEncipherOnly=false
policyset.serverCertSet.6.default.params.keyUsageDecipherOnly=false
policyset.serverCertSet.7.constraint.class_id=noConstraintImpl
policyset.serverCertSet.7.constraint.name=No Constraint
policyset.serverCertSet.7.default.class_id=extendedKeyUsageExtDefaultImpl
policyset.serverCertSet.7.default.name=Extended Key Usage Extension Default
policyset.serverCertSet.7.default.params.exKeyUsageCritical=false
policyset.serverCertSet.7.default.params.exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2
policyset.serverCertSet.8.constraint.class_id=signingAlgConstraintImpl
policyset.serverCertSet.8.constraint.name=No Constraint
policyset.serverCertSet.8.constraint.params.signingAlgsAllowed=SHA1withRSA,SHA256withRSA,SHA384withRSA,SHA512withRSA,MD5withRSA,MD2withRSA,SHA1withDSA,SHA1withEC,SHA256withEC,SHA384withEC,SHA512withEC
policyset.serverCertSet.8.default.class_id=signingAlgDefaultImpl
policyset.serverCertSet.8.default.name=Signing Alg
policyset.serverCertSet.8.default.params.signingAlg=-
policyset.serverCertSet.9.constraint.class_id=noConstraintImpl
policyset.serverCertSet.9.constraint.name=No Constraint
policyset.serverCertSet.9.default.class_id=crlDistributionPointsExtDefaultImpl
policyset.serverCertSet.9.default.name=CRL Distribution Points Extension Default
policyset.serverCertSet.9.default.params.crlDistPointsCritical=false
policyset.serverCertSet.9.default.params.crlDistPointsNum=1
policyset.serverCertSet.9.default.params.crlDistPointsEnable_0=true
policyset.serverCertSet.9.default.params.crlDistPointsIssuerName_0=\
CN=Certificate Authority,o=ipaca
policyset.serverCertSet.9.default.params.crlDistPointsIssuerType_0=\
DirectoryName
policyset.serverCertSet.9.default.params.crlDistPointsPointName_0=http://ipa-ca.{domain}/ipa/crl/MasterCRL.bin
policyset.serverCertSet.9.default.params.crlDistPointsPointType_0=URIName
policyset.serverCertSet.9.default.params.crlDistPointsReasons_0=
policyset.serverCertSet.10.constraint.class_id=noConstraintImpl
policyset.serverCertSet.10.constraint.name=No Constraint
policyset.serverCertSet.10.default.class_id=subjectKeyIdentifierExtDefaultImpl
policyset.serverCertSet.10.default.name=Subject Key Identifier Extension Default
policyset.serverCertSet.10.default.params.critical=false
policyset.serverCertSet.11.constraint.class_id=noConstraintImpl
policyset.serverCertSet.11.constraint.name=No Constraint
policyset.serverCertSet.11.default.class_id=userExtensionDefaultImpl
policyset.serverCertSet.11.default.name=User Supplied Extension Default
policyset.serverCertSet.11.default.params.userExtOID=2.5.29.17
policyset.serverCertSet.12.constraint.class_id=noConstraintImpl
policyset.serverCertSet.12.constraint.name=No Constraint
policyset.serverCertSet.12.default.class_id=commonNameToSANDefaultImpl
policyset.serverCertSet.12.default.name=\
Copy Common Name to Subject Alternative Name
"""

# allowedKeys constraint: RSA 2048/3072 permitted, 1024/4096 refused.
ALLOWEDKEYS_RSA_CONSTRAINT = """\
policyset.serverCertSet.3.constraint.class_id=keyConstraintImpl
policyset.serverCertSet.3.constraint.name=Key Constraint
policyset.serverCertSet.3.constraint.params.allowedKeys.RSA.1024=false
policyset.serverCertSet.3.constraint.params.allowedKeys.RSA.2048=true
policyset.serverCertSet.3.constraint.params.allowedKeys.RSA.3072=true
policyset.serverCertSet.3.constraint.params.allowedKeys.RSA.4096=false
policyset.serverCertSet.3.default.class_id=userKeyDefaultImpl
policyset.serverCertSet.3.default.name=Key Default"""

# Invalid: mixes the legacy keyType/keyParameters with the new allowedKeys.
MIXED_CONSTRAINT = """\
policyset.serverCertSet.3.constraint.class_id=keyConstraintImpl
policyset.serverCertSet.3.constraint.name=Key Constraint
policyset.serverCertSet.3.constraint.params.keyType=RSA
policyset.serverCertSet.3.constraint.params.keyParameters=2048,3072
policyset.serverCertSet.3.constraint.params.allowedKeys.RSA.2048=true
policyset.serverCertSet.3.constraint.params.allowedKeys.RSA.3072=true
policyset.serverCertSet.3.default.class_id=userKeyDefaultImpl
policyset.serverCertSet.3.default.name=Key Default"""

ALLOWED_KEY_SIZE = 2048
DISALLOWED_KEY_SIZE = 4096

# Wording Dogtag uses when a keyConstraintImpl refuses a request or an
# ambiguous configuration.  A bare non-zero exit status is not enough: an
# unrelated CA failure (CMS unreachable, CA ACL violation, unknown profile)
# would then look like a successful rejection.
KEY_CONSTRAINT_ERROR = re.compile(
    r'allowedkeys|keyparameters|keytype|'
    r'key\s+(constraint|length|size|type|parameters)',
    re.IGNORECASE,
)


def assert_key_constraint_error(text):
    """Fail unless ``text`` blames the key constraint for the failure."""
    assert KEY_CONSTRAINT_ERROR.search(text), (
        'expected a key constraint violation to be reported, got: '
        '{}'.format(text))


class TestCertProfileAllowedKeysConstraint(IntegrationTest):
    """Enforcement of the ``allowedKeys.*`` key constraint via the CLI."""

    num_replicas = 0

    PROFILE_ID = u'keyconstraintrsa'
    MIXED_PROFILE_ID = u'keyconstraintmixed'
    USER = u'keyconstraintuser'
    CAACL = u'keyconstraint_acl'

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)

    @pytest.fixture(autouse=True, scope='class')
    def keyconstraint_teardown(self, mh):
        """Remove the entries this class creates, once the class is done.

        This is class teardown rather than a test so that a reordered or
        partial run cannot delete the profiles and the user while the
        remaining tests still need them.  It depends on ``mh`` so that it
        tears down before the server is uninstalled.
        """
        yield
        tasks.kinit_admin(self.master)
        # The CA ACL references the profile, so it has to go first.
        self.master.run_command(
            ['ipa', 'caacl-del', self.CAACL], raiseonerr=False)
        for profile_id in (self.PROFILE_ID, self.MIXED_PROFILE_ID):
            self.master.run_command(
                ['ipa', 'certprofile-del', profile_id], raiseonerr=False)
        self.master.run_command(
            ['ipa', 'user-del', self.USER], raiseonerr=False)

    def _ensure_kinit(self):
        """Ensure we have a valid Kerberos ticket."""
        tasks.kinit_admin(self.master)

    def _profile_exists(self, profile_id):
        """Check if a certificate profile exists."""
        result = self.master.run_command(
            ['ipa', 'certprofile-show', profile_id],
            raiseonerr=False)
        return result.returncode == 0

    def _user_exists(self, user):
        """Check if a user exists."""
        result = self.master.run_command(
            ['ipa', 'user-show', user],
            raiseonerr=False)
        return result.returncode == 0

    def _caacl_exists(self, caacl):
        """Check if a CA ACL exists."""
        result = self.master.run_command(
            ['ipa', 'caacl-show', caacl],
            raiseonerr=False)
        return result.returncode == 0

    def _ensure_profile(self, profile_id, key_constraint, desc):
        """Ensure the certificate profile exists (idempotent)."""
        if not self._profile_exists(profile_id):
            self._import_profile(profile_id, key_constraint, desc)

    def _ensure_user(self):
        """Ensure the test user exists (idempotent)."""
        if not self._user_exists(self.USER):
            tasks.user_add(self.master, self.USER)

    def _ensure_caacl(self):
        """Ensure the CA ACL exists and is properly configured (idempotent)."""
        if not self._caacl_exists(self.CAACL):
            # Create the CA ACL
            self.master.run_command([
                'ipa', 'caacl-add', self.CAACL,
                '--desc=ACL for keyconstraint testing'
            ])
            # Add the profile to the ACL
            self.master.run_command([
                'ipa', 'caacl-add-profile', self.CAACL,
                '--certprofiles', self.PROFILE_ID
            ])
            # Add the user to the ACL
            self.master.run_command([
                'ipa', 'caacl-add-user', self.CAACL,
                '--users', self.USER
            ])

    def _setup_for_issuance(self):
        """Ensure all prerequisites for certificate issuance are in place."""
        self._ensure_kinit()
        self._ensure_profile(
            self.PROFILE_ID,
            ALLOWEDKEYS_RSA_CONSTRAINT,
            u'allowedKeys RSA constraint profile'
        )
        self._ensure_user()
        self._ensure_caacl()

    def _build_profile(self, profile_id, key_constraint, desc):
        return PROFILE_TEMPLATE.format(
            profile_id=profile_id,
            name=u'Test profile {}'.format(profile_id),
            desc=desc,
            key_constraint=key_constraint,
            realm=self.master.domain.realm,
            domain=self.master.domain.name,
        )

    def _import_profile(self, profile_id, key_constraint, desc,
                        raiseonerr=True):
        profile = self._build_profile(profile_id, key_constraint, desc)
        remote_path = os.path.join('/root', '{}.cfg'.format(profile_id))
        self.master.put_file_contents(remote_path, profile)
        try:
            return self.master.run_command(
                ['ipa', 'certprofile-import', profile_id,
                 '--file', remote_path,
                 '--desc', desc,
                 '--store=1'],
                raiseonerr=raiseonerr)
        finally:
            self.master.run_command(['rm', '-f', remote_path])

    def _request_cert(self, key_size, profile_id, raiseonerr=True):
        """Generate a CSR of ``key_size`` on the master and request a cert."""
        base = os.path.join('/root', 'keyconstraint-{}'.format(key_size))
        key_file = base + '.key'
        csr_file = base + '.csr'
        cert_file = base + '.crt'

        self.master.run_command(
            ['openssl', 'req', '-newkey', 'rsa:{}'.format(key_size),
             '-keyout', key_file, '-nodes', '-out', csr_file,
             '-subj', '/CN={}'.format(self.USER)])
        try:
            return self.master.run_command(
                ['ipa', 'cert-request', csr_file,
                 '--principal', self.USER,
                 '--profile-id', profile_id,
                 '--certificate-out', cert_file],
                raiseonerr=raiseonerr)
        finally:
            self.master.run_command(
                ['rm', '-f', key_file, csr_file, cert_file])

    def test_import_allowedkeys_profile(self):
        """A profile using the new allowedKeys format imports successfully."""
        self._ensure_kinit()
        # Only import if it doesn't already exist
        if self._profile_exists(self.PROFILE_ID):
            # Clean up existing profile to test import
            self.master.run_command(
                ['ipa', 'certprofile-del', self.PROFILE_ID],
                raiseonerr=False)

        result = self._import_profile(
            self.PROFILE_ID, ALLOWEDKEYS_RSA_CONSTRAINT,
            u'allowedKeys RSA constraint profile')
        assert 'Imported profile "{}"'.format(self.PROFILE_ID) \
            in result.stdout_text

    def test_add_user(self):
        """Test user creation (can run independently)."""
        self._ensure_kinit()
        # Only create if doesn't exist
        if not self._user_exists(self.USER):
            tasks.user_add(self.master, self.USER)
        # Verify user exists
        assert self._user_exists(self.USER)

    def test_allowed_key_size_is_issued(self):
        """A request with an allowed RSA key size (2048) is issued."""
        # Ensure all prerequisites are in place
        self._setup_for_issuance()

        result = self._request_cert(ALLOWED_KEY_SIZE, self.PROFILE_ID)
        assert 'Certificate:' in result.stdout_text \
            or 'Serial number:' in result.stdout_text

    def test_disallowed_key_size_is_rejected(self):
        """A request with a key size not in allowedKeys (4096) is refused."""
        # Ensure all prerequisites are in place
        self._setup_for_issuance()

        result = self._request_cert(
            DISALLOWED_KEY_SIZE, self.PROFILE_ID, raiseonerr=False)
        # The CA must refuse issuance; a zero return code would mean the
        # allowedKeys constraint was not enforced.
        assert result.returncode != 0, (
            'cert-request unexpectedly succeeded for a disallowed key size; '
            'the allowedKeys constraint was not enforced')
        assert_key_constraint_error(result.stderr_text)

    def test_mixed_config_profile_is_rejected(self):
        """A profile mixing legacy and allowedKeys config fails to import."""
        self._ensure_kinit()

        # Clean up any existing mixed profile from previous runs
        if self._profile_exists(self.MIXED_PROFILE_ID):
            self.master.run_command(
                ['ipa', 'certprofile-del', self.MIXED_PROFILE_ID],
                raiseonerr=False)

        result = self._import_profile(
            self.MIXED_PROFILE_ID, MIXED_CONSTRAINT,
            u'mixed key constraint profile', raiseonerr=False)
        assert result.returncode != 0, (
            'certprofile-import unexpectedly accepted a profile that mixes '
            'keyParameters with allowedKeys')
        assert_key_constraint_error(result.stderr_text)

        # A rejected import must not leave the profile behind.
        show = self.master.run_command(
            ['ipa', 'certprofile-show', self.MIXED_PROFILE_ID],
            raiseonerr=False)
        assert show.returncode != 0
