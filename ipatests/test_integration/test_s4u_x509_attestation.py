# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
"""
Integration tests for ipalib.x509_attestation with AD trust (OIDC schema).

Tests the S4U2Self X.509 attestation flow with service_type="oidc" against
both IPA users and AD trust users.  Verifies that the IPA KDB plugin
(ipa_kdb_s4u_x509) accepts the attestation certificate and issues a Kerberos
service ticket via S4U2Self / PA-FOR-X509-USER.

Topology
--------
  master  — IPA server with AD trust, ipa-kdb-s4u-x509 KDB plugin loaded
  ad      — Active Directory domain controller
  client  — not used (topology='line' still needs 1 client in BaseTestTrust)

Required packages on master
---------------------------
  python3-cryptography, python3-gssapi (both available on IPA servers)
"""

from __future__ import absolute_import

import textwrap

from ipatests.test_integration.test_trust import BaseTestTrust
from ipatests.pytest_ipa.integration import tasks
from ipapython.ipautil import ipa_generate_password

# ---------------------------------------------------------------------------
# Helper Python scripts deployed to the IPA master
# ---------------------------------------------------------------------------

# Generates an EC P-256 attestation key pair, writes the private key to
# argv[1], and prints the base64-encoded DER public-key SPKI to stdout.
_KEYGEN_SCRIPT = textwrap.dedent("""\
    #!/usr/bin/python3
    # argv[1]: private key path (PKCS#8 PEM)
    # argv[2]: public key path (SubjectPublicKeyInfo PEM)
    import sys
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    key_path, pub_path = sys.argv[1], sys.argv[2]
    key = ec.generate_private_key(ec.SECP256R1())
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(pub_path, 'wb') as f:
        f.write(key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
""")

# Loopback GSSAPI exchange helper: accepts the S4U token with the service
# keytab and retrieves "auth-indicators" via gss_get_name_attribute().
# Returns (sorted_indicators, context_lifetime_secs) so callers can assert
# both indicator presence and KDC-enforced ticket-policy limits.
# Included verbatim into each test script (OIDC via concatenation,
# SSH/generic via f-string interpolation).
_INDICATORS_HELPER = textwrap.dedent("""\

    def _get_indicators(creds, service_principal, keytab_path):
        # Loopback GSSAPI exchange: init with S4U creds, accept with keytab.
        # Returns (sorted_auth_indicators, context_lifetime_secs).
        # context_lifetime reflects the KDC-enforced ticket lifetime so
        # callers can assert per-indicator krbtpolicy limits.
        import gssapi
        import gssapi.raw as gss_raw
        AUTH_IND_ATTR = b"auth-indicators"
        target = gssapi.Name(
            service_principal,
            name_type=gssapi.NameType.kerberos_principal,
        )
        acc_creds = gssapi.Credentials(
            name=target,
            usage='accept',
            mechs=[gssapi.MechType.kerberos],
            store={'keytab': keytab_path},
        )
        init_ctx = gssapi.SecurityContext(
            name=target,
            creds=creds,
            usage='initiate',
            mechs=[gssapi.MechType.kerberos],
        )
        token = init_ctx.step()
        acc_ctx = gssapi.SecurityContext(usage='accept', creds=acc_creds)
        acc_ctx.step(token)
        src = acc_ctx.initiator_name
        lifetime = acc_ctx.lifetime   # remaining seconds; reflects KDC policy
        try:
            res = gss_raw.get_name_attribute(src, AUTH_IND_ATTR)
            return sorted(v.decode('utf-8') for v in res.values), lifetime
        except Exception:
            return [], lifetime
""")

# Builds an OIDC attestation certificate for a given user, performs
# S4U2Self via gssapi, and prints the impersonated principal name followed
# by sorted "indicators:" and "lifetime:" lines for per-test assertion.
#
# argv: username realm hostname keytab_path attest_key_path
_S4U_OIDC_SCRIPT = textwrap.dedent("""\
    #!/usr/bin/python3
    import hashlib
    import sys
    from cryptography.hazmat.primitives import serialization
    from ipalib.x509_attestation import (
        get_host_keytab_key,
        build_oidc_attestation_cert,
        acquire_s4u_creds,
    )

    username, realm, hostname, keytab_path, attest_key_path = sys.argv[1:6]

    with open(attest_key_path, 'rb') as f:
        attest_key = serialization.load_pem_private_key(
            f.read(), password=None)
    host_pubkey = attest_key.public_key()

    # realm=None: scan the keytab for any service/hostname@* entry so that
    # the service realm (IPA) is taken from the keytab rather than from
    # the user realm (which may be an AD realm in trust scenarios).
    keytab_entry = get_host_keytab_key(
        hostname, None, keytab_path=keytab_path, service_type='service')

    # Simulate an OIDC token exchange: the real caller would use the actual
    # access token issued by the IdP.  For testing purposes a fixed dummy
    # token is used so that the certificate content is deterministic.
    dummy_token = f'{username}@{realm}:test_oidc_token'.encode()
    cert_der = build_oidc_attestation_cert(
        user=username,
        realm=realm,
        issuer=f'https://{hostname}',
        access_token_hash=hashlib.sha256(dummy_token).digest(),
        host_pubkey=host_pubkey,
        keytab_entry=keytab_entry,
        amr=['pwd', 'otp'],
    )

    service_principal = keytab_entry.principal
    creds = acquire_s4u_creds(
        cert_der=cert_der,
        host_principal=service_principal,
        keytab_path=keytab_path,
    )
""") + _INDICATORS_HELPER + textwrap.dedent("""\
    inds, lt = _get_indicators(creds, service_principal, keytab_path)
    print(str(creds.name))
    print('indicators:' + ','.join(inds))
    print('lifetime:' + str(lt))
""")


class TestTrustS4UX509Oidc(BaseTestTrust):
    """
    S4U2Self X.509 attestation with OIDC schema against AD trust.

    Simulates an OIDC provider running on the IPA master that:
      1. Holds the host Kerberos keytab (/etc/krb5.keytab or a service copy).
      2. Has a registered EC attestation public key
         (ipaKrbServiceAttestationKey on the host service LDAP entry).
      3. Calls ipalib.x509_attestation.build_service_attestation_cert() to
         build an OIDC attestation X.509 certificate after a user login.
      4. Calls ipalib.x509_attestation.acquire_s4u_creds() to exchange the
         certificate for a Kerberos service ticket via S4U2Self.

    The IPA KDB plugin (ipa_kdb_s4u_x509) validates the certificate by:
      - Verifying the id-ce-kerberosServiceIssuerBinding signature against
        the registered ipaKrbServiceAttestationKey.
      - Confirming the enctype and kvno match the current host keytab entry.
      - Resolving the PKINIT SAN to the target Kerberos principal (IPA user
        or AD trust user via referral).
    """

    topology = 'line'
    num_ad_treedomains = 0
    num_ad_domains = 1
    num_ad_subdomains = 0
    num_clients = 0

    ipa_test_user = 'oidcattestu'
    ipa_test_password = None

    # Paths used on the IPA master
    attest_key_path = '/etc/ipa/s4u_x509_attest.key'    # private key
    attest_pubkey_path = '/etc/ipa/s4u_x509_attest.pub'  # public key PEM SPKI
    keygen_script_path = '/etc/ipa/s4u_x509_keygen.py'
    attest_script_path = '/etc/ipa/s4u_x509_run.py'
    keytab_path = '/etc/ipa/s4u_x509_host.keytab'

    @classmethod
    def install(cls, mh):
        """Set up AD trust, attestation key, host keytab, and IPA test user."""
        super().install(mh)
        tasks.install_adtrust(cls.master)
        tasks.configure_dns_for_trust(cls.master, cls.ad)
        tasks.sync_time(cls.master, cls.ad)
        tasks.establish_trust_with_ad(
            cls.master, cls.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

        hostname = cls.master.hostname

        # Create IPA user that will be impersonated via OIDC attestation.
        cls.ipa_test_password = ipa_generate_password()
        tasks.create_active_user(
            cls.master, cls.ipa_test_user,
            password=cls.ipa_test_password,
            first='Oidc', last='Attest',
        )

        # Deploy helper scripts to the master.
        cls.master.put_file_contents(cls.keygen_script_path, _KEYGEN_SCRIPT)
        cls.master.put_file_contents(cls.attest_script_path, _S4U_OIDC_SCRIPT)
        cls.master.run_command(
            ['chmod', '700', cls.keygen_script_path, cls.attest_script_path]
        )

        # Generate EC P-256 key pair: private key to attest_key_path,
        # public key (PEM SPKI) to attest_pubkey_path.
        cls.master.run_command([
            'python3', cls.keygen_script_path,
            cls.attest_key_path, cls.attest_pubkey_path,
        ])

        # Register the attestation public key on the host service LDAP entry.
        # The IPA KDB s4u_x509 plugin reads ipaKrbServiceAttestationKey to
        # validate the host_pubkey embedded in the attestation certificate.
        # Also register 'pam' as an allowed attestation type so the generic
        # handler tests can use it without a dedicated handler entry.
        tasks.kinit_admin(cls.master)
        service_name = f'service/{hostname}'
        cls.master.run_command([
            'ipa', 'service-add', service_name
        ])
        cls.master.run_command([
            'ipa', 'service-add-attestation-key', service_name,
            '--pubkey', cls.attest_pubkey_path,
            '--type', 'pam',
        ])

        # Retrieve the host keytab; restrict permissions so the scripts can
        # read it without a full root context.
        cls.master.run_command([
            'ipa-getkeytab',
            '-s', cls.master.hostname,
            '-k', cls.keytab_path,
            '-p', service_name,
        ])
        cls.master.run_command(['chmod', '600', cls.keytab_path])

        tasks.clear_sssd_cache(cls.master)
        tasks.wait_for_sssd_domain_status_online(cls.master)

    @staticmethod
    def _parse_indicators(stdout_text):
        """Parse the 'indicators:' line from script stdout."""
        for line in stdout_text.splitlines():
            if line.startswith('indicators:'):
                val = line[len('indicators:'):].strip()
                return sorted(val.split(',')) if val else []
        return []

    @staticmethod
    def _parse_lifetime(stdout_text):
        """Parse the 'lifetime:N' line; return remaining seconds or None."""
        for line in stdout_text.splitlines():
            if line.startswith('lifetime:'):
                return int(line[len('lifetime:'):].strip())
        return None

    def _acquire_s4u_oidc(self, username, realm):
        """
        Run the S4U2Self attestation script on the master.

        Invokes _S4U_OIDC_SCRIPT with the supplied username and realm.
        Returns the run_command result; raises RemoteCommandError on failure.
        """
        return self.master.run_command([
            'python3', self.attest_script_path,
            username,
            realm,
            self.master.hostname,
            self.keytab_path,
            self.attest_key_path,
        ])

    def test_oidc_attestation_ipa_user(self):
        """
        S4U2Self OIDC attestation succeeds for an IPA user.

        Simulates an OIDC provider attesting a completed login by an IPA
        user and acquiring a Kerberos service ticket via S4U2Self.  Verifies
        that the IPA KDB plugin accepts the attestation certificate and
        issues a ticket in the impersonated user's name, and that auth
        indicators oidc-authn:pwd and oidc-authn:otp are present.
        """
        realm = self.master.domain.realm
        result = self._acquire_s4u_oidc(self.ipa_test_user, realm)
        assert self.ipa_test_user in result.stdout_text, (
            f"Expected {self.ipa_test_user!r} in S4U2Self credential "
            f"name; got: {result.stdout_text!r}"
        )
        indicators = self._parse_indicators(result.stdout_text)
        assert 'oidc-authn:otp' in indicators, (
            f"Expected 'oidc-authn:otp' in indicators; got {indicators!r}"
        )
        assert 'oidc-authn:pwd' in indicators, (
            f"Expected 'oidc-authn:pwd' in indicators; got {indicators!r}"
        )

    def test_oidc_attestation_ad_user(self):
        """
        S4U2Self OIDC attestation succeeds for an AD trust user.

        Simulates an OIDC provider attesting a completed login by a user
        from the trusted AD domain.  The attestation certificate carries the
        AD user's Kerberos principal in the PKINIT SAN (KRB_NT_PRINCIPAL
        with realm=<AD_DOMAIN>).  The IPA KDB plugin must accept the cert
        and resolve the user via the AD trust referral path.
        """
        # aduser is "nonposixuser@<ad_domain>" — split to get components.
        ad_username = self.aduser.split('@', maxsplit=1)[0]   # "nonposixuser"
        ad_realm = self.ad_domain.upper()          # "AD.DOMAIN"

        result = self._acquire_s4u_oidc(ad_username, ad_realm)
        assert ad_username in result.stdout_text, (
            f"Expected {ad_username!r} in S4U2Self credential "
            f"name; got: {result.stdout_text!r}"
        )
        indicators = self._parse_indicators(result.stdout_text)
        assert indicators == [], (
            f"Expected no auth indicators for AD user OIDC; "
            f"got {indicators!r}"
        )

    def _acquire_s4u_ssh(self, username, user_realm):
        """
        Perform SSH password-auth S4U2Self attestation on the master.

        Uses /etc/ssh/ssh_host_ecdsa_key.pub as host_pubkey (registered in the
        host's ipasshpubkey LDAP attribute) and /etc/krb5.keytab for the host
        service principal.  The Kerberos host realm is always the IPA realm;
        user_realm may differ (e.g. a trusted AD realm).
        """
        hostname = self.master.hostname
        ipa_realm = self.master.domain.realm

        _svc = f'host/{hostname}@{ipa_realm}'
        ssh_script = textwrap.dedent(f"""\
            import os
            from cryptography.hazmat.primitives.serialization import (
                load_ssh_public_key,
            )
            from ipalib.x509_attestation import (
                get_host_keytab_key,
                build_attestation_cert,
                acquire_s4u_creds,
            )

            with open('/etc/ssh/ssh_host_ecdsa_key.pub', 'rb') as f:
                host_pubkey = load_ssh_public_key(f.read())

            keytab_entry = get_host_keytab_key({hostname!r}, {ipa_realm!r})
            cert_der = build_attestation_cert(
                user={username!r},
                realm={user_realm!r},
                auth_method='password',
                session_id=os.urandom(32),
                host_pubkey=host_pubkey,
                keytab_entry=keytab_entry,
            )
            creds = acquire_s4u_creds(
                cert_der=cert_der,
                host_principal={_svc!r},
                keytab_path='/etc/krb5.keytab',
            )
        """) + _INDICATORS_HELPER + textwrap.dedent(f"""\
            inds, lt = _get_indicators(creds, {_svc!r}, '/etc/krb5.keytab')
            print(str(creds.name))
            print('indicators:' + ','.join(inds))
            print('lifetime:' + str(lt))
        """)
        return self.master.run_command(['python3', '-c', ssh_script])

    def _acquire_s4u_generic(self, username, user_realm):
        """
        Perform generic (PAM) S4U2Self attestation on the master.

        Uses the registered EC attestation key (attest_key_path) as
        host_pubkey and the service keytab (keytab_path).  The service
        principal is read from the keytab.  service_type='pam' must be
        registered in ipaKrbServiceAttestationType on the service LDAP entry
        (done in install() via --type pam).
        """
        hostname = self.master.hostname
        keytab_path = self.keytab_path
        attest_key_path = self.attest_key_path

        script = textwrap.dedent(f"""\
            from cryptography.hazmat.primitives import serialization
            from ipalib.x509_attestation import (
                get_host_keytab_key,
                build_service_attestation_cert,
                acquire_s4u_creds,
            )

            with open({attest_key_path!r}, 'rb') as f:
                attest_key = serialization.load_pem_private_key(
                    f.read(), password=None)
            host_pubkey = attest_key.public_key()

            keytab_entry = get_host_keytab_key(
                {hostname!r}, None,
                keytab_path={keytab_path!r},
                service_type='service',
            )
            cert_der = build_service_attestation_cert(
                user={username!r},
                realm={user_realm!r},
                service_type='pam',
                host_pubkey=host_pubkey,
                keytab_entry=keytab_entry,
            )
            creds = acquire_s4u_creds(
                cert_der=cert_der,
                host_principal=keytab_entry.principal,
                keytab_path={keytab_path!r},
            )
            _svc_princ = keytab_entry.principal
            _ktpath = {keytab_path!r}
        """) + _INDICATORS_HELPER + textwrap.dedent("""\
            inds, lt = _get_indicators(creds, _svc_princ, _ktpath)
            print(str(creds.name))
            print('indicators:' + ','.join(inds))
            print('lifetime:' + str(lt))
        """)
        return self.master.run_command(['python3', '-c', script])

    def test_ssh_attestation_ipa_user(self):
        """
        S4U2Self SSH attestation with auth_method='password' succeeds.

        Simulates an SSH server attesting a password-authenticated login.
        All host SSH keys are registered automatically in the host's LDAP
        entry (ipasshpubkey).  ECDSA P-256 is selected because it is accepted
        in both FIPS and non-FIPS mode; Ed25519 would be rejected by the KDB
        plugin in FIPS mode.  An ephemeral subject key is used (password auth
        does not carry the user's public key).  Verifies that the IPA KDB
        plugin accepts the certificate, resolves the user, and issues a ticket.
        """
        realm = self.master.domain.realm
        result = self._acquire_s4u_ssh(self.ipa_test_user, realm)
        assert self.ipa_test_user in result.stdout_text, (
            f"Expected {self.ipa_test_user!r} in S4U2Self credential name "
            f"via SSH attestation; got: {result.stdout_text!r}"
        )
        indicators = self._parse_indicators(result.stdout_text)
        assert 'ssh-authn:password' in indicators, (
            f"Expected 'ssh-authn:password' in indicators; got {indicators!r}"
        )

    def test_ssh_attestation_ad_user_no_override(self):
        """
        SSH S4U2Self attestation succeeds for an AD user with no DTV entry.

        When there is no Default Trust View ID override for the AD user the
        IPA KDB plugin cannot resolve the user locally in TGS context.  MIT
        Kerberos falls back to an internal AS-REQ for realm discovery, which
        calls ipadb_get_s4u_x509_principal() with KRB5_KDB_FLAG_REFERRAL_OK
        set.  The plugin detects the foreign realm and returns a thin referral
        entry so the KDC can steer S4U2Self to the user's home AD domain.
        No auth indicators are attached to the resulting ticket.
        """
        ad_username = self.aduser.split('@', maxsplit=1)[0]
        ad_realm = self.ad_domain.upper()

        result = self._acquire_s4u_ssh(ad_username, ad_realm)
        assert ad_username in result.stdout_text, (
            f"Expected {ad_username!r} in S4U2Self credential name via SSH "
            f"attestation (no DTV); got: {result.stdout_text!r}"
        )
        indicators = self._parse_indicators(result.stdout_text)
        assert indicators == [], (
            f"Expected no auth indicators for AD user (no DTV); "
            f"got {indicators!r}"
        )

    def test_ssh_attestation_ad_user_with_ssh_override(self):
        """
        SSH S4U2Self attestation succeeds for an AD user with a DTV SSH key.

        Creates a Default Trust View ID override entry for the AD user that
        carries an SSH public key (ipasshpubkey).  The IPA KDB plugin finds
        the DTV entry in Pass 2 but Phase 2 certificate-to-override matching
        is not yet implemented, so S4U2Self still succeeds via the cross-realm
        referral path.  Verifies that the presence of a DTV override does not
        break attestation.
        """
        ad_username = self.aduser.split('@', maxsplit=1)[0]
        ad_user_fq = self.aduser          # "nonposixuser@ad.domain" (lowercase)
        ad_realm = self.ad_domain.upper()

        # Generate a throw-away ECDSA key to populate ipasshpubkey in the DTV.
        self.master.run_command([
            'ssh-keygen', '-t', 'ecdsa', '-b', '256',
            '-f', '/tmp/s4u_dtv_ssh_key', '-N', '',
        ])
        pubkey_result = self.master.run_command(
            ['cat', '/tmp/s4u_dtv_ssh_key.pub'])
        ssh_pubkey = pubkey_result.stdout_text.strip()

        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'idoverrideuser-add', 'Default Trust View', ad_user_fq,
                '--sshpubkey', ssh_pubkey,
            ])

            result = self._acquire_s4u_ssh(ad_username, ad_realm)
            assert ad_username in result.stdout_text, (
                f"Expected {ad_username!r} in S4U2Self credential name via "
                f"SSH attestation (DTV with SSH key); "
                f"got: {result.stdout_text!r}"
            )
            indicators = self._parse_indicators(result.stdout_text)
            assert indicators == [], (
                f"Expected no auth indicators for AD user (DTV SSH key); "
                f"got {indicators!r}"
            )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'idoverrideuser-del',
                'Default Trust View', ad_user_fq,
            ], raiseonerr=False)
            self.master.run_command(
                ['rm', '-f',
                 '/tmp/s4u_dtv_ssh_key', '/tmp/s4u_dtv_ssh_key.pub'],
                raiseonerr=False,
            )

    def test_generic_attestation_ipa_user(self):
        """
        Generic (PAM) S4U2Self attestation with per-method ticket policy.

        Uses build_service_attestation_cert() with service_type='pam' and the
        registered EC attestation key as host_pubkey.  Sets a short per-method
        krbAuthIndMaxTicketLife;pam-authn--unknown on the service LDAP entry,
        acquires the S4U2Self ticket, then verifies:
          - auth indicator 'pam-authn:unknown' is present in the ticket
          - the accepted GSSAPI context lifetime is capped at the short policy
        Since PAM_POLICY_LIFE < JITTER_WINDOW_SECONDS (3600 s), the KDC
        applies the limit without jitter, giving an exact upper bound.
        The policy attribute is removed in the finally block via --delattr.
        """
        # Policy well below the 3600 s jitter threshold → exact enforcement.
        PAM_POLICY_LIFE = 300   # seconds
        hostname = self.master.hostname
        service_name = f'service/{hostname}'
        policy_attr = 'krbAuthIndMaxTicketLife;pam-authn--unknown'

        tasks.kinit_admin(self.master)
        try:
            # Set the per-method lifetime limit on the service entry.
            # All IPA service entries carry krbticketpolicyaux by default, so
            # no objectClass modification is needed before setting this attr.
            # The KDB plugin's ipa_kdb_principals.c scans for any attribute
            # matching krbAuthIndMaxTicketLife;*--* and stores it in
            # ipadb_e_data.s4u_ind_limits[]; ipa_kdcpolicy_check_tgs() then
            # prefers exact-match over prefix-level limits.
            self.master.run_command([
                'ipa', 'service-mod', service_name,
                '--setattr', f'{policy_attr}={PAM_POLICY_LIFE}',
            ])

            realm = self.master.domain.realm
            result = self._acquire_s4u_generic(self.ipa_test_user, realm)
            assert self.ipa_test_user in result.stdout_text, (
                f"Expected {self.ipa_test_user!r} in S4U2Self credential name "
                f"via generic attestation; got: {result.stdout_text!r}"
            )
            indicators = self._parse_indicators(result.stdout_text)
            assert 'pam-authn:unknown' in indicators, (
                f"Expected 'pam-authn:unknown' in indicators; "
                f"got {indicators!r}"
            )
            lifetime = self._parse_lifetime(result.stdout_text)
            assert lifetime is not None, (
                "Expected 'lifetime:N' line in script output"
            )
            assert lifetime <= PAM_POLICY_LIFE, (
                f"Expected lifetime <= {PAM_POLICY_LIFE} s (policy cap); "
                f"got {lifetime} s"
            )
            # Allow up to 60 s for Python startup + S4U2Self + GSSAPI exchange
            assert lifetime >= PAM_POLICY_LIFE - 60, (
                f"Expected lifetime >= {PAM_POLICY_LIFE - 60} s; "
                f"got {lifetime} s (policy={PAM_POLICY_LIFE} s)"
            )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'service-mod', service_name,
                '--delattr', f'{policy_attr}={PAM_POLICY_LIFE}',
            ], raiseonerr=False)

    def test_generic_attestation_ad_user_with_cert_override(self):
        """
        Generic (PAM) S4U2Self attestation succeeds for an AD user with DTV
        userCertificate.

        Creates a Default Trust View ID override for the AD user carrying a
        self-signed X.509 certificate (userCertificate;binary).  The IPA KDB
        plugin finds the DTV entry in Pass 2 but Phase 2 cert-override matching
        is not yet implemented, so S4U2Self succeeds via the cross-realm
        referral path.  Verifies that the DTV entry with a certificate does not
        break generic attestation.
        """
        ad_username = self.aduser.split('@', maxsplit=1)[0]
        ad_user_fq = self.aduser
        ad_realm = self.ad_domain.upper()

        # Generate a self-signed certificate to populate userCertificate;binary
        # in the DTV override entry.
        gen_cert_script = textwrap.dedent("""\
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization, hashes
            from cryptography import x509
            from datetime import datetime, timezone, timedelta
            import base64

            key = ec.generate_private_key(ec.SECP256R1())
            now = datetime.now(tz=timezone.utc)
            cert = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([
                    x509.NameAttribute(
                        x509.oid.NameOID.COMMON_NAME, 'dtv-test'),
                ]))
                .issuer_name(x509.Name([
                    x509.NameAttribute(
                        x509.oid.NameOID.COMMON_NAME, 'dtv-test'),
                ]))
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=1))
                .sign(key, hashes.SHA256())
            )
            print(base64.b64encode(
                cert.public_bytes(serialization.Encoding.DER)).decode())
        """)
        cert_result = self.master.run_command(
            ['python3', '-c', gen_cert_script])
        cert_b64 = cert_result.stdout_text.strip()

        tasks.kinit_admin(self.master)
        try:
            self.master.run_command([
                'ipa', 'idoverrideuser-add', 'Default Trust View', ad_user_fq,
                '--certificate', cert_b64,
            ])

            result = self._acquire_s4u_generic(ad_username, ad_realm)
            assert ad_username in result.stdout_text, (
                f"Expected {ad_username!r} in S4U2Self credential name via "
                f"generic attestation (DTV with cert); "
                f"got: {result.stdout_text!r}"
            )
            indicators = self._parse_indicators(result.stdout_text)
            assert indicators == [], (
                f"Expected no auth indicators for AD user (DTV cert); "
                f"got {indicators!r}"
            )
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command([
                'ipa', 'idoverrideuser-del',
                'Default Trust View', ad_user_fq,
            ], raiseonerr=False)

    def test_oidc_attestation_wrong_key_rejected(self):
        """
        IPA KDB plugin rejects attestation cert signed with an unknown key.

        If the host_pubkey embedded in the id-ce-kerberosServiceIssuerBinding
        extension does not match any ipaKrbServiceAttestationKey registered on
        the host service entry, the IPA KDB plugin must reject the certificate
        and the KDC must return an error.  Verifies that acquire_s4u_creds()
        raises GSSError rather than returning credentials.
        """
        realm = self.master.domain.realm
        hostname = self.master.hostname
        keytab_path = self.keytab_path
        ipa_test_user = self.ipa_test_user
        service_name = f'service/{hostname}'

        # Build an inline script that uses a freshly generated, unregistered
        # key as the host_pubkey.  Embed all path/name literals so the script
        # runs without command-line arguments.
        wrong_key_script = textwrap.dedent(f"""\
            import hashlib
            import sys
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives import serialization
            from ipalib.x509_attestation import (
                get_host_keytab_key,
                build_oidc_attestation_cert,
                acquire_s4u_creds,
            )
            import gssapi

            wrong_key = ec.generate_private_key(ec.SECP256R1()).public_key()
            keytab_entry = get_host_keytab_key(
                {hostname!r}, {realm!r},
                keytab_path={keytab_path!r},
                service_type='service',
            )
            dummy_token = '{ipa_test_user}@{realm}:test_oidc_token'.encode()
            cert_der = build_oidc_attestation_cert(
                user={ipa_test_user!r},
                realm={realm!r},
                issuer=f'https://{hostname}',
                access_token_hash=hashlib.sha256(dummy_token).digest(),
                host_pubkey=wrong_key,
                keytab_entry=keytab_entry,
                amr=['pwd'],
            )
            try:
                creds = acquire_s4u_creds(
                    cert_der=cert_der,
                    host_principal='{service_name}@{realm}',
                    keytab_path={keytab_path!r},
                )
                print('UNEXPECTED_SUCCESS')
            except gssapi.exceptions.GSSError as exc:
                print(f'KDC_REJECTED: {{exc}}')
        """)

        result = self.master.run_command(
            ['python3', '-c', wrong_key_script],
            raiseonerr=False,
        )
        output = result.stdout_text + result.stderr_text
        assert 'UNEXPECTED_SUCCESS' not in output, (
            "Expected IPA KDB plugin to reject cert with unregistered key; "
            "S4U2Self succeeded unexpectedly"
        )
        assert 'KDC_REJECTED' in output, (
            "Expected GSSError from KDC when using unregistered attestation "
            f"key; got: {output[:400]!r}"
        )

        tasks.kinit_admin(self.master)
        self.master.run_command([
            'ipa', 'service-del', service_name
        ])
