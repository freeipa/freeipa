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

# Builds an OIDC attestation certificate for a given user, performs
# S4U2Self via gssapi, and prints the impersonated principal name.
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
        amr=['password'],
    )

    service_principal = keytab_entry.principal
    creds = acquire_s4u_creds(
        cert_der=cert_der,
        host_principal=service_principal,
        keytab_path=keytab_path,
    )

    print(str(creds.name))
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
        tasks.kinit_admin(cls.master)
        service_name = f'service/{hostname}'
        cls.master.run_command([
            'ipa', 'service-add', service_name
        ])
        cls.master.run_command([
            'ipa', 'service-add-attestation-key', service_name,
            '--pubkey', cls.attest_pubkey_path,
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
        issues a ticket in the impersonated user's name.
        """
        realm = self.master.domain.realm
        result = self._acquire_s4u_oidc(self.ipa_test_user, realm)
        assert self.ipa_test_user in result.stdout_text, (
            f"Expected {self.ipa_test_user!r} in S4U2Self credential "
            f"name; got: {result.stdout_text!r}"
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
            )
            dummy_token = '{ipa_test_user}@{realm}:test_oidc_token'.encode()
            cert_der = build_oidc_attestation_cert(
                user={ipa_test_user!r},
                realm={realm!r},
                issuer=f'https://{hostname}',
                access_token_hash=hashlib.sha256(dummy_token).digest(),
                host_pubkey=wrong_key,
                keytab_entry=keytab_entry,
                amr=['password'],
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
