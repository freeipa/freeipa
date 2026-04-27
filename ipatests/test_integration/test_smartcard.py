#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""Smart-card (SoftHSM / PKCS#11) checks for the IPA multihost stack.

Uses :class:`~ipatests.test_integration.base.IntegrationTest` (``topology`` +
``clients[0]``) and :class:`~ipatests.pytest_ipa.integration.smartcard.SmartCardUtils`
via ``host.run_command`` / ``transport`` — **not** ``pytest_mh`` / ``CLIBuilder``.

Behavior matches the intent of ``sssd-test-framework`` smart-card tests (same
underlying commands: ``softhsm2-util``, ``pkcs11-tool``, ``openssl``,
``virt_cacard.service``). See module docstring of ``smartcard`` for RPM/binary
requirements; ``python3-ipatests`` declares ``softhsm``, ``opensc``, and
``virt-cacard`` on Fedora so clients that install tests get dependencies.

Do **not** comment out :func:`_require_pkcs11_tools`—without ``pkcs11-tool``
(from ``opensc``) you get exit status **127** (command not found).

Token/list tests do not exercise full PAM login; :meth:`test_setup_local_card_sssd_files_domain`
temporarily replaces ``sssd.conf`` and restores it from backup.
"""

from __future__ import absolute_import

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration.smartcard import (
    SmartCardUtils,
    restore_local_smartcard_auth,
)
from ipaplatform.paths import paths


def _require_pkcs11_tools(host):
    """Skip if SoftHSM/OpenSC/openssl CLIs are missing (same as SSSD framework needs)."""
    for binary in ("softhsm2-util", "pkcs11-tool", "openssl"):
        result = host.run_command(["which", binary], raiseonerr=False)
        if result.returncode != 0:
            pytest.skip("%s is not installed on %s" % (binary, host.hostname))


class TestSmartCardUtils(IntegrationTest):
    """Exercise SoftHSM helpers on an enrolled IPA client."""

    topology = "line"
    num_clients = 1

    @property
    def host(self):
        """Single enrolled IPA client in this topology."""
        return self.clients[0]

    def smartcard(self, base_dir=None):
        """Build :class:`SmartCardUtils` for :attr:`host` (optional *base_dir*)."""
        if base_dir is not None:
            return SmartCardUtils(self.host, base_dir=base_dir)
        return SmartCardUtils(self.host)

    def test_soft_token_contains_cert_after_import(self):
        """Initialize a token, import key/cert, list objects via PKCS#11."""
        _require_pkcs11_tools(self.host)

        sc = self.smartcard()
        key_path, cert_path = sc.generate_cert()
        sc.initialize_card()
        sc.add_key(key_path)
        sc.add_cert(cert_path)

        listing = sc.pkcs11_list_objects()
        assert "Certificate" in listing or "cert" in listing.lower()

    def test_generate_cert_creates_pem_files(self):
        """Sanity check OpenSSL self-signed generation on the client."""
        _require_pkcs11_tools(self.host)

        sc = self.smartcard()
        key_path, cert_path = sc.generate_cert(
            key_path="/tmp/ipa_sc_gen.key",
            cert_path="/tmp/ipa_sc_gen.crt",
        )
        self.host.run_command(["test", "-s", key_path])
        self.host.run_command(["test", "-s", cert_path])
        subj = self.host.run_command(
            ["openssl", "x509", "-in", cert_path, "-noout", "-subject", "-nameopt", "RFC2253"]
        ).stdout_text
        assert "Test Cert" in subj

    def test_virt_cacard_insert_soft_token_and_credentials(self):
        """
        One workflow: simulate card insert, create SoftHSM token, load credentials.

        1. ``insert_card`` — ``systemctl start virt_cacard.service``.
        2. ``generate_cert`` — PEM key + self-signed cert on the client.
        3. ``initialize_card`` — new SoftHSM token.
        4. ``add_key`` / ``add_cert`` — private key and cert on the token.
        5. ``pkcs11_list_objects`` — token lists a certificate.
        6. ``remove_card`` — ``systemctl stop virt_cacard.service`` in
           ``finally``.

        Note: SoftHSM uses ``libsofthsm2.so``; ``virt_cacard`` only toggles the
        virtual reader service where installed. Both are exercised together for
        CI workflows that start the simulator before programming a software token.
        """
        _require_pkcs11_tools(self.host)

        sc = self.smartcard(base_dir="/var/tmp/ipa_smartcard_combo")
        try:
            sc.insert_card()

            key_path = "/var/tmp/ipa_sc_combo.key"
            cert_path = "/var/tmp/ipa_sc_combo.crt"
            sc.generate_cert(
                key_path=key_path,
                cert_path=cert_path,
                subj="/CN=IPA Smartcard Combo Test",
            )
            sc.initialize_card(
                label="ipa_sc_combo",
                so_pin="12345678",
                user_pin="123456",
            )
            sc.add_key(key_path, key_id="01", pin="123456")
            sc.add_cert(cert_path, cert_id="01", pin="123456")

            listing = sc.pkcs11_list_objects(pin="123456")
            assert (
                "Certificate" in listing
                or "certificate" in listing.lower()
            )
        finally:
            sc.remove_card()

    def test_setup_local_card_sssd_files_domain(self):
        """
        Local ``files`` SSSD + certmap (same intent as SSSD ``setup_local_card``).

        Replaces ``sssd.conf`` temporarily; always restores from backup in
        ``finally``.
        """
        _require_pkcs11_tools(self.host)

        self.host.run_command(["useradd", "-m", "localscuser1"], raiseonerr=False)

        sc = self.smartcard()
        backups = None
        try:
            backups = sc.setup_local_card("localscuser1")
            conf = self.host.get_file_contents(paths.SSSD_CONF, encoding="utf-8")
            assert "[domain/local]" in conf
            assert "pam_cert_auth = True" in conf
            assert "[certmap/local/localscuser1]" in conf
            ca_ok = self.host.transport.file_exists(
                "/etc/sssd/pki/sssd_auth_ca_db.pem"
            )
            assert ca_ok
        finally:
            if backups is not None:
                restore_local_smartcard_auth(self.host, backups)
