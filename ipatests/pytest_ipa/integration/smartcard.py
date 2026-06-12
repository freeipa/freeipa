# Authors:
#   FreeIPA Contributors see COPYING for license
#
"""Helpers for smart-card related integration tests (SoftHSM / PKCS#11).

Aligned with common SSSD-framework workflows (token init, pkcs11-tool, virt_cacard,
optional local ``files`` domain + certmap) but implemented with
:class:`~ipatests.pytest_ipa.integration.host.Host` and ``run_command`` only.
"""

from __future__ import annotations

import os
import re
import textwrap
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from ipaplatform.paths import paths

if TYPE_CHECKING:
    from ipatests.pytest_ipa.integration.host import Host

__all__: Tuple[str, ...] = (
    "SmartCardUtils",
    "SOFTHSM_PKCS11_MODULE",
    "OPT_TEST_CA_BASE",
    "restore_local_smartcard_auth",
)

# Default PKCS#11 module for SoftHSM 2 on Fedora/RHEL-like systems.
SOFTHSM_PKCS11_MODULE = "/usr/lib64/pkcs11/libsofthsm2.so"

# Same layout as typical SSSD multihost tests: fixed tree under /opt/test_ca.
OPT_TEST_CA_BASE = "/opt/test_ca"


def restore_local_smartcard_auth(host: Host, backups: Dict[str, Any]) -> None:
    """
    Restore files saved by :meth:`SmartCardUtils.setup_local_card`.

    *backups* maps absolute path strings to **bytes** (file contents). Entries
    whose keys start with ``_`` are skipped (metadata). If the CA bundle was
    not backed up (it did not exist before setup), it is removed.
    """
    ca_path = "/etc/sssd/pki/sssd_auth_ca_db.pem"
    for key, data in backups.items():
        if key.startswith("_") or not isinstance(key, str):
            continue
        if data is None:
            continue
        host.transport.put_file_contents(key, data)
    if ca_path not in backups:
        host.run_command(["rm", "-f", ca_path], raiseonerr=False)
    host.run_command(["chmod", "600", paths.SSSD_CONF], raiseonerr=False)
    host.run_command(["authselect", "apply-changes"], raiseonerr=False)
    host.run_command(["systemctl", "restart", "sssd"], raiseonerr=False)


class SmartCardUtils:
    """
    Manage SoftHSM tokens and PKCS#11 objects on a remote IPA test host.

    Typical flow: :meth:`generate_cert`, :meth:`initialize_card`,
    :meth:`add_key`, :meth:`add_cert`, :meth:`pkcs11_list_objects`.

    For local-only SSSD (``files`` domain + certmap), see :meth:`setup_local_card`.
    """

    # Mirrors SSSD framework constants (paths relative to OPT_TEST_CA_BASE when used).
    SOFTHSM2_CONF_PATH = os.path.join(OPT_TEST_CA_BASE, "softhsm2.conf")
    TOKEN_STORAGE_PATH = os.path.join(OPT_TEST_CA_BASE, "tokens")
    OPENSC_CACHE_PATHS = (
        "$HOME/.cache/opensc/",
        "/run/sssd/.cache/opensc/",
    )

    def __init__(
        self,
        host: Host,
        base_dir: Optional[str] = None,
        softhsm_conf_name: str = "softhsm2.conf",
    ) -> None:
        self.host = host
        self.base_dir = base_dir or "/var/tmp/ipa_smartcard_utils"
        self.softhsm_conf_path = os.path.join(self.base_dir, softhsm_conf_name)
        self.token_dir = os.path.join(self.base_dir, "tokens")

    def _run(self, argv, *, raiseonerr: bool = True):
        full = ["env", "SOFTHSM2_CONF=" + self.softhsm_conf_path] + argv
        return self.host.run_command(full, raiseonerr=raiseonerr)

    def _write_softhsm_conf(self) -> None:
        content = (
            "directories.tokendir = {tokendir}\n"
            "objectstore.backend = file\n"
        ).format(tokendir=self.token_dir)
        self.host.transport.put_file_contents(self.softhsm_conf_path, content.encode("utf-8"))

    def clear_opensc_caches(self) -> None:
        """Remove OpenSC cache dirs (same intent as SSSD ``OPENSC_CACHE_PATHS``)."""
        for path in self.OPENSC_CACHE_PATHS:
            self.host.run_command(
                ["bash", "-c", "rm -rf {}".format(path)],
                raiseonerr=False,
            )

    def initialize_card(
        self,
        label: str = "sc_test",
        so_pin: str = "12345678",
        user_pin: str = "123456",
    ) -> None:
        """Initialize a SoftHSM token (destroys previous token storage under ``base_dir``)."""
        self.clear_opensc_caches()
        self.host.run_command(["mkdir", "-p", os.path.dirname(self.base_dir) or self.base_dir])
        self.host.run_command(["rm", "-rf", self.base_dir])
        self.host.run_command(["mkdir", "-p", self.token_dir])
        self._write_softhsm_conf()
        self._run(
            [
                "softhsm2-util",
                "--init-token",
                "--free",
                "--label",
                label,
                "--so-pin",
                so_pin,
                "--pin",
                user_pin,
            ]
        )

    def add_cert(
        self,
        cert_path: str,
        cert_id: str = "01",
        pin: str = "123456",
        private: bool = False,
    ) -> None:
        """Import a PEM certificate or private key onto the token."""
        obj_type = "privkey" if private else "cert"
        self._run(
            [
                "pkcs11-tool",
                "--module",
                SOFTHSM_PKCS11_MODULE,
                "--login",
                "--pin",
                pin,
                "--write-object",
                cert_path,
                "--type",
                obj_type,
                "--id",
                cert_id,
            ]
        )

    def add_key(self, key_path: str, key_id: str = "01", pin: str = "123456") -> None:
        """Import a PEM private key onto the token."""
        self.add_cert(cert_path=key_path, cert_id=key_id, pin=pin, private=True)

    def generate_cert(
        self,
        key_path: str = "/tmp/ipa_sc_selfsigned.key",
        cert_path: str = "/tmp/ipa_sc_selfsigned.crt",
        subj: str = "/CN=Test Cert",
    ) -> Tuple[str, str]:
        """Generate a self-signed certificate and private key (PEM) on the host."""
        self.host.run_command(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-sha256",
                "-days",
                "365",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-subj",
                subj,
            ]
        )
        return key_path, cert_path

    def insert_card(self) -> None:
        """Start ``virt_cacard.service``."""
        self.host.run_command(["systemctl", "start", "virt_cacard.service"])

    def remove_card(self) -> None:
        """Stop ``virt_cacard.service``."""
        self.host.run_command(["systemctl", "stop", "virt_cacard.service"])

    def append_sssd_auth_ca(self, cert_path: str) -> None:
        """
        Append PEM at *cert_path* to ``/etc/sssd/pki/sssd_auth_ca_db.pem``.

        Modifies the live client trust store; pair with backups from
        :meth:`setup_local_card` or restore manually.
        """
        ca_path = "/etc/sssd/pki/sssd_auth_ca_db.pem"
        self.host.run_command(["mkdir", "-p", "/etc/sssd/pki"])
        self.host.run_command(
            [
                "bash",
                "-c",
                "test -f {ca} && cat {cert} >> {ca} || cat {cert} > {ca}".format(
                    ca=ca_path, cert=cert_path
                ),
            ]
        )

    def pkcs11_list_objects(self, pin: str = "123456") -> str:
        """Return ``pkcs11-tool -O`` stdout for assertions."""
        result = self._run(
            [
                "pkcs11-tool",
                "--module",
                SOFTHSM_PKCS11_MODULE,
                "-O",
                "--login",
                "--pin",
                pin,
            ]
        )
        return result.stdout_text

    def setup_local_card(
        self,
        username: str,
        subj: str = "/CN=Test Cert",
        user_pin: str = "123456",
    ) -> Dict[str, Any]:
        """
        Configure **local** ``files`` SSSD domain + smart-card PAM + certmap.

        Equivalent intent to SSSD framework ``setup_local_card``: token under
        ``/opt/test_ca``, ``authselect`` with ``with-smartcard``, certmap rule
        matching *subj*, ``pam_cert_auth``, CA PEM for the self-signed cert.

        **Warning:** replaces ``sssd.conf`` with a minimal local configuration.
        Call :func:`restore_local_smartcard_auth` with the returned dict when
        done. Destructive on an enrolled IPA client; use only for dedicated
        scenarios.

        :return: Mapping of file paths to **bytes** for restore (plus metadata
                 keys starting with ``_``).
        """
        host = self.host
        backups: Dict[str, Any] = {}

        for fpath in (
            paths.SSSD_CONF,
            "/etc/sssd/pki/sssd_auth_ca_db.pem",
            "/etc/authselect/authselect.conf",
        ):
            if host.transport.file_exists(fpath):
                backups[fpath] = host.get_file_contents(fpath)

        tok = SmartCardUtils(host, base_dir=OPT_TEST_CA_BASE)
        host.run_command(["rm", "-f", "/etc/sssd/pki/sssd_auth_ca_db.pem"], raiseonerr=False)

        key_path = "/tmp/ipa_sc_local.key"
        cert_path = "/tmp/ipa_sc_local.crt"
        tok.generate_cert(key_path=key_path, cert_path=cert_path, subj=subj)
        tok.initialize_card(label="sc_test", user_pin=user_pin)
        tok.add_key(key_path, pin=user_pin)
        tok.add_cert(cert_path, pin=user_pin)

        host.run_command(
            ["authselect", "select", "sssd", "with-smartcard", "--force"],
            raiseonerr=False,
        )
        host.run_command(["systemctl", "restart", "virt_cacard.service"])

        m = re.search(r"CN=([^/]+)", subj.replace(",", "/"))
        cn = m.group(1).strip() if m else "Test Cert"
        match = "<SUBJECT>.*CN=%s.*" % re.escape(cn)
        sssd_conf = textwrap.dedent(
            """
            [sssd]
            config_file_version = 2
            services = nss, pam
            domains = local

            [nss]

            [pam]
            pam_cert_auth = True

            [domain/local]
            id_provider = files
            local_auth_policy = only
            debug_level = 2

            [certmap/local/{user}]
            matchrule = {rule}
            debug_level = 2
            """
        ).format(user=username, rule=match)

        host.transport.put_file_contents(paths.SSSD_CONF, sssd_conf.encode("utf-8"))
        host.run_command(["chmod", "600", paths.SSSD_CONF])

        cert_pem = host.get_file_contents(cert_path)
        host.transport.put_file_contents("/etc/sssd/pki/sssd_auth_ca_db.pem", cert_pem)

        host.run_command(["systemctl", "restart", "sssd"], raiseonerr=False)
        backups["_username"] = username
        return backups
