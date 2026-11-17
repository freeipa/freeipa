#
# Copyright (C) 2026 FreeIPA Contributors see COPYING for license
#
"""Kerberos policy handling in the replica connection check."""
import os
from pathlib import Path
import runpy
import subprocess

import pytest

from ipaplatform.paths import paths


@pytest.fixture(scope="module")
def conncheck():
    script = (Path(__file__).resolve().parents[2]
              / "install/tools/ipa-replica-conncheck.in")
    if not script.is_file():
        script = Path(paths.IPA_REPLICA_CONNCHECK)
    return runpy.run_path(str(script))


@pytest.mark.parametrize("policy_required, policy_exists", [
    (False, False),
    (False, True),
    (True, True),
    (True, False),
])
def test_kerberos_crypto_policy(
    conncheck, monkeypatch, tmp_path, policy_required, policy_exists
):
    policy = tmp_path / "crypto-policies"
    if policy_exists:
        policy.write_text("[libdefaults]\n")
    monkeypatch.setattr(
        conncheck["paths"], "CRYPTO_POLICY_KRB5_FILE",
        str(policy) if policy_required else None, raising=False,
    )
    config = tmp_path / "krb5.conf"
    conncheck["configure_krb5_conf"](
        "EXAMPLE.TEST", "ipa.example.test", str(config)
    )
    include = "include " + str(policy)
    assert (include in config.read_text()) == policy_required

    # A version 2 FILE keytab header with no entries is a valid empty keytab.
    # Listing it initializes the context without contacting a KDC.
    keytab = tmp_path / "empty.keytab"
    keytab.write_bytes(b"\x05\x02")
    env = dict(os.environ, KRB5_CONFIG=str(config), LC_ALL="C")
    result = subprocess.run(
        [paths.KLIST, "-k", str(keytab)],
        env=env, capture_output=True, text=True, check=False, timeout=10,
    )
    if policy_required and not policy_exists:
        assert result.returncode != 0
        assert "Included profile file could not be read" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
