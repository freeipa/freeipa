"""
keytab.py — Keytab enumeration and entry selection via python-krb5.

Mirrors ssh_gssapi_s4u_x509_get_keytab_key() in gss-s4u-x509-keytab.c.
"""

from dataclasses import dataclass

import krb5


# Preference score for each AES enctype (higher = more preferred; 0 = reject).
_ENCTYPE_PREF: dict[int, int] = {
    20: 4,   # AES256-CTS-HMAC-SHA384-192  (RFC 8009)
    19: 3,   # AES128-CTS-HMAC-SHA256-128  (RFC 8009)
    18: 2,   # AES256-CTS-HMAC-SHA1-96     (RFC 3962)
    17: 1,   # AES128-CTS-HMAC-SHA1-96     (RFC 3962)
}

# AES-128 enctypes rejected in FIPS mode: their IKM provides only ~64-bit
# post-quantum security (Grover's algorithm halves AES-128 key length).
_FIPS_REJECT: frozenset[int] = frozenset({17, 19})


@dataclass
class KeytabEntry:
    principal: str      # "host/<hostname>@REALM"
    kvno: int
    enctype: int
    key: bytes          # raw key material — used as HKDF IKM


def get_host_keytab_key(
    hostname: str,
    realm: str,
    keytab_path: str | None = None,
    fips_mode: bool = False,
) -> KeytabEntry:
    """
    Open the host keytab and return the best entry for host/<hostname>@<realm>.

    Selection rules (matching gss-s4u-x509-keytab.c):
      - enctype must be 17–20 (AES variants only)
      - in FIPS mode enctypes 17 and 19 (AES-128) are skipped
      - highest preference score wins; ties broken by first-seen

    Raises LookupError when no suitable entry is found.
    Raises krb5.Krb5Error on any libkrb5 failure.
    """
    ctx = krb5.init_context()

    if keytab_path is not None:
        kt = krb5.kt_resolve(ctx, keytab_path.encode())
    else:
        kt = krb5.kt_default(ctx)

    want_principal = f"host/{hostname}@{realm}".encode()
    want = krb5.parse_name_flags(ctx, want_principal)

    best: krb5.KeyTabEntry | None = None
    best_pref = -1

    for entry in kt:
        # krb5.principal_compare is the correct way to compare principals,
        # but comparing the canonical string representation is simpler here
        # and sufficient for well-formed keytab files.
        ep = entry.principal
        if ep.realm != want.realm or ep.components != want.components:
            continue

        enctype = entry.key.enctype
        pref = _ENCTYPE_PREF.get(enctype, 0)
        if pref == 0:
            continue
        if fips_mode and enctype in _FIPS_REJECT:
            continue
        if pref > best_pref:
            best = entry
            best_pref = pref

    if best is None:
        msg = f"No suitable keytab entry for host/{hostname}@{realm}"
        if fips_mode:
            msg += " in FIPS mode (AES-128 enctypes 17 and 19 are rejected)"
        raise LookupError(msg)

    return KeytabEntry(
        principal=f"host/{hostname}@{realm}",
        kvno=best.kvno,
        enctype=best.key.enctype,
        key=bytes(best.key.data),
    )
