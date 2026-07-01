#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#
"""
Keytab enumeration and entry selection via direct libkrb5 ctypes bindings.

Mirrors ssh_gssapi_s4u_x509_get_keytab_key() in gss-s4u-x509-keytab.c.
"""

import ctypes
from dataclasses import dataclass

import ipapython.kerberos as krb5lib


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
    principal: str      # "<service_type>/<hostname>@REALM"
    kvno: int
    enctype: int
    key: bytes          # raw key material — used as HKDF IKM


def get_host_keytab_key(
    hostname: str,
    realm: str | None,
    keytab_path: str | None = None,
    fips_mode: bool = False,
    service_type: str = "host",
) -> KeytabEntry:
    """
    Open the keytab and return the best entry for
    <service_type>/<hostname>@<realm>.

    If realm is None the keytab is scanned for any entry whose principal
    starts with "<service_type>/<hostname>@" and the realm is taken from
    the winning entry.  This is useful when the caller knows the hostname
    but not the Kerberos realm of the service (e.g. when the user realm
    differs from the service realm in an AD-trust scenario).

    Selection rules (matching gss-s4u-x509-keytab.c):
      - enctype must be 17–20 (AES variants only)
      - in FIPS mode enctypes 17 and 19 (AES-128) are skipped
      - highest preference score wins; ties broken by first-seen

    Raises LookupError when no suitable entry is found.
    Raises ipapython.kerberos.KRB5Error on any libkrb5 failure.
    """
    context = krb5lib.krb5_context()
    keytab = krb5lib.krb5_keytab()
    want = krb5lib.krb5_principal()

    best_key: bytes | None = None
    best_kvno: int = 0
    best_enctype: int = 0
    best_pref = -1
    best_realm: str = realm or ""

    # Prefix used for realm-agnostic matching when realm is None.
    prefix = (f"{service_type}/{hostname}@".encode()
              if realm is None else None)

    try:
        krb5lib.krb5_init_context(ctypes.byref(context))

        if keytab_path is not None:
            krb5lib.krb5_kt_resolve(context, keytab_path.encode(),
                                    ctypes.byref(keytab))
        else:
            krb5lib.krb5_kt_default(context, ctypes.byref(keytab))

        if realm is not None:
            want_name = f"{service_type}/{hostname}@{realm}".encode()
            krb5lib.krb5_parse_name(context, want_name, ctypes.byref(want))

        cursor = krb5lib.krb5_kt_cursor()
        krb5lib.krb5_kt_start_seq_get(context, keytab, ctypes.byref(cursor))
        try:
            while True:
                entry = krb5lib.krb5_keytab_entry()
                rc = krb5lib.krb5_kt_next_entry(context, keytab,
                                                ctypes.byref(entry),
                                                ctypes.byref(cursor))
                if rc == krb5lib.KRB5_KT_END:
                    break
                if rc != 0:
                    raise krb5lib.KRB5Error(rc, 'krb5_kt_next_entry', ())

                try:
                    if realm is not None:
                        if krb5lib.krb5_principal_compare(
                                context, want, entry.principal) != 1:
                            continue
                        entry_realm = realm
                    else:
                        # Realm-agnostic: unparse and check the prefix.
                        name_ptr = ctypes.c_char_p()
                        try:
                            krb5lib.krb5_unparse_name(
                                context, entry.principal,
                                ctypes.byref(name_ptr))
                            # c_char_p.value is bytes|None at runtime but
                            # pylint infers the ctypes descriptor; disable
                            # no-member for the two method calls below.
                            name = name_ptr.value
                            # pylint: disable=no-member
                            if not name or not name.startswith(prefix):
                                # pylint: enable=no-member
                                continue
                            # Copy realm before freeing name_ptr.
                            entry_realm = name.decode().split('@', 1)[1]
                            # pylint: enable=no-member
                        finally:
                            if name_ptr.value is not None:
                                krb5lib.krb5_free_unparsed_name(
                                    context, name_ptr)

                    enctype = entry.key.enctype
                    pref = _ENCTYPE_PREF.get(enctype, 0)
                    if pref == 0 or (fips_mode and enctype in _FIPS_REJECT):
                        continue

                    if pref > best_pref:
                        best_pref = pref
                        best_enctype = enctype
                        best_kvno = entry.vno
                        best_key = bytes(
                            entry.key.contents[:entry.key.length]
                        )
                        best_realm = entry_realm
                finally:
                    krb5lib.krb5_free_keytab_entry_contents(
                        context, ctypes.byref(entry)
                    )
        finally:
            krb5lib.krb5_kt_end_seq_get(context, keytab, ctypes.byref(cursor))

    finally:
        if want:
            krb5lib.krb5_free_principal(context, want)
        if keytab:
            krb5lib.krb5_kt_close(context, keytab)
        if context:
            krb5lib.krb5_free_context(context)

    if best_key is None:
        if realm is not None:
            desc = f"{service_type}/{hostname}@{realm}"
        else:
            desc = f"{service_type}/{hostname}@*"
        msg = f"No suitable keytab entry for {desc}"
        if fips_mode:
            msg += " in FIPS mode (AES-128 enctypes 17 and 19 are rejected)"
        raise LookupError(msg)

    return KeytabEntry(
        principal=f"{service_type}/{hostname}@{best_realm}",
        kvno=best_kvno,
        enctype=best_enctype,
        key=best_key,
    )
