# Trusted domain object principals when the NetBIOS name equals the trusted domain name

## Overview

Establishing a trust to an Active Directory domain creates a set of LDAP
objects under `cn=ad,cn=trusts,$SUFFIX` through the `ipasam` Samba module.
Two attributes of the trusted domain object (TDO) define the Kerberos
principals that must exist for the trust to work:

* the trusted domain name, which becomes the Kerberos realm of the trusted
  domain, and
* the trusted domain NetBIOS name (`ipaNTFlatName`), which is used to build
  the Kerberos principals the remote domain controllers authenticate as.

Normally these two names are different (for `ad.example.com` the NetBIOS name
is `AD`). When they are equal — the NetBIOS name of the trusted domain is the
same string as the domain name, e.g. `ad.test` for the domain `ad.test`, or
`AD` for a single-label domain `ad` — the principals required for the trust
collide with each other and the trust cannot be created. Deployments that
predate the principal split (FreeIPA 4.6 and earlier) could hold such trusts
as a single entry; upgrading them to the current layout runs into the same
collision.

This design defines how IPA represents and upgrades trusts for trusted domains
whose NetBIOS name equals their domain name.

## Background: why the trust principals are split

Since the `trusts: add support for one-way shared secret trust` change
(FreeIPA 4.7) and the corresponding `update_tdo_to_new_layout` upgrade plugin
(FreeIPA 4.8), `ipasam` creates the following principals as children of the
trust entry for a bidirectional trust (`LOCAL` is the IPA realm,
`LOCAL-FLAT` the IPA NetBIOS name, `REMOTE` the trusted domain name/realm,
`REMOTE-FLAT` its NetBIOS name):

| Principal (canonical name) | Alias | Key derived from | Used for |
| --- | --- | --- | --- |
| `krbtgt/REMOTE@LOCAL` | – | trustAuthOutgoing | outbound cross-realm TGT issued by the IPA KDC |
| `krbtgt/REMOTE-FLAT@LOCAL` | `REMOTE-FLAT$@LOCAL` | trustAuthIncoming | account the remote AD DC authenticates as against IPA Samba; POSIX/SMB identity lives on the trust entry itself |
| `krbtgt/LOCAL@REMOTE` | – | trustAuthOutgoing | inbound cross-realm TGT issued for trust agents/SSSD |
| `krbtgt/LOCAL-FLAT@REMOTE` | `LOCAL-FLAT$@REMOTE` | trustAuthIncoming | IPA domain account in the remote forest, used by SSSD to talk to AD DCs; disabled on the IPA side |

The canonical name matters because the Kerberos key for a principal is
derived with `string2key(password, salt)` where the salt is the canonical
principal name. The two principals per direction must have different keys
(the incoming and the outgoing trust passwords) and different salts, so they
must be separate entries. The alias exists because Active Directory derives
the key for a trusted domain's machine account in the trusting realm using
the `krbtgt/<flat>@<realm>` form as the salt, while the name actually used
in requests is the `<flat>$@<realm>` form.

Before FreeIPA 4.7 there was a single principal per role, with the canonical
name and the salt-carrying name swapped for the TDO account and one password
used for all principals. That configuration is broken for two-way trusts,
which is why the split was made and why `update_tdo_to_new_layout` converts
existing trusts to the new layout.

## The collision

`ipasam` builds the principal names in `handle_cross_realm_princs()`
(`daemons/ipa-sam/ipa_sam.c`). The realm component is upper-cased
(`talloc_strdup_upper()`), the NetBIOS name is used verbatim as reported by
the trusted domain. When `REMOTE-FLAT` equals `REMOTE`:

* `krbtgt/REMOTE-FLAT@LOCAL` and `krbtgt/REMOTE@LOCAL` become the same
  principal name. Kerberos principal comparison and the IPA uniqueness
  constraints on `krbPrincipalName`/`krbCanonicalName` are case-insensitive,
  so the two entries cannot coexist.
* They still require different keys: the salts differ (at minimum by case,
  e.g. `krbtgt/AD.TEST@EXAMPLE.COM` vs `krbtgt/ad.test@EXAMPLE.COM`, and in
  general because trustAuthIncoming and trustAuthOutgoing are different
  passwords after a validation initiated from the AD side).
* Merging them into one entry breaks both roles at once: a single principal
  can hold only one key set, and each role needs its own salt-derived key.

The same collision occurs symmetrically on the inbound side when the IPA
server's own NetBIOS name equals the IPA realm (possible for single-label
realms): `krbtgt/LOCAL-FLAT@REMOTE` collides with `krbtgt/LOCAL@REMOTE`.

The result today: `ipa trust-add` for such a domain fails with a uniqueness
constraint violation (or, where the merge silently happens, the trust is
created with a wrong key for one of the two roles), and the upgrade plugin
`update_tdo_to_new_layout` finds the existing `krbtgt/REMOTE@LOCAL` entry
when it tries to create the TDO principal, adds the alias to it and skips
setting the key — leaving the two-way trust non-functional.

## Use Cases

1. As a FreeIPA administrator, I want to establish a bidirectional trust to
   an Active Directory domain whose NetBIOS name equals its DNS name — for
   example a Samba AD DC configured with `netbios name = ad.test` for the
   domain `ad.test`, or a single-label domain whose NetBIOS name is derived
   from it.
2. As a FreeIPA administrator, I upgrade a deployment that has an existing
   trust to such a domain created before FreeIPA 4.7 (single principal per
   role). After the upgrade both trust directions must work without
   re-creating the trust on either side.

## Design

### Keep both principals; move the collision out of the name

The two principals must remain separate because their keys are derived from
different salts. The only way to represent them when the salt-carrying names
collide is to give the TDO account principal a name that does not collide
and derive its key from an explicit salt instead of from its own name:

| Principal (canonical name) | Salt used for key derivation |
| --- | --- |
| `krbtgt/REMOTE@LOCAL` | its own name (unchanged) |
| `REMOTE-FLAT$@LOCAL` | `krbtgt/REMOTE-FLAT@LOCAL` (explicit) |

`REMOTE-FLAT$@LOCAL` is the name the remote domain controllers, Samba and
SSSD already use today as the alias; making it the canonical name removes
the collision because it differs from `krbtgt/REMOTE@LOCAL`. The colliding
`krbtgt/REMOTE-FLAT@LOCAL` alias is simply not created. The KDC only ever
uses the stored keys when issuing or verifying tickets — the salt matters
solely at key-derivation time — so a principal whose key salt differs from
its name is functionally correct.

The storage format already supports this: `krbPrincipalKey` stores
`krb5_key_data` entries with a per-key salt (`key_data_ver = 2`,
`key_data_contents[1]`), and `ipa_krb5_generate_key_data()`
(`util/ipa_krb5.c`) already writes the salt into the key data. What is
missing is a way to request a salt that differs from the principal name at
generation time, and reuse of the stored salt on key rotation.

### Detection

The collision is detected by a case-insensitive comparison of
`ipaNTFlatName` with the trusted domain realm (`ipaNTTrustPartner` / the
trust entry `cn`), and of the IPA NetBIOS name (`cn=ad,cn=adtrust-dns,...`
trust configuration `ipantflatname`) with the IPA realm. It must be checked
in the creation path (`ipasam`), the upgrade plugin and the trust principal
lookup helpers that construct these names.

### Salt-aware key derivation

1. **GetKeytab extended operation gains an optional explicit salt.**
   `GKNewKeys` in `asn1/asn1c/ipa.asn1` gets
   `salt [3] OCTET STRING OPTIONAL`. When present, `ipa-pwd-extop`
   (`decode_getkeytab_request()`, `ipapwd_encrypt_encode_key()`) derives the
   keys with that salt instead of the service identity, and stores it in the
   key data as it already does for name-derived salts. The field is only
   used by `ipasam` and the upgrade tooling; `ipa-getkeytab` gains a
   corresponding option for the upgrade path.
2. **`ipa-kdb` reuses the stored salt on rotation.** `ipadb_change_pwd()`
   (`daemons/ipa-kdb/ipa_kdb_passwords.c`) currently re-derives the salt
   from `db_entry->princ`. It must reuse the salt persisted in the existing
   `db_entry->key_data` when one is present. Without this, any
   `kadmin`-driven password change of such a principal re-keys it with the
   wrong salt and silently breaks the trust direction that depends on it.
3. **`ipasam` uses both.** In `handle_cross_realm_princs()`, when the
   collision is detected, the TDO principal is created with the
   `<flat>$@<realm>` canonical name (no colliding alias) and
   `set_cross_realm_pw()` passes the explicit `krbtgt/<flat>@<realm>` salt.
   `del_cross_realm_princs()` deletes the principal under the name it was
   created with.

With (1) for creation and (2) for rotation, every path that re-keys the
principal — trust re-validation from the AD side, `ipa trust-add`
re-establishment, `kadmin.local` — preserves the required salt.

### Behaviour of the trust itself

No change: the trust entry keeps `ipaNTFlatName`, the POSIX/SMB identity
(`uid = <flat>$`, `uidNumber`, `gidNumber`, SID), and the ID ranges are
allocated as today. SSSD and the oddjob trust-fetch helper already look up
the `<flat>$@<realm>` principal name; it resolves to the entry directly
instead of through the alias.

## Implementation

| Component | Change |
| --- | --- |
| `asn1/asn1c/ipa.asn1`, `asn1/ipa_asn1.c` | `GKNewKeys.salt [3] OCTET STRING OPTIONAL`; regenerate the asn1c bindings and `ipaasn1_enc_getkt()` helper |
| `util/ipa_krb5.c` | accept an explicit salt string in key generation in addition to the principal-derived one |
| `daemons/ipa-slapi-plugins/ipa-pwd-extop/` | decode the optional salt in `decode_getkeytab_request()`; pass it through `ipapwd_encrypt_encode_key()` to key generation |
| `client/ipa-getkeytab.c` | pass the salt through in `create_getkeytab_control()`; CLI option for the upgrade path |
| `daemons/ipa-sam/ipa_sam.c` | collision detection in `handle_cross_realm_princs()`; create/delete the TDO principal as `<flat>$@<realm>`; pass the explicit salt in `set_cross_realm_pw()` |
| `daemons/ipa-kdb/ipa_kdb_passwords.c` | `ipadb_change_pwd()` reuses the salt stored in existing key data |
| `ipaserver/install/plugins/adtrust.py` | `update_tdo_to_new_layout()` collision branch (see Upgrade); `update_tdo_default_read_keys_permissions()` must also match the `<flat>$@<realm>` form when the collision applies |

The optional ASN.1 field is ignored by older servers only in the sense that
they reject requests that carry it; since trusts with colliding names could
not be created before, no existing working trust changes behaviour.
`freeipa-server` (the extop plugin, `ipa-kdb`) and `freeipa-server-trust-ad`
(`ipasam`) ship in lockstep, and the upgrade plugin runs on the master it
upgrades.

## Upgrade

`update_tdo_to_new_layout` processes each trust entry as today, with one
additional branch. Let `nbt = ipaNTFlatName` and `realm = ipaNTTrustPartner`
of the trust entry.

1. If `nbt` and `realm` differ case-insensitively: current behaviour,
   unchanged.
2. If they are equal:
   * The existing `krbtgt/REMOTE@LOCAL` principal from the old layout is
     kept as the outbound cross-realm TGT; it is still required to exist and
     re-keyed from trustAuthOutgoing as today.
   * The TDO principal is created as `REMOTE-FLAT$@LOCAL` (canonical name,
     no alias) with the POSIX attributes, SID and read-keys permissions the
     plugin already manages. Its keys are derived from trustAuthIncoming with
     the explicit salt `krbtgt/REMOTE-FLAT@LOCAL` via the getkeytab extended
     operation (through `ipa-getkeytab`), not through the
     `kadmin.local change_password` path used for the non-colliding case.
   * A stale pre-4.7 entry occupying that name is deleted first, as
     `set_krb_principal()` already does for alias entries.
   * For the symmetric case (IPA NetBIOS name equals the IPA realm), the
     inbound TDO principal is created as `LOCAL-FLAT$@REMOTE` with the
     explicit salt `krbtgt/LOCAL-FLAT@REMOTE` and the disabled ticket flags
     the current code sets.
   * If trustAuthIncoming and trustAuthOutgoing decode to different
     passwords, the trust is still converted correctly — the two principals
     are separate entries with their own salts. This is the case that makes
     merging the principals impossible and is the reason the conversion must
     keep them apart.

No user-facing command changes are required; `ipa trust-add` for a colliding
domain starts working through the `ipasam` path described above. An
administrator who re-creates such a trust gets the same representation.

## Testing

* Integration test in `ipatests/test_integration/test_trust.py`: establish a
  bidirectional trust to a Samba AD DC whose `netbios name` equals its DNS
  domain name; verify both directions — the remote DC authenticates against
  IPA Samba (NETLOGON/SMB, trust validation from the Windows side) and IPA
  users obtain cross-realm TGTs — and that the principals have the expected
  names and stored salts (`kadmin.local getprinc` inspection).
* Upgrade test: seed the pre-4.7 single-entry layout for a colliding trust
  (the fixture approach already used for `update_tdo_to_new_layout`), run
  `ipa-server-upgrade`, verify the converted principals and that both trust
  directions authenticate.
* Rotation test: re-validate the trust from the AD side and confirm the
  stored salt survives the key change (covers the `ipadb_change_pwd` path).
