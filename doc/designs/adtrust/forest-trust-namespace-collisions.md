# Forest trust namespace collision detection and exclusions

## Overview

Reference: https://codeberg.org/freeipa/freeipa/issues/10033

FreeIPA's Kerberos KDB plugin (`daemons/ipa-kdb`) resolves a client-supplied
realm or UPN suffix to the AD trust it belongs to, falling back to the
longest matching DNS suffix when no trust's domain name, NetBIOS name, or
UPN suffix matches exactly (see `ipadb_trust_find_by_name()` in
`daemons/ipa-kdb/ipa_kdb_mspac_trusts.c`).

This surfaced a real, reproducible misconfiguration. Given:

| domain       | flat name | UPN suffix          |
|--------------|-----------|----------------------|
| `a.test`     | A         | —                    |
| `b.a.test`   | B         | `deeper.c.b.a.test`  |
| `c.b.a.test` | C         | —                    |
| `d.test`     | D         | `deep.c.b.a.test`    |
| `bb.a.test`  | BB        | —                    |

`d.test` registered a UPN suffix, `deep.c.b.a.test`, that is a subdomain of
`c.b.a.test` — a domain belonging to a *different*, independently
established trust (`a.test`'s forest). A Kerberos referral for
`deep.c.b.a.test` was incorrectly routed to `c.b.a.test`'s trust (`a.test`)
instead of the intended `d.test`.

This is exactly the "namespace collision" scenario defined by
[MS-ADTS §6.1.6.9.3.2](https://learn.microsoft.com/openspecs), "Determining
Whether Namespaces Collide": a name must not be subordinate to (or superior
to) another forest's top-level name (TLN) unless an explicit exclusion
record says otherwise. FreeIPA today has no way to register such an
exclusion, and no code that detects the collision before it produces
silently-wrong referral routing.

Samba already implements the MS-ADTS algorithm generically, in
`check_ft_info()` (`source3/rpc_server/lsa/srv_lsa_nt.c`), operating on
`ForestTrustInfo` records (`TopLevelName`, `TopLevelNameEx`,
`DomainInfo`) via a `dns_cmp()` helper. `check_ft_info()` treats a
`TopLevelNameEx` exclusion record as resolving a collision **only on an exact
name match** — never on a child/parent DNS relationship. FreeIPA's own
enforcement in `ipa-kdb` must match that behavior exactly, or the two will
disagree about whether the same configuration is valid.

This design covers the full loop needed to detect and resolve such
collisions: LDAP schema, `ipa-kdb` runtime enforcement, `ipaserver`
validation and CLI, and `ipa-sam` (the Samba passdb backend).

## Use Cases

### Detecting a collision when adding a UPN suffix

As IPA administrator, I run `ipa trustdomain-mod` to add a new UPN suffix
to a subordinate domain of a trust I am configuring. If that suffix falls
under the namespace of a domain from a *different*, already-established
trust, IPA rejects the change with an error naming the specific domain it
collides with, instead of silently creating a configuration that misroutes
Kerberos referrals.

### Resolving a legitimate collision with an exclusion

As IPA administrator, I know that a particular UPN suffix should be routed
to a specific trust even though it looks like a subdomain of another
trust's namespace (for example, because the colliding domain in the other
forest doesn't actually exist or has been decommissioned). I register an
explicit exclusion for that exact name on the domain it collides with, then
retry the original suffix addition, which now succeeds.

### Establishing a brand-new forest trust

As IPA administrator, I run `ipa trust-add` to establish a new forest
trust. This continues to work exactly as it does today: the existing LSA
RPC round-trip against IPA's own local Samba instance
(`TrustDomainInstance.establish_trust()`/`update_ftinfo()` in
`ipaserver/dcerpc.py`) already invokes Samba's own `check_ft_info()`
collision detection and its existing best-effort auto-fix
(`clear_ftinfo_conflict()`). This design does not change that path's
behavior.

## How to Use

`ipaNTTrustTLNExclusions`, like the existing `ipaNTAdditionalSuffixes`
(UPN suffixes) attribute it's modeled on, lives on a trust's *root* entry
and is managed via `trust-mod` — there is no `trustdomain-mod` CLI command
today (`trustdomain-mod` is an internal-only, `NO_CLI` command used to
implement `trustdomain-add`/`-del`/`-enable`/`-disable`).

To add a UPN suffix that IPA determines collides with another trust:

```
# ipa trust-mod d.test --upn-suffixes=deep.c.b.a.test
ipa: ERROR: Forest trust namespace collision: 'deep.c.b.a.test' collides
with domain 'c.b.a.test' of trust 'a.test'. Add an exclusion with
--tln-exclusions on the a.test trust, or choose a different suffix.
```

To resolve it by registering an exclusion (assuming the collision has been
verified to be a non-issue, e.g. the other forest's domain has been
retired):

```
# ipa trust-mod a.test --tln-exclusions=deep.c.b.a.test
# ipa trust-mod d.test --upn-suffixes=deep.c.b.a.test
```

The exclusion is registered on the root of whichever trust owns the
colliding name (here, `a.test`'s trust owns `c.b.a.test`), but its value is
always the exact colliding name itself (a TLN or one of its subordinate
domains) — never a wildcard over that name's descendants. An exclusion for
`deep.c.b.a.test` does not also cover `sub.deep.c.b.a.test`; a second
colliding name needs its own separate exclusion entry, matching
`check_ft_info()`'s exact-match semantics.

## Design

### LDAP schema

A new multi-valued attribute, `ipaNTTrustTLNExclusions`, is added to the
`ipaNTTrustedDomain` objectclass, following the same pattern as the
existing `ipaNTAdditionalSuffixes` attribute (same object, same
multi-valued shape):

```
attributeTypes: ( <OID> NAME 'ipaNTTrustTLNExclusions'
    DESC 'DNS names excluded from this domain forest trust namespace collision checks'
    EQUALITY caseIgnoreMatch
    SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
```

(OID to be registered in the `2.16.840.1.113730.3.8.11.x` attribute arc
already used by `ipaNTAdditionalSuffixes` and related attributes.)
`ipaNTTrustedDomain`'s `MAY` clause gains `ipaNTTrustTLNExclusions`. Since
`ipaNTTrustedDomain` is shared by both a trust's root entry and its
subordinate domain entries, the attribute is schema-legal on either — but
see Design below for why it is only ever written on the root entry.

The exclusion list is stored on the same entry as
`ipaNTAdditionalSuffixes` — the trust's *root* entry (one per established
trust relationship, matching one Samba `pdb_trusted_domain`/one
`ipaNTTrustForestTrustInfo` blob) — not on individual subordinate
`trustdomain` entries. There is no separate exclusions object and no
dedicated LDAP subtree.

### `ipa-kdb` enforcement

`struct ipadb_adtrusts` gains a new field pair, `exclusions` /
`exclusions_len`, loaded from `ipaNTTrustTLNExclusions` via the same
LDAP-attribute-loading code path already used for `upn_suffixes`.

No new index tree is needed. The exclusion list is only consulted from
`suffix_scan()` in `ipa_kdb_mspac_trusts.c`, on the existing suffix-fallback
path (reached only when no exact domain/flat/UPN match was found — see
`ipadb_trust_find_by_name()`). Before accepting a suffix-match candidate for
lookup key `name`, `suffix_scan()` checks whether `name` — the exact string
being resolved, compared full-length — appears verbatim in any trust's
exclusion list. If so, that candidate is skipped entirely (an excluded name
resolves to "no trust", not to a shorter remaining match).

### `ipaserver` (collision validation, LDAP writes, CLI)

Two independent write paths matter here:

`trust-add` already flows through Samba's own `check_ft_info()` (via
`update_ftinfo()`/`lsaRSetForestTrustInformation` against IPA's own local
`smbd`), comparing the new domain's records against every previously
established trust (via `pdb_enum_trusted_domains()`, which reads each
trust's `ipaNTTrustForestTrustInfo`). This path, including its existing
auto-fix attempt in `clear_ftinfo_conflict()`, is unchanged — no code in
`generate_ftinfo()`/`get_realmdomains()` needs to change, because
`trust_mod` (below) keeps every trust's own stored
`ipaNTTrustForestTrustInfo` blob up to date directly, so `check_ft_info()`
already sees current exclusions the next time it runs.

`trust_mod` (adding a UPN suffix, or writing `ipaNTTrustTLNExclusions`
itself — both live on the trust root object, see Data model above) is a
plain LDAP write today with no LSA RPC round-trip and no collision check —
the actual gap this design fills. A shared helper added to
`ipaserver/dcerpc.py` implements the same `dns_cmp()`-equivalent comparison
`check_ft_info()` uses: given a candidate name being added, walk every
other currently-trusted domain (root and subordinate) and UPN suffix and
check for a collision — an exact match, or a parent/child DNS relationship
— mirroring `dns_cmp()`'s three collision-triggering outcomes. A collision
found this way is then checked against the exclusion lists of both trusts
involved: only an **exact-match** exclusion for the colliding name cancels
it, never a parent/child relationship — the exclusion check is stricter
than the collision check itself, exactly as `check_ft_info()` behaves.

`ipaserver/plugins/trust.py`'s `trust_mod.pre_callback` calls this helper.
On a detected, unexcluded collision, it raises
`errors.TrustTopologyConflictError` — the same exception
`clear_ftinfo_conflict()` already raises — rejecting the write, naming the
colliding domain/trust in the error message.

When the write is accepted, `trust_mod` also regenerates that trust's
`ipaNTTrustForestTrustInfo` blob and writes it as part of the same LDAP
update. This does **not** require a live RPC round-trip: the blob is just
an NDR-serialized `drsblobs.ForestTrustInfo` structure, and `dcerpc.py`
already builds one of these purely in Python (see `fetch_domains()`'s use
of `drsblobs.ForestTrustInfo`/`ForestTrustInfoRecord`/
`ForestTrustInfoRecordArmor` plus `ndr_pack()`). A new helper reuses that
same pattern to construct a `TopLevelName` record for the trust's domain
name and each UPN suffix, plus a `TopLevelNameEx` record for each
exclusion, and packs it directly — no credentials or SMB connection
needed, since this only updates our own LDAP-stored copy, which Samba's
`ipa_sam.c` already round-trips opaquely.

### `ipa-sam`

No code changes. `daemons/ipa-sam/ipa_sam.c` already round-trips
`ipaNTTrustForestTrustInfo` opaquely via `repack_pdb_forest_trust_info()`
and already declares `PDB_CAP_TRUSTED_DOMAINS_EX`
(`pdb_ipasam_capabilities()`). That capability flag only gates Samba's
`_lsa_EnumTrustedDomainsEx` RPC (extended trusted-domain enumeration with
trust type/direction/attributes) and has no bearing on `check_ft_info()` or
the `lsaR{Query,Set}ForestTrustInformation` path, which operate generically
on whatever blob `pdb_enum_trusted_domains()` returns. Since `ipaserver` is
responsible for keeping that blob's TLN/TLN-EX records correct, Samba's own
collision detection gets correct exclusion data with zero new `ipa-sam`
code.

## Implementation

- Dependencies: no new dependency on any FreeIPA package.
- Backup and Restore: `ipaNTTrustTLNExclusions` is a regular LDAP attribute
  on existing `ipaNTTrustedDomain` entries; it is covered by IPA's existing
  LDAP backup/restore, no new files or paths to handle.

## Feature Management

### UI

`IPA Server / Trusts` domain view gains a field to display and edit
`ipaNTTrustTLNExclusions`, next to the existing UPN suffixes field.

### CLI

| Command | Options |
| --- | ----- |
| `trust-mod` | `--tln-exclusions=STR` (multi-valued) |
| `trust-mod` | `--upn-suffixes=STR` now validated for namespace collisions before being written |
| `trust-show`/`trust-find` | display `ipaNTTrustTLNExclusions` alongside existing attributes |

### Configuration

No new configuration options; no way to disable the collision check itself,
since an unresolved collision otherwise produces silently incorrect
Kerberos referral routing.

## Upgrade

No impact on upgrade. `ipaNTTrustTLNExclusions` is optional and absent on
all existing `ipaNTTrustedDomain` entries after upgrade;
`generate_ftinfo()`/`suffix_scan()` behave exactly as before when no
exclusions are present. No existing trust configuration is revalidated
retroactively on upgrade — the collision check only runs on new writes
through `trust_mod`.

## Test plan

- `daemons/ipa-kdb/tests/ipa_kdb_tests.c`: fixture-based unit tests
  reproducing the reported bug configuration, asserting that: without an
  exclusion the (undesired) collision-affected routing is documented; with
  the exclusion registered, resolving the colliding name returns no trust
  (or falls through to whatever shorter match remains) rather than the
  wrong trust; a subdomain of the excluded name is unaffected by it.
- `ipaserver` unit tests for the new `dcerpc.py` collision helper: exact
  match and parent/child collisions are both detected; an exact-match
  exclusion cancels a collision; a parent/child relationship to an excluded
  name does not cancel it; unrelated names are unaffected.
- Integration tests (PRCI): `trust-mod --tln-exclusions` CLI surface,
  rejection of a colliding `--upn-suffixes` addition without an exclusion,
  and successful addition once the exclusion is registered.

## Troubleshooting and debugging

- `ipaNTTrustTLNExclusions` and `ipaNTAdditionalSuffixes` on a given
  trust's root entry can be inspected directly:
  ```
  # ipa trust-show TRUST --all | grep -i 'tln\|suffixes'
  ```
- A rejected `trust-mod` due to a namespace collision raises
  `errors.TrustTopologyConflictError`, surfaced to the CLI/UI with the
  colliding domain and trust named in the message.
- If Kerberos referrals for a given name still appear misrouted after
  registering an exclusion, confirm the exclusion's spelling matches the
  colliding name exactly (case-insensitive, but otherwise full-string
  equality) — a partial or suffix match does not apply.
- `ipaNTTrustForestTrustInfo` is an NDR-serialized blob; there is currently
  no CLI tool to decode it directly. To confirm it was regenerated after a
  suffix/exclusion change, check the `modifyTimestamp` of the corresponding
  `ipaNTTrustedDomain` entry.
