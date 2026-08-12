/*
 * Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
 *
 * Indexed trust lookup using POSIX tsearch/tfind binary trees.
 */

#pragma once

#include <search.h>

struct ipadb_adtrusts;
struct dom_sid;

/* Which field of ipadb_adtrusts a trust_key_entry's key points into. */
enum trust_key_kind {
    TRUST_KEY_DOMAIN,
    TRUST_KEY_FLAT,
    TRUST_KEY_SID,
    TRUST_KEY_UPN,
};

/*
 * An index entry that maps a single string key (domain name, flat name,
 * or UPN suffix) to the owning ipadb_adtrusts record.
 *
 * We need a wrapper because tsearch stores pointers to whatever the
 * caller passes in, and the comparison function receives those pointers.
 * Storing the key explicitly lets each tree node carry its own lookup
 * key without reaching back into the trust record (which would be
 * ambiguous -- a trust has *multiple* searchable names).
 */
struct trust_key_entry {
    const char *key;               /* the search key (not owned, points into
                                      ipadb_adtrusts fields) */
    size_t key_len;                /* strlen(key), cached for speed */
    enum trust_key_kind kind;      /* which field 'key' points into */
    struct ipadb_adtrusts *trust;  /* back-pointer to the trust record */
};

/*
 * Collection of tsearch binary trees that index the trusts array.
 *
 * by_domain   — keyed by ipadb_adtrusts.domain_name   (case-insensitive)
 * by_flat      — keyed by ipadb_adtrusts.flat_name     (case-insensitive)
 * by_upn       — keyed by every UPN suffix in every trust (case-insensitive)
 * by_sid       — keyed by ipadb_adtrusts.domain_sid    (string form, exact)
 *
 * All keys compare case-insensitively (DNS names / NetBIOS names).
 * SIDs are compared as strings because they are stored that way in
 * ipadb_adtrusts.domain_sid.
 *
 * Each tree stores pointers to trust_key_entry structs.  The entries
 * themselves are kept in a flat array (entries / num_entries) so they
 * can be freed in one shot.
 */
struct ipadb_trust_index {
    void *by_domain;      /* tsearch root: domain_name -> trust */
    void *by_flat;        /* tsearch root: flat_name   -> trust */
    void *by_upn;         /* tsearch root: upn_suffix  -> trust */
    void *by_sid;         /* tsearch root: domain_sid  -> trust */

    struct trust_key_entry *entries;   /* flat array of all key entries */
    size_t num_entries;                /* count of entries */
};

/*
 * Build all four index trees from the trusts array.
 * Returns 0 on success, errno on failure (ENOMEM).
 *
 * The trusts array and its strings must remain valid for the lifetime
 * of the index.
 */
int ipadb_trust_index_build(struct ipadb_adtrusts *trusts,
                            size_t num_trusts,
                            struct ipadb_trust_index **index_out);

/*
 * Free the index (entries array + tdestroy all trees).
 * Does NOT free the underlying trust records.
 */
void ipadb_trust_index_free(struct ipadb_trust_index **indexp);

/*
 * Exact-match lookups.  Return the matching trust, or NULL.
 * name/name_len identify the search key (not necessarily NUL-terminated).
 */
struct ipadb_adtrusts *
ipadb_trust_find_by_domain(struct ipadb_trust_index *idx,
                           const char *name, size_t name_len);

struct ipadb_adtrusts *
ipadb_trust_find_by_flat(struct ipadb_trust_index *idx,
                         const char *name, size_t name_len);

struct ipadb_adtrusts *
ipadb_trust_find_by_upn(struct ipadb_trust_index *idx,
                        const char *name, size_t name_len);

struct ipadb_adtrusts *
ipadb_trust_find_by_sid(struct ipadb_trust_index *idx,
                        const char *sid_str);

/*
 * Combined lookup: exact match on domain name, then flat name, then UPN
 * suffixes, in that order -- all exact matches are tried before any
 * suffix (subdomain) match is attempted, since an explicitly
 * configured name is always more authoritative than an incidental
 * naming-hierarchy relationship.
 *
 * Only if none of those match do we fall back to a suffix match
 * (e.g. "child.ad.example.com" matches "ad.example.com" if separated
 * by a dot), taking the longest (most specific) match across domain
 * names and UPN suffixes together.
 *
 * Returns the matching trust or NULL.
 */
struct ipadb_adtrusts *
ipadb_trust_find_by_name(struct ipadb_trust_index *idx,
                         const char *name, size_t name_len);

/*
 * Find a trust whose domain SID is a prefix of (or exact match for)
 * the given dom_sid.  This is needed for PAC filtering where we check
 * if a SID belongs to a trusted domain.
 *
 * This falls back to linear scan because SID prefix matching is not
 * amenable to binary tree lookup.
 *
 * trusts/num_trusts are the raw arrays (not the index).
 */
struct ipadb_adtrusts *
ipadb_trust_find_by_sid_prefix(struct ipadb_adtrusts *trusts,
                               size_t num_trusts,
                               const struct dom_sid *sid);
