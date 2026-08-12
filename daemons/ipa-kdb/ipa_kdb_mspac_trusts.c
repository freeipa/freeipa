/*
 * Copyright (C) 2026 FreeIPA Contributors, see 'COPYING' for license.
 *
 * Indexed trust lookup using POSIX tsearch/tfind binary trees.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <search.h>

#include "ipa_kdb.h"
#include "gen_ndr/ndr_krb5pac.h"
#include "ipa_kdb_mspac_private.h"

/* ------------------------------------------------------------------
 * Comparison functions for tsearch/tfind.
 *
 * Each tree stores pointers to trust_key_entry.  The comparison
 * function receives pointers-to-pointers (void *a is actually
 * const struct trust_key_entry *).  Keys are compared
 * case-insensitively.
 * ------------------------------------------------------------------
 */

static int cmp_ci_key(const void *a, const void *b)
{
    const struct trust_key_entry *ea = a;
    const struct trust_key_entry *eb = b;

    return strcasecmp(ea->key, eb->key);
}

/* ------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------
 */

/*
 * Count the total number of index entries we need to allocate for
 * all trusts.  Each trust contributes:
 *   1 for domain_name (always present)
 *   1 for flat_name   (if not NULL)
 *   1 for domain_sid  (if not NULL)
 *   N for upn_suffixes (each non-NULL suffix)
 */
static size_t count_entries(struct ipadb_adtrusts *trusts, size_t n)
{
    size_t total = 0;
    size_t i, j;

    for (i = 0; i < n; i++) {
        if (trusts[i].domain_name)
            total++;
        if (trusts[i].flat_name)
            total++;
        if (trusts[i].domain_sid)
            total++;
        if (trusts[i].upn_suffixes) {
            for (j = 0; trusts[i].upn_suffixes[j]; j++)
                total++;
        }
    }
    return total;
}

/* no-op free function for tdestroy -- entries are owned by the flat array */
static void noop_free(void *p)
{
    (void)p;
}

/*
 * Insert 'e' into '*root'.  Returns ENOMEM on allocation failure.
 *
 * Per POSIX, if a key equal (per cmp_ci_key) to 'e' is already in the
 * tree, tsearch() leaves the tree untouched and returns the existing
 * node instead of inserting 'e'.  We detect that case and log it: two
 * trusts (or a trust and one of its own UPN suffixes) sharing the same
 * case-insensitive key would otherwise vanish from lookups silently.
 */
static int insert_entry(void **root, struct trust_key_entry *e,
                        const char *what)
{
    void **ret = tsearch(e, root, cmp_ci_key);

    if (!ret)
        return ENOMEM;

    if (*ret != e) {
        krb5_klog_syslog(LOG_WARNING,
                         "Trust index: duplicate %s '%s', keeping the "
                         "first trust seen for this key", what, e->key);
    }
    return 0;
}

/* ------------------------------------------------------------------
 * Build
 * ------------------------------------------------------------------
 */

int ipadb_trust_index_build(struct ipadb_adtrusts *trusts,
                            size_t num_trusts,
                            struct ipadb_trust_index **index_out)
{
    struct ipadb_trust_index *idx = NULL;
    struct trust_key_entry *e;
    size_t total, pos;
    size_t i, j;

    if (index_out == NULL)
        return EINVAL;

    *index_out = NULL;

    if (num_trusts == 0 || trusts == NULL) {
        /* Nothing to index, but that's not an error. Callers must
         * handle a NULL index gracefully (= "no trusts"). */
        return 0;
    }

    idx = calloc(1, sizeof(*idx));
    if (!idx)
        return ENOMEM;

    total = count_entries(trusts, num_trusts);
    if (total == 0) {
        *index_out = idx;
        return 0;
    }

    idx->entries = calloc(total, sizeof(struct trust_key_entry));
    if (!idx->entries) {
        free(idx);
        return ENOMEM;
    }
    idx->num_entries = total;

    pos = 0;
    for (i = 0; i < num_trusts; i++) {
        struct ipadb_adtrusts *t = &trusts[i];

        /* domain_name -> by_domain */
        if (t->domain_name) {
            e = &idx->entries[pos++];
            e->key = t->domain_name;
            e->key_len = strlen(t->domain_name);
            e->kind = TRUST_KEY_DOMAIN;
            e->trust = t;
            if (insert_entry(&idx->by_domain, e, "domain name"))
                goto fail;
        }

        /* flat_name -> by_flat */
        if (t->flat_name) {
            e = &idx->entries[pos++];
            e->key = t->flat_name;
            e->key_len = strlen(t->flat_name);
            e->kind = TRUST_KEY_FLAT;
            e->trust = t;
            if (insert_entry(&idx->by_flat, e, "flat name"))
                goto fail;
        }

        /* domain_sid -> by_sid */
        if (t->domain_sid) {
            e = &idx->entries[pos++];
            e->key = t->domain_sid;
            e->key_len = strlen(t->domain_sid);
            e->kind = TRUST_KEY_SID;
            e->trust = t;
            if (insert_entry(&idx->by_sid, e, "domain SID"))
                goto fail;
        }

        /* upn_suffixes -> by_upn */
        if (t->upn_suffixes) {
            for (j = 0; t->upn_suffixes[j]; j++) {
                e = &idx->entries[pos++];
                e->key = t->upn_suffixes[j];
                e->key_len = t->upn_suffixes_len
                                ? t->upn_suffixes_len[j]
                                : strlen(t->upn_suffixes[j]);
                e->kind = TRUST_KEY_UPN;
                e->trust = t;
                if (insert_entry(&idx->by_upn, e, "UPN suffix"))
                    goto fail;
            }
        }
    }

    *index_out = idx;
    return 0;

fail:
    ipadb_trust_index_free(&idx);
    return ENOMEM;
}

/* ------------------------------------------------------------------
 * Free
 * ------------------------------------------------------------------
 */

void ipadb_trust_index_free(struct ipadb_trust_index **indexp)
{
    struct ipadb_trust_index *idx;

    if (!indexp || !*indexp)
        return;

    idx = *indexp;

    /* tdestroy is a glibc extension (available on Linux).
     * We pass noop_free because the key entries are owned by
     * the flat idx->entries array freed below. */
    if (idx->by_domain)
        tdestroy(idx->by_domain, noop_free);
    if (idx->by_flat)
        tdestroy(idx->by_flat, noop_free);
    if (idx->by_upn)
        tdestroy(idx->by_upn, noop_free);
    if (idx->by_sid)
        tdestroy(idx->by_sid, noop_free);

    free(idx->entries);
    free(idx);
    *indexp = NULL;
}

/* ------------------------------------------------------------------
 * Exact-match lookups
 * ------------------------------------------------------------------
 */

/*
 * Common helper: search a tree for a key that may not be NUL-terminated.
 * We build a temporary NUL-terminated copy on the stack (or heap for
 * very long keys) so the comparison function can use strcasecmp().
 */
static struct ipadb_adtrusts *
find_in_tree(void *root, const char *name, size_t name_len,
             int (*compar)(const void *, const void *))
{
    struct trust_key_entry probe;
    void **found;
    char stack_buf[256];
    char *buf;

    if (!root || !name || name_len == 0)
        return NULL;

    /* Build NUL-terminated key.  Use stack buffer when possible. */
    if (name_len < sizeof(stack_buf)) {
        buf = stack_buf;
        memcpy(buf, name, name_len);
        buf[name_len] = '\0';
    } else {
        buf = strndup(name, name_len);
        if (!buf)
            return NULL;
    }

    probe.key = buf;
    probe.key_len = name_len;
    probe.kind = TRUST_KEY_DOMAIN;
    probe.trust = NULL;

    found = tfind(&probe, &root, compar);

    if (buf != stack_buf)
        free(buf);

    if (found) {
        struct trust_key_entry *entry = *(struct trust_key_entry **)found;
        return entry->trust;
    }
    return NULL;
}

/* Pick the tree root for a given key kind. */
static void *tree_root(struct ipadb_trust_index *idx, enum trust_key_kind kind)
{
    switch (kind) {
    case TRUST_KEY_DOMAIN: return idx->by_domain;
    case TRUST_KEY_FLAT:   return idx->by_flat;
    case TRUST_KEY_SID:    return idx->by_sid;
    case TRUST_KEY_UPN:    return idx->by_upn;
    }
    return NULL;
}

static struct ipadb_adtrusts *
find_exact(struct ipadb_trust_index *idx, enum trust_key_kind kind,
          const char *name, size_t name_len)
{
    if (!idx)
        return NULL;
    return find_in_tree(tree_root(idx, kind), name, name_len, cmp_ci_key);
}

struct ipadb_adtrusts *
ipadb_trust_find_by_domain(struct ipadb_trust_index *idx,
                           const char *name, size_t name_len)
{
    return find_exact(idx, TRUST_KEY_DOMAIN, name, name_len);
}

struct ipadb_adtrusts *
ipadb_trust_find_by_flat(struct ipadb_trust_index *idx,
                         const char *name, size_t name_len)
{
    return find_exact(idx, TRUST_KEY_FLAT, name, name_len);
}

struct ipadb_adtrusts *
ipadb_trust_find_by_upn(struct ipadb_trust_index *idx,
                        const char *name, size_t name_len)
{
    return find_exact(idx, TRUST_KEY_UPN, name, name_len);
}

struct ipadb_adtrusts *
ipadb_trust_find_by_sid(struct ipadb_trust_index *idx,
                        const char *sid_str)
{
    if (!sid_str)
        return NULL;
    return find_exact(idx, TRUST_KEY_SID, sid_str, strlen(sid_str));
}

/* ------------------------------------------------------------------
 * Suffix match helper
 *
 * Check if 'name' (length name_len) is a subdomain of an indexed
 * trust domain name or UPN suffix, i.e. name ends with ".<suffix>".
 *
 * Domain names and UPN suffixes are considered together in a single
 * pass so the longest (most specific) match wins regardless of which
 * kind it came from: an admin-configured UPN suffix a few labels deep
 * (e.g. "deep.c.b.a.test" on trust "d.test") must not lose to a
 * shorter, coincidental subdomain match against an unrelated ancestor
 * domain name (e.g. "c.b.a.test").
 *
 * We iterate over the index entries.  This is O(n) but only runs when
 * the O(log n) exact match fails, and the number of trusts+UPN
 * suffixes is typically very small.
 * ------------------------------------------------------------------
 */

static struct ipadb_adtrusts *
suffix_scan(struct trust_key_entry *entries, size_t num_entries,
            const char *name, size_t name_len)
{
    size_t i;
    struct trust_key_entry *e;
    size_t klen;
    struct ipadb_adtrusts *best = NULL;
    size_t best_len = 0;

    for (i = 0; i < num_entries; i++) {
        e = &entries[i];

        if (e->kind != TRUST_KEY_DOMAIN && e->kind != TRUST_KEY_UPN)
            continue;

        klen = e->key_len;

        /* suffix check: name = "child.example.com", key = "example.com"
         * name_len > klen, and name[name_len - klen - 1] == '.'
         *
         * Track the longest (most specific) match so that
         * "sub.child.my.domain" prefers "child.my.domain" over
         * "my.domain". */
        if (name_len > klen && name[name_len - klen - 1] == '.') {
            if (strncasecmp(name + (name_len - klen), e->key, klen) == 0) {
                if (klen > best_len) {
                    best = e->trust;
                    best_len = klen;
                }
            }
        }
    }
    return best;
}

/* ------------------------------------------------------------------ */
/* Combined lookup                                                     */
/* ------------------------------------------------------------------ */

struct ipadb_adtrusts *
ipadb_trust_find_by_name(struct ipadb_trust_index *idx,
                         const char *name, size_t name_len)
{
    struct ipadb_adtrusts *trust;

    if (!idx || !name || name_len == 0)
        return NULL;

    /* Exact matches always take priority over any suffix (subdomain)
     * match, regardless of kind: an admin-configured UPN suffix or
     * NetBIOS name is exactly as authoritative as a literal domain
     * name, and none of them may lose to a merely coincidental
     * subdomain relationship. */

    /* 1. Exact match on domain name */
    trust = ipadb_trust_find_by_domain(idx, name, name_len);
    if (trust)
        return trust;

    /* 2. Exact match on flat/NetBIOS name */
    trust = ipadb_trust_find_by_flat(idx, name, name_len);
    if (trust)
        return trust;

    /* 3. Exact match on UPN suffixes */
    trust = ipadb_trust_find_by_upn(idx, name, name_len);
    if (trust)
        return trust;

    /* 4. No exact match: fall back to the most specific (longest)
     * suffix match across domain names and UPN suffixes together. */
    return suffix_scan(idx->entries, idx->num_entries, name, name_len);
}

/* ------------------------------------------------------------------
 * SID prefix lookup (linear, needed for PAC filtering)
 * ------------------------------------------------------------------
 */

#define SID_ID_AUTHS 6

/*
 * Check if sid1 is a prefix of sid2, i.e. sid2 starts with all
 * sub-authorities of sid1 and may have at most one more (a RID).
 * Also matches when both SIDs are identical.
 */
static bool sid_is_prefix(const struct dom_sid *sid1,
                          const struct dom_sid *sid2)
{
    int c;

    if (sid1 == sid2)
        return true;
    if (sid1 == NULL || sid2 == NULL)
        return false;
    if (sid1->sid_rev_num != sid2->sid_rev_num)
        return false;
    if (sid1->num_auths > sid2->num_auths)
        return false;

    /* sid2 may only carry a single extra sub-authority (a RID) on top
     * of sid1's domain; anything deeper is not a domain/resource-SID
     * relationship and must not be treated as a prefix match */
    if (sid2->num_auths - sid1->num_auths > 1)
        return false;

    for (c = 0; c < sid1->num_auths; c++) {
        if (sid1->sub_auths[c] != sid2->sub_auths[c])
            return false;
    }

    for (c = 0; c < SID_ID_AUTHS; c++) {
        if (sid1->id_auth[c] != sid2->id_auth[c])
            return false;
    }

    return true;
}

struct ipadb_adtrusts *
ipadb_trust_find_by_sid_prefix(struct ipadb_adtrusts *trusts,
                               size_t num_trusts,
                               const struct dom_sid *sid)
{
    size_t i;

    if (!trusts || !sid)
        return NULL;

    for (i = 0; i < num_trusts; i++) {
        if (sid_is_prefix(&trusts[i].domsid, sid)) {
            return &trusts[i];
        }
    }
    return NULL;
}
