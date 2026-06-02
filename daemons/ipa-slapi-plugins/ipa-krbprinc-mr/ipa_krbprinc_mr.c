/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Alexander Bokovoy <abokovoy@redhat.com>
 *
 * Copyright (C) 2026 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <strings.h>
#include <ctype.h>
#include "slapi-plugin.h"
#include <krb5/krb5.h>

#define IPA_PLUGIN_NAME "ipa-krbprinc-mr"
#include "util.h"

#define KRBPRINC_MATCH_OID "2.16.840.1.113730.3.8.29.1"
#define KRBPRINC_MATCH_NAME "krbPrincipalMatch"
#define IA5STRING_SYNTAX_OID "1.3.6.1.4.1.1466.115.121.1.26"

static Slapi_PluginDesc plugin_desc = {
    IPA_PLUGIN_NAME,
    "Red Hat, Inc.",
    "1.0",
    "Kerberos principal matching rule plugin"
};

static const char *mr_names[] = {
    KRBPRINC_MATCH_NAME,
    KRBPRINC_MATCH_OID,
    NULL
};

static krb5_context krb_ctx;
static char *default_realm;

/*
 * Normalize a Kerberos principal string to its canonical form.
 *
 * Parses the input through krb5_parse_name (which appends the default realm
 * if none is present), then unparses back to a string to get the fully
 * qualified form. The result is lowercased for case-insensitive comparison.
 *
 * Returns a slapi_ch_malloc'd string on success, NULL on failure.
 */
static char *
normalize_krbprinc(const char *raw, size_t len, int fold_case)
{
    krb5_error_code kerr;
    krb5_principal princ = NULL;
    char *unparsed = NULL;
    char *normalized = NULL;
    char *tmpstr;

    /* krb5_parse_name needs a NUL-terminated string */
    tmpstr = slapi_ch_malloc(len + 1);
    if (!tmpstr) {
        LOG_OOM();
        return NULL;
    }
    memcpy(tmpstr, raw, len);
    tmpstr[len] = '\0';

    kerr = krb5_parse_name(krb_ctx, tmpstr, &princ);
    if (kerr) {
        LOG_TRACE("krb5_parse_name failed for '%s': %d\n", tmpstr, kerr);
        slapi_ch_free_string(&tmpstr);
        return NULL;
    }
    slapi_ch_free_string(&tmpstr);

    kerr = krb5_unparse_name(krb_ctx, princ, &unparsed);
    krb5_free_principal(krb_ctx, princ);
    if (kerr) {
        LOG_TRACE("krb5_unparse_name failed: %d\n", kerr);
        return NULL;
    }

    normalized = slapi_ch_strdup(unparsed);
    krb5_free_unparsed_name(krb_ctx, unparsed);
    if (!normalized) {
        LOG_OOM();
        return NULL;
    }

    if (fold_case) {
        char *p;
        for (p = normalized; *p; p++)
            *p = tolower((unsigned char)*p);
    }

    return normalized;
}

/*
 * EQUALITY filter callback (AVA).
 *
 * Compare a filter assertion value against each attribute value.
 * Returns 0 if any attribute value matches, -1 otherwise.
 */
static int
krbprinc_mr_filter_ava(Slapi_PBlock *pb __attribute__((unused)),
                        struct berval *bvfilter,
                        Slapi_Value **bvals,
                        int ftype,
                        Slapi_Value **retVal)
{
    char *norm_filter;
    int rc = -1;
    int i;

    if (!bvfilter || !bvals || ftype != LDAP_FILTER_EQUALITY)
        return -1;

    norm_filter = normalize_krbprinc(bvfilter->bv_val, bvfilter->bv_len, 0);
    if (!norm_filter)
        return -1;

    for (i = 0; bvals[i]; i++) {
        const struct berval *bv = slapi_value_get_berval(bvals[i]);
        char *norm_val;

        if (!bv)
            continue;

        norm_val = normalize_krbprinc(bv->bv_val, bv->bv_len, 0);
        if (!norm_val)
            continue;

        if (strcasecmp(norm_filter, norm_val) == 0) {
            if (retVal)
                *retVal = bvals[i];
            rc = 0;
            slapi_ch_free_string(&norm_val);
            break;
        }
        slapi_ch_free_string(&norm_val);
    }

    slapi_ch_free_string(&norm_filter);
    return rc;
}

/*
 * Index key generation for stored attribute values.
 *
 * Normalizes each value and returns the normalized forms as index keys.
 * The returned ivals array is owned by the caller (the server frees it
 * via valuearray_free after indexing).
 */
static int
krbprinc_mr_values2keys(Slapi_PBlock *pb __attribute__((unused)),
                         Slapi_Value **vals,
                         Slapi_Value ***ivals,
                         int ftype __attribute__((unused)))
{
    int count, i;
    Slapi_Value **keys;

    if (!vals || !ivals)
        return LDAP_OPERATIONS_ERROR;

    for (count = 0; vals[count]; count++)
        ;

    keys = (Slapi_Value **)slapi_ch_calloc(count + 1, sizeof(Slapi_Value *));
    if (!keys)
        return LDAP_OPERATIONS_ERROR;

    for (i = 0; i < count; i++) {
        const struct berval *bv = slapi_value_get_berval(vals[i]);
        char *norm;

        if (!bv || !(norm = normalize_krbprinc(bv->bv_val, bv->bv_len, 1))) {
            keys[i] = slapi_value_new_string("");
            continue;
        }
        keys[i] = slapi_value_new_string_passin(norm);
    }
    keys[count] = NULL;

    *ivals = keys;
    return LDAP_SUCCESS;
}

/*
 * Index key generation for a filter assertion value.
 *
 * Normalizes the assertion and returns it as a single index key.
 * The returned ivals array is owned by the caller (the server frees it
 * via valuearray_free after indexing).
 */
static int
krbprinc_mr_assertion2keys_ava(Slapi_PBlock *pb __attribute__((unused)),
                                Slapi_Value *val,
                                Slapi_Value ***ivals,
                                int ftype __attribute__((unused)))
{
    const struct berval *bv;
    char *norm;
    Slapi_Value **keys;

    if (!val || !ivals)
        return LDAP_OPERATIONS_ERROR;

    bv = slapi_value_get_berval(val);
    if (!bv)
        return LDAP_OPERATIONS_ERROR;

    norm = normalize_krbprinc(bv->bv_val, bv->bv_len, 1);
    if (!norm)
        return LDAP_OPERATIONS_ERROR;

    keys = (Slapi_Value **)slapi_ch_calloc(2, sizeof(Slapi_Value *));
    if (!keys) {
        slapi_ch_free_string(&norm);
        return LDAP_OPERATIONS_ERROR;
    }

    keys[0] = slapi_value_new_string_passin(norm);
    keys[1] = NULL;

    *ivals = keys;
    return LDAP_SUCCESS;
}

/*
 * Comparison function for ordering (used by sort).
 *
 * Returns <0, 0, or >0 like strcmp.
 */
static int
krbprinc_mr_compare(struct berval *v1, struct berval *v2)
{
    char *n1, *n2;
    int rc;

    if (!v1 && !v2) return 0;
    if (!v1) return -1;
    if (!v2) return 1;

    n1 = normalize_krbprinc(v1->bv_val, v1->bv_len, 0);
    n2 = normalize_krbprinc(v2->bv_val, v2->bv_len, 0);

    if (!n1 && !n2) rc = 0;
    else if (!n1) rc = -1;
    else if (!n2) rc = 1;
    else rc = strcasecmp(n1, n2);

    slapi_ch_free_string(&n1);
    slapi_ch_free_string(&n2);
    return rc;
}

/*
 * Normalization callback.
 *
 * If the input can be parsed as a Kerberos principal, returns the
 * normalized (realm-qualified) form in *alt. Otherwise
 * leaves *alt as NULL and the server falls back to the original value.
 */
static void
krbprinc_mr_normalize(Slapi_PBlock *pb __attribute__((unused)),
                       char *s,
                       int trim_spaces __attribute__((unused)),
                       char **alt)
{
    char *norm;

    if (!s || !alt)
        return;

    norm = normalize_krbprinc(s, strlen(s), 0);
    if (norm)
        *alt = norm;
}

static int
krbprinc_mr_close(Slapi_PBlock *pb __attribute__((unused)))
{
    if (default_realm) {
        krb5_free_default_realm(krb_ctx, default_realm);
        default_realm = NULL;
    }
    if (krb_ctx) {
        krb5_free_context(krb_ctx);
        krb_ctx = NULL;
    }
    return 0;
}

int
ipa_krbprinc_mr_init(Slapi_PBlock *pb)
{
    int rc;
    int not_obsolete = 0;
    krb5_error_code kerr;
    Slapi_MatchingRuleEntry *mrEntry = NULL;

    LOG("=> ipa_krbprinc_mr_init\n");

    kerr = krb5_init_context(&krb_ctx);
    if (kerr) {
        LOG_FATAL("krb5_init_context failed: %d\n", kerr);
        return -1;
    }

    kerr = krb5_get_default_realm(krb_ctx, &default_realm);
    if (kerr) {
        LOG_FATAL("krb5_get_default_realm failed: %d, OK during bootstrap, "
                  "default to EXAMPLE.TEST\n", kerr);
        default_realm = strdup("EXAMPLE.TEST");
        if (default_realm == NULL) {
            krb5_free_context(krb_ctx);
            krb_ctx = NULL;
            return -1;
	}
    }

    LOG("default realm: %s\n", default_realm);

    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                          SLAPI_PLUGIN_VERSION_03);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                           (void *)&plugin_desc);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                           (void *)krbprinc_mr_close);

    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_MR_NAMES,
                           (void *)mr_names);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_MR_FILTER_AVA,
                           (void *)krbprinc_mr_filter_ava);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_MR_VALUES2KEYS,
                           (void *)krbprinc_mr_values2keys);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_MR_ASSERTION2KEYS_AVA,
                           (void *)krbprinc_mr_assertion2keys_ava);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_MR_COMPARE,
                           (void *)krbprinc_mr_compare);
    rc |= slapi_pblock_set(pb, SLAPI_PLUGIN_MR_NORMALIZE,
                           (void *)krbprinc_mr_normalize);

    if (rc) {
        LOG_FATAL("failed to set plugin callbacks\n");
        krbprinc_mr_close(pb);
        return -1;
    }

    mrEntry = slapi_matchingrule_new();
    if (!mrEntry) {
        LOG_FATAL("slapi_matchingrule_new failed\n");
        krbprinc_mr_close(pb);
        return -1;
    }

    slapi_matchingrule_set(mrEntry, SLAPI_MATCHINGRULE_NAME,
                           (void *)KRBPRINC_MATCH_NAME);
    slapi_matchingrule_set(mrEntry, SLAPI_MATCHINGRULE_OID,
                           (void *)KRBPRINC_MATCH_OID);
    slapi_matchingrule_set(mrEntry, SLAPI_MATCHINGRULE_DESC,
                           (void *)"Kerberos principal equality match "
                           "with realm normalization");
    slapi_matchingrule_set(mrEntry, SLAPI_MATCHINGRULE_SYNTAX,
                           (void *)IA5STRING_SYNTAX_OID);
    slapi_matchingrule_set(mrEntry, SLAPI_MATCHINGRULE_OBSOLETE,
                           &not_obsolete);

    rc = slapi_matchingrule_register(mrEntry);
    if (rc) {
        LOG_FATAL("slapi_matchingrule_register failed: %d\n", rc);
        slapi_matchingrule_free(&mrEntry, 1);
        krbprinc_mr_close(pb);
        return -1;
    }

    LOG("<= ipa_krbprinc_mr_init: success\n");
    return 0;
}
