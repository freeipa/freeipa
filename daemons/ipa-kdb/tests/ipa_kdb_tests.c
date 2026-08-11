/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

    ipa-kdb tests

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <talloc.h>

#include "gen_ndr/ndr_krb5pac.h"
#include "gen_ndr/netlogon.h"

#include "ipa_kdb.h"
#include "ipa_kdb_mspac_private.h"

#define NFS_PRINC_STRING "nfs/fully.qualified.host.name@REALM.NAME"
#define NON_NFS_PRINC_STRING "abcdef/fully.qualified.host.name@REALM.NAME"

int krb5_klog_syslog(int l, const char *format, ...)
{
    va_list ap;
    char *s = NULL;
    int ret;

    va_start(ap, format);

    ret = vasprintf(&s, format, ap);
    va_end(ap);
    if (ret < 0) {
        /* ENOMEM */
        return -1;
    }

    fprintf(stderr, "%s\n", s);
    free(s);

    return 0;
}

struct test_ctx {
    krb5_context krb5_ctx;
};

#define DOMAIN_NAME "my.domain"
#define REALM "MY.DOMAIN"
#define REALM_LEN (sizeof(REALM) - 1)
#define FLAT_NAME "MYDOM"
#define DOM_SID "S-1-5-21-1-2-3"
#define DOM_SID_TRUST "S-1-5-21-4-5-6"
#define BLOCKLIST_SID "S-1-5-1"
#define NUM_SUFFIXES 10
#define SUFFIX_TEMPLATE "d%zu" DOMAIN_NAME
#define TEST_REALM_TEMPLATE "some." SUFFIX_TEMPLATE
#define EXTERNAL_REALM "WRONG.DOMAIN"

/*
 * Trusted domains for the matching tests. The overlapping pair reproduces two
 * forests sharing a parent domain; the nested set has matching names at eight
 * distinct lengths, so that no two names of different trusts are of equal
 * length and every expectation is independent of the order of the trust list.
 */
#define OVERLAP_A_DOMAIN "forest.shared.test"
#define OVERLAP_A_REALM "FOREST.SHARED.TEST"
#define OVERLAP_B_DOMAIN "forestry.shared.test"
#define OVERLAP_B_REALM "FORESTRY.SHARED.TEST"
#define SHARED_PARENT "shared.test"
/* a string prefix of the local realm EXAMPLE.COM that is no parent of it */
#define LOCAL_REALM_PREFIX "EXAMPLE"

struct trust_fixture {
    const char *domain_name;
    const char *flat_name;
    const char *domain_sid;
    const char *upn_suffixes[3];
};

static int setup(void **state)
{
    int ret;
    krb5_context krb5_ctx;
    krb5_error_code kerr;
    struct ipadb_context *ipa_ctx;
    struct test_ctx *test_ctx;

    kerr = krb5_init_context(&krb5_ctx);
    assert_int_equal(kerr, 0);

    kerr = krb5_set_default_realm(krb5_ctx, "EXAMPLE.COM");
    assert_int_equal(kerr, 0);

    kerr = krb5_db_setup_lib_handle(krb5_ctx);
    assert_int_equal(kerr, 0);

    ipa_ctx = calloc(1, sizeof(struct ipadb_context));
    assert_non_null(ipa_ctx);

    kerr = krb5_get_default_realm(krb5_ctx, &ipa_ctx->realm);
    assert_int_equal(kerr, 0);

    ipa_ctx->mspac = calloc(1, sizeof(struct ipadb_mspac));
    assert_non_null(ipa_ctx->mspac);

    /* make sure data is not read from LDAP */
    ipa_ctx->mspac->last_update = time(NULL) - 1;

    ret = ipadb_string_to_sid(DOM_SID, &ipa_ctx->mspac->domsid);
    assert_int_equal(ret, 0);

    ipa_ctx->mspac->num_trusts = 1;
    ipa_ctx->mspac->trusts = calloc(1, sizeof(struct ipadb_adtrusts));
    assert_non_null(ipa_ctx->mspac->trusts);

    ipa_ctx->mspac->trusts[0].domain_name = strdup(DOMAIN_NAME);
    assert_non_null(ipa_ctx->mspac->trusts[0].domain_name);

    ipa_ctx->mspac->trusts[0].flat_name = strdup(FLAT_NAME);
    assert_non_null(ipa_ctx->mspac->trusts[0].flat_name);

    ipa_ctx->mspac->trusts[0].domain_sid = strdup(DOM_SID_TRUST);
    assert_non_null(ipa_ctx->mspac->trusts[0].domain_sid);

    ret = ipadb_string_to_sid(DOM_SID_TRUST, &ipa_ctx->mspac->trusts[0].domsid);
    assert_int_equal(ret, 0);

    ipa_ctx->mspac->trusts[0].len_sid_blocklist_incoming = 1;
    ipa_ctx->mspac->trusts[0].sid_blocklist_incoming = calloc(
                           ipa_ctx->mspac->trusts[0].len_sid_blocklist_incoming,
                           sizeof(struct dom_sid));
    assert_non_null(ipa_ctx->mspac->trusts[0].sid_blocklist_incoming);
    ret = ipadb_string_to_sid(BLOCKLIST_SID,
                        &ipa_ctx->mspac->trusts[0].sid_blocklist_incoming[0]);
    assert_int_equal(ret, 0);

    ipa_ctx->mspac->trusts[0].upn_suffixes = calloc(NUM_SUFFIXES + 1, sizeof(char *));
    ipa_ctx->mspac->trusts[0].upn_suffixes_len = calloc(NUM_SUFFIXES, sizeof(size_t));
    for (size_t i = 0; i < NUM_SUFFIXES; i++) {
	assert_int_not_equal(asprintf(&(ipa_ctx->mspac->trusts[0].upn_suffixes[i]),
                                      SUFFIX_TEMPLATE, i), -1);
        ipa_ctx->mspac->trusts[0].upn_suffixes_len[i] =
            strlen(ipa_ctx->mspac->trusts[0].upn_suffixes[i]);

    }

    ipa_ctx->kcontext = krb5_ctx;
    kerr = krb5_db_set_context(krb5_ctx, ipa_ctx);
    assert_int_equal(kerr, 0);

    test_ctx = talloc(NULL, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->krb5_ctx = krb5_ctx;

    *state = test_ctx;

    return 0;
}

/*
 * Like setup(), but with a caller supplied list of trusted domains and only the
 * fields ipadb_is_princ_from_trusted_realm() reads. teardown() is shared with
 * setup().
 */
static int setup_trusts(void **state, const struct trust_fixture *defs,
                        size_t num_trusts)
{
    krb5_context krb5_ctx;
    krb5_error_code kerr;
    struct ipadb_context *ipa_ctx;
    struct test_ctx *test_ctx;
    size_t i, j, num_suffixes;

    kerr = krb5_init_context(&krb5_ctx);
    assert_int_equal(kerr, 0);

    kerr = krb5_set_default_realm(krb5_ctx, "EXAMPLE.COM");
    assert_int_equal(kerr, 0);

    kerr = krb5_db_setup_lib_handle(krb5_ctx);
    assert_int_equal(kerr, 0);

    ipa_ctx = calloc(1, sizeof(struct ipadb_context));
    assert_non_null(ipa_ctx);

    kerr = krb5_get_default_realm(krb5_ctx, &ipa_ctx->realm);
    assert_int_equal(kerr, 0);

    ipa_ctx->mspac = calloc(1, sizeof(struct ipadb_mspac));
    assert_non_null(ipa_ctx->mspac);

    /* make sure data is not read from LDAP */
    ipa_ctx->mspac->last_update = time(NULL) - 1;

    ipa_ctx->mspac->num_trusts = num_trusts;
    ipa_ctx->mspac->trusts = calloc(num_trusts,
                                    sizeof(struct ipadb_adtrusts));
    assert_non_null(ipa_ctx->mspac->trusts);

    for (i = 0; i < num_trusts; i++) {
        struct ipadb_adtrusts *trust = &ipa_ctx->mspac->trusts[i];

        trust->domain_name = strdup(defs[i].domain_name);
        assert_non_null(trust->domain_name);
        trust->flat_name = strdup(defs[i].flat_name);
        assert_non_null(trust->flat_name);
        trust->domain_sid = strdup(defs[i].domain_sid);
        assert_non_null(trust->domain_sid);

        for (num_suffixes = 0; defs[i].upn_suffixes[num_suffixes] != NULL;
             num_suffixes++) {
        }
        if (num_suffixes == 0) {
            continue;
        }

        trust->upn_suffixes = calloc(num_suffixes + 1, sizeof(char *));
        assert_non_null(trust->upn_suffixes);
        trust->upn_suffixes_len = calloc(num_suffixes, sizeof(size_t));
        assert_non_null(trust->upn_suffixes_len);

        for (j = 0; j < num_suffixes; j++) {
            trust->upn_suffixes[j] = strdup(defs[i].upn_suffixes[j]);
            assert_non_null(trust->upn_suffixes[j]);
            trust->upn_suffixes_len[j] = strlen(trust->upn_suffixes[j]);
        }
    }

    ipa_ctx->kcontext = krb5_ctx;
    kerr = krb5_db_set_context(krb5_ctx, ipa_ctx);
    assert_int_equal(kerr, 0);

    test_ctx = talloc(NULL, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->krb5_ctx = krb5_ctx;

    *state = test_ctx;

    return 0;
}

/* Two forests sharing a parent domain, which the first one owns as a UPN
 * suffix while it is the parent of the second one's realm. The first one's
 * realm is additionally a string prefix of the second one's, and the second
 * one owns a UPN suffix that is a string prefix of the local realm. */
static int setup_overlapping_trusts(void **state)
{
    static const struct trust_fixture defs[] = {
        { OVERLAP_A_DOMAIN, "FOREST", "S-1-5-21-7-8-9",
          { SHARED_PARENT, NULL } },
        { OVERLAP_B_DOMAIN, "FORESTRY", "S-1-5-21-10-11-12",
          { "example", NULL } },
    };

    return setup_trusts(state, defs, 2);
}

/*
 * Trusted domains nested several levels deep:
 *
 *   A   realm a.test          UPN suffix test
 *   B   realm b.a.test        UPN suffix deeper.c.b.a.test
 *   C   realm c.b.a.test
 *   D   realm d.test          UPN suffix deep.c.b.a.test
 *   BB  realm bb.a.test
 *
 * B and BB differ in a way that only the dot boundary tells apart, and the UPN
 * suffixes of B and D are deeper than the realm of C, so realms and suffixes
 * have to compete by match length alone.
 */
static int setup_nested_trusts(void **state)
{
    static const struct trust_fixture defs[] = {
        { "a.test",     "A",  "S-1-5-21-21-1-1", { "test", NULL } },
        { "b.a.test",   "B",  "S-1-5-21-21-2-2",
          { "deeper.c.b.a.test", NULL } },
        { "c.b.a.test", "C",  "S-1-5-21-21-3-3", { NULL } },
        { "d.test",     "D",  "S-1-5-21-21-4-4",
          { "deep.c.b.a.test", NULL } },
        { "bb.a.test",  "BB", "S-1-5-21-21-5-5", { NULL } },
    };

    return setup_trusts(state, defs, 5);
}

static int teardown(void **state)
{
    struct test_ctx *test_ctx;
    struct ipadb_context *ipa_ctx;

    test_ctx = (struct test_ctx *) *state;

    ipa_ctx = ipadb_get_context(test_ctx->krb5_ctx);
    assert_non_null(ipa_ctx);
    ipadb_mspac_struct_free(&ipa_ctx->mspac);

    krb5_db_fini(test_ctx->krb5_ctx);
    krb5_free_context(test_ctx->krb5_ctx);

    talloc_free(test_ctx);

    return 0;
}

extern krb5_error_code filter_logon_info(krb5_context context,
                                  TALLOC_CTX *memctx,
                                  krb5_data *realm,
                                  struct PAC_LOGON_INFO_CTR *info);

static void test_filter_logon_info(void **state)
{
    krb5_error_code kerr;
    krb5_data realm = {KV5M_DATA, REALM_LEN, REALM};
    struct test_ctx *test_ctx;
    struct PAC_LOGON_INFO_CTR *info;
    int ret;
    struct dom_sid dom_sid;
    size_t c;
    size_t d;

    test_ctx = (struct test_ctx *) *state;

    info = talloc_zero(test_ctx, struct PAC_LOGON_INFO_CTR);
    assert_non_null(info);
    info->info = talloc_zero(info, struct PAC_LOGON_INFO);
    assert_non_null(info->info);

    /* wrong flat name */
    info->info->info3.base.logon_domain.string = talloc_strdup(info->info,
                                                               "WRONG");
    assert_non_null(info->info->info3.base.logon_domain.string);

    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, &realm, info);
    assert_int_equal(kerr, EINVAL);

    info->info->info3.base.logon_domain.string = talloc_strdup(info->info,
                                                               FLAT_NAME);
    assert_non_null(info->info->info3.base.logon_domain.string);

    /* missing domain SID */
    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, &realm, info);
    assert_int_equal(kerr, EINVAL);

    /* wrong domain SID */
    ret = ipadb_string_to_sid("S-1-5-21-1-1-1", &dom_sid);
    assert_int_equal(ret, 0);
    info->info->info3.base.domain_sid = &dom_sid;

    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, &realm, info);
    assert_int_equal(kerr, EINVAL);

    /* matching domain SID */
    ret = ipadb_string_to_sid(DOM_SID_TRUST, &dom_sid);
    assert_int_equal(ret, 0);
    info->info->info3.base.domain_sid = &dom_sid;

    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, &realm, info);
    assert_int_equal(kerr, 0);

    /* empty SIDs */
    info->info->info3.sidcount = 3;
    info->info->info3.sids = talloc_zero_array(info->info,
                                               struct netr_SidAttr,
                                               info->info->info3.sidcount);
    assert_non_null(info->info->info3.sids);
    for(c = 0; c < info->info->info3.sidcount; c++) {
        info->info->info3.sids[c].sid = talloc_zero(info->info->info3.sids,
                                                    struct dom_sid2);
        assert_non_null(info->info->info3.sids[c].sid);
    }

    kerr = filter_logon_info(test_ctx->krb5_ctx, NULL, &realm, info);
    assert_int_equal(kerr, 0);
    assert_int_equal(info->info->info3.sidcount, 3);

    struct test_data {
        size_t sidcount;
        const char *sids[3];
        size_t exp_sidcount;
        const char *exp_sids[3];
    } test_data[] = {
        /* only allowed SIDs */
        {3, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1001", DOM_SID_TRUST"-1002"},
         3, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1001", DOM_SID_TRUST"-1002"}},
        /* last SID filtered */
        {3, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1001", BLOCKLIST_SID"-1002"},
         2, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1001"}},
        /* center SID filtered */
        {3, {DOM_SID_TRUST"-1000", BLOCKLIST_SID"-1001", DOM_SID_TRUST"-1002"},
         2, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1002"}},
        /* first SID filtered */
        {3, {BLOCKLIST_SID"-1000", DOM_SID_TRUST"-1001", DOM_SID_TRUST"-1002"},
         2, {DOM_SID_TRUST"-1001", DOM_SID_TRUST"-1002"}},
        /* first and last SID filtered */
        {3, {BLOCKLIST_SID"-1000", DOM_SID_TRUST"-1001", BLOCKLIST_SID"-1002"},
         1, {DOM_SID_TRUST"-1001"}},
        /* two SIDs in a rwo filtered */
        {3, {BLOCKLIST_SID"-1000", BLOCKLIST_SID"-1001", DOM_SID_TRUST"-1002"},
         1, {DOM_SID_TRUST"-1002"}},
        /* all SIDs filtered*/
        {3, {BLOCKLIST_SID"-1000", BLOCKLIST_SID"-1001", BLOCKLIST_SID"-1002"},
         0, {}},
        {0, {}, 0 , {}}
    };

    for (c = 0; test_data[c].sidcount != 0; c++) {
        talloc_free(info->info->info3.sids);

        info->info->info3.sidcount = test_data[c].sidcount;
        info->info->info3.sids = talloc_zero_array(info->info,
                                                   struct netr_SidAttr,
                                                   info->info->info3.sidcount);
        assert_non_null(info->info->info3.sids);
        for(d = 0; d < info->info->info3.sidcount; d++) {
            info->info->info3.sids[d].sid = talloc_zero(info->info->info3.sids,
                                                        struct dom_sid2);
            assert_non_null(info->info->info3.sids[d].sid);
        }

        for (d = 0; d < info->info->info3.sidcount; d++) {
            ret = ipadb_string_to_sid(test_data[c].sids[d],
                                info->info->info3.sids[d].sid);
            assert_int_equal(ret, 0);
        }

        kerr = filter_logon_info(test_ctx->krb5_ctx, NULL, &realm, info);
        assert_int_equal(kerr, 0);
        assert_int_equal(info->info->info3.sidcount, test_data[c].exp_sidcount);
        if (test_data[c].exp_sidcount == 0) {
            assert_null(info->info->info3.sids);
        } else {
            for (d = 0; d < test_data[c].exp_sidcount; d++) {
                assert_string_equal(test_data[c].exp_sids[d],
                                 dom_sid_string(info->info->info3.sids,
                                                info->info->info3.sids[d].sid));
            }
        }
    }


    talloc_free(info);

}

static void test_get_authz_data_types(void **state)
{
    bool with_pac;
    bool with_pad;
    krb5_db_entry *entry;
    struct ipadb_e_data *ied;
    size_t c;
    char *ad_none_only[] = {"NONE", NULL};
    char *ad_pad_only[] = {"PAD", NULL};
    char *ad_pac_only[] = {"MS-PAC", NULL};
    char *ad_illegal_only[] = {"abc", NULL};
    char *ad_pac_and_pad[] = {"MS-PAC", "PAD", NULL};
    char *ad_pac_and_none[] = {"MS-PAC", "NONE", NULL};
    char *ad_none_and_pad[] = {"NONE", "PAD", NULL};
    char *ad_global_pac_nfs_none[] = {"MS-PAC", "nfs:NONE", NULL};
    char *ad_global_pac_nfs_pad[] = {"MS-PAC", "nfs:PAD", NULL};
    krb5_error_code kerr;
    struct ipadb_context *ipa_ctx;
    krb5_principal nfs_princ;
    krb5_principal non_nfs_princ;
    struct test_ctx *test_ctx;

    test_ctx = (struct test_ctx *) *state;
    ipa_ctx = ipadb_get_context(test_ctx->krb5_ctx);
    assert_non_null(ipa_ctx);

    get_authz_data_types(NULL, NULL, NULL, NULL);

    with_pad = true;
    get_authz_data_types(NULL, NULL, NULL, &with_pad);
    assert_false(with_pad);

    with_pac = true;
    get_authz_data_types(NULL, NULL, &with_pac, NULL);
    assert_false(with_pad);

    with_pad = true;
    with_pac = true;
    get_authz_data_types(NULL, NULL, &with_pac, &with_pad);
    assert_false(with_pac);
    assert_false(with_pad);

    entry = calloc(1, sizeof(krb5_db_entry));
    assert_non_null(entry);

    ied = calloc(1, sizeof(struct ipadb_e_data));
    assert_non_null(ied);
    entry->e_data = (void *) ied;

    kerr = krb5_parse_name(test_ctx->krb5_ctx, NFS_PRINC_STRING, &nfs_princ);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(test_ctx->krb5_ctx, NON_NFS_PRINC_STRING,
                           &non_nfs_princ);
    assert_int_equal(kerr, 0);

    struct test_set {
        char **authz_data;
        char **global_authz_data;
        krb5_principal princ;
        bool exp_with_pac;
        bool exp_with_pad;
        const char *err_msg;
    } test_set[] = {
        {ad_none_only, NULL, NULL, false, false, "with only NONE in entry"},
        {ad_pac_only, NULL, NULL, true, false, "with only MS-PAC in entry"},
        {ad_pad_only, NULL, NULL, false, true, "with only PAD in entry"},
        {ad_illegal_only, NULL, NULL, false, false, "with only an invalid value in entry"},
        {ad_pac_and_pad, NULL, NULL, true, true, "with MS-PAC and PAD in entry"},
        {ad_pac_and_none, NULL, NULL, false, false, "with MS-PAC and NONE in entry"},
        {ad_none_and_pad, NULL, NULL, false, false, "with NONE and PAD in entry"},
        {NULL, ad_none_only, NULL, false, false, "with only NONE in global config"},
        {NULL, ad_pac_only, NULL, true, false, "with only MS-PAC in global config"},
        {NULL, ad_pad_only, NULL, false, true, "with only PAD in global config"},
        {NULL, ad_illegal_only, NULL, false, false, "with only an invalid value in global config"},
        {NULL, ad_pac_and_pad, NULL, true, true, "with MS-PAC and PAD in global config"},
        {NULL, ad_pac_and_none, NULL, false, false, "with MS-PAC and NONE in global config"},
        {NULL, ad_none_and_pad, NULL, false, false, "with NONE and PAD in global entry"},
        {NULL, ad_global_pac_nfs_none, NULL, true, false, "with NULL principal and PAC and nfs:NONE in global entry"},
        {NULL, ad_global_pac_nfs_none, nfs_princ, false, false, "with nfs principal and PAC and nfs:NONE in global entry"},
        {NULL, ad_global_pac_nfs_none, non_nfs_princ, true, false, "with non-nfs principal and PAC and nfs:NONE in global entry"},
        {NULL, ad_global_pac_nfs_pad, NULL, true, false, "with NULL principal and PAC and nfs:PAD in global entry"},
        {NULL, ad_global_pac_nfs_pad, nfs_princ, false, true, "with nfs principal and PAC and nfs:PAD in global entry"},
        {NULL, ad_global_pac_nfs_pad, non_nfs_princ, true, false, "with non-nfs principal and PAC and nfs:PAD in global entry"},
        {ad_none_only, ad_pac_only, NULL, false, false, "with NONE overriding PAC in global entry"},
        {ad_pad_only, ad_pac_only, NULL, false, true, "with PAC overriding PAC in global entry"},
        {ad_illegal_only, ad_pac_only, NULL, false, false, "with invalid value overriding PAC in global entry"},
        {ad_pac_and_pad, ad_pac_only, NULL, true, true, "with PAC and PAD overriding PAC in global entry"},
        {ad_none_and_pad, ad_pac_only, NULL, false, false, "with NONE and PAD overriding PAC in global entry"},
        {NULL, NULL, NULL, false, false, NULL}
    };

    for (c = 0; test_set[c].authz_data != NULL ||
                test_set[c].global_authz_data != NULL; c++) {
        ied->authz_data = test_set[c].authz_data;
        ipa_ctx->config.authz_data = test_set[c].global_authz_data;
        /* Set last_update to avoid LDAP lookups during tests */
        ipa_ctx->config.last_update = time(NULL);
        entry->princ = test_set[c].princ;
        get_authz_data_types(test_ctx->krb5_ctx, entry, &with_pac, &with_pad);
        assert_true(with_pad == test_set[c].exp_with_pad);
        assert_true(with_pac == test_set[c].exp_with_pac);

        /* test if global default are returned if there is no server entry */
        if (test_set[c].authz_data == NULL && test_set[c].princ == NULL) {
            get_authz_data_types(test_ctx->krb5_ctx, NULL, &with_pac,
                                                           &with_pad);
            assert_true(with_pad == test_set[c].exp_with_pad);
            assert_true(with_pac == test_set[c].exp_with_pac);
        }
    }

    free(ied);
    free(entry);
    krb5_free_principal(test_ctx->krb5_ctx, nfs_princ);
    krb5_free_principal(test_ctx->krb5_ctx, non_nfs_princ);
}

static void test_ipadb_string_to_sid(void **state)
{
    int ret;
    struct dom_sid sid;
    struct dom_sid exp_sid = {1, 5, {0, 0, 0, 0, 0, 5},
                              {21, 2127521184, 1604012920, 1887927527, 72713,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    ret = ipadb_string_to_sid(NULL, &sid);
    assert_int_equal(ret, EINVAL);

    ret = ipadb_string_to_sid("abc", &sid);
    assert_int_equal(ret, EINVAL);

    ret = ipadb_string_to_sid("S-", &sid);
    assert_int_equal(ret, EINVAL);

    ret = ipadb_string_to_sid("S-ABC", &sid);
    assert_int_equal(ret, EINVAL);

    ret = ipadb_string_to_sid("S-123", &sid);
    assert_int_equal(ret, EINVAL);

    ret = ipadb_string_to_sid("S-1-123-1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6", &sid);
    assert_int_equal(ret, EINVAL);

    ret = ipadb_string_to_sid("S-1-5-21-2127521184-1604012920-1887927527-72713",
                        &sid);
    assert_int_equal(ret, 0);
    assert_memory_equal(&exp_sid, &sid, sizeof(struct dom_sid));
}

static void test_dom_sid_string(void **state)
{
    struct test_ctx *test_ctx;
    char *str_sid;
    struct dom_sid test_sid = {1, 5, {0, 0, 0, 0, 0, 5},
                               {21, 2127521184, 1604012920, 1887927527, 72713,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    test_ctx = (struct test_ctx *) *state;

    str_sid = dom_sid_string(test_ctx, NULL);
    assert_null(str_sid);

    str_sid = dom_sid_string(test_ctx, &test_sid);
    assert_non_null(str_sid);
    assert_string_equal(str_sid,
                        "S-1-5-21-2127521184-1604012920-1887927527-72713");

    test_sid.num_auths = -3;
    str_sid = dom_sid_string(test_ctx, &test_sid);

    test_sid.num_auths = 16;
    str_sid = dom_sid_string(test_ctx, &test_sid);
}


/* Resolve test_realm and assert that the expected trusted realm is returned. */
static void assert_resolves_to(krb5_context krb5_ctx, const char *test_realm,
                               const char *expected_realm)
{
    krb5_error_code kerr;
    char *trusted_realm = NULL;

    kerr = ipadb_is_princ_from_trusted_realm(krb5_ctx, test_realm,
                                             strlen(test_realm),
                                             &trusted_realm);
    assert_int_equal(kerr, 0);
    assert_non_null(trusted_realm);
    assert_string_equal(trusted_realm, expected_realm);
    free(trusted_realm);
}

/* Resolve test_realm and assert that it belongs to no trusted domain. */
static void assert_resolves_to_nothing(krb5_context krb5_ctx,
                                       const char *test_realm)
{
    krb5_error_code kerr;
    char *trusted_realm = NULL;

    kerr = ipadb_is_princ_from_trusted_realm(krb5_ctx, test_realm,
                                             strlen(test_realm),
                                             &trusted_realm);
    assert_int_equal(kerr, KRB5_KDB_NOENTRY);
    assert_null(trusted_realm);
}

/* Reverse the list of trusts, so that a lookup can be repeated with the trusts
 * in the other order. */
static void reverse_trusts(struct ipadb_context *ipa_ctx)
{
    struct ipadb_adtrusts swap;
    size_t i, last;

    for (i = 0; i < (size_t) ipa_ctx->mspac->num_trusts / 2; i++) {
        last = (size_t) ipa_ctx->mspac->num_trusts - 1 - i;
        swap = ipa_ctx->mspac->trusts[i];
        ipa_ctx->mspac->trusts[i] = ipa_ctx->mspac->trusts[last];
        ipa_ctx->mspac->trusts[last] = swap;
    }
}

static void test_check_trusted_realms(void **state)
{
    struct test_ctx *test_ctx;
    krb5_error_code kerr = 0;
    char *trusted_realm = NULL;

    test_ctx = (struct test_ctx *) *state;

    for(size_t i = 0; i < NUM_SUFFIXES; i++) {
        char *test_realm = NULL;
        assert_int_not_equal(asprintf(&test_realm, TEST_REALM_TEMPLATE, i), -1);

        if (test_realm) {
            kerr = ipadb_is_princ_from_trusted_realm(
                       test_ctx->krb5_ctx,
                       test_realm,
                       strlen(test_realm),
                       &trusted_realm);
            assert_int_equal(kerr, 0);
            free(test_realm);
            free(trusted_realm);
        }
    }

    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               EXTERNAL_REALM,
               strlen(EXTERNAL_REALM),
               &trusted_realm);
    assert_int_equal(kerr, KRB5_KDB_NOENTRY);

    /* The NetBIOS name resolves when it is the whole name that is tested. */
    assert_resolves_to(test_ctx->krb5_ctx, FLAT_NAME, REALM);

    /* A NetBIOS name is flat, so a name merely ending in it does not belong to
     * the trust. */
    assert_resolves_to_nothing(test_ctx->krb5_ctx, "host." FLAT_NAME);}

static void check_overlapping_namespaces(krb5_context krb5_ctx)
{
    /* The realm of the second trust is the parent of nothing but matches
     * completely, which beats the subordinate match on the UPN suffix of the
     * first one. */
    assert_resolves_to(krb5_ctx, OVERLAP_B_REALM, OVERLAP_B_REALM);
    assert_resolves_to(krb5_ctx, OVERLAP_A_REALM, OVERLAP_A_REALM);

    /* The UPN suffix resolves to the trust owning it, and so does a name below
     * it that belongs to no trust of its own. */
    assert_resolves_to(krb5_ctx, "SHARED.TEST", OVERLAP_A_REALM);
    assert_resolves_to(krb5_ctx, "OTHER.SHARED.TEST", OVERLAP_A_REALM);

    /* A name below both the UPN suffix of the first trust and the realm of the
     * second one resolves to the second one, whose name is longer. */
    assert_resolves_to(krb5_ctx, "SUB." OVERLAP_B_REALM, OVERLAP_B_REALM);
    assert_resolves_to(krb5_ctx, "SUB." OVERLAP_A_REALM, OVERLAP_A_REALM);

    /* A name sharing only its first characters with the local realm is not the
     * local realm, so it resolves against the trusts like any other name. */
    assert_resolves_to(krb5_ctx, LOCAL_REALM_PREFIX, OVERLAP_B_REALM);

    assert_resolves_to_nothing(krb5_ctx, EXTERNAL_REALM);
}

static void test_check_trusted_realms_overlapping_namespaces(void **state)
{
    struct test_ctx *test_ctx;
    struct ipadb_context *ipa_ctx;

    test_ctx = (struct test_ctx *) *state;
    ipa_ctx = ipadb_get_context(test_ctx->krb5_ctx);
    assert_non_null(ipa_ctx);

    check_overlapping_namespaces(test_ctx->krb5_ctx);
    reverse_trusts(ipa_ctx);
    check_overlapping_namespaces(test_ctx->krb5_ctx);
}

static void check_nested_namespaces(krb5_context krb5_ctx)
{
    /* a complete match at every level */
    assert_resolves_to(krb5_ctx, "TEST", "A.TEST");
    assert_resolves_to(krb5_ctx, "A.TEST", "A.TEST");
    assert_resolves_to(krb5_ctx, "B.A.TEST", "B.A.TEST");
    assert_resolves_to(krb5_ctx, "C.B.A.TEST", "C.B.A.TEST");
    assert_resolves_to(krb5_ctx, "D.TEST", "D.TEST");
    assert_resolves_to(krb5_ctx, "BB.A.TEST", "BB.A.TEST");

    /* one level below each of them, the longest match has to win */
    assert_resolves_to(krb5_ctx, "X.TEST", "A.TEST");
    assert_resolves_to(krb5_ctx, "X.A.TEST", "A.TEST");
    assert_resolves_to(krb5_ctx, "X.B.A.TEST", "B.A.TEST");
    assert_resolves_to(krb5_ctx, "X.C.B.A.TEST", "C.B.A.TEST");
    assert_resolves_to(krb5_ctx, "X.D.TEST", "D.TEST");

    /* two and three levels below the deepest realm */
    assert_resolves_to(krb5_ctx, "Y.X.C.B.A.TEST", "C.B.A.TEST");
    assert_resolves_to(krb5_ctx, "Z.Y.X.C.B.A.TEST", "C.B.A.TEST");

    /* a UPN suffix longer than any realm wins, and the realm of the trust
     * owning it is returned rather than the suffix */
    assert_resolves_to(krb5_ctx, "DEEP.C.B.A.TEST", "D.TEST");
    assert_resolves_to(krb5_ctx, "X.DEEP.C.B.A.TEST", "D.TEST");

    /* a UPN suffix of a trust high up beats the realm of a trust further down,
     * so realms and suffixes compete by match length alone */
    assert_resolves_to(krb5_ctx, "DEEPER.C.B.A.TEST", "B.A.TEST");
    assert_resolves_to(krb5_ctx, "Z.DEEPER.C.B.A.TEST", "B.A.TEST");

    /* the dot boundary decides: bb.a.test is not below b.a.test, and neither
     * is a name below bb.a.test */
    assert_resolves_to(krb5_ctx, "X.BB.A.TEST", "BB.A.TEST");

    /* a NetBIOS name matches completely or not at all */
    assert_resolves_to(krb5_ctx, "BB", "BB.A.TEST");
    assert_resolves_to(krb5_ctx, "A", "A.TEST");
    assert_resolves_to_nothing(krb5_ctx, "X.BB");
    assert_resolves_to_nothing(krb5_ctx, "X.A");

    /* a name cut short of a trusted domain's name is no match */
    assert_resolves_to_nothing(krb5_ctx, "B.A.TES");
    assert_resolves_to_nothing(krb5_ctx, "C.B.A.TES");
    assert_resolves_to_nothing(krb5_ctx, "DEEP.C.B.A.TES");

    assert_resolves_to_nothing(krb5_ctx, EXTERNAL_REALM);
}

static void test_check_trusted_realms_nested_namespaces(void **state)
{
    struct test_ctx *test_ctx;
    struct ipadb_context *ipa_ctx;

    test_ctx = (struct test_ctx *) *state;
    ipa_ctx = ipadb_get_context(test_ctx->krb5_ctx);
    assert_non_null(ipa_ctx);

    check_nested_namespaces(test_ctx->krb5_ctx);
    reverse_trusts(ipa_ctx);
    check_nested_namespaces(test_ctx->krb5_ctx);
}

int main(int argc, const char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_authz_data_types,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_filter_logon_info,
                                        setup, teardown),
        cmocka_unit_test(test_ipadb_string_to_sid),
        cmocka_unit_test_setup_teardown(test_dom_sid_string,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_check_trusted_realms,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(
                              test_check_trusted_realms_overlapping_namespaces,
                              setup_overlapping_trusts, teardown),
        cmocka_unit_test_setup_teardown(
                                   test_check_trusted_realms_nested_namespaces,
                                   setup_nested_trusts, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
