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
#include "ipa_kdb_mspac_trusts.h"

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

    /* Build the trust index for fast lookups */
    ret = ipadb_trust_index_build(ipa_ctx->mspac->trusts,
                                  ipa_ctx->mspac->num_trusts,
                                  &ipa_ctx->mspac->trust_idx);
    assert_int_equal(ret, 0);
    assert_non_null(ipa_ctx->mspac->trust_idx);

    ipa_ctx->kcontext = krb5_ctx;
    kerr = krb5_db_set_context(krb5_ctx, ipa_ctx);
    assert_int_equal(kerr, 0);

    test_ctx = talloc(NULL, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->krb5_ctx = krb5_ctx;

    *state = test_ctx;

    return 0;
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
}

static void test_check_transited_realms(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *) *state;
    krb5_error_code kerr;
    krb5_data empty_transited = {KV5M_DATA, 0, ""};
    krb5_data our_realm = {KV5M_DATA, strlen("EXAMPLE.COM"), "EXAMPLE.COM"};
    krb5_data trusted_domain = {KV5M_DATA, strlen(DOMAIN_NAME), DOMAIN_NAME};
    krb5_data unknown_realm = {KV5M_DATA, strlen(EXTERNAL_REALM), EXTERNAL_REALM};
    krb5_data short_realm = {KV5M_DATA, 2, "EX"};

    /* Direct trust: our own realm on both sides with an empty transited
     * path is allowed without consulting trust data. */
    kerr = ipadb_check_transited_realms(test_ctx->krb5_ctx, &empty_transited,
                                        &our_realm, &our_realm);
    assert_int_equal(kerr, 0);

    /* Cross-realm via a trusted domain that also appears in the
     * transited path. */
    kerr = ipadb_check_transited_realms(test_ctx->krb5_ctx, &trusted_domain,
                                        &trusted_domain, &our_realm);
    assert_int_equal(kerr, 0);

    /* A short realm that is a case-insensitive prefix of our own realm
     * must not be treated as if it were our own realm (regression test
     * for a missing length check). */
    kerr = ipadb_check_transited_realms(test_ctx->krb5_ctx, &empty_transited,
                                        &short_realm, &our_realm);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);

    /* Completely unrelated realm never matches. */
    kerr = ipadb_check_transited_realms(test_ctx->krb5_ctx, &unknown_realm,
                                        &unknown_realm, &our_realm);
    assert_int_equal(kerr, KRB5_PLUGIN_NO_HANDLE);
}

/* ------------------------------------------------------------------ */
/* Trust index tests                                                   */
/* ------------------------------------------------------------------ */

#define CHILD_DOMAIN_NAME "child." DOMAIN_NAME
#define CHILD_FLAT_NAME   "CHILD"
#define CHILD_DOM_SID     "S-1-5-21-7-8-9"
#define SECOND_DOMAIN_NAME "second.test"
#define SECOND_FLAT_NAME   "SECOND"
#define SECOND_DOM_SID     "S-1-5-21-10-11-12"

/* A standalone setup/teardown that builds a richer trust topology
 * without needing krb5 context (the index is independent of Kerberos). */

struct trust_index_ctx {
    struct ipadb_adtrusts *trusts;
    size_t num_trusts;
    struct ipadb_trust_index *idx;
};

static int trust_index_setup(void **state)
{
    struct trust_index_ctx *ctx;
    struct ipadb_adtrusts *t;
    int ret;

    ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);

    /* 3 trusts: root domain, child domain, and an unrelated second domain */
    ctx->num_trusts = 3;
    ctx->trusts = calloc(ctx->num_trusts, sizeof(struct ipadb_adtrusts));
    assert_non_null(ctx->trusts);

    /* trust 0: root domain with UPN suffixes */
    t = &ctx->trusts[0];
    t->domain_name = strdup(DOMAIN_NAME);
    t->flat_name = strdup(FLAT_NAME);
    t->domain_sid = strdup(DOM_SID_TRUST);
    ret = ipadb_string_to_sid(DOM_SID_TRUST, &t->domsid);
    assert_int_equal(ret, 0);
    t->upn_suffixes = calloc(3, sizeof(char *));
    assert_non_null(t->upn_suffixes);
    t->upn_suffixes[0] = strdup("upn1." DOMAIN_NAME);
    t->upn_suffixes[1] = strdup("upn2." DOMAIN_NAME);
    t->upn_suffixes[2] = NULL;
    t->upn_suffixes_len = calloc(2, sizeof(size_t));
    assert_non_null(t->upn_suffixes_len);
    t->upn_suffixes_len[0] = strlen(t->upn_suffixes[0]);
    t->upn_suffixes_len[1] = strlen(t->upn_suffixes[1]);
    t->parent_name = NULL;

    /* trust 1: child domain (parent = root) */
    t = &ctx->trusts[1];
    t->domain_name = strdup(CHILD_DOMAIN_NAME);
    t->flat_name = strdup(CHILD_FLAT_NAME);
    t->domain_sid = strdup(CHILD_DOM_SID);
    ret = ipadb_string_to_sid(CHILD_DOM_SID, &t->domsid);
    assert_int_equal(ret, 0);
    t->parent_name = strdup(DOMAIN_NAME);
    t->parent = &ctx->trusts[0];

    /* trust 2: unrelated domain */
    t = &ctx->trusts[2];
    t->domain_name = strdup(SECOND_DOMAIN_NAME);
    t->flat_name = strdup(SECOND_FLAT_NAME);
    t->domain_sid = strdup(SECOND_DOM_SID);
    ret = ipadb_string_to_sid(SECOND_DOM_SID, &t->domsid);
    assert_int_equal(ret, 0);

    /* Build index */
    ret = ipadb_trust_index_build(ctx->trusts, ctx->num_trusts, &ctx->idx);
    assert_int_equal(ret, 0);
    assert_non_null(ctx->idx);

    *state = ctx;
    return 0;
}

static int trust_index_teardown(void **state)
{
    struct trust_index_ctx *ctx = *state;
    size_t i, j;

    ipadb_trust_index_free(&ctx->idx);
    assert_null(ctx->idx);

    for (i = 0; i < ctx->num_trusts; i++) {
        free(ctx->trusts[i].domain_name);
        free(ctx->trusts[i].flat_name);
        free(ctx->trusts[i].domain_sid);
        free(ctx->trusts[i].parent_name);
        if (ctx->trusts[i].upn_suffixes) {
            for (j = 0; ctx->trusts[i].upn_suffixes[j]; j++)
                free(ctx->trusts[i].upn_suffixes[j]);
            free(ctx->trusts[i].upn_suffixes);
            free(ctx->trusts[i].upn_suffixes_len);
        }
    }
    free(ctx->trusts);
    free(ctx);
    return 0;
}

/* -- Exact domain name lookup -- */
static void test_trust_index_find_by_domain(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;

    /* Exact match */
    found = ipadb_trust_find_by_domain(ctx->idx,
                                       DOMAIN_NAME, strlen(DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* Case-insensitive */
    found = ipadb_trust_find_by_domain(ctx->idx, "MY.DOMAIN", 9);
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* Child domain */
    found = ipadb_trust_find_by_domain(ctx->idx,
                                       CHILD_DOMAIN_NAME,
                                       strlen(CHILD_DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, CHILD_DOMAIN_NAME);

    /* Second domain */
    found = ipadb_trust_find_by_domain(ctx->idx,
                                       SECOND_DOMAIN_NAME,
                                       strlen(SECOND_DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, SECOND_DOMAIN_NAME);

    /* Non-existent */
    found = ipadb_trust_find_by_domain(ctx->idx,
                                       "no.such.domain",
                                       strlen("no.such.domain"));
    assert_null(found);

    /* NULL index */
    found = ipadb_trust_find_by_domain(NULL, DOMAIN_NAME, strlen(DOMAIN_NAME));
    assert_null(found);

    /* Empty name */
    found = ipadb_trust_find_by_domain(ctx->idx, "", 0);
    assert_null(found);

    /* NULL name */
    found = ipadb_trust_find_by_domain(ctx->idx, NULL, 5);
    assert_null(found);
}

/* -- Exact flat/NetBIOS name lookup -- */
static void test_trust_index_find_by_flat(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;

    found = ipadb_trust_find_by_flat(ctx->idx, FLAT_NAME, strlen(FLAT_NAME));
    assert_non_null(found);
    assert_string_equal(found->flat_name, FLAT_NAME);

    /* Case-insensitive */
    found = ipadb_trust_find_by_flat(ctx->idx, "mydom", 5);
    assert_non_null(found);
    assert_string_equal(found->flat_name, FLAT_NAME);

    found = ipadb_trust_find_by_flat(ctx->idx,
                                     CHILD_FLAT_NAME,
                                     strlen(CHILD_FLAT_NAME));
    assert_non_null(found);
    assert_string_equal(found->flat_name, CHILD_FLAT_NAME);

    found = ipadb_trust_find_by_flat(ctx->idx,
                                     SECOND_FLAT_NAME,
                                     strlen(SECOND_FLAT_NAME));
    assert_non_null(found);
    assert_string_equal(found->flat_name, SECOND_FLAT_NAME);

    /* Non-existent */
    found = ipadb_trust_find_by_flat(ctx->idx, "NOPE", 4);
    assert_null(found);
}

/* -- Exact UPN suffix lookup -- */
static void test_trust_index_find_by_upn(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;

    found = ipadb_trust_find_by_upn(ctx->idx,
                                    "upn1." DOMAIN_NAME,
                                    strlen("upn1." DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    found = ipadb_trust_find_by_upn(ctx->idx,
                                    "upn2." DOMAIN_NAME,
                                    strlen("upn2." DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* Case-insensitive */
    found = ipadb_trust_find_by_upn(ctx->idx,
                                    "UPN1.MY.DOMAIN",
                                    strlen("UPN1.MY.DOMAIN"));
    assert_non_null(found);

    /* Non-existent UPN suffix */
    found = ipadb_trust_find_by_upn(ctx->idx,
                                    "upn99." DOMAIN_NAME,
                                    strlen("upn99." DOMAIN_NAME));
    assert_null(found);

    /* Domain with no UPN suffixes */
    found = ipadb_trust_find_by_upn(ctx->idx,
                                    CHILD_DOMAIN_NAME,
                                    strlen(CHILD_DOMAIN_NAME));
    assert_null(found);
}

/* -- Exact SID string lookup -- */
static void test_trust_index_find_by_sid(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;

    found = ipadb_trust_find_by_sid(ctx->idx, DOM_SID_TRUST);
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    found = ipadb_trust_find_by_sid(ctx->idx, CHILD_DOM_SID);
    assert_non_null(found);
    assert_string_equal(found->domain_name, CHILD_DOMAIN_NAME);

    found = ipadb_trust_find_by_sid(ctx->idx, SECOND_DOM_SID);
    assert_non_null(found);
    assert_string_equal(found->domain_name, SECOND_DOMAIN_NAME);

    /* Non-existent SID */
    found = ipadb_trust_find_by_sid(ctx->idx, "S-1-5-21-99-99-99");
    assert_null(found);

    /* NULL */
    found = ipadb_trust_find_by_sid(ctx->idx, NULL);
    assert_null(found);

    found = ipadb_trust_find_by_sid(NULL, DOM_SID_TRUST);
    assert_null(found);
}

/* -- Combined lookup (ipadb_trust_find_by_name) -- */
static void test_trust_index_find_by_name(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;

    /* 1. Exact domain name */
    found = ipadb_trust_find_by_name(ctx->idx,
                                     DOMAIN_NAME, strlen(DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* 2. Suffix match on domain name:
     *    "sub.child.my.domain" should match "child.my.domain" */
    found = ipadb_trust_find_by_name(ctx->idx,
                                     "sub." CHILD_DOMAIN_NAME,
                                     strlen("sub." CHILD_DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, CHILD_DOMAIN_NAME);

    /* 3. Flat name */
    found = ipadb_trust_find_by_name(ctx->idx,
                                     FLAT_NAME, strlen(FLAT_NAME));
    assert_non_null(found);
    assert_string_equal(found->flat_name, FLAT_NAME);

    /* 4. Exact UPN suffix */
    found = ipadb_trust_find_by_name(ctx->idx,
                                     "upn1." DOMAIN_NAME,
                                     strlen("upn1." DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* 5. Suffix match on UPN suffix:
     *    "host.upn2.my.domain" should match UPN suffix "upn2.my.domain" */
    found = ipadb_trust_find_by_name(ctx->idx,
                                     "host.upn2." DOMAIN_NAME,
                                     strlen("host.upn2." DOMAIN_NAME));
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* 6. Case-insensitive combined */
    found = ipadb_trust_find_by_name(ctx->idx, "SECOND.TEST",
                                     strlen("SECOND.TEST"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, SECOND_DOMAIN_NAME);

    /* 7. No match at all */
    found = ipadb_trust_find_by_name(ctx->idx,
                                     "completely.unknown.realm",
                                     strlen("completely.unknown.realm"));
    assert_null(found);

    /* 8. NULL / empty edge cases */
    found = ipadb_trust_find_by_name(NULL, DOMAIN_NAME, strlen(DOMAIN_NAME));
    assert_null(found);
    found = ipadb_trust_find_by_name(ctx->idx, NULL, 5);
    assert_null(found);
    found = ipadb_trust_find_by_name(ctx->idx, "", 0);
    assert_null(found);
}

/* -- Cross-type name collision: a domain-exact match must win over a
 * UPN-exact match on another trust, regardless of array order -- */
static void test_trust_index_find_by_name_priority(void **state)
{
    struct ipadb_trust_index *idx = NULL;
    struct ipadb_adtrusts trusts[2];
    struct ipadb_adtrusts *found;
    int ret;

    (void)state;

    memset(trusts, 0, sizeof(trusts));

    /* trust 0 comes first in array order and has a UPN suffix that
     * collides with trust 1's domain name. */
    trusts[0].domain_name = strdup("other.test");
    assert_non_null(trusts[0].domain_name);
    trusts[0].upn_suffixes = calloc(2, sizeof(char *));
    assert_non_null(trusts[0].upn_suffixes);
    trusts[0].upn_suffixes[0] = strdup("priority.test");
    assert_non_null(trusts[0].upn_suffixes[0]);
    trusts[0].upn_suffixes_len = calloc(1, sizeof(size_t));
    assert_non_null(trusts[0].upn_suffixes_len);
    trusts[0].upn_suffixes_len[0] = strlen(trusts[0].upn_suffixes[0]);

    /* trust 1 is the "real" owner of the "priority.test" domain name. */
    trusts[1].domain_name = strdup("priority.test");
    assert_non_null(trusts[1].domain_name);

    ret = ipadb_trust_index_build(trusts, 2, &idx);
    assert_int_equal(ret, 0);
    assert_non_null(idx);

    /* Even though trust 0 (a UPN-exact match) is earlier in array
     * order, the domain-exact match on trust 1 must win. */
    found = ipadb_trust_find_by_name(idx, "priority.test",
                                     strlen("priority.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "priority.test");

    /* "other.test" still resolves via its own domain name. */
    found = ipadb_trust_find_by_name(idx, "other.test", strlen("other.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "other.test");

    ipadb_trust_index_free(&idx);
    free(trusts[0].domain_name);
    free(trusts[0].upn_suffixes[0]);
    free(trusts[0].upn_suffixes);
    free(trusts[0].upn_suffixes_len);
    free(trusts[1].domain_name);
}

/* -- A deep UPN suffix must not lose to a shorter, coincidental
 * domain-name suffix match against an unrelated ancestor domain -- */
static void test_trust_index_find_by_name_deep_upn_suffix(void **state)
{
    struct ipadb_trust_index *idx = NULL;
    struct ipadb_adtrusts trusts[5];
    struct ipadb_adtrusts *found;
    int ret;
    size_t i;

    static const struct {
        const char *domain_name;
        const char *flat_name;
        const char *domain_sid;
        const char *upn_suffix;
    } defs[] = {
        { "a.test",     "A",  "S-1-5-21-21-1-1", NULL },
        { "b.a.test",   "B",  "S-1-5-21-21-2-2", "deeper.c.b.a.test" },
        { "c.b.a.test", "C",  "S-1-5-21-21-3-3", NULL },
        { "d.test",     "D",  "S-1-5-21-21-4-4", "deep.c.b.a.test" },
        { "bb.a.test",  "BB", "S-1-5-21-21-5-5", NULL },
    };

    (void)state;

    memset(trusts, 0, sizeof(trusts));
    for (i = 0; i < 5; i++) {
        trusts[i].domain_name = strdup(defs[i].domain_name);
        assert_non_null(trusts[i].domain_name);
        trusts[i].flat_name = strdup(defs[i].flat_name);
        assert_non_null(trusts[i].flat_name);
        trusts[i].domain_sid = strdup(defs[i].domain_sid);
        assert_non_null(trusts[i].domain_sid);
        ret = ipadb_string_to_sid(defs[i].domain_sid, &trusts[i].domsid);
        assert_int_equal(ret, 0);

        if (defs[i].upn_suffix) {
            trusts[i].upn_suffixes = calloc(2, sizeof(char *));
            assert_non_null(trusts[i].upn_suffixes);
            trusts[i].upn_suffixes[0] = strdup(defs[i].upn_suffix);
            assert_non_null(trusts[i].upn_suffixes[0]);
            trusts[i].upn_suffixes_len = calloc(1, sizeof(size_t));
            assert_non_null(trusts[i].upn_suffixes_len);
            trusts[i].upn_suffixes_len[0] = strlen(trusts[i].upn_suffixes[0]);
        }
    }

    ret = ipadb_trust_index_build(trusts, 5, &idx);
    assert_int_equal(ret, 0);
    assert_non_null(idx);

    /* "deep.c.b.a.test" is an exact UPN suffix configured on D; it
     * must resolve to D, not to C via a domain-name suffix match. */
    found = ipadb_trust_find_by_name(idx, "deep.c.b.a.test",
                                     strlen("deep.c.b.a.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "d.test");

    /* Likewise for B's UPN suffix. */
    found = ipadb_trust_find_by_name(idx, "deeper.c.b.a.test",
                                     strlen("deeper.c.b.a.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "b.a.test");

    /* No exact match anywhere: falls back to the longest suffix match
     * across domain names and UPN suffixes together, not whichever
     * kind happens to be scanned first. */
    found = ipadb_trust_find_by_name(idx, "sub.deep.c.b.a.test",
                                     strlen("sub.deep.c.b.a.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "d.test");

    /* A genuine subdomain of c.b.a.test with no UPN suffix involved
     * still resolves via the ordinary domain-suffix fallback. */
    found = ipadb_trust_find_by_name(idx, "host.c.b.a.test",
                                     strlen("host.c.b.a.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "c.b.a.test");

    ipadb_trust_index_free(&idx);
    for (i = 0; i < 5; i++) {
        free(trusts[i].domain_name);
        free(trusts[i].flat_name);
        free(trusts[i].domain_sid);
        if (trusts[i].upn_suffixes) {
            free(trusts[i].upn_suffixes[0]);
            free(trusts[i].upn_suffixes);
            free(trusts[i].upn_suffixes_len);
        }
    }
}

/* -- An exclusion cancels a suffix (subdomain) match on the exact
 * excluded name, but not on a subdomain of that excluded name, and
 * not on unrelated names -- exact-match-only semantics matching
 * Samba's check_ft_info(). -- */
static void test_trust_index_find_by_name_tln_exclusion(void **state)
{
    struct ipadb_trust_index *idx = NULL;
    struct ipadb_adtrusts trusts[5];
    struct ipadb_adtrusts *found;
    int ret;
    size_t i;

    static const struct {
        const char *domain_name;
        const char *flat_name;
        const char *domain_sid;
    } defs[] = {
        { "a.test",     "A",  "S-1-5-21-21-1-1" },
        { "b.a.test",   "B",  "S-1-5-21-21-2-2" },
        { "c.b.a.test", "C",  "S-1-5-21-21-3-3" },
        { "d.test",     "D",  "S-1-5-21-21-4-4" },
        { "bb.a.test",  "BB", "S-1-5-21-21-5-5" },
    };

    (void)state;

    memset(trusts, 0, sizeof(trusts));
    for (i = 0; i < 5; i++) {
        trusts[i].domain_name = strdup(defs[i].domain_name);
        assert_non_null(trusts[i].domain_name);
        trusts[i].flat_name = strdup(defs[i].flat_name);
        assert_non_null(trusts[i].flat_name);
        trusts[i].domain_sid = strdup(defs[i].domain_sid);
        assert_non_null(trusts[i].domain_sid);
        ret = ipadb_string_to_sid(defs[i].domain_sid, &trusts[i].domsid);
        assert_int_equal(ret, 0);
    }

    /* Register an exclusion for "foo.c.b.a.test" on trust "d.test" --
     * which trust holds the exclusion doesn't matter for matching. */
    trusts[3].exclusions = calloc(2, sizeof(char *));
    assert_non_null(trusts[3].exclusions);
    trusts[3].exclusions[0] = strdup("foo.c.b.a.test");
    assert_non_null(trusts[3].exclusions[0]);
    trusts[3].exclusions_len = calloc(1, sizeof(size_t));
    assert_non_null(trusts[3].exclusions_len);
    trusts[3].exclusions_len[0] = strlen(trusts[3].exclusions[0]);

    ret = ipadb_trust_index_build(trusts, 5, &idx);
    assert_int_equal(ret, 0);
    assert_non_null(idx);

    /* Without the exclusion, "foo.c.b.a.test" would fall back to the
     * domain-suffix match on "c.b.a.test". With it, it must resolve
     * to no trust at all. */
    found = ipadb_trust_find_by_name(idx, "foo.c.b.a.test",
                                     strlen("foo.c.b.a.test"));
    assert_null(found);

    /* A sibling name that is NOT excluded still resolves normally. */
    found = ipadb_trust_find_by_name(idx, "bar.c.b.a.test",
                                     strlen("bar.c.b.a.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "c.b.a.test");

    /* The exclusion is exact-match only: a SUBDOMAIN of the excluded
     * name is not covered by it and still resolves via the ordinary
     * domain-suffix fallback. */
    found = ipadb_trust_find_by_name(idx, "sub.foo.c.b.a.test",
                                     strlen("sub.foo.c.b.a.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "c.b.a.test");

    ipadb_trust_index_free(&idx);
    for (i = 0; i < 5; i++) {
        free(trusts[i].domain_name);
        free(trusts[i].flat_name);
        free(trusts[i].domain_sid);
    }
    free(trusts[3].exclusions[0]);
    free(trusts[3].exclusions);
    free(trusts[3].exclusions_len);
}

/* -- A trust that contributes many index entries (several UPN suffixes,
 * a flat name, a SID) must still have its exclusion list honored, and
 * an unrelated trust's exclusion must not leak into the wrong lookup --
 * exercises is_excluded()'s per-trust dedup path. -- */
static void test_trust_index_find_by_name_tln_exclusion_many_suffixes(
    void **state)
{
    struct ipadb_trust_index *idx = NULL;
    struct ipadb_adtrusts trusts[2];
    struct ipadb_adtrusts *found;
    int ret;
    size_t i;

    (void)state;

    memset(trusts, 0, sizeof(trusts));

    /* trust 0: many UPN suffixes, one of them excluded. */
    trusts[0].domain_name = strdup("d.test");
    assert_non_null(trusts[0].domain_name);
    trusts[0].flat_name = strdup("D");
    assert_non_null(trusts[0].flat_name);
    trusts[0].domain_sid = strdup("S-1-5-21-21-4-4");
    assert_non_null(trusts[0].domain_sid);
    ret = ipadb_string_to_sid(trusts[0].domain_sid, &trusts[0].domsid);
    assert_int_equal(ret, 0);

    trusts[0].upn_suffixes = calloc(4, sizeof(char *));
    assert_non_null(trusts[0].upn_suffixes);
    trusts[0].upn_suffixes[0] = strdup("suffix1.test");
    trusts[0].upn_suffixes[1] = strdup("suffix2.test");
    trusts[0].upn_suffixes[2] = strdup("suffix3.test");
    for (i = 0; i < 3; i++)
        assert_non_null(trusts[0].upn_suffixes[i]);
    trusts[0].upn_suffixes_len = calloc(3, sizeof(size_t));
    assert_non_null(trusts[0].upn_suffixes_len);
    for (i = 0; i < 3; i++)
        trusts[0].upn_suffixes_len[i] = strlen(trusts[0].upn_suffixes[i]);

    trusts[0].exclusions = calloc(2, sizeof(char *));
    assert_non_null(trusts[0].exclusions);
    trusts[0].exclusions[0] = strdup("excluded.other.test");
    assert_non_null(trusts[0].exclusions[0]);
    trusts[0].exclusions_len = calloc(1, sizeof(size_t));
    assert_non_null(trusts[0].exclusions_len);
    trusts[0].exclusions_len[0] = strlen(trusts[0].exclusions[0]);

    /* trust 1: unrelated, holds the domain "other.test" that the
     * exclusion above targets a subdomain of. */
    trusts[1].domain_name = strdup("other.test");
    assert_non_null(trusts[1].domain_name);

    ret = ipadb_trust_index_build(trusts, 2, &idx);
    assert_int_equal(ret, 0);
    assert_non_null(idx);

    /* The excluded name must resolve to no trust, even though trust 0
     * contributes 6 index entries (domain, flat, SID, 3 UPN suffixes)
     * that all have to be deduplicated down to a single exclusion-list
     * scan for this to work correctly. */
    found = ipadb_trust_find_by_name(idx, "excluded.other.test",
                                     strlen("excluded.other.test"));
    assert_null(found);

    /* A sibling of the excluded name still resolves normally. */
    found = ipadb_trust_find_by_name(idx, "sibling.other.test",
                                     strlen("sibling.other.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "other.test");

    /* Every UPN suffix on the many-entries trust still resolves. */
    found = ipadb_trust_find_by_name(idx, "suffix1.test",
                                     strlen("suffix1.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "d.test");
    found = ipadb_trust_find_by_name(idx, "suffix3.test",
                                     strlen("suffix3.test"));
    assert_non_null(found);
    assert_string_equal(found->domain_name, "d.test");

    ipadb_trust_index_free(&idx);
    free(trusts[0].domain_name);
    free(trusts[0].flat_name);
    free(trusts[0].domain_sid);
    for (i = 0; i < 3; i++)
        free(trusts[0].upn_suffixes[i]);
    free(trusts[0].upn_suffixes);
    free(trusts[0].upn_suffixes_len);
    free(trusts[0].exclusions[0]);
    free(trusts[0].exclusions);
    free(trusts[0].exclusions_len);
    free(trusts[1].domain_name);
}

/* -- Binary dom_sid exact lookup -- */
static void test_trust_index_find_by_domsid(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;
    struct dom_sid sid;
    int ret;

    /* Match root domain */
    ret = ipadb_string_to_sid(DOM_SID_TRUST, &sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_domsid(ctx->idx, &sid);
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* Match child domain */
    ret = ipadb_string_to_sid(CHILD_DOM_SID, &sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_domsid(ctx->idx, &sid);
    assert_non_null(found);
    assert_string_equal(found->domain_name, CHILD_DOMAIN_NAME);

    /* Match second domain */
    ret = ipadb_string_to_sid(SECOND_DOM_SID, &sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_domsid(ctx->idx, &sid);
    assert_non_null(found);
    assert_string_equal(found->domain_name, SECOND_DOMAIN_NAME);

    /* User SID (domain + RID) should NOT match -- exact only */
    ret = ipadb_string_to_sid(DOM_SID_TRUST "-1000", &sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_domsid(ctx->idx, &sid);
    assert_null(found);

    /* Unknown SID */
    ret = ipadb_string_to_sid("S-1-5-21-99-99-99", &sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_domsid(ctx->idx, &sid);
    assert_null(found);

    /* NULL inputs */
    found = ipadb_trust_find_by_domsid(NULL, &sid);
    assert_null(found);
    found = ipadb_trust_find_by_domsid(ctx->idx, NULL);
    assert_null(found);
}

/* -- SID prefix lookup (indexed) -- */
static void test_trust_index_find_by_sid_prefix(void **state)
{
    struct trust_index_ctx *ctx = *state;
    struct ipadb_adtrusts *found;
    struct dom_sid user_sid;
    int ret;

    /* User SID = domain SID + RID -> should find the domain */
    ret = ipadb_string_to_sid(DOM_SID_TRUST "-1000", &user_sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_sid_prefix(ctx->idx, &user_sid);
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* User SID from child domain */
    ret = ipadb_string_to_sid(CHILD_DOM_SID "-500", &user_sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_sid_prefix(ctx->idx, &user_sid);
    assert_non_null(found);
    assert_string_equal(found->domain_name, CHILD_DOMAIN_NAME);

    /* Domain SID itself (no RID) -> exact match still found */
    ret = ipadb_string_to_sid(DOM_SID_TRUST, &user_sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_sid_prefix(ctx->idx, &user_sid);
    assert_non_null(found);
    assert_string_equal(found->domain_name, DOMAIN_NAME);

    /* SID nested more than one RID deep must NOT match */
    ret = ipadb_string_to_sid(DOM_SID_TRUST "-1000-1", &user_sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_sid_prefix(ctx->idx, &user_sid);
    assert_null(found);

    /* Completely unknown SID */
    ret = ipadb_string_to_sid("S-1-5-21-99-99-99-500", &user_sid);
    assert_int_equal(ret, 0);
    found = ipadb_trust_find_by_sid_prefix(ctx->idx, &user_sid);
    assert_null(found);

    /* NULL inputs */
    found = ipadb_trust_find_by_sid_prefix(NULL, &user_sid);
    assert_null(found);
    found = ipadb_trust_find_by_sid_prefix(ctx->idx, NULL);
    assert_null(found);
}

/* -- Build/free edge cases -- */
static void test_trust_index_build_empty(void **state)
{
    struct ipadb_trust_index *idx = NULL;
    int ret;

    (void)state;

    /* Zero trusts */
    ret = ipadb_trust_index_build(NULL, 0, &idx);
    assert_int_equal(ret, 0);
    assert_null(idx);  /* nothing to index */

    /* NULL output pointer */
    ret = ipadb_trust_index_build(NULL, 0, NULL);
    assert_int_equal(ret, EINVAL);

    /* Free NULL is safe */
    ipadb_trust_index_free(NULL);
    idx = NULL;
    ipadb_trust_index_free(&idx);
}

/* -- Build with minimal trust (domain_name only, no flat/sid/upn) -- */
static void test_trust_index_build_minimal(void **state)
{
    struct ipadb_trust_index *idx = NULL;
    struct ipadb_adtrusts t;
    struct ipadb_adtrusts *found;
    int ret;

    (void)state;

    memset(&t, 0, sizeof(t));
    t.domain_name = strdup("minimal.test");
    assert_non_null(t.domain_name);
    /* flat_name, domain_sid, upn_suffixes all NULL */

    ret = ipadb_trust_index_build(&t, 1, &idx);
    assert_int_equal(ret, 0);
    assert_non_null(idx);

    /* Can find by domain name */
    found = ipadb_trust_find_by_domain(idx, "minimal.test",
                                       strlen("minimal.test"));
    assert_non_null(found);
    assert_ptr_equal(found, &t);

    /* Other lookups return NULL since fields are missing */
    found = ipadb_trust_find_by_flat(idx, "MINIMAL", 7);
    assert_null(found);
    found = ipadb_trust_find_by_sid(idx, "S-1-5-21-0-0-0");
    assert_null(found);

    ipadb_trust_index_free(&idx);
    free(t.domain_name);
}

/* -- Verify the index agrees with ipadb_is_princ_from_trusted_realm -- */
static void test_trust_index_integrated(void **state)
{
    struct test_ctx *test_ctx = *state;
    struct ipadb_context *ipa_ctx;
    krb5_error_code kerr;
    char *trusted_realm = NULL;

    ipa_ctx = ipadb_get_context(test_ctx->krb5_ctx);
    assert_non_null(ipa_ctx);
    assert_non_null(ipa_ctx->mspac);
    assert_non_null(ipa_ctx->mspac->trust_idx);

    /* Domain name match */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               DOMAIN_NAME, strlen(DOMAIN_NAME),
               &trusted_realm);
    assert_int_equal(kerr, 0);
    assert_non_null(trusted_realm);
    /* DOMAIN_NAME uppercased */
    assert_string_equal(trusted_realm, "MY.DOMAIN");
    free(trusted_realm);
    trusted_realm = NULL;

    /* Flat name match */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               FLAT_NAME, strlen(FLAT_NAME),
               &trusted_realm);
    assert_int_equal(kerr, 0);
    assert_non_null(trusted_realm);
    assert_string_equal(trusted_realm, "MY.DOMAIN");
    free(trusted_realm);
    trusted_realm = NULL;

    /* UPN suffix match (from setup's SUFFIX_TEMPLATE) */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               "d0" DOMAIN_NAME, strlen("d0" DOMAIN_NAME),
               &trusted_realm);
    assert_int_equal(kerr, 0);
    assert_non_null(trusted_realm);
    assert_string_equal(trusted_realm, "MY.DOMAIN");
    free(trusted_realm);
    trusted_realm = NULL;

    /* Suffix match: "some.d0my.domain" ends with UPN suffix "d0my.domain" */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               "some.d0" DOMAIN_NAME, strlen("some.d0" DOMAIN_NAME),
               &trusted_realm);
    assert_int_equal(kerr, 0);
    assert_non_null(trusted_realm);
    assert_string_equal(trusted_realm, "MY.DOMAIN");
    free(trusted_realm);
    trusted_realm = NULL;

    /* Own realm should not match */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               "EXAMPLE.COM", strlen("EXAMPLE.COM"),
               &trusted_realm);
    assert_int_equal(kerr, KRB5_KDB_NOENTRY);

    /* Unknown realm */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx,
               EXTERNAL_REALM, strlen(EXTERNAL_REALM),
               &trusted_realm);
    assert_int_equal(kerr, KRB5_KDB_NOENTRY);

    /* NULL / empty */
    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx, NULL, 0, &trusted_realm);
    assert_int_equal(kerr, KRB5_KDB_NOENTRY);

    kerr = ipadb_is_princ_from_trusted_realm(
               test_ctx->krb5_ctx, "", 0, &trusted_realm);
    assert_int_equal(kerr, KRB5_KDB_NOENTRY);
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
        cmocka_unit_test_setup_teardown(test_check_transited_realms,
                                        setup, teardown),
        /* Trust index unit tests (standalone, no krb5 context needed) */
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_domain,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_flat,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_upn,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_sid,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_name,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test(test_trust_index_find_by_name_priority),
        cmocka_unit_test(test_trust_index_find_by_name_deep_upn_suffix),
        cmocka_unit_test(test_trust_index_find_by_name_tln_exclusion),
        cmocka_unit_test(
            test_trust_index_find_by_name_tln_exclusion_many_suffixes),
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_domsid,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test_setup_teardown(test_trust_index_find_by_sid_prefix,
                                        trust_index_setup,
                                        trust_index_teardown),
        cmocka_unit_test(test_trust_index_build_empty),
        cmocka_unit_test(test_trust_index_build_minimal),
        /* Integration test: index used via ipadb_is_princ_from_trusted_realm */
        cmocka_unit_test_setup_teardown(test_trust_index_integrated,
                                        setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
