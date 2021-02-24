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
#define BLACKLIST_SID "S-1-5-1"

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

    ipa_ctx->mspac = calloc(1, sizeof(struct ipadb_mspac));
    assert_non_null(ipa_ctx->mspac);

    /* make sure data is not read from LDAP */
    ipa_ctx->mspac->last_update = time(NULL) - 1;

    ret = string_to_sid(DOM_SID, &ipa_ctx->mspac->domsid);
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

    ret = string_to_sid(DOM_SID_TRUST, &ipa_ctx->mspac->trusts[0].domsid);
    assert_int_equal(ret, 0);

    ipa_ctx->mspac->trusts[0].len_sid_blacklist_incoming = 1;
    ipa_ctx->mspac->trusts[0].sid_blacklist_incoming = calloc(
                           ipa_ctx->mspac->trusts[0].len_sid_blacklist_incoming,
                           sizeof(struct dom_sid));
    assert_non_null(ipa_ctx->mspac->trusts[0].sid_blacklist_incoming);
    ret = string_to_sid(BLACKLIST_SID,
                        &ipa_ctx->mspac->trusts[0].sid_blacklist_incoming[0]);
    assert_int_equal(ret, 0);

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
                                  krb5_data realm,
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

    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, realm, info);
    assert_int_equal(kerr, EINVAL);

    info->info->info3.base.logon_domain.string = talloc_strdup(info->info,
                                                               FLAT_NAME);
    assert_non_null(info->info->info3.base.logon_domain.string);

    /* missing domain SID */
    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, realm, info);
    assert_int_equal(kerr, EINVAL);

    /* wrong domain SID */
    ret = string_to_sid("S-1-5-21-1-1-1", &dom_sid);
    assert_int_equal(ret, 0);
    info->info->info3.base.domain_sid = &dom_sid;

    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, realm, info);
    assert_int_equal(kerr, EINVAL);

    /* matching domain SID */
    ret = string_to_sid(DOM_SID_TRUST, &dom_sid);
    assert_int_equal(ret, 0);
    info->info->info3.base.domain_sid = &dom_sid;

    kerr = filter_logon_info(test_ctx->krb5_ctx, test_ctx, realm, info);
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

    kerr = filter_logon_info(test_ctx->krb5_ctx, NULL, realm, info);
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
        {3, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1001", BLACKLIST_SID"-1002"},
         2, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1001"}},
        /* center SID filtered */
        {3, {DOM_SID_TRUST"-1000", BLACKLIST_SID"-1001", DOM_SID_TRUST"-1002"},
         2, {DOM_SID_TRUST"-1000", DOM_SID_TRUST"-1002"}},
        /* first SID filtered */
        {3, {BLACKLIST_SID"-1000", DOM_SID_TRUST"-1001", DOM_SID_TRUST"-1002"},
         2, {DOM_SID_TRUST"-1001", DOM_SID_TRUST"-1002"}},
        /* first and last SID filtered */
        {3, {BLACKLIST_SID"-1000", DOM_SID_TRUST"-1001", BLACKLIST_SID"-1002"},
         1, {DOM_SID_TRUST"-1001"}},
        /* two SIDs in a rwo filtered */
        {3, {BLACKLIST_SID"-1000", BLACKLIST_SID"-1001", DOM_SID_TRUST"-1002"},
         1, {DOM_SID_TRUST"-1002"}},
        /* all SIDs filtered*/
        {3, {BLACKLIST_SID"-1000", BLACKLIST_SID"-1001", BLACKLIST_SID"-1002"},
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
            ret = string_to_sid(test_data[c].sids[d],
                                info->info->info3.sids[d].sid);
            assert_int_equal(ret, 0);
        }

        kerr = filter_logon_info(test_ctx->krb5_ctx, NULL, realm, info);
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

static void test_string_to_sid(void **state)
{
    int ret;
    struct dom_sid sid;
    struct dom_sid exp_sid = {1, 5, {0, 0, 0, 0, 0, 5},
                              {21, 2127521184, 1604012920, 1887927527, 72713,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

    ret = string_to_sid(NULL, &sid);
    assert_int_equal(ret, EINVAL);

    ret = string_to_sid("abc", &sid);
    assert_int_equal(ret, EINVAL);

    ret = string_to_sid("S-", &sid);
    assert_int_equal(ret, EINVAL);

    ret = string_to_sid("S-ABC", &sid);
    assert_int_equal(ret, EINVAL);

    ret = string_to_sid("S-123", &sid);
    assert_int_equal(ret, EINVAL);

    ret = string_to_sid("S-1-123-1-2-3-4-5-6-7-8-9-0-1-2-3-4-5-6", &sid);
    assert_int_equal(ret, EINVAL);

    ret = string_to_sid("S-1-5-21-2127521184-1604012920-1887927527-72713",
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


int main(int argc, const char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_authz_data_types,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_filter_logon_info,
                                        setup, teardown),
        cmocka_unit_test(test_string_to_sid),
        cmocka_unit_test_setup_teardown(test_dom_sid_string,
                                        setup, teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
