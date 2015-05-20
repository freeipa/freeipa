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
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ipa-kdb/ipa_kdb.h"

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

extern void get_authz_data_types(krb5_context context, krb5_db_entry *entry,
                                 bool *with_pac, bool *with_pad);

void test_get_authz_data_types(void **state)
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
    krb5_context krb5_ctx;
    krb5_error_code kerr;
    struct ipadb_context *ipa_ctx;
    krb5_principal nfs_princ;
    krb5_principal non_nfs_princ;

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

    kerr = krb5_init_context(&krb5_ctx);
    assert_int_equal(kerr, 0);
    kerr = krb5_db_setup_lib_handle(krb5_ctx);
    assert_int_equal(kerr, 0);
    ipa_ctx = calloc(1, sizeof(struct ipadb_context));
    assert_non_null(ipa_ctx);
    ipa_ctx->kcontext = krb5_ctx;
    kerr = krb5_db_set_context(krb5_ctx, ipa_ctx);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(krb5_ctx, NFS_PRINC_STRING, &nfs_princ);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(krb5_ctx, NON_NFS_PRINC_STRING, &non_nfs_princ);
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
        get_authz_data_types(krb5_ctx, entry, &with_pac, &with_pad);
        assert_true(with_pad == test_set[c].exp_with_pad);
        assert_true(with_pac == test_set[c].exp_with_pac);
    }

    krb5_free_principal(krb5_ctx, nfs_princ);
    krb5_free_principal(krb5_ctx, non_nfs_princ);
    krb5_db_fini(krb5_ctx);
    krb5_free_context(krb5_ctx);
}

int main(int argc, const char *argv[])
{
    const UnitTest tests[] = {
        unit_test(test_get_authz_data_types),
    };

    return run_tests(tests);
}
