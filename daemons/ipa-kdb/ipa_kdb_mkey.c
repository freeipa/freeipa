/*
 * MIT Kerberos KDC database backend for FreeIPA
 *
 * Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011  Simo Sorce, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
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
 */

#include "ipa_kdb.h"

static char *krbmkey_attrs[] = {
    "krbMKey",
    NULL
};

krb5_error_code ipadb_fetch_master_key(krb5_context kcontext,
                                       krb5_principal mname,
                                       krb5_keyblock *key,
                                       krb5_kvno *kvno,
                                       char *db_args)
{
    struct ipadb_context *ipactx;
    LDAPMessage *res = NULL;
    LDAPMessage *first;
    struct berval **vals = NULL;
    BerElement *be = NULL;
    krb5_error_code kerr;
    krb5_keyblock k;
    int mkvno;
    int ret;
    int i;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    if (!ipactx->lcontext) {
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }
    }

    be = ber_alloc_t(LBER_USE_DER);
    if (!be) {
        kerr = ENOMEM;
        goto done;
    }

    kerr = ipadb_simple_search(ipactx, ipactx->realm_base, LDAP_SCOPE_BASE,
                               "(krbMKey=*)", krbmkey_attrs, &res);
    if (kerr) {
        goto done;
    }

    first = ldap_first_entry(ipactx->lcontext, res);
    if (!first) {
        kerr = KRB5_KDB_NOENTRY;
        goto done;
    }

    mkvno = 0;
    k.contents = NULL;
    vals = ldap_get_values_len(ipactx->lcontext, first, "krbmkey");
    for (i = 0; vals[i]; i++) {
        struct berval *mkey;
        ber_tag_t tag;
        ber_int_t tvno;
        ber_int_t ttype;

        ber_init2(be, vals[i], LBER_USE_DER);

        tag = ber_scanf(be, "{i{iO}}", &tvno, &ttype, &mkey);
        if (tag == LBER_ERROR) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }

        if (tvno > mkvno) {
            mkvno = tvno;
            k.enctype = ttype;
            k.length = mkey->bv_len;
            if (k.contents) {
                free(k.contents);
            }
            k.contents = malloc(k.length);
            if (!k.contents) {
                kerr = ENOMEM;
                goto done;
            }
            memcpy(k.contents, mkey->bv_val, k.length);
        }
        ber_bvfree(mkey);
    }

    if (mkvno == 0) {
        kerr = KRB5_KDB_NOENTRY;
        goto done;
    }

    *kvno = mkvno;
    key->magic = KV5M_KEYBLOCK;
    key->enctype = k.enctype;
    key->length = k.length;
    key->contents = k.contents;

    kerr = 0;

done:
    if (be) {
        ber_free(be, 0);
    }
    ldap_value_free_len(vals);
    ldap_msgfree(res);
    return kerr;
}

krb5_error_code ipadb_store_master_key_list(krb5_context kcontext,
                                            char *db_arg,
                                            krb5_principal mname,
                                            krb5_keylist_node *keylist,
                                            char *master_pwd)
{
    struct ipadb_context *ipactx;
    BerElement *be = NULL;
    krb5_keyblock k = { 0, 0, 0, NULL };
    struct berval mkey;
    ber_int_t tvno;
    ber_int_t ttype;
    LDAPMod **mods = NULL;
    krb5_error_code kerr;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    /* we support storing only one key for now */
    if (!keylist || keylist->next) {
        return EINVAL;
    }

    if (!ipactx->lcontext) {
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }
    }

    be = ber_alloc_t(LBER_USE_DER);
    if (!be) {
        kerr = ENOMEM;
        goto done;
    }


    tvno = keylist->kvno;
    ttype = keylist->keyblock.enctype;
    mkey.bv_len = keylist->keyblock.length;
    mkey.bv_val = (void *)keylist->keyblock.contents;

    ret = ber_printf(be, "{i{iO}}", tvno, ttype, &mkey);
    if (ret == -1) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    mods = calloc(2, sizeof(LDAPMod *));
    if (!mods) {
        kerr = ENOMEM;
        goto done;
    }
    mods[0] = calloc(1, sizeof(LDAPMod));
    if (!mods[0]) {
        kerr = ENOMEM;
        goto done;
    }
    mods[0]->mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
    mods[0]->mod_type = strdup("krbMKey");
    if (!mods[0]->mod_type) {
        kerr = ENOMEM;
        goto done;
    }
    mods[0]->mod_bvalues = calloc(2, sizeof(struct berval *));
    if (!mods[0]->mod_bvalues) {
        kerr = ENOMEM;
        goto done;
    }

    ret = ber_flatten(be, &mods[0]->mod_bvalues[0]);
    if (ret == -1) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_simple_modify(ipactx, ipactx->realm_base, mods);

    kerr = 0;

done:
    if (be) {
        ber_free(be, 1);
    }
    krb5_free_keyblock_contents(kcontext, &k);
    ldap_mods_free(mods, 1);
    return kerr;
}
