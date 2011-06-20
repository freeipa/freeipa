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

#define PRINC_SEARCH_FILTER "(&(|(objectclass=krbprincipalaux)" \
                                "(objectclass=krbprincipal))" \
                              "(krbprincipalname=%s))"

static char *std_principal_attrs[] = {
    "krbPrincipalName",
    "krbCanonicalName",
    "krbUPEnabled",
    "krbPrincipalKey",
    "krbTicketPolicyReference",
    "krbPrincipalExpiration",
    "krbPasswordExpiration",
    "krbPwdPolicyReference",
    "krbPrincipalType",
    "krbPwdHistory",
    "krbLastPwdChange",
    "krbPrincipalAliases",
    "krbLastSuccessfulAuth",
    "krbLastFailedAuth",
    "krbLoginFailedCount",
    "krbExtraData",
    "krbLastAdminUnlock",
    "krbObjectReferences",
    "krbTicketFlags",
    "krbMaxTicketLife",
    "krbMaxRenewableAge",

    "nsaccountlock",

    NULL
};

static char *std_tktpolicy_attrs[] = {
    "krbmaxticketlife",
    "krbmaxrenewableage",
    "krbticketflags",

    NULL
};

#define TKTFLAGS_BIT        0x01
#define MAXTKTLIFE_BIT      0x02
#define MAXRENEWABLEAGE_BIT 0x04

static char *std_principal_obj_classes[] = {
    "krbprincipal",
    "krbprincipalaux",
    "krbTicketPolicyAux",

    NULL
};

#define STD_PRINCIPAL_OBJ_CLASSES_SIZE (sizeof(std_principal_obj_classes) / sizeof(char *) - 1)

static int ipadb_ldap_attr_to_tl_data(LDAP *lcontext, LDAPMessage *le,
                                      char *attrname,
                                      krb5_tl_data **result, int *num)
{
    struct berval **vals;
    krb5_tl_data *prev, *next;
    krb5_int16 be_type;
    int i;
    int ret = ENOENT;

    *result = NULL;
    prev = NULL;
    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        for (i = 0; vals[i]; i++) {
            next = calloc(1, sizeof(krb5_tl_data));
            if (!next) {
                ret = ENOMEM;
                goto done;
            }

            /* fill tl_data struct with the data */
            memcpy(&be_type, vals[i]->bv_val, 2);
            next->tl_data_type = ntohs(be_type);
            next->tl_data_length = vals[i]->bv_len - 2;
            next->tl_data_contents = malloc(next->tl_data_length);
            if (!next->tl_data_contents) {
                ret = ENOMEM;
                goto done;
            }
            memcpy(next->tl_data_contents,
                   vals[i]->bv_val + 2,
                   next->tl_data_length);

            if (prev) {
                prev->tl_data_next = next;
            } else {
                *result = next;
            }
            prev = next;
        }
        *num = i;
        ret = 0;

        ldap_value_free_len(vals);
    }

done:
    if (ret) {
        if (*result) {
            prev = *result;
            while (prev) {
                next = prev->tl_data_next;
                free(prev);
                prev = next;
            }
        }
        *result = NULL;
        *num = 0;
    }
    return ret;
}

static krb5_error_code ipadb_set_tl_data(krb5_db_entry *entry,
                                         krb5_int16 type,
                                         krb5_ui_2 length,
                                         krb5_octet *data)
{
    krb5_error_code kerr;
    krb5_tl_data *new_td = NULL;
    krb5_tl_data *td;

    for (td = entry->tl_data; td; td = td->tl_data_next) {
        if (td->tl_data_type == type) {
            break;
        }
    }
    if (!td) {
        /* an existing entry was not found, make new */
        new_td = malloc(sizeof(krb5_tl_data));
        if (!new_td) {
            kerr = ENOMEM;
            goto done;
        }
        td = new_td;
        td->tl_data_next = entry->tl_data;
        td->tl_data_type = type;
        entry->tl_data = td;
        entry->n_tl_data++;
    }
    td->tl_data_length = length;
    td->tl_data_contents = malloc(td->tl_data_length);
    if (!td->tl_data_contents) {
        kerr = ENOMEM;
        goto done;
    }
    memcpy(td->tl_data_contents, data, td->tl_data_length);

    new_td = NULL;
    kerr = 0;

done:
    free(new_td);
    return kerr;
}

static int ipadb_ldap_attr_to_key_data(LDAP *lcontext, LDAPMessage *le,
                                       char *attrname,
                                       krb5_key_data **result, int *num,
                                       krb5_kvno *res_mkvno)
{
    struct berval **vals;
    krb5_key_data *keys = NULL;
    BerElement *be = NULL;
    void *tmp;
    int i = 0;
    int ret = ENOENT;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (vals) {
        ber_tag_t tag;
        ber_int_t major_vno;
        ber_int_t minor_vno;
        ber_int_t kvno;
        ber_int_t mkvno;
        ber_int_t type;
        ber_tag_t seqtag;
        ber_len_t seqlen;
        ber_len_t setlen;
        ber_tag_t retag;
        ber_tag_t opttag;
        struct berval tval;

        be = ber_alloc_t(LBER_USE_DER);
        if (!be) {
            return ENOMEM;
        }

        /* reinit the ber element with the new val */
        ber_init2(be, vals[0], LBER_USE_DER);

        /* fill key_data struct with the data */
        retag = ber_scanf(be, "{t[i]t[i]t[i]t[i]t[{",
                          &tag, &major_vno,
                          &tag, &minor_vno,
                          &tag, &kvno,
                          &tag, &mkvno,
                          &seqtag);
        if (retag == LBER_ERROR ||
                major_vno != 1 ||
                minor_vno != 1 ||
                seqtag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 4)) {
            ret = EINVAL;
            goto done;
        }

        retag = ber_skip_tag(be, &seqlen);

        /* sequence of keys */
        for (i = 0; retag == LBER_SEQUENCE; i++) {

            tmp = realloc(keys, (i + 1) * sizeof(krb5_key_data));
            if (!tmp) {
                ret = ENOMEM;
                goto done;
            }
            keys = tmp;

            memset(&keys[i], 0, sizeof(krb5_key_data));

            keys[i].key_data_kvno = kvno;

            /* do we have a salt type ? (optional) */
            retag = ber_scanf(be, "t", &opttag);
            if (retag == LBER_ERROR) {
                ret = EINVAL;
                goto done;
            }
            if (opttag == (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0)) {
                keys[i].key_data_ver = 2;

                retag = ber_scanf(be, "[l{tl[i]",
                                  &seqlen, &tag, &setlen, &type);
                if (tag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0)) {
                    ret = EINVAL;
                    goto done;
                }
                keys[i].key_data_type[1] = type;

                /* do we have salt data ? (optional) */
                if (seqlen > setlen + 2) {
                    retag = ber_scanf(be, "t[o]", &tag, &tval);
                    if (retag == LBER_ERROR ||
                        tag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {
                        ret = EINVAL;
                        goto done;
                    }
                    keys[i].key_data_length[1] = tval.bv_len;
                    keys[i].key_data_contents[1] = (krb5_octet *)tval.bv_val;
                }

                retag = ber_scanf(be, "}]t", &opttag);
                if (retag == LBER_ERROR) {
                    ret = EINVAL;
                    goto done;
                }

            } else {
                keys[i].key_data_ver = 1;
            }

            if (opttag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {
                ret = EINVAL;
                goto done;
            }

            /* get the key */
            retag = ber_scanf(be, "[{t[i]t[o]}]", &tag, &type, &tag, &tval);
            if (retag == LBER_ERROR) {
                ret = EINVAL;
                goto done;
            }
            keys[i].key_data_type[0] = type;
            keys[i].key_data_length[0] = tval.bv_len;
            keys[i].key_data_contents[0] = (krb5_octet *)tval.bv_val;

            /* check for sk2params */
            retag = ber_peek_tag(be, &setlen);
            if (retag == (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2)) {
                /* not supported yet, skip */
                retag = ber_scanf(be, "t[x]}");
            } else {
                retag = ber_scanf(be, "}");
            }
            if (retag == LBER_ERROR) {
                ret = EINVAL;
                goto done;
            }

            retag = ber_skip_tag(be, &seqlen);
        }
        *result = keys;
        *num = i;
        *res_mkvno = mkvno;
        ret = 0;
    }

done:
    ber_free(be, 0); /* internal buffer is 'vals[0]' */
    ldap_value_free_len(vals);
    if (ret) {
        for (i -= 1; keys && i >= 0; i--) {
            free(keys[i].key_data_contents[0]);
            free(keys[i].key_data_contents[1]);
        }
        *result = NULL;
        *num = 0;
    }
    return ret;
}

static krb5_error_code ipadb_parse_ldap_entry(krb5_context kcontext,
                                              char *principal,
                                              LDAPMessage *lentry,
                                              krb5_db_entry **kentry,
                                              uint32_t *polmask)
{
    LDAP *lcontext;
    krb5_db_entry *entry;
    krb5_error_code kerr;
    krb5_tl_data *res_tl_data;
    krb5_key_data *res_key_data;
    krb5_kvno mkvno = 0;
    char *restring;
    time_t restime;
    bool resbool;
    int result;
    int ret;

    *polmask = 0;
    entry = calloc(1, sizeof(krb5_db_entry));
    if (!entry) {
        return ENOMEM;
    }

    /* proceed to fill in attributes in the order they are defined in
     * krb5_db_entry in kdb.h */
    lcontext = (ipadb_get_context(kcontext))->lcontext;

    entry->magic = KRB5_KDB_MAGIC_NUMBER;
    entry->len = KRB5_KDB_V1_BASE_LENGTH;

    /* ignore mask for now */

    ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                 "krbTicketFlags", &result);
    if (ret == 0) {
        entry->attributes = result;
    } else {
        *polmask |= TKTFLAGS_BIT;
    }

    ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                 "krbMaxTicketLife", &result);
    if (ret == 0) {
        entry->max_life = result;
    } else {
        *polmask |= MAXTKTLIFE_BIT;
    }

    ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                 "krbMaxRenewableAge", &result);
    if (ret == 0) {
        entry->max_renewable_life = result;
    } else {
        *polmask |= MAXRENEWABLEAGE_BIT;
    }

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbPrincipalexpiration", &restime);
    switch (ret) {
    case 0:
        entry->expiration = restime;
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbPasswordExpiration", &restime);
    switch (ret) {
    case 0:
        entry->pw_expiration = restime;
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbLastSuccessfulAuth", &restime);
    switch (ret) {
    case 0:
        entry->last_success = restime;
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbLastFailedAuth", &restime);
    switch (ret) {
    case 0:
        entry->last_failed = restime;
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                 "krbLoginFailedCount", &result);
    if (ret == 0) {
        entry->fail_auth_count = result;
    }

    /* TODO: e_length, e_data */

    if (principal) {
        kerr = krb5_parse_name(kcontext, principal, &entry->princ);
        if (kerr != 0) {
            goto done;
        }
    } else {
        /* see if canonical name is available */
        ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                     "krbCanonicalName", &restring);
        switch (ret) {
        case ENOENT:
            /* if not pick the first principal name in the entry */
            ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                         "krbPrincipalName", &restring);
            if (ret != 0) {
                kerr = KRB5_KDB_INTERNAL_ERROR;
                goto done;
            }
        case 0:
            break;
        default:
            kerr = KRB5_KDB_INTERNAL_ERROR;
            goto done;
        }
        kerr = krb5_parse_name(kcontext, restring, &entry->princ);
        free(restring);
        if (kerr != 0) {
            goto done;
        }
    }

    ret = ipadb_ldap_attr_to_tl_data(lcontext, lentry,
                                     "krbExtraData", &res_tl_data, &result);
    switch (ret) {
    case 0:
        entry->tl_data = res_tl_data;
        entry->n_tl_data = result;
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_key_data(lcontext, lentry,
                                      "krbPrincipalKey",
                                      &res_key_data, &result, &mkvno);
    switch (ret) {
    case 0:
        entry->key_data = res_key_data;
        entry->n_key_data = result;
        if (mkvno) {
            krb5_int16 kvno16le = htole16((krb5_int16)mkvno);

            kerr = ipadb_set_tl_data(entry, KRB5_TL_MKVNO,
                                     sizeof(kvno16le),
                                     (krb5_octet *)&kvno16le);
            if (kerr) {
                goto done;
            }
        }
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_bool(lcontext, lentry,
                                  "nsAccountLock", &resbool);
    if ((ret == 0 && resbool == true) || (ret != 0 && ret != ENOENT)) {
        entry->attributes |= KRB5_KDB_DISALLOW_ALL_TIX;
    }

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbLastPwdChange", &restime);
    if (ret == 0) {
        krb5_int32 time32le = htole32((krb5_int32)restime);

        kerr = ipadb_set_tl_data(entry,
                                 KRB5_TL_LAST_PWD_CHANGE,
                                 sizeof(time32le),
                                 (krb5_octet *)&time32le);
        if (kerr) {
            goto done;
        }
    }

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbLastAdminUnlock", &restime);
    if (ret == 0) {
        krb5_int32 time32le = htole32((krb5_int32)restime);

        kerr = ipadb_set_tl_data(entry,
                                 KRB5_TL_LAST_ADMIN_UNLOCK,
                                 sizeof(time32le),
                                 (krb5_octet *)&time32le);
        if (kerr) {
            goto done;
        }
    }

    /* FIXME: fetch and se policy via krbpwdpolicyreference or fallback */

    kerr = 0;

done:
    if (kerr) {
        ipadb_free_principal(kcontext, entry);
        entry = NULL;
    }
    *kentry = entry;
    return kerr;
}

static krb5_error_code ipadb_fetch_principals(struct ipadb_context *ipactx,
                                              char *search_expr,
                                              LDAPMessage **result)
{
    krb5_error_code kerr;
    char *src_filter = NULL;
    char *esc_search_expr = NULL;
    int ret;

    if (!ipactx->lcontext) {
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }
    }

    /* escape filter but do not touch '*' as this function accepts
     * wildcards in names */
    esc_search_expr = ipadb_filter_escape(search_expr, false);
    if (!esc_search_expr) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = asprintf(&src_filter, PRINC_SEARCH_FILTER, esc_search_expr);
    if (ret == -1) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_simple_search(ipactx,
                               ipactx->base, LDAP_SCOPE_SUBTREE,
                               src_filter, std_principal_attrs,
                               result);

done:
    free(src_filter);
    free(esc_search_expr);
    return kerr;
}

static krb5_error_code ipadb_find_principal(krb5_context kcontext,
                                            unsigned int flags,
                                            LDAPMessage *res,
                                            char **principal,
                                            LDAPMessage **entry)
{
    struct ipadb_context *ipactx;
    bool found = false;
    LDAPMessage *le = NULL;
    struct berval **vals;
    int i;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    while (!found) {

        if (!le) {
            le = ldap_first_entry(ipactx->lcontext, res);
        } else {
            le = ldap_next_entry(ipactx->lcontext, le);
        }
        if (!le) {
            break;
        }

        vals = ldap_get_values_len(ipactx->lcontext, le, "krbprincipalname");
        if (vals == NULL) {
            continue;
        }

        /* we need to check for a strict match as a '*' in the name may have
         * caused the ldap server to return multiple entries */
        for (i = 0; vals[i]; i++) {
            /* FIXME: use case insensitive compare and tree as alias ?? */
            if (strcmp(vals[i]->bv_val, (*principal)) == 0) {
                found = true;
            }
        }

        ldap_value_free_len(vals);

        if (!found) {
            continue;
        }

        /* we need to check if this is the canonical name */
        vals = ldap_get_values_len(ipactx->lcontext, le, "krbcanonicalname");
        if (vals == NULL) {
            continue;
        }

        /* FIXME: use case insensitive compare and treat as alias ?? */
        if (strcmp(vals[0]->bv_val, (*principal)) != 0 &&
                !(flags & KRB5_KDB_FLAG_ALIAS_OK)) {
            /* search does not allow aliases */
            found = false;
            ldap_value_free_len(vals);
            continue;
        }

        free(*principal);
        *principal = strdup(vals[0]->bv_val);
        if (!(*principal)) {
            return KRB5_KDB_INTERNAL_ERROR;
        }

        ldap_value_free_len(vals);
    }

    if (!found || !le) {
        return KRB5_KDB_NOENTRY;
    }

    *entry = le;
    return 0;
}

static krb5_error_code ipadb_fetch_tktpolicy(krb5_context kcontext,
                                             LDAPMessage *lentry,
                                             krb5_db_entry *entry,
                                             uint32_t polmask)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *policy_dn = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *first;
    int result;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "krbticketpolicyreference", &policy_dn);
    switch (ret) {
    case 0:
        break;
    case ENOENT:
        ret = asprintf(&policy_dn, "cn=%s,cn=kerberos,%s",
                                   ipactx->realm, ipactx->base);
        if (ret == -1) {
            kerr = ENOMEM;
            goto done;
        }
        break;
    default:
        kerr = ret;
        goto done;
    }

    kerr = ipadb_simple_search(ipactx,
                               policy_dn, LDAP_SCOPE_BASE,
                               "(objectclass=krbticketpolicyaux)",
                               std_tktpolicy_attrs,
                               &res);
    if (kerr == 0) {
        first = ldap_first_entry(ipactx->lcontext, res);
        if (!first) {
            kerr = KRB5_KDB_NOENTRY;
        } else {
            if (polmask & MAXTKTLIFE_BIT) {
                ret = ipadb_ldap_attr_to_int(ipactx->lcontext, first,
                                             "krbmaxticketlife", &result);
                if (ret == 0) {
                    entry->max_life = result;
                } else {
                    entry->max_life = 86400;
                }
            }
            if (polmask & MAXRENEWABLEAGE_BIT) {
                ret = ipadb_ldap_attr_to_int(ipactx->lcontext, first,
                                             "krbmaxrenewableage", &result);
                if (ret == 0) {
                    entry->max_renewable_life = result;
                } else {
                    entry->max_renewable_life = 604800;
                }
            }
            if (polmask & TKTFLAGS_BIT) {
                ret = ipadb_ldap_attr_to_int(ipactx->lcontext, first,
                                             "krbticketflags", &result);
                if (ret == 0) {
                    entry->attributes |= result;
                } else {
                    entry->attributes |= KRB5_KDB_REQUIRES_PRE_AUTH;
                }
            }
        }
    }

    if (kerr == KRB5_KDB_NOENTRY) {
        /* No policy at all ??
         * set hardcoded default policy for now */
        if (polmask & MAXTKTLIFE_BIT) {
            entry->max_life = 86400;
        }
        if (polmask & MAXRENEWABLEAGE_BIT) {
            entry->max_renewable_life = 604800;
        }
        if (polmask & TKTFLAGS_BIT) {
            entry->attributes |= KRB5_KDB_REQUIRES_PRE_AUTH;
        }

        kerr = 0;
    }

done:
    ldap_msgfree(res);
    free(policy_dn);
    return kerr;
}

/* TODO: handle case where main object and krbprincipal data are not
 * the same object but linked objects ?
 * (by way of krbprincipalaux being in a separate object from krbprincipal).
 * Currently we only support objcts with both objectclasses present at the
 * same time. */

krb5_error_code ipadb_get_principal(krb5_context kcontext,
                                    krb5_const_principal search_for,
                                    unsigned int flags,
                                    krb5_db_entry **entry)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *principal = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    uint32_t pol;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    kerr = krb5_unparse_name(kcontext, search_for, &principal);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_fetch_principals(ipactx, principal, &res);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_find_principal(kcontext, flags, res, &principal, &lentry);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_parse_ldap_entry(kcontext, principal, lentry, entry, &pol);
    if (kerr != 0) {
        goto done;
    }

    if (pol) {
        kerr = ipadb_fetch_tktpolicy(kcontext, lentry, *entry, pol);
        if (kerr != 0) {
            goto done;
        }
    }

done:
    ldap_msgfree(res);
    krb5_free_unparsed_name(kcontext, principal);
    return kerr;
}

void ipadb_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    krb5_tl_data *prev, *next;

    if (entry) {
        free(entry->e_data);
        krb5_free_principal(kcontext, entry->princ);
        prev = entry->tl_data;
        while(prev) {
            next = prev->tl_data_next;
            free(prev->tl_data_contents);
            free(prev);
            prev = next;
        }
        ipa_krb5_free_key_data(entry->key_data, entry->n_key_data);
        free(entry);
    }
}

static krb5_error_code ipadb_get_tl_data(krb5_db_entry *entry,
                                         krb5_int16 type,
                                         krb5_ui_2 length,
                                         krb5_octet *data)
{
    krb5_tl_data *td;

    for (td = entry->tl_data; td; td = td->tl_data_next) {
        if (td->tl_data_type == type) {
            break;
        }
    }
    if (!td) {
        return ENOENT;
    }

    if (td->tl_data_length != length) {
        return EINVAL;
    }

    memcpy(data, td->tl_data_contents, length);

    return 0;
}

struct ipadb_mods {
    LDAPMod **mods;
    int alloc_size;
    int tip;
};

static int new_ipadb_mods(struct ipadb_mods **imods)
{
    struct ipadb_mods *r;

    r = malloc(sizeof(struct ipadb_mods));
    if (!r) {
        return ENOMEM;
    }

    /* alloc the average space for a full change of all ldap attrinbutes */
    r->alloc_size = 15;
    r->mods = calloc(r->alloc_size, sizeof(LDAPMod *));
    if (!r->mods) {
        free(r);
        return ENOMEM;
    }
    r->tip = 0;

    *imods = r;
    return 0;
}

static void ipadb_mods_free(struct ipadb_mods *imods)
{
    if (imods == NULL) {
        return;
    }

    ldap_mods_free(imods->mods, 1);
    free(imods);
}

static krb5_error_code ipadb_mods_new(struct ipadb_mods *imods,
                                      LDAPMod **slot)
{
    LDAPMod **lmods = NULL;
    LDAPMod *m;
    int n;

    lmods = imods->mods;
    for (n = imods->tip; n < imods->alloc_size && lmods[n] != NULL; n++) {
        /* find empty slot */ ;
    }

    if (n + 1 > imods->alloc_size) {
        /* need to increase size */
        lmods = realloc(imods->mods, (n * 2) * sizeof(LDAPMod *));
        if (!lmods) {
            return ENOMEM;
        }
        imods->mods = lmods;
        imods->alloc_size = n * 2;
        memset(&lmods[n + 1], 0,
               (imods->alloc_size - n - 1) * sizeof(LDAPMod *));
    }

    m = calloc(1, sizeof(LDAPMod));
    if (!m) {
        return ENOMEM;
    }
    imods->tip = n;
    *slot = imods->mods[n] = m;
    return 0;
}

static void ipadb_mods_free_tip(struct ipadb_mods *imods)
{
    LDAPMod *m;
    int i;

    if (imods->alloc_size == 0) {
        return;
    }

    m = imods->mods[imods->tip];

    if (!m) {
        return;
    }

    free(m->mod_type);
    if (m->mod_values) {
        for (i = 0; m->mod_values[i]; i++) {
            free(m->mod_values[i]);
        }
    }
    free(m->mod_values);
    free(m);

    imods->mods[imods->tip] = NULL;
    imods->tip--;
}

static krb5_error_code ipadb_get_ldap_mod_str(struct ipadb_mods *imods,
                                              char *attribute, char *value,
                                              int mod_op)
{
    krb5_error_code kerr;
    LDAPMod *m = NULL;

    kerr = ipadb_mods_new(imods, &m);
    if (kerr) {
        return kerr;
    }

    m->mod_op = mod_op;
    m->mod_type = strdup(attribute);
    if (!m->mod_type) {
        kerr = ENOMEM;
        goto done;
    }
    m->mod_values = calloc(2, sizeof(char *));
    if (!m->mod_values) {
        kerr = ENOMEM;
        goto done;
    }
    m->mod_values[0] = strdup(value);
    if (!m->mod_values[0]) {
        kerr = ENOMEM;
        goto done;
    }

    kerr = 0;

done:
    if (kerr) {
        ipadb_mods_free_tip(imods);
    }
    return kerr;
}

static krb5_error_code ipadb_get_ldap_mod_int(struct ipadb_mods *imods,
                                              char *attribute, int value,
                                              int mod_op)
{
    krb5_error_code kerr;
    char *v = NULL;
    int ret;

    ret = asprintf(&v, "%d", value);
    if (ret == -1) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_get_ldap_mod_str(imods, attribute, v, mod_op);

done:
    free(v);
    return kerr;
}

static krb5_error_code ipadb_get_ldap_mod_time(struct ipadb_mods *imods,
                                               char *attribute,
                                               krb5_timestamp value,
                                               int mod_op)
{
    struct tm date, *t;
    time_t timeval;
    char v[20];

    timeval = (time_t)value;
    t = gmtime_r(&timeval, &date);
    if (t == NULL) {
        return EINVAL;
    }

    strftime(v, 20, "%Y%m%d%H%M%SZ", &date);

    return ipadb_get_ldap_mod_str(imods, attribute, v, mod_op);
}

static krb5_error_code ipadb_get_ldap_mod_bvalues(struct ipadb_mods *imods,
                                                  char *attribute,
                                                  struct berval **values,
                                                  int num_values,
                                                  int mod_op)
{
    krb5_error_code kerr;
    LDAPMod *m = NULL;
    int i;

    if (values == NULL || values[0] == NULL || num_values <= 0) {
        return EINVAL;
    }

    kerr = ipadb_mods_new(imods, &m);
    if (kerr) {
        return kerr;
    }

    m->mod_op = mod_op | LDAP_MOD_BVALUES;
    m->mod_type = strdup(attribute);
    if (!m->mod_type) {
        kerr = ENOMEM;
        goto done;
    }
    m->mod_bvalues = calloc(num_values + 1, sizeof(struct berval *));
    if (!m->mod_bvalues) {
        kerr = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_values; i++) {
        m->mod_bvalues[i] = values[i];
    }

    kerr = 0;

done:
    if (kerr) {
        /* we need to free bvalues manually here otherwise
         * ipadb_mods_free_tip will free contents which we
         * did not allocate here */
        free(m->mod_bvalues);
        m->mod_bvalues = NULL;
        ipadb_mods_free_tip(imods);
    }
    return kerr;
}

static krb5_error_code ipadb_get_ldap_mod_extra_data(struct ipadb_mods *imods,
                                                     krb5_tl_data *tl_data,
                                                     int mod_op)
{
    krb5_error_code kerr;
    krb5_tl_data *data;
    struct berval **bvs = NULL;
    krb5_int16 be_type;
    int n, i;

    for (n = 0, data = tl_data; data; data = data->tl_data_next) {
        if (data->tl_data_type == KRB5_TL_LAST_PWD_CHANGE ||
            data->tl_data_type == KRB5_TL_KADM_DATA ||
            data->tl_data_type == KRB5_TL_DB_ARGS ||
            data->tl_data_type == KRB5_TL_MKVNO ||
            data->tl_data_type == KRB5_TL_LAST_ADMIN_UNLOCK) {
            continue;
        }
        n++;
    }

    if (n == 0) {
        return ENOENT;
    }

    bvs = calloc(n + 1, sizeof(struct berval *));
    if (!bvs) {
        kerr = ENOMEM;
        goto done;
    }

    for (i = 0, data = tl_data; data; data = data->tl_data_next) {

        if (data->tl_data_type == KRB5_TL_LAST_PWD_CHANGE ||
            data->tl_data_type == KRB5_TL_KADM_DATA ||
            data->tl_data_type == KRB5_TL_DB_ARGS ||
            data->tl_data_type == KRB5_TL_MKVNO ||
            data->tl_data_type == KRB5_TL_LAST_ADMIN_UNLOCK) {
            continue;
        }

        be_type = htons(data->tl_data_type);

        bvs[i] = calloc(1, sizeof(struct berval));
        if (!bvs[i]) {
            kerr = ENOMEM;
            goto done;
        }

        bvs[i]->bv_len = data->tl_data_length + 2;
        bvs[i]->bv_val = malloc(bvs[i]->bv_len);
        if (!bvs[i]->bv_val) {
            kerr = ENOMEM;
            goto done;
        }
        memcpy(bvs[i]->bv_val, &be_type, 2);
        memcpy(&(bvs[i]->bv_val[2]), data->tl_data_contents, data->tl_data_length);

        i++;

        if (i > n) {
            kerr = KRB5_KDB_INTERNAL_ERROR;
            goto done;
        }
    }

    kerr = ipadb_get_ldap_mod_bvalues(imods, "krbExtraData", bvs, i, mod_op);

done:
    if (kerr) {
        for (i = 0; bvs && bvs[i]; i++) {
            free(bvs[i]->bv_val);
            free(bvs[i]);
        }
    }
    free(bvs);
    return kerr;
}

static krb5_error_code ipadb_get_mkvno_from_tl_data(krb5_tl_data *tl_data,
                                                    int *mkvno)
{
    krb5_tl_data *data;
    int master_kvno = 0;
    krb5_int16 tmp;

    for (data = tl_data; data; data = data->tl_data_next) {

        if (data->tl_data_type != KRB5_TL_MKVNO) {
            continue;
        }

        if (data->tl_data_length != 2) {
            return KRB5_KDB_TRUNCATED_RECORD;
        }

        memcpy(&tmp, data->tl_data_contents, 2);
        master_kvno = le16toh(tmp);

        break;
    }

    if (master_kvno == 0) {
        /* fall back to std mkvno of 1 */
        *mkvno = 1;
    } else {
        *mkvno = master_kvno;
    }

    return 0;
}

static krb5_error_code ipadb_get_ldap_mod_key_data(struct ipadb_mods *imods,
                                                   krb5_key_data *key_data,
                                                   int n_key_data, int mkvno,
                                                   int mod_op)
{
    krb5_error_code kerr;
    struct berval *bval = NULL;
    int ret;

    ret = ber_encode_krb5_key_data(key_data, n_key_data, mkvno, &bval);
    if (ret != 0) {
        kerr = ret;
        goto done;
    }

    kerr = ipadb_get_ldap_mod_bvalues(imods, "krbPrincipalKey",
                                      &bval, 1, mod_op);

done:
    if (kerr) {
        ber_bvfree(bval);
    }
    return kerr;
}

static krb5_error_code ipadb_entry_to_mods(struct ipadb_mods *imods,
                                           krb5_db_entry *entry,
                                           char *principal,
                                           int mod_op)
{
    krb5_error_code kerr;
    krb5_int32 time32le;
    int mkvno;

    /* check each mask flag in order */

    /* KADM5_PRINCIPAL */
    if (entry->mask & KMASK_PRINCIPAL) {
        kerr = ipadb_get_ldap_mod_str(imods, "krbPrincipalName",
                                      principal, mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_PRINC_EXPIRE_TIME */
    if (entry->mask & KMASK_PRINC_EXPIRE_TIME) {
        kerr = ipadb_get_ldap_mod_time(imods,
                                       "krbPrincipalExpiration",
                                       entry->expiration,
                                       mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_PW_EXPIRATION */
    if (entry->mask & KMASK_PW_EXPIRATION) {
        kerr = ipadb_get_ldap_mod_time(imods,
                                       "krbPasswordExpiration",
                                       entry->pw_expiration,
                                       mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_LAST_PWD_CHANGE */
    /* apparently, at least some versions of kadmin fail to set this flag
     * when they do include a pwd change timestamp in TL_DATA.
     * So for now always check for it regardless. */
#if KADM5_ACTUALLY_SETS_LAST_PWD_CHANGE
    if (entry->mask & KMASK_LAST_PWD_CHANGE) {
        if (!entry->n_tl_data) {
            kerr = EINVAL;
            goto done;
        }

#else
    if (entry->n_tl_data) {
#endif
        kerr = ipadb_get_tl_data(entry,
                                 KRB5_TL_LAST_PWD_CHANGE,
                                 sizeof(time32le),
                                 (krb5_octet *)&time32le);
        if (kerr && kerr != ENOENT) {
            goto done;
        }
        if (kerr == 0) {
            kerr = ipadb_get_ldap_mod_time(imods,
                                           "krbLastPwdChange",
                                           le32toh(time32le),
                                           mod_op);
            if (kerr) {
                goto done;
            }
        }
    }

    /* KADM5_ATTRIBUTES */
    if (entry->mask & KMASK_ATTRIBUTES) {
        kerr = ipadb_get_ldap_mod_int(imods,
                                      "krbTicketFlags",
                                      (int)entry->attributes,
                                      mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_MAX_LIFE */
    if (entry->mask & KMASK_MAX_LIFE) {
        kerr = ipadb_get_ldap_mod_int(imods,
                                      "krbMaxTicketLife",
                                      (int)entry->max_life,
                                      mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_MOD_TIME */
    /* KADM5_MOD_NAME */
    /* KADM5_KVNO */
    /* KADM5_MKVNO */
    /* KADM5_AUX_ATTRIBUTES */
    /* KADM5_POLICY */
    /* KADM5_POLICY_CLR */

    /* version 2 masks */
    /* KADM5_MAX_RLIFE */
    if (entry->mask & KMASK_MAX_RLIFE) {
        kerr = ipadb_get_ldap_mod_int(imods,
                                      "krbMaxRenewableAge",
                                      (int)entry->max_renewable_life,
                                      mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_LAST_SUCCESS */
    if (entry->mask & KMASK_LAST_SUCCESS) {
        kerr = ipadb_get_ldap_mod_time(imods,
                                       "krbLastSuccessfulAuth",
                                       entry->last_success,
                                       mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_LAST_FAILED */
    if (entry->mask & KMASK_LAST_FAILED) {
        kerr = ipadb_get_ldap_mod_time(imods,
                                       "krbLastFailedAuth",
                                       entry->last_failed,
                                       mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_FAIL_AUTH_COUNT */
    if (entry->mask & KMASK_FAIL_AUTH_COUNT) {
        kerr = ipadb_get_ldap_mod_int(imods,
                                      "krbLoginFailedCount",
                                      (int)entry->fail_auth_count,
                                      mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_KEY_DATA */
    if (entry->mask & KMASK_KEY_DATA) {
        /* TODO: password changes should go via change_pwd
         * then we can get clear text and set all needed
         * LDAP attributes */

        kerr = ipadb_get_mkvno_from_tl_data(entry->tl_data, &mkvno);
        if (kerr) {
            goto done;
        }

        kerr = ipadb_get_ldap_mod_key_data(imods,
                                           entry->key_data,
                                           entry->n_key_data,
                                           mkvno,
                                           mod_op);
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_TL_DATA */
    if (entry->mask & KMASK_TL_DATA) {
        kerr = ipadb_get_tl_data(entry,
                                 KRB5_TL_LAST_ADMIN_UNLOCK,
                                 sizeof(time32le),
                                 (krb5_octet *)&time32le);
        if (kerr && kerr != ENOENT) {
            goto done;
        }
        if (kerr == 0) {
            kerr = ipadb_get_ldap_mod_time(imods,
                                           "krbLastAdminUnlock",
                                           le32toh(time32le),
                                           mod_op);
            if (kerr) {
                goto done;
            }
        }

        kerr = ipadb_get_ldap_mod_extra_data(imods,
                                             entry->tl_data,
                                             mod_op);
        if (kerr && kerr != ENOENT) {
            goto done;
        }
    }

    /* KADM5_LOAD */

    kerr = 0;

done:
    return kerr;
}

/* adds default objectclasses and attributes */
static krb5_error_code ipadb_entry_default_attrs(struct ipadb_mods *imods)
{
    krb5_error_code kerr;
    LDAPMod *m = NULL;
    int i;

    kerr = ipadb_mods_new(imods, &m);
    if (kerr) {
        return kerr;
    }

    m->mod_op = LDAP_MOD_ADD;
    m->mod_type = strdup("objectClass");
    if (!m->mod_type) {
        kerr = ENOMEM;
        goto done;
    }
    m->mod_values = calloc(STD_PRINCIPAL_OBJ_CLASSES_SIZE + 1, sizeof(char *));
    if (!m->mod_values) {
        kerr = ENOMEM;
        goto done;
    }
    for (i = 0; i < STD_PRINCIPAL_OBJ_CLASSES_SIZE; i++) {
        m->mod_values[i] = strdup(std_principal_obj_classes[i]);
        if (!m->mod_values[i]) {
            kerr = ENOMEM;
            goto done;
        }
    }

    kerr = 0;

done:
    if (kerr) {
        ipadb_mods_free_tip(imods);
    }
    return kerr;
}

static krb5_error_code ipadb_add_principal(krb5_context kcontext,
                                           krb5_db_entry *entry)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *principal = NULL;
    struct ipadb_mods *imods = NULL;
    char *dn = NULL;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto done;
    }

    if (!ipactx->override_restrictions) {
        return KRB5_KDB_CONSTRAINT_VIOLATION;
    }

    kerr = krb5_unparse_name(kcontext, entry->princ, &principal);
    if (kerr != 0) {
        goto done;
    }

    ret = asprintf(&dn, "krbPrincipalName=%s,cn=%s,cn=kerberos,%s",
                        principal, ipactx->realm, ipactx->base);
    if (ret == -1) {
        kerr = ENOMEM;
        goto done;
    }

    ret = new_ipadb_mods(&imods);
    if (ret != 0) {
        kerr = ret;
        goto done;
    }

    kerr = ipadb_entry_to_mods(imods, entry, principal, LDAP_MOD_ADD);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_entry_default_attrs(imods);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_simple_add(ipactx, dn, imods->mods);

done:
    ipadb_mods_free(imods);
    krb5_free_unparsed_name(kcontext, principal);
    ldap_memfree(dn);
    return kerr;
}

static krb5_error_code ipadb_modify_principal(krb5_context kcontext,
                                              krb5_db_entry *entry)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *principal = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    struct ipadb_mods *imods = NULL;
    char *dn = NULL;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    kerr = krb5_unparse_name(kcontext, entry->princ, &principal);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_fetch_principals(ipactx, principal, &res);
    if (kerr != 0) {
        goto done;
    }

    /* FIXME: no alias allowed for now, should we allow modifies
     * by alias name ? */
    kerr = ipadb_find_principal(kcontext, 0, res, &principal, &lentry);
    if (kerr != 0) {
        goto done;
    }

    dn = ldap_get_dn(ipactx->lcontext, lentry);
    if (!dn) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = new_ipadb_mods(&imods);
    if (kerr) {
        goto done;
    }

    kerr = ipadb_entry_to_mods(imods, entry, principal, LDAP_MOD_REPLACE);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_simple_modify(ipactx, dn, imods->mods);

done:
    ipadb_mods_free(imods);
    ldap_msgfree(res);
    krb5_free_unparsed_name(kcontext, principal);
    ldap_memfree(dn);
    return kerr;
}

krb5_error_code ipadb_put_principal(krb5_context kcontext,
                                    krb5_db_entry *entry,
                                    char **db_args)
{
    if (entry->mask & KMASK_PRINCIPAL) {
        return ipadb_add_principal(kcontext, entry);
    } else {
        return ipadb_modify_principal(kcontext, entry);
    }
}

static krb5_error_code ipadb_delete_entry(krb5_context kcontext,
                                          LDAPMessage *lentry)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *dn = NULL;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto done;
    }

    if (!ipactx->lcontext) {
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }
    }

    dn = ldap_get_dn(ipactx->lcontext, lentry);
    if (!dn) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_simple_delete(ipactx, dn);

done:
    ldap_memfree(dn);
    return kerr;
}

static krb5_error_code ipadb_delete_alias(krb5_context kcontext,
                                          LDAPMessage *lentry,
                                          char *principal)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *dn = NULL;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto done;
    }

    if (!ipactx->lcontext) {
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }
    }

    dn = ldap_get_dn(ipactx->lcontext, lentry);
    if (!dn) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_simple_delete_val(ipactx, dn, "krbprincipalname", principal);

done:
    ldap_memfree(dn);
    return kerr;
}

krb5_error_code ipadb_delete_principal(krb5_context kcontext,
                                       krb5_const_principal search_for)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *principal = NULL;
    char *canonicalized = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    unsigned int flags;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    if (!ipactx->override_restrictions) {
        return KRB5_KDB_CONSTRAINT_VIOLATION;
    }

    kerr = krb5_unparse_name(kcontext, search_for, &principal);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_fetch_principals(ipactx, principal, &res);
    if (kerr != 0) {
        goto done;
    }

    canonicalized = strdup(principal);
    if (!canonicalized) {
        kerr = ENOMEM;
        goto done;
    }

    flags = KRB5_KDB_FLAG_ALIAS_OK;
    kerr = ipadb_find_principal(kcontext, flags, res, &canonicalized, &lentry);
    if (kerr != 0) {
        goto done;
    }

    /* check if this is an alias (remove it) or if we should remove the whole
     * ldap record */

    /* TODO: should we use case insensitive matching here ? */
    if (strcmp(canonicalized, principal) == 0) {
        kerr = ipadb_delete_entry(kcontext, lentry);
    } else {
        kerr = ipadb_delete_alias(kcontext, lentry, principal);
    }

done:
    ldap_msgfree(res);
    free(canonicalized);
    krb5_free_unparsed_name(kcontext, principal);
    return kerr;
}

krb5_error_code ipadb_iterate(krb5_context kcontext,
                              char *match_entry,
                              int (*func)(krb5_pointer, krb5_db_entry *),
                              krb5_pointer func_arg)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    krb5_db_entry *kentry;
    uint32_t pol;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    /* fetch list of principal matching filter */
    kerr = ipadb_fetch_principals(ipactx, match_entry, &res);
    if (kerr != 0) {
        goto done;
    }

    lentry = ldap_first_entry(ipactx->lcontext, res);

    while (lentry) {

        kentry = NULL;
        kerr = ipadb_parse_ldap_entry(kcontext, NULL, lentry, &kentry, &pol);
        if (kerr == 0 && pol != 0) {
            kerr = ipadb_fetch_tktpolicy(kcontext, lentry, kentry, pol);
        }
        if (kerr == 0) {
            /* Now call the callback with the entry */
            func(func_arg, kentry);
        }
        ipadb_free_principal(kcontext, kentry);

        lentry = ldap_next_entry(ipactx->lcontext, lentry);
    }

    kerr = 0;

done:
    ldap_msgfree(res);
    return kerr;
}

