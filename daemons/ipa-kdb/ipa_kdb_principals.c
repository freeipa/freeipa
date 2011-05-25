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
    krb5_kvno mkvno;
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
    LDAPMessage *res = NULL;
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
    if (kerr) {
        ldap_msgfree(res);
    }
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
    return;
}

krb5_error_code ipadb_put_principal(krb5_context kcontext,
                                    krb5_db_entry *entry,
                                    char **db_args)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

krb5_error_code ipadb_delete_principal(krb5_context kcontext,
                                       krb5_const_principal search_for)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

krb5_error_code ipadb_iterate(krb5_context kcontext,
                              char *match_entry,
                              int (*func)(krb5_pointer, krb5_db_entry *),
                              krb5_pointer func_arg)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

