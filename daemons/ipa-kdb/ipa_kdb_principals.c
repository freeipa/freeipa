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
#include <unicase.h>

/*
 * During TGS request search by ipaKrbPrincipalName (case-insensitive)
 * and krbPrincipalName (case-sensitive)
 */
#define PRINC_TGS_SEARCH_FILTER "(&(|(objectclass=krbprincipalaux)" \
                                    "(objectclass=krbprincipal)" \
                                    "(objectclass=ipakrbprincipal))" \
                                    "(|(ipakrbprincipalalias=%s)" \
                                      "(krbprincipalname:caseIgnoreIA5Match:=%s)))"

#define PRINC_SEARCH_FILTER "(&(|(objectclass=krbprincipalaux)" \
                                "(objectclass=krbprincipal))" \
                              "(krbprincipalname=%s))"

#define PRINC_TGS_SEARCH_FILTER_EXTRA "(&(|(objectclass=krbprincipalaux)" \
                                          "(objectclass=krbprincipal)" \
                                          "(objectclass=ipakrbprincipal))" \
                                        "(|(ipakrbprincipalalias=%s)" \
                                          "(krbprincipalname:caseIgnoreIA5Match:=%s))" \
                                         "%s)"

#define PRINC_SEARCH_FILTER_EXTRA "(&(|(objectclass=krbprincipalaux)" \
                                      "(objectclass=krbprincipal))" \
                                    "(krbprincipalname=%s)" \
                                    "%s)"
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
    "krbPrincipalAuthInd",
    "krbExtraData",
    "krbLastAdminUnlock",
    "krbObjectReferences",
    "krbTicketFlags",
    "krbMaxTicketLife",
    "krbMaxRenewableAge",

    /* IPA SPECIFIC ATTRIBUTES */
    "nsaccountlock",
    "passwordHistory",
    IPA_KRB_AUTHZ_DATA_ATTR,
    IPA_USER_AUTH_TYPE,
    "ipatokenRadiusConfigLink",

    "objectClass",
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

#define DEFAULT_TL_DATA_CONTENT "\x00\x00\x00\x00principal@UNINITIALIZED"

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
    next = NULL;
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
        free(next);
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
                                         const krb5_octet *data)
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
    int mkvno;
    int ret;

    vals = ldap_get_values_len(lcontext, le, attrname);
    if (!vals) {
        return ENOENT;
    }

    ret = ber_decode_krb5_key_data(vals[0], &mkvno, num, result);
    ldap_value_free_len(vals);
    if (ret == 0) {
        *res_mkvno = mkvno;
    }
    return ret;
}

static void ipadb_validate_otp(struct ipadb_context *ipactx,
                               LDAPMessage *lentry,
                               enum ipadb_user_auth *ua)
{
    static const char *attrs[] = { "dn", NULL };
    static const char *dttmpl = "%Y%m%d%H%M%SZ";
    static const char *ftmpl = "(&"
        "(objectClass=ipaToken)(ipatokenOwner=%s)"
        "(|(ipatokenNotBefore<=%s)(!(ipatokenNotBefore=*)))"
        "(|(ipatokenNotAfter>=%s)(!(ipatokenNotAfter=*)))"
        "(|(ipatokenDisabled=FALSE)(!(ipatokenDisabled=*)))"
    ")";
    krb5_error_code kerr = 0;
    LDAPMessage *res = NULL;
    char datetime[16] = {};
    char *filter = NULL;
    struct tm tm = {};
    char *dn = NULL;
    time_t now = 0;
    int count = 0;

    if (!(*ua & IPADB_USER_AUTH_OTP))
        return;

    /* Get the current time. */
    if (time(&now) == (time_t) -1)
        return;
    if (gmtime_r(&now, &tm) == NULL)
        return;

    /* Make the current time string. */
    if (strftime(datetime, sizeof(datetime), dttmpl, &tm) == 0)
        return;

    /* Make the filter. */
    dn = ldap_get_dn(ipactx->lcontext, lentry);
    if (dn == NULL)
        return;
    count = asprintf(&filter, ftmpl, dn, datetime, datetime);
    ldap_memfree(dn);
    if (count < 0)
        return;

    /* Fetch the active token list. */
    kerr = ipadb_simple_search(ipactx, ipactx->base, LDAP_SCOPE_SUBTREE,
                               filter, (char**) attrs, &res);
    free(filter);
    if (kerr != 0 || res == NULL)
        return;

    /* Count the number of active tokens. */
    count = ldap_count_entries(ipactx->lcontext, res);
    ldap_msgfree(res);

    /* If the user is configured for OTP, but has no active tokens, remove
     * OTP from the list since the user obviously can't log in this way. */
    if (count == 0)
        *ua &= ~IPADB_USER_AUTH_OTP;
}

static void ipadb_validate_radius(struct ipadb_context *ipactx,
                                  LDAPMessage *lentry,
                                  enum ipadb_user_auth *ua)
{
    struct berval **vals;

    if (!(*ua & IPADB_USER_AUTH_RADIUS))
        return;

    /* Ensure that the user has a link to a RADIUS config. */
    vals = ldap_get_values_len(ipactx->lcontext, lentry,
                               "ipatokenRadiusConfigLink");
    if (vals == NULL || vals[0] == NULL)
        *ua &= ~IPADB_USER_AUTH_RADIUS;
    else
        *ua = IPADB_USER_AUTH_RADIUS;

    if (vals != NULL)
        ldap_value_free_len(vals);
}

static enum ipadb_user_auth ipadb_get_user_auth(struct ipadb_context *ipactx,
                                                LDAPMessage *lentry)
{
    enum ipadb_user_auth gua = IPADB_USER_AUTH_NONE;
    enum ipadb_user_auth ua = IPADB_USER_AUTH_NONE;
    const struct ipadb_global_config *gcfg = NULL;

    /* Get the global user_auth settings. */
    gcfg = ipadb_get_global_config(ipactx);
    if (gcfg != NULL)
        gua = gcfg->user_auth;

    /* Get the user's user_auth settings if not disabled. */
    if ((gua & IPADB_USER_AUTH_DISABLED) == 0)
        ipadb_parse_user_auth(ipactx->lcontext, lentry, &ua);

    /* Filter out the disabled flag. */
    gua &= ~IPADB_USER_AUTH_DISABLED;
    ua &= ~IPADB_USER_AUTH_DISABLED;

    /* Determine which user_auth policy is active: user or global. */
    if (ua == IPADB_USER_AUTH_NONE)
        ua = gua;

    /* Perform flag validation. */
    ipadb_validate_otp(ipactx, lentry, &ua);
    ipadb_validate_radius(ipactx, lentry, &ua);

    return ua;
}

#define OSA_ADB_PRINC_VERSION_1  0x12345C01
/* The XDR encoding of OSA_PRINC_ENC is as follows:
    version:        int (signed 32 bit integer)
    name:           nullstring (null terminated variable string)
    aux_attributes: long (signed 32 bit integer)
    old_key_next:   u_int (unsigned 32 bit integer)
    adm_hist_kvno:  u_char (unisgned char)
    old_keys:       array of keys, we do not care so alway u_int of 0
*/
#define OSA_PRINC_ENC_BASE_SIZE 20

static krb5_error_code ipadb_policydn_to_kdam_tl_data(const char *policydn,
                                                      krb5_db_entry *entry)
{
    krb5_error_code kerr;
    uint32_t tmp;
    char *policy_name = NULL;
    char *p;
    uint8_t *buf = NULL;
    size_t buf_len;
    int slen;
    int plen;
    int cur;

    /* policy objects must use cn as the RDN */
    if (strncmp(policydn, "cn=", 3) != 0) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    /* Should we try to consider the case where a ',' is part of the polict
     * name ? */
    policy_name = strdup(&policydn[3]);
    if (!policy_name) {
        kerr = ENOMEM;
        goto done;
    }
    p = strchr(policy_name, ',');
    if (p) *p = '\0';

    /* Now we open code a basic KRB5_TL_KADM_DATA which is a XDR encoded
     * structure in MIT code */

    slen = strlen(policy_name) + 1;
    /* A xdr varstring is preceeded by a 32bit len field and is always 32
     * bit aligned */
    plen = slen + 4;
    plen = (((plen + 3) / 4) * 4);

    buf_len = OSA_PRINC_ENC_BASE_SIZE + plen;
    buf = calloc(1, buf_len);
    if (!buf) {
        kerr = ENOMEM;
        goto done;
    }

    /* version */
    cur = 0;
    tmp = htobe32(OSA_ADB_PRINC_VERSION_1);
    memcpy(&buf[cur], &tmp, 4);
    cur += 4;

    /* name */
    tmp = htobe32(slen);
    memcpy(&buf[cur], &tmp, 4);
    memcpy(&buf[cur + 4], policy_name, slen);
    cur += plen;

    /* All the other fileds are left empty */

    kerr = ipadb_set_tl_data(entry, KRB5_TL_KADM_DATA, buf_len, buf);

done:
    free(policy_name);
    free(buf);
    return kerr;
}

static void strv_free(char **strv)
{
    int i;

    if (strv == NULL) {
        return;
    }

    for (i = 0; strv[i] != NULL; i++) {
        free(strv[i]);
    }

    free(strv);
}

static krb5_error_code ipadb_get_ldap_auth_ind(krb5_context kcontext,
                                               LDAP *lcontext,
                                               LDAPMessage *lentry,
                                               krb5_db_entry *entry)
{
    krb5_error_code ret = 0;
    char **authinds = NULL;
    char *aistr = NULL;
    char *ap = NULL;
    size_t len = 0;
    size_t l = 0;
    int count = 0;
    int i = 0;

    ret = ipadb_ldap_attr_to_strlist(lcontext, lentry, "krbPrincipalAuthInd",
                                     &authinds);
    switch (ret) {
    case 0:
        break;
    case ENOENT:
        return 0;
    default:
        return ret;
    }

    for (count = 0; authinds != NULL && authinds[count] != NULL; count++) {
        len += strlen(authinds[count]) + 1;
    }

    if (len == 0) {
        strv_free(authinds);
        return 0;
    }

    aistr = malloc(len);
    if (aistr == NULL) {
        ret = errno;
        goto cleanup;
    }

    /* Create a space-separated string of authinds. */
    ap = aistr;
    l = len;
    for (i = 0; i < count; i++) {
        ret = snprintf(ap, l, "%s ", authinds[i]);
        if (ret <= 0 || ret > l) {
            ret = ENOMEM;
            goto cleanup;
        }
        ap += ret;
        l -= ret;
    }
    aistr[len - 1] = '\0';

    ret = krb5_dbe_set_string(kcontext, entry, "require_auth",
                              aistr);

cleanup:
    strv_free(authinds);
    free(aistr);

    return ret;
}

static krb5_error_code ipadb_parse_ldap_entry(krb5_context kcontext,
                                              char *principal,
                                              LDAPMessage *lentry,
                                              krb5_db_entry **kentry,
                                              uint32_t *polmask)
{
    const krb5_octet rad_string[] = "otp\0[{\"indicators\": [\"radius\"]}]";
    const krb5_octet otp_string[] = "otp\0[{\"indicators\": [\"otp\"]}]";
    struct ipadb_context *ipactx;
    enum ipadb_user_auth ua;
    LDAP *lcontext;
    krb5_db_entry *entry;
    struct ipadb_e_data *ied;
    krb5_error_code kerr;
    krb5_tl_data *res_tl_data;
    krb5_key_data *res_key_data;
    krb5_kvno mkvno = 0;
    char **restrlist;
    char *restring;
    char **authz_data_list;
    krb5_timestamp restime;
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
    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        free(entry);
        return KRB5_KDB_DBNOTINITED;
    }
    lcontext = ipactx->lcontext;

    entry->magic = KRB5_KDB_MAGIC_NUMBER;
    entry->len = KRB5_KDB_V1_BASE_LENGTH;

    /* Get User Auth configuration. */
    ua = ipadb_get_user_auth(ipactx, lentry);

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

    ret = ipadb_ldap_attr_to_krb5_timestamp(lcontext, lentry,
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

    ret = ipadb_ldap_attr_to_krb5_timestamp(lcontext, lentry,
                                           "krbPasswordExpiration", &restime);
    switch (ret) {
    case 0:
        entry->pw_expiration = restime;

        /* If we are using only RADIUS, we don't know expiration. */
        if (ua == IPADB_USER_AUTH_RADIUS)
            entry->pw_expiration = 0;
    case ENOENT:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_krb5_timestamp(lcontext, lentry,
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

    ret = ipadb_ldap_attr_to_krb5_timestamp(lcontext, lentry,
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
        break;
    case ENOENT:
        /* The kadmin utility expects always at least KRB5_TL_MOD_PRINC tl_data
         * to be available. So if krbExtraData is missing (may happen when a
         * user is created but no password has been set yet) then add a default
         * one. */
        kerr = ipadb_set_tl_data(entry, KRB5_TL_MOD_PRINC,
                                 sizeof(DEFAULT_TL_DATA_CONTENT),
                                 (const krb5_octet *)DEFAULT_TL_DATA_CONTENT);
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_get_ldap_auth_ind(kcontext, lcontext, lentry, entry);
    if (ret)
        goto done;

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

    ied = calloc(1, sizeof(struct ipadb_e_data));
    if (!ied) {
        kerr = ENOMEM;
        goto done;
    }
    ied->magic = IPA_E_DATA_MAGIC;

    entry->e_data = (krb5_octet *)ied;

    ied->entry_dn = ldap_get_dn(lcontext, lentry);
    if (!ied->entry_dn) {
        kerr = ENOMEM;
        goto done;
    }

    /* mark this as an ipa_user if it has the posixaccount objectclass */
    ret = ipadb_ldap_attr_has_value(lcontext, lentry,
                                    "objectClass", "posixAccount");
    if (ret != 0 && ret != ENOENT) {
        kerr = ret;
        goto done;
    }
    if (ret == 0) {
        ied->ipa_user = true;
    }

    /* check if it has the krbTicketPolicyAux objectclass */
    ret = ipadb_ldap_attr_has_value(lcontext, lentry,
                                    "objectClass", "krbTicketPolicyAux");
    if (ret != 0 && ret != ENOENT) {
        kerr = ret;
        goto done;
    }
    if (ret == 0) {
        ied->has_tktpolaux = true;
    }

    ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                 "krbPwdPolicyReference", &restring);
    switch (ret) {
    case ENOENT:
        /* use the default policy if ref. is not available */
        ret = asprintf(&restring,
                       "cn=global_policy,%s", ipactx->realm_base);
        if (ret == -1) {
            kerr = ENOMEM;
            goto done;
        }
    case 0:
        break;
    default:
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }
    ied->pw_policy_dn = restring;

    kerr = ipadb_policydn_to_kdam_tl_data(restring, entry);
    if (kerr) goto done;

    ret = ipadb_ldap_attr_to_strlist(lcontext, lentry,
                                     "passwordHistory", &restrlist);
    if (ret != 0 && ret != ENOENT) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }
    if (ret == 0) {
        ied->pw_history = restrlist;
    }

    ret = ipadb_ldap_attr_to_krb5_timestamp(lcontext, lentry,
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

        ied->last_pwd_change = restime;
    }

    ret = ipadb_ldap_attr_to_krb5_timestamp(lcontext, lentry,
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

        ied->last_admin_unlock = restime;
    }

    ret = ipadb_ldap_attr_to_strlist(lcontext, lentry,
                                     IPA_KRB_AUTHZ_DATA_ATTR, &authz_data_list);
    if (ret != 0 && ret != ENOENT) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }
    if (ret == 0) {
        ied->authz_data = authz_data_list;
    }

    ied->user_auth = ua;

    /* If enabled, set the otp user string, enabling otp. */
    if (ua & IPADB_USER_AUTH_OTP) {
        kerr = ipadb_set_tl_data(entry, KRB5_TL_STRING_ATTRS,
                                 sizeof(otp_string), otp_string);
        if (kerr)
            goto done;
    } else if (ua & IPADB_USER_AUTH_RADIUS) {
        kerr = ipadb_set_tl_data(entry, KRB5_TL_STRING_ATTRS,
                                 sizeof(rad_string), rad_string);
        if (kerr)
            goto done;
    }

    kerr = 0;

done:
    if (kerr) {
        ipadb_free_principal(kcontext, entry);
        entry = NULL;
    }
    *kentry = entry;
    return kerr;
}

krb5_error_code
ipadb_fetch_principals_with_extra_filter(struct ipadb_context *ipactx,
                                         unsigned int flags,
                                         const char *principal,
                                         const char *filter,
                                         LDAPMessage **result)
{
    krb5_error_code kerr;
    char *src_filter = NULL;
    char *esc_original_princ = NULL;
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
    esc_original_princ = ipadb_filter_escape(principal, false);
    if (!esc_original_princ) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    if (filter == NULL) {
        if (flags & KRB5_KDB_FLAG_ALIAS_OK) {
            ret = asprintf(&src_filter, PRINC_TGS_SEARCH_FILTER,
                           esc_original_princ, esc_original_princ);
        } else {
            ret = asprintf(&src_filter, PRINC_SEARCH_FILTER, esc_original_princ);
        }
    } else {
        if (flags & KRB5_KDB_FLAG_ALIAS_OK) {
            ret = asprintf(&src_filter, PRINC_TGS_SEARCH_FILTER_EXTRA,
                           esc_original_princ, esc_original_princ, filter);
        } else {
            ret = asprintf(&src_filter, PRINC_SEARCH_FILTER_EXTRA,
                           esc_original_princ, filter);
        }
    }

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
    free(esc_original_princ);
    return kerr;
}

static krb5_error_code ipadb_fetch_principals(struct ipadb_context *ipactx,
                                              unsigned int flags,
                                              char *principal,
                                              LDAPMessage **result)
{
    return ipadb_fetch_principals_with_extra_filter(ipactx, flags, principal,
                                                    NULL, result);
}

krb5_error_code ipadb_find_principal(krb5_context kcontext,
                                     unsigned int flags,
                                     LDAPMessage *res,
                                     char **principal,
                                     LDAPMessage **entry)
{
    struct ipadb_context *ipactx;
    bool found = false;
    LDAPMessage *le = NULL;
    struct berval **vals;
    int i, result;

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
            /* KDC will accept aliases when doing TGT lookup (ref_tgt_again in do_tgs_req.c */
            /* Use case-insensitive comparison in such cases */
            if ((flags & KRB5_KDB_FLAG_ALIAS_OK) != 0) {
                if (ulc_casecmp(vals[i]->bv_val, vals[i]->bv_len,
                                (*principal), strlen(*principal),
                                NULL, NULL, &result) != 0)
                    return KRB5_KDB_INTERNAL_ERROR;
                found = (result == 0);
                if (found) {
                    /* replace the incoming principal with the value having
                     * the correct case. This ensures that valid name/alias
                     * is returned even if krbCanonicalName is not present
                     */
                    free(*principal);
                    *principal = strdup(vals[i]->bv_val);
                    if (!(*principal)) {
                        return KRB5_KDB_INTERNAL_ERROR;
                    }
                }
            } else {
                found = (strcmp(vals[i]->bv_val, (*principal)) == 0);
            }
            if (found) {
                break;
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

        /* Again, if aliases are accepted by KDC, use case-insensitive comparison */
        if ((flags & KRB5_KDB_FLAG_ALIAS_OK) != 0) {
            found = true;
        } else {
            found = (strcmp(vals[0]->bv_val, (*principal)) == 0);
        }

        if (!found) {
            /* search does not allow aliases */
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

static krb5_flags maybe_require_preauth(struct ipadb_context *ipactx,
                                        krb5_db_entry *entry)
{
    const struct ipadb_global_config *config;
    struct ipadb_e_data *ied;

    config = ipadb_get_global_config(ipactx);
    if (config->disable_preauth_for_spns) {
        ied = (struct ipadb_e_data *)entry->e_data;
        if (ied && ied->ipa_user != true) {
            /* not a user, assume SPN */
            return 0;
        }
    }

    /* By default require preauth for all principals */
    return KRB5_KDB_REQUIRES_PRE_AUTH;
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
                    entry->attributes |= maybe_require_preauth(ipactx, entry);
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
            entry->attributes |= maybe_require_preauth(ipactx, entry);
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
    char *trusted_realm = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    krb5_db_entry *kentry = NULL;
    uint32_t pol;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    kerr = krb5_unparse_name(kcontext, search_for, &principal);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_fetch_principals(ipactx, flags, principal, &res);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_find_principal(kcontext, flags, res, &principal, &lentry);
    if (kerr != 0) {
        if ((kerr == KRB5_KDB_NOENTRY) &&
            ((flags & (KRB5_KDB_FLAG_CANONICALIZE |
                       KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY)) != 0)) {

            /* First check if we got enterprise principal which looks like
             * username\@enterprise_realm@REALM */
            char *realm;
            krb5_data *upn;

            upn = krb5_princ_component(kcontext, search_for,
                                       krb5_princ_size(kcontext, search_for) - 1);

            if (upn == NULL) {
                kerr = KRB5_KDB_NOENTRY;
                goto done;
            }

            realm = memrchr(upn->data, '@', upn->length);
            if (realm == NULL) {
                kerr = KRB5_KDB_NOENTRY;
                goto done;
            }

            /* skip '@' and use part after '@' as an enterprise realm for comparison */
            realm++;

            /* check for our realm */
            if (strncasecmp(ipactx->realm, realm,
                            upn->length - (realm - upn->data)) == 0) {
                /* it looks like it is ok to use malloc'ed strings as principal */
                krb5_free_unparsed_name(kcontext, principal);
                principal = strndup((const char *) upn->data, upn->length);
                if (principal == NULL) {
                    kerr = ENOMEM;
                    goto done;
                }

                ldap_msgfree(res);
                res = NULL;
                kerr = ipadb_fetch_principals(ipactx, flags, principal, &res);
                if (kerr != 0) {
                    goto done;
                }

                kerr = ipadb_find_principal(kcontext, flags, res, &principal,
                                            &lentry);
                if (kerr != 0) {
                    goto done;
                }
            } else {

                kerr = ipadb_is_princ_from_trusted_realm(kcontext,
                                                         realm,
                                                         upn->length - (realm - upn->data),
                                                         &trusted_realm);
                if (kerr == KRB5_KDB_NOENTRY) {
                    /* try to refresh trusted domain data and try again */
                    kerr = ipadb_reinit_mspac(ipactx, false);
                    if (kerr != 0) {
                        kerr = KRB5_KDB_NOENTRY;
                        goto done;
                    }
                    kerr = ipadb_is_princ_from_trusted_realm(kcontext, realm,
                                              upn->length - (realm - upn->data),
                                              &trusted_realm);
                }
                if (kerr == 0) {
                    kentry = calloc(1, sizeof(krb5_db_entry));
                    if (!kentry) {
                        kerr = ENOMEM;
                        goto done;
                    }
                    kerr = krb5_parse_name(kcontext, principal,
                                           &kentry->princ);
                    if (kerr != 0) {
                        goto done;
                    }

                    kerr = krb5_set_principal_realm(kcontext, kentry->princ, trusted_realm);
                    if (kerr != 0) {
                        goto done;
                    }
                    *entry = kentry;
                }
                goto done;
            }
        } else {
            goto done;
        }
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
    free(trusted_realm);
    if ((kerr != 0) && (kentry != NULL)) {
        ipadb_free_principal(kcontext, kentry);
    }
    ldap_msgfree(res);
    krb5_free_unparsed_name(kcontext, principal);
    return kerr;
}

void ipadb_free_principal_e_data(krb5_context kcontext, krb5_octet *e_data)
{
    struct ipadb_e_data *ied;
    int i;

    ied = (struct ipadb_e_data *)e_data;
    if (ied->magic == IPA_E_DATA_MAGIC) {
	ldap_memfree(ied->entry_dn);
	free(ied->passwd);
	free(ied->pw_policy_dn);
	for (i = 0; ied->pw_history && ied->pw_history[i]; i++) {
	    free(ied->pw_history[i]);
	}
	free(ied->pw_history);
	for (i = 0; ied->authz_data && ied->authz_data[i]; i++) {
	    free(ied->authz_data[i]);
	}
	free(ied->authz_data);
	free(ied->pol);
	free(ied);
    }
}

void ipadb_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    krb5_tl_data *prev, *next;

    if (entry) {
        krb5_free_principal(kcontext, entry->princ);
        prev = entry->tl_data;
        while(prev) {
            next = prev->tl_data_next;
            free(prev->tl_data_contents);
            free(prev);
            prev = next;
        }
        ipa_krb5_free_key_data(entry->key_data, entry->n_key_data);

        if (entry->e_data) {
	    ipadb_free_principal_e_data(kcontext, entry->e_data);
        }

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
    LDAPMod *mod;
    int ret;

    /* If the key data is empty, remove all keys. */
    if (n_key_data == 0 || key_data == NULL) {
        kerr = ipadb_mods_new(imods, &mod);
        if (kerr != 0)
            return kerr;

        mod->mod_op = LDAP_MOD_DELETE;
        mod->mod_bvalues = NULL;
        mod->mod_type = strdup("krbPrincipalKey");
        if (mod->mod_type == NULL) {
            ipadb_mods_free_tip(imods);
            return ENOMEM;
        }

        return 0;
    }

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

static krb5_error_code ipadb_get_ldap_mod_str_list(struct ipadb_mods *imods,
                                                   char *attrname,
                                                   char **strlist, int len,
                                                   int mod_op)
{
    krb5_error_code kerr;
    struct berval **bvs = NULL;
    int i;

    bvs = calloc(len + 1, sizeof(struct berval *));
    if (!bvs) {
        kerr = ENOMEM;
        goto done;
    }

    for (i = 0; i < len; i++) {
        bvs[i] = calloc(1, sizeof(struct berval));
        if (!bvs[i]) {
            kerr = ENOMEM;
            goto done;
        }

        bvs[i]->bv_val = strdup(strlist[i]);
        if (!bvs[i]->bv_val) {
            kerr = ENOMEM;
            goto done;
        }
        bvs[i]->bv_len = strlen(strlist[i]) + 1;
    }

    kerr = ipadb_get_ldap_mod_bvalues(imods, attrname, bvs, len, mod_op);

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

static krb5_error_code ipadb_principal_to_mods(krb5_context kcontext,
                                               struct ipadb_mods *imods,
                                               char *principal,
                                               int mod_op)
{
    krb5_error_code kerr;

    if (principal == NULL) {
       kerr = EINVAL;
       goto done;
    }

    kerr = ipadb_get_ldap_mod_str(imods, "krbPrincipalName",
                                  principal, mod_op);
    if (kerr) {
        goto done;
    }
    kerr = ipadb_get_ldap_mod_str(imods, "krbCanonicalName",
                                  principal, mod_op);
    if (kerr) {
        goto done;
    }

    kerr = 0;

done:
    return kerr;
}

static krb5_error_code ipadb_get_ldap_mod_auth_ind(krb5_context kcontext,
                                                   struct ipadb_mods *imods,
                                                   krb5_db_entry *entry,
                                                   int mod_op)
{
    krb5_error_code ret = 0;
    char **strlist = NULL;
    char *ais = NULL;
    char *ai = NULL;
    char *s = NULL;
    size_t ai_size = 0;
    int cnt = 0;
    int i = 0;

    ret = krb5_dbe_get_string(kcontext, entry, "require_auth", &ais);
    if (ret) {
        return ret;
    }
    if (ais == NULL) {
        return 0;
    }

    ai_size = strlen(ais) + 1;

    for (i = 0; i < ai_size; i++) {
        if (ais[i] != ' ') {
            continue;
        }
        if (i > 0 && ais[i - 1] != ' ') {
            cnt++;
        }
    }

    strlist = calloc(cnt + 2, sizeof(*strlist));
    if (strlist == NULL) {
        free(ais);
        return errno;
    }

    cnt = 0;
    ai = strtok_r(ais, " ", &s);
    while (ai != NULL) {
        if (ai[0] != '\0') {
            strlist[cnt++] = ai;
        }
        ai = strtok_r(NULL, " ", &s);
    }

    ret = ipadb_get_ldap_mod_str_list(imods, "krbPrincipalAuthInd",
                                      strlist, cnt, mod_op);

    free(ais);
    free(strlist);
    return ret;
}

static krb5_error_code ipadb_entry_to_mods(krb5_context kcontext,
                                           struct ipadb_mods *imods,
                                           krb5_db_entry *entry,
                                           int mod_op)
{
    krb5_error_code kerr;
    krb5_int32 time32le;
    int mkvno;
    char *req_auth_str = NULL;

    /* check each mask flag in order */

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
        if (entry->pw_expiration == 0) {
            kerr = ipadb_get_ldap_mod_time(imods,
                                           "krbPasswordExpiration",
                                           entry->pw_expiration, LDAP_MOD_DELETE);
        }
        if (kerr) {
            goto done;
        }
    }

    /* KADM5_LAST_PWD_CHANGE */
    /* apparently, at least some versions of kadmin fail to set this flag
     * when they do include a pwd change timestamp in TL_DATA.
     * So for now check if KADM5_KEY_DATA has been set, which kadm5
     * always does on password changes */
#if KADM5_ACTUALLY_SETS_LAST_PWD_CHANGE
    if (entry->mask & KMASK_LAST_PWD_CHANGE) {
        if (!entry->n_tl_data) {
            kerr = EINVAL;
            goto done;
        }

#else
    if (entry->n_tl_data &&
        entry->mask & KMASK_KEY_DATA) {
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
        /* if the object does not have the krbTicketPolicyAux class
         * we need to add it or this will fail, only for modifications.
         * We always add this objectclass by default when doing an add
         * from scratch. */
        if ((mod_op == LDAP_MOD_REPLACE) && entry->e_data) {
            struct ipadb_e_data *ied;

            ied = (struct ipadb_e_data *)entry->e_data;
            if (ied->magic != IPA_E_DATA_MAGIC) {
                kerr = EINVAL;
                goto done;
            }

            if (!ied->has_tktpolaux) {
                kerr = ipadb_get_ldap_mod_str(imods, "objectclass",
                                              "krbTicketPolicyAux",
                                              LDAP_MOD_ADD);
                if (kerr) {
                    goto done;
                }
            }
        }

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

    kerr = ipadb_get_ldap_mod_auth_ind(kcontext, imods, entry, mod_op);
    if (kerr)
        goto done;

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

        kerr = krb5_dbe_get_string(kcontext, entry, "require_auth",
                                   &req_auth_str);
        if (kerr) {
            goto done;
        }

        /* Do not store auth indicators from the string attribute in
         * krbExtraData. Remove require_auth value from the entry temporarily. */
        if (req_auth_str != NULL) {
            kerr = krb5_dbe_set_string(kcontext, entry, "require_auth", NULL);
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

        /* Restore require_auth value */
        if (req_auth_str != NULL) {
            kerr = krb5_dbe_set_string(kcontext, entry, "require_auth",
                                       req_auth_str);
            if (kerr) {
                goto done;
            }
        }
    }

    /* KADM5_LOAD */

    /* Handle password change related operations. */
    if (entry->e_data) {
        struct ipadb_e_data *ied;
        time_t now = time(NULL);
        time_t expire_time;
        char **new_history;
        int nh_len;
        int ret;
        int i;

        ied = (struct ipadb_e_data *)entry->e_data;
        if (ied->magic != IPA_E_DATA_MAGIC) {
            kerr = EINVAL;
            goto done;
        }

        /*
         * We need to set userPassword and history only if this is
         * a IPA User, we don't do that for simple service principals
         */
        if (ied->ipa_user && ied->passwd) {
            kerr = ipadb_get_ldap_mod_str(imods, "userPassword",
                                          ied->passwd, mod_op);
            if (kerr) {
                goto done;
            }

            /* Also set new password expiration time.
             * Have to do it here because kadmin doesn't know policies and
             * resets entry->mask after we have gone through the password
             * change code.  */
            kerr = ipadb_get_pwd_expiration(kcontext, entry,
                                            ied, &expire_time);
            if (kerr) {
                goto done;
            }

            kerr = ipadb_get_ldap_mod_time(imods,
                                           "krbPasswordExpiration",
                                           expire_time, mod_op);
            if (expire_time == 0) {
                kerr = ipadb_get_ldap_mod_time(imods,
                                               "krbPasswordExpiration",
                                               expire_time, LDAP_MOD_DELETE);
            }

            if (kerr) {
                goto done;
            }
        }

        if (ied->ipa_user && ied->passwd &&
            ied->pol && ied->pol->history_length) {
            ret = ipapwd_generate_new_history(ied->passwd, now,
                                              ied->pol->history_length,
                                              ied->pw_history,
                                              &new_history, &nh_len);
            if (ret) {
                kerr = ret;
                goto done;
            }

            kerr = ipadb_get_ldap_mod_str_list(imods, "passwordHistory",
                                               new_history, nh_len, mod_op);

            for (i = 0; i < nh_len; i++) {
                free(new_history[i]);
            }
            free(new_history);

            if (kerr) {
                goto done;
            }
        }
    }

    kerr = 0;

done:
    free(req_auth_str);
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

    kerr = ipadb_entry_default_attrs(imods);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_principal_to_mods(kcontext, imods, principal, LDAP_MOD_ADD);
    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_entry_to_mods(kcontext, imods, entry, LDAP_MOD_ADD);
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
    struct ipadb_e_data *ied;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    kerr = new_ipadb_mods(&imods);
    if (kerr) {
        goto done;
    }

    ied = (struct ipadb_e_data *)entry->e_data;
    if (!ied || !ied->entry_dn) {
        kerr = krb5_unparse_name(kcontext, entry->princ, &principal);
        if (kerr != 0) {
            goto done;
        }

        kerr = ipadb_fetch_principals(ipactx, 0, principal, &res);
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

        kerr = ipadb_principal_to_mods(kcontext, imods, principal,
                                       LDAP_MOD_REPLACE);
        if (kerr != 0) {
            goto done;
        }

    }

    kerr = ipadb_entry_to_mods(kcontext, imods, entry, LDAP_MOD_REPLACE);
    if (kerr != 0) {
        goto done;
    }

    if (!ied || !ied->entry_dn) {
        kerr = ipadb_simple_modify(ipactx, dn, imods->mods);
    } else {
        kerr = ipadb_simple_modify(ipactx, ied->entry_dn, imods->mods);
    }

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

    kerr = ipadb_fetch_principals(ipactx, 0, principal, &res);
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

#if KRB5_KDB_API_VERSION < 8
krb5_error_code ipadb_iterate(krb5_context kcontext,
                              char *match_entry,
                              int (*func)(krb5_pointer, krb5_db_entry *),
                              krb5_pointer func_arg)
#else
krb5_error_code ipadb_iterate(krb5_context kcontext,
                              char *match_entry,
                              int (*func)(krb5_pointer, krb5_db_entry *),
                              krb5_pointer func_arg, krb5_flags iterflags)
#endif
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

    /* If no match_entry is given iterate through all krb princs like the db2
     * or ldap plugin */
    if (match_entry == NULL) {
        match_entry = "*";
    }

    /* fetch list of principal matching filter */
    kerr = ipadb_fetch_principals(ipactx, 0, match_entry, &res);
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

