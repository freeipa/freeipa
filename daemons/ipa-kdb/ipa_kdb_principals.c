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
#include "ipa_krb5.h"
#include <unicase.h>

/*
 * During TGS request search by ipaKrbPrincipalName (case-insensitive)
 * and krbPrincipalName (case-sensitive)
 */
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

#define PRINC_TGS_SEARCH_FILTER_WILD_EXTRA "(&(|(objectclass=krbprincipalaux)" \
                                               "(objectclass=krbprincipal)" \
                                               "(objectclass=ipakrbprincipal))" \
                                             "(|(ipakrbprincipalalias=*)" \
                                               "(krbprincipalname=*))" \
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
    "uid",
    "nsaccountlock",
    "passwordHistory",
    IPA_KRB_AUTHZ_DATA_ATTR,
    IPA_USER_AUTH_TYPE,
    "ipatokenRadiusConfigLink",
    "ipaIdpConfigLink",
    "ipaPassKey",
    "krbAuthIndMaxTicketLife",
    "krbAuthIndMaxRenewableAge",
    "ipaNTSecurityIdentifier",
    "ipaUniqueID",
    "memberPrincipal",

    "objectClass",
    NULL
};

static char *std_tktpolicy_attrs[] = {
    "krbmaxticketlife",
    "krbmaxrenewableage",
    "krbticketflags",
    "krbauthindmaxticketlife",
    "krbauthindmaxrenewableage",

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

#ifndef KRB5_KDB_SK_OPTIONAL_PAC_TKT_CHKSUM
#define KRB5_KDB_SK_OPTIONAL_PAC_TKT_CHKSUM "optional_pac_tkt_chksum"
#endif

#ifndef KRB5_KDB_SK_PAC_PRIVSVR_ENCTYPE
#define KRB5_KDB_SK_PAC_PRIVSVR_ENCTYPE "pac_privsvr_enctype"
#endif

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

static bool
is_tgs_princ(krb5_context kcontext, krb5_const_principal princ)
{
    krb5_data *primary;
    size_t l_tgs_name;

    if (2 != krb5_princ_size(kcontext, princ))
        return false;

    primary = krb5_princ_component(kcontext, princ, 0);

    l_tgs_name = strlen(KRB5_TGS_NAME);

    if (l_tgs_name != primary->length)
        return false;

    return 0 == memcmp(primary->data, KRB5_TGS_NAME, l_tgs_name);
}

static krb5_error_code
cmp_local_tgs_princ(krb5_context kcontext, const char *local_realm,
                   krb5_const_principal princ, bool *result)
{
    krb5_principal local_tgs_princ;
    size_t l_local_realm;
    krb5_error_code kerr;
    bool res;

    l_local_realm = strlen(local_realm);

    kerr = krb5_build_principal(kcontext, &local_tgs_princ,
                                l_local_realm, local_realm,
                                KRB5_TGS_NAME, local_realm, NULL);
    if (kerr)
        goto end;

    res = (bool) krb5_principal_compare(kcontext, local_tgs_princ, princ);

    if (result)
        *result = res;

end:
    krb5_free_principal(kcontext, local_tgs_princ);
    return kerr;
}

krb5_error_code ipadb_set_tl_data(krb5_db_entry *entry,
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
    if (count < 0) {
        ldap_memfree(dn);
        return;
    }

    /* Fetch the active token list. */
    kerr = ipadb_simple_search(ipactx, ipactx->base, LDAP_SCOPE_SUBTREE,
                               filter, (char**) attrs, &res);
    free(filter);
    filter = NULL;
    if (kerr != 0 || res == NULL)
        return;

    /* Count the number of active tokens. */
    count = ldap_count_entries(ipactx->lcontext, res);
    ldap_msgfree(res);

    /*
     * If there are no valid tokens then we need to remove the OTP flag,
     * unless OTP is the only auth type allowed...
     */
    if (count == 0) {
        /* Remove the OTP flag for now */
        *ua &= ~IPADB_USER_AUTH_OTP;

        if (*ua == 0) {
            /*
             * Ok, we "only" allow OTP, so if there is an expired/disabled
             * token then add back the OTP flag as the server will double
             * check the validity and reject the entire bind. Otherwise, this
             * is the first time the user is authenticating and the user
             * should be allowed to bind using its password
             */
            static const char *expired_ftmpl = "(&"
                "(objectClass=ipaToken)(ipatokenOwner=%s)"
                "(|(ipatokenNotAfter<=%s)(!(ipatokenNotAfter=*))"
                "(ipatokenDisabled=True))"
            ")";
            if (asprintf(&filter, expired_ftmpl, dn, datetime) < 0) {
                ldap_memfree(dn);
                return;
            }

            krb5_klog_syslog(LOG_INFO,
                "Entry (%s) does not have a valid token and only OTP "
                "authentication is supported, checking for expired tokens...",
                dn);

            kerr = ipadb_simple_search(ipactx, ipactx->base, LDAP_SCOPE_SUBTREE,
                                       filter, (char**) attrs, &res);
            free(filter);
            if (kerr != 0 || res == NULL) {
                ldap_memfree(dn);
                return;
            }

            if (ldap_count_entries(ipactx->lcontext, res) > 0) {
                /*
                 * Ok we only allow OTP, and there are expired/disabled tokens
                 * so add the OTP flag back, and the server will reject the
                 * bind
                 */
                krb5_klog_syslog(LOG_INFO,
                    "Entry (%s) does have an expired/disabled token so this "
                    "user can not fall through to password auth", dn);
                *ua |= IPADB_USER_AUTH_OTP;
            }
            ldap_msgfree(res);
        }
    }
    ldap_memfree(dn);
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
    else {
        /* OTP use implies presence of password in IPA LDAP,
         * this is incompatible with RADIUS proxy case where
         * a password in LDAP is not used anymore. */
        *ua &= ~IPADB_USER_AUTH_OTP;
    }

    if (vals != NULL)
        ldap_value_free_len(vals);
}

static void ipadb_validate_idp(struct ipadb_context *ipactx,
                               LDAPMessage *lentry,
                               enum ipadb_user_auth *ua)
{
    struct berval **vals;

    if (!(*ua & IPADB_USER_AUTH_IDP))
        return;

    /* Ensure that the user has a link to an IdP config. */
    vals = ldap_get_values_len(ipactx->lcontext, lentry,
                               "ipaIdpConfigLink");
    if (vals == NULL || vals[0] == NULL)
        *ua &= ~IPADB_USER_AUTH_IDP;

    if (vals != NULL)
        ldap_value_free_len(vals);
}

static void ipadb_validate_passkey(struct ipadb_context *ipactx,
                               LDAPMessage *lentry,
                               enum ipadb_user_auth *ua)
{
    struct berval **vals;

    if (!(*ua & IPADB_USER_AUTH_PASSKEY))
        return;

    /* Ensure that the user has a link to an IdP config. */
    vals = ldap_get_values_len(ipactx->lcontext, lentry,
                               "ipaPassKey");
    if (vals == NULL || vals[0] == NULL)
        *ua &= ~IPADB_USER_AUTH_PASSKEY;

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

    /* lcontext == NULL means ipadb_get_global_config() failed to load
     * global config and cleared the ipactx */
    if (ipactx->lcontext == NULL)
        return IPADB_USER_AUTH_NONE;

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
    ipadb_validate_idp(ipactx, lentry, &ua);
    ipadb_validate_passkey(ipactx, lentry, &ua);

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
        if (ret <= 0 || ret > (int) l) {
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

static void ipadb_parse_authind_policies(krb5_context kcontext,
                                         LDAP *lcontext,
                                         LDAPMessage *lentry,
                                         krb5_db_entry *entry,
                                         enum ipadb_user_auth ua)
{
    int result;
    int ret;
    struct ipadb_e_data *ied;
    const struct {
        char *attribute;
        enum ipadb_user_auth flag;
        enum ipadb_user_auth_idx idx;
    } life_authind_map[] = {
        {"krbAuthIndMaxTicketLife;otp",
         IPADB_USER_AUTH_OTP, IPADB_USER_AUTH_IDX_OTP},
        {"krbAuthIndMaxTicketLife;radius",
         IPADB_USER_AUTH_RADIUS, IPADB_USER_AUTH_IDX_RADIUS},
        {"krbAuthIndMaxTicketLife;pkinit",
         IPADB_USER_AUTH_PKINIT, IPADB_USER_AUTH_IDX_PKINIT},
        {"krbAuthIndMaxTicketLife;hardened",
         IPADB_USER_AUTH_HARDENED, IPADB_USER_AUTH_IDX_HARDENED},
        {"krbAuthIndMaxTicketLife;idp",
         IPADB_USER_AUTH_IDP, IPADB_USER_AUTH_IDX_IDP},
        {"krbAuthIndMaxTicketLife;passkey",
         IPADB_USER_AUTH_PASSKEY, IPADB_USER_AUTH_IDX_PASSKEY},
	    {NULL, IPADB_USER_AUTH_NONE, IPADB_USER_AUTH_IDX_MAX},
    }, age_authind_map[] = {
        {"krbAuthIndMaxRenewableAge;otp",
         IPADB_USER_AUTH_OTP, IPADB_USER_AUTH_IDX_OTP},
        {"krbAuthIndMaxRenewableAge;radius",
         IPADB_USER_AUTH_RADIUS, IPADB_USER_AUTH_IDX_RADIUS},
        {"krbAuthIndMaxRenewableAge;pkinit",
         IPADB_USER_AUTH_PKINIT, IPADB_USER_AUTH_IDX_PKINIT},
        {"krbAuthIndMaxRenewableAge;hardened",
         IPADB_USER_AUTH_HARDENED, IPADB_USER_AUTH_IDX_HARDENED},
        {"krbAuthIndMaxRenewableAge;idp",
         IPADB_USER_AUTH_IDP, IPADB_USER_AUTH_IDX_IDP},
        {"krbAuthIndMaxRenewableAge;passkey",
         IPADB_USER_AUTH_PASSKEY, IPADB_USER_AUTH_IDX_PASSKEY},
        {NULL, IPADB_USER_AUTH_NONE, IPADB_USER_AUTH_IDX_MAX},
    };

    ied = (struct ipadb_e_data *)entry->e_data;
    if (ied == NULL) {
        return;
    }

    for (size_t i = 0; life_authind_map[i].attribute != NULL; i++) {
        /* Only change max_life/max_renewable_life per indicator
         * if the value wasn't set yet. This function gets called twice:
         * - for the principal entry
         * - for the associated policy lookup */
        if ((ua & life_authind_map[i].flag) &&
            (ied->pol_limits[life_authind_map[i].idx].max_life == 0)) {

            ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                         life_authind_map[i].attribute,
                                         &result);
            if (ret == 0) {
                ied->pol_limits[life_authind_map[i].idx].max_life = result;
            }

            ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                         age_authind_map[i].attribute,
                                         &result);
            if (ret == 0) {
                ied->pol_limits[age_authind_map[i].idx].max_renewable_life = result;
            }
        }
    }
}


static krb5_error_code ipadb_parse_ldap_entry(krb5_context kcontext,
                                              char *principal,
                                              LDAPMessage *lentry,
                                              krb5_db_entry **kentry,
                                              uint32_t *polmask)
{
    const krb5_octet rad_string[] = "otp\0[{\"indicators\": [\"radius\"]}]";
    const krb5_octet otp_string[] = "otp\0[{\"indicators\": [\"otp\"]}]";
    const krb5_octet idp_string[] = "idp\0[{\"type\":\"oauth2\",\"indicators\": [\"idp\"]}]";
    const krb5_octet passkey_string[] = "passkey\0[{\"indicators\": [\"passkey\"]}]";
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
    char *uidstring;
    char **authz_data_list;
    char *princ_sid;
    char **acl_list;
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

    entry->magic = KRB5_KDB_MAGIC_NUMBER;
    entry->len = KRB5_KDB_V1_BASE_LENGTH;

    /* Get User Auth configuration. */
    ua = ipadb_get_user_auth(ipactx, lentry);

    /* ipadb_get_user_auth() calls into ipadb_get_global_config()
     * and that might fail, causing lcontext to become NULL */
    if (!ipactx->lcontext) {
        krb5_klog_syslog(LOG_INFO,
                         "No LDAP connection in ipadb_parse_ldap_entry(); retrying...\n");
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            krb5_klog_syslog(LOG_ERR,
                             "No LDAP connection on retry in ipadb_parse_ldap_entry()!\n");
            kerr = KRB5_KDB_INTERNAL_ERROR;
            goto done;
        }
    }

    /* If any code below would result in invalidating ipactx->lcontext,
     * lcontext must be updated with the new ipactx->lcontext value.
     * We rely on the fact that none of LDAP-parsing helpers does it. */
    lcontext = ipactx->lcontext;

    /* ignore mask for now */

    ret = ipadb_ldap_attr_to_int(lcontext, lentry,
                                 "krbTicketFlags", &result);
    if (ret == 0) {
        entry->attributes = result;
    }
    /* Since principal, global policy, and virtual ticket flags are combined,
     * they must always be resolved, except if we are in IPA setup mode (because
     * ticket policies and virtual ticket flags are irrelevant in this case). */
    if (!ipactx->override_restrictions)
        *polmask |= TKTFLAGS_BIT;

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
        /* Only set a principal's key if password or hardened auth can be used.
         * Otherwise the KDC would add pre-authentication methods to the
         * NEEDED_PREAUTH reply for AS-REQs which indicate the password
         * authentication is available. This might confuse applications like
         * e.g. SSSD which try to determine suitable authentication methods and
         * corresponding prompts with the help of MIT Kerberos' responder
         * interface which acts on the returned pre-authentication methods. A
         * typical example is enforced OTP authentication where of course keys
         * are available for the first factor but password authentication
         * should not be advertised by the KDC. */
        if (!(ua & (IPADB_USER_AUTH_PASSWORD | IPADB_USER_AUTH_HARDENED)) &&
            (ua != IPADB_USER_AUTH_NONE)) {
            /* This is the same behavior as ENOENT below. */
            ipa_krb5_free_key_data(res_key_data, result);
            break;
        }

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
        if (1 == krb5_princ_size(kcontext, entry->princ)) {
            /* A principal must be a POSIX account AND have only one element to
             * be considered a user (this is to filter out CIFS principals). */
            ied->ipa_user = true;
        }

        ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                     "uid", &uidstring);
        if (ret != 0 && ret != ENOENT) {
            kerr = ret;
            goto done;
        }
        ied->user = uidstring;
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

        ied->last_pwd_change = krb5_ts2tt(restime);
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

        ied->last_admin_unlock = krb5_ts2tt(restime);
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
    } else if (ua & IPADB_USER_AUTH_IDP) {
        kerr = ipadb_set_tl_data(entry, KRB5_TL_STRING_ATTRS,
                                 sizeof(idp_string), idp_string);
        if (kerr)
            goto done;
    } else if (ua & IPADB_USER_AUTH_PASSKEY) {
        kerr = ipadb_set_tl_data(entry, KRB5_TL_STRING_ATTRS,
                                 sizeof(passkey_string), passkey_string);
        if (kerr)
            goto done;
    }

    if (ua & ~IPADB_USER_AUTH_NONE) {
        ipadb_parse_authind_policies(kcontext, lcontext, lentry, entry, ua);
    }

    /* Add SID if it is associated with the principal account */
    ied->has_sid = false;
    ied->sid = NULL;
    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTSecurityIdentifier", &princ_sid);
    if (ret == 0 && princ_sid != NULL) {
        alloc_sid(&ied->sid);
        if (ied->sid == NULL) {
            kerr = KRB5_KDB_INTERNAL_ERROR;
            free(princ_sid);
            goto done;
        }
        ret = ipadb_string_to_sid(princ_sid, ied->sid);
        free(princ_sid);
        if (ret != 0) {
            kerr = ret;
            goto done;
        }
        ied->has_sid = true;
    }

    /* check if it has the serviceDelegation objectclass */
    ret = ipadb_ldap_attr_has_value(lcontext, lentry,
                                    "objectClass", "resourceDelegation");
    if (ret != 0 && ret != ENOENT) {
        kerr = ret;
        goto done;
    }
    if (ret == 0) {
        ret = ipadb_ldap_attr_to_strlist(lcontext, lentry,
                                        "memberPrincipal", &acl_list);
        if (ret != 0 && ret != ENOENT) {
            kerr = KRB5_KDB_INTERNAL_ERROR;
            goto done;
        }
        if (ret == 0) {
            kerr = ipadb_set_tl_data(entry, KRB5_TL_CONSTRAINED_DELEGATION_ACL,
                                     sizeof(acl_list),
                                     (const krb5_octet *) &acl_list);
            if (kerr) {
                goto done;
            }
        }
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
    char *src_filter = NULL, *esc_original_princ = NULL;
    int ret;
    int len = 0;

    if (!ipactx->lcontext) {
        ret = ipadb_get_connection(ipactx);
        if (ret != 0) {
            kerr = KRB5_KDB_SERVER_INTERNAL_ERR;
            goto done;
        }
    }

    /* Escape filter but do not touch '*' as this function accepts
     * wildcards in names. */
    esc_original_princ = ipadb_filter_escape(principal, false);
    if (!esc_original_princ) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    len = strlen(esc_original_princ);

    /* Starting in DAL 8.0, aliases are always okay. */
#ifdef KRB5_KDB_FLAG_ALIAS_OK
    if (!(flags & KRB5_KDB_FLAG_ALIAS_OK)) {
        ret = asprintf(&src_filter, PRINC_SEARCH_FILTER_EXTRA,
                       esc_original_princ,
                       filter ? filter : "");
    } else
#endif
    {
        /* In case we've got a principal name as '*', we don't need to specify
         * the principal itself, use pre-defined filter for a wild-card search.
         */
        if ((len == 1) && (esc_original_princ[0] == '*')) {
            ret = asprintf(&src_filter, PRINC_TGS_SEARCH_FILTER_WILD_EXTRA,
                           filter ? filter : "");
        } else {
            ret = asprintf(&src_filter, PRINC_TGS_SEARCH_FILTER_EXTRA,
                           esc_original_princ, esc_original_princ,
                           filter ? filter : "");
        }
    }

    if (ret == -1) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_simple_search(ipactx, ipactx->base, LDAP_SCOPE_SUBTREE,
                               src_filter, std_principal_attrs, result);
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
    struct berval **vals = NULL;
    int result;
    krb5_error_code ret;
    size_t princ_len = 0;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        ret = KRB5_KDB_DBNOTINITED;
        goto done;
    }

    princ_len = strlen(*principal);
    for (le = ldap_first_entry(ipactx->lcontext, res); le != NULL;
         le = ldap_next_entry(ipactx->lcontext, le)) {
        vals = ldap_get_values_len(ipactx->lcontext, le, "krbprincipalname");
        if (vals == NULL)
            continue;

        /* We need to check for a strict match as a '*' in the name may have
         * caused the ldap server to return multiple entries. */
        for (int i = 0; vals[i]; i++) {
#ifdef KRB5_KDB_FLAG_ALIAS_OK
            if ((flags & KRB5_KDB_FLAG_ALIAS_OK) == 0) {
                found = ((vals[i]->bv_len == princ_len) &&
                         strncmp(vals[i]->bv_val, *principal, vals[i]->bv_len) == 0);
                if (found)
                    break;

                continue;
            }
#endif

            /* The KDC will accept aliases when doing TGT lookup
             * (ref_tgt_again in do_tgs_req.c), so use case-insensitive
             * comparison. */
            if (ulc_casecmp(vals[i]->bv_val, vals[i]->bv_len, *principal,
                            princ_len, NULL, NULL, &result) != 0) {
                ret = KRB5_KDB_INTERNAL_ERROR;
                goto done;
            }
            if (result != 0)
                continue;

            /* Fix case on the incoming principal to ensure that a valid
             * name/alias is returned even if krbCanonicalName is not
             * present. */
            free(*principal);
            *principal = strndup(vals[i]->bv_val, vals[i]->bv_len);
            if (!*principal) {
                ret = KRB5_KDB_INTERNAL_ERROR;
                goto done;
            }
            princ_len = strlen(*principal);
            found = true;
            break;
        }

        ldap_value_free_len(vals);
        vals = NULL;
        if (!found) {
            continue;
        }

        /* We need to check if this is the canonical name. */
        vals = ldap_get_values_len(ipactx->lcontext, le, "krbcanonicalname");
        if (vals == NULL)
            break;

#ifdef KRB5_KDB_FLAG_ALIAS_OK
        /* If aliases aren't accepted by the KDC, use case-sensitive
         * comparison. */
        if ((flags & KRB5_KDB_FLAG_ALIAS_OK) == 0) {
            found = ((vals[0]->bv_len == strlen(*principal)) &&
                     strncmp(vals[0]->bv_val, *principal, vals[0]->bv_len) == 0);
            if (!found) {
                ldap_value_free_len(vals);
		vals = NULL;
                continue;
            }
        }
#endif

        free(*principal);
        *principal = strndup(vals[0]->bv_val, vals[0]->bv_len);
        if (!*principal) {
            ret = KRB5_KDB_INTERNAL_ERROR;
            goto done;
        }
        break;
    }

    if (!found || !le) {
        ret = KRB5_KDB_NOENTRY;
        goto done;
    }

    ret = 0;
    *entry = le;
done:
    if (vals)
        ldap_value_free_len(vals);

    return ret;
}

static krb5_error_code
are_final_tktflags(struct ipadb_context *ipactx, krb5_db_entry *entry,
                   bool *final_tktflags)
{
    krb5_error_code kerr;
    struct ipadb_e_data *ied;
    char *str = NULL;
    bool in_final_tktflags = false;

    kerr = ipadb_get_edata(entry, &ied);
    if (kerr)
        goto end;

    if (!ied->ipa_user) {
        kerr = 0;
        goto end;
    }

    kerr = krb5_dbe_get_string(ipactx->kcontext, entry,
                               IPA_KDB_STRATTR_FINAL_USER_TKTFLAGS, &str);
    if (kerr)
        goto end;

    in_final_tktflags = str && ipa_krb5_parse_bool(str);

end:
    if (final_tktflags)
        *final_tktflags = in_final_tktflags;

    krb5_dbe_free_string(ipactx->kcontext, str);
    return kerr;
}

static krb5_error_code
add_virtual_static_tktflags(struct ipadb_context *ipactx, krb5_db_entry *entry,
                            krb5_flags *tktflags)
{
    krb5_error_code kerr;
    krb5_flags vsflg;
    bool final_tktflags;
    const struct ipadb_global_config *gcfg;
    struct ipadb_e_data *ied;

    vsflg = IPA_KDB_TKTFLAGS_VIRTUAL_STATIC_MANDATORY;

    kerr = ipadb_get_edata(entry, &ied);
    if (kerr)
        goto end;

    kerr = are_final_tktflags(ipactx, entry, &final_tktflags);
    if (kerr)
        goto end;

    /* In practice, principal ticket flags cannot be final for SPNs. */
    if (!final_tktflags)
        vsflg |= ied->ipa_user ? IPA_KDB_TKTFLAGS_VIRTUAL_STATIC_DEFAULTS_USER
                               : IPA_KDB_TKTFLAGS_VIRTUAL_STATIC_DEFAULTS_SPN;

    if (!ied->ipa_user) {
        gcfg = ipadb_get_global_config(ipactx);
        if (gcfg && gcfg->disable_preauth_for_spns)
            vsflg &= ~KRB5_KDB_REQUIRES_PRE_AUTH;
    }

    if (tktflags)
        *tktflags |= vsflg;

end:
    return kerr;
}

static krb5_error_code
get_virtual_static_tktflags_mask(struct ipadb_context *ipactx,
                                 krb5_db_entry *entry, krb5_flags *mask)
{
    krb5_error_code kerr;
    krb5_flags flags = IPA_KDB_TKTFLAGS_VIRTUAL_MANAGED_ALL;

    kerr = add_virtual_static_tktflags(ipactx, entry, &flags);
    if (kerr)
        goto end;

    if (mask)
        *mask = ~flags;

    kerr = 0;

end:
    return kerr;
}

/* Add ticket flags from the global ticket policy if it exists, otherwise
 * succeed. If the global ticket policy is set, the "exists" parameter is set to
 * true. */
static krb5_error_code
add_global_ticket_policy_flags(struct ipadb_context *ipactx,
                               bool *gtpol_exists, krb5_flags *tktflags)
{
    krb5_error_code kerr;
    char *policy_dn;
    char *tktflags_attr[] = { "krbticketflags", NULL };
    LDAPMessage *res = NULL, *first;
    int ec, ldap_tktflags;
    bool in_gtpol_exists = false;

    ec = asprintf(&policy_dn, "cn=%s,cn=kerberos,%s", ipactx->realm,
                  ipactx->base);
    if (-1 == ec) {
        kerr = ENOMEM;
        goto end;
    }

    kerr = ipadb_simple_search(ipactx, policy_dn, LDAP_SCOPE_BASE,
                               "(objectclass=krbticketpolicyaux)",
                               tktflags_attr, &res);
    if (kerr) {
        if (KRB5_KDB_NOENTRY == kerr)
            kerr = 0;
        goto end;
    }

    first = ldap_first_entry(ipactx->lcontext, res);
    if (!first) {
        kerr = 0;
        goto end;
    }

    in_gtpol_exists = true;

    ec = ipadb_ldap_attr_to_int(ipactx->lcontext, first, "krbticketflags",
                                &ldap_tktflags);
    if (0 == ec && tktflags) {
        *tktflags |= (krb5_flags)ldap_tktflags;
    }

    kerr = 0;

end:
    if (gtpol_exists)
        *gtpol_exists = in_gtpol_exists;

    ldap_msgfree(res);
    free(policy_dn);
    return kerr;
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
    bool final_tktflags, has_local_tktpolicy = true;
    int result;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    kerr = are_final_tktflags(ipactx, entry, &final_tktflags);
    if (kerr)
        goto done;

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "krbticketpolicyreference", &policy_dn);
    switch (ret) {
    case 0:
        break;
    case ENOENT:
        /* If no principal ticket policy, fallback to the global one. */
        has_local_tktpolicy = false;
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
            struct ipadb_e_data *ied;

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
                /* If global ticket policy is being applied, set flags only if
                 * user principal ticket flags are not final. */
                if (has_local_tktpolicy || !final_tktflags) {
                    ret = ipadb_ldap_attr_to_int(ipactx->lcontext, first,
                                                 "krbticketflags", &result);
                    if (ret == 0)
                        entry->attributes |= result;
                }
            }

            ied = (struct ipadb_e_data *)entry->e_data;
            if (ied && ied->ipa_user == true) {
            /* Apply default policy to indicators, if any */
                if (ied->user_auth & ~IPADB_USER_AUTH_NONE) {
                    ipadb_parse_authind_policies(kcontext, ipactx->lcontext,
                                                first, entry, ied->user_auth);
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

        kerr = 0;
    }

    if (polmask & TKTFLAGS_BIT) {
        /* If the principal ticket flags were applied, then flags from the
         * global ticket policy has to be applied atop of them if user principal
         * ticket flags are not final. */
        if (has_local_tktpolicy && !final_tktflags) {
            kerr = add_global_ticket_policy_flags(ipactx, NULL,
                                                  &entry->attributes);
            if (kerr)
            goto done;
        }

        /* Virtual static ticket flags are set regardless of database content */
        kerr = add_virtual_static_tktflags(ipactx, entry, &entry->attributes);
        if (kerr)
            goto done;
    }

done:
    ldap_msgfree(res);
    free(policy_dn);
    return kerr;
}

static krb5_boolean is_request_for_us(krb5_context kcontext,
                                      krb5_principal local_tgs,
                                      krb5_const_principal search_for)
{
    krb5_boolean for_us;

    if (search_for == NULL) {
        return FALSE;
    }
    for_us = krb5_realm_compare(kcontext, local_tgs, search_for) ||
             krb5_principal_compare_any_realm(kcontext,
                                              local_tgs, search_for);
    return for_us;
}

static krb5_error_code dbget_princ(krb5_context kcontext,
                                   struct ipadb_context *ipactx,
                                   krb5_const_principal search_for,
                                   unsigned int flags,
                                   krb5_db_entry **entry)
{
    krb5_error_code kerr;
    char *principal = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    uint32_t pol;
    krb5_boolean check = FALSE;


#if defined(KRB5_KDB_FLAG_CLIENT)
    check = flags & KRB5_KDB_FLAG_CLIENT;
#else
    check = (flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) &&
            (flags & KRB5_KDB_FLAG_CANONICALIZE);
#endif

    if (check) {
        /* AS_REQ with canonicalization*/
        krb5_principal norm_princ = NULL;

        /* unparse the Kerberos principal without (our) outer realm. */
        kerr = krb5_unparse_name_flags(kcontext, search_for,
                                    KRB5_PRINCIPAL_UNPARSE_NO_REALM |
                                    KRB5_PRINCIPAL_UNPARSE_DISPLAY,
                                    &principal);
        if (kerr != 0) {
            goto done;
        }

        /* Re-parse the principal to normalize it. Innner realm becomes
        * the realm if present. If no inner realm, our default realm
        * will be used instead (as it was before). */
        kerr = krb5_parse_name(kcontext, principal, &norm_princ);
        if (kerr != 0) {
            goto done;
        }
        /* Unparse without escaping '@' and '/' because we are going to use them
        * in LDAP filters where escaping character '\' will be escaped and the
        * result will never match. */
        kerr = krb5_unparse_name_flags(kcontext, norm_princ,
                                    KRB5_PRINCIPAL_UNPARSE_DISPLAY, &principal);
        krb5_free_principal(kcontext, norm_princ);
    } else {
        /* Unparse without escaping '@' and '/' because we are going to use them
        * in LDAP filters where escaping character '\' will be escaped and the
        * result will never match. */
        kerr = krb5_unparse_name_flags(kcontext, search_for,
                                    KRB5_PRINCIPAL_UNPARSE_DISPLAY, &principal);
    }

    if (kerr != 0) {
        goto done;
    }

    kerr = ipadb_fetch_principals(ipactx, flags, principal, &res);
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

/* For krb5 1.19, there is no KRB5_KDB_FLAG_REFERRAL_OK, emulate it
 * See krb5 commit a441fbe329ebbd7775eb5d4ccc4a05eef370f08b */
#ifndef KRB5_KDB_FLAG_REFERRAL_OK
#ifdef KRB5_KDB_FLAG_CANONICALIZE
#define KRB5_KDB_FLAG_REFERRAL_OK KRB5_KDB_FLAG_CANONICALIZE
#endif
#endif

static krb5_error_code dbget_alias(krb5_context kcontext,
                                   struct ipadb_context *ipactx,
                                   krb5_const_principal search_for,
                                   unsigned int flags,
                                   krb5_db_entry **entry)
{
    krb5_error_code kerr = 0;
    char *principal = NULL;
    krb5_principal norm_princ = NULL;
    char *trusted_realm = NULL;
    krb5_db_entry *kentry = NULL;
    krb5_data *realm;
    krb5_boolean check = FALSE;
    /* KRB5_NT_PRINCIPAL must be the last element */
    krb5_int32 supported_types[] = {
        [0] = KRB5_NT_ENTERPRISE_PRINCIPAL,
        [1] = KRB5_NT_PRINCIPAL,
        -1,
    };
    size_t i = 0;
    const char *stmsg = NULL;

    /* For TGS-REQ server principal lookup, KDC asks with KRB5_KDB_FLAG_REFERRAL_OK
     * and client usually asks for an KRB5_NT_PRINCIPAL type principal. */
    if ((flags & KRB5_KDB_FLAG_REFERRAL_OK) == 0) {
       /* this is *not* TGS-REQ server principal search, remove
	* KRB5_NT_PRINCIPAL from the supported principal types for this lookup */
       supported_types[(sizeof(supported_types) / sizeof(supported_types[0])) - 2] = -1;
    }

    /* Enterprise principal name type is for potential aliases or principals
     * from trusted realms. Except for the TGS-REQ server lookup, we only
     * expect enterprise principals here */
    for (i = 0; supported_types[i] != -1; i++) {
        if (krb5_princ_type(kcontext, search_for) == supported_types[i]) {
            break;
        }
    }

    if (supported_types[i] == -1) {
        return KRB5_KDB_NOENTRY;
    }

    /* enterprise principal can only have single component in the name
     * according to RFC6806 section 5. */
    if ((krb5_princ_type(kcontext, search_for) == KRB5_NT_ENTERPRISE_PRINCIPAL) &&
        (krb5_princ_size(kcontext, search_for) != 1)) {
        return KRB5_KDB_NOENTRY;
    }

    /* unparse the Kerberos principal without (our) outer realm. */
    kerr = krb5_unparse_name_flags(kcontext, search_for,
                                   KRB5_PRINCIPAL_UNPARSE_NO_REALM |
                                   KRB5_PRINCIPAL_UNPARSE_DISPLAY,
                                   &principal);
    if (kerr != 0) {
        goto done;
    }

    /* Re-parse the principal to normalize it. Innner realm becomes
     * the realm if present. If no inner realm, our default realm
     * will be used instead (as it was before). */
    kerr = krb5_parse_name(kcontext, principal, &norm_princ);
    if (kerr != 0) {
        goto done;
    }

    if (krb5_realm_compare(kcontext, ipactx->local_tgs, norm_princ)) {
        /* In realm alias, try to retrieve it and let the caller handle it. */
        kerr = dbget_princ(kcontext, ipactx, norm_princ, flags, entry);
    }

    /* if we haven't found the principal in our realm, it might still
     * be a referral to a known realm. Otherwise, bail out with the result */
    if ((kerr != KRB5_KDB_NOENTRY) &&
        (flags & KRB5_KDB_FLAG_REFERRAL_OK) == 0) {
        goto done;
    }

    /* The request is out of realm starting from here */

    /*
     * Per RFC6806 section 7 and 8, the canonicalize flag is required for
     * both client and server referrals. But it is more useful to ignore it
     * like Windows KDC does for client referrals.
     */
#if defined(KRB5_KDB_FLAG_CLIENT)
    check = ((flags & KRB5_KDB_FLAG_CLIENT) == 0) &&
            ((flags & KRB5_KDB_FLAG_REFERRAL_OK) == 0);
#else
    check = ((flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) == 0) &&
            ((flags & KRB5_KDB_FLAG_CANONICALIZE) == 0);
#endif
    if (check) {
        kerr = KRB5_KDB_NOENTRY;
        goto done;
    }

    /* Determine the trusted realm to refer to. We don't need the principal
     * itself, only its realm */
    realm = krb5_princ_realm(kcontext, norm_princ);
    kerr = ipadb_is_princ_from_trusted_realm(kcontext,
                                             realm->data,
                                             realm->length,
                                             &trusted_realm);
    if (kerr == KRB5_KDB_NOENTRY) {
        /* If no trusted realm found, refresh trusted domain data and try again
         * because it might be a freshly added trust to AD */
        kerr = ipadb_reinit_mspac(ipactx, false, &stmsg);
        if (kerr != 0) {
            if (stmsg)
                krb5_klog_syslog(LOG_WARNING, "MS-PAC generator: %s",
                                 stmsg);
            kerr = KRB5_KDB_NOENTRY;
            goto done;
        }
        kerr = ipadb_is_princ_from_trusted_realm(kcontext,
                                                 realm->data,
                                                 realm->length,
                                                 &trusted_realm);
    }

    if (kerr == KRB5_KDB_NOENTRY) {
        krb5_data *hstname = NULL;
        int ncomponents = krb5_princ_size(kcontext, norm_princ);

        /* We did not find any alias so far for non-server principal lookups */
        if ((ncomponents < 2) && ((flags & KRB5_KDB_FLAG_REFERRAL_OK) == 0)) {
            goto done;
        }

	/* At this point it is a server principal lookup that might be
         * referencing a host name in a trusted domain. It might also
         * have multiple service components so take the last one for the
         * hostname or the domain name. See MS-ADTS 2.2.21 and MS-DRSR 2.2.4.2.
         */
        hstname = krb5_princ_component(kcontext, norm_princ, ncomponents - 1);

        kerr = ipadb_is_princ_from_trusted_realm(kcontext,
                                                 hstname->data,
                                                 hstname->length,
                                                 &trusted_realm);
    }

    if (kerr != 0) {
        kerr = KRB5_KDB_NOENTRY;
        goto done;
    }

    /* This is a known trusted realm. Issue a referral depending on whether this
     * is client or server referral request */
#if defined(KRB5_KDB_FLAG_CLIENT)
    check = (flags & KRB5_KDB_FLAG_CLIENT) && (flags & KRB5_KDB_FLAG_REFERRAL_OK);
#else
    check = (flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) &&
            ((flags & KRB5_KDB_FLAG_CANONICALIZE) ||
              search_for->type == KRB5_NT_ENTERPRISE_PRINCIPAL);
#endif

    if (check) {
        /* client referral out of realm, set next realm. */
        kerr = krb5_set_principal_realm(kcontext, norm_princ, trusted_realm);
        if (kerr != 0) {
            goto done;
        }
        kentry = calloc(1, sizeof(krb5_db_entry));
        if (!kentry) {
            kerr = ENOMEM;
            goto done;
        }

        kentry->princ = norm_princ;
        norm_princ = NULL;
        *entry = kentry;

        goto done;
    }

#if defined(KRB5_KDB_FLAG_CLIENT)
    check = flags & KRB5_KDB_FLAG_CLIENT;
#else
    check = flags & KRB5_KDB_FLAG_INCLUDE_PAC;
#endif
    if (check) {
        /* TGS request where KDC wants to generate PAC
         * but the principal is out of our realm */
        kerr = KRB5_KDB_NOENTRY;
        goto done;
    }

    /* server referrals: lookup krbtgt/next_realm@our_realm */

    krb5_free_principal(kcontext, norm_princ);
    norm_princ = NULL;
    kerr = krb5_build_principal_ext(kcontext, &norm_princ,
                                    strlen(ipactx->realm),
                                    ipactx->realm,
                                    KRB5_TGS_NAME_SIZE,
                                    KRB5_TGS_NAME,
                                    strlen(trusted_realm),
                                    trusted_realm, 0);
    if (kerr != 0) {
        goto done;
    }

    kerr = dbget_princ(kcontext, ipactx, norm_princ, flags, entry);

done:
    free(trusted_realm);
    krb5_free_principal(kcontext, norm_princ);
    krb5_free_unparsed_name(kcontext, principal);

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
    bool is_local_tgs_princ;
    const char *opt_pac_tkt_chksum_val;
    krb5_error_code kerr;

    *entry = NULL;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    if (!is_request_for_us(kcontext, ipactx->local_tgs, search_for)) {
        return KRB5_KDB_NOENTRY;
    }

    /* Lookup local names and aliases first. */
    kerr = dbget_princ(kcontext, ipactx, search_for, flags, entry);
    if (kerr == KRB5_KDB_NOENTRY) {
        kerr = dbget_alias(kcontext, ipactx, search_for, flags, entry);
    }
    if (kerr)
        return kerr;

    /* If TGS principal, some virtual attributes may be added */
    if (is_tgs_princ(kcontext, (*entry)->princ)) {
        kerr = cmp_local_tgs_princ(kcontext, ipactx->realm, (*entry)->princ,
                                   &is_local_tgs_princ);
        if (kerr)
            return kerr;

        /* for trusted AD forests we currently must use SHA-1-based
         * encryption types. For details, see
         * https://github.com/krb5/krb5/commit/5af907156f8f502bbe268f0c62274f88a61261e4
         */
        if (!is_local_tgs_princ) {
            kerr = krb5_dbe_set_string(kcontext, *entry,
                                       KRB5_KDB_SK_PAC_PRIVSVR_ENCTYPE,
                                       "aes256-sha1");
            if (kerr)
                return kerr;

        }

        /* We should have been initialized at this point already */
        if (ipactx->optional_pac_tkt_chksum == IPADB_TRISTATE_UNDEFINED) {
                return KRB5_KDB_SERVER_INTERNAL_ERR;
        }
        /* PAC ticket signature should be optional for foreign realms, and local
         * realm if not supported by all servers
         */
        if (!is_local_tgs_princ || ipactx->optional_pac_tkt_chksum)
            opt_pac_tkt_chksum_val = "true";
        else
            opt_pac_tkt_chksum_val = "false";

        kerr = krb5_dbe_set_string(kcontext, *entry,
                                   KRB5_KDB_SK_OPTIONAL_PAC_TKT_CHKSUM,
                                   opt_pac_tkt_chksum_val);
    }

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
	free(ied->user);
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
	free_sid(&ied->sid);
	free(ied);
    }
}

void ipadb_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    krb5_tl_data *prev, *next;
    size_t i;

    if (entry) {
        krb5_free_principal(kcontext, entry->princ);
        prev = entry->tl_data;
        while(prev) {
            next = prev->tl_data_next;
            /* Handle RBCD ACL type */
            if (prev->tl_data_type == KRB5_TL_CONSTRAINED_DELEGATION_ACL) {
                char **acl_list = (char **) prev->tl_data_contents;
                for (i = 0; (acl_list != NULL) && (acl_list[i] != NULL); i++) {
                    free(acl_list[i]);
                }
                free(acl_list);
            }
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

krb5_error_code ipadb_get_tl_data(krb5_db_entry *entry,
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

/* Use LDAP REPLACE operation to remove an attribute.
 * Contrary to the DELETE operation, it will not fail if the attribute does not
 * exist. */
static krb5_error_code
ipadb_ldap_replace_remove(struct ipadb_mods *imods, char *attribute)
{
    krb5_error_code kerr;
    LDAPMod *m = NULL;

    kerr = ipadb_mods_new(imods, &m);
    if (kerr)
        return kerr;

    m->mod_op = LDAP_MOD_REPLACE;
    m->mod_type = strdup(attribute);
    if (!m->mod_type) {
        kerr = ENOMEM;
        goto end;
    }

    m->mod_values = NULL;

    kerr = 0;

end:
    if (kerr)
        ipadb_mods_free_tip(imods);
    return kerr;
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

    timeval = krb5_ts2tt(value);
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

static bool should_filter_out_attr(krb5_tl_data *data)
{
    switch (data->tl_data_type) {
        case KRB5_TL_CONSTRAINED_DELEGATION_ACL:
        case KRB5_TL_DB_ARGS:
        case KRB5_TL_KADM_DATA:
        case KRB5_TL_LAST_ADMIN_UNLOCK:
        case KRB5_TL_LAST_PWD_CHANGE:
        case KRB5_TL_MKVNO:
            return true;
        default:
            return false;
    }
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
        if (should_filter_out_attr(data))
            continue;
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

        if (should_filter_out_attr(data))
            continue;

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
    size_t i = 0;

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

static krb5_error_code
update_tktflags(krb5_context kcontext, struct ipadb_mods *imods,
                krb5_db_entry *entry, int mod_op)
{
    krb5_error_code kerr;
    struct ipadb_context *ipactx;
    struct ipadb_e_data *ied;
    bool final_tktflags;
    krb5_flags tktflags_mask;
    int tktflags;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto end;
    }

    if (ipactx->override_restrictions) {
        /* In IPA setup mode, IPA edata might not be available. In this mode,
         * ticket flags are written as they are provided. */
        tktflags = (int)entry->attributes;
    } else {
        kerr = ipadb_get_edata(entry, &ied);
        if (kerr)
            goto end;

        kerr = get_virtual_static_tktflags_mask(ipactx, entry, &tktflags_mask);
        if (kerr)
            goto end;

        kerr = are_final_tktflags(ipactx, entry, &final_tktflags);
        if (kerr)
            goto end;

        /* Flags from the global ticket policy are filtered out only if the user
         * principal flags are not final. */
        if (!final_tktflags) {
            krb5_flags gbl_tktflags = 0;

            kerr = add_global_ticket_policy_flags(ipactx, NULL, &gbl_tktflags);
            if (kerr)
                goto end;

            tktflags_mask &= ~gbl_tktflags;
        }

        tktflags = (int)(entry->attributes & tktflags_mask);

        if (LDAP_MOD_REPLACE == mod_op && ied && !ied->has_tktpolaux) {
            if (0 == tktflags) {
                /* No point initializing principal ticket policy if there are no
                 * flags left after filtering out virtual and global ticket
                 * policy ones. */
                kerr = 0;
                goto end;
            }

            /* if the object does not have the krbTicketPolicyAux class
             * we need to add it or this will fail, only for modifications.
             * We always add this objectclass by default when doing an add
             * from scratch. */
            kerr = ipadb_get_ldap_mod_str(imods, "objectclass",
                                          "krbTicketPolicyAux", LDAP_MOD_ADD);
            if (kerr)
                goto end;
        }
    }

    if (tktflags != 0) {
        kerr = ipadb_get_ldap_mod_int(imods, "krbTicketFlags", tktflags,
                                      mod_op);
        if (kerr)
            goto end;
    } else if (LDAP_MOD_REPLACE == mod_op) {
        /* If the principal is not being created, and there are no custom ticket
         * flags to be set, remove the "krbTicketFlags" attribute. */
        kerr = ipadb_ldap_replace_remove(imods, "krbTicketFlags");
        if (kerr)
            goto end;
    }

    kerr = 0;

end:
    return kerr;
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
        kerr = update_tktflags(kcontext, imods, entry, mod_op);
        if (kerr)
            goto done;
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
    size_t i;

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

static krb5_error_code
remove_virtual_str_attrs(krb5_context kcontext, krb5_db_entry *entry)
{
    char *str_attr_val;
    krb5_error_code kerr;
    const char *str_attrs[] = {
        KRB5_KDB_SK_OPTIONAL_PAC_TKT_CHKSUM,
        KRB5_KDB_SK_PAC_PRIVSVR_ENCTYPE,
        NULL};

    for(int i = 0; str_attrs[i] != NULL; i++) {
        kerr = krb5_dbe_get_string(kcontext, entry,
                                   str_attrs[i],
                                   &str_attr_val);
        if (kerr)
            return kerr;

        if (str_attr_val)
            kerr = krb5_dbe_set_string(kcontext, entry,
                                       str_attrs[i],
                                       NULL);

        krb5_dbe_free_string(kcontext, str_attr_val);
    }
    return kerr;
}

krb5_error_code ipadb_put_principal(krb5_context kcontext,
                                    krb5_db_entry *entry,
                                    char **db_args)
{
    krb5_error_code kerr;

    kerr = remove_virtual_str_attrs(kcontext, entry);
    if (kerr)
        return kerr;

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
    unsigned int flags = 0;

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

#ifdef KRB5_KDB_FLAG_ALIAS_OK
    flags = KRB5_KDB_FLAG_ALIAS_OK;
#endif
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

