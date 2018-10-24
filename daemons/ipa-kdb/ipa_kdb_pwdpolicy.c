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
#include "ipa_pwd.h"

#define POLICY_SEARCH_FILTER "(&(objectClass=krbPwdPolicy)(cn=%s))"

char *std_pwdpolicy_attrs[] = {
    "krbmaxpwdlife",
    "krbminpwdlife",
    "krbpwdmindiffchars",
    "krbpwdminlength",
    "krbpwdhistorylength",
    "krbpwdmaxfailure",
    "krbpwdfailurecountinterval",
    "krbpwdlockoutduration",

    NULL
};

krb5_error_code ipadb_get_ipapwd_policy(struct ipadb_context *ipactx,
                                        char *pw_policy_dn,
                                        struct ipapwd_policy **_pol)
{
    struct ipapwd_policy *pol;
    krb5_error_code kerr;
    LDAPMessage *res = NULL;
    LDAPMessage *lentry;
    uint32_t result;
    int ret;

    pol = calloc(1, sizeof(struct ipapwd_policy));
    if (!pol) {
        return ENOMEM;
    }

    pol->max_pwd_life = IPAPWD_DEFAULT_PWDLIFE;
    pol->min_pwd_length = IPAPWD_DEFAULT_MINLEN;

    kerr = ipadb_simple_search(ipactx, pw_policy_dn, LDAP_SCOPE_BASE,
                               "(objectClass=*)", std_pwdpolicy_attrs, &res);
    if (kerr) {
        goto done;
    }

    lentry = ldap_first_entry(ipactx->lcontext, res);
    if (!lentry) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbMinPwdLife", &result);
    if (ret == 0) {
        pol->min_pwd_life = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbMaxPwdLife", &result);
    if (ret == 0) {
        pol->max_pwd_life = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdMinLength", &result);
    if (ret == 0) {
        pol->min_pwd_length = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdHistoryLength", &result);
    if (ret == 0) {
        pol->history_length = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdMinDiffChars", &result);
    if (ret == 0) {
        pol->min_complexity = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdMaxFailure", &result);
    if (ret == 0) {
        pol->max_fail = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdFailureCountInterval", &result);
    if (ret == 0) {
        pol->failcnt_interval = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdLockoutDuration", &result);
    if (ret == 0) {
        pol->lockout_duration = result;
    }

    *_pol = pol;

done:
    ldap_msgfree(res);
    if (kerr) {
        free(pol);
    }
    return kerr;
}

krb5_error_code ipadb_create_pwd_policy(krb5_context kcontext,
                                        osa_policy_ent_t policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

krb5_error_code ipadb_get_pwd_policy(krb5_context kcontext, char *name,
                                     osa_policy_ent_t *policy)
{
    struct ipadb_context *ipactx;
    char *bases[3] = { NULL };
    char *esc_name = NULL;
    char *src_filter = NULL;
    krb5_error_code kerr;
    struct ipadb_multires *res = NULL;
    LDAPMessage *lentry;
    osa_policy_ent_t pentry = NULL;
    uint32_t result;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }
    bases[0] = ipactx->realm_base;
    bases[1] = ipactx->accounts_base;

    esc_name = ipadb_filter_escape(name, true);
    if (!esc_name) {
        return ENOMEM;
    }

    ret = asprintf(&src_filter, POLICY_SEARCH_FILTER, esc_name);
    if (ret == -1) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = ipadb_multibase_search(ipactx, bases, LDAP_SCOPE_SUBTREE,
                                  src_filter, std_pwdpolicy_attrs, &res,
                                  true);
    if (kerr) {
        goto done;
    }

    lentry = ipadb_multires_next_entry(res);
    if (!lentry) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    pentry = calloc(1, sizeof(osa_policy_ent_rec));
    if (!pentry) {
        kerr = ENOMEM;
        goto done;
    }
    pentry->version = 1;
    pentry->name = strdup(name);
    if (!pentry->name) {
        kerr = ENOMEM;
        goto done;
    }

    /* FIXME: what to do with missing attributes ? */

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbMinPwdLife", &result);
    if (ret == 0) {
        pentry->pw_min_life = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbMaxPwdLife", &result);
    if (ret == 0) {
        pentry->pw_max_life = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdMinLength", &result);
    if (ret == 0) {
        pentry->pw_min_length = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdMinDiffChars", &result);
    if (ret == 0) {
        pentry->pw_min_classes = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdHistoryLength", &result);
    if (ret == 0) {
        pentry->pw_history_num = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdMaxFailure", &result);
    if (ret == 0) {
        pentry->pw_max_fail = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdFailureCountInterval", &result);
    if (ret == 0) {
        pentry->pw_failcnt_interval = result;
    }

    ret = ipadb_ldap_attr_to_uint32(ipactx->lcontext, lentry,
                                    "krbPwdLockoutDuration", &result);
    if (ret == 0) {
        pentry->pw_lockout_duration = result;
    }

    ret = ipa_kstuples_to_string(ipactx->supp_encs, ipactx->n_supp_encs,
                                 &pentry->allowed_keysalts);
    if (ret != 0) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    *policy = pentry;

done:
    if (kerr) {
        free(pentry);
    }
    free(esc_name);
    free(src_filter);
    ipadb_multires_free(res);

    return kerr;
}

krb5_error_code ipadb_put_pwd_policy(krb5_context kcontext,
                                     osa_policy_ent_t policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

krb5_error_code ipadb_iterate_pwd_policy(krb5_context kcontext,
                                         char *match_entry,
                                         osa_adb_iter_policy_func func,
                                         void *data)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

krb5_error_code ipadb_delete_pwd_policy(krb5_context kcontext,
                                        char *policy)
{
    return KRB5_PLUGIN_OP_NOTSUPP;
}

void ipadb_free_pwd_policy(krb5_context kcontext, osa_policy_ent_t val)
{
    if (val) {
        free(val->name);
        free(val->allowed_keysalts);
        free(val);
    }
}

krb5_error_code ipadb_check_policy_as(krb5_context kcontext,
                                      krb5_kdc_req *request,
                                      krb5_db_entry *client,
                                      krb5_db_entry *server,
                                      krb5_timestamp kdc_time,
                                      const char **status,
                                      krb5_pa_data ***e_data)
{
    struct ipadb_context *ipactx;
    struct ipadb_e_data *ied;
    krb5_error_code kerr;

    if (!client) {
        return ENOENT;
    }

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return EINVAL;
    }

    ied = (struct ipadb_e_data *)client->e_data;
    if (!ied) {
        return EINVAL;
    }

    if (!ied->pol) {
        kerr = ipadb_get_ipapwd_policy(ipactx, ied->pw_policy_dn, &ied->pol);
        if (kerr != 0) {
            return kerr;
        }
    }

    if (client->last_failed <= ied->last_admin_unlock) {
        /* admin unlocked the account */
        return 0;
    }

    if (ied->pol->max_fail == 0 ||
        client->fail_auth_count < ied->pol->max_fail) {
        /* still within allowed failures range */
        return 0;
    }

    if (ied->pol->lockout_duration == 0 ||
        client->last_failed + ied->pol->lockout_duration > kdc_time) {
        /* ok client permanently locked, or within lockout period */
        *status = "LOCKED_OUT";
        return KRB5KDC_ERR_CLIENT_REVOKED;
    }

    return 0;
}
