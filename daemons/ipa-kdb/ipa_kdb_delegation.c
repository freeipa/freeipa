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
#include <strings.h>
#include <unicase.h>

static char *acl_attrs[] = {
    "objectClass",
    "memberPrincipal",
    NULL
};

static char *search_attrs[] = {
    "ipaAllowToImpersonate",
    "ipaAllowedTarget",
    NULL
};

static krb5_error_code ipadb_get_delegation_acl(krb5_context kcontext,
                                                char *srv_principal,
                                                LDAPMessage **results)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *filter = NULL, *basedn = NULL;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    ret = asprintf(&filter,
                   "(&(objectclass=ipaKrb5DelegationACL)"
                     "(memberPrincipal=%s))", srv_principal);
    if (ret == -1) {
        kerr = ENOMEM;
        goto done;
    }

    ret = asprintf(&basedn,
                   "cn=s4u2proxy,cn=etc,%s", ipactx->base);
    if (ret == -1) {
        kerr = ENOMEM;
        goto done;
    }

    /* == Search ACL info == */
    kerr = ipadb_deref_search(ipactx, basedn,
                              LDAP_SCOPE_SUBTREE, filter, acl_attrs,
                              search_attrs, acl_attrs, results);

done:
    free(basedn);
    free(filter);
    return kerr;
}

static bool ipadb_match_member(char *princ, LDAPDerefRes *dres)
{
    LDAPDerefVal *dval;
    int i;

    for (dval = dres->attrVals; dval; dval = dval->next) {
        if (strcasecmp(dval->type, "memberPrincipal") != 0) {
            continue;
        }

        for (i = 0; dval->vals[i].bv_val != NULL; i++) {
            /* FIXME: use utf8 aware comparison ? */
            /* FIXME: support wildcards ? */
            if (strncasecmp(princ, dval->vals[i].bv_val,
                                    dval->vals[i].bv_len) == 0) {
                return true;
            }
        }
    }

    return false;
}

#if KRB5_KDB_DAL_MAJOR_VERSION >= 9
static krb5_error_code
ipadb_has_acl(krb5_context kcontext, LDAPMessage *ldap_acl, bool *res)
{
    struct ipadb_context *ipactx;
    bool in_res = false;
    krb5_error_code kerr = 0;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx)
        return KRB5_KDB_DBNOTINITED;

    switch (ldap_count_entries(ipactx->lcontext, ldap_acl)) {
    case 0:
        break;
    case -1:
        kerr = EINVAL;
        goto end;
    default:
        in_res = true;
        goto end;
    }

end:
    if (res)
        *res = in_res;

    return kerr;
}
#endif

static krb5_error_code
ipadb_match_acl(krb5_context kcontext, LDAPMessage *ldap_acl,
                krb5_const_principal client, krb5_const_principal target)
{
    struct ipadb_context *ipactx;
    LDAPMessage *rule;
    LDAPDerefRes *acis, *aci;
    char *client_princ = NULL, *target_princ= NULL;
    bool client_missing, client_found, target_found;
    int lerr;
    krb5_error_code kerr;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx)
        return KRB5_KDB_DBNOTINITED;

    kerr = krb5_unparse_name(kcontext, client, &client_princ);
    if (kerr)
        goto end;

    kerr = krb5_unparse_name(kcontext, target, &target_princ);
    if (kerr)
        goto end;

    /* the default is that we fail */
    kerr = KRB5KDC_ERR_BADOPTION;

    for (rule = ldap_first_entry(ipactx->lcontext, ldap_acl);
         rule;
         rule = ldap_next_entry(ipactx->lcontext, rule))
    {
        /* both client and target must be found in the same ACI */
        client_missing = true;
        client_found = false;
        target_found = false;

        lerr = ipadb_ldap_deref_results(ipactx->lcontext, rule, &acis);
        switch (lerr) {
        case 0:
            for (aci = acis; aci; aci = aci->next) {
                if (!client_found &&
                    0 == strcasecmp(aci->derefAttr, "ipaAllowToImpersonate"))
                {
                    /* NOTE: client_missing is used to signal that the
                     * attribute was completely missing. This signals that
                     * ANY client is allowed to be impersonated.
                     * This logic is valid only for clients, not for targets */
                    client_missing = false;
                    client_found = ipadb_match_member(client_princ, aci);
                }
                if (!target_found &&
                    0 == strcasecmp(aci->derefAttr, "ipaAllowedTarget"))
                {
                    target_found = ipadb_match_member(target_princ, aci);
                }
            }

            ldap_derefresponse_free(acis);
            break;
        case ENOENT:
            break;
        default:
            kerr = lerr;
            goto end;
        }

        if ((client_found || client_missing) && target_found) {
            kerr = 0;
            goto end;
        }
    }

end:
    krb5_free_unparsed_name(kcontext, client_princ);
    krb5_free_unparsed_name(kcontext, target_princ);
    return kerr;
}

/* Ok terminology is confusing here so read carefully:
 * here 'proxy' is the service for which 'server' wants a ticket on behalf of
 * 'client' */

krb5_error_code ipadb_check_allowed_to_delegate(krb5_context kcontext,
                                                krb5_const_principal client,
                                                const krb5_db_entry *server,
                                                krb5_const_principal proxy)
{
    krb5_error_code kerr, result;
    char *srv_principal = NULL;
    krb5_db_entry *proxy_entry = NULL;
    struct ipadb_e_data *ied_server, *ied_proxy;
    LDAPMessage *ldap_gcd_acl = NULL;

    if (proxy != NULL) {
        /* Handle the case where server == proxy, this is allowed in S4U */
        kerr = ipadb_get_principal(kcontext, proxy,
                                   CLIENT_REFERRALS_FLAGS,
                                   &proxy_entry);
        if (kerr) {
            goto done;
        }

        ied_server = (struct ipadb_e_data *) server->e_data;
        ied_proxy = (struct ipadb_e_data *) proxy_entry->e_data;

        /* If we have SIDs for both entries, compare SIDs */
        if ((ied_server->has_sid && ied_server->sid != NULL) &&
            (ied_proxy->has_sid && ied_proxy->sid != NULL)) {

            if (dom_sid_check(ied_server->sid, ied_proxy->sid, true)) {
                kerr = 0;
                goto done;
            }
        }

        /* Otherwise, compare entry DNs */
        kerr = ulc_casecmp(ied_server->entry_dn, strlen(ied_server->entry_dn),
                        ied_proxy->entry_dn, strlen(ied_proxy->entry_dn),
                        NULL, NULL, &result);
        if (kerr == 0 && result == 0) {
            goto done;
        }
    }

    kerr = krb5_unparse_name(kcontext, server->princ, &srv_principal);
    if (kerr) {
        goto done;
    }

    /* Load general constrained delegation rules */
    kerr = ipadb_get_delegation_acl(kcontext, srv_principal, &ldap_gcd_acl);
    if (kerr) {
        goto done;
    }

#if KRB5_KDB_DAL_MAJOR_VERSION >= 9
    /*
     * Microsoft revised the S4U2Proxy rules for forwardable tickets.  All
     * S4U2Proxy operations require forwardable evidence tickets, but
     * S4U2Self should issue a forwardable ticket if the requesting service
     * has no ok-to-auth-as-delegate bit but also no constrained delegation
     * privileges for traditional S4U2Proxy.  Implement these rules,
     * extending the check_allowed_to_delegate() DAL method so that the KDC
     * can ask if a principal has any delegation privileges.
     *
     * If target service principal is NULL, and the impersonating service has
     * at least one GCD rule, then succeed.
     */
    if (!proxy) {
        bool has_gcd_rules;

        kerr = ipadb_has_acl(kcontext, ldap_gcd_acl, &has_gcd_rules);
        if (!kerr)
            kerr = has_gcd_rules ? 0 : KRB5KDC_ERR_BADOPTION;
    } else if (client) {
#else
    if (client && proxy) {
#endif
        kerr = ipadb_match_acl(kcontext, ldap_gcd_acl, client, proxy);
    } else {
        /* client and/or proxy is missing */
        kerr = KRB5KDC_ERR_BADOPTION;
    }
    if (kerr)
        goto done;

done:
    if (kerr) {
#if KRB5_KDB_DAL_MAJOR_VERSION >= 9
        kerr = KRB5KDC_ERR_BADOPTION;
#else
        kerr = KRB5KDC_ERR_POLICY;
#endif
    }
    ipadb_free_principal(kcontext, proxy_entry);
    krb5_free_unparsed_name(kcontext, srv_principal);
    ldap_msgfree(ldap_gcd_acl);
    return kerr;
}


krb5_error_code ipadb_allowed_to_delegate_from(krb5_context context,
                                               krb5_const_principal client,
                                               krb5_const_principal server,
                                               krb5_pac server_pac,
                                               const krb5_db_entry *proxy)
{
    char **acl_list = NULL;
    krb5_error_code kerr;
    size_t i;

    kerr = ipadb_get_tl_data((krb5_db_entry *) proxy, KRB5_TL_CONSTRAINED_DELEGATION_ACL,
                             sizeof(acl_list), (krb5_octet *)&acl_list);

    if (kerr != 0 && kerr != ENOENT) {
        return KRB5KDC_ERR_BADOPTION;
    }

    if (kerr == ENOENT) {
        return KRB5_PLUGIN_OP_NOTSUPP;
    }

    kerr = KRB5KDC_ERR_BADOPTION;
    if (acl_list != NULL) {
        krb5_principal acl;
        for (i = 0; acl_list[i] != NULL; i++) {
            if (krb5_parse_name(context, acl_list[i], &acl) != 0)
                continue;
            if ((server == NULL) ||
                (krb5_principal_compare(context, server, acl) == TRUE)) {
                kerr = 0;
                krb5_free_principal(context, acl);
                break;
            }
            krb5_free_principal(context, acl);
        }
    }

    return kerr;
}
