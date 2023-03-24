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

static krb5_error_code ipadb_match_acl(krb5_context kcontext,
                                       LDAPMessage *results,
                                       krb5_const_principal client,
                                       krb5_const_principal target)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    LDAPMessage *lentry;
    LDAPDerefRes *deref_results;
    LDAPDerefRes *dres;
    char *client_princ = NULL;
    char *target_princ = NULL;
    bool client_missing;
    bool client_found;
    bool target_found;
    bool is_constraint_delegation = false;
    size_t nrules = 0;
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    if ((client != NULL) && (target != NULL)) {
        kerr = krb5_unparse_name(kcontext, client, &client_princ);
        if (kerr != 0) {
            goto done;
        }
        kerr = krb5_unparse_name(kcontext, target, &target_princ);
        if (kerr != 0) {
            goto done;
        }
    } else {
        is_constraint_delegation = true;
    }

    lentry = ldap_first_entry(ipactx->lcontext, results);
    if (!lentry) {
        kerr = ENOENT;
        goto done;
    }

    /* the default is that we fail */
    kerr = ENOENT;

    while (lentry) {
        /* both client and target must be found in the same ACI */
        client_missing = true;
        client_found = false;
        target_found = false;

        ret = ipadb_ldap_deref_results(ipactx->lcontext, lentry,
                                       &deref_results);
        switch (ret) {
        case 0:
            for (dres = deref_results; dres; dres = dres->next) {
                nrules++;
                if (is_constraint_delegation) {
                    /*
                        Microsoft revised the S4U2Proxy rules for forwardable
                        tickets.  All S4U2Proxy operations require forwardable
                        evidence tickets, but S4U2Self should issue a
                        forwardable ticket if the requesting service has no
                        ok-to-auth-as-delegate bit but also no constrained
                        delegation privileges for traditional S4U2Proxy.
                        Implement these rules, extending the
                        check_allowed_to_delegate() DAL method so that the KDC
                        can ask if a principal has any delegation privileges.

                        Since target principal is NULL and client principal is
                        NULL in this case, we simply calculate number of rules associated
                        with the server principal to decide whether to deny forwardable bit
                    */
                    continue;
                }
                if (client_found == false &&
                    strcasecmp(dres->derefAttr, "ipaAllowToImpersonate") == 0) {
                    /* NOTE: client_missing is used to signal that the
                     * attribute was completely missing. This signals that
                     * ANY client is allowed to be impersonated.
                     * This logic is valid only for clients, not for targets */
                    client_missing = false;
                    client_found = ipadb_match_member(client_princ, dres);
                }
                if (target_found == false &&
                    strcasecmp(dres->derefAttr, "ipaAllowedTarget") == 0) {
                    target_found = ipadb_match_member(target_princ, dres);
                }
            }

            ldap_derefresponse_free(deref_results);
            break;
        case ENOENT:
            break;
        default:
            kerr = ret;
            goto done;
        }

        if ((client_found == true || client_missing == true) &&
            target_found == true) {
            kerr = 0;
            goto done;
        }

        lentry = ldap_next_entry(ipactx->lcontext, lentry);
    }

    if (nrules > 0) {
        kerr = 0;
    }

done:
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
    LDAPMessage *res = NULL;

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

    kerr = ipadb_get_delegation_acl(kcontext, srv_principal, &res);
    if (kerr) {
        goto done;
    }

    kerr = ipadb_match_acl(kcontext, res, client, proxy);
    if (kerr) {
        goto done;
    }

done:
    if (kerr) {
#if KRB5_KDB_DAL_MAJOR_VERSION < 9
        kerr = KRB5KDC_ERR_POLICY;
#else
        kerr = KRB5KDC_ERR_BADOPTION;
#endif
    }
    ipadb_free_principal(kcontext, proxy_entry);
    krb5_free_unparsed_name(kcontext, srv_principal);
    ldap_msgfree(res);
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
