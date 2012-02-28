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
    char *filter = NULL;
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

    /* == Search ACL info == */
    kerr = ipadb_deref_search(ipactx, ipactx->base,
                              LDAP_SCOPE_SUBTREE, filter, acl_attrs,
                              search_attrs, acl_attrs, results);

done:
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
    int ret;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    kerr = krb5_unparse_name(kcontext, client, &client_princ);
    if (kerr != 0) {
        goto done;
    }
    kerr = krb5_unparse_name(kcontext, target, &target_princ);
    if (kerr != 0) {
        goto done;
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
    krb5_error_code kerr;
    char *srv_principal = NULL;
    LDAPMessage *res = NULL;

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
    krb5_free_unparsed_name(kcontext, srv_principal);
    ldap_msgfree(res);
    return kerr;
}
