/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2017 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <errno.h>
//#include <krb5/certauth_plugin.h>
#include <sss_certmap.h>

#include "ipa_krb5.h"
#include "ipa_kdb.h"

#define IPA_OC_CERTMAP_RULE "ipaCertMapRule"
#define IPA_CERTMAP_MAPRULE "ipaCertMapMapRule"
#define IPA_CERTMAP_MATCHRULE "ipaCertMapMatchRule"
#define IPA_CERTMAP_PRIORITY "ipaCertMapPriority"
#define IPA_ENABLED_FLAG "ipaEnabledFlag"
#define IPA_TRUE_VALUE "TRUE"
#define IPA_ASSOCIATED_DOMAIN "associatedDomain"

#define OBJECTCLASS "objectClass"

#define CERTMAP_FILTER "(&("OBJECTCLASS"="IPA_OC_CERTMAP_RULE")" \
                              "("IPA_ENABLED_FLAG"="IPA_TRUE_VALUE"))"

#define DEFAULT_CERTMAP_LIFETIME 300

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif


struct krb5_certauth_moddata_st {
    char *local_domain;
    struct sss_certmap_ctx *sss_certmap_ctx;
    struct ipadb_context *ipactx;
    time_t valid_until;
};

void ipa_certmap_debug(void *private,
                       const char *file, long line,
                       const char *function,
                       const char *format, ...)
{
    va_list ap;
    char str[255] = { 0 };

    va_start(ap, format);
    vsnprintf(str, sizeof(str)-1, format, ap);
    va_end(ap);
    krb5_klog_syslog(LOG_INFO, str);
}

void ipa_certauth_free_moddata(krb5_certauth_moddata *moddata)
{
    if (moddata == NULL || *moddata == NULL) {
        return;
    }

    free((*moddata)->local_domain);
    (*moddata)->local_domain = NULL;
    sss_certmap_free_ctx((*moddata)->sss_certmap_ctx);
    (*moddata)->sss_certmap_ctx = NULL;

    free(*moddata);

    return;
}

static krb5_error_code ipa_get_init_data(krb5_context kcontext,
                                         krb5_certauth_moddata moddata_out)
{
    int ret;
    struct sss_certmap_ctx *ctx = NULL;
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    char *basedn = NULL;
    LDAPMessage *result = NULL;
    LDAPMessage *le;
    LDAP *lc;
    size_t c;
    uint32_t prio;
    char *map_rule = NULL;
    char *match_rule = NULL;
    char **domains = NULL;

    const char *certmap_attrs[] = { OBJECTCLASS,
                                    IPA_CERTMAP_PRIORITY,
                                    IPA_CERTMAP_MATCHRULE,
                                    IPA_CERTMAP_MAPRULE,
                                    IPA_ASSOCIATED_DOMAIN,
                                    IPA_ENABLED_FLAG,
                                    NULL};


    krb5_klog_syslog(LOG_INFO, "Initializing IPA certauth plugin.");

    ipactx = ipadb_get_context(kcontext);
    if (ipactx == NULL || ipactx->magic != IPA_CONTEXT_MAGIC) {
        return KRB5_KDB_DBNOTINITED;
    }

    if (ipactx->certauth_moddata == NULL) {
        ipactx->certauth_moddata = moddata_out;

        if (ipactx->realm != NULL) {
            ipactx->certauth_moddata->local_domain = strdup(ipactx->realm);
            if (ipactx->certauth_moddata->local_domain == NULL) {
                free(ipactx->certauth_moddata);
                ipactx->certauth_moddata = NULL;
                ret = ENOMEM;
                goto done;
            }
        }

        ipactx->certauth_moddata->ipactx = ipactx;

    }

    ret = asprintf(&basedn, "cn=certmap,%s", ipactx->base);
    if (ret == -1) {
        return ENOMEM;
    }

    kerr = ipadb_simple_search(ipactx,basedn, LDAP_SCOPE_SUBTREE,
                               CERTMAP_FILTER, discard_const(certmap_attrs),
                               &result);
    if (kerr != 0 && kerr != KRB5_KDB_NOENTRY) {
        goto done;
    }

    ret = sss_certmap_init(NULL, ipa_certmap_debug, NULL, &ctx);
    if (ret != 0) {
        return ret;
    }

    if (kerr == KRB5_KDB_NOENTRY) {
        ret = sss_certmap_add_rule(ctx, SSS_CERTMAP_MIN_PRIO,
                                   NULL, NULL, NULL);
        if (ret != 0) {
            goto done;
        }
    } else {
        lc = ipactx->lcontext;

        for (le = ldap_first_entry(lc, result); le;
                                             le = ldap_next_entry(lc, le)) {
            prio = SSS_CERTMAP_MIN_PRIO;
            ret = ipadb_ldap_attr_to_uint32(lc, le, IPA_CERTMAP_PRIORITY,
                                            &prio);
            if (ret != 0 && ret != ENOENT) {
                goto done;
            }

            free(map_rule);
            map_rule = NULL;
            ret = ipadb_ldap_attr_to_str(lc, le, IPA_CERTMAP_MAPRULE,
                                         &map_rule);
            if (ret != 0 && ret != ENOENT) {
                goto done;
            }

            free(match_rule);
            match_rule = NULL;
            ret = ipadb_ldap_attr_to_str(lc, le, IPA_CERTMAP_MATCHRULE,
                                         &match_rule);
            if (ret != 0 && ret != ENOENT) {
                goto done;
            }

            if (domains != NULL) {
                for (c = 0; domains[c] != NULL; c++) {
                    free(domains[c]);
                }
                free(domains);
                domains = NULL;
            }
            ret = ipadb_ldap_attr_to_strlist(lc, le, IPA_ASSOCIATED_DOMAIN,
                                             &domains);
            if (ret != 0 && ret != ENOENT) {
                goto done;
            }

            ret = sss_certmap_add_rule(ctx, prio, match_rule, map_rule,
                                       (const char **) domains);
            if (ret != 0) {
                goto done;
            }
        }
    }

    sss_certmap_free_ctx(ipactx->certauth_moddata->sss_certmap_ctx);
    ipactx->certauth_moddata->sss_certmap_ctx = ctx;
    ipactx->certauth_moddata->valid_until = time(NULL)
                                                 + DEFAULT_CERTMAP_LIFETIME;
    krb5_klog_syslog(LOG_DEBUG,
                     "Successfully updates certificate mapping rules.");

    ret = 0;

done:
    ldap_msgfree(result);
    free(basedn);
    free(map_rule);
    free(match_rule);
    if (domains != NULL) {
        for (c = 0; domains[c] != NULL; c++) {
            free(domains[c]);
        }
        free(domains);
        domains = NULL;
    }

    if (ret != 0) {
        sss_certmap_free_ctx(ctx);
    }

    return ret;
}

static krb5_error_code ipa_certauth_authorize(krb5_context context,
                                              krb5_certauth_moddata moddata,
                                              const uint8_t *cert,
                                              size_t cert_len,
                                              krb5_const_principal princ,
                                              const void *opts,
                                              const krb5_db_entry *db_entry,
                                              char ***authinds_out)
{
    char *cert_filter = NULL, **domains = NULL;
    int ret, flags = 0;
    size_t c;
    char *principal = NULL, **auth_inds = NULL;
    LDAPMessage *res = NULL;
    krb5_error_code kerr;
    LDAPMessage *lentry;

#ifdef KRB5_KDB_FLAG_ALIAS_OK
    flags = KRB5_KDB_FLAG_ALIAS_OK;
#endif

    if (moddata == NULL) {
        return KRB5_PLUGIN_NO_HANDLE;
    }

    if (moddata->sss_certmap_ctx == NULL || time(NULL) > moddata->valid_until) {
        kerr = ipa_get_init_data(context, moddata);
        if (kerr != 0) {
            krb5_klog_syslog(LOG_ERR, "Failed to init certmapping data");
            return KRB5_PLUGIN_NO_HANDLE;
        }
    }

    ret = krb5_unparse_name(context, db_entry->princ, &principal);
    if (ret != 0) {
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }
    krb5_klog_syslog(LOG_INFO, "Doing certauth authorize for [%s]", principal);

    ret = sss_certmap_get_search_filter(moddata->sss_certmap_ctx,
                                        cert, cert_len,
                                        &cert_filter, &domains);
    if (ret != 0) {
        if (ret == ENOENT) {
            ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        }
        goto done;
    }
    krb5_klog_syslog(LOG_INFO, "Got cert filter [%s]", cert_filter);

    /* If there are no domains assigned the rule will apply to the local
     * domain only. */
    if (domains != NULL) {

        if (moddata->local_domain == NULL) {
        /* We don't know our own domain name, in general this should not
         * happen. But to be fault tolerant we allow matching rule which
         * do not have a domain assigned. */

            ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
            goto done;
        }

        for (c = 0; domains[c] != NULL; c++) {
            if (strcasecmp(domains[c], moddata->local_domain) == 0) {
                break;
            }
        }

        /* Our domain was not in the list */
        if (domains[c] == NULL) {
            ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
            goto done;
        }
    }

    kerr = ipadb_fetch_principals_with_extra_filter(moddata->ipactx, flags,
                                                    principal, cert_filter,
                                                    &res);
    if (kerr != 0) {
        krb5_klog_syslog(LOG_ERR, "Search failed [%d]", kerr);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    kerr = ipadb_find_principal(context, flags, res, &principal, &lentry);
    if (kerr == KRB5_KDB_NOENTRY) {
        krb5_klog_syslog(LOG_INFO, "No matching entry found");
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    } else if (kerr != 0) {
        krb5_klog_syslog(LOG_ERR, "ipadb_find_principal failed [%d]", kerr);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /* Associate authentication indicator "pkinit" with the successful match.
     * SSSD interface doesn't give us a clue which rule did match
     * so there is nothing more to add here. */
    auth_inds = calloc(2, sizeof(char *));
    if (auth_inds != NULL) {
	ret = asprintf(&auth_inds[0], "pkinit");
	if (ret != -1) {
            auth_inds[1] = NULL;
            *authinds_out = auth_inds;
	} else {
	    free(auth_inds);
        }
    }

    /* TODO: add more tests ? */

    ret = 0;

done:
    sss_certmap_free_filter_and_domains(cert_filter, domains);
    krb5_free_unparsed_name(context, principal);
    ldap_msgfree(res);

    return ret;
}

static krb5_error_code ipa_certauth_init(krb5_context kcontext,
                                         krb5_certauth_moddata *moddata_out)
{
    struct krb5_certauth_moddata_st *certauth_moddata;

    certauth_moddata = calloc(1, sizeof(struct krb5_certauth_moddata_st));
    if (certauth_moddata == NULL) {
        return ENOMEM;
    }

    *moddata_out = certauth_moddata;

    return 0;
}

static void ipa_certauth_fini(krb5_context context,
                              krb5_certauth_moddata moddata_out)
{
    krb5_klog_syslog(LOG_INFO, "IPA certauth plugin un-loaded.");
    return;
}

static void ipa_certauth_free_indicator(krb5_context context,
                                        krb5_certauth_moddata moddata,
                                        char **authinds)
{
    size_t i = 0;

    if ((authinds == NULL) || (moddata == NULL)) {
	return;
    }

    for(i=0; authinds[i]; i++) {
	free(authinds[i]);
	authinds[i] = NULL;
    }

    free(authinds);
}


krb5_error_code certauth_ipakdb_initvt(krb5_context context,
                                          int maj_ver, int min_ver,
                                          krb5_plugin_vtable vtable)
{
    krb5_certauth_vtable vt;

    if (maj_ver != 1) {
        return KRB5_PLUGIN_VER_NOTSUPP;
    }

    vt = (krb5_certauth_vtable) vtable;

    vt->name = "ipakdb";
    vt->authorize = ipa_certauth_authorize;
    vt->init = ipa_certauth_init;
    vt->fini = ipa_certauth_fini;
    vt->free_ind = ipa_certauth_free_indicator;
    return 0;
}
