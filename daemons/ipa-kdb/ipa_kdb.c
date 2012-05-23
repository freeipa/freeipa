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

struct ipadb_context *ipadb_get_context(krb5_context kcontext)
{
    void *db_ctx;
    krb5_error_code kerr;

    kerr = krb5_db_get_context(kcontext, &db_ctx);
    if (kerr != 0) {
        return NULL;
    }

    return (struct ipadb_context *)db_ctx;
}

static void ipadb_context_free(krb5_context kcontext,
                               struct ipadb_context **ctx)
{
    if (*ctx != NULL) {
        free((*ctx)->uri);
        /* ldap free lcontext */
        if ((*ctx)->lcontext) {
            ldap_unbind_ext_s((*ctx)->lcontext, NULL, NULL);
        }
        krb5_free_default_realm(kcontext, (*ctx)->realm);
        free(*ctx);
        *ctx = NULL;
    }
}

#define LDAPI_URI_PREFIX "ldapi://"
#define LDAPI_PATH_PREFIX "%2fslapd-"
#define SOCKET_SUFFIX ".socket"
#define APPEND_PATH_PART(pos, part) \
    do { \
        int partlen = strlen(part); \
        strncpy(pos, part, partlen + 1); \
        p += partlen; \
    } while (0)

static char *ipadb_realm_to_ldapi_uri(char *realm)
{
    char *uri = NULL;
    char *p;
    const char *q;
    int len;

    /* uri length, assume worst case for LDAPIDIR */
    len = strlen(LDAPI_URI_PREFIX) + strlen(LDAPIDIR) * 3
          + strlen(LDAPI_PATH_PREFIX) + strlen(realm)
          + strlen(SOCKET_SUFFIX) + 1;

    /* worst case they are all '/' to escape */
    uri = malloc(len);
    if (!uri) {
        return NULL;
    }
    p = uri;

    APPEND_PATH_PART(p, LDAPI_URI_PREFIX);

    /* copy path and escape '/' to '%2f' */
    for (q = LDAPIDIR; *q; q++) {
        if (*q == '/') {
            strncpy(p, "%2f", 3);
            p += 3;
        } else {
            *p = *q;
            p++;
        }
    }

    APPEND_PATH_PART(p, LDAPI_PATH_PREFIX);

    /* copy realm and convert '.' to '-' */
    for (q = realm; *q; q++) {
        if (*q == '.') {
            *p = '-';
        } else {
            *p = *q;
        }
        p++;
    }

    /* terminate string */
    APPEND_PATH_PART(p, SOCKET_SUFFIX);

    return uri;
}

/* in IPA the base is always derived from the realm name */
static char *ipadb_get_base_from_realm(krb5_context kcontext)
{
    krb5_error_code kerr;
    char *realm = NULL;
    char *base = NULL;
    char *tmp;
    size_t bi, ri;
    size_t len;

    kerr = krb5_get_default_realm(kcontext, &realm);
    if (kerr != 0) {
        return NULL;
    }

    bi = 3;
    len = strlen(realm) + 3 + 1;

    base = malloc(len);
    if (!base) {
        goto done;
    }
    strcpy(base, "dc=");

    /* convert EXAMPLE.COM in dc=example,dc=com */
    for (ri = 0; realm[ri]; ri++) {
        if (realm[ri] == '.') {
            len += 4;
            tmp = realloc(base, len);
            if (!tmp) {
                free(base);
                base = NULL;
                goto done;
            }
            base = tmp;
            strcpy(&base[bi], ",dc=");
            bi += 4;
        } else {
            base[bi] = tolower(realm[ri]);
            bi++;
        }
    }
    base[bi] = '\0';

done:
    krb5_free_default_realm(kcontext, realm);
    return base;
}

int ipadb_get_global_configs(struct ipadb_context *ipactx)
{
    char *attrs[] = { "ipaConfigString", NULL };
    struct berval **vals = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *first;
    char *base = NULL;
    int i;
    int ret;

    ret = asprintf(&base, "cn=ipaConfig,cn=etc,%s", ipactx->base);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    ret = ipadb_simple_search(ipactx, base, LDAP_SCOPE_BASE,
                              "(objectclass=*)", attrs, &res);
    if (ret) {
        goto done;
    }

    first = ldap_first_entry(ipactx->lcontext, res);
    if (!first) {
        /* no results, set nothing */
        ret = 0;
        goto done;
    }

    vals = ldap_get_values_len(ipactx->lcontext, first,
                               "ipaConfigString");
    if (!vals || !vals[0]) {
        /* no config, set nothing */
        ret = 0;
        goto done;
    }

    for (i = 0; vals[i]; i++) {
        if (strncasecmp("KDC:Disable Last Success",
                        vals[i]->bv_val, vals[i]->bv_len) == 0) {
            ipactx->disable_last_success = true;
            continue;
        }
        if (strncasecmp("KDC:Disable Lockout",
                        vals[i]->bv_val, vals[i]->bv_len) == 0) {
            ipactx->disable_lockout = true;
            continue;
        }
    }

    ret = 0;

done:
    ldap_value_free_len(vals);
    ldap_msgfree(res);
    free(base);
    return ret;
}

int ipadb_get_connection(struct ipadb_context *ipactx)
{
    struct berval **vals = NULL;
    struct timeval tv = { 5, 0 };
    LDAPMessage *res = NULL;
    LDAPMessage *first;
    krb5_key_salt_tuple *kst;
    int n_kst;
    int ret;
    int v3;
    int i;
    char **cvals = NULL;
    int c = 0;

    if (!ipactx->uri) {
        return EINVAL;
    }

    /* free existing conneciton if any */
    if (ipactx->lcontext) {
        ldap_unbind_ext_s(ipactx->lcontext, NULL, NULL);
        ipactx->lcontext = NULL;
    }

    ret = ldap_initialize(&ipactx->lcontext, ipactx->uri);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    /* make sure we talk LDAPv3 */
    v3 = LDAP_VERSION3;
    ret = ldap_set_option(ipactx->lcontext, LDAP_OPT_PROTOCOL_VERSION, &v3);
    if (ret != LDAP_OPT_SUCCESS) {
        goto done;
    }

    ret = ldap_set_option(ipactx->lcontext,  LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (ret != LDAP_OPT_SUCCESS) {
        goto done;
    }

    ret = ldap_set_option(ipactx->lcontext,  LDAP_OPT_TIMEOUT, &tv);
    if (ret != LDAP_OPT_SUCCESS) {
        goto done;
    }

    ret = ldap_sasl_bind_s(ipactx->lcontext,
                           NULL, "EXTERNAL",
                           NULL, NULL, NULL, NULL);
    if (ret != LDAP_SUCCESS) {
        goto done;
    }

    /* TODO: search rootdse */

    ret = ipadb_simple_search(ipactx,
                              ipactx->realm_base, LDAP_SCOPE_BASE,
                              "(objectclass=*)", NULL, &res);
    if (ret) {
        goto done;
    }

    first = ldap_first_entry(ipactx->lcontext, res);
    if (!first) {
        goto done;
    }

    vals = ldap_get_values_len(ipactx->lcontext, first,
                               "krbSupportedEncSaltTypes");
    if (!vals || !vals[0]) {
        goto done;
    }

    for (c = 0; vals[c]; c++) /* count */ ;
    cvals = calloc(c, sizeof(char *));
    if (!cvals) {
        ret = ENOMEM;
        goto done;
    }
    for (i = 0; i < c; i++) {
        cvals[i] = strndup(vals[i]->bv_val, vals[i]->bv_len);
        if (!cvals[i]) {
            ret = ENOMEM;
            goto done;
        }
    }

    ret = parse_bval_key_salt_tuples(ipactx->kcontext,
                                     (const char * const *)cvals, c,
                                     &kst, &n_kst);
    if (ret) {
        goto done;
    }

    if (ipactx->supp_encs) {
        free(ipactx->supp_encs);
    }
    ipactx->supp_encs = kst;
    ipactx->n_supp_encs = n_kst;

    /* get additional options */
    ret = ipadb_get_global_configs(ipactx);
    if (ret) {
        goto done;
    }

    /* get adtrust options */
    ret = ipadb_reinit_mspac(ipactx);
    if (ret && ret != ENOENT) {
        /* TODO: log that there is an issue with adtrust settings */
    }

    ret = 0;

done:
    ldap_msgfree(res);

    ldap_value_free_len(vals);
    for (i = 0; i < c && cvals[i]; i++) {
        free(cvals[i]);
    }
    free(cvals);

    if (ret) {
        if (ipactx->lcontext) {
            ldap_unbind_ext_s(ipactx->lcontext, NULL, NULL);
            ipactx->lcontext = NULL;
        }
        if (ret == LDAP_SERVER_DOWN) {
            return ETIMEDOUT;
        }
        return EIO;
    }

    return 0;
}

/* INTERFACE */

static krb5_error_code ipadb_init_library(void)
{
    return 0;
}

static krb5_error_code ipadb_fini_library(void)
{
    return 0;
}

static krb5_error_code ipadb_init_module(krb5_context kcontext,
                                         char *conf_section,
                                         char **db_args, int mode)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    int ret;
    int i;

    /* make sure the context is freed to avoid leaking it */
    ipactx = ipadb_get_context(kcontext);
    ipadb_context_free(kcontext, &ipactx);

    ipactx = calloc(1, sizeof(struct ipadb_context));
    if (!ipactx) {
        return ENOMEM;
    }

    /* only check for unsupported 'temporary' value for now */
    for (i = 0; db_args != NULL && db_args[i] != NULL; i++) {

        if (strncmp(db_args[i], IPA_SETUP, sizeof(IPA_SETUP)) == 0) {
            ipactx->override_restrictions = true;
        }

        if (strncmp(db_args[i], "temporary", 9) == 0) {
            krb5_set_error_message(kcontext, EINVAL,
                                   "Plugin requires -update argument!");
            ret = EINVAL;
            goto fail;
        }
    }

    ipactx->kcontext = kcontext;

    kerr = krb5_get_default_realm(kcontext, &ipactx->realm);
    if (kerr != 0) {
        ret = EINVAL;
        goto fail;
    }

    ipactx->uri = ipadb_realm_to_ldapi_uri(ipactx->realm);
    if (!ipactx->uri) {
        ret = ENOMEM;
        goto fail;
    }

    ipactx->base = ipadb_get_base_from_realm(kcontext);
    if (!ipactx->base) {
        ret = ENOMEM;
        goto fail;
    }

    ret = asprintf(&ipactx->realm_base, "cn=%s,cn=kerberos,%s",
                                        ipactx->realm, ipactx->base);
    if (ret == -1) {
        ret = ENOMEM;
        goto fail;
    }

    ret = ipadb_get_connection(ipactx);
    if (ret != 0) {
        /* not a fatal failure, as the LDAP server may be temporarily down */
        /* TODO: spam syslog with this error */
    }

    kerr = krb5_db_set_context(kcontext, ipactx);
    if (kerr != 0) {
        ret = EACCES;
        goto fail;
    }

    return 0;

fail:
    ipadb_context_free(kcontext, &ipactx);
    return ret;
}

static krb5_error_code ipadb_fini_module(krb5_context kcontext)
{
    struct ipadb_context *ipactx;

    ipactx = ipadb_get_context(kcontext);
    ipadb_context_free(kcontext, &ipactx);

    return 0;
}

static krb5_error_code ipadb_create(krb5_context kcontext,
                                    char *conf_section,
                                    char **db_args)
{
    return ipadb_init_module(kcontext, conf_section, db_args, 0);
}

static krb5_error_code ipadb_get_age(krb5_context kcontext,
                                     char *db_name, time_t *age)
{
    /* just return the current time for now,
     * until we can use persistent searches and have
     * a better estimate */
    *age = time(NULL);
    return 0;
}

static void *ipadb_alloc(krb5_context context, void *ptr, size_t size)
{
    return realloc(ptr, size);
}

static void ipadb_free(krb5_context context, void *ptr)
{
    free(ptr);
}

/* KDB Virtual Table */

kdb_vftabl kdb_function_table = {
    KRB5_KDB_DAL_MAJOR_VERSION,         /* major version number */
    0,                                  /* minor version number */
    ipadb_init_library,                 /* init_library */
    ipadb_fini_library,                 /* fini_library */
    ipadb_init_module,                  /* init_module */
    ipadb_fini_module,                  /* fini_module */
    ipadb_create,                       /* create */
    NULL,                               /* destroy */
    ipadb_get_age,                      /* get_age */
    NULL,                               /* lock */
    NULL,                               /* unlock */
    ipadb_get_principal,                /* get_principal */
    ipadb_free_principal,               /* free_principal */
    ipadb_put_principal,                /* put_principal */
    ipadb_delete_principal,             /* delete_principal */
    ipadb_iterate,                      /* iterate */
    ipadb_create_pwd_policy,            /* create_policy */
    ipadb_get_pwd_policy,               /* get_policy */
    ipadb_put_pwd_policy,               /* put_policy */
    ipadb_iterate_pwd_policy,           /* iter_policy */
    ipadb_delete_pwd_policy,            /* delete_policy */
    ipadb_free_pwd_policy,              /* free_policy */
    ipadb_alloc,                        /* alloc */
    ipadb_free,                         /* free */
    ipadb_fetch_master_key,             /* fetch_master_key */
    NULL,                               /* fetch_master_key_list */
    ipadb_store_master_key_list,        /* store_master_key_list */
    NULL,                               /* dbe_search_enctype */
    ipadb_change_pwd,                   /* change_pwd */
    NULL,                               /* promote_db */
    NULL,                               /* decrypt_key_data */
    NULL,                               /* encrypt_key_data */
    ipadb_sign_authdata,                /* sign_authdata */
    NULL,                               /* check_transited_realms */
    ipadb_check_policy_as,              /* check_policy_as */
    NULL,                               /* check_policy_tgs */
    ipadb_audit_as_req,                 /* audit_as_req */
    NULL,                               /* refresh_config */
    ipadb_check_allowed_to_delegate     /* check_allowed_to_delegate */
};

