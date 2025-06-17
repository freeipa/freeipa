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

#include <talloc.h>
#include <sys/utsname.h>

#include "ipa_kdb.h"
#include "ipa_krb5.h"
#include "ipa_hostname.h"
#include <kadm5/admin.h>

#define IPADB_GLOBAL_CONFIG_CACHE_TIME 60

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
    struct ipadb_global_config *cfg;
    size_t c;

    if (*ctx != NULL) {
        if ((*ctx)->magic != IPA_CONTEXT_MAGIC) {
            krb5_klog_syslog(LOG_ERR, "IPA context is corrupted");
            *ctx = NULL;
            return;
        }
        free((*ctx)->uri);
        free((*ctx)->base);
        free((*ctx)->realm_base);
        free((*ctx)->accounts_base);
        /* kdc_hostname is a pointer to a static char[] */
        /* ldap free lcontext */
        if ((*ctx)->lcontext) {
            ldap_unbind_ext_s((*ctx)->lcontext, NULL, NULL);
            (*ctx)->lcontext = NULL;
        }
        free((*ctx)->supp_encs);
        free((*ctx)->def_encs);
        ipadb_mspac_struct_free(&(*ctx)->mspac);
        krb5_free_principal(kcontext, (*ctx)->local_tgs);
        krb5_free_default_realm(kcontext, (*ctx)->realm);

        cfg = &(*ctx)->config;
        for (c = 0; cfg->authz_data && cfg->authz_data[c]; c++) {
            free(cfg->authz_data[c]);
        }
        free(cfg->authz_data);

#ifdef HAVE_KRB5_CERTAUTH_PLUGIN
        ipa_certauth_free_moddata(&((*ctx)->certauth_moddata));
#endif

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
            memcpy(p, "%2f", 3);
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

/* In this table all _AUTH_PASSWORD entries will be
 * expanded to include _AUTH_HARDENED in ipadb_parse_user_auth()
 * which means there is no need to explicitly add it here */
static const struct {
    const char *name;
    enum ipadb_user_auth flag;
} userauth_table[] = {
    { "disabled", IPADB_USER_AUTH_DISABLED },
    { "password", IPADB_USER_AUTH_PASSWORD },
    { "radius", IPADB_USER_AUTH_RADIUS },
    { "otp", IPADB_USER_AUTH_OTP },
    { "pkinit", IPADB_USER_AUTH_PKINIT },
    { "hardened", IPADB_USER_AUTH_HARDENED },
    { "idp", IPADB_USER_AUTH_IDP },
    { "passkey", IPADB_USER_AUTH_PASSKEY },
    { }
},
  objclass_table[] = {
    { "ipaservice", IPADB_USER_AUTH_PASSWORD },
    { "ipahost", IPADB_USER_AUTH_PASSWORD },
    { }
},
  princname_table[] = {
    { KRB5_TGS_NAME, IPADB_USER_AUTH_PASSWORD },
    { KRB5_KDB_M_NAME, IPADB_USER_AUTH_PASSWORD },
    { KADM5_ADMIN_SERVICE, IPADB_USER_AUTH_PASSWORD },
    { KADM5_CHANGEPW_SERVICE, IPADB_USER_AUTH_PASSWORD },
    { KADM5_HIST_PRINCIPAL, IPADB_USER_AUTH_PASSWORD },
    { }
};

void ipadb_parse_user_auth(LDAP *lcontext, LDAPMessage *le,
                           enum ipadb_user_auth *userauth)
{
    struct berval **vals;
    int i, j;

    *userauth = IPADB_USER_AUTH_NONE;
    vals = ldap_get_values_len(lcontext, le, IPA_USER_AUTH_TYPE);
    if (!vals) {
        /* if there is no explicit ipaUserAuthType set, use objectclass */
        vals = ldap_get_values_len(lcontext, le, "objectclass");
        if (!vals)
            return;

        for (i = 0; vals[i]; i++) {
            for (j = 0; objclass_table[j].name; j++) {
                if (strcasecmp(vals[i]->bv_val, objclass_table[j].name) == 0) {
                    *userauth |= objclass_table[j].flag;
                    break;
                }
            }
        }
    } else {
        for (i = 0; vals[i]; i++) {
            for (j = 0; userauth_table[j].name; j++) {
                if (strcasecmp(vals[i]->bv_val, userauth_table[j].name) == 0) {
                    *userauth |= userauth_table[j].flag;
                    break;
                }
            }
        }
    }

    /* If neither ipaUserAuthType nor objectClass were definitive,
     * check the krbPrincipalName to see if it is krbtgt/ or K/M one */
    if (*userauth == IPADB_USER_AUTH_NONE) {
        ldap_value_free_len(vals);
        vals = ldap_get_values_len(lcontext, le, "krbprincipalname");
        if (!vals)
            return;
        for (i = 0; vals[i]; i++) {
            for (j = 0; princname_table[j].name; j++) {
                if (strncmp(vals[i]->bv_val, princname_table[j].name,
                            strlen(princname_table[j].name)) == 0) {
                    *userauth |= princname_table[j].flag;
                    break;
                }
            }
        }

    }
    /* If password auth is enabled, enable hardened policy too. */
    if (*userauth & IPADB_USER_AUTH_PASSWORD) {
        *userauth |= IPADB_USER_AUTH_HARDENED;
    }

    ldap_value_free_len(vals);
}

static int ipadb_load_global_config(struct ipadb_context *ipactx)
{
    char *attrs[] = { "ipaConfigString", IPA_KRB_AUTHZ_DATA_ATTR,
                      IPA_USER_AUTH_TYPE, NULL };
    struct berval **vals = NULL;
    LDAPMessage *res = NULL;
    LDAPMessage *first;
    char *base = NULL;
    int ret;
    char **authz_data_list;

    if (!ipactx || !ipactx->lcontext) {
        return EINVAL;
    }

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

    /* Check for permitted authentication types. */
    ipadb_parse_user_auth(ipactx->lcontext, res, &ipactx->config.user_auth);

    /* Load config strings. */
    vals = ldap_get_values_len(ipactx->lcontext, first, "ipaConfigString");
    if (vals) {
        ipactx->config.disable_last_success = false;
        ipactx->config.disable_lockout = false;
        for (int i = 0; vals[i]; i++) {
            if (strncasecmp("KDC:Disable Last Success",
                            vals[i]->bv_val, vals[i]->bv_len) == 0) {
                ipactx->config.disable_last_success = true;
                continue;
            } else if (strncasecmp("KDC:Disable Lockout",
                                   vals[i]->bv_val, vals[i]->bv_len) == 0) {
                ipactx->config.disable_lockout = true;
                continue;
            } else if (strncasecmp("KDC:Disable Default Preauth for SPNs",
                                   vals[i]->bv_val, vals[i]->bv_len) == 0) {
                ipactx->config.disable_preauth_for_spns = true;
            }
        }
    }

	/* Load authz data. */
    ret = ipadb_ldap_attr_to_strlist(ipactx->lcontext, first,
                                     IPA_KRB_AUTHZ_DATA_ATTR, &authz_data_list);
    if (ret == 0) {
        if (ipactx->config.authz_data != NULL) {
            for (int i = 0; ipactx->config.authz_data[i]; i++)
                free(ipactx->config.authz_data[i]);
            free(ipactx->config.authz_data);
        }

        ipactx->config.authz_data = authz_data_list;
    } else if (ret != ENOENT)
        goto done;

    /* Success! */
    ipactx->config.last_update = time(NULL);
    ret = 0;

done:
    ldap_value_free_len(vals);
    ldap_msgfree(res);
    free(base);
    return ret;
}

const struct ipadb_global_config *
ipadb_get_global_config(struct ipadb_context *ipactx)
{
    time_t now = 0;
    int ret;

    if (time(&now) != (time_t)-1 &&
        now - ipactx->config.last_update > IPADB_GLOBAL_CONFIG_CACHE_TIME) {
        if (!ipactx->lcontext) {
            ret = ipadb_get_connection(ipactx);
            if (ret != 0)
                return NULL;
        }
        ret = ipadb_load_global_config(ipactx);
        if (ret != 0)
            return NULL;
    }

    return &ipactx->config;
}

int ipadb_get_enc_salt_types(struct ipadb_context *ipactx,
                             LDAPMessage *entry, char *attr,
                             krb5_key_salt_tuple **enc_salt_types,
                             int *n_enc_salt_types)
{
    struct berval **vals = NULL;
    char **cvals = NULL;
    int c = 0;
    int i;
    int ret = 0;
    krb5_key_salt_tuple *kst;
    int n_kst;

    vals = ldap_get_values_len(ipactx->lcontext, entry, attr);
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

    if (*enc_salt_types) {
        free(*enc_salt_types);
    }

    *enc_salt_types = kst;
    *n_enc_salt_types = n_kst;

done:
    ldap_value_free_len(vals);
    for (i = 0; i < c && cvals[i]; i++) {
        free(cvals[i]);
    }
    free(cvals);
    return ret;
}

int ipadb_get_connection(struct ipadb_context *ipactx)
{
    struct timeval tv = { 5, 0 };
    LDAPMessage *res = NULL;
    LDAPMessage *first;
    const char *stmsg;
    int ret;
    int v3;

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

    /* defaults first, this is used to tell what default enc:salts to use
     * for kadmin password changes */
    ret = ipadb_get_enc_salt_types(ipactx, first,  "krbDefaultEncSaltTypes",
                                   &ipactx->def_encs, &ipactx->n_def_encs);
    if (ret) {
        goto done;
    }

    /* supported enc salt types, use to tell kadmin what to accept
     * but also to detect if kadmin is requesting the default set */
    ret = ipadb_get_enc_salt_types(ipactx, first, "krbSupportedEncSaltTypes",
                                   &ipactx->supp_encs, &ipactx->n_supp_encs);
    if (ret) {
        goto done;
    }

    /* get additional options */
    ret = ipadb_load_global_config(ipactx);
    if (ret) {
        goto done;
    }

    /* get adtrust options using default refresh interval */
    ret = ipadb_reinit_mspac(ipactx, false, &stmsg);
    if (ret) {
        if (stmsg) {
            krb5_klog_syslog(LOG_WARNING, "MS-PAC generator: %s", stmsg);
        }
        /* Initialization of the MS-PAC generator is an optional dependency.
         * Fail only if the connection was lost. */
        if (!ipactx->lcontext) {
            goto done;
        }
    }

    ret = 0;

done:
    ldap_msgfree(res);

    /* LDAP context should never be null on success, but keep this test out of
     * security to make sure we do not return an invalid context. */
    if (ret == 0 && !ipactx->lcontext) {
        krb5_klog_syslog(LOG_WARNING, "Internal malfunction: LDAP connection "
                                      "process resulted in an invalid context "
                                      "(please report this incident)");
        ret = LDAP_SERVER_DOWN;
    }

    if (ret) {
        /* Cleanup LDAP context if connection failed. */
        if (ipactx->lcontext) {
            ldap_unbind_ext_s(ipactx->lcontext, NULL, NULL);
            ipactx->lcontext = NULL;
        }

        /* Replace LDAP error code by POSIX error code. */
        ret = ret == LDAP_SERVER_DOWN ? ETIMEDOUT : EIO;
    }

    return ret;
}

static krb5_principal ipadb_create_local_tgs(krb5_context kcontext,
                                             struct ipadb_context *ipactx)
{
    krb5_principal tgtp;
    unsigned int length = strlen(ipactx->realm);
    krb5_error_code kerr = 0;

    kerr = krb5_build_principal_ext(kcontext, &tgtp,
                                    length,
                                    ipactx->realm,
                                    KRB5_TGS_NAME_SIZE,
                                    KRB5_TGS_NAME,
                                    length,
                                    ipactx->realm, 0);
    if (kerr != 0) {
        return NULL;
    }

    return tgtp;
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
    ipactx->magic = IPA_CONTEXT_MAGIC;

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

    ipactx->local_tgs = ipadb_create_local_tgs(kcontext, ipactx);
    if (!ipactx->local_tgs) {
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

    ret = asprintf(&ipactx->accounts_base, "cn=accounts,%s", ipactx->base);
    if (ret == -1) {
        ret = ENOMEM;
        goto fail;
    }

    ipactx->kdc_hostname = ipa_gethostfqdn();
    if (!ipactx->kdc_hostname) {
        ret = errno;
        goto fail;
    }

    ipactx->optional_pac_tkt_chksum = IPADB_TRISTATE_UNDEFINED;

    ret = ipadb_get_connection(ipactx);
    if (ret != 0) {
        /* Not a fatal failure, as the LDAP server may be temporarily down. */
        krb5_klog_syslog(LOG_INFO,
                         "Didn't connect to LDAP on startup: %d", ret);
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
    talloc_free(talloc_autofree_context());

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

/* KDB Virtual Table */

/* We explicitly want to keep different ABI tables below separate. */
/* Do not merge them together. Older ABI does not need to be updated */

#if (KRB5_KDB_DAL_MAJOR_VERSION == 6) && !defined(HAVE_KDB_FREEPRINCIPAL_EDATA)
kdb_vftabl kdb_function_table = {
    .maj_ver = KRB5_KDB_DAL_MAJOR_VERSION,
    .min_ver = 0,
    .init_library = ipadb_init_library,
    .fini_library = ipadb_fini_library,
    .init_module = ipadb_init_module,
    .fini_module = ipadb_fini_module,
    .create = ipadb_create,
    .get_age = ipadb_get_age,
    .get_principal = ipadb_get_principal,
    .put_principal = ipadb_put_principal,
    .delete_principal = ipadb_delete_principal,
    .iterate = ipadb_iterate,
    .create_policy = ipadb_create_pwd_policy,
    .get_policy = ipadb_get_pwd_policy,
    .put_policy = ipadb_put_pwd_policy,
    .iter_policy = ipadb_iterate_pwd_policy,
    .delete_policy = ipadb_delete_pwd_policy,
    .fetch_master_key = ipadb_fetch_master_key,
    .store_master_key_list = ipadb_store_master_key_list,
    .change_pwd = ipadb_change_pwd,
    .sign_authdata = ipadb_sign_authdata,
    .check_transited_realms = ipadb_check_transited_realms,
    .check_policy_as = ipadb_check_policy_as,
    .audit_as_req = ipadb_audit_as_req,
    .check_allowed_to_delegate = ipadb_check_allowed_to_delegate
};
#endif

#if ((KRB5_KDB_DAL_MAJOR_VERSION == 6) || \
     (KRB5_KDB_DAL_MAJOR_VERSION == 7)) && \
    defined(HAVE_KDB_FREEPRINCIPAL_EDATA)
kdb_vftabl kdb_function_table = {
    .maj_ver = KRB5_KDB_DAL_MAJOR_VERSION,
    .min_ver = 1,
    .init_library = ipadb_init_library,
    .fini_library = ipadb_fini_library,
    .init_module = ipadb_init_module,
    .fini_module = ipadb_fini_module,
    .create = ipadb_create,
    .get_age = ipadb_get_age,
    .get_principal = ipadb_get_principal,
    .put_principal = ipadb_put_principal,
    .delete_principal = ipadb_delete_principal,
    .iterate = ipadb_iterate,
    .create_policy = ipadb_create_pwd_policy,
    .get_policy = ipadb_get_pwd_policy,
    .put_policy = ipadb_put_pwd_policy,
    .iter_policy = ipadb_iterate_pwd_policy,
    .delete_policy = ipadb_delete_pwd_policy,
    .fetch_master_key = ipadb_fetch_master_key,
    .store_master_key_list = ipadb_store_master_key_list,
    .change_pwd = ipadb_change_pwd,
    .sign_authdata = ipadb_sign_authdata,
    .check_transited_realms = ipadb_check_transited_realms,
    .check_policy_as = ipadb_check_policy_as,
    .audit_as_req = ipadb_audit_as_req,
    .check_allowed_to_delegate = ipadb_check_allowed_to_delegate,
    /* The order is important, DAL version 6.1 added
     * the free_principal_e_data callback */
    .free_principal_e_data = ipadb_free_principal_e_data,
};
#endif

#if (KRB5_KDB_DAL_MAJOR_VERSION == 8)
/* Version 8 adds several arguments here.  However, if we want to actually use
 * them in mspac, we really ought to drop support for older DAL versions. */
static inline krb5_error_code
stub_sign_authdata(krb5_context context, unsigned int flags,
                   krb5_const_principal client_princ,
                   krb5_const_principal server_princ, krb5_db_entry *client,
                   krb5_db_entry *server, krb5_db_entry *header_server,
                   krb5_db_entry *local_tgt, krb5_keyblock *client_key,
                   krb5_keyblock *server_key, krb5_keyblock *header_key,
                   krb5_keyblock *local_tgt_key, krb5_keyblock *session_key,
                   krb5_timestamp authtime, krb5_authdata **tgt_auth_data,
                   void *ad_info, krb5_data ***auth_indicators,
                   krb5_authdata ***signed_auth_data)
{
    krb5_db_entry *krbtgt = header_server ? header_server : local_tgt;
    krb5_keyblock *krbtgt_key = header_key ? header_key : local_tgt_key;

    if (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) {
        client = header_server;
        krbtgt = local_tgt;
        krbtgt_key = local_tgt_key;
    }

    return ipadb_sign_authdata(context, flags, client_princ, client, server,
                               krbtgt, client_key, server_key, krbtgt_key,
                               session_key, authtime, tgt_auth_data,
                               signed_auth_data);
}

kdb_vftabl kdb_function_table = {
    .maj_ver = KRB5_KDB_DAL_MAJOR_VERSION,
    .min_ver = 0,
    .init_library = ipadb_init_library,
    .fini_library = ipadb_fini_library,
    .init_module = ipadb_init_module,
    .fini_module = ipadb_fini_module,
    .create = ipadb_create,
    .get_age = ipadb_get_age,
    .get_principal = ipadb_get_principal,
    .put_principal = ipadb_put_principal,
    .delete_principal = ipadb_delete_principal,
    .iterate = ipadb_iterate,
    .create_policy = ipadb_create_pwd_policy,
    .get_policy = ipadb_get_pwd_policy,
    .put_policy = ipadb_put_pwd_policy,
    .iter_policy = ipadb_iterate_pwd_policy,
    .delete_policy = ipadb_delete_pwd_policy,
    .fetch_master_key = ipadb_fetch_master_key,
    .store_master_key_list = ipadb_store_master_key_list,
    .change_pwd = ipadb_change_pwd,
    .sign_authdata = stub_sign_authdata,
    .check_transited_realms = ipadb_check_transited_realms,
    .check_policy_as = ipadb_check_policy_as,
    .audit_as_req = ipadb_audit_as_req,
    .check_allowed_to_delegate = ipadb_check_allowed_to_delegate,
    .free_principal_e_data = ipadb_free_principal_e_data,
    .get_s4u_x509_principal = NULL,
    .allowed_to_delegate_from = NULL,
    .get_authdata_info = NULL,
    .free_authdata_info = NULL,
};
#endif

#if (KRB5_KDB_DAL_MAJOR_VERSION == 9)
/* Version 9 removes sign_authdata and adds issue_pac method. It is a complete
 * revamp of how PAC is issued, so we need to implement it differently to previous
 * versions. */

krb5_error_code
ipadb_v9_issue_pac(krb5_context context, unsigned int flags,
                   krb5_db_entry *client,
                   krb5_keyblock *replaced_reply_key,
                   krb5_db_entry *server,
                   krb5_db_entry *signing_krbtgt,
                   krb5_timestamp authtime, krb5_pac old_pac,
                   krb5_pac new_pac,
                   krb5_data ***auth_indicators);

kdb_vftabl kdb_function_table = {
    .maj_ver = KRB5_KDB_DAL_MAJOR_VERSION,
    .min_ver = 0,
    .init_library = ipadb_init_library,
    .fini_library = ipadb_fini_library,
    .init_module = ipadb_init_module,
    .fini_module = ipadb_fini_module,
    .create = ipadb_create,
    .get_age = ipadb_get_age,
    .get_principal = ipadb_get_principal,
    .put_principal = ipadb_put_principal,
    .delete_principal = ipadb_delete_principal,
    .iterate = ipadb_iterate,
    .create_policy = ipadb_create_pwd_policy,
    .get_policy = ipadb_get_pwd_policy,
    .put_policy = ipadb_put_pwd_policy,
    .iter_policy = ipadb_iterate_pwd_policy,
    .delete_policy = ipadb_delete_pwd_policy,
    .fetch_master_key = ipadb_fetch_master_key,
    .store_master_key_list = ipadb_store_master_key_list,
    .change_pwd = ipadb_change_pwd,
    .check_transited_realms = ipadb_check_transited_realms,
    .check_policy_as = ipadb_check_policy_as,
    .audit_as_req = ipadb_audit_as_req,
    .check_allowed_to_delegate = ipadb_check_allowed_to_delegate,
    .free_principal_e_data = ipadb_free_principal_e_data,
    .get_s4u_x509_principal = NULL,
    .allowed_to_delegate_from = ipadb_allowed_to_delegate_from,
    .issue_pac = ipadb_v9_issue_pac,
};
#endif

#if (KRB5_KDB_DAL_MAJOR_VERSION != 6) && \
    (KRB5_KDB_DAL_MAJOR_VERSION != 7) && \
    (KRB5_KDB_DAL_MAJOR_VERSION != 8) && \
    (KRB5_KDB_DAL_MAJOR_VERSION != 9)
#error unsupported DAL major version
#endif
