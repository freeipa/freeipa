/*
 * Copyright (C) 2018  FreeIPA Contributors see COPYING for license
 */

#include <errno.h>
#include <syslog.h>
#include <krb5/kdcpolicy_plugin.h>

#include "ipa_krb5.h"
#include "ipa_kdb.h"

static krb5_error_code
ipa_kdcpolicy_check_as(krb5_context context, krb5_kdcpolicy_moddata moddata,
                       const krb5_kdc_req *request,
                       const krb5_db_entry *client,
                       const krb5_db_entry *server,
                       const char *const *auth_indicators,
                       const char **status, krb5_deltat *lifetime_out,
                       krb5_deltat *renew_lifetime_out)
{
    krb5_error_code kerr;
    enum ipadb_user_auth ua;
    struct ipadb_e_data *ied;
    int valid_auth_indicators = 0;

    *status = NULL;
    *lifetime_out = 0;
    *renew_lifetime_out = 0;

    krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: checking AS-REQ.");

    ied = (struct ipadb_e_data *)client->e_data;
    if (ied == NULL || ied->magic != IPA_E_DATA_MAGIC) {
        /* e-data is not availble, getting user auth from LDAP */
        krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: client e_data not availble. Try fetching...");
        kerr = ipadb_get_principal(context, request->client, KRB5_KDB_FLAG_ALIAS_OK, &client);
        if (kerr != 0) {
            krb5_klog_syslog(LOG_ERR, "IPA kdcpolicy: ipadb_find_principal failed.");
            return kerr;
        }

        ied = (struct ipadb_e_data *)client->e_data;
        if (ied == NULL && ied->magic != IPA_E_DATA_MAGIC) {
            krb5_klog_syslog(LOG_ERR, "IPA kdcpolicy: client e_data fetching failed.");
            return EINVAL;
        }
    }

    ua = ied->user_auth;
    
    /* If no mechanisms are set, allow every auth method */
    if (ua == IPADB_USER_AUTH_NONE) {
        return 0;
    }

    /* For each auth indicator, see if it is allowed for that user */
    for (int i = 0; auth_indicators[i] != NULL; i++) {
        const char *auth_indicator = auth_indicators[i];

        if (strcmp(auth_indicator, "otp") == 0) {
            valid_auth_indicators++;
            if (!(ua & IPADB_USER_AUTH_OTP)) {
                *status = "OTP pre-authentication not allowed for this user.";
                return KRB5KDC_ERR_POLICY;
            }
        } else if (strcmp(auth_indicator, "radius") == 0) {
            valid_auth_indicators++;
            if (!(ua & IPADB_USER_AUTH_RADIUS)) {
                *status = "OTP pre-authentication not allowed for this user.";
                return KRB5KDC_ERR_POLICY;
            }
        } else if (strcmp(auth_indicator, "pkinit") == 0) {
            valid_auth_indicators++;
            if (!(ua & IPADB_USER_AUTH_PKINIT)) {
                *status = "PKINIT pre-authentication not allowed for this user.";
                return KRB5KDC_ERR_POLICY;
            }
        } else if (strcmp(auth_indicator, "hardened") == 0) {
            valid_auth_indicators++;
            /* Allow hardened even if only password pre-auth is allowed */
            if (!(ua & (IPADB_USER_AUTH_HARDENED | IPADB_USER_AUTH_PASSWORD))) {
                *status = "Password pre-authentication not not allowed for this user.";
                return KRB5KDC_ERR_POLICY;
            }
        }
    }

    /* There is no auth indicator assigned for non-hardened password authentication
     * so we assume password is used when no supported indicator exists */
    if (!valid_auth_indicators) {
        if (!(ua & IPADB_USER_AUTH_PASSWORD)) {
            *status = "Non-hardened password authentication not allowed for this user.";
            return KRB5KDC_ERR_POLICY;
        }
    }

    return 0;
}

static krb5_error_code
ipa_kdcpolicy_check_tgs(krb5_context context, krb5_kdcpolicy_moddata moddata,
                        const krb5_kdc_req *request,
                        const krb5_db_entry *server,
                        const krb5_ticket *ticket,
                        const char *const *auth_indicators,
                        const char **status, krb5_deltat *lifetime_out,
                        krb5_deltat *renew_lifetime_out)
{
    *status = NULL;
    *lifetime_out = 0;
    *renew_lifetime_out = 0;

    krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: checking TGS-REQ.");

    return 0;
}

krb5_error_code kdcpolicy_ipakdb_initvt(krb5_context context,
                                        int maj_ver, int min_ver,
                                        krb5_plugin_vtable vtable)
{
    krb5_kdcpolicy_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;

    vt = (krb5_kdcpolicy_vtable)vtable;
    vt->name = "ipakdb";
    vt->init = NULL;
    vt->fini = NULL;
    vt->check_as = ipa_kdcpolicy_check_as;
    vt->check_tgs = ipa_kdcpolicy_check_tgs;
    return 0;
}
