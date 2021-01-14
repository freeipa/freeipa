/*
 * Copyright (C) 2018,2020  FreeIPA Contributors see COPYING for license
 */

#include <errno.h>
#include <syslog.h>
#include <sys/random.h>

#include <krb5/kdcpolicy_plugin.h>

#include "ipa_krb5.h"
#include "ipa_kdb.h"

#define ONE_DAY_SECONDS (24 * 60 * 60)
#define JITTER_WINDOW_SECONDS (1 * 60 * 60)

static void
jitter(krb5_deltat baseline, krb5_deltat *lifetime_out)
{
    krb5_deltat offset;
    ssize_t ret;

    if (baseline < JITTER_WINDOW_SECONDS) {
        /* A negative value here would correspond to a never-valid ticket,
         * which isn't the goal. */
        *lifetime_out = baseline;
        return;
    }

    do {
        ret = getrandom(&offset, sizeof(offset), 0);
    } while (ret == -1 && errno == EINTR);
    if (ret < 0) {
        krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: getrandom failed (errno %d); skipping jitter...",
                         errno);
        return;
    }

    *lifetime_out = baseline - offset % JITTER_WINDOW_SECONDS;
}

static krb5_error_code
ipa_kdcpolicy_check_as(krb5_context context, krb5_kdcpolicy_moddata moddata,
                       const krb5_kdc_req *request,
                       const krb5_db_entry *client,
                       const krb5_db_entry *server,
                       const char *const *auth_indicators,
                       const char **status, krb5_deltat *lifetime_out,
                       krb5_deltat *renew_lifetime_out)
{
    krb5_error_code kerr = 0;
    enum ipadb_user_auth ua;
    struct ipadb_e_data *ied;
    struct ipadb_e_pol_limits *pol_limits = NULL;
    int valid_auth_indicators = 0, flags = 0;
    krb5_db_entry *client_actual = NULL;

#ifdef KRB5_KDB_FLAG_ALIAS_OK
    flags = KRB5_KDB_FLAG_ALIAS_OK;
#endif


    *status = NULL;
    *lifetime_out = 0;
    *renew_lifetime_out = 0;

    ied = (struct ipadb_e_data *)client->e_data;
    if (ied == NULL || ied->magic != IPA_E_DATA_MAGIC) {
        /* e-data is not availble, getting user auth from LDAP */
        krb5_klog_syslog(LOG_INFO, "IPA kdcpolicy: client e_data not availble. Try fetching...");
        kerr = ipadb_get_principal(context, request->client, flags,
                                   &client_actual);
        if (kerr != 0) {
            krb5_klog_syslog(LOG_ERR, "IPA kdcpolicy: ipadb_find_principal failed.");
            goto done;
        }

        ied = (struct ipadb_e_data *)client_actual->e_data;
        if (ied == NULL || ied->magic != IPA_E_DATA_MAGIC) {
            krb5_klog_syslog(LOG_ERR, "IPA kdcpolicy: client e_data fetching failed.");
            kerr = EINVAL;
            goto done;
        }
    }

    ua = ied->user_auth;
    
    /* If no mechanisms are set, allow every auth method */
    if (ua == IPADB_USER_AUTH_NONE) {
        jitter(ONE_DAY_SECONDS, lifetime_out);
        kerr = 0;
        goto done;
    }

    /* For each auth indicator, see if it is allowed for that user */
    for (int i = 0; auth_indicators[i] != NULL; i++) {
        const char *auth_indicator = auth_indicators[i];

        if (strcmp(auth_indicator, "otp") == 0) {
            valid_auth_indicators++;
            if (!(ua & IPADB_USER_AUTH_OTP)) {
                *status = "OTP pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_OTP]);
        } else if (strcmp(auth_indicator, "radius") == 0) {
            valid_auth_indicators++;
            if (!(ua & IPADB_USER_AUTH_RADIUS)) {
                *status = "OTP pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_RADIUS]);
        } else if (strcmp(auth_indicator, "pkinit") == 0) {
            valid_auth_indicators++;
            if (!(ua & IPADB_USER_AUTH_PKINIT)) {
                *status = "PKINIT pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_PKINIT]);
        } else if (strcmp(auth_indicator, "hardened") == 0) {
            valid_auth_indicators++;
            /* Allow hardened even if only password pre-auth is allowed */
            if (!(ua & (IPADB_USER_AUTH_HARDENED | IPADB_USER_AUTH_PASSWORD))) {
                *status = "Password pre-authentication not not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_HARDENED]);
        }
    }

    /* There is no auth indicator assigned for non-hardened password authentication
     * so we assume password is used when no supported indicator exists */
    if (!valid_auth_indicators) {
        if (!(ua & IPADB_USER_AUTH_PASSWORD)) {
            *status = "Non-hardened password authentication not allowed for this user.";
            kerr = KRB5KDC_ERR_POLICY;
            goto done;
        }
    }

    /* If there were policy limits associated with the authentication indicators,
     * apply them */
    if (pol_limits != NULL) {
        if (pol_limits->max_life != 0) {
            jitter(pol_limits->max_life, lifetime_out);
        } else {
            jitter(ONE_DAY_SECONDS, lifetime_out);
        }

        if (pol_limits->max_renewable_life != 0) {
            *renew_lifetime_out = pol_limits->max_renewable_life;
        }
    }

done:
    ipadb_free_principal(context, client_actual);

    return kerr;
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
