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

krb5_error_code kdcpolicy_ipakdb_initvt(krb5_context context,
                                        int maj_ver, int min_ver,
                                        krb5_plugin_vtable vtable);

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

    *lifetime_out = baseline - abs(offset) % JITTER_WINDOW_SECONDS;
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
    bool passwordless_auth = false;
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

    /* If no mechanisms are set, or it is anonymous PKINIT, allow every auth method */
    if ((ua == IPADB_USER_AUTH_NONE) ||
        (request->kdc_options & KDC_OPT_REQUEST_ANONYMOUS)) {
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
            passwordless_auth = true;
            if (!(ua & IPADB_USER_AUTH_RADIUS)) {
                *status = "OTP pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_RADIUS]);
        } else if (strcmp(auth_indicator, "pkinit") == 0) {
            valid_auth_indicators++;
            passwordless_auth = true;
            /* allow PKINIT unconditionally -- it has passed already at this
             * point so some certificate was useful, only apply the limits */
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_PKINIT]);
        } else if (strcmp(auth_indicator, "hardened") == 0) {
            valid_auth_indicators++;
            /* Allow hardened even if only password pre-auth is allowed */
            if (!(ua & (IPADB_USER_AUTH_HARDENED | IPADB_USER_AUTH_PASSWORD))) {
                *status = "Password pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_HARDENED]);
        } else if (strcmp(auth_indicator, "idp") == 0) {
            valid_auth_indicators++;
            passwordless_auth = true;
            if (!(ua & IPADB_USER_AUTH_IDP)) {
                *status = "IdP pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_IDP]);
        } else if (strcmp(auth_indicator, "passkey") == 0) {
            valid_auth_indicators++;
            passwordless_auth = true;
            if (!(ua & IPADB_USER_AUTH_PASSKEY)) {
                *status = "Passkey pre-authentication not allowed for this user.";
                kerr = KRB5KDC_ERR_POLICY;
                goto done;
            }
            pol_limits = &(ied->pol_limits[IPADB_USER_AUTH_IDX_PASSKEY]);
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

    /* When a passwordless method is available, ipadb_parse_ldap_entry() clears
     * entry->pw_expiration so the KDC does not reject the AS-REQ before
     * pre-authentication.  Now that pre-auth is complete and we know the
     * actual method used, enforce password expiration for password-based
     * authentication. */
    if (!passwordless_auth && ied->pw_expiration != 0) {
        krb5_timestamp now;
        kerr = krb5_timeofday(context, &now);
        if (kerr)
            goto done;

        if ((uint32_t)now > (uint32_t)ied->pw_expiration) {
            *status = "CLIENT KEY EXPIRED";
            kerr = KRB5KDC_ERR_KEY_EXP;
            goto done;
        }
    }

    /* If there were policy limits associated with the authentication indicators,
     * apply them */
    if (pol_limits != NULL) {
        if (pol_limits->max_life != 0) {
            jitter(pol_limits->max_life, lifetime_out);
        } else {
            jitter(client->max_life, lifetime_out);
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
    struct ipadb_context *ipactx = NULL;
    krb5_error_code kerr = EINVAL;
    krb5_pac pac = NULL;
    bool is_tgs = false;
    bool is_cross_realm = false;
    bool need_bronze_bit_check = false;
    bool need_trust_check = false;

    *status = NULL;
    *lifetime_out = 0;
    *renew_lifetime_out = 0;

    /* Check if this is a TGS principal */
    is_tgs = ipadb_is_tgs_princ(context, ticket->server);
    if (!is_tgs) {
        kerr = 0;
        goto end;
    }

    /* Get IPA context */
    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto end;
    }

    /* Determine which checks are needed */
    is_cross_realm = ipadb_is_cross_realm_krbtgt(ticket->server);

    /* Bronze-Bit check needed for local TGT with PAC generator */
    need_bronze_bit_check = krb5_realm_compare(context, ipactx->local_tgs,
                                               ticket->server)
                            && ipactx->mspac;

    /* Trust check needed for cross-realm tickets */
    need_trust_check = is_cross_realm;

    /* If no checks needed, return success */
    if (!need_bronze_bit_check && !need_trust_check) {
        kerr = 0;
        goto end;
    }

    /* Parse PAC once for all checks */
    kerr = ipadb_find_and_parse_pac(context,
                                    ticket->enc_part2->authorization_data,
                                    &pac, status);
    if (kerr) {
        /* PAC missing or parse failure applies to both Bronze-Bit and trust
         * checks - return the error from ipadb_find_and_parse_pac() */
        goto end;
    }

    /* Perform trust PAC content checks if needed */
    if (need_trust_check) {
        kerr = ipadb_check_trust_pac_content(context, request, ticket, pac,
                                             status);
        if (kerr)
            goto end;
    }

    kerr = 0;

end:
    if (pac)
        krb5_pac_free(context, pac);

    return kerr;
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
