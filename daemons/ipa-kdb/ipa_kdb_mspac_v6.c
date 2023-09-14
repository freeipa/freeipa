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

#include "config.h"

#include "ipa_hostname.h"
#include "ipa_kdb.h"
#include <talloc.h>
#include <unicase.h>
#include "util/time.h"
#include "gen_ndr/ndr_krb5pac.h"

#include "ipa_kdb_mspac_private.h"

static
krb5_error_code ipadb_verify_pac(krb5_context context,
                                 unsigned int flags,
                                 krb5_const_principal client_princ,
                                 krb5_db_entry *proxy,
                                 krb5_db_entry *server,
                                 krb5_db_entry *krbtgt,
                                 krb5_keyblock *server_key,
                                 krb5_keyblock *krbtgt_key,
                                 krb5_timestamp authtime,
                                 krb5_authdata **authdata,
                                 krb5_pac *pac)
{
    krb5_error_code kerr;
    krb5_pac old_pac = NULL;
    kerr = krb5_pac_parse(context,
                          authdata[0]->contents,
                          authdata[0]->length,
                          &old_pac);
    if (kerr == 0) {
        krb5_keyblock *srv_key = NULL;
        krb5_keyblock *priv_key = NULL;
        bool is_cross_realm = false;

        /* for cross realm trusts cases we need to check the right checksum.
        * when the PAC is signed by our realm, we can always just check it
        * passing our realm krbtgt key as the kdc checksum key (privsvr).
        * But when a trusted realm passes us a PAC the kdc checksum is
        * generated with that realm krbtgt key, so we need to use the cross
        * realm krbtgt to check the 'server' checksum instead. */
        if (ipadb_is_cross_realm_krbtgt(krbtgt->princ)) {
            /* krbtgt from a trusted realm */
            is_cross_realm = true;
            srv_key = krbtgt_key;
        } else {
            /* krbtgt from our own realm */
            priv_key = krbtgt_key;
        }

        /* only pass with_realm TRUE when it is cross-realm ticket and S4U
        * extension (S4U2Self or S4U2Proxy (RBCD)) was requested */
        kerr = krb5_pac_verify_ext(context, old_pac, authtime,
                                NULL, srv_key, priv_key,
                                (is_cross_realm &&
                                    (flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION)));
        if (kerr) {
            goto done;
        }

        kerr = ipadb_common_verify_pac(context, flags,
                                       proxy, server, krbtgt,
                                       krbtgt_key,
                                       authtime, old_pac, pac);
    }

done:
    krb5_free_authdata(context, authdata);
    krb5_pac_free(context, old_pac);
    return kerr;
}



static krb5_error_code ipadb_sign_pac(krb5_context context,
                                      unsigned int flags,
                                      krb5_const_principal client_princ,
                                      krb5_db_entry *server,
                                      krb5_db_entry *krbtgt,
                                      krb5_keyblock *server_key,
                                      krb5_keyblock *krbtgt_key,
                                      krb5_timestamp authtime,
                                      krb5_pac pac,
                                      krb5_data *pac_data)
{
    krb5_keyblock *right_krbtgt_signing_key = NULL;
    krb5_key_data *right_krbtgt_key;
    krb5_db_entry *right_krbtgt = NULL;
    krb5_principal krbtgt_princ = NULL;
    krb5_error_code kerr;
    char *princ = NULL;
    bool is_issuing_referral = false;
    int ret;

    /* for cross realm trusts cases we need to sign with the right key.
     * we need to fetch the right key on our own until the DAL is fixed
     * to pass us separate check tgt keys and sign tgt keys */

    /* We can only ever create the kdc checksum with our realm tgt key.
     * So, if we get a cross realm tgt we have to fetch our realm tgt
     * instead. */
    if (ipadb_is_cross_realm_krbtgt(krbtgt->princ)) {

        ret = asprintf(&princ, "krbtgt/%.*s@%.*s",
                       server->princ->realm.length,
                       server->princ->realm.data,
                       server->princ->realm.length,
                       server->princ->realm.data);
        if (ret == -1) {
            princ = NULL;
            kerr = ENOMEM;
            goto done;
        }

        kerr = krb5_parse_name(context, princ, &krbtgt_princ);
        if (kerr) {
            goto done;
        }

        kerr = ipadb_get_principal(context, krbtgt_princ, 0, &right_krbtgt);
        if (kerr) {
            goto done;
        }

        kerr = krb5_dbe_find_enctype(context, right_krbtgt,
                                     -1, -1, 0, &right_krbtgt_key);
        if (kerr) {
            goto done;
        }
        if (!right_krbtgt_key) {
            kerr = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
            goto done;
        }

        right_krbtgt_signing_key = malloc(sizeof(krb5_keyblock));
        if (!right_krbtgt_signing_key) {
            kerr = ENOMEM;
            goto done;
        }

        kerr = krb5_dbe_decrypt_key_data(context, NULL, right_krbtgt_key,
                                         right_krbtgt_signing_key, NULL);
        if (kerr) {
            goto done;
        }

    } else {
        right_krbtgt_signing_key = krbtgt_key;
    }

#ifdef KRB5_KDB_FLAG_ISSUING_REFERRAL
    is_issuing_referral = (flags & KRB5_KDB_FLAG_ISSUING_REFERRAL) != 0;
#endif

    /* only pass with_realm TRUE when it is cross-realm ticket and S4U2Self
     * was requested */
#ifdef HAVE_KRB5_PAC_FULL_SIGN_COMPAT
    kerr = krb5_pac_full_sign_compat(
        context, pac, authtime, client_princ, server->princ, server_key,
        right_krbtgt_signing_key,
        (is_issuing_referral && (flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION)),
        pac_data
    );
#else
    /* Use standard function, PAC extended KDC signature not supported */
    kerr = krb5_pac_sign_ext(context, pac, authtime, client_princ, server_key,
                             right_krbtgt_signing_key,
                             (is_issuing_referral &&
                              (flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION)),
                             pac_data);
#endif

done:
    free(princ);
    krb5_free_principal(context, krbtgt_princ);
    ipadb_free_principal(context, right_krbtgt);
    if (right_krbtgt_signing_key != krbtgt_key) {
        krb5_free_keyblock(context, right_krbtgt_signing_key);
    }
    return kerr;
}


krb5_error_code ipadb_sign_authdata(krb5_context context,
                                    unsigned int flags,
                                    krb5_const_principal client_princ,
                                    krb5_db_entry *client,
                                    krb5_db_entry *server,
                                    krb5_db_entry *krbtgt,
                                    krb5_keyblock *client_key,
                                    krb5_keyblock *server_key,
                                    krb5_keyblock *krbtgt_key,
                                    krb5_keyblock *session_key,
                                    krb5_timestamp authtime,
                                    krb5_authdata **tgt_auth_data,
                                    krb5_authdata ***signed_auth_data)
{
    krb5_const_principal ks_client_princ;
    krb5_authdata **pac_auth_data = NULL;
    krb5_authdata *authdata[2] = { NULL, NULL };
    krb5_authdata ad;
    krb5_boolean is_as_req;
    krb5_error_code kerr;
    krb5_pac pac = NULL;
    krb5_data pac_data;
    struct ipadb_context *ipactx;
    bool with_pac;
    bool with_pad;
    bool make_ad = false;
    int result;
    krb5_db_entry *client_entry = NULL;
    krb5_boolean is_equal;
    bool force_reinit_mspac = false;


    is_as_req = ((flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) != 0);

    /* When using s4u2proxy client_princ actually refers to the proxied user
     * while client->princ to the proxy service asking for the TGS on behalf
     * of the proxied user. So always use client_princ in preference */
    if (client_princ != NULL) {
        ks_client_princ = client_princ;
        if (!is_as_req) {
            is_equal = false;
            if ((client != NULL) && (client->princ != NULL)) {
                is_equal = krb5_principal_compare(context, client_princ, client->princ);
            }
            if (!is_equal) {
                kerr = ipadb_get_principal(context, client_princ, flags, &client_entry);
                /* If we didn't find client_princ in our database, it might be:
                 * - a principal from another realm, handle it down in ipadb_get/verify_pac()
                 */
                if (kerr != 0) {
                    client_entry = NULL;
                }
            }
        }
    } else {
        if (client == NULL) {
            *signed_auth_data = NULL;
            return 0;
        }
        ks_client_princ = client->princ;
    }

    if (client_entry == NULL) client_entry = client;

    if (is_as_req) {
        get_authz_data_types(context, client_entry, &with_pac, &with_pad);
    } else {
        get_authz_data_types(context, server, &with_pac, &with_pad);
    }

    if (with_pad) {
        krb5_klog_syslog(LOG_ERR, "PAD authorization data is requested but " \
                                  "currently not supported.");
    }

    /* we need to create a PAC if we are requested one and this is an AS REQ,
     * or we are doing protocol transition (S4USelf) but not over cross-realm
     */
    if ((is_as_req && (flags & KRB5_KDB_FLAG_INCLUDE_PAC)) ||
        ((flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION) && (client != NULL))) {
        make_ad = true;
    }

    if (with_pac && make_ad) {

        ipactx = ipadb_get_context(context);
        if (!ipactx) {
            kerr = ENOMEM;
            goto done;
        }

        /* Be aggressive here: special case for discovering range type
         * immediately after establishing the trust by IPA framework. For all
         * other cases call ipadb_reinit_mspac() with force_reinit_mspac set
         * to 'false' to make sure the information about trusted domains is
         * updated on a regular basis for all worker processes. */
        if ((krb5_princ_size(context, ks_client_princ) == 2) &&
            (strncmp(krb5_princ_component(context, ks_client_princ, 0)->data, "HTTP",
                     krb5_princ_component(context, ks_client_princ, 0)->length) == 0) &&
            (ulc_casecmp(krb5_princ_component(context, ks_client_princ, 1)->data,
                         krb5_princ_component(context, ks_client_princ, 1)->length,
                         ipactx->kdc_hostname, strlen(ipactx->kdc_hostname),
                         NULL, NULL, &result) == 0)) {
            force_reinit_mspac = true;
        }

        (void)ipadb_reinit_mspac(ipactx, force_reinit_mspac);

        kerr = ipadb_get_pac(context, flags, client, server, NULL, authtime, &pac);
        if (kerr != 0 && kerr != ENOENT) {
            goto done;
        }
    } else if (with_pac && !is_as_req) {
        /* find the existing PAC, if present */
        kerr = krb5_find_authdata(context, tgt_auth_data, NULL,
                                  KRB5_AUTHDATA_WIN2K_PAC, &pac_auth_data);
        if (kerr != 0) {
            goto done;
        }
        /* check or generate pac data */
        if ((pac_auth_data == NULL) || (pac_auth_data[0] == NULL)) {
            if (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) {
                kerr = ipadb_get_pac(context, flags, client_entry, server, NULL, authtime, &pac);
                if (kerr != 0 && kerr != ENOENT) {
                    goto done;
                }
            }
        } else {
            if (pac_auth_data[1] != NULL) {
                kerr = KRB5KDC_ERR_BADOPTION; /* FIXME: right error ? */
                goto done;
            }

            kerr = ipadb_verify_pac(context, flags, ks_client_princ, client,
                                    server, krbtgt, server_key, krbtgt_key,
                                    authtime, pac_auth_data, &pac);
            if (kerr != 0) {
                goto done;
            }
        }
    }

    if (pac == NULL) {
        /* No PAC to deal with, proceed */
        *signed_auth_data = NULL;
        kerr = 0;
        goto done;
    }

    kerr = ipadb_sign_pac(context, flags, ks_client_princ, server, krbtgt,
                          server_key, krbtgt_key, authtime, pac, &pac_data);
    if (kerr != 0) {
        goto done;
    }

    /* put in signed data */
    ad.magic = KV5M_AUTHDATA;
    ad.ad_type = KRB5_AUTHDATA_WIN2K_PAC;
    ad.contents = (krb5_octet *)pac_data.data;
    ad.length = pac_data.length;

    authdata[0] = &ad;

    kerr = krb5_encode_authdata_container(context,
                                          KRB5_AUTHDATA_IF_RELEVANT,
                                          authdata,
                                          signed_auth_data);
    krb5_free_data_contents(context, &pac_data);
    if (kerr != 0) {
        goto done;
    }

    kerr = 0;

done:
    if (client_entry != NULL && client_entry != client) {
        ipadb_free_principal(context, client_entry);
    }
    krb5_pac_free(context, pac);
    return kerr;
}

