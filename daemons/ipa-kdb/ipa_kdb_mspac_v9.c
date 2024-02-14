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

krb5_error_code
ipadb_v9_issue_pac(krb5_context context, unsigned int flags,
                   krb5_db_entry *client,
                   krb5_keyblock *replaced_reply_key,
                   krb5_db_entry *server,
                   krb5_db_entry *signing_krbtgt,
                   krb5_timestamp authtime,
                   krb5_pac old_pac,
                   krb5_pac new_pac,
                   krb5_data ***auth_indicators)
{
    bool with_pac;
    bool with_pad;
    krb5_error_code kerr = 0;
    bool is_as_req = flags & CLIENT_REFERRALS_FLAGS;
    const char *stmsg = NULL;

    if (is_as_req) {
        get_authz_data_types(context, client, &with_pac, &with_pad);
    } else {
        get_authz_data_types(context, server, &with_pac, &with_pad);
    }

    if (with_pad) {
        krb5_klog_syslog(LOG_ERR, "PAD authorization data is requested but " \
                                  "currently not supported.");
    }

    /*
        * Get a new PAC for AS-REQ or S4U2Self for our realm.
        *
        * For a simple cross-realm S4U2Proxy there will be the following TGS
        * requests after the client realm is identified:
        *
        * 1. server@SREALM to SREALM for krbtgt/CREALM@SREALM -- a regular TGS
        *    request with server's normal TGT and no S4U2Self padata.
        * 2. server@SREALM to CREALM for server@SREALM (expressed as an
        *    enterprise principal), with the TGT from #1 as header ticket and
        *    S4U2Self padata identifying the client.
        * 3. server@SREALM to SREALM for server@SREALM with S4U2Self padata,
        *    with the referral TGT from #2 as header ticket
        *
        * In request 2 the PROTOCOL_TRANSITION and CROSS_REALM flags are set,
        * and the request is for a local client (so client != NULL) and we
        * want to make a new PAC.
        *
        * In request 3 the PROTOCOL_TRANSITION and CROSS_REALM flags are also
        * set, but the request is for a non-local client (so client == NULL)
        * and we want to copy the subject PAC contained in the referral TGT.
        */

    if (old_pac == NULL ||
        (client != NULL && (flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION))) {
        /* generate initial PAC */
        if (with_pac) {
            krb5_boolean force_reinit_mspac = FALSE;
            struct ipadb_context *ipactx = ipadb_get_context(context);
            int result = 0;

            if (!ipactx) {
                kerr = ENOMEM;
                goto done;
            }

            if (client != NULL) {
                /* Be aggressive here: special case for discovering range type
                * immediately after establishing the trust by IPA framework. For all
                * other cases call ipadb_reinit_mspac() with force_reinit_mspac set
                * to 'false' to make sure the information about trusted domains is
                * updated on a regular basis for all worker processes. */
                if ((krb5_princ_size(context, client->princ) == 2) &&
                    (strncmp(krb5_princ_component(context, client->princ, 0)->data, "HTTP",
                            krb5_princ_component(context, client->princ, 0)->length) == 0) &&
                    (ulc_casecmp(krb5_princ_component(context, client->princ, 1)->data,
                                 krb5_princ_component(context, client->princ, 1)->length,
                                 ipactx->kdc_hostname, strlen(ipactx->kdc_hostname),
                                 NULL, NULL, &result) == 0)) {
                    force_reinit_mspac = TRUE;
                }
            }

            /* MS-PAC generator has to be initalized */
            kerr = ipadb_reinit_mspac(ipactx, force_reinit_mspac, &stmsg);
            if (kerr && stmsg)
                krb5_klog_syslog(LOG_ERR, "MS-PAC generator: %s", stmsg);

            /* Continue even if initilization of PAC generator failed.
             * It may caused by the trust objects part only. */

            /* At least the core part of the PAC generator is required. */
            if (!ipactx->mspac)
                return KRB5_PLUGIN_OP_NOTSUPP;

            kerr = ipadb_get_pac(context, flags,
                                 client, server, replaced_reply_key,
                                 authtime, &new_pac);
        }
    } else {
        kerr = ipadb_common_verify_pac(context, flags,
                                        client, server,
                                        signing_krbtgt,
                                        NULL,
                                        authtime,
                                        old_pac, &new_pac);
        if (kerr == ENOENT) {
            kerr = 0;
        }
    }

    /* in krb5 1.20 no need to sign tickets anymore, KDC does it for us */
done:
    return kerr;
}
