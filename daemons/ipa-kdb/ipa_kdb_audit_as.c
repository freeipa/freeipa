/*
 * MIT Kerberos KDC database backend for FreeIPA
 *
 * Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2012  Simo Sorce, Red Hat
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
#include "ipa_pwd.h"

void ipadb_audit_as_req(krb5_context kcontext,
                        krb5_kdc_req *request,
#if (KRB5_KDB_DAL_MAJOR_VERSION == 7)
                        const krb5_address *local_addr,
                        const krb5_address *remote_addr,
#endif
                        krb5_db_entry *client,
                        krb5_db_entry *server,
                        krb5_timestamp authtime,
                        krb5_error_code error_code)
{
    const struct ipadb_global_config *gcfg;
    struct ipadb_context *ipactx;
    struct ipadb_e_data *ied;
    krb5_error_code kerr;

    if (!client) {
        return;
    }

    if (error_code != 0 &&
        error_code != KRB5KDC_ERR_PREAUTH_FAILED &&
        error_code != KRB5KRB_AP_ERR_BAD_INTEGRITY) {
        return;
    }

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return;
    }

    ied = (struct ipadb_e_data *)client->e_data;
    if (!ied) {
        return;
    }

    if (!ied->pol) {
        kerr = ipadb_get_ipapwd_policy(ipactx, ied->pw_policy_dn, &ied->pol);
        if (kerr != 0) {
            return;
        }
    }

    client->mask = 0;

    gcfg = ipadb_get_global_config(ipactx);
    if (gcfg == NULL)
        return;

    switch (error_code) {
    case 0:
        /* Check if preauth flag is specified (default), otherwise we have
        * no data to know if auth was successful or not */
        if (client->attributes & KRB5_KDB_REQUIRES_PRE_AUTH) {
            if (client->fail_auth_count != 0) {
                client->fail_auth_count = 0;
                client->mask |= KMASK_FAIL_AUTH_COUNT;
            }
            if (gcfg->disable_last_success) {
                break;
            }
            client->last_success = authtime;
            client->mask |= KMASK_LAST_SUCCESS;
        }
        break;

    case KRB5KDC_ERR_PREAUTH_FAILED:
    case KRB5KRB_AP_ERR_BAD_INTEGRITY:

        if (gcfg->disable_lockout) {
            break;
        }

        if (client->last_failed <= ied->last_admin_unlock) {
            /* Reset fail_auth_count, and admin unlocked the account */
            client->fail_auth_count = 0;
            client->mask |= KMASK_FAIL_AUTH_COUNT;
        }
        if (ied->pol->lockout_duration != 0 &&
            ied->pol->failcnt_interval != 0 &&
            client->last_failed + ied->pol->failcnt_interval < authtime) {
            /* Reset fail_auth_count, the interval's expired already */
            client->fail_auth_count = 0;
            client->mask |= KMASK_FAIL_AUTH_COUNT;
        }

        if (client->last_failed + ied->pol->lockout_duration > authtime &&
            (client->fail_auth_count >= ied->pol->max_fail && 
             ied->pol->max_fail != 0)) {
            /* client already locked, nothing more to do */
            break;
        }
        if (ied->pol->max_fail == 0 ||
            client->fail_auth_count < ied->pol->max_fail) {
            /* let's increase the fail counter */
            client->fail_auth_count++;
            client->mask |= KMASK_FAIL_AUTH_COUNT;
        }
        client->last_failed = authtime;
        client->mask |= KMASK_LAST_FAILED;
        break;
    default:
        krb5_klog_syslog(LOG_ERR,
                         "File '%s' line %d: Got an unexpected value of "
                         "error_code: %d\n", __FILE__, __LINE__, error_code);
        return;
    }

    if (client->mask) {
        kerr = ipadb_put_principal(kcontext, client, NULL);
        if (kerr != 0) {
            return;
        }
    }
    client->mask = 0;
}
