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
#include "ipa_pwd.h"
#include <kadm5/kadm_err.h>

static krb5_error_code ipapwd_error_to_kerr(krb5_context context,
                                            enum ipapwd_error err)
{
    krb5_error_code kerr;

    switch(err) {
    case IPAPWD_POLICY_OK:
        kerr = 0;
        break;
    case IPAPWD_POLICY_ACCOUNT_EXPIRED:
        kerr = KADM5_BAD_PRINCIPAL;
        krb5_set_error_message(context, kerr, "Account expired");
        break;
    case IPAPWD_POLICY_PWD_TOO_YOUNG:
        kerr = KADM5_PASS_TOOSOON;
        krb5_set_error_message(context, kerr, "Too soon to change password");
        break;
    case IPAPWD_POLICY_PWD_TOO_SHORT:
        kerr = KADM5_PASS_Q_TOOSHORT;
        krb5_set_error_message(context, kerr, "Password is too short");
        break;
    case IPAPWD_POLICY_PWD_IN_HISTORY:
        kerr = KADM5_PASS_REUSE;
        krb5_set_error_message(context, kerr, "Password reuse not permitted");
        break;
    case IPAPWD_POLICY_PWD_COMPLEXITY:
        kerr = KADM5_PASS_Q_CLASS;
        krb5_set_error_message(context, kerr, "Password is too simple");
        break;
    default:
        kerr = KADM5_PASS_Q_GENERIC;
        break;
    }

    return kerr;
}

static krb5_error_code ipadb_check_pw_policy(krb5_context context,
                                             char *passwd,
                                             krb5_db_entry *db_entry)
{
    krb5_error_code kerr;
    struct ipadb_e_data *ied;
    struct ipadb_context *ipactx;
    int ret;

    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    ied = (struct ipadb_e_data *)db_entry->e_data;
    if (ied->magic != IPA_E_DATA_MAGIC) {
        return EINVAL;
    }

    ied->passwd = strdup(passwd);
    if (!ied->passwd) {
        return ENOMEM;
    }

    kerr = ipadb_get_ipapwd_policy(ipactx, ied->pw_policy_dn, &ied->pol);
    if (kerr != 0) {
        return kerr;
    }
    ret = ipapwd_check_policy(ied->pol, passwd, time(NULL),
                              db_entry->expiration,
                              db_entry->pw_expiration,
                              ied->last_pwd_change,
                              ied->pw_history);
    return ipapwd_error_to_kerr(context, ret);
}

krb5_error_code ipadb_change_pwd(krb5_context context,
                                 krb5_keyblock *master_key,
                                 krb5_key_salt_tuple *ks_tuple,
                                 int ks_tuple_count, char *passwd,
                                 int new_kvno, krb5_boolean keepold,
                                 krb5_db_entry *db_entry)
{
    krb5_error_code kerr;
    krb5_data pwd;
    struct ipadb_context *ipactx;
    struct ipadb_e_data *ied;
    krb5_key_salt_tuple *fks = NULL;
    int n_fks;
    krb5_key_data *keys = NULL;
    int n_keys;
    krb5_key_data *tdata;
    int t_keys;
    int old_kvno;
    int ret;
    int i;

    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    if (!db_entry->e_data) {
        if (!ipactx->override_restrictions) {
            return EINVAL;
        } else {
            /* kadmin is creating a new principal */
            ied = calloc(1, sizeof(struct ipadb_e_data));
            if (!ied) {
                return ENOMEM;
            }
            ied->magic = IPA_E_DATA_MAGIC;
            /* set the default policy on new entries */
            ret = asprintf(&ied->pw_policy_dn,
                           "cn=global_policy,%s", ipactx->realm_base);
            if (ret == -1) {
                free(ied);
                return ENOMEM;
            }
            db_entry->e_data = (krb5_octet *)ied;
        }
    }

    /* check pwd policy before doing any other work */
    kerr = ipadb_check_pw_policy(context, passwd, db_entry);
    if (kerr) {
        return kerr;
    }

    old_kvno = krb5_db_get_key_data_kvno(context, db_entry->n_key_data,
                                         db_entry->key_data);
    if (old_kvno >= new_kvno) {
        new_kvno = old_kvno + 1;
    }

    pwd.data = passwd;
    pwd.length = strlen(passwd);

    /* We further filter supported enctypes to restrict to the list
     * we have in ldap */
    kerr = filter_key_salt_tuples(context, ks_tuple, ks_tuple_count,
                                       ipactx->supp_encs, ipactx->n_supp_encs,
                                       &fks, &n_fks);
    if (kerr) {
        return kerr;
    }

    kerr = ipa_krb5_generate_key_data(context, db_entry->princ,
                                      pwd, new_kvno, master_key,
                                      n_fks, fks, &n_keys, &keys);
    free(fks);
    if (kerr) {
        return kerr;
    }

    if (keepold) {
        /* need to add the new keys to the old list */
        t_keys = db_entry->n_key_data;

        tdata = realloc(db_entry->key_data,
                        sizeof(krb5_key_data) * (t_keys + n_keys));
        if (!tdata) {
            ipa_krb5_free_key_data(keys, n_keys);
            return ENOMEM;
        }
        db_entry->key_data = tdata;
        db_entry->n_key_data = t_keys + n_keys;

        for (i = 0; i < n_keys; i++) {
            db_entry->key_data[t_keys + i] = keys[i];
        }
        free(keys);

    } else {

        ipa_krb5_free_key_data(db_entry->key_data, db_entry->n_key_data);
        db_entry->key_data = keys;
        db_entry->n_key_data = n_keys;
    }

    return 0;
}

/*
 * Check who actually changed the password, if it is not 'self' then
 * we need to expire it if it is a user principal.
 */
krb5_error_code ipadb_get_pwd_expiration(krb5_context context,
                                         krb5_db_entry *entry,
                                         struct ipadb_e_data *ied,
                                         time_t *expire_time)
{
    krb5_error_code kerr;
    krb5_timestamp mod_time = 0;
    krb5_principal mod_princ = NULL;
    krb5_boolean truexp = true;

    if (ied->ipa_user) {
        kerr = krb5_dbe_lookup_mod_princ_data(context, entry,
                                              &mod_time, &mod_princ);
        if (kerr) {
            goto done;
        }

        /* If the mod principal is kadmind then we have to assume an actual
         * password change for now. Apparently kadmind does not properly pass
         * the actual user principal down when said user is performing a
         * password change */
        if (mod_princ->length == 1 &&
            strcmp(mod_princ->data[0].data, "kadmind") != 0) {
            truexp = krb5_principal_compare(context, mod_princ, entry->princ);
        }
    }

    if (truexp) {
        if (ied->pol) {
            *expire_time = mod_time + ied->pol->max_pwd_life;
        } else {
            *expire_time = mod_time + IPAPWD_DEFAULT_PWDLIFE;
        }
    } else {
        /* not 'self', so reset */
        *expire_time = mod_time;
    }

    kerr = 0;

done:
    krb5_free_principal(context, mod_princ);
    return kerr;
}
