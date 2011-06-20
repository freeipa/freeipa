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
    krb5_key_salt_tuple *fks = NULL;
    int n_fks;
    krb5_key_data *keys = NULL;
    int n_keys;
    krb5_key_data *tdata;
    int t_keys;
    int old_kvno;
    int i;

    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
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

