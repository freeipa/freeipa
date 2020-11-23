/*
 * Kerberos related utils for FreeIPA
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
/*
 * Functions krb5_ts2tt, krb5_ts_incr, krb5_ts_after are taken from Kerberos 5:
 * https://github.com/krb5/krb5/blob/master/src/include/k5-int.h
 *
 * Authors: Greg Hudson <ghudson@mit.edu>
 *
 * Copyright (C) 2017
 *
 * This software is being provided to you, the LICENSEE, by the
 * Massachusetts Institute of Technology (M.I.T.) under the following
 * license.  By obtaining, using and/or copying this software, you agree
 * that you have read, understood, and will comply with these terms and
 * conditions:
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute
 * this software and its documentation for any purpose and without fee or
 * royalty is hereby granted, provided that you agree to comply with the
 * following copyright notice and statements, including the disclaimer, and
 * that the same appear on ALL copies of the software and documentation,
 * including modifications that you make for internal use or for
 * distribution:
 *
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.
 *
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT
 * be used in advertising or publicity pertaining to distribution of the
 * software.  Title to copyright in this software and any associated
 * documentation shall at all times remain with M.I.T., and USER agrees to
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 */

#pragma once

#include <stdbool.h>
#include <time.h>
#include <lber.h>
#include <krb5/krb5.h>
#include <kdb.h>
#include <syslog.h>

struct krb_key_salt {
    krb5_enctype enctype;
    krb5_int32 salttype;
    krb5_keyblock key;
    krb5_data salt;
};

struct keys_container {
    krb5_int32 nkeys;
    struct krb_key_salt *ksdata;
};

/* Salt types */
#define NO_SALT                        -1
#define KRB5_KDB_SALTTYPE_NORMAL        0
#define KRB5_KDB_SALTTYPE_V4            1
#define KRB5_KDB_SALTTYPE_NOREALM       2
#define KRB5_KDB_SALTTYPE_ONLYREALM     3
#define KRB5_KDB_SALTTYPE_SPECIAL       4
#define KRB5_KDB_SALTTYPE_AFS3          5

#define KEYTAB_SET_OID "2.16.840.1.113730.3.8.10.1"
#define KEYTAB_RET_OID "2.16.840.1.113730.3.8.10.2"
#define KEYTAB_GET_OID "2.16.840.1.113730.3.8.10.5"

#define IPAPWD_PASSWORD_MAX_LEN 1000
extern const char *ipapwd_password_max_len_errmsg;

int krb5_klog_syslog(int, const char *, ...);

void
ipa_krb5_free_ktypes(krb5_context context, krb5_enctype *val);

krb5_error_code ipa_krb5_principal2salt_norealm(krb5_context context,
                                                krb5_const_principal pr,
                                                krb5_data *ret);

krb5_error_code ipa_krb5_generate_key_data(krb5_context krbctx,
                                           krb5_principal principal,
                                           krb5_data pwd, int kvno,
                                           krb5_keyblock *kmkey,
                                           int num_encsalts,
                                           krb5_key_salt_tuple *encsalts,
                                           int *_num_keys,
                                           krb5_key_data **_keys);

void ipa_krb5_free_key_data(krb5_key_data *keys, int num_keys);

int ber_encode_krb5_key_data(krb5_key_data *data,
                             int numk, int mkvno,
                             struct berval **encoded);
int ber_decode_krb5_key_data(struct berval *encoded, int *m_kvno,
                             int *numk, krb5_key_data **data);

krb5_error_code parse_bval_key_salt_tuples(krb5_context kcontext,
                                           const char * const *vals,
                                           int n_vals,
                                           krb5_key_salt_tuple **kst,
                                           int *n_kst);

krb5_error_code filter_key_salt_tuples(krb5_context context,
                                       krb5_key_salt_tuple *req, int n_req,
                                       krb5_key_salt_tuple *supp, int n_supp,
                                       krb5_key_salt_tuple **res, int *n_res);

void free_keys_contents(krb5_context krbctx, struct keys_container *keys);

struct berval *create_key_control(struct keys_container *keys,
                                  const char *principalName);

int ipa_string_to_enctypes(const char *str, struct krb_key_salt **encsalts,
                           int *num_encsalts, char **err_msg);

int create_keys(krb5_context krbctx,
                krb5_principal princ,
                char *password,
                const char *enctypes_string,
                struct keys_container *keys,
                char **err_msg);

int ipa_kstuples_to_string(krb5_key_salt_tuple *kst, int n_kst, char **str);

/* Convert a krb5_timestamp to a time_t value, treating the negative range of
 * krb5_timestamp as times between 2038 and 2106 (if time_t is 64-bit). */
static inline time_t
krb5_ts2tt(krb5_timestamp timestamp) {
    return (time_t)(uint32_t)timestamp;
}

/* Increment a timestamp by a signed 32-bit interval, without relying on
 * undefined behavior. */
static inline krb5_timestamp
krb5_ts_incr(krb5_timestamp ts, krb5_deltat delta) {
    return (krb5_timestamp)((uint32_t)ts + (uint32_t)delta);
}

/* Return true if a comes after b. */
static inline bool
krb5_ts_after(krb5_timestamp a, krb5_timestamp b) {
    return (uint32_t)a > (uint32_t)b;
}
