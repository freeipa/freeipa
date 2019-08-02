#pragma once

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
