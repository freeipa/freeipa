#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <lber.h>
#include <errno.h>

#include "ipa_krb5.h"

/* Salt types */
#define KRB5P_SALT_SIZE 16

void
ipa_krb5_free_ktypes(krb5_context context, krb5_enctype *val)
{
    free(val);
}

/*
 * Convert a krb5_principal into the default salt for that principal.
 */
krb5_error_code ipa_krb5_principal2salt_norealm(krb5_context context,
                                                krb5_const_principal pr,
                                                krb5_data *ret)
{
    unsigned int size = 0, offset=0;
    krb5_int32 nelem;
    register int i;

    if (pr == NULL) {
        ret->length = 0;
        ret->data = NULL;
        return 0;
    }

    nelem = krb5_princ_size(context, pr);

    for (i = 0; i < (int) nelem; i++)
        size += krb5_princ_component(context, pr, i)->length;

    ret->length = size;
    if (!(ret->data = malloc (size)))
        return ENOMEM;

    for (i = 0; i < (int) nelem; i++) {
        memcpy(&ret->data[offset], krb5_princ_component(context, pr, i)->data,
               krb5_princ_component(context, pr, i)->length);
        offset += krb5_princ_component(context, pr, i)->length;
    }
    return 0;
}

void krb5int_c_free_keyblock_contents(krb5_context context,
                                      register krb5_keyblock *key);

/*
 * Generate a krb5_key_data set by encrypting keys according to
 * enctype/salttype preferences
 */
krb5_error_code ipa_krb5_generate_key_data(krb5_context krbctx,
                                           krb5_principal principal,
                                           krb5_data pwd, int kvno,
                                           krb5_keyblock *kmkey,
                                           int num_encsalts,
                                           krb5_key_salt_tuple *encsalts,
                                           int *_num_keys,
                                           krb5_key_data **_keys)
{
    krb5_error_code kerr;
    krb5_key_data *keys;
    int num_keys;
    int i;

    num_keys = num_encsalts;
    keys = calloc(num_keys, sizeof(krb5_key_data));
    if (!keys) {
        return ENOMEM;
    }

    for (i = 0; i < num_keys; i++) {
        krb5_keyblock key;
        krb5_data salt;
        krb5_octet *ptr;
        krb5_data plain;
        krb5_enc_data cipher;
        krb5_int16 t;
        size_t len;

        salt.data = NULL;

        keys[i].key_data_ver = 2; /* we always have a salt */
        keys[i].key_data_kvno = kvno;

        switch (encsalts[i].ks_salttype) {

        case KRB5_KDB_SALTTYPE_ONLYREALM:

            if (!principal->realm.data) {
                kerr = EINVAL;
                goto done;
            }
            salt.length = principal->realm.length;
            salt.data = malloc(salt.length);
            if (!salt.data) {
                kerr = ENOMEM;
                goto done;
            }
            memcpy(salt.data, principal->realm.data, salt.length);
            break;

        case KRB5_KDB_SALTTYPE_NOREALM:

            kerr = ipa_krb5_principal2salt_norealm(krbctx, principal, &salt);
            if (kerr) {
                goto done;
            }
            break;

        case KRB5_KDB_SALTTYPE_NORMAL:

            kerr = krb5_principal2salt(krbctx, principal, &salt);
            if (kerr) {
                goto done;
            }
            break;

        case KRB5_KDB_SALTTYPE_SPECIAL:

            /* make random salt */
            salt.length = KRB5P_SALT_SIZE;
            salt.data = malloc(KRB5P_SALT_SIZE);
            if (!salt.data) {
                kerr = ENOMEM;
                goto done;
            }
            kerr = krb5_c_random_make_octets(krbctx, &salt);
            if (kerr) {
                goto done;
            }
            break;

        case KRB5_KDB_SALTTYPE_V4:
            salt.length = 0;
            break;

        case KRB5_KDB_SALTTYPE_AFS3:

            if (!principal->realm.data) {
                kerr = EINVAL;
                goto done;
            }
            salt.data = strndup((char *)principal->realm.data,
                                        principal->realm.length);
            if (!salt.data) {
                kerr = ENOMEM;
                goto done;
            }
            salt.length = SALT_TYPE_AFS_LENGTH; /* special value */
            break;

        default:
            kerr = EINVAL;
            goto done;
        }

        /* need to build the key now to manage the AFS salt.length
         * special case */
        kerr = krb5_c_string_to_key(krbctx,
                                    encsalts[i].ks_enctype,
                                    &pwd, &salt, &key);
        if (kerr) {
            krb5_free_data_contents(krbctx, &salt);
            goto done;
        }
        if (salt.length == SALT_TYPE_AFS_LENGTH) {
            salt.length = strlen(salt.data);
        }

        kerr = krb5_c_encrypt_length(krbctx,
                                     kmkey->enctype, key.length, &len);
        if (kerr) {
            krb5int_c_free_keyblock_contents(krbctx, &key);
            krb5_free_data_contents(krbctx, &salt);
            goto done;
        }

        if ((ptr = (krb5_octet *) malloc(2 + len)) == NULL) {
            kerr = ENOMEM;
            krb5int_c_free_keyblock_contents(krbctx, &key);
            krb5_free_data_contents(krbctx, &salt);
            goto done;
        }

        t = htole16(key.length);
        memcpy(ptr, &t, 2);

        plain.length = key.length;
        plain.data = (char *)key.contents;

        cipher.ciphertext.length = len;
        cipher.ciphertext.data = (char *)ptr+2;

        kerr = krb5_c_encrypt(krbctx, kmkey, 0, 0, &plain, &cipher);
        if (kerr) {
            krb5int_c_free_keyblock_contents(krbctx, &key);
            krb5_free_data_contents(krbctx, &salt);
            free(ptr);
            goto done;
        }

        /* KrbSalt  */
        keys[i].key_data_type[1] = encsalts[i].ks_salttype;

        if (salt.length) {
            keys[i].key_data_length[1] = salt.length;
            keys[i].key_data_contents[1] = (krb5_octet *)salt.data;
        }

        /* EncryptionKey */
        keys[i].key_data_type[0] = key.enctype;
        keys[i].key_data_length[0] = len + 2;
        keys[i].key_data_contents[0] = malloc(len + 2);
        if (!keys[i].key_data_contents[0]) {
            kerr = ENOMEM;
            krb5int_c_free_keyblock_contents(krbctx, &key);
            free(ptr);
            goto done;
        }
        memcpy(keys[i].key_data_contents[0], ptr, len + 2);

        /* make sure we free the memory used now that we are done with it */
        krb5int_c_free_keyblock_contents(krbctx, &key);
        free(ptr);
    }

    *_num_keys = num_keys;
    *_keys = keys;
    kerr = 0;

done:
    if (kerr) {
        ipa_krb5_free_key_data(keys, num_keys);
    }

    return kerr;
}

void ipa_krb5_free_key_data(krb5_key_data *keys, int num_keys)
{
    int i;

    for (i = 0; i < num_keys; i++) {
        /* try to wipe key from memory,
         * hopefully the compiler will not optimize it away */
        if (keys[i].key_data_length[0]) {
            memset(keys[i].key_data_contents[0],
                   0, keys[i].key_data_length[0]);
        }
        free(keys[i].key_data_contents[0]);
        free(keys[i].key_data_contents[1]);
    }
    free(keys);
}

/* Novell key-format scheme:

   KrbKeySet ::= SEQUENCE {
   attribute-major-vno       [0] UInt16,
   attribute-minor-vno       [1] UInt16,
   kvno                      [2] UInt32,
   mkvno                     [3] UInt32 OPTIONAL,
   keys                      [4] SEQUENCE OF KrbKey,
   ...
   }

   KrbKey ::= SEQUENCE {
   salt      [0] KrbSalt OPTIONAL,
   key       [1] EncryptionKey,
   s2kparams [2] OCTET STRING OPTIONAL,
    ...
   }

   KrbSalt ::= SEQUENCE {
   type      [0] Int32,
   salt      [1] OCTET STRING OPTIONAL
   }

   EncryptionKey ::= SEQUENCE {
   keytype   [0] Int32,
   keyvalue  [1] OCTET STRING
   }

 */

int ber_encode_krb5_key_data(krb5_key_data *data,
                             int numk, int mkvno,
                             struct berval **encoded)
{
    BerElement *be = NULL;
    ber_tag_t tag;
    int ret, i;

    be = ber_alloc_t(LBER_USE_DER);
    if (!be) {
        return ENOMEM;
    }

    tag = LBER_CONSTRUCTED | LBER_CLASS_CONTEXT;

    ret = ber_printf(be, "{t[i]t[i]t[i]t[i]t[{",
                         tag | 0, 1, tag | 1, 1,
                         tag | 2, (ber_int_t)data[0].key_data_kvno,
                         tag | 3, (ber_int_t)mkvno, tag | 4);
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    for (i = 0; i < numk; i++) {

        ret = ber_printf(be, "{");
        if (ret == -1) {
            ret = EFAULT;
            goto done;
        }

        if (data[i].key_data_length[1] != 0) {
            ret = ber_printf(be, "t[{t[i]",
                                 tag | 0,
                                   tag | 0,
                                     (ber_int_t)data[i].key_data_type[1]);
            if (ret != -1) {
                ret = ber_printf(be, "t[o]",
                                     tag | 1,
                                       data[i].key_data_contents[1],
                                       (ber_len_t)data[i].key_data_length[1]);
            }
            if (ret != -1) {
                ret = ber_printf(be, "}]");
            }
            if (ret == -1) {
                ret = EFAULT;
                goto done;
            }
        }

        ret = ber_printf(be, "t[{t[i]t[o]}]",
                              tag | 1,
                                tag | 0,
                                  (ber_int_t)data[i].key_data_type[0],
                                tag | 1,
                                  data[i].key_data_contents[0],
                                  (ber_len_t)data[i].key_data_length[0]);
        if (ret == -1) {
            ret = EFAULT;
            goto done;
        }

        ret = ber_printf(be, "}");
        if (ret == -1) {
            ret = EFAULT;
            goto done;
        }
    }

    ret = ber_printf(be, "}]}");
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

    ret = ber_flatten(be, encoded);
    if (ret == -1) {
        ret = EFAULT;
        goto done;
    }

done:
    ber_free(be, 1);
    return ret;
}

krb5_error_code parse_bval_key_salt_tuples(krb5_context kcontext,
                                           const char * const *vals,
                                           int n_vals,
                                           krb5_key_salt_tuple **kst,
                                           int *n_kst)
{
    krb5_error_code kerr;
    krb5_key_salt_tuple *ks;
    int n_ks;
    int i;

    ks = calloc(n_vals + 1, sizeof(krb5_key_salt_tuple));
    if (!ks) {
        return ENOMEM;
    }

    for (i = 0, n_ks = 0; i < n_vals; i++) {
        char *enc, *salt;
        krb5_int32 tmpsalt;
        krb5_enctype tmpenc;
        krb5_boolean similar;
        krb5_error_code krberr;
        int j;

        enc = strdup(vals[i]);
        if (!enc) {
            kerr = ENOMEM;
            goto fail;
        }

        salt = strchr(enc, ':');
        if (!salt) {
            free(enc);
            continue;
        }
        *salt = '\0'; /* null terminate the enc type */
        salt++; /* skip : */

        krberr = krb5_string_to_enctype(enc, &tmpenc);
        if (krberr) {
            free(enc);
            continue;
        }

        krberr = krb5_string_to_salttype(salt, &tmpsalt);
        for (j = 0; j < n_ks; j++) {
            krb5_c_enctype_compare(kcontext,
                                   ks[j].ks_enctype, tmpenc, &similar);
            if (similar && (ks[j].ks_salttype == tmpsalt)) {
                break;
            }
        }

        if (j == n_ks) {
            /* not found */
            ks[j].ks_enctype = tmpenc;
            ks[j].ks_salttype = tmpsalt;
            n_ks++;
        }

        free(enc);
    }

    *kst = ks;
    *n_kst = n_ks;

    return 0;

fail:
    free(ks);
    return kerr;
}

krb5_error_code filter_key_salt_tuples(krb5_context context,
                                       krb5_key_salt_tuple *req, int n_req,
                                       krb5_key_salt_tuple *supp, int n_supp,
                                       krb5_key_salt_tuple **res, int *n_res)
{
    krb5_key_salt_tuple *ks = NULL;
    int n_ks;
    int i, j;

    ks = calloc(n_req, sizeof(krb5_key_salt_tuple));
    if (!ks) {
        return ENOMEM;
    }
    n_ks = 0;

    for (i = 0; i < n_req; i++) {
        for (j = 0; j < n_supp; j++) {
            if (req[i].ks_enctype == supp[j].ks_enctype &&
                req[i].ks_salttype == supp[j].ks_salttype) {
                break;
            }
        }
        if (j < n_supp) {
            ks[n_ks] = req[i];
            n_ks++;
        }
    }

    *res = ks;
    *n_res = n_ks;
    return 0;
}

