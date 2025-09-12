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

#define _GNU_SOURCE /* for qsort_r() */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <lber.h>

#include <libintl.h>
#define _(STRING) gettext(STRING)

#include "ipa_krb5.h"

#define ENC_BUF_SIZE 64
#define SALT_BUF_SIZE 32

#define TOSTR(x) STR(x)
#define STR(x) #x
const char *ipapwd_password_max_len_errmsg = \
    "clear-text password is too long (max " \
    TOSTR(IPAPWD_PASSWORD_MAX_LEN) \
    " chars)!";

/* Case-insensitive string values to by parsed as boolean true */
static const char *const conf_yes[] = {
    "y", "yes", "true", "t", "1", "on",
    NULL,
};

/* Salt types */
#define KRB5P_SALT_SIZE 16

#define IPA_ADD_SALTTYPE_NORMAL (1 << 0)
#define IPA_ADD_SALTTYPE_SPECIAL (1 << 1)

static krb5_error_code ipa_get_random_salt(krb5_context krbctx,
                                           krb5_data *salt)
{
    krb5_error_code kerr;
    int i, v;

    /* make random salt */
    salt->length = KRB5P_SALT_SIZE;
    salt->data = malloc(KRB5P_SALT_SIZE);
    if (!salt->data) {
        return ENOMEM;
    }
    kerr = krb5_c_random_make_octets(krbctx, salt);
    if (kerr) {
        return kerr;
    }

    /* Windows treats the salt as a string.
     * To avoid any compatibility issue, limits octects only to
     * the ASCII printable range, or 0x20 <= val <= 0x7E */
    for (i = 0; i < salt->length; i++) {
        v = (unsigned char)salt->data[i];
        v %= 0x5E; /* 7E - 20 */
        v += 0x20; /* add base */
        salt->data[i] = v;
    }

    return 0;
}

void
ipa_krb5_free_ktypes(krb5_context context, krb5_enctype *val)
{
    krb5_free_enctypes(context, val);
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

    if ((pwd.data != NULL) && (pwd.length > IPAPWD_PASSWORD_MAX_LEN)) {
        kerr = E2BIG;
        krb5_set_error_message(krbctx, kerr, "%s",
                               ipapwd_password_max_len_errmsg);
        return kerr;
    }

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

            kerr = ipa_get_random_salt(krbctx, &salt);
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
        if (pwd.data == NULL) {
            kerr = krb5_c_make_random_key(krbctx,
                                          encsalts[i].ks_enctype,
                                          &key);
        } else {
            kerr = krb5_c_string_to_key(krbctx,
                                        encsalts[i].ks_enctype,
                                        &pwd, &salt, &key);
        }
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

    if (keys == NULL)
        return;

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

        /* All keys must have the same KVNO, because there is only one attribute
         * for all of them. */
        if (data[i].key_data_kvno != data[0].key_data_kvno) {
            ret = EINVAL;
            goto done;
        }

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

int ber_decode_krb5_key_data(struct berval *encoded, int *m_kvno,
                             int *numk, krb5_key_data **data)
{
    krb5_key_data *keys = NULL;
    BerElement *be = NULL;
    void *tmp;
    int i = 0;
    ber_tag_t tag;
    ber_int_t major_vno;
    ber_int_t minor_vno;
    ber_int_t kvno;
    ber_int_t mkvno;
    ber_int_t type;
    ber_tag_t seqtag;
    ber_len_t seqlen;
    ber_len_t setlen;
    ber_tag_t retag;
    ber_tag_t opttag;
    struct berval tval;
    int ret;

    be = ber_alloc_t(LBER_USE_DER);
    if (!be) {
        return ENOMEM;
    }

    /* reinit the ber element with the new val */
    ber_init2(be, encoded, LBER_USE_DER);

    /* fill key_data struct with the data */
    retag = ber_scanf(be, "{t[i]t[i]t[i]t[i]t[{",
                      &tag, &major_vno,
                      &tag, &minor_vno,
                      &tag, &kvno,
                      &tag, &mkvno,
                      &seqtag);
    if (retag == LBER_ERROR ||
            major_vno != 1 ||
            minor_vno != 1 ||
            seqtag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 4)) {
        ret = EINVAL;
        goto done;
    }

    retag = ber_skip_tag(be, &seqlen);

    /* sequence of keys */
    for (i = 0; retag == LBER_SEQUENCE; i++) {

        tmp = realloc(keys, (i + 1) * sizeof(krb5_key_data));
        if (!tmp) {
            ret = ENOMEM;
            goto done;
        }
        keys = tmp;

        memset(&keys[i], 0, sizeof(krb5_key_data));

        keys[i].key_data_kvno = kvno;

        /* do we have a salt type ? (optional) */
        retag = ber_scanf(be, "t", &opttag);
        if (retag == LBER_ERROR) {
            ret = EINVAL;
            goto done;
        }
        if (opttag == (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0)) {
            keys[i].key_data_ver = 2;

            retag = ber_scanf(be, "[l{tl[i]",
                              &seqlen, &tag, &setlen, &type);
            if (tag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0)) {
                ret = EINVAL;
                goto done;
            }
            keys[i].key_data_type[1] = type;

            /* do we have salt data ? (optional) */
            if (seqlen > setlen + 2) {
                retag = ber_scanf(be, "t[o]", &tag, &tval);
                if (retag == LBER_ERROR ||
                    tag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {
                    ret = EINVAL;
                    goto done;
                }
                keys[i].key_data_length[1] = tval.bv_len;
                keys[i].key_data_contents[1] = (krb5_octet *)tval.bv_val;
            }

            retag = ber_scanf(be, "}]t", &opttag);
            if (retag == LBER_ERROR) {
                ret = EINVAL;
                goto done;
            }

        } else {
            keys[i].key_data_ver = 1;
        }

        if (opttag != (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {
            ret = EINVAL;
            goto done;
        }

        /* get the key */
        retag = ber_scanf(be, "[{t[i]t[o]}]", &tag, &type, &tag, &tval);
        if (retag == LBER_ERROR) {
            ret = EINVAL;
            goto done;
        }
        keys[i].key_data_type[0] = type;
        keys[i].key_data_length[0] = tval.bv_len;
        keys[i].key_data_contents[0] = (krb5_octet *)tval.bv_val;

        /* check for sk2params */
        retag = ber_peek_tag(be, &setlen);
        if (retag == (LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2)) {
            /* not supported yet, skip */
            retag = ber_scanf(be, "t[x]}", &tag);
        } else {
            retag = ber_scanf(be, "}");
        }
        if (retag == LBER_ERROR) {
            ret = EINVAL;
            goto done;
        }

        retag = ber_skip_tag(be, &seqlen);
    }

    ret = 0;

done:
    ber_free(be, 0); /* internal buffer is 'encoded' */
    if (ret) {
        for (i -= 1; keys && i >= 0; i--) {
            free(keys[i].key_data_contents[0]);
            free(keys[i].key_data_contents[1]);
        }
        free(keys);
        keys = NULL;
        mkvno = 0;
    }
    *m_kvno = mkvno;
    *numk = i;
    *data = keys;
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

struct berval *create_key_control(struct keys_container *keys,
                                  const char *principalName)
{
    struct krb_key_salt *ksdata;
    struct berval *bval;
    BerElement *be;
    int ret, i;

    be = ber_alloc_t(LBER_USE_DER);
    if (!be) {
        return NULL;
    }

    ret = ber_printf(be, "{s{", principalName);
    if (ret == -1) {
        ber_free(be, 1);
        return NULL;
    }

    ksdata = keys->ksdata;
    for (i = 0; i < keys->nkeys; i++) {

        /* we set only the EncryptionKey and salt, no s2kparams */

        ret = ber_printf(be, "{t[{t[i]t[o]}]",
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 (ber_int_t)ksdata[i].enctype,
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (char *)ksdata[i].key.contents, (ber_len_t)ksdata[i].key.length);

        if (ret == -1) {
            ber_free(be, 1);
            return NULL;
        }

        if (ksdata[i].salttype == NO_SALT) {
            ret = ber_printf(be, "}");
            if (ret == -1) {
                ber_free(be, 1);
                return NULL;
            }
            continue;
        }

        /* we have to pass a salt structure */
        ret = ber_printf(be, "t[{t[i]t[o]}]}",
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 (ber_int_t)ksdata[i].salttype,
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (char *)ksdata[i].salt.data, (ber_len_t)ksdata[i].salt.length);

        if (ret == -1) {
            ber_free(be, 1);
            return NULL;
        }
    }

    ret = ber_printf(be, "}}");
    if (ret == -1) {
        ber_free(be, 1);
        return NULL;
    }

    ret = ber_flatten(be, &bval);
    if (ret == -1) {
        ber_free(be, 1);
        return NULL;
    }

    ber_free(be, 1);
    return bval;
}

void free_keys_contents(krb5_context krbctx, struct keys_container *keys)
{
    struct krb_key_salt *ksdata;
    int i;

    ksdata = keys->ksdata;
    for (i = 0; i < keys->nkeys; i++) {
        krb5_free_keyblock_contents(krbctx, &ksdata[i].key);
        krb5_free_data_contents(krbctx, &ksdata[i].salt);
    }
    free(ksdata);

    keys->ksdata = NULL;
    keys->nkeys = 0;
}

int ipa_string_to_enctypes(const char *str, struct krb_key_salt **encsalts,
                           int *num_encsalts, char **err_msg)
{
    struct krb_key_salt *ksdata;
    krb5_error_code krberr;
    char *tmp, *t;
    int count;
    int num;

    *err_msg = NULL;

    tmp = strdup(str);
    if (!tmp) {
        *err_msg = _("Out of memory\n");
        return ENOMEM;
    }

    /* count */
    count = 0;
    for (t = tmp; t; t = strchr(t, ',')) {
        count++;
        t++;
    }

    /* at the end we will have at most count entries + 1 terminating */
    ksdata = calloc(count + 1, sizeof(struct krb_key_salt));
    if (!ksdata) {
        *err_msg = _("Out of memory\n");
        free(tmp);
        return ENOMEM;
    }

    num = 0;
    t = tmp;
    for (int i = 0; i < count; i++) {
        char *p, *q;

        p = strchr(t, ',');
        if (p) *p = '\0';

        q = strchr(t, ':');
        if (q) *q++ = '\0';

        krberr = krb5_string_to_enctype(t, &ksdata[num].enctype);
        if (krberr) {
            *err_msg = _("Warning unrecognized encryption type.\n");
            if (p) t = p + 1;
            continue;
        }
        if (p) t = p + 1;

        if (!q) {
            ksdata[num].salttype = KRB5_KDB_SALTTYPE_NORMAL;
            num++;
            continue;
        }

        krberr = krb5_string_to_salttype(q, &ksdata[num].salttype);
        if (krberr) {
            *err_msg = _("Warning unrecognized salt type.\n");
            continue;
        }

        num++;
    }

    *num_encsalts = num;
    *encsalts = ksdata;
    free(tmp);
    return 0;
}

/* Determines Encryption and Salt types,
 * allocates key_salt data storage,
 * filters out equivalent encodings,
 * returns 0 if no enctypes available, >0 if enctypes are available */
static int prep_ksdata(krb5_context krbctx, const char *str,
                       struct keys_container *keys,
                       char **err_msg)
{
    struct krb_key_salt *ksdata;
    krb5_error_code krberr;
    int n, i, j, nkeys;

    *err_msg = NULL;

    if (str == NULL) {
        krb5_enctype *ktypes;

        krberr = krb5_get_permitted_enctypes(krbctx, &ktypes);
        if (krberr) {
            *err_msg = _("No system preferred enctypes ?!\n");
            return 0;
        }

        for (n = 0; ktypes[n]; n++) /* count */ ;

        ksdata = calloc(n + 1, sizeof(struct krb_key_salt));
        if (NULL == ksdata) {
            *err_msg = _("Out of memory!?\n");
            ipa_krb5_free_ktypes(krbctx, ktypes);
            return 0;
        }

        for (i = 0; i < n; i++) {
            ksdata[i].enctype = ktypes[i];
            ksdata[i].salttype = KRB5_KDB_SALTTYPE_NORMAL;
        }

        ipa_krb5_free_ktypes(krbctx, ktypes);

        nkeys = i;

    } else {
        krberr = ipa_string_to_enctypes(str, &ksdata, &nkeys, err_msg);
        if (krberr) {
            return 0;
        }
    }

    /* Check we don't already have a key with a similar encoding,
     * it would just produce redundant data and this is what the
     * MIT code do anyway */

    for (i = 0, n = 0; i < nkeys; i++ ) {
        krb5_boolean similar = 0;

        for (j = 0; j < i; j++) {
            krberr = krb5_c_enctype_compare(krbctx,
                                            ksdata[j].enctype,
                                            ksdata[i].enctype,
                                            &similar);
            if (krberr) {
                free_keys_contents(krbctx, keys);
                free(ksdata);
                *err_msg = _("Enctype comparison failed!\n");
                return 0;
            }
            if (similar &&
                (ksdata[j].salttype == ksdata[i].salttype)) {
                break;
            }
        }
        if (j < i) {
            /* redundant encoding, remove it, and shift others */
            int x;
            for (x = i; x < nkeys-1; x++) {
                ksdata[x].enctype = ksdata[x+1].enctype;
                ksdata[x].salttype = ksdata[x+1].salttype;
            }
            continue;
        }
        /* count only confirmed enc/salt tuples */
        n++;
    }

    keys->nkeys = n;
    keys->ksdata = ksdata;

    return n;
}

int create_keys(krb5_context krbctx,
                krb5_principal princ,
                char *password,
                const char *enctypes_string,
                struct keys_container *keys,
                char **err_msg)
{
    struct krb_key_salt *ksdata;
    krb5_error_code krberr;
    krb5_data key_password;
    krb5_data *realm = NULL;
    int i, nkeys;
    int ret;

    *err_msg = NULL;

    ret = prep_ksdata(krbctx, enctypes_string, keys, err_msg);
    if (ret == 0) return 0;

    ksdata = keys->ksdata;
    nkeys = keys->nkeys;

    if (password) {
        key_password.data = password;
        key_password.length = strlen(password);
        if (key_password.length > IPAPWD_PASSWORD_MAX_LEN) {
            *err_msg = _("Password is too long!\n");
            return 0;
        }

        realm = krb5_princ_realm(krbctx, princ);
    }

    for (i = 0; i < nkeys; i++) {
        krb5_data *salt;

        if (!password) {
            /* cool, random keys */
            krberr = krb5_c_make_random_key(krbctx,
                                            ksdata[i].enctype,
                                            &ksdata[i].key);
            if (krberr) {
                *err_msg = _("Failed to create random key!\n");
                return 0;
            }
            /* set the salt to NO_SALT as the key was random */
            ksdata[i].salttype = NO_SALT;
            continue;
        }

        /* Make keys using password and required salt */
        switch (ksdata[i].salttype) {
        case KRB5_KDB_SALTTYPE_ONLYREALM:
            krberr = krb5_copy_data(krbctx, realm, &salt);
            if (krberr) {
                *err_msg = _("Failed to create key!\n");
                return 0;
            }

            ksdata[i].salt.length = salt->length;
            ksdata[i].salt.data = malloc(salt->length);
            if (!ksdata[i].salt.data) {
                *err_msg = _("Out of memory!\n");
                return 0;
            }
            memcpy(ksdata[i].salt.data, salt->data, salt->length);
            krb5_free_data(krbctx, salt);
            break;

        case KRB5_KDB_SALTTYPE_NOREALM:
            krberr = ipa_krb5_principal2salt_norealm(krbctx, princ,
                                                     &ksdata[i].salt);
            if (krberr) {
                *err_msg = _("Failed to create key!\n");
                return 0;
            }
            break;

        case KRB5_KDB_SALTTYPE_NORMAL:
            krberr = krb5_principal2salt(krbctx, princ, &ksdata[i].salt);
            if (krberr) {
                *err_msg = _("Failed to create key!\n");
                return 0;
            }
            break;

        /* no KRB5_KDB_SALTTYPE_V4, we do not support krb v4 */

        case KRB5_KDB_SALTTYPE_AFS3:
            /* Comment from MIT sources:
             * * Why do we do this? Well, the afs_mit_string_to_key
             * * needs to use strlen, and the realm is not NULL
             * * terminated....
             */
            ksdata[i].salt.data = (char *)malloc(realm->length + 1);
            if (NULL == ksdata[i].salt.data) {
                *err_msg = _("Out of memory!\n");
                return 0;
            }
            memcpy((char *)ksdata[i].salt.data,
                   (char *)realm->data, realm->length);
            ksdata[i].salt.data[realm->length] = '\0';
            /* AFS uses a special length (UGLY) */
            ksdata[i].salt.length = SALT_TYPE_AFS_LENGTH;
            break;

        default:
            *err_msg = _("Bad or unsupported salt type.\n");
/* FIXME:
            fprintf(stderr, _("Bad or unsupported salt type (%d)!\n"),
                ksdata[i].salttype);
*/
            return 0;
        }

        krberr = krb5_c_string_to_key(krbctx,
                                      ksdata[i].enctype,
                                      &key_password,
                                      &ksdata[i].salt,
                                      &ksdata[i].key);
        if (krberr) {
            *err_msg = _("Failed to create key!\n");
            return 0;
        }

        /* set back salt length to real value if AFS3 */
        if (ksdata[i].salttype == KRB5_KDB_SALTTYPE_AFS3) {
            ksdata[i].salt.length = realm->length;
        }
    }

    return nkeys;
}

krb5_error_code
ipa_kstuples_to_string(const krb5_key_salt_tuple *keysalts, size_t n_keysalts,
                       char separator, char **out, size_t *n_out)
{
    krb5_error_code err;
    char encbuf[ENC_BUF_SIZE], saltbuf[SALT_BUF_SIZE], *str = NULL, *p;
    size_t i, n = 0;

    /* Count output string length */
    if (n_keysalts == 0) {
        n = 1; /* output string will contain '\0' only */
    } else {
        for (i = 0; i < n_keysalts; ++i) {
            err = krb5_enctype_to_name(keysalts[i].ks_enctype, false, encbuf,
                                       ENC_BUF_SIZE);
            if (err) goto end;

            n += strnlen(encbuf, ENC_BUF_SIZE); /* enctype */

            ++n; /* colon */

            err = krb5_salttype_to_string(keysalts[i].ks_salttype, saltbuf,
                                          SALT_BUF_SIZE);
            if (err) goto end;

            n += strnlen(saltbuf, SALT_BUF_SIZE); /* salt type */

            ++n; /* separator or \0 */
        }
    }


    /* If "out" is not set, the purpose of this call was just to count the
     * required string length. So skip memory allocation. */
    if (out) {
        str = malloc(n * sizeof(*str));
        if (!str) {
            err = ENOMEM;
            goto end;
        }

        /* Write string to output buffer */
        for (i = 0, p = str; i < n_keysalts; ++i) {
            if (i > 0) *(p++) = separator; /* separator */

            err = krb5_enctype_to_name(keysalts[i].ks_enctype, false, p,
                                       ENC_BUF_SIZE);
            if (err) goto end;

            p += strnlen(p, ENC_BUF_SIZE); /* enctype */

            *(p++) = ':'; /* colon */

            err = krb5_salttype_to_string(keysalts[i].ks_salttype, p,
                                          SALT_BUF_SIZE);
            if (err) goto end;

            p += strnlen(p, SALT_BUF_SIZE); /* salt type */
        }

        str[n-1] = '\0'; /* required for empty list */

        *out = str;
    }

    if (n_out) *n_out = n - 1; /* do not count \0 */

end:
    if (err) free(str);

    return err;
}

bool ipa_krb5_parse_bool(const char *str)
{
    const char *const *p;

    for (p = conf_yes; *p; p++) {
        if (!strcasecmp(*p, str))
            return true;
    }

    return false;
}

bool
ipa_is_cifs_princname(const char *princname)
{
    return 0 == strncmp("cifs/", princname, 5);
}

bool
ipa_is_cifs_dn(const char *dn)
{
#define CIFS_PRINC_PRIMARY "krbprincipalname=cifs/"
    return 0 == strncmp(CIFS_PRINC_PRIMARY, dn, sizeof(CIFS_PRINC_PRIMARY) - 1);
}

bool
ipa_is_cifs_princ(krb5_context kctx, krb5_const_principal princ)
{
    krb5_data *primary;

    if (2 != krb5_princ_size(kctx, princ)) {
        return false;
    }

    primary = krb5_princ_component(kctx, princ, 0);

    if (4 != primary->length) {
        return false;
    }

    return 0 == memcmp(primary->data, "cifs", 4);
}

static krb5_error_code
get_enctype_rank(krb5_context kctx, const krb5_enctype *ptypes,
                 const krb5_enctype *ftypes /* optional */,
                 krb5_enctype enctype, int *rank, bool *unknown)
{
    int i = 0, j = 0;
    krb5_boolean similar;
    krb5_error_code err = 0;

    /* Search enctype in permitted types */
    for (; ptypes[i]; ++i) {
        err = krb5_c_enctype_compare(kctx, enctype, ptypes[i], &similar);
        if (err) return err;
        if (similar) {
            if (unknown) *unknown = false;
            break;
        }
    }
    if (!ptypes[i]) {
        /* If not found, search enctype in fallback types (if provided) */
        if (ftypes) {
            for (; ftypes[j]; ++j) {
                err = krb5_c_enctype_compare(kctx, enctype, ftypes[j],
                                             &similar);
                if (err) return err;
                if (similar) {
                    if (unknown) *unknown = false;
                    i += j;
                    break;
                }
            }
        }
        if (!ftypes || !ftypes[j]) {
            /* If unknown, use value of the enctype identifier */
            if (unknown) *unknown = true;
            i = (INT_MAX / 2) - (int)enctype;
        }
    }

    *rank = i;
    return err;
}

static int
get_salttype_rank(const krb5_int16 *stypes, size_t n_stypes,
                  krb5_int16 salttype)
{
    size_t i;

    /* Search salttype in prioritized list */
    for (i = 0; i < n_stypes; ++i) {
        if (salttype == stypes[i]) {
            return (int)i;
        }
    }

    /* If unknown, use value of the salttype identifier */
    return (INT_MAX / 2) - (int)salttype;
}

struct cmp_krb5_keys_ctx {
    krb5_error_code err;
    krb5_context kctx;
    bool filter_mode;
    krb5_enctype *permitted_enctypes;
    const krb5_enctype *fallback_enctypes;
    const krb5_int16 *salttypes_priority;
    size_t n_salttypes_priority;
};

enum keys_op {
    SORT_ONLY,
    SORT_FILTER,
    SORT_FILTER_NTHASH,
};

static krb5_error_code
init_cmp_ctx(krb5_context kctx, enum keys_op op,
               struct cmp_krb5_keys_ctx *cmpctx)
{
    static const krb5_enctype full_ftypes[] = {
        ENCTYPE_AES256_CTS_HMAC_SHA384_192,
        ENCTYPE_AES128_CTS_HMAC_SHA256_128,
        ENCTYPE_AES256_CTS_HMAC_SHA1_96,
        ENCTYPE_AES128_CTS_HMAC_SHA1_96,
        ENCTYPE_CAMELLIA256_CTS_CMAC,
        ENCTYPE_CAMELLIA128_CTS_CMAC,
        ENCTYPE_ARCFOUR_HMAC,
        ENCTYPE_ARCFOUR_HMAC_EXP,
        0
    };

    static const krb5_enctype nthash_ftypes[] = {
        ENCTYPE_ARCFOUR_HMAC,
        0
    };

    static const krb5_int16 stypes[] = {
        KRB5_KDB_SALTTYPE_SPECIAL,
        KRB5_KDB_SALTTYPE_NORMAL,
        KRB5_KDB_SALTTYPE_NOREALM,
        KRB5_KDB_SALTTYPE_ONLYREALM,
        KRB5_KDB_SALTTYPE_CERTHASH,
    };

    memset(cmpctx, 0, sizeof(*cmpctx));

    cmpctx->kctx = kctx;
    cmpctx->filter_mode = op != SORT_ONLY;

    switch (op) {
    /* Sort non-permitted keys nonetheless because they won't be removed */
    case SORT_ONLY:          cmpctx->fallback_enctypes = full_ftypes;   break;
    /* Fallback not needed, non-permitted types will be removed anyway */
    case SORT_FILTER:        cmpctx->fallback_enctypes = NULL;          break;
    /* RC4 will be kept, even if not permitted */
    case SORT_FILTER_NTHASH: cmpctx->fallback_enctypes = nthash_ftypes; break;
    }

    cmpctx->salttypes_priority = stypes;
    cmpctx->n_salttypes_priority = sizeof(stypes) / sizeof(*stypes);

    return krb5_get_permitted_enctypes(kctx, &cmpctx->permitted_enctypes);
}

static void
deinit_cmp_ctx(struct cmp_krb5_keys_ctx *cmpctx)
{
    krb5_free_enctypes(cmpctx->kctx, cmpctx->permitted_enctypes);
}

static int
cmp_krb5_keysalts_ext(const krb5_key_salt_tuple *ka,
                      const krb5_key_salt_tuple *kb,
                      struct cmp_krb5_keys_ctx *cmpctx,
                      bool *a_unknown, bool *b_unknown)
{
    int rka, rkb;
    krb5_error_code err;

    if (ka->ks_enctype != kb->ks_enctype) {
        /* Enctypes are different */
        err = get_enctype_rank(cmpctx->kctx, cmpctx->permitted_enctypes,
                               cmpctx->fallback_enctypes, ka->ks_enctype, &rka,
                               a_unknown);
        if (err) {
            cmpctx->err = err;
            return 0;
        }

        err = get_enctype_rank(cmpctx->kctx, cmpctx->permitted_enctypes,
                               cmpctx->fallback_enctypes, kb->ks_enctype, &rkb,
                               b_unknown);
        if (err) {
            cmpctx->err = err;
            return 0;
        }

        return rka - rkb;
    }

    if (ka->ks_salttype != kb->ks_salttype) {
        /* Salt types are different */
        rka = get_salttype_rank(cmpctx->salttypes_priority,
                                cmpctx->n_salttypes_priority, ka->ks_salttype);
        rkb = get_salttype_rank(cmpctx->salttypes_priority,
                                cmpctx->n_salttypes_priority, kb->ks_salttype);
        return rka - rkb;
    }

    /* Types are identical */
    return 0;
}

static int
cmp_krb5_keysalts(const void *a, const void *b, void *arg)
{
    const krb5_key_salt_tuple *ka, *kb;
    struct cmp_krb5_keys_ctx *cmpctx;

    ka = (krb5_key_salt_tuple *)a;
    kb = (krb5_key_salt_tuple *)b;
    cmpctx = arg;

    /* If an error was raised, stop sorting */
    if (cmpctx->err) {
        return 0;
    }

    return cmp_krb5_keysalts_ext(ka, kb, cmpctx, NULL, NULL);
}

static int
cmp_krb5_keys(const void *a, const void *b, void *arg)
{
    const krb5_key_data *ka, *kb;
    struct cmp_krb5_keys_ctx *cmpctx;
    krb5_key_salt_tuple ksta, kstb;
    bool a_unknown, b_unknown;
    int ret;

    ka = (krb5_key_data *)a;
    kb = (krb5_key_data *)b;
    cmpctx = arg;

    /* If an error was raised, stop sorting */
    if (cmpctx->err) {
        return 0;
    }

    if (!cmpctx->filter_mode && ka->key_data_kvno != kb->key_data_kvno) {
        /* If not in filter mode and KVNOs are different, compare KVNOs only */
        return (int)ka->key_data_kvno - (int)kb->key_data_kvno;
    }

    ksta = (krb5_key_salt_tuple){ ka->key_data_type[0], ka->key_data_type[1] };
    kstb = (krb5_key_salt_tuple){ kb->key_data_type[0], kb->key_data_type[1] };

    ret = cmp_krb5_keysalts_ext(&ksta, &kstb, cmpctx, &a_unknown, &b_unknown);

    if (cmpctx->filter_mode) {
        /* In filter mode, unknown types go to the end of the list (unsorted) */
        if (a_unknown) {
            return 1;
        } else if (b_unknown) {
            return -1;
        }

        if (ka->key_data_kvno != kb->key_data_kvno) {
            /* In filter mode, sort by KVNOs only if both types known */
            return (int)ka->key_data_kvno - (int)kb->key_data_kvno;
        }
    }
    return ret;
}

static bool
is_permitted(enum keys_op op, krb5_enctype *ptypes, krb5_enctype e)
{
    size_t i;

    if (op == SORT_FILTER_NTHASH && e == ENCTYPE_ARCFOUR_HMAC) {
        return true;
    }

    for (i=0; ptypes[i] && ptypes[i] != e; ++i);

    return ptypes[i] == e;
}

static krb5_error_code
process_keys_by_pref(enum keys_op op, krb5_context kctx, krb5_key_data *keys,
                     size_t *n_keys)
{
    krb5_error_code err;
    struct cmp_krb5_keys_ctx cmpctx;
    size_t i, n;

    err = init_cmp_ctx(kctx, op, &cmpctx);
    if (err) goto end;

    /* Sort keys by decreasing order of preference */
    qsort_r(keys, *n_keys, sizeof(*keys), cmp_krb5_keys, &cmpctx);

    if (cmpctx.err) {
        /* An error occurred while sorting, raise and abort */
        err = cmpctx.err;
        goto end;
    }

    if (op != SORT_ONLY) {
        /* If there are non-permitted key types, the sorting moved them to the
         * end of the list. So we can reverse-iterate on the list to count them,
         * and decrement the number of keys accordingly to remove them. */
        n = *n_keys;
        for (i = n; i-- > 0; ) {
            if (is_permitted(op, cmpctx.permitted_enctypes,
                             keys[i].key_data_type[0])) {
                break;
            } else {
                --n;
            }
        }
        *n_keys = n;
    }

end:
    deinit_cmp_ctx(&cmpctx);
    return err;
}

static krb5_error_code
process_keysalt_types_by_pref(enum keys_op op, krb5_context kctx,
                              krb5_key_salt_tuple *ks, size_t *n_ks)
{
    krb5_error_code err;
    struct cmp_krb5_keys_ctx cmpctx;
    size_t i, n;

    err = init_cmp_ctx(kctx, op, &cmpctx);
    if (err) goto end;

    /* Sort types by decreasing order of preference */
    qsort_r(ks, *n_ks, sizeof(*ks), cmp_krb5_keysalts, &cmpctx);

    if (cmpctx.err) {
        /* An error occurred while sorting, raise and abort */
        err = cmpctx.err;
        goto end;
    }

    if (op != SORT_ONLY) {
        /* If there are non-permitted key types, the sorting moved them to the
         * end of the list. So we can reverse-iterate on the list to count them,
         * and decrement the number of types accordingly to remove them. */
        n = *n_ks;
        for (i = n; i-- > 0; ) {
            if (is_permitted(op, cmpctx.permitted_enctypes,
                             ks[i].ks_enctype)) {
                break;
            } else {
                --n;
            }
        }
        *n_ks = n;
    }

end:
    deinit_cmp_ctx(&cmpctx);
    return err;
}

krb5_error_code
ipa_sort_keys(krb5_context kctx, krb5_key_data *keys, size_t n_keys)
{
    return process_keys_by_pref(SORT_ONLY, kctx, keys, &n_keys);
}

krb5_error_code
ipa_sort_and_filter_keys(krb5_context kctx, krb5_key_data *keys, size_t *n_keys,
                         bool allow_nthash)
{
    return process_keys_by_pref(allow_nthash ? SORT_FILTER_NTHASH : SORT_FILTER,
                                kctx, keys, n_keys);
}

krb5_error_code
ipa_sort_keysalt_types(krb5_context kctx, krb5_key_salt_tuple *ks, size_t n_ks)
{
    return process_keysalt_types_by_pref(SORT_ONLY, kctx, ks, &n_ks);
}

krb5_error_code
ipa_sort_and_filter_keysalt_types(krb5_context kctx, krb5_key_salt_tuple *ks,
                                  size_t *n_ks, bool allow_nthash)
{
    return process_keysalt_types_by_pref(
        allow_nthash ? SORT_FILTER_NTHASH : SORT_FILTER, kctx, ks, n_ks);
}

krb5_error_code
ipa_sort_and_filter_keysalt_types_i(krb5_context kctx, krb5_key_salt_tuple *ks,
                                    int *n_ks, bool allow_nthash)
{
    krb5_error_code err;
    size_t in_n_ks = *n_ks;

    err = ipa_sort_and_filter_keysalt_types(kctx, ks, &in_n_ks, allow_nthash);
    if (!err) {
        *n_ks = (int)in_n_ks;
    }

    return err;
}

krb5_error_code
ipa_sort_and_filter_keys_i(krb5_context kctx, krb5_key_data *keys, int *n_keys,
                           bool allow_nthash)
{
    krb5_error_code err;
    size_t in_n_keys = *n_keys;

    err = ipa_sort_and_filter_keys(kctx, keys, &in_n_keys, allow_nthash);
    if (!err) {
        *n_keys = (int)in_n_keys;
    }

    return err;
}

static krb5_error_code
permitted_to_keysalt_types(krb5_context kctx, krb5_key_salt_tuple **keysalts,
                           size_t *n_keysalts, unsigned int add_salt_types)
{
    krb5_error_code err;
    krb5_enctype *ptypes;
    /* Index and number of enctypes and key/salt pairs */
    size_t ie, n_enctypes, iks, n_ks;
    krb5_key_salt_tuple *ksts = NULL;
    bool add_normal = add_salt_types & IPA_ADD_SALTTYPE_NORMAL;
    bool add_special = add_salt_types & IPA_ADD_SALTTYPE_SPECIAL;

    err = krb5_get_permitted_enctypes(kctx, &ptypes);
    if (err) goto end;

    for (n_enctypes = 0; ptypes[n_enctypes]; ++n_enctypes);

    n_ks = 0;
    if (add_normal) n_ks += n_enctypes;
    if (add_special) n_ks += n_enctypes;

    ksts = calloc(n_ks, sizeof(*ksts));
    if (!ksts) {
        err = ENOMEM;
        goto end;
    }

    iks = 0;
    for (ie = 0; ie < n_enctypes; ++ie) {
        /* Special salt type is prioritized over normal type. */
        if (add_special) {
            ksts[iks++] = (krb5_key_salt_tuple){
                ptypes[ie], KRB5_KDB_SALTTYPE_SPECIAL };
        }
        if (add_normal) {
            ksts[iks++] = (krb5_key_salt_tuple){
                ptypes[ie], KRB5_KDB_SALTTYPE_NORMAL };
        }
    }

    *keysalts = ksts;
    *n_keysalts = n_ks;

end:
    krb5_free_enctypes(kctx, ptypes);
    return err;
}

krb5_error_code
ipa_get_default_types(krb5_context kctx, krb5_key_salt_tuple **keysalts,
                      size_t *n_keysalts)
{
    return permitted_to_keysalt_types(kctx, keysalts, n_keysalts,
                                      IPA_ADD_SALTTYPE_SPECIAL);
}

krb5_error_code
ipa_get_supported_types(krb5_context kctx, krb5_key_salt_tuple **keysalts,
                        size_t *n_keysalts)
{
    return permitted_to_keysalt_types(kctx, keysalts, n_keysalts,
                                      IPA_ADD_SALTTYPE_NORMAL |
                                      IPA_ADD_SALTTYPE_SPECIAL);
}

krb5_error_code
ipa_get_randkey_types(krb5_context kctx, krb5_key_salt_tuple **keysalts,
                      size_t *n_keysalts)
{
    return permitted_to_keysalt_types(kctx, keysalts, n_keysalts,
                                      IPA_ADD_SALTTYPE_NORMAL);
}
