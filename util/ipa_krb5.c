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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <lber.h>
#include <errno.h>

#include <libintl.h>
#define _(STRING) gettext(STRING)

#include "ipa_krb5.h"

/* Salt types */
#define KRB5P_SALT_SIZE 16

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
    count++; /* count the last one that is 0 terminated instead */

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

/* in older versions of libkrb5 the krb5_salttype_to_string() function is
 * faulty and returns strings that do not match the expected format.
 * Later version of krb5 were fixed to return the proper string.
 * Do lazy detection the first time the function is invoked to determine
 * if we can use the library provided function or if we have to use a
 * fallback map which includes the salt types known up to krb5 1.12 (the
 * fault is fixed upstream in 1.13). */
static int ipa_salttype_to_string(krb5_int32 salttype,
                                  char *buffer, size_t buflen)
{
    static int faulty_function = -1;

    static const struct {
        krb5_int32 salttype;
        const char *name;
    } fallback_map[] = {
        { KRB5_KDB_SALTTYPE_NORMAL, "normal" },
        { KRB5_KDB_SALTTYPE_V4, "v4" },
        { KRB5_KDB_SALTTYPE_NOREALM, "norealm" },
        { KRB5_KDB_SALTTYPE_ONLYREALM, "onlyrealm" },
        { KRB5_KDB_SALTTYPE_SPECIAL, "special" },
        { KRB5_KDB_SALTTYPE_AFS3, "afs3" },
        { -1, NULL }
    };

    if (faulty_function == -1) {
        /* haven't checked yet, let's find out */
        char testbuf[100];
        size_t len = 100;
        int ret;

        ret = krb5_salttype_to_string(KRB5_KDB_SALTTYPE_NORMAL, testbuf, len);
        if (ret) return ret;

        if (strcmp(buffer, "normal") == 0) {
            faulty_function = 0;
        } else {
            faulty_function = 1;
        }
    }

    if (faulty_function == 0) {
        return krb5_salttype_to_string(salttype, buffer, buflen);
    } else {
        size_t len;
        int i;
        for (i = 0; fallback_map[i].name != NULL; i++) {
            if (salttype == fallback_map[i].salttype) break;
        }
        if (fallback_map[i].name == NULL) return EINVAL;

        len = strlen(fallback_map[i].name);
        if (len >= buflen) return ENOMEM;

        memcpy(buffer, fallback_map[i].name, len + 1);
        return 0;
    }
}

int ipa_kstuples_to_string(krb5_key_salt_tuple *kst, int n_kst, char **str)
{
    char *buf = NULL;
    char *tmp;
    int buf_avail;
    int buf_size;
    int buf_cur;
    int len;
    int ret = 0;
    int i;

    buf_size = 512; /* should be enough for the default supported enctypes */
    buf = malloc(buf_size);
    if (!buf) {
        ret = ENOMEM;
        goto done;
    }

    buf_cur = 0;
    for (i = 0; i < n_kst; i++) {
        /* grow if too tight */
        if (ret == ENOMEM) {
            buf_size *= 2;
            /* hard limit at 8k, do not eat all memory by mistake */
            if (buf_size > 8192) goto done;
            tmp = realloc(buf, buf_size);
            if (!tmp) {
                ret = ENOMEM;
                goto done;
            }
            buf = tmp;
        }

        buf_avail = buf_size - buf_cur;
        len = 0;

        /* append separator if necessary */
        if (buf_cur > 0) {
            buf[buf_cur] = ',';
            len++;
        }

        ret = krb5_enctype_to_name(kst[i].ks_enctype, 0,
                                   &buf[buf_cur + len], buf_avail - len);
        if (ret == ENOMEM) {
            i--;
            continue;
        } else if (ret != 0) {
            goto done;
        }

        len += strlen(&buf[buf_cur + len]);
        buf[buf_cur + len] = ':';
        len++;

        ret = ipa_salttype_to_string(kst[i].ks_salttype,
                                     &buf[buf_cur + len], buf_avail - len);
        if (ret == ENOMEM) {
            i--;
            continue;
        } else if (ret != 0) {
            goto done;
        }

        len += strlen(&buf[buf_cur + len]);

        if (buf_avail - len < 2) {
            ret = ENOMEM;
            i--;
            continue;
        }

        buf_cur += len;
    }

    buf[buf_cur] = '\0';
    *str = buf;
    ret = 0;

done:
    if (ret) {
        free(buf);
    }
    return ret;
}
