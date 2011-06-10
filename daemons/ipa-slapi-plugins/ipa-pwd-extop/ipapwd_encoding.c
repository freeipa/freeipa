/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <dirsrv/slapi-plugin.h>
#include <lber.h>
#include <time.h>

#include <endian.h>

#include "ipapwd.h"
#include "util.h"
#include "ipa_krb5.h"

/* krbTicketFlags */
#define KTF_DISALLOW_POSTDATED        0x00000001
#define KTF_DISALLOW_FORWARDABLE      0x00000002
#define KTF_DISALLOW_TGT_BASED        0x00000004
#define KTF_DISALLOW_RENEWABLE        0x00000008
#define KTF_DISALLOW_PROXIABLE        0x00000010
#define KTF_DISALLOW_DUP_SKEY         0x00000020
#define KTF_DISALLOW_ALL_TIX          0x00000040
#define KTF_REQUIRES_PRE_AUTH         0x00000080
#define KTF_REQUIRES_HW_AUTH          0x00000100
#define KTF_REQUIRES_PWCHANGE         0x00000200
#define KTF_DISALLOW_SVR              0x00001000
#define KTF_PWCHANGE_SERVICE          0x00002000

/* Salt types */
#define KRB5_KDB_SALTTYPE_NORMAL        0
#define KRB5_KDB_SALTTYPE_V4            1
#define KRB5_KDB_SALTTYPE_NOREALM       2
#define KRB5_KDB_SALTTYPE_ONLYREALM     3
#define KRB5_KDB_SALTTYPE_SPECIAL       4
#define KRB5_KDB_SALTTYPE_AFS3          5
#define KRB5P_SALT_SIZE 16

void krb5int_c_free_keyblock_contents(krb5_context context,
                                      register krb5_keyblock *key);

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

/* ascii hex output of bytes in "in"
 * out len is 32 (preallocated)
 * in len is 16 */
static const char hexchars[] = "0123456789ABCDEF";
static void hexbuf(char *out, const uint8_t *in)
{
    int i;

    for (i = 0; i < 16; i++) {
        out[i*2] = hexchars[in[i] >> 4];
        out[i*2+1] = hexchars[in[i] & 0x0f];
    }
}

struct berval *encode_keys(struct ipapwd_keyset *kset)
{
    BerElement *be = NULL;
    struct berval *bval = NULL;
    int ret, i;

    be = ber_alloc_t(LBER_USE_DER);

    if (!be) {
        LOG_OOM();
        return NULL;
    }

    ret = ber_printf(be, "{t[i]t[i]t[i]t[i]t[{",
                    (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                    kset->major_vno,
                    (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                    kset->minor_vno,
                    (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2),
                    kset->kvno,
                    (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 3),
                    kset->mkvno,
                    (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 4));
    if (ret == -1) {
        LOG_FATAL("encoding asn1 vno info failed\n");
        goto done;
    }

    for (i = 0; i < kset->num_keys; i++) {

        ret = ber_printf(be, "{");
        if (ret == -1) {
            LOG_FATAL("encoding asn1 EncryptionKey failed\n");
            goto done;
        }

        if (kset->keys[i].salt) {
            ret = ber_printf(be, "t[{t[i]",
                     (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                     (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                     kset->keys[i].salt->type);
            if ((ret != -1) && kset->keys[i].salt->value.bv_len) {
                ret = ber_printf(be, "t[o]",
                         (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                         kset->keys[i].salt->value.bv_val,
                         kset->keys[i].salt->value.bv_len);
            }
            if (ret != -1) {
                ret = ber_printf(be, "}]");
            }
            if (ret == -1) {
                goto done;
            }
        }

        ret = ber_printf(be, "t[{t[i]t[o]}]",
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 kset->keys[i].ekey->type,
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 kset->keys[i].ekey->value.bv_val,
                 kset->keys[i].ekey->value.bv_len);
        if (ret == -1) {
            LOG_FATAL("encoding asn1 EncryptionKey failed\n");
            goto done;
        }

        /* FIXME: s2kparams not supported yet */

        ret = ber_printf(be, "}");
        if (ret == -1) {
            LOG_FATAL("encoding asn1 EncryptionKey failed\n");
            goto done;
        }
    }

    ret = ber_printf(be, "}]}");
    if (ret == -1) {
        LOG_FATAL("encoding asn1 end of sequences failed\n");
        goto done;
    }

    ret = ber_flatten(be, &bval);
    if (ret == -1) {
        LOG_FATAL("flattening asn1 failed\n");
        goto done;
    }
done:
    ber_free(be, 1);

    return bval;
}

void ipapwd_keyset_free(struct ipapwd_keyset **pkset)
{
    struct ipapwd_keyset *kset = *pkset;
    int i;

    if (!kset) return;

    for (i = 0; i < kset->num_keys; i++) {
        if (kset->keys[i].salt) {
            free(kset->keys[i].salt->value.bv_val);
            free(kset->keys[i].salt);
        }
        if (kset->keys[i].ekey) {
            free(kset->keys[i].ekey->value.bv_val);
            free(kset->keys[i].ekey);
        }
        free(kset->keys[i].s2kparams.bv_val);
    }
    free(kset->keys);
    free(kset);
    *pkset = NULL;
}

static Slapi_Value **encrypt_encode_key(struct ipapwd_krbcfg *krbcfg,
                                        struct ipapwd_data *data,
                                        char **errMesg)
{
    krb5_context krbctx;
    char *krbPrincipalName = NULL;
    int kvno, i;
    struct berval *bval = NULL;
    Slapi_Value **svals = NULL;
    krb5_principal princ = NULL;
    krb5_error_code krberr;
    krb5_data pwd;
    struct ipapwd_keyset *kset = NULL;

    krbctx = krbcfg->krbctx;

    svals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
    if (!svals) {
        LOG_OOM();
        return NULL;
    }

    kvno = ipapwd_get_cur_kvno(data->target);

    krbPrincipalName = slapi_entry_attr_get_charptr(data->target,
                                                    "krbPrincipalName");
    if (!krbPrincipalName) {
        *errMesg = "no krbPrincipalName present in this entry\n";
        LOG_FATAL("%s", *errMesg);
        goto enc_error;
    }

    krberr = krb5_parse_name(krbctx, krbPrincipalName, &princ);
    if (krberr) {
        LOG_FATAL("krb5_parse_name failed [%s]\n",
                  krb5_get_error_message(krbctx, krberr));
        goto enc_error;
    }

    pwd.data = (char *)data->password;
    pwd.length = strlen(data->password);

    kset = malloc(sizeof(struct ipapwd_keyset));
    if (!kset) {
        LOG_OOM();
        goto enc_error;
    }

    /* this encoding assumes all keys have the same kvno */
    /* major-vno = 1 and minor-vno = 1 */
    kset->major_vno = 1;
    kset->minor_vno = 1;
    /* increment kvno (will be 1 if this is a new entry) */
    kset->kvno = kvno + 1;
    kset->mkvno = krbcfg->mkvno;

    kset->num_keys = krbcfg->num_pref_encsalts;
    kset->keys = calloc(kset->num_keys, sizeof(struct ipapwd_krbkey));
    if (!kset->keys) {
        LOG_OOM();
        goto enc_error;
    }

    for (i = 0; i < kset->num_keys; i++) {
        krb5_keyblock key;
        krb5_data salt;
        krb5_octet *ptr;
        krb5_data plain;
        krb5_enc_data cipher;
        krb5_int16 t;
        size_t len;
        const char *p;

        salt.data = NULL;

        switch (krbcfg->pref_encsalts[i].salt_type) {

        case KRB5_KDB_SALTTYPE_ONLYREALM:

            p = strchr(krbPrincipalName, '@');
            if (!p) {
                LOG_FATAL("Invalid principal name, no realm found!\n");
                goto enc_error;
            }
            p++;
            salt.data = strdup(p);
            if (!salt.data) {
                LOG_OOM();
                goto enc_error;
            }
            salt.length = strlen(salt.data); /* final \0 omitted on purpose */
            break;

        case KRB5_KDB_SALTTYPE_NOREALM:

            krberr = ipa_krb5_principal2salt_norealm(krbctx, princ, &salt);
            if (krberr) {
                LOG_FATAL("krb5_principal2salt failed [%s]\n",
                          krb5_get_error_message(krbctx, krberr));
                goto enc_error;
            }
            break;

        case KRB5_KDB_SALTTYPE_NORMAL:

            krberr = krb5_principal2salt(krbctx, princ, &salt);
            if (krberr) {
                LOG_FATAL("krb5_principal2salt failed [%s]\n",
                          krb5_get_error_message(krbctx, krberr));
                goto enc_error;
            }
            break;

        case KRB5_KDB_SALTTYPE_SPECIAL:

            /* make random salt */
            salt.length = KRB5P_SALT_SIZE;
            salt.data = malloc(KRB5P_SALT_SIZE);
            if (!salt.data) {
                LOG_OOM();
                goto enc_error;
            }
            krberr = krb5_c_random_make_octets(krbctx, &salt);
            if (krberr) {
                LOG_FATAL("krb5_c_random_make_octets failed [%s]\n",
                          krb5_get_error_message(krbctx, krberr));
                goto enc_error;
            }
            break;

        case KRB5_KDB_SALTTYPE_V4:
            salt.length = 0;
            break;

        case KRB5_KDB_SALTTYPE_AFS3:

            p = strchr(krbPrincipalName, '@');
            if (!p) {
                LOG_FATAL("Invalid principal name, no realm found!\n");
                goto enc_error;
            }
            p++;
            salt.data = strdup(p);
            if (!salt.data) {
                LOG_OOM();
                goto enc_error;
            }
            salt.length = SALT_TYPE_AFS_LENGTH; /* special value */
            break;

        default:
            LOG_FATAL("Invalid salt type [%d]\n",
                      krbcfg->pref_encsalts[i].salt_type);
            goto enc_error;
        }

        /* need to build the key now to manage the AFS salt.length
         * special case */
        krberr = krb5_c_string_to_key(krbctx,
                                      krbcfg->pref_encsalts[i].enc_type,
                                      &pwd, &salt, &key);
        if (krberr) {
            LOG_FATAL("krb5_c_string_to_key failed [%s]\n",
                      krb5_get_error_message(krbctx, krberr));
            krb5_free_data_contents(krbctx, &salt);
            goto enc_error;
        }
        if (salt.length == SALT_TYPE_AFS_LENGTH) {
            salt.length = strlen(salt.data);
        }

        krberr = krb5_c_encrypt_length(krbctx,
                                       krbcfg->kmkey->enctype,
                                       key.length, &len);
        if (krberr) {
            LOG_FATAL("krb5_c_string_to_key failed [%s]\n",
                      krb5_get_error_message(krbctx, krberr));
            krb5int_c_free_keyblock_contents(krbctx, &key);
            krb5_free_data_contents(krbctx, &salt);
            goto enc_error;
        }

        if ((ptr = (krb5_octet *) malloc(2 + len)) == NULL) {
            LOG_OOM();
            krb5int_c_free_keyblock_contents(krbctx, &key);
            krb5_free_data_contents(krbctx, &salt);
            goto enc_error;
        }

        t = htole16(key.length);
        memcpy(ptr, &t, 2);

        plain.length = key.length;
        plain.data = (char *)key.contents;

        cipher.ciphertext.length = len;
        cipher.ciphertext.data = (char *)ptr+2;

        krberr = krb5_c_encrypt(krbctx, krbcfg->kmkey, 0, 0, &plain, &cipher);
        if (krberr) {
            LOG_FATAL("krb5_c_encrypt failed [%s]\n",
                      krb5_get_error_message(krbctx, krberr));
            krb5int_c_free_keyblock_contents(krbctx, &key);
            krb5_free_data_contents(krbctx, &salt);
            free(ptr);
            goto enc_error;
        }

        /* KrbSalt  */
        kset->keys[i].salt = malloc(sizeof(struct ipapwd_krbkeydata));
        if (!kset->keys[i].salt) {
            LOG_OOM();
            krb5int_c_free_keyblock_contents(krbctx, &key);
            free(ptr);
            goto enc_error;
        }

        kset->keys[i].salt->type = krbcfg->pref_encsalts[i].salt_type;

        if (salt.length) {
            kset->keys[i].salt->value.bv_len = salt.length;
            kset->keys[i].salt->value.bv_val = salt.data;
        }

        /* EncryptionKey */
        kset->keys[i].ekey = malloc(sizeof(struct ipapwd_krbkeydata));
        if (!kset->keys[i].ekey) {
            LOG_OOM();
            krb5int_c_free_keyblock_contents(krbctx, &key);
            free(ptr);
            goto enc_error;
        }
        kset->keys[i].ekey->type = key.enctype;
        kset->keys[i].ekey->value.bv_len = len+2;
        kset->keys[i].ekey->value.bv_val = malloc(len+2);
        if (!kset->keys[i].ekey->value.bv_val) {
            LOG_OOM();
            krb5int_c_free_keyblock_contents(krbctx, &key);
            free(ptr);
            goto enc_error;
        }
        memcpy(kset->keys[i].ekey->value.bv_val, ptr, len+2);

        /* make sure we free the memory used now that we are done with it */
        krb5int_c_free_keyblock_contents(krbctx, &key);
        free(ptr);
    }

    bval = encode_keys(kset);
    if (!bval) {
        LOG_FATAL("encoding asn1 KrbSalt failed\n");
        goto enc_error;
    }

    svals[0] = slapi_value_new_berval(bval);
    if (!svals[0]) {
        LOG_FATAL("Converting berval to Slapi_Value\n");
        goto enc_error;
    }

    ipapwd_keyset_free(&kset);
    krb5_free_principal(krbctx, princ);
    slapi_ch_free_string(&krbPrincipalName);
    ber_bvfree(bval);
    return svals;

enc_error:
    *errMesg = "key encryption/encoding failed\n";
    if (kset) ipapwd_keyset_free(&kset);
    krb5_free_principal(krbctx, princ);
    slapi_ch_free_string(&krbPrincipalName);
    if (bval) ber_bvfree(bval);
    free(svals);
    return NULL;
}


#define KTF_DOS_CHARSET "CP850" /* same default as samba */
#define KTF_UTF8 "UTF-8"
#define KTF_UCS2 "UCS-2LE"

static const uint8_t parity_table[128] = {
      1,  2,  4,  7,  8, 11, 13, 14, 16, 19, 21, 22, 25, 26, 28, 31,
     32, 35, 37, 38, 41, 42, 44, 47, 49, 50, 52, 55, 56, 59, 61, 62,
     64, 67, 69, 70, 73, 74, 76, 79, 81, 82, 84, 87, 88, 91, 93, 94,
     97, 98,100,103,104,107,109,110,112,115,117,118,121,122,124,127,
    128,131,133,134,137,138,140,143,145,146,148,151,152,155,157,158,
    161,162,164,167,168,171,173,174,176,179,181,182,185,186,188,191,
    193,194,196,199,200,203,205,206,208,211,213,214,217,218,220,223,
    224,227,229,230,233,234,236,239,241,242,244,247,248,251,253,254
};

static void lm_shuffle(uint8_t *out, uint8_t *in)
{
    out[0] = parity_table[in[0]>>1];
    out[1] = parity_table[((in[0]<<6)|(in[1]>>2)) & 0x7F];
    out[2] = parity_table[((in[1]<<5)|(in[2]>>3)) & 0x7F];
    out[3] = parity_table[((in[2]<<4)|(in[3]>>4)) & 0x7F];
    out[4] = parity_table[((in[3]<<3)|(in[4]>>5)) & 0x7F];
    out[5] = parity_table[((in[4]<<2)|(in[5]>>6)) & 0x7F];
    out[6] = parity_table[((in[5]<<1)|(in[6]>>7)) & 0x7F];
    out[7] = parity_table[in[6] & 0x7F];
}

struct ntlm_keys {
    uint8_t lm[16];
    uint8_t nt[16];
};

/* create the lm and nt hashes
   newPassword: the clear text utf8 password
   do_lm_hash: determine if LM hash is generated
   do_nt_hash: determine if NT hash is generated
   keys[out]: array with generated hashes
*/
static int encode_ntlm_keys(char *newPasswd,
                            bool do_lm_hash,
                            bool do_nt_hash,
                            struct ntlm_keys *keys)
{
    int ret = 0;

    /* do lanman first */
    if (do_lm_hash) {
        iconv_t cd;
        size_t cs, il, ol;
        char *inc, *outc;
        char *upperPasswd;
        char *asciiPasswd;
        DES_key_schedule schedule;
        DES_cblock deskey;
        DES_cblock magic = "KGS!@#$%";

        /* TODO: must store the dos charset somewhere in the directory */
        cd = iconv_open(KTF_DOS_CHARSET, KTF_UTF8);
        if (cd == (iconv_t)(-1)) {
            ret = -1;
            goto done;
        }

        /* the lanman password is upper case */
        upperPasswd = (char *)slapi_utf8StrToUpper((unsigned char *)newPasswd);
        if (!upperPasswd) {
            iconv_close(cd);
            ret = -1;
            goto done;
        }
        il = strlen(upperPasswd);

        /* an ascii string can only be smaller than or equal to an utf8 one */
        ol = il;
        if (ol < 14) ol = 14;
        asciiPasswd = calloc(ol+1, 1);
        if (!asciiPasswd) {
            slapi_ch_free_string(&upperPasswd);
            iconv_close(cd);
            ret = -1;
            goto done;
        }

        inc = upperPasswd;
        outc = asciiPasswd;
        cs = iconv(cd, &inc, &il, &outc, &ol);
        if (cs == -1) {
            ret = -1;
            slapi_ch_free_string(&upperPasswd);
            free(asciiPasswd);
            iconv_close(cd);
            goto done;
        }

        /* done with these */
        slapi_ch_free_string(&upperPasswd);
        iconv_close(cd);

        /* we are interested only in the first 14 ASCII chars for lanman */
        if (strlen(asciiPasswd) > 14) {
            asciiPasswd[14] = '\0';
        }

        /* first half */
        lm_shuffle(deskey, (uint8_t *)asciiPasswd);

        DES_set_key_unchecked(&deskey, &schedule);
        DES_ecb_encrypt(&magic, (DES_cblock *)keys->lm,
                        &schedule, DES_ENCRYPT);

        /* second half */
        lm_shuffle(deskey, (uint8_t *)&asciiPasswd[7]);

        DES_set_key_unchecked(&deskey, &schedule);
        DES_ecb_encrypt(&magic, (DES_cblock *)&(keys->lm[8]),
                        &schedule, DES_ENCRYPT);

        /* done with it */
        free(asciiPasswd);

    } else {
        memset(keys->lm, 0, 16);
    }

    if (do_nt_hash) {
        iconv_t cd;
        size_t cs, il, ol, sl;
        char *inc, *outc;
        char *ucs2Passwd;
        MD4_CTX md4ctx;

        /* TODO: must store the dos charset somewhere in the directory */
        cd = iconv_open(KTF_UCS2, KTF_UTF8);
        if (cd == (iconv_t)(-1)) {
            ret = -1;
            goto done;
        }

        il = strlen(newPasswd);

        /* an ucs2 string can be at most double than an utf8 one */
        sl = ol = (il+1)*2;
        ucs2Passwd = calloc(ol, 1);
        if (!ucs2Passwd) {
            ret = -1;
            iconv_close(cd);
            goto done;
        }

        inc = newPasswd;
        outc = ucs2Passwd;
        cs = iconv(cd, &inc, &il, &outc, &ol);
        if (cs == -1) {
            ret = -1;
            free(ucs2Passwd);
            iconv_close(cd);
            goto done;
        }

        /* done with it */
        iconv_close(cd);

        /* get the final ucs2 string length */
        sl -= ol;

        ret = MD4_Init(&md4ctx);
        if (ret == 0) {
            ret = -1;
            free(ucs2Passwd);
            goto done;
        }
        ret = MD4_Update(&md4ctx, ucs2Passwd, sl);
        if (ret == 0) {
            ret = -1;
            free(ucs2Passwd);
            goto done;
        }
        ret = MD4_Final(keys->nt, &md4ctx);
        if (ret == 0) {
            ret = -1;
            free(ucs2Passwd);
            goto done;
        }

    } else {
        memset(keys->nt, 0, 16);
    }

    ret = 0;

done:
    return ret;
}

int ipapwd_gen_hashes(struct ipapwd_krbcfg *krbcfg,
                      struct ipapwd_data *data, char *userpw,
                      int is_krb, int is_smb, Slapi_Value ***svals,
                      char **nthash, char **lmhash, char **errMesg)
{
    int rc;

    *svals = NULL;
    *nthash = NULL;
    *lmhash = NULL;
    *errMesg = NULL;

    if (is_krb) {

        *svals = encrypt_encode_key(krbcfg, data, errMesg);

        if (!*svals) {
            /* errMesg should have been set in encrypt_encode_key() */
            LOG_FATAL("key encryption/encoding failed\n");
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    if (is_smb) {
        char lm[33], nt[33];
        struct ntlm_keys ntlm;
        int ret;

        ret = encode_ntlm_keys(userpw,
                               krbcfg->allow_lm_hash,
                               krbcfg->allow_nt_hash,
                               &ntlm);
        if (ret) {
            *errMesg = "Failed to generate NT/LM hashes\n";
            LOG_FATAL("%s", *errMesg);
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        if (krbcfg->allow_lm_hash) {
            hexbuf(lm, ntlm.lm);
            lm[32] = '\0';
            *lmhash = slapi_ch_strdup(lm);
        }
        if (krbcfg->allow_nt_hash) {
            hexbuf(nt, ntlm.nt);
            nt[32] = '\0';
            *nthash = slapi_ch_strdup(nt);
        }
    }

    rc = LDAP_SUCCESS;

done:

    /* when error, free possibly allocated output parameters */
    if (rc) {
        ipapwd_free_slapi_value_array(svals);
    }

    return rc;
}

