/*
 * Password related utils for FreeIPA
 *
 * Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011,2012  Simo Sorce, Red Hat
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

#include <stdbool.h>
#include <iconv.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <dirsrv/slapi-plugin.h>

#include "ipa_pwd.h"

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

/* create the lm and nt hashes
   newPassword: the clear text utf8 password
   upperPasswd: upper case version of clear text utf8 password
   do_lm_hash: determine if LM hash is generated
   do_nt_hash: determine if NT hash is generated
   keys[out]: array with generated hashes
*/
int encode_ntlm_keys(char *newPasswd,
                     char *upperPasswd,
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
        char *asciiPasswd;
        DES_key_schedule schedule;
        DES_cblock deskey;
        DES_cblock magic = "KGS!@#$%";

        if (upperPasswd == NULL) {
            ret = -1;
            goto done;
        }
        il = strlen(upperPasswd);

        /* TODO: must store the dos charset somewhere in the directory */
        cd = iconv_open(KTF_DOS_CHARSET, KTF_UTF8);
        if (cd == (iconv_t)(-1)) {
            ret = -1;
            goto done;
        }

        /* an ascii string can only be smaller than or equal to an utf8 one */
        ol = il;
        if (ol < 14) ol = 14;
        asciiPasswd = calloc(ol+1, 1);
        if (!asciiPasswd) {
            iconv_close(cd);
            ret = -1;
            goto done;
        }

        inc = upperPasswd;
        outc = asciiPasswd;
        cs = iconv(cd, &inc, &il, &outc, &ol);
        if (cs == -1) {
            ret = -1;
            free(asciiPasswd);
            iconv_close(cd);
            goto done;
        }

        /* done with these */
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
