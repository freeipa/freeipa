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
 *
 * This file includes an "OpenSSL license exception", see the
 * COPYING.openssl file for details.
 *
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <iconv.h>
#include <openssl/md4.h>

#include "ipa_pwd.h"

#define KTF_DOS_CHARSET "CP850" /* same default as samba */
#define KTF_UTF8 "UTF-8"
#define KTF_UCS2 "UCS-2LE"

/* create the nt hash
   newPassword: the clear text utf8 password
   nt_key[out]: array with generated hash
*/
int encode_nt_key(char *newPasswd, uint8_t *nt_key)
{
    int ret = 0;
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
    ret = MD4_Final(nt_key, &md4ctx);
    if (ret == 0) {
        ret = -1;
        free(ucs2Passwd);
        goto done;
    }

    ret = 0;
    free(ucs2Passwd);

done:
    return ret;
}
