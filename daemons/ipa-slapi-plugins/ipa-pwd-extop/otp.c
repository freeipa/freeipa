/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 3 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception.
 *
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

/*
 * This file contains an implementation of HOTP (RFC 4226) and TOTP (RFC 6238).
 * For details of how these algorithms work, please see the relevant RFCs.
 */

#include <stdbool.h>
#include <time.h>

#include <nss.h>
#include <pk11pub.h>
#include <hasht.h>
#include <prnetdb.h>

struct digest_buffer {
    uint8_t buf[SHA512_LENGTH];
    unsigned int len;
};

static const struct {
    const char *algo;
    CK_MECHANISM_TYPE mech;
} algo2mech[] = {
    { "sha1",   CKM_SHA_1_HMAC },
    { "sha256", CKM_SHA256_HMAC },
    { "sha384", CKM_SHA384_HMAC },
    { "sha512", CKM_SHA512_HMAC },
    { }
};

/*
 * This code is mostly cargo-cult taken from here:
 *   http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn5.html
 *
 * It should implement HMAC with the given mechanism (SHA: 1, 256, 384, 512).
 */
static bool hmac(SECItem *key, CK_MECHANISM_TYPE mech, const SECItem *in,
                 struct digest_buffer *out)
{
    SECItem param = { siBuffer, NULL, 0 };
    PK11SlotInfo *slot = NULL;
    PK11SymKey *symkey = NULL;
    PK11Context *ctx = NULL;
    bool ret = false;
    SECStatus s;

    slot = PK11_GetBestSlot(mech, NULL);
    if (slot == NULL) {
        slot = PK11_GetInternalKeySlot();
        if (slot == NULL) {
            goto done;
        }
    }

    symkey = PK11_ImportSymKey(slot, mech, PK11_OriginUnwrap,
                               CKA_SIGN, key, NULL);
    if (symkey == NULL)
        goto done;

    ctx = PK11_CreateContextBySymKey(mech, CKA_SIGN, symkey, &param);
    if (ctx == NULL)
        goto done;

    s = PK11_DigestBegin(ctx);
    if (s != SECSuccess)
        goto done;

    s = PK11_DigestOp(ctx, in->data, in->len);
    if (s != SECSuccess)
        goto done;

    s = PK11_DigestFinal(ctx, out->buf, &out->len, sizeof(out->buf));
    if (s != SECSuccess)
        goto done;

    ret = true;

done:
    if (ctx != NULL)
        PK11_DestroyContext(ctx, PR_TRUE);
    if (symkey != NULL)
        PK11_FreeSymKey(symkey);
    if (slot != NULL)
        PK11_FreeSlot(slot);
    return ret;
}

/*
 * An implementation of HOTP (RFC 4226).
 */
bool ipapwd_hotp(const uint8_t *key, size_t len, const char *algo, int digits,
                 uint64_t counter, uint32_t *out)
{
    const SECItem cntr = { siBuffer, (uint8_t *) &counter, sizeof(counter) };
    SECItem keyitm = { siBuffer, (uint8_t *) key, len };
    CK_MECHANISM_TYPE mech = CKM_SHA_1_HMAC;
    PRUint64 offset, binary, div;
    struct digest_buffer digest;
    int i;

    /* Convert counter to network byte order. */
    counter = PR_htonll(counter);

    /* Find the mech. */
    for (i = 0; algo2mech[i].algo; i++) {
        if (strcasecmp(algo2mech[i].algo, algo) == 0) {
            mech = algo2mech[i].mech;
            break;
        }
    }

    /* Create the digits divisor. */
    for (div = 1; digits > 0; digits--) {
        div *= 10;
    }

    /* Do the digest. */
    if (!hmac(&keyitm, mech, &cntr, &digest)) {
        return false;
    }

    /* Truncate. */
    offset  = digest.buf[digest.len - 1] & 0xf;
    binary  = (digest.buf[offset + 0] & 0x7f) << 0x18;
    binary |= (digest.buf[offset + 1] & 0xff) << 0x10;
    binary |= (digest.buf[offset + 2] & 0xff) << 0x08;
    binary |= (digest.buf[offset + 3] & 0xff) << 0x00;
    binary  = binary % div;

    *out = binary;
    return true;
}

/*
 * An implementation of TOTP (RFC 6238).
 */
bool ipapwd_totp(const uint8_t *key, size_t len, const char *algo, int digits,
                 time_t time, int offset, unsigned int step, uint32_t *out)
{
    if (step == 0)
        return false;

    return ipapwd_hotp(key, len, algo, digits, (time - offset) / step, out);
}
