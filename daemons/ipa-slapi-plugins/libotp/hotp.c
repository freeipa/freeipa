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
 * code that is governed neither by the GPL nor a license
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
 * Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2013 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

/*
 * This file contains an implementation of HOTP (RFC 4226) and TOTP (RFC 6238).
 * For details of how these algorithms work, please see the relevant RFCs.
 */

#include "hotp.h"
#include <time.h>

#include <nss.h>
#include <blapit.h>
#include <pk11pub.h>
#include <hasht.h>
#include <prerror.h>
#include <prnetdb.h>
#include <syslog.h>

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

static PK11SymKey *
import_key(PK11SlotInfo *slot, CK_MECHANISM_TYPE mech, SECItem *key)
{
    uint8_t ct[(key->len / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE];
    uint8_t iv[AES_BLOCK_SIZE] = {};
    SECItem ivitem = { .data = iv, .len = sizeof(iv), .type = siBuffer };
    SECItem ctitem = { .data = ct, .len = sizeof(ct), .type = siBuffer };
    PK11SymKey *ekey = NULL;
    PK11SymKey *skey = NULL;

    /* Try to import the key directly. */
    skey = PK11_ImportSymKey(slot, mech, PK11_OriginUnwrap,
                             CKA_SIGN, key, NULL);
    if (skey)
        return skey;

    /* If we get here, we are probably in FIPS mode. Let's encrypt the key so
     * that we can unseal it instead of loading it directly. */

    /* Generate an ephemeral key. */
    ekey = PK11_TokenKeyGenWithFlags(slot, CKM_AES_CBC_PAD, NULL,
                                     AES_128_KEY_LENGTH, NULL,
                                     CKF_ENCRYPT | CKF_UNWRAP,
                                     PK11_ATTR_SESSION |
                                     PK11_ATTR_PRIVATE |
                                     PK11_ATTR_SENSITIVE, NULL);
    if (!ekey) {
        syslog(LOG_ERR, "libotp: in FIPS, PK11_TokenKeyGenWithFlags failed: %d",
               PR_GetError());
        goto egress;
    }

    /* Encrypt the input key. */
    if (PK11_Encrypt(ekey, CKM_AES_CBC_PAD, &ivitem, ctitem.data, &ctitem.len,
                     ctitem.len, key->data, key->len) != SECSuccess) {
        syslog(LOG_ERR, "libotp: in FIPS, PK11_Encrypt failed: %d",
               PR_GetError());
        goto egress;
    }

    /* Unwrap the input key. */
    skey = PK11_UnwrapSymKey(ekey, CKM_AES_CBC_PAD, &ivitem,
                             &ctitem, mech, CKA_SIGN, key->len);
    if (!skey) {
        syslog(LOG_ERR, "libotp: in FIPS, PK11_UnwrapSymKey failed: %d",
               PR_GetError());
    }

egress:
    PK11_FreeSymKey(ekey);
    return skey;
}

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

    symkey = import_key(slot, mech, key);
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
bool hotp(const struct hotp_token *token, uint64_t counter, uint32_t *out)
{
    const SECItem cntr = { siBuffer, (uint8_t *) &counter, sizeof(counter) };
    SECItem keyitm = { siBuffer, token->key.bytes, token->key.len };
    CK_MECHANISM_TYPE mech = CKM_SHA_1_HMAC;
    PRUint64 offset, binary, div;
    struct digest_buffer digest;
    int digits = token->digits;
    int i;

    /* Convert counter to network byte order. */
    counter = PR_htonll(counter);

    /* Find the mech. */
    for (i = 0; algo2mech[i].algo; i++) {
        if (strcasecmp(algo2mech[i].algo, token->algo) == 0) {
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
