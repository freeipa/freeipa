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
#include <endian.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <openssl/hmac.h>

struct digest_buffer {
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len;
};

static const struct {
    const char *algo;
    const char *sn_mech;
} algo2mech[] = {
    { "sha1",   SN_sha1 },
    { "sha256", SN_sha256 },
    { "sha384", SN_sha384 },
    { "sha512", SN_sha512 },
    { }
};

static bool hmac(const struct hotp_token_key *key, const char *sn_mech,
                 uint64_t counter, struct digest_buffer *out)
{
    unsigned char in[sizeof(uint64_t)];
    const EVP_MD *evp;
    unsigned char *result;

    memcpy(in, &counter, sizeof(uint64_t));

    evp = EVP_get_digestbyname(sn_mech);
    if (evp == NULL) {
        return false;
    }

    if (!HMAC(evp, (void *)key->bytes, key->len, in, sizeof(in),
              out->buf, &out->len)) {
        return false;
    }

    return true;
}

/*
 * An implementation of HOTP (RFC 4226).
 */
bool hotp(const struct hotp_token *token, uint64_t counter, uint32_t *out)
{
    const char *mech = SN_sha1;
    struct digest_buffer digest;
    unsigned char counter_buf[sizeof(uint64_t)];
    const EVP_MD *evp;
    int digits = token->digits;
    int i;
    uint64_t div, offset, binary;

    /* Convert counter to network byte order. */
    counter = htobe64(counter);

    /* Copy counter to buffer */
    memcpy(counter_buf, &counter, sizeof(uint64_t));

    /* Find the mech. */
    for (i = 0; algo2mech[i].algo; i++) {
        if (strcasecmp(algo2mech[i].algo, token->algo) == 0) {
            mech = algo2mech[i].sn_mech;
            break;
        }
    }
    /* Create the digits divisor. */
    for (div = 1; digits > 0; digits--) {
        div *= 10;
    }

    /* Do the digest. */
    if (!hmac(&(token->key), mech, counter, &digest)) {
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
