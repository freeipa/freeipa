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

#include "hotp.h"

#include <assert.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <nss.h>

#define KEY(s) { (uint8_t *) s, sizeof(s) - 1 }

/* All HOTP test examples from RFC 4226 (Appendix D). */
static const struct hotp_token hotp_token = {
    KEY("12345678901234567890"),
    "sha1",
    6
};
static const uint32_t hotp_answers[] = {
    755224,
    287082,
    359152,
    969429,
    338314,
    254676,
    287922,
    162583,
    399871,
    520489
};

/* All TOTP test examples from RFC 6238 (Appendix B). */
#define SHA1   { KEY("12345678901234567890"), "sha1", 8 }
#define SHA256 { KEY("12345678901234567890123456789012"), "sha256", 8 }
#define SHA512 { KEY("12345678901234567890123456789012" \
                     "34567890123456789012345678901234"), "sha512", 8 }
static const struct {
    struct hotp_token token;
    time_t time;
    uint32_t answer;
} totp_tests[] = {
    { SHA1,            59, 94287082 },
    { SHA256,          59, 46119246 },
    { SHA512,          59, 90693936 },
    { SHA1,    1111111109,  7081804 },
    { SHA256,  1111111109, 68084774 },
    { SHA512,  1111111109, 25091201 },
    { SHA1,    1111111111, 14050471 },
    { SHA256,  1111111111, 67062674 },
    { SHA512,  1111111111, 99943326 },
    { SHA1,    1234567890, 89005924 },
    { SHA256,  1234567890, 91819424 },
    { SHA512,  1234567890, 93441116 },
    { SHA1,    2000000000, 69279037 },
    { SHA256,  2000000000, 90698825 },
    { SHA512,  2000000000, 38618901 },
#ifdef _LP64 /* Only do these tests on 64-bit systems. */
    { SHA1,   20000000000, 65353130 },
    { SHA256, 20000000000, 77737706 },
    { SHA512, 20000000000, 47863826 },
#endif
};

int
main(int argc, const char *argv[])
{
    uint32_t otp;
    int i;

    NSS_NoDB_Init(".");

    for (i = 0; i < sizeof(hotp_answers) / sizeof(*hotp_answers); i++) {
        assert(hotp(&hotp_token, i, &otp));
        assert(otp == hotp_answers[i]);
    }

    for (i = 0; i < sizeof(totp_tests) / sizeof(*totp_tests); i++) {
        assert(hotp(&totp_tests[i].token, totp_tests[i].time / 30, &otp));
        assert(otp == totp_tests[i].answer);
    }

    NSS_Shutdown();
    return 0;
}
