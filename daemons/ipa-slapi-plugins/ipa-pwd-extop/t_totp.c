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

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include <nss.h>

/*
 * From otp.c
 */
bool ipapwd_totp(const uint8_t *key, size_t len, const char *algo, int digits,
                 time_t time, int offset, unsigned int step, uint32_t *out);

#define SHA1   "sha1",   (uint8_t *) "12345678901234567890",             20
#define SHA256 "sha256", (uint8_t *) "12345678901234567890123456789012", 32
#define SHA512 "sha512", (uint8_t *) "12345678901234567890123456789012" \
                                     "34567890123456789012345678901234", 64

/* All TOTP test examples from RFC 6238 (Appendix B). */
const static struct {
    const char *algo;
    const uint8_t *key;
    size_t len;
    time_t time;
    uint32_t answer;
} tests[] = {
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

    for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
        assert(ipapwd_totp(tests[i].key, tests[i].len, tests[i].algo,
                           8, tests[i].time, 0, 30, &otp));
        assert(otp == tests[i].answer);
    }

    NSS_Shutdown();
    return 0;
}
