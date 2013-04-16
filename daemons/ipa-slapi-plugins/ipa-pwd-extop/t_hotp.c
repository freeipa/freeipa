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
bool ipapwd_hotp(const uint8_t *key, size_t len, const char *algo, int digits,
                 uint64_t counter, uint32_t *out);

/* All HOTP test examples from RFC 4226 (Appendix D). */
static const uint8_t *key = (uint8_t *) "12345678901234567890";
static const uint32_t answers[] = {
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

int
main(int argc, const char *argv[])
{
    uint32_t otp;
    int i;

    NSS_NoDB_Init(".");

    for (i = 0; i < sizeof(answers) / sizeof(*answers); i++) {
        assert(ipapwd_hotp(key, 20, "sha1", 6, i, &otp));
        assert(otp == answers[i]);
    }

    NSS_Shutdown();
    return 0;
}
