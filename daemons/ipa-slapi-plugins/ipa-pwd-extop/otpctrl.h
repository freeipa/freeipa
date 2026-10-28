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

#pragma once

#include "../libotp/otp_config.h"
#include <stdbool.h>

/*
 * The ASN.1 encoding of the request structure:
 *
 *     OTPSyncRequest ::= SEQUENCE {
 *         firstCode   OCTET STRING,
 *         secondCode  OCTET STRING,
 *         tokenDN     OCTET STRING OPTIONAL
 *     }
 */
#define OTP_SYNC_REQUEST_OID "2.16.840.1.113730.3.8.10.6"

/* This control has no data. */
#define OTP_REQUIRED_OID "2.16.840.1.113730.3.8.10.7"

bool otpctrl_present(Slapi_PBlock *pb, const char *oid);

bool otpctrl_sync_handle(const struct otp_config *cfg, Slapi_PBlock *pb,
                         const char *user_dn);
