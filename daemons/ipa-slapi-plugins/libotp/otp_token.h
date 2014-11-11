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

#include "otp_config.h"
#include <stdbool.h>
#include <stdlib.h>

struct otp_token;

/* Frees the token array. */
void
otp_token_free_array(struct otp_token **tokens);

/* Find tokens.
 *
 * All criteria below are cumulative. For example, if you specify both dn and
 * active and the token at the dn specified isn't active, an empty array will
 * be returned.
 *
 * If user_dn is not NULL, the user's tokens are returned.
 *
 * If token_dn is not NULL, only this specified token is returned.
 *
 * If active is true, only tokens that are active are returned.
 *
 * If filter is not NULL, the filter will be added to the search criteria.
 *
 * Returns NULL on error. If no tokens are found, an empty array is returned.
 * The array is NULL terminated.
 */
struct otp_token **otp_token_find(const struct otp_config *cfg,
                                  const char *user_dn, const char *token_dn,
                                  bool active, const char *filter);

/* Get the SDN of the token. */
const Slapi_DN *otp_token_get_sdn(struct otp_token *token);

/* Perform OTP authentication.
 *
 * If only the first code is specified, validation will be performed and the
 * validated token will be stripped.
 *
 * If both codes are specified, synchronization will be performed and the
 * validated tokens will be stripped.
 *
 * Returns true if and only if all specified tokens were validated.
 */
bool otp_token_validate_berval(struct otp_token * const *tokens,
                               struct berval *first_code,
                               struct berval *second_code);
