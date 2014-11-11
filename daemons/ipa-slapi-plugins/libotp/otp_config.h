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
 * Copyright (C) 2014 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#pragma once

#include <dirsrv/slapi-plugin.h>

#define OTP_CONFIG_AUTH_TYPE_NONE     0
#define OTP_CONFIG_AUTH_TYPE_PASSWORD (1 << 0)
#define OTP_CONFIG_AUTH_TYPE_OTP      (1 << 1)
#define OTP_CONFIG_AUTH_TYPE_PKINIT   (1 << 2)
#define OTP_CONFIG_AUTH_TYPE_RADIUS   (1 << 3)

struct otp_config;

struct otp_config_window {
    uint32_t auth;
    uint32_t sync;
};

struct otp_config *otp_config_init(Slapi_ComponentId *plugin_id);

void otp_config_fini(struct otp_config **cfg);

void otp_config_update(struct otp_config *cfg, Slapi_PBlock *pb);

Slapi_ComponentId *otp_config_plugin_id(const struct otp_config *cfg);

/* Gets the permitted authentication types for the given user entry.
 *
 * The entry should be queried for the "ipaUserAuthType" attribute.
 */
uint32_t otp_config_auth_types(const struct otp_config *cfg,
                               Slapi_Entry *user_entry);

/* Gets the window sizes for a token.
 *
 * The entry should be queried for the following attributes:
 *   objectClass
 *   ipatokenTOTPauthWindow
 *   ipatokenTOTPsyncWindow
 *   ipatokenHOTPauthWindow
 *   ipatokenHOTPsyncWindow
 */
struct otp_config_window otp_config_window(const struct otp_config *cfg,
                                           Slapi_Entry *token_entry);
