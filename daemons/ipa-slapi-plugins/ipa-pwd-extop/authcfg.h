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


#ifndef AUTHCFG_H_
#define AUTHCFG_H_

#include <dirsrv/slapi-plugin.h>
#include <stdbool.h>

#define AUTHCFG_AUTH_TYPE_NONE     0
#define AUTHCFG_AUTH_TYPE_DISABLED 1
#define AUTHCFG_AUTH_TYPE_PASSWORD 2
#define AUTHCFG_AUTH_TYPE_OTP      4
#define AUTHCFG_AUTH_TYPE_PKINIT   8
#define AUTHCFG_AUTH_TYPE_RADIUS   16

/* Initialize authentication configuration.
 *
 * Thread Safety: NO
 */
bool authcfg_init(void);

/* Free global authentication configuration resources.
 *
 * Thread Safety: NO
 */
void authcfg_fini(void);

/* Gets the permitted authentication types for the given user entry.
 *
 * The entry should be queried for the "ipaUserAuthType" attribute.
 *
 * Thread Safety: YES
 */
uint32_t authcfg_get_auth_types(Slapi_Entry *user_entry);

/* Reloads configuration from the specified global config entry.
 *
 * If the provided entry isn't a global config entry, this is a no-op.
 *
 * Thread Safety: YES
 */
void authcfg_reload_global_config(Slapi_DN *sdn, Slapi_Entry *config_entry);

#endif /* AUTHCFG_H_ */
