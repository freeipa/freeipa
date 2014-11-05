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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <libotp.h>
#include <time.h>

#include "util.h"

#define PLUGIN_NAME               "ipa-otp-lasttoken"
#define LOG(sev, ...) \
    slapi_log_error(SLAPI_LOG_ ## sev, PLUGIN_NAME, \
                    "%s: %s\n", __func__, __VA_ARGS__), -1

static void *plugin_id;
static const Slapi_PluginDesc preop_desc = {
    PLUGIN_NAME,
    "FreeIPA",
    "FreeIPA/1.0",
    "Protect the user's last active token"
};

static bool
target_is_only_enabled_token(Slapi_PBlock *pb)
{
    Slapi_DN *target_sdn = NULL;
    Slapi_DN *token_sdn = NULL;
    struct otptoken **tokens;
    char *user_dn = NULL;
    bool match;

    /* Ignore internal operations. */
    if (slapi_op_internal(pb))
        return false;

    /* Get the current user's SDN. */
    slapi_pblock_get(pb, SLAPI_CONN_DN, &user_dn);
    if (user_dn == NULL)
        return false;

    /* Get the SDN of the only enabled token. */
    tokens = otptoken_find(plugin_id, user_dn, NULL, true, NULL);
    if (tokens != NULL && tokens[0] != NULL && tokens[1] == NULL)
        token_sdn = slapi_sdn_dup(otptoken_get_sdn(tokens[0]));
    otptoken_free_array(tokens);
    if (token_sdn == NULL)
        return false;

    /* Get the target SDN. */
    slapi_pblock_get(pb, SLAPI_TARGET_SDN, &target_sdn);
    if (target_sdn == NULL) {
        slapi_sdn_free(&token_sdn);
        return false;
    }

    /* Does the target SDN match the only enabled token SDN? */
    match = slapi_sdn_compare(token_sdn, target_sdn) == 0;
    slapi_sdn_free(&token_sdn);
    return match;
}

static inline int
send_error(Slapi_PBlock *pb, int rc, char *errstr)
{
    slapi_send_ldap_result(pb, rc, NULL, errstr, 0, NULL);
    if (slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
    }
    return rc;
}

static int
preop_del(Slapi_PBlock *pb)
{
    if (!target_is_only_enabled_token(pb))
        return 0;

    return send_error(pb, LDAP_UNWILLING_TO_PERFORM,
                      "Can't delete last active token");
}

static int
preop_mod(Slapi_PBlock *pb)
{
    LDAPMod **mods = NULL;

    if (!target_is_only_enabled_token(pb))
        return 0;

    /* Do not permit deactivation of the last active token. */
    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    for (int i = 0; mods != NULL && mods[i] != NULL; i++) {
        if (strcasecmp(mods[i]->mod_type, "ipatokenDisabled") == 0) {
            return send_error(pb, LDAP_UNWILLING_TO_PERFORM,
                              "Can't disable last active token");
        }

        if (strcasecmp(mods[i]->mod_type, "ipatokenOwner") == 0) {
            return send_error(pb, LDAP_UNWILLING_TO_PERFORM,
                              "Can't change last active token's owner");
        }

        if (strcasecmp(mods[i]->mod_type, "ipatokenNotBefore") == 0) {
            return send_error(pb, LDAP_UNWILLING_TO_PERFORM,
                              "Can't change last active token's start time");
        }

        if (strcasecmp(mods[i]->mod_type, "ipatokenNotAfter") == 0) {
            return send_error(pb, LDAP_UNWILLING_TO_PERFORM,
                              "Can't change last active token's end time");
        }
    }

    return 0;
}

static int
preop_init(Slapi_PBlock *pb)
{
    int ret = 0;

    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_DELETE_FN, preop_del);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_MODIFY_FN, preop_mod);
    return ret;
}

int
ipa_otp_lasttoken_init(Slapi_PBlock *pb)
{
    int ret = 0;

    ret |= slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_id);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *) &preop_desc);
    ret |= slapi_register_plugin("betxnpreoperation", 1, __func__, preop_init,
                                 PLUGIN_NAME, NULL, plugin_id);
    return ret;
}
