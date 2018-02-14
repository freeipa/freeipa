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

#include "../libotp/otp_token.h"
#include <time.h>

#include "util.h"

#define PLUGIN_NAME "ipa-otp-lasttoken"
#define OTP_CONTAINER "cn=otp,%s"

static struct otp_config *otp_config;
void *ipa_otp_lasttoken_plugin_id;

static bool entry_is_token(Slapi_Entry *entry)
{
    char **ocls;

    ocls = slapi_entry_attr_get_charray(entry, SLAPI_ATTR_OBJECTCLASS);
    for (size_t i = 0; ocls != NULL && ocls[i] != NULL; i++) {
        if (strcasecmp(ocls[i], "ipaToken") == 0) {
            slapi_ch_array_free(ocls);
            return true;
        }
    }

    return false;
}

static bool sdn_in_otp_container(Slapi_DN *sdn)
{
    const Slapi_DN *base;
    Slapi_DN *container;
    bool result;
    char *dn;

    base = slapi_get_suffix_by_dn(sdn);
    if (base == NULL)
        return false;

    dn = slapi_ch_smprintf(OTP_CONTAINER, slapi_sdn_get_dn(base));
    if (dn == NULL)
        return false;

    container = slapi_sdn_new_dn_passin(dn);
    result = slapi_sdn_issuffix(sdn, container);
    slapi_sdn_free(&container);

    return result;
}

static bool sdn_is_only_enabled_token(Slapi_DN *target_sdn, const char *user_dn)
{
    struct otp_token **tokens;
    bool result = false;

    tokens = otp_token_find(otp_config, user_dn, NULL, true, NULL);

    if (tokens != NULL && tokens[0] != NULL && tokens[1] == NULL) {
        const Slapi_DN *token_sdn = otp_token_get_sdn(tokens[0]);
        if (token_sdn != NULL)
            result = slapi_sdn_compare(token_sdn, target_sdn) == 0;
    }

    otp_token_free_array(tokens);
    return result;
}

static bool is_pwd_enabled(const char *user_dn)
{
    char *attrs[] = { "ipaUserAuthType", NULL };
    Slapi_Entry *entry = NULL;
    uint32_t authtypes;
    Slapi_DN *sdn;
    int search_result = 0;

    sdn = slapi_sdn_new_dn_byval(user_dn);
    if (sdn == NULL)
        return false;

    search_result = slapi_search_internal_get_entry(sdn, attrs, &entry,
            otp_config_plugin_id(otp_config));
    if (search_result != LDAP_SUCCESS) {
        LOG_TRACE("File '%s' line %d: Unable to access LDAP entry '%s'. "
                "Perhaps it doesn't exist? Error code: %d\n", __FILE__,
                __LINE__, slapi_sdn_get_dn(sdn), search_result);
    }
    slapi_sdn_free(&sdn);
    if (entry == NULL)
        return false;

    authtypes = otp_config_auth_types(otp_config, entry);
    slapi_entry_free(entry);

    return authtypes & OTP_CONFIG_AUTH_TYPE_PASSWORD;
}

static bool is_allowed(Slapi_PBlock *pb, Slapi_Entry *entry)
{
    Slapi_DN *target_sdn = NULL;
    const char *bind_dn;

    /* Ignore internal operations. */
    if (slapi_op_internal(pb))
        return true;

    /* Load parameters. */
    (void) slapi_pblock_get(pb, SLAPI_TARGET_SDN, &target_sdn);
    (void) slapi_pblock_get(pb, SLAPI_CONN_DN, &bind_dn);
    if (target_sdn == NULL || bind_dn == NULL) {
        LOG_FATAL("Missing parameters!\n");
        return false;
    }

    if (entry != NULL
            ? !entry_is_token(entry)
            : !sdn_in_otp_container(target_sdn))
        return true;

    if (!sdn_is_only_enabled_token(target_sdn, bind_dn))
        return true;

    if (is_pwd_enabled(bind_dn))
        return true;

    return false;
}

static inline int send_error(Slapi_PBlock *pb, int rc, const char *errstr)
{
    slapi_send_ldap_result(pb, rc, NULL, (char *) errstr, 0, NULL);
    if (slapi_pblock_set(pb, SLAPI_RESULT_CODE, &rc)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
    }
    return rc;
}

static int preop_del(Slapi_PBlock *pb)
{
    if (is_allowed(pb, NULL))
        return 0;

    return send_error(pb, LDAP_UNWILLING_TO_PERFORM,
                      "Can't delete last active token");
}

static int preop_mod(Slapi_PBlock *pb)
{
    static const struct {
        const char *attr;
        const char *msg;
    } errors[] = {
        {"ipatokenDisabled",  "Can't disable last active token"},
        {"ipatokenOwner",     "Can't change last active token's owner"},
        {"ipatokenNotBefore", "Can't change last active token's start time"},
        {"ipatokenNotAfter",  "Can't change last active token's end time"},
        {}
    };

    const LDAPMod **mods = NULL;
    Slapi_Entry *entry = NULL;

    (void) slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &entry);
    (void) slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);

    if (is_allowed(pb, entry))
        return 0;

    /* If a protected attribute is modified, deny. */
    for (int i = 0; mods != NULL && mods[i] != NULL; i++) {
        for (int j = 0; errors[j].attr != NULL; j++) {
            if (strcasecmp(mods[i]->mod_type, errors[j].attr) == 0)
                return send_error(pb, LDAP_UNWILLING_TO_PERFORM, errors[j].msg);
        }
    }

    return 0;
}

static int preop_init(Slapi_PBlock *pb)
{
    int ret = 0;

    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_DELETE_FN, preop_del);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_MODIFY_FN, preop_mod);
    return ret;
}

static int update_config(Slapi_PBlock *pb)
{
    otp_config_update(otp_config, pb);
    return 0;
}

static int intpostop_init(Slapi_PBlock *pb)
{
    int ret = 0;

    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_ADD_FN,    (void *) update_config);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_DELETE_FN, (void *) update_config);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODIFY_FN, (void *) update_config);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODRDN_FN, (void *) update_config);

    return ret;
}

static int postop_init(Slapi_PBlock *pb)
{
    int ret = 0;

    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,    (void *) update_config);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN, (void *) update_config);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN, (void *) update_config);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODRDN_FN, (void *) update_config);

    return ret;
}

/* Init data structs */
static int ipa_otp_lasttoken_start(Slapi_PBlock *pb)
{
    /* NOTE: We never call otp_config_fini() from a destructor. This is because
     *       it may race with threaded requests at shutdown. This leak should
     *       only occur when the DS is exiting, so it isn't a big deal.
     */
    otp_config = otp_config_init(ipa_otp_lasttoken_plugin_id);
    return LDAP_SUCCESS;
}

int ipa_otp_lasttoken_init(Slapi_PBlock *pb)
{
    static const Slapi_PluginDesc preop_desc = {
        PLUGIN_NAME,
        "FreeIPA",
        "FreeIPA/1.0",
        "Protect the user's last active token"
    };

    int ret = 0;

    ret |= slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,
                            &ipa_otp_lasttoken_plugin_id);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *) &preop_desc);
    ret |= slapi_register_plugin("betxnpreoperation", 1, __func__, preop_init,
                                 PLUGIN_NAME " betxnpreoperation", NULL,
                                 ipa_otp_lasttoken_plugin_id);
    ret |= slapi_register_plugin("postoperation", 1, __func__, postop_init,
                                 PLUGIN_NAME " postoperation", NULL,
                                 ipa_otp_lasttoken_plugin_id);
    ret |= slapi_register_plugin("internalpostoperation", 1, __func__,
                                 intpostop_init,
                                 PLUGIN_NAME " internalpostoperation", NULL,
                                 ipa_otp_lasttoken_plugin_id);
    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                            (void *)ipa_otp_lasttoken_start);

    return ret;
}
