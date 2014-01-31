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

#include "authcfg.h"
#include "ipapwd.h"

#include "pratom.h"

static struct config {
    struct config *next;
    Slapi_DN *suffix;
    uint32_t config;
} *config;

static uint32_t string_to_config(const char *str)
{
    static const struct {
        const char *string;
        uint32_t config;
    } map[] = {
        { "disabled", AUTHCFG_AUTH_TYPE_DISABLED },
        { "password", AUTHCFG_AUTH_TYPE_PASSWORD },
        { "otp",      AUTHCFG_AUTH_TYPE_OTP },
        { "pkinit",   AUTHCFG_AUTH_TYPE_PKINIT },
        { "radius",   AUTHCFG_AUTH_TYPE_RADIUS },
        {}
    };

    for (uint32_t i = 0; map[i].string != NULL; i++) {
        if (strcasecmp(map[i].string, str) == 0)
            return map[i].config;
    }

    return AUTHCFG_AUTH_TYPE_NONE;
}

static uint32_t entry_to_config(Slapi_Entry *e)
{
    char **auth_types = NULL;

    if (e == NULL)
        return AUTHCFG_AUTH_TYPE_NONE;

    /* Fetch the auth type values from the config entry. */
    auth_types = slapi_entry_attr_get_charray(e, "ipaUserAuthType");
    if (auth_types == NULL)
        return AUTHCFG_AUTH_TYPE_NONE;

    uint32_t types = AUTHCFG_AUTH_TYPE_NONE;
    for (uint32_t i = 0; auth_types[i] != NULL; i++)
        types |= string_to_config(auth_types[i]);

    slapi_ch_array_free(auth_types);

    return types;
}

static Slapi_DN *suffix_to_config_dn(Slapi_DN *suffix)
{
    Slapi_DN *sdn = NULL;
    char *dn = NULL;

    if (suffix == NULL)
        return NULL;

    dn = PR_smprintf("cn=ipaConfig,cn=etc,%s", slapi_sdn_get_dn(suffix));
    if (dn == NULL)
        return NULL;

    sdn = slapi_sdn_new_dn_byval(dn);
    PR_smprintf_free(dn);
    return sdn;
}

static uint32_t suffix_to_config(Slapi_DN *suffix)
{
    static char *attrs[] = { "ipaUserAuthType", NULL };
    Slapi_Entry *entry = NULL;
    Slapi_DN *sdn = NULL;
    uint32_t types;
    int ret;

    sdn = suffix_to_config_dn(suffix);
    if (sdn == NULL)
        return AUTHCFG_AUTH_TYPE_NONE;

    ret = slapi_search_internal_get_entry(sdn, attrs, &entry,
                                          ipapwd_get_plugin_id());
    slapi_sdn_free(&sdn);
    if (ret != LDAP_SUCCESS)
        return AUTHCFG_AUTH_TYPE_NONE;

    types = entry_to_config(entry);
    slapi_entry_free(entry);

    return types;
}

static Slapi_DN *sdn_to_suffix(Slapi_DN *sdn)
{
    Slapi_DN *suffix = NULL;
    void *node = NULL;

    if (sdn == NULL)
        return NULL;

    for (suffix = slapi_get_first_suffix(&node, 0); suffix != NULL;
         suffix = slapi_get_next_suffix(&node, 0)) {
        if (slapi_sdn_issuffix(sdn, suffix))
            return suffix;
    }

    return NULL;
}

static bool sdn_is_config(Slapi_DN *sdn)
{
    Slapi_DN *sfx = NULL;
    Slapi_DN *cfg = NULL;
    int cmp;

    if (sdn == NULL)
        return false;

    sfx = sdn_to_suffix(sdn);
    if (sfx == NULL)
        return false;

    cfg = suffix_to_config_dn(sfx);
    if (cfg == NULL)
        return false;

    cmp = slapi_sdn_compare(cfg, sdn);
    slapi_sdn_free(&cfg);
    return cmp == 0;
}

void cache_free(struct config **cfg)
{
    if (cfg == NULL || *cfg == NULL)
        return;

    cache_free(&(*cfg)->next);
    free(*cfg);
    *cfg = NULL;
}

bool authcfg_init(void)
{
    struct config *cfg = NULL;
    Slapi_DN *sfx = NULL;
    void *node = NULL;

    /* If we are already initialized, return true. */
    if (config != NULL)
        return true;

    /* Look up the config for each suffix. */
    for (sfx = slapi_get_first_suffix(&node, 0); sfx != NULL;
         sfx = slapi_get_next_suffix(&node, 0)) {
        cfg = calloc(1, sizeof(*cfg));
        if (cfg == NULL) {
            authcfg_fini();
            return false;
        }

        cfg->suffix = sfx;
        cfg->config = suffix_to_config(sfx);
        cfg->next = config;
        config = cfg;
    }

    return true;
}

void authcfg_fini(void)
{
    cache_free(&config);
}

uint32_t authcfg_get_auth_types(Slapi_Entry *user_entry)
{
    uint32_t glbl = AUTHCFG_AUTH_TYPE_NONE;
    uint32_t user = AUTHCFG_AUTH_TYPE_NONE;
    Slapi_DN *sfx = NULL;
    Slapi_DN *sdn = NULL;

    /* Find the root suffix. */
    sdn = slapi_entry_get_sdn(user_entry);
    sfx = sdn_to_suffix(sdn);

    /* Find the global config. */
    if (sfx != NULL) {
        for (struct config *cfg = config; cfg && sfx; cfg = cfg->next) {
            if (slapi_sdn_compare(sfx, cfg->suffix) == 0) {
                glbl = PR_ATOMIC_ADD(&cfg->config, 0);
                break;
            }
        }
    }

    /* Global disabled overrides user settings. */
    if (glbl & AUTHCFG_AUTH_TYPE_DISABLED)
        return AUTHCFG_AUTH_TYPE_DISABLED;

    /* Get the user's config. */
    user = entry_to_config(user_entry);

    if (user == AUTHCFG_AUTH_TYPE_NONE) {
        if (glbl == AUTHCFG_AUTH_TYPE_NONE)
            return AUTHCFG_AUTH_TYPE_PASSWORD;
        return glbl;
    }

    return user & ~AUTHCFG_AUTH_TYPE_DISABLED;
}

void authcfg_reload_global_config(Slapi_DN *sdn, Slapi_Entry *config_entry)
{
    uint32_t glbl = AUTHCFG_AUTH_TYPE_NONE;
    Slapi_DN *sfx = NULL;
    Slapi_DN *dest;

    /* Get the destination DN. */
    dest = config_entry == NULL ? NULL : slapi_entry_get_sdn(config_entry);

    /* Added, modified, moved into place. */
    if (sdn_is_config(dest)) {
        sfx = sdn_to_suffix(dest);
        glbl = entry_to_config(config_entry);

    /* Deleted, moved out of place. */
    } else if (sdn_is_config(sdn)) {
        sfx = sdn_to_suffix(sdn);
    }

    /* Reload config. */
    for (struct config *cfg = config; cfg && sfx; cfg = cfg->next) {
        if (slapi_sdn_compare(sfx, cfg->suffix) == 0) {
            PR_ATOMIC_SET(&cfg->config, glbl);
            break;
        }
    }
}
