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

#include "otp_config.h"

#include <pratom.h>
#include <plstr.h>

#define OTP_CONFIG_AUTH_TYPE_DISABLED (1 << 31)

struct spec {
    uint32_t (*func)(Slapi_Entry *, const char *attr);
    const char *prefix;
    const char *attr;
    uint32_t dflt;
};

struct record {
    struct record *next;
    const struct spec *spec;
    Slapi_DN *sdn;
    uint32_t value;
};

struct otp_config {
    Slapi_ComponentId *plugin_id;
    struct record *records;
};

static uint32_t string_to_types(const char *str)
{
    static const struct {
        const char *string;
        uint32_t config;
    } map[] = {
        { "disabled", OTP_CONFIG_AUTH_TYPE_DISABLED },
        { "password", OTP_CONFIG_AUTH_TYPE_PASSWORD },
        { "otp",      OTP_CONFIG_AUTH_TYPE_OTP },
        { "pkinit",   OTP_CONFIG_AUTH_TYPE_PKINIT },
        { "radius",   OTP_CONFIG_AUTH_TYPE_RADIUS },
        {}
    };

    for (uint32_t i = 0; map[i].string != NULL; i++) {
        if (strcasecmp(map[i].string, str) == 0)
            return map[i].config;
    }

    return OTP_CONFIG_AUTH_TYPE_NONE;
}

static uint32_t entry_to_authtypes(Slapi_Entry *e, const char *attr)
{
    char **auth_types = NULL;

    if (e == NULL)
        return OTP_CONFIG_AUTH_TYPE_NONE;

    /* Fetch the auth type values from the config entry. */
    auth_types = slapi_entry_attr_get_charray(e, attr);
    if (auth_types == NULL)
        return OTP_CONFIG_AUTH_TYPE_NONE;

    uint32_t types = OTP_CONFIG_AUTH_TYPE_NONE;
    for (uint32_t i = 0; auth_types[i] != NULL; i++)
        types |= string_to_types(auth_types[i]);

    slapi_ch_array_free(auth_types);
    return types;
}

static const struct spec authtypes = {
    entry_to_authtypes,
    "cn=ipaConfig,cn=etc,%s",
    "ipaUserAuthType",
    OTP_CONFIG_AUTH_TYPE_PASSWORD
};

static Slapi_DN *make_sdn(const char *prefix, const Slapi_DN *suffix)
{
    char *dn = slapi_ch_smprintf(prefix, slapi_sdn_get_dn(suffix));
    return slapi_sdn_new_dn_passin(dn);
}

static uint32_t find_value(const struct otp_config *cfg,
                           const Slapi_DN *suffix, const struct spec *spec)
{
    uint32_t value = 0;
    Slapi_DN *sdn;

    sdn = make_sdn(spec->prefix, suffix);
    for (struct record *rec = cfg->records; rec != NULL; rec = rec->next) {
        if (rec->spec == spec) {
            value = PR_ATOMIC_ADD(&rec->value, 0);
            break;
        }
    }

    slapi_sdn_free(&sdn);
    return value;
}

static void update(const struct otp_config *cfg, Slapi_DN *src,
                   Slapi_Entry *entry)
{
    Slapi_DN *dst = entry == NULL ? NULL : slapi_entry_get_sdn(entry);

    for (struct record *rec = cfg->records; rec != NULL; rec = rec->next) {
        uint32_t val = rec->spec->dflt;

        /* If added, modified or moved into place... */
        if (dst != NULL && slapi_sdn_compare(rec->sdn, dst) == 0) {
            Slapi_Attr *attr = NULL;
            if (slapi_entry_attr_find(entry, rec->spec->attr, &attr) == 0)
                val = rec->spec->func(entry, rec->spec->attr);

        /* If NOT deleted or moved out of place... */
        } else if (slapi_sdn_compare(rec->sdn, src) != 0)
            continue;

        PR_ATOMIC_SET(&rec->value, val);
    }
}

struct otp_config *otp_config_init(Slapi_ComponentId *plugin_id)
{
    static const struct spec *specs[] = {
        &authtypes,
        NULL
    };

    struct otp_config *cfg = NULL;
    void *node = NULL;

    cfg = (typeof(cfg)) slapi_ch_calloc(1, sizeof(*cfg));
    cfg->plugin_id = plugin_id;

    /* Build the config table. */
    for (Slapi_DN *sfx = slapi_get_first_suffix(&node, 0);
         sfx != NULL;
         sfx = slapi_get_next_suffix(&node, 0)) {
        for (size_t i = 0; specs[i] != NULL; i++) {
            Slapi_Entry *entry = NULL;
            struct record *rec;

            /* Create the config entry. */
            rec = (typeof(rec)) slapi_ch_calloc(1, sizeof(*rec));
            rec->spec = specs[i];
            rec->sdn = make_sdn(rec->spec->prefix, sfx);

            /* Add config to the list. */
            rec->next = cfg->records;
            cfg->records = rec;

            /* Load the specified entry. */
            slapi_search_internal_get_entry(rec->sdn, NULL, &entry, plugin_id);
            update(cfg, rec->sdn, entry);
            slapi_entry_free(entry);
        }
    }

    return cfg;
}

static void record_fini(struct record **rec)
{
    if (rec == NULL || *rec == NULL)
        return;

    record_fini(&(*rec)->next);
    slapi_sdn_free(&(*rec)->sdn);
    slapi_ch_free((void **) rec);
}

void otp_config_fini(struct otp_config **cfg)
{
    if (cfg == NULL || *cfg == NULL)
        return;

    record_fini(&(*cfg)->records);
    slapi_ch_free((void **) cfg);
}

void otp_config_update(struct otp_config *cfg, Slapi_PBlock *pb)
{
    Slapi_Entry *entry = NULL;
    Slapi_DN *src = NULL;
    int oprc = 0;

    /* Just bail if the operation failed. */
    if (slapi_pblock_get(pb, SLAPI_PLUGIN_OPRETURN, &oprc) != 0 || oprc != 0)
        return;

    /* Get the source SDN. */
    if (slapi_pblock_get(pb, SLAPI_TARGET_SDN, &src) != 0)
        return;

    /* Ignore the error here (delete operations). */
    (void) slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &entry);

    update(cfg, src, entry);
}

Slapi_ComponentId *otp_config_plugin_id(const struct otp_config *cfg)
{
    if (cfg == NULL)
        return NULL;

    return cfg->plugin_id;
}

uint32_t otp_config_auth_types(const struct otp_config *cfg,
                               Slapi_Entry *user_entry)
{
    uint32_t glbl = OTP_CONFIG_AUTH_TYPE_NONE;
    uint32_t user = OTP_CONFIG_AUTH_TYPE_NONE;
    const Slapi_DN *sfx;

    /* Load the global value. */
    sfx = slapi_get_suffix_by_dn(slapi_entry_get_sdn(user_entry));
    glbl = find_value(cfg, sfx, &authtypes);

    /* Load the user value if not disabled. */
    if ((glbl & OTP_CONFIG_AUTH_TYPE_DISABLED) == 0)
        user = entry_to_authtypes(user_entry, authtypes.attr);

    /* Filter out the disabled flag. */
    glbl &= ~OTP_CONFIG_AUTH_TYPE_DISABLED;
    user &= ~OTP_CONFIG_AUTH_TYPE_DISABLED;

    if (user != OTP_CONFIG_AUTH_TYPE_NONE)
        return user;

    if (glbl != OTP_CONFIG_AUTH_TYPE_NONE)
        return glbl;

    return OTP_CONFIG_AUTH_TYPE_PASSWORD;
}
