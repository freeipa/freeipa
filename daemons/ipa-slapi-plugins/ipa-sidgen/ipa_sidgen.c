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
 * Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2012 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <dirsrv/slapi-plugin.h>

#include "util.h"
#include "ipa_sidgen.h"

Slapi_PluginDesc ipa_sidgen_plugin_desc = {
    IPA_SIDGEN_FEATURE_DESC,
    "FreeIPA project",
    "FreeIPA/1.0",
    IPA_SIDGEN_PLUGIN_DESC
};

static int ipa_sidgen_start(Slapi_PBlock *pb)
{
    return 0;
}

static int ipa_sidgen_close(Slapi_PBlock *pb)
{
    int ret;
    struct ipa_sidgen_ctx *ctx;

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret == 0) {
        free_ranges(&ctx->ranges);
        slapi_ch_free_string(&ctx->dom_sid);
    } else {
        LOG_FATAL("Missing private plugin context.\n");
    }

    return 0;
}

static int ipa_sidgen_add_post_op(Slapi_PBlock *pb)
{
    int ret;
    int is_repl_op;
    struct slapi_entry *entry = NULL;
    const char *dn_str;
    Slapi_DN *dn = NULL;
    struct ipa_sidgen_ctx *ctx;
    Slapi_PBlock *search_pb = NULL;
    char *errmsg = NULL;

    ret = slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl_op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        return LDAP_OPERATIONS_ERROR;
    }

    if (is_repl_op) {
        LOG("Is replicated operation, nothing to do.\n");
        return LDAP_SUCCESS;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret != 0) {
        LOG_FATAL("Missing private plugin context.\n");
        goto done;
    }

    if (ctx->dom_sid == NULL) {
        ret = get_dom_sid(ctx->plugin_id, ctx->base_dn, &ctx->dom_sid);
        if (ret != 0) {
            LOG_FATAL("Domain SID not available, nothing to do.\n");
            ret = 0;
            goto done;
        }
    }

    ret = slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn_str);
    if (ret != 0) {
        LOG_FATAL("Missing target DN.\n");
        goto done;
    }

    dn = slapi_sdn_new_dn_byref(dn_str);
    if (dn == NULL) {
        LOG_FATAL("Failed to convert target DN.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_search_internal_get_entry(dn, NULL, &entry, ctx->plugin_id);
    if (ret != 0 || entry == NULL) {
        LOG_FATAL("Missing target entry.\n");
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    if (ctx->ranges == NULL) {
        ret = get_ranges(ctx->plugin_id, ctx->base_dn, &ctx->ranges);
        if (ret != 0) {
            if (ret == LDAP_NO_SUCH_OBJECT) {
                ret = 0;
                LOG("No ID ranges found, nothing to do.\n");
            } else {
                LOG_FATAL("Failed to get ID ranges.\n");
            }
            goto done;
        }
    }

    ret = find_sid_for_ldap_entry(entry, ctx->plugin_id, ctx->base_dn,
                                  ctx->dom_sid, ctx->ranges);
    if (ret != 0) {
        LOG_FATAL("Cannot add SID to new entry.\n");
        goto done;
    }

    ret = 0;
done:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    slapi_sdn_free(&dn);

    if (ret != 0) {
        if (errmsg == NULL) {
            errmsg = "SIDGEN error";
        }
        slapi_send_ldap_result(pb, ret, NULL, errmsg, 0, NULL);
    }

    return ret;
}

static int ipa_sidgen_init_ctx(Slapi_PBlock *pb, struct ipa_sidgen_ctx **_ctx)
{
    struct ipa_sidgen_ctx *ctx;
    Slapi_Entry *entry;
    int ret;

    ctx = calloc(1, sizeof(struct ipa_sidgen_ctx));
    if (ctx == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ctx->plugin_id);
    if ((ret != 0) || (ctx->plugin_id == NULL)) {
        LOG_FATAL("Could not get identity or identity was NULL\n");
        if (ret == 0) {
            ret = -1;
        }
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &entry);
    if (entry == NULL) {
        LOG_FATAL("Plugin configuration not found!\n");
        ret = EINVAL;
        goto done;
    }

    ctx->base_dn = slapi_entry_attr_get_charptr(entry, "nsslapd-basedn");
    if (ctx->base_dn == NULL) {
        LOG_FATAL("Base DN not found in plugin configuration!\n");
        ret = EINVAL;
        goto done;
    }

    ret = 0;

done:
    if (ret != 0) {
        free(ctx);
    } else {
        *_ctx = ctx;
    }

    return ret;
}

int ipa_sidgen_init(Slapi_PBlock *pb)
{
    int ret;
    struct ipa_sidgen_ctx *ctx;

    ret = ipa_sidgen_init_ctx(pb, &ctx);
    if (ret != 0) {
        LOG_FATAL("Failed ot initialize sidgen postop plugin.\n");
        /* do not cause DS to stop, simply do nothing */
        return 0;
    }

    ret = 0;
    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_03) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) ipa_sidgen_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipa_sidgen_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &ipa_sidgen_plugin_desc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
                         (void *) ipa_sidgen_add_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, ctx) != 0) {
        LOG_FATAL("failed to register plugin\n");
        ret = EFAIL;
    }

    return ret;
}
