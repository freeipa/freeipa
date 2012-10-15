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
 * Copyright (C) 2011 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include <dirsrv/slapi-plugin.h>

#include "util.h"

#define IPA_CN "cn"
#define IPA_BASE_ID "ipaBaseID"
#define IPA_ID_RANGE_SIZE "ipaIDRangeSize"
#define IPA_BASE_RID "ipaBaseRID"
#define IPA_SECONDARY_BASE_RID "ipaSecondaryBaseRID"
#define IPA_DOMAIN_ID "ipaNTTrustedDomainSID"
#define RANGES_FILTER "objectclass=ipaIDRange"

#define IPA_PLUGIN_NAME "ipa-range-check"
#define IPA_RANGE_CHECK_FEATURE_DESC "IPA ID range check plugin"
#define IPA_RANGE_CHECK_PLUGIN_DESC "Check if newly added or modified " \
                                    "ID ranges do not overlap with existing ones"

Slapi_PluginDesc ipa_range_check_plugin_desc = {
    IPA_RANGE_CHECK_FEATURE_DESC,
    "FreeIPA project",
    "FreeIPA/1.0",
    IPA_RANGE_CHECK_PLUGIN_DESC
};

struct ipa_range_check_ctx {
    Slapi_ComponentId *plugin_id;
    const char *base_dn;
};

struct range_info {
    char *name;
    char *domain_id;
    uint32_t base_id;
    uint32_t id_range_size;
    uint32_t base_rid;
    uint32_t secondary_base_rid;
};

static int slapi_entry_to_range_info(struct slapi_entry *entry,
                                     struct range_info **_range)
{
    int ret;
    unsigned long ul_val;
    struct range_info *range = NULL;

    range = calloc(1, sizeof(struct range_info));
    if (range == NULL) {
        return ENOMEM;
    }

    range->name = slapi_entry_attr_get_charptr(entry, IPA_CN);
    if (range->name == NULL) {
        ret = EINVAL;
        goto done;
    }

    range->domain_id = slapi_entry_attr_get_charptr(entry, IPA_DOMAIN_ID);

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_BASE_ID);
    if (ul_val == 0 || ul_val >= UINT32_MAX) {
        ret = ERANGE;
        goto done;
    }
    range->base_id = ul_val;

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_ID_RANGE_SIZE);
    if (ul_val == 0 || ul_val >= UINT32_MAX) {
        ret = ERANGE;
        goto done;
    }
    range->id_range_size = ul_val;

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_BASE_RID);
    if (ul_val >= UINT32_MAX) {
        ret = ERANGE;
        goto done;
    }
    range->base_rid = ul_val;

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_SECONDARY_BASE_RID);
    if (ul_val >= UINT32_MAX) {
        ret = ERANGE;
        goto done;
    }
    range->secondary_base_rid = ul_val;

    *_range = range;
    ret = 0;

done:
    if (ret != 0) {
        free(range);
    }

    return ret;
}

#define IN_RANGE(x,base,size) ( (x) >= (base) && ((x) - (base) < (size)) )
static bool intervals_overlap(uint32_t x, uint32_t base, uint32_t x_size, uint32_t base_size)
{
    if (IN_RANGE(x, base, base_size) ||
        IN_RANGE((x + x_size - 1), base, base_size) ||
        IN_RANGE(base, x, x_size) ||
        IN_RANGE((base + base_size - 1), x, x_size)) {
        return true;
    }

    return false;
}

/**
 * returns 0 if there is no overlap
 *
 * connected ranges must not overlap:
 * existing range:  base  rid  sec_rid
 *                   |     |  \  / |
 *                   |     |   \/  |
 *                   |     |   /\  |
 *                   |     |  /  \ |
 * new range:       base  rid  sec_rid
 **/
static int ranges_overlap(struct range_info *r1, struct range_info *r2)
{
    if (r1->name != NULL && r2->name != NULL &&
        strcasecmp(r1->name, r2->name) == 0) {
        return 0;
    }

    /* check if base range overlaps with existing base range */
    if (intervals_overlap(r1->base_id, r2->base_id,
        r1->id_range_size, r2->id_range_size)){
        return 1;
    }

    /* if both base_rid and secondary_base_rid = 0, the rid range is not set */
    bool rid_ranges_set = (r1->base_rid != 0 || r1->secondary_base_rid != 0) &&
                          (r2->base_rid != 0 || r2->secondary_base_rid != 0);

    bool ranges_from_same_domain =
         (r1->domain_id == NULL && r2->domain_id == NULL) ||
         (r1->domain_id != NULL && r2->domain_id != NULL &&
          strcasecmp(r1->domain_id, r2->domain_id) == 0);

    /**
     * in case rid range is not set or ranges belong to different domains
     * we can skip rid range tests as they are irrelevant
     */
    if (rid_ranges_set && ranges_from_same_domain){

        /* check if rid range overlaps with existing rid range */
        if (intervals_overlap(r1->base_rid, r2->base_rid,
            r1->id_range_size, r2->id_range_size))
            return 2;

        /* check if secondary rid range overlaps with existing secondary rid range */
        if (intervals_overlap(r1->secondary_base_rid, r2->secondary_base_rid,
            r1->id_range_size, r2->id_range_size))
            return 3;

        /* check if rid range overlaps with existing secondary rid range */
        if (intervals_overlap(r1->base_rid, r2->secondary_base_rid,
            r1->id_range_size, r2->id_range_size))
            return 4;

        /* check if secondary rid range overlaps with existing rid range */
        if (intervals_overlap(r1->secondary_base_rid, r2->base_rid,
            r1->id_range_size, r2->id_range_size))
            return 5;
    }

    return 0;
}

static int ipa_range_check_start(Slapi_PBlock *pb)
{
    return 0;
}

static int ipa_range_check_close(Slapi_PBlock *pb)
{
    return 0;
}

static int ipa_range_check_pre_op(Slapi_PBlock *pb, int modtype)
{
    int ret;
    int is_repl_op;
    struct slapi_entry *entry = NULL;
    bool free_entry = false;
    struct range_info *new_range = NULL;
    struct range_info *old_range = NULL;
    const char *dn_str;
    Slapi_DN *dn = NULL;
    struct ipa_range_check_ctx *ctx;
    LDAPMod **mods = NULL;
    Slapi_PBlock *search_pb = NULL;
    int search_result;
    Slapi_Entry **search_entries = NULL;
    size_t c;
    int no_overlap = 0;
    const char *check_attr;
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


    switch (modtype) {
        case LDAP_CHANGETYPE_ADD:
            ret = slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &entry);
            if (ret != 0) {
                LOG_FATAL("Missing entry to add.\n");
                goto done;
            }

            /* Check if this is a range object */
            check_attr = slapi_entry_attr_get_charptr(entry, IPA_BASE_ID);
            if (check_attr == NULL) {
                LOG("Not an ID range object, nothing to do.\n");
                ret = 0;
                goto done;
            }

            break;
        case  LDAP_CHANGETYPE_MODIFY:
            ret = slapi_search_internal_get_entry(dn, NULL, &entry,
                                                  ctx->plugin_id);
            if (ret != 0 || entry == NULL) {
                LOG_FATAL("Missing entry to modify.\n");
                ret = LDAP_NO_SUCH_OBJECT;
                goto done;
            }
            free_entry = true;

            /* Check if this is a range object */
            check_attr = slapi_entry_attr_get_charptr(entry, IPA_BASE_ID);
            if (check_attr == NULL) {
                LOG("Not an ID range object, nothing to do.\n");
                ret = 0;
                goto done;
            }

            ret = slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
            if (ret != 0) {
                LOG_FATAL("Missing modify values.\n");
                goto done;
            }

            ret = slapi_entry_apply_mods(entry, mods);
            if (ret != 0) {
                LOG_FATAL("Failed to apply modifications.\n");
                goto done;
            }

            break;
        default:
            ret = LDAP_OPERATIONS_ERROR;
            LOG_FATAL("Unsupported LDAP operation.\n");
            goto done;
    }

    ret = slapi_entry_to_range_info(entry, &new_range);
    if (ret != 0) {
        LOG_FATAL("Failed to convert LDAP entry to range struct.\n");
        goto done;
    }

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        LOG_FATAL("Failed to create new pblock.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    slapi_search_internal_set_pb(search_pb, ctx->base_dn,
                                 LDAP_SCOPE_SUBTREE, RANGES_FILTER,
                                 NULL, 0, NULL, NULL, ctx->plugin_id, 0);

    ret = slapi_search_internal_pb(search_pb);
    if (ret != 0) {
        LOG_FATAL("Starting internal search failed.\n");
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &search_result);
    if (ret != 0 || search_result != LDAP_SUCCESS) {
        LOG_FATAL("Internal search failed.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &search_entries);
    if (ret != 0) {
        LOG_FATAL("Failed to read searched entries.\n");
        goto done;
    }

    if (search_entries == NULL || search_entries[0] == NULL) {
        LOG("No existing entries.\n");
        ret = 0;
        goto done;
    }

    for (c = 0; search_entries[c] != NULL; c++) {
        ret = slapi_entry_to_range_info(search_entries[c], &old_range);
        if (ret != 0) {
            LOG_FATAL("Failed to convert LDAP entry to range struct.\n");
            goto done;
        }

        no_overlap = ranges_overlap(new_range, old_range);
        free(old_range);
        old_range = NULL;
        if (no_overlap != 0) {
            ret = LDAP_CONSTRAINT_VIOLATION;

            switch (no_overlap){
            case 1:
                errmsg = "New base range overlaps with existing base range.";
                break;
            case 2:
                errmsg = "New primary rid range overlaps with existing primary rid range.";
                break;
            case 3:
                errmsg = "New secondary rid range overlaps with existing secondary rid range.";
                break;
            case 4:
                errmsg = "New primary rid range overlaps with existing secondary rid range.";
                break;
            case 5:
                errmsg = "New secondary rid range overlaps with existing primary rid range.";
                break;
            default:
                errmsg = "New range overlaps with existing one.";
                break;
            }

            LOG_FATAL("%s\n",errmsg);
            goto done;
        }
    }
    LOG("No overlaps found.\n");

    ret = 0;

done:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    slapi_sdn_free(&dn);
    free(old_range);
    free(new_range);
    if (free_entry) {
        slapi_entry_free(entry);
    }

    if (ret != 0) {
        if (errmsg == NULL) {
            errmsg = "Range Check error";
        }
        slapi_send_ldap_result(pb, ret, NULL, errmsg, 0, NULL);
    }

    return ret;
}

static int ipa_range_check_mod_pre_op(Slapi_PBlock * pb)
{
    return ipa_range_check_pre_op(pb, LDAP_CHANGETYPE_MODIFY);
}

static int ipa_range_check_add_pre_op(Slapi_PBlock *pb)
{
    return ipa_range_check_pre_op(pb, LDAP_CHANGETYPE_ADD);
}

static int ipa_range_check_init_ctx(Slapi_PBlock *pb,
                                    struct ipa_range_check_ctx **_ctx)
{
    struct ipa_range_check_ctx *ctx;
    Slapi_Entry *entry;
    int ret;

    ctx = calloc(1, sizeof(struct ipa_range_check_ctx));
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

int ipa_range_check_init(Slapi_PBlock *pb)
{
    int ret;
    struct ipa_range_check_ctx *rc_ctx;

    ret = ipa_range_check_init_ctx(pb, &rc_ctx);
    if (ret != 0) {
        LOG_FATAL("Failed ot initialize range check plugin.\n");
        /* do not cause DS to stop, simply do nothing */
        return 0;
    }

    ret = 0;
    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) ipa_range_check_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipa_range_check_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &ipa_range_check_plugin_desc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN,
                         (void *) ipa_range_check_mod_pre_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN,
                         (void *) ipa_range_check_add_pre_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, rc_ctx) != 0) {
        LOG_FATAL("failed to register plugin\n");
        ret = EFAIL;
    }

    return ret;
}
