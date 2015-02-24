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

#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <dirsrv/slapi-plugin.h>

#include "util.h"

#define IPA_CN "cn"
#define IPA_BASE_ID "ipaBaseID"
#define IPA_ID_RANGE_SIZE "ipaIDRangeSize"
#define IPA_RANGE_TYPE "ipaRangeType"
#define IPA_BASE_RID "ipaBaseRID"
#define IPA_SECONDARY_BASE_RID "ipaSecondaryBaseRID"
#define IPA_DOMAIN_ID "ipaNTTrustedDomainSID"
#define RANGES_FILTER "objectclass=ipaIDRange"
#define DOMAIN_ID_FILTER "ipaNTTrustedDomainSID=*"

#define AD_TRUST_RANGE_TYPE "ipa-ad-trust"
#define AD_TRUST_POSIX_RANGE_TYPE "ipa-ad-trust-posix"
#define LOCAL_RANGE_TYPE "ipa-local"


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

typedef enum {
    RANGE_CHECK_OK,
    RANGE_CHECK_BASE_OVERLAP,
    RANGE_CHECK_PRIMARY_PRIMARY_RID_OVERLAP,
    RANGE_CHECK_SECONDARY_SECONDARY_RID_OVERLAP,
    RANGE_CHECK_PRIMARY_SECONDARY_RID_OVERLAP,
    RANGE_CHECK_SECONDARY_PRIMARY_RID_OVERLAP,
    RANGE_CHECK_DIFFERENT_TYPE_IN_DOMAIN,
} range_check_result_t;

struct range_info {
    char *name;
    char *domain_id;
    char *forest_root_id;
    char *id_range_type;
    uint32_t base_id;
    uint32_t id_range_size;
    uint32_t base_rid;
    uint32_t secondary_base_rid;
    bool base_rid_set;
    bool secondary_base_rid_set;
};

static void free_range_info(struct range_info *range) {
    if (range != NULL) {
        slapi_ch_free_string(&(range->name));
        slapi_ch_free_string(&(range->domain_id));
        slapi_ch_free_string(&(range->forest_root_id));
        slapi_ch_free_string(&(range->id_range_type));
        free(range);
    }
}

struct domain_info {
    char *domain_id;
    char *forest_root_id;
    struct domain_info *next;
};

static void free_domain_info(struct domain_info *info) {
    if (info != NULL) {
        slapi_ch_free_string(&(info->domain_id));
        slapi_ch_free_string(&(info->forest_root_id));
        free(info);
    }
}

static int map_domain_to_root(struct domain_info **head,
                              struct slapi_entry *domain,
                              struct slapi_entry *root_domain){

    struct domain_info* new_head = NULL;
    new_head = (struct domain_info*) malloc(sizeof(struct domain_info));
    if (new_head == NULL) {
        return ENOMEM;
    }

    new_head->domain_id = slapi_entry_attr_get_charptr(domain,
                                                       IPA_DOMAIN_ID);
    new_head->forest_root_id = slapi_entry_attr_get_charptr(root_domain,
                                                            IPA_DOMAIN_ID);
    new_head->next = *head;
    *head = new_head;

    return 0;
}

/* Searches for the domain_info struct with the specified domain_id
 * in the linked list. Returns the forest root domain's ID, or NULL for
 * local ranges. */

static char* get_forest_root_id(struct domain_info *head, char* domain_id) {

    /* For local ranges there is no forest root domain,
     * so consider only ranges with domain_id set */
    if (domain_id != NULL) {
        while(head) {
            if (strcasecmp(head->domain_id, domain_id) == 0) {
                return slapi_ch_strdup(head->forest_root_id);
            }
            head = head->next;
        }
     }

    return NULL;
}


/*
 * This function builds a mapping from domain ID to forest
 * root domain ID.
 */

static int build_domain_to_forest_root_map(struct domain_info **head,
                                           struct ipa_range_check_ctx *ctx){

    Slapi_PBlock *trusted_domain_search_pb = NULL;
    Slapi_Entry **trusted_domain_entries = NULL;
    Slapi_DN *base_dn = NULL;
    char *base = NULL;

    int search_result;
    int ret = 0;

    LOG("Building forest root map \n");

    /* Set the base DN for the search to cn=ad, cn=trusts, $SUFFIX */
    ret = asprintf(&base, "cn=ad,cn=trusts,%s", ctx->base_dn);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    /* Create SDN from the base */
    base_dn = slapi_sdn_new_dn_byref(base);
    if (base_dn == NULL) {
        LOG_FATAL("Failed to convert base DN.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* Allocate a new parameter block */
    trusted_domain_search_pb = slapi_pblock_new();
    if (trusted_domain_search_pb == NULL) {
        LOG_FATAL("Failed to create new pblock.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* Search for all the root domains, note the LDAP_SCOPE_ONELEVEL */
    slapi_search_internal_set_pb(trusted_domain_search_pb,
                                 base,
                                 LDAP_SCOPE_SUBTREE, DOMAIN_ID_FILTER,
                                 NULL, 0, NULL, NULL, ctx->plugin_id, 0);

    ret = slapi_search_internal_pb(trusted_domain_search_pb);
    if (ret != 0) {
        LOG_FATAL("Starting internal search failed.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_pblock_get(trusted_domain_search_pb, SLAPI_PLUGIN_INTOP_RESULT, &search_result);
    if (ret != 0 || search_result != LDAP_SUCCESS) {

        /* If the search for the trusted domains fails,
         * AD Trust support on IPA server is not available */

        LOG("Empty forest root map as trusts are not enabled on this IPA server.\n");
        ret = 0;
        *head = NULL;

        goto done;
    }

    ret = slapi_pblock_get(trusted_domain_search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &trusted_domain_entries);

    if (ret != 0) {
        LOG_FATAL("Failed to read searched root domain entries.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (trusted_domain_entries == NULL || trusted_domain_entries[0] == NULL) {
        LOG("No existing root domain entries.\n");
        ret = 0;
        goto done;
    }

    /* now we iterate the domains and determine which of them are root domains */
    for (int i = 0; trusted_domain_entries[i] != NULL; i++) {

        ret = slapi_sdn_isparent(base_dn,
                                 slapi_entry_get_sdn(trusted_domain_entries[i]));

        /* trusted domain is root domain */
        if (ret == 1) {
            ret = map_domain_to_root(head,
                                     trusted_domain_entries[i],
                                     trusted_domain_entries[i]);
            if (ret != 0) {
                goto done;
            }
        }
        else {
            /* we need to search for the root domain */
            for (int j = 0; trusted_domain_entries[j] != NULL; j++) {
                ret = slapi_sdn_isparent(
                          slapi_entry_get_sdn(trusted_domain_entries[j]),
                          slapi_entry_get_sdn(trusted_domain_entries[i]));

                /* match, set the jth domain as the root domain for the ith */
                if (ret == 1) {
                    ret = map_domain_to_root(head,
                                             trusted_domain_entries[i],
                                             trusted_domain_entries[j]);
                    if (ret != 0) {
                        goto done;
                    }

                    break;
                }
            }
        }
    }

done:
    slapi_free_search_results_internal(trusted_domain_search_pb);
    slapi_pblock_destroy(trusted_domain_search_pb);
    free(base);

    return ret;

}

static int slapi_entry_to_range_info(struct domain_info *domain_info_head,
                                     struct slapi_entry *entry,
                                     struct range_info **_range)
{
    int ret;
    unsigned long ul_val;
    struct range_info *range = NULL;
    Slapi_Attr *attr;

    range = calloc(1, sizeof(struct range_info));
    if (range == NULL) {
        return ENOMEM;
    }

    range->name = slapi_entry_attr_get_charptr(entry, IPA_CN);
    range->domain_id = slapi_entry_attr_get_charptr(entry, IPA_DOMAIN_ID);
    range->id_range_type = slapi_entry_attr_get_charptr(entry, IPA_RANGE_TYPE);
    range->forest_root_id = get_forest_root_id(domain_info_head,
                                               range->domain_id);

    if (range->name == NULL || range->id_range_type == NULL) {
        ret = EINVAL;
        goto done;
    }

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

    /* slapi_entry_attr_find return 0 if requested attribute is present in entry */
    range->base_rid_set = (slapi_entry_attr_find(entry, IPA_BASE_RID, &attr) == 0);
    range->secondary_base_rid_set = (slapi_entry_attr_find(entry, IPA_SECONDARY_BASE_RID, &attr) == 0);

    *_range = range;
    ret = 0;

done:
    if (ret != 0) {
        free_range_info(range);
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
static range_check_result_t check_ranges(struct range_info *r1, struct range_info *r2)
{
    /* Do not check overlaps of range with the range itself */
    if (r1->name != NULL && r2->name != NULL &&
        strcasecmp(r1->name, r2->name) == 0) {
        return RANGE_CHECK_OK;
    }

    /* Check if base range overlaps with existing base range.
     * Exception: ipa-ad-trust-posix ranges from the same forest */
    if (!((strcasecmp(r1->id_range_type, AD_TRUST_POSIX_RANGE_TYPE) == 0) &&
          (strcasecmp(r2->id_range_type, AD_TRUST_POSIX_RANGE_TYPE) == 0) &&
          (r1->forest_root_id != NULL && r2->forest_root_id != NULL) &&
          (strcasecmp(r1->forest_root_id, r2->forest_root_id) == 0))) {

        if (intervals_overlap(r1->base_id, r2->base_id,
            r1->id_range_size, r2->id_range_size)){
            return RANGE_CHECK_BASE_OVERLAP;
        }

    }

    /* Following checks apply for the ranges from the same domain */
    bool ranges_from_same_domain =
         (r1->domain_id == NULL && r2->domain_id == NULL) ||
         (r1->domain_id != NULL && r2->domain_id != NULL &&
          strcasecmp(r1->domain_id, r2->domain_id) == 0);

    if (ranges_from_same_domain) {

        /* Ranges from the same domain must have the same type */
        if (strcasecmp(r1->id_range_type, r2->id_range_type) != 0) {
            return RANGE_CHECK_DIFFERENT_TYPE_IN_DOMAIN;
        }

        /* For ipa-local or ipa-ad-trust range types primary RID ranges should
         * not overlap */

        if (strcasecmp(r1->id_range_type, AD_TRUST_RANGE_TYPE) == 0 ||
            strcasecmp(r1->id_range_type, LOCAL_RANGE_TYPE) == 0) {

            /* Check if primary rid range overlaps with existing primary rid range */
            if ((r1->base_rid_set && r2->base_rid_set) &&
                intervals_overlap(r1->base_rid, r2->base_rid,
                                  r1->id_range_size, r2->id_range_size))
                return RANGE_CHECK_PRIMARY_PRIMARY_RID_OVERLAP;
        }

        /* The following 3 checks are relevant only if both ranges are local. */
        if (strcasecmp(r1->id_range_type, LOCAL_RANGE_TYPE) == 0){

            /* Check if secondary RID range overlaps with existing secondary or
             * primary RID range. */
            if ((r1->secondary_base_rid_set && r2->secondary_base_rid_set) &&
                intervals_overlap(r1->secondary_base_rid, r2->secondary_base_rid,
                                  r1->id_range_size, r2->id_range_size))
                return RANGE_CHECK_SECONDARY_SECONDARY_RID_OVERLAP;

            /* Check if RID range overlaps with existing secondary RID range */
            if ((r1->base_rid_set && r2->secondary_base_rid_set) &&
                intervals_overlap(r1->base_rid, r2->secondary_base_rid,
                                  r1->id_range_size, r2->id_range_size))
                return RANGE_CHECK_PRIMARY_SECONDARY_RID_OVERLAP;

            /* Check if secondary RID range overlaps with existing RID range */
            if ((r1->secondary_base_rid_set && r2->base_rid_set) &&
                intervals_overlap(r1->secondary_base_rid, r2->base_rid,
                                  r1->id_range_size, r2->id_range_size))
                return RANGE_CHECK_SECONDARY_PRIMARY_RID_OVERLAP;
            }
    }

    return RANGE_CHECK_OK;
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
    int ranges_valid = 0;
    const char *check_attr;
    char *errmsg = NULL;
    struct domain_info *domain_info_head = NULL;

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
                LOG("Missing entry to modify.\n");
                /* No range object, nothing to do. */
                ret = 0;
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

    /* build a linked list of domain_info structs */
    ret = build_domain_to_forest_root_map(&domain_info_head, ctx);
    if (ret != 0) {
        LOG_FATAL("Building of domain forest root domain map failed.\n");
        goto done;
    }

    ret = slapi_entry_to_range_info(domain_info_head, entry, &new_range);
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
        ret = slapi_entry_to_range_info(domain_info_head, search_entries[c],
                                        &old_range);
        if (ret != 0) {
            LOG_FATAL("Failed to convert LDAP entry to range struct.\n");
            goto done;
        }

        ranges_valid = check_ranges(new_range, old_range);
        free_range_info(old_range);
        old_range = NULL;
        if (ranges_valid != RANGE_CHECK_OK) {
            ret = LDAP_CONSTRAINT_VIOLATION;

            switch (ranges_valid){
            case RANGE_CHECK_BASE_OVERLAP:
                errmsg = "New base range overlaps with existing base range.";
                break;
            case RANGE_CHECK_PRIMARY_PRIMARY_RID_OVERLAP:
                errmsg = "New primary rid range overlaps with existing primary rid range.";
                break;
            case RANGE_CHECK_SECONDARY_SECONDARY_RID_OVERLAP:
                errmsg = "New secondary rid range overlaps with existing secondary rid range.";
                break;
            case RANGE_CHECK_PRIMARY_SECONDARY_RID_OVERLAP:
                errmsg = "New primary rid range overlaps with existing secondary rid range.";
                break;
            case RANGE_CHECK_SECONDARY_PRIMARY_RID_OVERLAP:
                errmsg = "New secondary rid range overlaps with existing primary rid range.";
                break;
            case RANGE_CHECK_DIFFERENT_TYPE_IN_DOMAIN:
                errmsg = "New ID range has invalid type. All ranges in the same domain must be of the same type.";
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
    free_range_info(old_range);
    free_range_info(new_range);
    if (free_entry) {
        slapi_entry_free(entry);
    }

    /* Remove the domain info linked list from memory */
    struct domain_info *next;
    while(domain_info_head) {
        next = domain_info_head->next;
        free_domain_info(domain_info_head);
        domain_info_head = next;
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
