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

int get_dom_sid(Slapi_ComponentId *plugin_id, const char *base_dn, char **_sid)
{
    Slapi_PBlock *search_pb = NULL;
    int search_result;
    Slapi_Entry **search_entries = NULL;
    int ret;
    const char *sid;

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        LOG_FATAL("Failed to create new pblock.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    slapi_search_internal_set_pb(search_pb, base_dn,
                                 LDAP_SCOPE_SUBTREE, DOM_ATTRS_FILTER,
                                 NULL, 0, NULL, NULL, plugin_id, 0);

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
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    if (search_entries[1] != NULL) {
        LOG("Too many results found.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    sid = slapi_entry_attr_get_charptr(search_entries[0], IPA_SID);
    if (sid == NULL) {
        LOG("Domain object does not have a SID.\n");
        ret = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }

    *_sid = slapi_ch_strdup(sid);
    if (*_sid == NULL) {
        LOG("slapi_ch_strdup failed.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    LOG("Found domain SID [%s].\n", *_sid);
    ret = 0;

done:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);

    return ret;
}

static int slapi_entry_to_range_info(struct slapi_entry *entry,
                                     struct range_info **_range)
{
    int ret;
    unsigned long ul_val;
    struct range_info *range = NULL;

    range = ( struct range_info *) slapi_ch_calloc(1, sizeof(struct range_info));
    if (range == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_BASE_ID);
    if (ul_val == 0 || ul_val >= UINT32_MAX) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    range->base_id = ul_val;

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_ID_RANGE_SIZE);
    if (ul_val == 0 || ul_val >= UINT32_MAX) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    range->id_range_size = ul_val;

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_BASE_RID);
    if (ul_val == 0 || ul_val >= UINT32_MAX) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    range->base_rid = ul_val;

    ul_val = slapi_entry_attr_get_ulong(entry, IPA_SECONDARY_BASE_RID);
    if (ul_val == 0 || ul_val >= UINT32_MAX) {
        ret = ERANGE;
        goto done;
    }
    range->secondary_base_rid = ul_val;

    *_range = range;
    ret = 0;

done:
    if (ret != 0) {
        slapi_ch_free((void **) &range);
    }

    return ret;
}

int get_objectclass_flags(char **objectclasses,
                          bool *has_posix_account,
                          bool *has_posix_group,
                          bool *has_ipa_id_object)
{
    size_t c;

    if (objectclasses == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    *has_posix_account = false;
    *has_posix_group = false;
    *has_ipa_id_object = false;

    for (c = 0; objectclasses[c] != NULL; c++) {
        if (strcasecmp(objectclasses[c], POSIX_ACCOUNT) == 0) {
            *has_posix_account = true;
        } else if (strcasecmp(objectclasses[c], POSIX_GROUP) == 0) {
            *has_posix_group = true;
        } else if (strcasecmp(objectclasses[c], IPA_ID_OBJECT) == 0) {
            *has_ipa_id_object = true;
        }
    }

    return 0;
}

void free_ranges(struct range_info ***_ranges)
{
    size_t c;
    struct range_info **ranges = *_ranges;

    if (ranges != NULL) {
        for (c = 0; ranges[c] != NULL; c++) {
            slapi_ch_free((void **) &ranges[c]);
        }

        slapi_ch_free((void **) _ranges);
    }
}

int get_ranges(Slapi_ComponentId *plugin_id, const char *base_dn,
               struct range_info ***_ranges)
{
    Slapi_PBlock *search_pb = NULL;
    Slapi_Entry **search_entries = NULL;
    int search_result;
    size_t c;
    int ret;
    struct range_info **ranges = NULL;

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        LOG_FATAL("Failed to create new pblock.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    slapi_search_internal_set_pb(search_pb, base_dn,
                                 LDAP_SCOPE_SUBTREE, DOMAIN_ID_RANGE_FILTER,
                                 NULL, 0, NULL, NULL, plugin_id, 0);

    ret = slapi_search_internal_pb(search_pb);
    if (ret != 0) {
        LOG_FATAL("Starting internal search failed.\n");
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &search_result);
    if (ret != 0 || search_result != LDAP_SUCCESS) {
        LOG_FATAL("Internal search failed.\n");
        ret = (search_result != LDAP_SUCCESS) ? search_result:
                                                LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &search_entries);
    if (ret != 0) {
        LOG_FATAL("Failed to read searched entries.\n");
        goto done;
    }

    if (search_entries == NULL || search_entries[0] == NULL) {
        LOG("No ranges found.\n");
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    for (c = 0; search_entries[c] != NULL; c++);
    ranges = (struct range_info **) slapi_ch_calloc(c + 1,
                                                    sizeof(struct range_info *));
    if (ranges == NULL) {
        LOG("calloc failed.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    for (c = 0; search_entries[c] != NULL; c++) {
        ret = slapi_entry_to_range_info(search_entries[c], &ranges[c]);
        if (ret != 0) {
            LOG_FATAL("Failed to convert LDAP entry to range struct.\n");
            goto done;
        }
    }

    *_ranges = ranges;
    ret = 0;

done:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    if (ret != 0) {
        free_ranges(&ranges);
    }

    return ret;
}

static int find_sid(const char *sid, Slapi_ComponentId *plugin_id,
                    const char *base_dn)
{
    Slapi_PBlock *search_pb = NULL;
    Slapi_Entry **search_entries = NULL;
    int search_result;
    int ret;
    char *filter = NULL;

    search_pb = slapi_pblock_new();
    if (search_pb == NULL) {
        LOG_FATAL("Failed to create new pblock.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    filter = slapi_ch_smprintf("%s=%s", IPA_SID, sid);
    if (filter == NULL) {
        LOG_FATAL("Cannot create search filter to check if SID is used.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    slapi_search_internal_set_pb(search_pb, base_dn,
                                 LDAP_SCOPE_SUBTREE, filter,
                                 NULL, 0, NULL, NULL, plugin_id, 0);

    ret = slapi_search_internal_pb(search_pb);
    if (ret != 0) {
        LOG_FATAL("Starting internal search failed.\n");
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &search_result);
    if (ret != 0 || search_result != LDAP_SUCCESS) {
        LOG_FATAL("Internal search failed.\n");
        ret = (search_result != LDAP_SUCCESS) ? search_result:
                                                LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                           &search_entries);
    if (ret != 0) {
        LOG_FATAL("Failed to read searched entries.\n");
        goto done;
    }

    if (search_entries == NULL || search_entries[0] == NULL) {
        LOG("No SID found.\n");
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    ret = 0;

done:
    slapi_ch_free_string(&filter);
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);

    return ret;
}

static int rid_to_sid_with_check(uint32_t rid, Slapi_ComponentId *plugin_id,
                                 const char *base_dn, const char *dom_sid,
                                 char **_sid)
{
    char *sid = NULL;
    int ret;

    sid = slapi_ch_smprintf("%s-%lu", dom_sid, (unsigned long) rid);
    if (sid == NULL) {
        LOG("Failed to create SID string.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    LOG("SID is [%s].\n", sid);

    ret = find_sid(sid, plugin_id, base_dn);
    if (ret == LDAP_NO_SUCH_OBJECT) {
        *_sid = sid;
        ret = 0;
        goto done;
    } else if (ret != 0) {
        LOG_FATAL("Cannot check if SID is already used.\n");
        goto done;
    }

    LOG_FATAL("SID [%s] is already used.\n", sid);
    ret = LDAP_CONSTRAINT_VIOLATION;

done:
    if (ret != 0) {
        slapi_ch_free_string(&sid);
    }

    return ret;
}

int find_sid_for_id(uint32_t id, Slapi_ComponentId *plugin_id,
                    const char *base_dn, const char *dom_sid,
                    struct range_info **ranges, char **_sid)
{
    uint32_t rid;
    size_t c;
    char *sid = NULL;
    int ret;

    rid = 0;
    for (c = 0; ranges[c] != NULL; c++) {
        if (id >= ranges[c]->base_id &&
            id < (ranges[c]->base_id + ranges[c]->id_range_size)) {
            rid = ranges[c]->base_rid + (id - ranges[c]->base_id);
            break;
        }
    }

    if (rid == 0) {
        LOG("No matching range found. Cannot add SID.\n");
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    ret = rid_to_sid_with_check(rid, plugin_id, base_dn, dom_sid, &sid);
    if (ret != LDAP_CONSTRAINT_VIOLATION) {
        goto done;
    }

    /* SID is already used, try secondary range.*/
    rid = ranges[c]->secondary_base_rid + (id - ranges[c]->base_id);

    ret = rid_to_sid_with_check(rid, plugin_id, base_dn, dom_sid, &sid);
    if (ret != LDAP_CONSTRAINT_VIOLATION) {
        goto done;
    }

    LOG_FATAL("Secondary SID is used as well.\n");

done:
    if (ret != 0) {
        slapi_ch_free_string(&sid);
    } else {
        *_sid = sid;
    }

    return ret;
}

int find_sid_for_ldap_entry(struct slapi_entry *entry,
                            Slapi_ComponentId *plugin_id,
                            const char *base_dn,
                            const char *dom_sid,
                            struct range_info **ranges)
{
    int ret;
    const char *dn_str;
    uint32_t uid_number;
    uint32_t gid_number;
    uint32_t id;
    char *sid = NULL;
    char **objectclasses = NULL;
    Slapi_PBlock *mod_pb = NULL;
    Slapi_Mods *smods = NULL;
    int result;
    bool has_posix_account = false;
    bool has_posix_group = false;
    bool has_ipa_id_object = false;
    const char *objectclass_to_add = NULL;

    dn_str = slapi_entry_get_dn_const(entry);
    if (dn_str == NULL) {
        LOG_FATAL("Cannot find DN of an LDAP entry.\n");
        ret = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }
    LOG("Trying to add SID for [%s].\n", dn_str);

    uid_number = slapi_entry_attr_get_ulong(entry, UID_NUMBER);
    gid_number = slapi_entry_attr_get_ulong(entry, GID_NUMBER);

    if (uid_number == 0 && gid_number == 0) {
        LOG("[%s] does not have Posix IDs, nothing to do.\n", dn_str);
        ret = 0;
        goto done;
    }

    if (uid_number >= UINT32_MAX || gid_number >= UINT32_MAX) {
        LOG_FATAL("ID value too large.\n");
        ret = LDAP_CONSTRAINT_VIOLATION;
        goto done;
    }

    sid = slapi_entry_attr_get_charptr(entry, IPA_SID);
    if (sid != NULL) {
        LOG("Object already has a SID, nothing to do.\n");
        ret = 0;
        goto done;
    }

    objectclasses = slapi_entry_attr_get_charray(entry, OBJECTCLASS);
    ret = get_objectclass_flags(objectclasses, &has_posix_account,
                                               &has_posix_group,
                                               &has_ipa_id_object);
    if (ret != 0) {
        LOG_FATAL("Cannot determine objectclasses.\n");
        goto done;
    }

    if (has_posix_account && uid_number != 0 && gid_number != 0) {
        id = uid_number;
        objectclass_to_add = IPANT_USER_ATTRS;
    } else if (has_posix_group && gid_number != 0) {
        id = gid_number;
        objectclass_to_add = IPANT_GROUP_ATTRS;
    } else if (has_ipa_id_object) {
        id = (uid_number != 0) ? uid_number : gid_number;
        objectclass_to_add = NULL;
    } else {
        LOG_FATAL("Inconsistent objectclasses and attributes, nothing to do.\n");
        ret = 0;
        goto done;
    }

    ret = find_sid_for_id(id, plugin_id, base_dn, dom_sid, ranges, &sid);
    if (ret != 0) {
        LOG_FATAL("Cannot convert Posix ID [%ul] into an unused SID.\n", id);
        goto done;
    }

    smods = slapi_mods_new();
    if (smods == NULL) {
        LOG("slapi_mods_new failed.\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (objectclass_to_add != NULL) {
        slapi_mods_add_string(smods, LDAP_MOD_ADD,
                              OBJECTCLASS, objectclass_to_add);
    }
    slapi_mods_add_string(smods, LDAP_MOD_REPLACE, IPA_SID, sid);

    mod_pb = slapi_pblock_new();
    slapi_modify_internal_set_pb(mod_pb, dn_str,
                                 slapi_mods_get_ldapmods_byref(smods),
                                 NULL, NULL, plugin_id, 0);

    ret = slapi_modify_internal_pb(mod_pb);
    if (ret != 0) {
        LOG_FATAL("Modify failed with [%d] on entry [%s]\n", ret, dn_str);
        goto done;
    }

    ret = slapi_pblock_get(mod_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);
    if (ret != 0 || result != LDAP_SUCCESS){
        LOG_FATAL("Modify failed on entry [%s]\n", dn_str);
        goto done;
    }

done:
    slapi_ch_free_string(&sid);
    slapi_pblock_destroy(mod_pb);
    slapi_mods_free(&smods);
    slapi_ch_array_free(objectclasses);

    return ret;
}
