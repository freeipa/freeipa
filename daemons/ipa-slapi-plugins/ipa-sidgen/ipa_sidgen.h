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

#pragma once

#define OBJECTCLASS "objectclass"
#define IPA_OBJECT "ipaobject"
#define MEP_MANAGED_ENTRY "mepmanagedentry"
#define UID_NUMBER "uidnumber"
#define GID_NUMBER "gidnumber"
#define IPA_SID "ipantsecurityidentifier"
#define DOM_ATTRS_FILTER OBJECTCLASS"=ipantdomainattrs"
#define DOMAIN_ID_RANGE_FILTER OBJECTCLASS"=ipadomainidrange"
#define POSIX_ACCOUNT "posixaccount"
#define POSIX_GROUP "posixgroup"
#define IPA_ID_OBJECT "ipaidobject"
#define IPANT_USER_ATTRS "ipantuserattrs"
#define IPANT_GROUP_ATTRS "ipantgroupattrs"

#define IPA_PLUGIN_NAME "ipa-sidgen-postop"
#define IPA_SIDGEN_FEATURE_DESC "IPA SIDGEN postop plugin"
#define IPA_SIDGEN_PLUGIN_DESC "Add a SID to newly added or modified " \
                               "objects with uid pr gid numbers"

#define IPA_BASE_ID "ipaBaseID"
#define IPA_ID_RANGE_SIZE "ipaIDRangeSize"
#define IPA_BASE_RID "ipaBaseRID"
#define IPA_SECONDARY_BASE_RID "ipaSecondaryBaseRID"

struct range_info {
    uint32_t base_id;
    uint32_t id_range_size;
    uint32_t base_rid;
    uint32_t secondary_base_rid;
};

struct ipa_sidgen_ctx {
    Slapi_ComponentId *plugin_id;
    const char *base_dn;
    char *dom_sid;
    struct range_info **ranges;
};

void set_plugin_id_for_sidgen_task(Slapi_ComponentId *plugin_id);

int sidgen_task_add(Slapi_PBlock *pb, Slapi_Entry *e,
                    Slapi_Entry *eAfter, int *returncode,
                    char *returntext, void *arg);

int get_dom_sid(Slapi_ComponentId *plugin_id, const char *base_dn, char **_sid);

int get_objectclass_flags(char **objectclasses,
                          bool *has_posix_account,
                          bool *has_posix_group,
                          bool *has_ipa_id_object);

void free_ranges(struct range_info ***_ranges);

int get_ranges(Slapi_ComponentId *plugin_id, const char *base_dn,
               struct range_info ***_ranges);

int find_sid_for_id(uint32_t id, Slapi_ComponentId *plugin_id,
                    const char *base_dn, const char *dom_sid,
                    struct range_info **ranges, char **_sid);

int find_sid_for_ldap_entry(struct slapi_entry *entry,
                            Slapi_ComponentId *plugin_id,
                            const char *base_dn,
                            const char *dom_sid,
                            struct range_info **ranges);
