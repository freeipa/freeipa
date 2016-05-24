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
 * Rich Megginson <rmeggins@redhat.com>
 *
 * Copyright (C) 2008 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#pragma once

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#ifdef WINSYNC_TEST_IPA
#include <slapi-plugin.h>
#include "winsync-plugin.h"
#else /* the default */
#include <dirsrv/slapi-plugin.h>
#include <dirsrv/winsync-plugin.h>
#endif /* WINSYNC_TEST_IPA */

#include <string.h>
#include <strings.h>

#include "util.h"

#define IPA_PLUGIN_NAME "ipa-winsync"

typedef struct ipa_winsync_config_struct {
    Slapi_Mutex *lock; /* for config access */
    Slapi_Entry *config_e; /* configuration entry */
    PRBool flatten; /* flatten AD DNs */
    char *realm_filter;
    char *realm_attr;
    char *new_entry_filter;
    char *new_user_oc_attr; /* don't care about groups for now */
    char *homedir_prefix_attr;
    char *login_shell_attr;
    char *default_group_attr;
    char *default_group_filter;
    int acct_disable; /* see below for possible values */
    char *inactivated_filter;
    char *activated_filter;
    PRBool forceSync;
} IPA_WinSync_Config;

/*
  This is the structure that holds our domain 
  specific configuration
*/
typedef struct ipa_winsync_domain_config {
    Slapi_Entry *domain_e; /* info is stored in this entry */
    char *realm_name; /* realm name */
    char *homedir_prefix;
    char *login_shell;
    char *inactivated_group_dn; /* DN of inactivated group */
    char *activated_group_dn; /* DN of activated group */
} IPA_WinSync_Domain_Config;

void ipa_winsync_set_plugin_identity(void * identity);
void * ipa_winsync_get_plugin_identity(void);

int ipa_winsync_config( Slapi_Entry *config_e );
IPA_WinSync_Config *ipa_winsync_get_config( void );

/*
 * Agreement/domain specific configuration
 */
/* return a new domain specific configuration object */
void *ipa_winsync_config_new_domain(const Slapi_DN *ds_subtree, const Slapi_DN *ad_subtree);
/* refresh the domain specific configuration object */
void ipa_winsync_config_refresh_domain(void *cbdata, const Slapi_DN *ds_subtree, const Slapi_DN *ad_subtree);
/* destroy the domain specific configuration object */
void ipa_winsync_config_destroy_domain(void *cbdata, const Slapi_DN *ds_subtree, const Slapi_DN *ad_subtree);

/* name of attribute holding the filter to use to
   find the ipa realm value
*/
#define IPA_WINSYNC_REALM_FILTER_ATTR "ipaWinSyncRealmFilter"
/* name of attribute holding the name of the attribute
   which contains the ipa realm value
*/
#define IPA_WINSYNC_REALM_ATTR_ATTR "ipaWinSyncRealmAttr"
/* name of attribute holding the filter to use to
   find the new user template entry
*/
#define IPA_WINSYNC_NEW_ENTRY_FILTER_ATTR "ipaWinSyncNewEntryFilter"
/* name of attribute holding the name of the attribute
   in the new user template entry which has the list of objectclasses
*/
#define IPA_WINSYNC_NEW_USER_OC_ATTR "ipaWinSyncNewUserOCAttr"
/* name of attribute holding the new user attributes and values */
#define IPA_WINSYNC_NEW_USER_ATTRS_VALS "ipaWinSyncUserAttr"
/* name of attribute holding the name of the attribute which
   has the homeDirectory prefix - suffix is the uid */
#define IPA_WINSYNC_HOMEDIR_PREFIX_ATTR "ipaWinSyncHomeDirAttr"
/* name of attribute holding the name of the attribute which
   has the loginShell value */
#define IPA_WINSYNC_LOGIN_SHELL_ATTR "ipaWinSyncLoginShellAttr"
/* name of attribute holding the name of the attribute which is
   used to get the default posix gidNumber */
#define IPA_WINSYNC_DEFAULTGROUP_ATTR "ipaWinSyncDefaultGroupAttr"
/* filter used to find the group with the gid number whose group name
   is in the IPA_WINSYNC_DEFAULTGROUP_ATTR - the filter will have
   cn=valueofIPA_WINSYNC_DEFAULTGROUP_ATTR appended to it */
#define IPA_WINSYNC_DEFAULTGROUP_FILTER_ATTR "ipaWinSyncDefaultGroupFilter"
/* name of attribute holding boolean value to flatten user dns or not */
#define IPA_WINSYNC_USER_FLATTEN "ipaWinSyncUserFlatten"
/* name of attribute holding account disable sync value */
#define IPA_WINSYNC_ACCT_DISABLE "ipaWinSyncAcctDisable"
/* possible values of IPA_WINSYNC_ACCT_DISABLE */
#define IPA_WINSYNC_ACCT_DISABLE_NONE "none"
#define IPA_WINSYNC_ACCT_DISABLE_TO_AD "to_ad"
#define IPA_WINSYNC_ACCT_DISABLE_TO_DS "to_ds"
#define IPA_WINSYNC_ACCT_DISABLE_BOTH "both"
/* enum representing the values above */
enum {
    ACCT_DISABLE_INVALID, /* the invalid value */
    ACCT_DISABLE_NONE, /* do not sync acct disable status */
    ACCT_DISABLE_TO_AD, /* sync only from ds to ad */
    ACCT_DISABLE_TO_DS, /* sync only from ad to ds */
    ACCT_DISABLE_BOTH /* bi-directional sync */
};
/* name of attributes holding the search filters to use to find
   the DN of the groups that represent inactivated and activated users */
#define IPA_WINSYNC_INACTIVATED_FILTER "ipaWinSyncInactivatedFilter"
#define IPA_WINSYNC_ACTIVATED_FILTER "ipaWinSyncActivatedFilter"
/* name of attribute holding the value of the forceSync parameter -
   this is a boolean attribute - if true, all users in AD that have
   a corresponding entry in the DS will be synced - there will be no
   way to "turn off sync" on individual entries - if this value is
   false, only users which have the ntUser objectclass and an
   ntDomainUserID attribute which corresponds to an AD account
   with the same value for samAccountName will be synced
*/
#define IPA_WINSYNC_FORCE_SYNC "ipaWinSyncForceSync"

/* Path to UPG configuration */
#define IPA_WINSYNC_UPG_DEF_DN "cn=UPG Definition,cn=Definitions,cn=Managed Entries,cn=etc,%s"
#define IPA_WINSYNC_UPG_DEF_ATTR "originfilter"
#define IPA_WINSYNC_UPG_DEF_DISABLED "(objectclass=disable)"
