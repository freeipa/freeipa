/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details
 *
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code
 * used in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish
 * to provide this exception without modification, you must delete this
 * exception statement from your version and license this file solely under the
 * GPL without exception.
 *
 * Authors:
 * Rich Megginson <rmeggins@redhat.com>
 *
 * Copyright (C) 2008 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifndef IPA_WINSYNC_H
#define IPA_WINSYNC_H

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

#define IPA_WINSYNC_PLUGIN_NAME "ipa-winsync"

typedef struct ipa_winsync_config_struct {
    Slapi_Mutex *lock; /* for config access */
    Slapi_Entry *config_e; /* configuration entry */
    PRBool flatten; /* flatten AD DNs */
    char *realm_filter;
    char *realm_attr;
    char *new_entry_filter;
    char *new_user_oc_attr; /* don't care about groups for now */
    char *homedir_prefix_attr;
    char *default_group_attr;
    char *default_group_filter;
} IPA_WinSync_Config;

/*
  This is the structure that holds our domain 
  specific configuration
*/
typedef struct ipa_winsync_domain_config {
    Slapi_Entry *domain_e; /* info is stored in this entry */
    char *realm_name; /* realm name */
    char *homedir_prefix;
} IPA_WinSync_Domain_Config;

void ipa_winsync_set_plugin_identity(void * identity);
void * ipa_winsync_get_plugin_identity();

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
#define IPA_WINSYNC_HOMEDIR_PREFIX_ATTR "ipaWinsyncHomeDirAttr"
/* name of attribute holding the name of the attribute which is
   used to get the default posix gidNumber */
#define IPA_WINSYNC_DEFAULTGROUP_ATTR "ipaWinSyncDefaultGroupAttr"
/* filter used to find the group with the gid number whose group name
   is in the IPA_WINSYNC_DEFAULTGROUP_ATTR - the filter will have
   cn=valueofIPA_WINSYNC_DEFAULTGROUP_ATTR appended to it */
#define IPA_WINSYNC_DEFAULTGROUP_FILTER_ATTR "ipaWinSyncDefaultGroupFilter"
/* name of attribute holding boolean value to flatten user dns or not */
#define IPA_WINSYNC_USER_FLATTEN "ipaWinSyncUserFlatten"

#endif /* IPA_WINSYNC_H */
