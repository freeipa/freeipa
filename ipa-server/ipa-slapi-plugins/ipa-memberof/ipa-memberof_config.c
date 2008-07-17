/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 * 
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
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
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception. 
 * 
 * 
 * Copyright (C) 2008 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

/*
 * memberof_config.c - configuration-related code for memberOf plug-in
 *
 */

#include <plstr.h>

#include "ipa-memberof.h"

#define MEMBEROF_CONFIG_FILTER "(objectclass=*)"

/*
 * The configuration attributes are contained in the plugin entry e.g.
 * cn=MemberOf Plugin,cn=plugins,cn=config
 *
 * Configuration is a two step process.  The first pass is a validation step which
 * occurs pre-op - check inputs and error out if bad.  The second pass actually
 * applies the changes to the run time config.
 */


/*
 * function prototypes
 */ 
static int memberof_apply_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
										 int *returncode, char *returntext, void *arg);
static int memberof_search (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
								int *returncode, char *returntext, void *arg)
{
	return SLAPI_DSE_CALLBACK_OK;
}

/*
 * static variables
 */
/* This is the main configuration which is updated from dse.ldif.  The
 * config will be copied when it is used by the plug-in to prevent it
 * being changed out from under a running memberOf operation. */
static MemberOfConfig theConfig;
static PRRWLock *memberof_config_lock = 0;
static int inited = 0;


static int dont_allow_that(Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
						   int *returncode, char *returntext, void *arg)
{
	*returncode = LDAP_UNWILLING_TO_PERFORM;
	return SLAPI_DSE_CALLBACK_ERROR;
}

/*
 * memberof_config()
 *
 * Read configuration and create a configuration data structure.
 * This is called after the server has configured itself so we can
 * perform checks with regards to suffixes if it ever becomes
 * necessary.
 * Returns an LDAP error code (LDAP_SUCCESS if all goes well).
 */
int
memberof_config(Slapi_Entry *config_e)
{
	int returncode = LDAP_SUCCESS;
	char returntext[SLAPI_DSE_RETURNTEXT_SIZE];

	if ( inited ) {
		slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
				 "only one memberOf plugin instance can be used\n" );
		return( LDAP_PARAM_ERROR );
	}

	/* initialize the RW lock to protect the main config */
	memberof_config_lock = PR_NewRWLock(PR_RWLOCK_RANK_NONE, "memberof_config_lock");

	/* initialize fields */
	memberof_apply_config(NULL, NULL, config_e,
				&returncode, returntext, NULL);

	/* config DSE must be initialized before we get here */
	if (returncode == LDAP_SUCCESS) {
		const char *config_dn = slapi_entry_get_dn_const(config_e);
		slapi_config_register_callback(SLAPI_OPERATION_MODIFY, DSE_FLAG_PREOP,
			config_dn, LDAP_SCOPE_BASE, MEMBEROF_CONFIG_FILTER,
			dont_allow_that,NULL);
		slapi_config_register_callback(SLAPI_OPERATION_MODRDN, DSE_FLAG_PREOP,
			config_dn, LDAP_SCOPE_BASE, MEMBEROF_CONFIG_FILTER,
			dont_allow_that, NULL);
		slapi_config_register_callback(SLAPI_OPERATION_DELETE, DSE_FLAG_PREOP,
			config_dn, LDAP_SCOPE_BASE, MEMBEROF_CONFIG_FILTER,
			dont_allow_that, NULL);
		slapi_config_register_callback(SLAPI_OPERATION_SEARCH, DSE_FLAG_PREOP,
			config_dn, LDAP_SCOPE_BASE, MEMBEROF_CONFIG_FILTER,
			memberof_search,NULL);
	}

	inited = 1;

	if (returncode != LDAP_SUCCESS) {
		slapi_log_error(SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
				"Error %d: %s\n", returncode, returntext);
        }

	return returncode;
}


/*
 * memberof_apply_config()
 *
 * Just use hardcoded config values.
 */
static int 
memberof_apply_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
	int *returncode, char *returntext, void *arg)
{
	char *groupattr = NULL;
	char *memberof_attr = NULL;
	char *filter_str = NULL;

	*returncode = LDAP_SUCCESS;

	groupattr = slapi_ch_strdup(MEMBEROF_GROUP_ATTR);
        memberof_attr = slapi_ch_strdup(MEMBEROF_ATTR);

	/* We want to be sure we don't change the config in the middle of
	 * a memberOf operation, so we obtain an exclusive lock here */
	memberof_wlock_config();

	if (!theConfig.groupattr ||
		(groupattr && PL_strcmp(theConfig.groupattr, groupattr))) {
		slapi_ch_free_string(&theConfig.groupattr);
		theConfig.groupattr = groupattr;
		groupattr = NULL; /* config now owns memory */

		/* We allocate a Slapi_Attr using the groupattr for
		 * convenience in our memberOf comparison functions */
		slapi_attr_free(&theConfig.group_slapiattr);
		theConfig.group_slapiattr = slapi_attr_new();
                slapi_attr_init(theConfig.group_slapiattr, theConfig.groupattr);

		/* The filter is based off of the groupattr, so we
		 * update it here too. */
		slapi_filter_free(theConfig.group_filter, 1);
		filter_str = slapi_ch_smprintf("(%s=*)", theConfig.groupattr);
		theConfig.group_filter = slapi_str2filter(filter_str);
		slapi_ch_free_string(&filter_str);
	}

	if (!theConfig.memberof_attr ||
		(memberof_attr && PL_strcmp(theConfig.memberof_attr, memberof_attr))) {
		slapi_ch_free_string(&theConfig.memberof_attr);
		theConfig.memberof_attr = memberof_attr;
		memberof_attr = NULL; /* config now owns memory */
	}

	/* release the lock */
	memberof_unlock_config();

	slapi_ch_free_string(&groupattr);
	slapi_ch_free_string(&memberof_attr);

	if (*returncode != LDAP_SUCCESS)
	{
		return SLAPI_DSE_CALLBACK_ERROR;
	}
	else
	{
		return SLAPI_DSE_CALLBACK_OK;
	}
}

/*
 * memberof_copy_config()
 *
 * Makes a copy of the config in src.  This function will free the
 * elements of dest if they already exist.  This should only be called
 * if you hold the memberof config lock if src was obtained with
 * memberof_get_config().
 */
void
memberof_copy_config(MemberOfConfig *dest, MemberOfConfig *src)
{
	if (dest && src)
	{
		/* Check if the copy is already up to date */
		if (!dest->groupattr || (src->groupattr
			&& PL_strcmp(dest->groupattr, src->groupattr)))
		{
			slapi_ch_free_string(&dest->groupattr);
			dest->groupattr = slapi_ch_strdup(src->groupattr);
			slapi_filter_free(dest->group_filter, 1);
			dest->group_filter = slapi_filter_dup(src->group_filter);
			slapi_attr_free(&dest->group_slapiattr);
			dest->group_slapiattr = slapi_attr_dup(src->group_slapiattr);
		}

		if (!dest->memberof_attr || (src->memberof_attr
			&& PL_strcmp(dest->memberof_attr, src->memberof_attr)))
		{
			slapi_ch_free_string(&dest->memberof_attr);
			dest->memberof_attr = slapi_ch_strdup(src->memberof_attr);
		}
	}
}

/*
 * memberof_free_config()
 *
 * Free's the contents of a config structure.
 */
void
memberof_free_config(MemberOfConfig *config)
{
	if (config)
	{
		slapi_ch_free_string(&config->groupattr);
		slapi_filter_free(config->group_filter, 1);
		slapi_attr_free(&config->group_slapiattr);
		slapi_ch_free_string(&config->memberof_attr);
	}
}

/*
 * memberof_get_config()
 *
 * Returns a pointer to the main config.  You should call
 * memberof_rlock_config() first so the main config doesn't
 * get modified out from under you.
 */
MemberOfConfig *
memberof_get_config()
{
	return &theConfig;
}

/*
 * memberof_rlock_config()
 *
 * Gets a non-exclusive lock on the main config.  This will
 * prevent the config from being changed out from under you
 * while you read it, but it will still allow other threads
 * to read the config at the same time.
 */
void
memberof_rlock_config()
{
	PR_RWLock_Rlock(memberof_config_lock);
}

/*
 * memberof_wlock_config()
 * 
 * Gets an exclusive lock on the main config.  This should
 * be called if you need to write to the main config.
 */
void
memberof_wlock_config()
{
	PR_RWLock_Wlock(memberof_config_lock);
}

/*
 * memberof_unlock_config()
 *
 * Unlocks the main config.
 */
void
memberof_unlock_config()
{
	PR_RWLock_Unlock(memberof_config_lock);
}
