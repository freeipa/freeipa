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
 * Authors: 
 * Pete Rowley <prowley@redhat.com>
 *
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK
 **/

/* The memberof plugin updates the memberof attribute of entries
 * based on modifications performed on groupofuniquenames entries
 *
 * In addition the plugin provides a DS task that may be started
 * administrative clients and that creates the initial memberof
 * list for imported entries and/or fixes the memberof list of
 * existing entries that have inconsistent state (for example,
 * if the memberof attribute was incorrectly edited directly) 
 *
 * To start the memberof task add an entry like:
 *
 * dn: cn=mytask, cn=memberof task, cn=tasks, cn=config
 * objectClass: top
 * objectClass: extensibleObject
 * cn: mytask
 * basedn: dc=example, dc=com
 * filter: (uid=test4)
 *
 * where "basedn" is required and refers to the top most node to perform the
 * task on, and where "filter" is an optional attribute that provides a filter
 * describing the entries to be worked on
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <dirsrv/slapi-plugin.h>

#include "string.h"
#include "nspr.h"

#include "ipa-memberof.h"

static Slapi_PluginDesc pdesc = { "ipamo", "FreeIPA project", "FreeIPA/1.0",
        "IPA memberof plugin" };

static void* _PluginID = NULL;
static Slapi_Mutex *memberof_operation_lock = 0;
MemberOfConfig *qsortConfig = 0;

typedef struct _memberofstringll
{
	const char *dn;
	void *next;
} memberofstringll;

typedef struct _memberof_get_groups_data
{
        MemberOfConfig *config;
        Slapi_Value *memberdn_val;
        Slapi_ValueSet **groupvals;
} memberof_get_groups_data;

/****** secrets *********/
#ifndef SLAPI_TASK_PUBLIC
/*from FDS slap.h
 * until we get a proper api for access
 */
#define TASK_RUNNING_AS_TASK             0x0

/******************************************************************************
 * Online tasks interface (to support import, export, etc)
 * After some cleanup, we could consider making these public.
 */
struct _slapi_task {
    struct _slapi_task *next;
    char *task_dn;
    int task_exitcode;          /* for the end user */
    int task_state;             /* (see above) */
    int task_progress;          /* number between 0 and task_work */
    int task_work;              /* "units" of work to be done */
    int task_flags;             /* (see above) */

    /* it is the task's responsibility to allocate this memory & free it: */
    char *task_status;          /* transient status info */
    char *task_log;             /* appended warnings, etc */

    void *task_private;         /* for use by backends */
    TaskCallbackFn cancel;      /* task has been cancelled by user */
    TaskCallbackFn destructor;  /* task entry is being destroyed */
        int task_refcount;
};

static void slapi_task_set_data(Slapi_Task *task, void *data)
{
    if (task) {
        task->task_private = data;
    }
}

/*
 * Retrieve some opaque task specific data from the task.
 */
static void * slapi_task_get_data(Slapi_Task *task)
{
    if (task) {
        return task->task_private;
    }
}

static void slapi_task_begin(Slapi_Task *task, int total_work)
{
    if (task) {
        task->task_work = total_work;
        task->task_progress = 0;
        task->task_state = SLAPI_TASK_RUNNING;
        slapi_task_status_changed(task);
    }
}

static void slapi_task_inc_progress(Slapi_Task *task)
{
    if (task) {
        task->task_progress++;
        slapi_task_status_changed(task);
    }
}

static void slapi_task_finish(Slapi_Task *task, int rc)
{
    if (task) {
        task->task_exitcode = rc;
        task->task_state = SLAPI_TASK_FINISHED;
        slapi_task_status_changed(task);
    }
}

static void slapi_task_set_destructor_fn(Slapi_Task *task, TaskCallbackFn func)
{
    if (task) {
        task->destructor = func;
    }
}

#endif /* !SLAPI_TASK_PUBLIC */
/****** secrets ********/

/*** function prototypes ***/

/* exported functions */
int ipamo_postop_init(Slapi_PBlock *pb );

/* plugin callbacks */ 
static int memberof_postop_del(Slapi_PBlock *pb ); 
static int memberof_postop_modrdn(Slapi_PBlock *pb );
static int memberof_postop_modify(Slapi_PBlock *pb );
static int memberof_postop_add(Slapi_PBlock *pb ); 
static int memberof_postop_start(Slapi_PBlock *pb);
static int memberof_postop_close(Slapi_PBlock *pb);

/* supporting cast */
static int memberof_oktodo(Slapi_PBlock *pb);
static char *memberof_getdn(Slapi_PBlock *pb);
static int memberof_modop_one(Slapi_PBlock *pb, MemberOfConfig *config, int mod_op,
	char *op_this, char *op_to);
static int memberof_modop_one_r(Slapi_PBlock *pb, MemberOfConfig *config, int mod_op,
	char *group_dn, char *op_this, char *op_to, memberofstringll *stack);
static int memberof_add_one(Slapi_PBlock *pb, MemberOfConfig *config, char *addthis,
	char *addto);
static int memberof_del_one(Slapi_PBlock *pb, MemberOfConfig *config, char *delthis,
	char *delfrom);
static int memberof_mod_smod_list(Slapi_PBlock *pb, MemberOfConfig *config, int mod,
	char *groupdn, Slapi_Mod *smod);
static int memberof_add_smod_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *groupdn, Slapi_Mod *smod);
static int memberof_del_smod_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *groupdn, Slapi_Mod *smod);
static int memberof_mod_attr_list(Slapi_PBlock *pb, MemberOfConfig *config, int mod,
	char *groupdn, Slapi_Attr *attr);
static int memberof_mod_attr_list_r(Slapi_PBlock *pb, MemberOfConfig *config,
	int mod, char *group_dn, char *op_this, Slapi_Attr *attr, memberofstringll *stack);
static int memberof_add_attr_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *groupdn, Slapi_Attr *attr);
static int memberof_del_attr_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *groupdn, Slapi_Attr *attr);
static int memberof_moddn_attr_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *pre_dn, char *post_dn, Slapi_Attr *attr);
static int memberof_replace_list(Slapi_PBlock *pb, MemberOfConfig *config, char *group_dn);
static void memberof_set_plugin_id(void * plugin_id);
static void *memberof_get_plugin_id();
static int memberof_compare(MemberOfConfig *config, const void *a, const void *b);
static int memberof_qsort_compare(const void *a, const void *b);
static void memberof_load_array(Slapi_Value **array, Slapi_Attr *attr);
static int memberof_del_dn_from_groups(Slapi_PBlock *pb, MemberOfConfig *config, char *dn);
static int memberof_call_foreach_dn(Slapi_PBlock *pb, char *dn,
	char *type, plugin_search_entry_callback callback,  void *callback_data);
static int memberof_is_direct_member(MemberOfConfig *config, Slapi_Value *groupdn,
	Slapi_Value *memberdn);
static Slapi_ValueSet *memberof_get_groups(MemberOfConfig *config, char *memberdn);
static int memberof_get_groups_r(MemberOfConfig *config, char *memberdn,
	memberof_get_groups_data *data);
static int memberof_get_groups_callback(Slapi_Entry *e, void *callback_data);
static int memberof_test_membership(Slapi_PBlock *pb, MemberOfConfig *config,
	char *group_dn);
static int memberof_test_membership_callback(Slapi_Entry *e, void *callback_data);
static int memberof_del_dn_type_callback(Slapi_Entry *e, void *callback_data);
static int memberof_replace_dn_type_callback(Slapi_Entry *e, void *callback_data);
static int memberof_replace_dn_from_groups(Slapi_PBlock *pb, MemberOfConfig *config,
	char *pre_dn, char *post_dn);
static int memberof_modop_one_replace_r(Slapi_PBlock *pb, MemberOfConfig *config,
	int mod_op, char *group_dn, char *op_this, char *replace_with, char *op_to,
	memberofstringll *stack);
static int memberof_task_add(Slapi_PBlock *pb, Slapi_Entry *e,
                    Slapi_Entry *eAfter, int *returncode, char *returntext,
                    void *arg);
static void memberof_task_destructor(Slapi_Task *task);
static const char *fetch_attr(Slapi_Entry *e, const char *attrname,
                                              const char *default_val);
static void memberof_fixup_task_thread(void *arg);
static int memberof_fix_memberof(MemberOfConfig *config, char *dn, char *filter_str);
static int memberof_fix_memberof_callback(Slapi_Entry *e, void *callback_data);


/*** implementation ***/


/*** exported functions ***/

/*
 * ipamo_postop_init()
 *
 * Register plugin call backs
 *
 */
int
ipamo_postop_init(Slapi_PBlock *pb)
{
	int ret = 0;
	char *memberof_plugin_identity = 0;

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		"--> ipamo_postop_init\n" );
	/*
	 * Get plugin identity and stored it for later use
	 * Used for internal operations
	 */

	slapi_pblock_get (pb, SLAPI_PLUGIN_IDENTITY, &memberof_plugin_identity);
	PR_ASSERT (memberof_plugin_identity);
	memberof_set_plugin_id(memberof_plugin_identity);

	if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION,
				SLAPI_PLUGIN_VERSION_01 ) != 0 ||
		slapi_pblock_set( pb, SLAPI_PLUGIN_DESCRIPTION,
	                     (void *)&pdesc ) != 0 ||
		slapi_pblock_set( pb, SLAPI_PLUGIN_POST_DELETE_FN,
			(void *) memberof_postop_del ) != 0 ||
		slapi_pblock_set( pb, SLAPI_PLUGIN_POST_MODRDN_FN,
			(void *) memberof_postop_modrdn ) != 0 ||
		slapi_pblock_set( pb, SLAPI_PLUGIN_POST_MODIFY_FN,
			(void *) memberof_postop_modify ) != 0 ||
		slapi_pblock_set( pb, SLAPI_PLUGIN_POST_ADD_FN,
			(void *) memberof_postop_add ) != 0 ||
		slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
			(void *) memberof_postop_start ) != 0 ||
		slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
			(void *) memberof_postop_close ) != 0)
	{
		slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
			"ipamo_postop_init failed\n" );
		ret = -1;
	}

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		"<-- ipamo_postop_init\n" );
	return ret;
}

/*
 * memberof_postop_start()
 *
 * Do plugin start up stuff
 *
 */
int memberof_postop_start(Slapi_PBlock *pb)
{
	int rc = 0;
	Slapi_Entry *config_e = NULL; /* entry containing plugin config */

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		"--> memberof_postop_start\n" );

	memberof_operation_lock = slapi_new_mutex();
	if(0 == memberof_operation_lock)
	{
		rc = -1;
		goto bail;
	}

	if ( slapi_pblock_get( pb, SLAPI_ADD_ENTRY, &config_e ) != 0 ) {
		slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
				"missing config entry\n" );
		rc = -1;
		goto bail;
	}

	if (( rc = memberof_config( config_e )) != LDAP_SUCCESS ) {
		slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
				"configuration failed (%s)\n", ldap_err2string( rc ));
		return( -1 );
	}

	rc = slapi_task_register_handler("memberof task", memberof_task_add);
	if(rc)
	{
		goto bail;
	}

	/*
	 * TODO: start up operation actor thread
	 * need to get to a point where server failure
         * or shutdown doesn't hose our operations
         * so we should create a task entry that contains
	 * all required information to complete the operation
         * then the tasks can be restarted safely if
	 * interrupted
	 */

bail:
	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		"<-- memberof_postop_start\n" );

	return rc;
}

/*
 * memberof_postop_close()
 *
 * Do plugin shut down stuff
 *
 */
int memberof_postop_close(Slapi_PBlock *pb)
{
	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "--> memberof_postop_close\n" );



	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "<-- memberof_postop_close\n" );
	return 0;
}

/*
 * memberof_postop_del()
 *
 * All entries with a memberOf attribute that contains the group DN get retrieved
 * and have the their memberOf attribute regenerated (it is far too complex and
 * error prone to attempt to change only those dn values involved in this case - 
 * mainly because the deleted group may itself be a member of other groups which
 * may be members of other groups etc. in a big recursive mess involving dependency
 * chains that must be created and traversed in order to decide if an entry should
 * really have those groups removed too)
 */
int memberof_postop_del(Slapi_PBlock *pb)
{
	int ret = 0;
	MemberOfConfig configCopy = {0, 0, 0, 0};
	char *dn;

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "--> memberof_postop_del\n" );

	if(memberof_oktodo(pb) && (dn = memberof_getdn(pb)))
	{
		struct slapi_entry *e = NULL;

		slapi_pblock_get( pb, SLAPI_ENTRY_PRE_OP, &e );

		/* We need to get the config lock first.  Trying to get the
		 * config lock after we already hold the op lock can cause
		 * a deadlock. */
		memberof_rlock_config();
		/* copy config so it doesn't change out from under us */
		memberof_copy_config(&configCopy, memberof_get_config());
		memberof_unlock_config();

		/* get the memberOf operation lock */
		memberof_lock();
		
		/* remove this group DN from the
		 * membership lists of groups
		 */
		memberof_del_dn_from_groups(pb, &configCopy, dn);

		/* is the entry of interest as a group? */
		if(e && !slapi_filter_test_simple(e, configCopy.group_filter))
		{
			Slapi_Attr *attr = 0;

			if(0 == slapi_entry_attr_find(e, configCopy.groupattr, &attr))
			{
				memberof_del_attr_list(pb, &configCopy, dn, attr);
			}
		}

		memberof_unlock();

		memberof_free_config(&configCopy);
	}

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "<-- memberof_postop_del\n" );
	return ret;
}

typedef struct _memberof_del_dn_data
{
	char *dn;
	char *type;
} memberof_del_dn_data;

int memberof_del_dn_from_groups(Slapi_PBlock *pb, MemberOfConfig *config, char *dn)
{
	memberof_del_dn_data data = {dn, config->groupattr};

	return memberof_call_foreach_dn(pb, dn,
		config->groupattr, memberof_del_dn_type_callback, &data);
}

int memberof_del_dn_type_callback(Slapi_Entry *e, void *callback_data)
{
	int rc = 0;
	LDAPMod mod;
	LDAPMod *mods[2];
	char *val[2];
	Slapi_PBlock *mod_pb = 0;

	mod_pb = slapi_pblock_new();

	mods[0] = &mod;
	mods[1] = 0;

	val[0] = ((memberof_del_dn_data *)callback_data)->dn;
	val[1] = 0;

	mod.mod_op = LDAP_MOD_DELETE;
	mod.mod_type = ((memberof_del_dn_data *)callback_data)->type;
	mod.mod_values = val;

	slapi_modify_internal_set_pb(
		mod_pb, slapi_entry_get_dn(e),
		mods, 0, 0,
		memberof_get_plugin_id(), 0);

	slapi_modify_internal_pb(mod_pb);

	slapi_pblock_get(mod_pb,
		SLAPI_PLUGIN_INTOP_RESULT,
		&rc);

	slapi_pblock_destroy(mod_pb);

	return rc;
}

/*
 * Does a callback search of "type=dn" under the db suffix that "dn" is in.
 * If "dn" is a user, you'd want "type" to be "member".  If "dn" is a group,
 * you could want type to be either "member" or "memberOf" depending on the
 * case.
 */
int memberof_call_foreach_dn(Slapi_PBlock *pb, char *dn,
	char *type, plugin_search_entry_callback callback, void *callback_data)
{
	int rc = 0;
	Slapi_PBlock *search_pb = slapi_pblock_new();
	Slapi_Backend *be = 0;
	Slapi_DN *sdn = 0;
	Slapi_DN *base_sdn = 0;
	char *filter_str = 0;

	/* get the base dn for the backend we are in
	   (we don't support having members and groups in
           different backends - issues with offline / read only backends)
	*/
	sdn = slapi_sdn_new_dn_byref(dn);
	be = slapi_be_select(sdn);
	if(be)
	{
		base_sdn = (Slapi_DN*)slapi_be_getsuffix(be,0);
	}

	if(base_sdn)
	{
		filter_str = slapi_ch_smprintf("(%s=%s)", type, dn);
	}

	if(filter_str)
	{
		slapi_search_internal_set_pb(search_pb, slapi_sdn_get_dn(base_sdn),
			LDAP_SCOPE_SUBTREE, filter_str, 0, 0,
			0, 0,
			memberof_get_plugin_id(),
			0);	

		slapi_search_internal_callback_pb(search_pb,
			callback_data,
			0, callback,
			0);
	}

	slapi_sdn_free(&sdn);
	slapi_pblock_destroy(search_pb);
	slapi_ch_free_string(&filter_str);
	return rc;
}

/*
 * memberof_postop_modrdn()
 *
 * All entries with a memberOf attribute that contains the old group DN get retrieved
 * and have the old group DN deleted and the new group DN added to their memberOf attribute
 */
int memberof_postop_modrdn(Slapi_PBlock *pb)
{
	int ret = 0;

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "--> memberof_postop_modrdn\n" );

	if(memberof_oktodo(pb))
	{
		MemberOfConfig *mainConfig = 0;
		MemberOfConfig configCopy = {0, 0, 0, 0};
		struct slapi_entry *pre_e = NULL;
		struct slapi_entry *post_e = NULL;
		char *pre_dn = 0;
		char *post_dn = 0;
		int interested = 0;

		slapi_pblock_get( pb, SLAPI_ENTRY_PRE_OP, &pre_e );
		slapi_pblock_get( pb, SLAPI_ENTRY_POST_OP, &post_e );
		
		if(pre_e && post_e)
		{
			pre_dn = slapi_entry_get_ndn(pre_e);
			post_dn = slapi_entry_get_ndn(post_e);
		}

		/* is the entry of interest? */
		memberof_rlock_config();
		mainConfig = memberof_get_config();
		if(pre_dn && post_dn &&
			!slapi_filter_test_simple(post_e, mainConfig->group_filter))
		{
			interested = 1;
			/* copy config so it doesn't change out from under us */
			memberof_copy_config(&configCopy, mainConfig);
		}
		memberof_unlock_config();

		if(interested)
		{
			Slapi_Attr *attr = 0;

			memberof_lock();

			/* get a list of member attributes present in the group
			 * entry that is being renamed. */
			if(0 == slapi_entry_attr_find(post_e, configCopy.groupattr, &attr))
			{
				memberof_moddn_attr_list(pb, &configCopy, pre_dn, post_dn, attr);
			}

			/* modrdn must change the dns in groups that have
			 * this group as a member.
			 */
			memberof_replace_dn_from_groups(pb, &configCopy, pre_dn, post_dn);

			memberof_unlock();

			memberof_free_config(&configCopy);
		}
	}


	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "<-- memberof_postop_modrdn\n" );
	return ret;
}

typedef struct _replace_dn_data
{
	char *pre_dn;
	char *post_dn;
	char *type;
} replace_dn_data;

int memberof_replace_dn_from_groups(Slapi_PBlock *pb, MemberOfConfig *config,
	char *pre_dn, char *post_dn)
{
	replace_dn_data data = {pre_dn, post_dn, config->groupattr};

	return memberof_call_foreach_dn(pb, pre_dn, config->groupattr, 
		memberof_replace_dn_type_callback, &data);
}


int memberof_replace_dn_type_callback(Slapi_Entry *e, void *callback_data)
{
	int rc = 0;
	LDAPMod delmod;
	LDAPMod addmod;
	LDAPMod *mods[3];
	char *delval[2];
	char *addval[2];
	Slapi_PBlock *mod_pb = 0;

	mod_pb = slapi_pblock_new();

	mods[0] = &delmod;
	mods[1] = &addmod;
	mods[2] = 0;

	delval[0] = ((replace_dn_data *)callback_data)->pre_dn;
	delval[1] = 0;

	delmod.mod_op = LDAP_MOD_DELETE;
	delmod.mod_type = ((replace_dn_data *)callback_data)->type;
	delmod.mod_values = delval;

	addval[0] = ((replace_dn_data *)callback_data)->post_dn;
	addval[1] = 0;

	addmod.mod_op = LDAP_MOD_ADD;
	addmod.mod_type = ((replace_dn_data *)callback_data)->type;
	addmod.mod_values = addval;

	slapi_modify_internal_set_pb(
		mod_pb, slapi_entry_get_dn(e),
		mods, 0, 0,
		memberof_get_plugin_id(), 0);

	slapi_modify_internal_pb(mod_pb);

	slapi_pblock_get(mod_pb,
		SLAPI_PLUGIN_INTOP_RESULT,
		&rc);

	slapi_pblock_destroy(mod_pb);

	return rc;
}

/*
 * memberof_postop_modify()
 *
 * Added members are retrieved and have the group DN added to their memberOf attribute
 * Deleted members are retrieved and have the group DN deleted from their memberOf attribute
 * On replace of the membership attribute values:
 * 	1. Sort old and new values
 *	2. Iterate through both lists at same time
 *	3. Any value not in old list but in new list - add group DN to memberOf attribute
 *	4. Any value in old list but not in new list - remove group DN from memberOf attribute
 *
 * Note: this will suck for large groups but nonetheless is optimal (it's linear) given
 * current restrictions i.e. originally adding members in sorted order would allow
 * us to sort one list only (the new one) but that is under server control, not this plugin
 */
int memberof_postop_modify(Slapi_PBlock *pb)
{
	int ret = 0;
	char *dn = 0;
	Slapi_Mods *smods = 0;
	Slapi_Mod *smod = 0;
	LDAPMod **mods;
	Slapi_Mod *next_mod = 0;

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "--> memberof_postop_modify\n" );

	if(memberof_oktodo(pb) &&
		(dn = memberof_getdn(pb)))
	{
		int config_copied = 0;
		MemberOfConfig *mainConfig = 0;
		MemberOfConfig configCopy = {0, 0, 0, 0};

		/* get the mod set */
		slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
		smods = slapi_mods_new();
		slapi_mods_init_byref(smods, mods);

		next_mod = slapi_mod_new();
		smod = slapi_mods_get_first_smod(smods, next_mod);
		while(smod)
		{
			int interested = 0;
			char *type = (char *)slapi_mod_get_type(smod);

			/* We only want to copy the config if we encounter an
			 * operation that we need to act on.  We also want to
			 * only copy the config the first time it's needed so
			 * it remains the same for all mods in the operation,
			 * despite any config changes that may be made. */
			if (!config_copied)
			{
				memberof_rlock_config();
				mainConfig = memberof_get_config();

				if(slapi_attr_types_equivalent(type, mainConfig->groupattr))
				{
					interested = 1;
					/* copy config so it doesn't change out from under us */
					memberof_copy_config(&configCopy, mainConfig);
					config_copied = 1;
				}

				memberof_unlock_config();
			} else {
				if(slapi_attr_types_equivalent(type, configCopy.groupattr))
				{
					interested = 1;
				}
			}

			if(interested)
			{
				int op = slapi_mod_get_operation(smod);

				memberof_lock();

				/* the modify op decides the function */
				switch(op & ~LDAP_MOD_BVALUES)
				{
				case LDAP_MOD_ADD:
					{
						/* add group DN to targets */
						memberof_add_smod_list(pb, &configCopy, dn, smod);
						break;
					}
				
				case LDAP_MOD_DELETE:
					{
						/* If there are no values in the smod, we should
						 * just do a replace instead.  The  user is just
						 * trying to delete all members from this group
						 * entry, which the replace code deals with. */
						if (slapi_mod_get_num_values(smod) == 0)
						{
							memberof_replace_list(pb, &configCopy, dn);
						}
						else
						{
							/* remove group DN from target values in smod*/
							memberof_del_smod_list(pb, &configCopy, dn, smod);
						}
						break;
					}

				case LDAP_MOD_REPLACE:
					{
						/* replace current values */
						memberof_replace_list(pb, &configCopy, dn);
						break;
					}

				default:
					{
						slapi_log_error(
							SLAPI_LOG_PLUGIN,
							MEMBEROF_PLUGIN_SUBSYSTEM,
							"memberof_postop_modify: unknown mod type\n" );
						break;
					}
				}

				memberof_unlock();
			}

			slapi_mod_done(next_mod);
			smod = slapi_mods_get_next_smod(smods, next_mod);
		}

		if (config_copied)
		{
			memberof_free_config(&configCopy);
		}

		slapi_mod_free(&next_mod);
		slapi_mods_free(&smods);
	}

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "<-- memberof_postop_modify\n" );
	return ret;
}


/*
 * memberof_postop_add()
 *
 * All members in the membership attribute of the new entry get retrieved
 * and have the group DN added to their memberOf attribute
 */
int memberof_postop_add(Slapi_PBlock *pb)
{
	int ret = 0;
	int interested = 0;
	char *dn = 0;

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "--> memberof_postop_add\n" );

	if(memberof_oktodo(pb) && (dn = memberof_getdn(pb)))
	{
		MemberOfConfig *mainConfig = 0;
		MemberOfConfig configCopy = {0, 0, 0, 0};
		struct slapi_entry *e = NULL;

		slapi_pblock_get( pb, SLAPI_ENTRY_POST_OP, &e );
		

		/* is the entry of interest? */
		memberof_rlock_config();
		mainConfig = memberof_get_config();
		if(e && !slapi_filter_test_simple(e, mainConfig->group_filter))
		{
			interested = 1;
			/* copy config so it doesn't change out from under us */
			memberof_copy_config(&configCopy, mainConfig);
		}
		memberof_unlock_config();

		if(interested)
		{
			Slapi_Attr *attr = 0;

			memberof_lock();

			if(0 == slapi_entry_attr_find(e, configCopy.groupattr, &attr))
			{
				memberof_add_attr_list(pb, &configCopy, dn, attr);
			}

			memberof_unlock();

			memberof_free_config(&configCopy);
		}
	}

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "<-- memberof_postop_add\n" );
	return ret;
}

/*** Support functions ***/

/*
 * memberof_oktodo()
 *
 * Check that the op succeeded
 * Note: we also respond to replicated ops so we don't test for that
 * this does require that the memberOf attribute not be replicated
 * and this means that memberof is consistent with local state
 * not the network system state
 *
 */
int memberof_oktodo(Slapi_PBlock *pb)
{
	int ret = 1;
	int oprc = 0;

	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "--> memberof_postop_oktodo\n" );

	if(slapi_pblock_get(pb, SLAPI_PLUGIN_OPRETURN, &oprc) != 0) 
        {
		slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
			"memberof_postop_oktodo: could not get parameters\n" );
		ret = -1;
	}

        /* this plugin should only execute if the operation succeeded
	*/
        if(oprc != 0)
	{
		ret = 0;
	}
	
	slapi_log_error( SLAPI_LOG_TRACE, MEMBEROF_PLUGIN_SUBSYSTEM,
		     "<-- memberof_postop_oktodo\n" );

	return ret;
}

/*
 * memberof_getdn()
 *
 * Get dn of target entry
 *
 */
char *memberof_getdn(Slapi_PBlock *pb)
{
	char *dn = 0;

	slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn);
	
	return dn;
}

/*
 * memberof_modop_one()
 *
 * Perform op on memberof attribute of op_to using op_this as the value
 * However, if op_to happens to be a group, we must arrange for the group
 * members to have the mod performed on them instead, and we must take
 * care to not recurse when we have visted a group before
 *
 * Also, we must not delete entries that are a member of the group
 */
int memberof_modop_one(Slapi_PBlock *pb, MemberOfConfig *config, int mod_op,
	char *op_this, char *op_to)
{
	return memberof_modop_one_r(pb, config, mod_op, op_this, op_this, op_to, 0);
}

/* memberof_modop_one_r()
 *
 * recursive function to perform above (most things don't need the replace arg)
 */

int memberof_modop_one_r(Slapi_PBlock *pb, MemberOfConfig *config, int mod_op,
	char *group_dn, char *op_this, char *op_to, memberofstringll *stack)
{
	return memberof_modop_one_replace_r(
		pb, config, mod_op, group_dn, op_this, 0, op_to, stack);
}

/* memberof_modop_one_replace_r()
 *
 * recursive function to perform above (with added replace arg)
 */
int memberof_modop_one_replace_r(Slapi_PBlock *pb, MemberOfConfig *config,
	int mod_op, char *group_dn, char *op_this, char *replace_with,
	char *op_to, memberofstringll *stack)
{
	int rc = 0;
	LDAPMod mod;
	LDAPMod replace_mod;
	LDAPMod *mods[3];
	char *val[2];
	char *replace_val[2];
	Slapi_PBlock *mod_pb = 0;
	char *attrlist[2] = {config->groupattr,0};
	Slapi_DN *op_to_sdn = 0;
	Slapi_Entry *e = 0; 
	memberofstringll *ll = 0;
	char *op_str = 0;
	Slapi_Value *to_dn_val = slapi_value_new_string(op_to);
	Slapi_Value *this_dn_val = slapi_value_new_string(op_this);

	/* determine if this is a group op or single entry */
	op_to_sdn = slapi_sdn_new_dn_byref(op_to);
	slapi_search_internal_get_entry( op_to_sdn, attrlist,
		&e, memberof_get_plugin_id());
	if(!e)
	{
		/* In the case of a delete, we need to worry about the
		 * missing entry being a nested group.  There's a small
		 * window where another thread may have deleted a nested
		 * group that our group_dn entry refers to.  This has the
		 * potential of us missing some indirect member entries
		 * that need to be updated. */
		if(LDAP_MOD_DELETE == mod_op)
		{
			Slapi_PBlock *search_pb = slapi_pblock_new();
			Slapi_DN *base_sdn = 0;
			Slapi_Backend *be = 0;
			char *filter_str = 0;
			int n_entries = 0;

			/* We can't tell for sure if the op_to entry is a
			 * user or a group since the entry doesn't exist
			 * anymore.  We can safely ignore the missing entry
			 * if no other entries have a memberOf attribute that
			 * points to the missing entry. */
			be = slapi_be_select(op_to_sdn);
			if(be)
			{
				base_sdn = (Slapi_DN*)slapi_be_getsuffix(be,0);
			}

			if(base_sdn)
			{
				filter_str = slapi_ch_smprintf("(%s=%s)",
				config->memberof_attr, op_to);
			}

			if(filter_str)
			{
				slapi_search_internal_set_pb(search_pb, slapi_sdn_get_dn(base_sdn),
					LDAP_SCOPE_SUBTREE, filter_str, 0, 0, 0, 0,
					memberof_get_plugin_id(), 0);

				if (slapi_search_internal_pb(search_pb))
				{
					/* get result and log an error */
					int res = 0;
					slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
					slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
					"memberof_modop_one_replace_r: error searching for members: "
					"%d", res);
				} else {
					slapi_pblock_get(search_pb, SLAPI_NENTRIES, &n_entries);

					if(n_entries > 0)
					{
						/* We want to fixup the membership for the
						 * entries that referred to the missing group
						 * entry.  This will fix the references to
						 * the missing group as well as the group
						 * represented by op_this. */
						memberof_test_membership(pb, config, op_to);
					}
				}

				slapi_free_search_results_internal(search_pb);
				slapi_ch_free_string(&filter_str);
			}

			slapi_pblock_destroy(search_pb);
		}

		goto bail;
	}

	if(LDAP_MOD_DELETE == mod_op)
	{
		op_str = "DELETE";
	}
	else if(LDAP_MOD_ADD == mod_op)
	{
		op_str = "ADD";
	}
	else if(LDAP_MOD_REPLACE == mod_op)
	{
		op_str = "REPLACE";
	}
	else
	{
		op_str = "UNKNOWN";
	}

	slapi_log_error( SLAPI_LOG_PLUGIN, MEMBEROF_PLUGIN_SUBSYSTEM,
		"memberof_modop_one_replace_r: %s %s in %s\n"
		,op_str, op_this, op_to);

	if(!slapi_filter_test_simple(e, config->group_filter))
	{
		/* group */
		Slapi_Value *ll_dn_val = 0;
		Slapi_Attr *members = 0;

		ll = stack;

		/* have we been here before? */
		while(ll)
		{
			ll_dn_val = slapi_value_new_string(ll->dn);

			if(0 == memberof_compare(config, &ll_dn_val, &to_dn_val))
			{
				slapi_value_free(&ll_dn_val);

				/* 	someone set up infinitely
					recursive groups - bail out */
				slapi_log_error( SLAPI_LOG_PLUGIN,
					MEMBEROF_PLUGIN_SUBSYSTEM,
					"memberof_modop_one_replace_r: group recursion"
					" detected in %s\n"
					,op_to);
				goto bail;
			}

			slapi_value_free(&ll_dn_val);
			ll = ll->next;
		}

		/* do op on group */
		slapi_log_error( SLAPI_LOG_PLUGIN,
			MEMBEROF_PLUGIN_SUBSYSTEM,
			"memberof_modop_one_replace_r: descending into group %s\n",
			op_to);
		/* Add the nested group's DN to the stack so we can detect loops later. */
		ll = (memberofstringll*)slapi_ch_malloc(sizeof(memberofstringll));
		ll->dn = op_to;
		ll->next = stack;
		
		slapi_entry_attr_find( e, config->groupattr, &members );
		if(members)
		{
			memberof_mod_attr_list_r(pb, config, mod_op, group_dn, op_this, members, ll);
		}

		{
			/* crazyness follows:
			 * strict-aliasing doesn't like the required cast
			 * to void for slapi_ch_free so we are made to
			 * juggle to get a normal thing done
			 */
			void *pll = ll;
			slapi_ch_free(&pll);
			ll = 0;
		}
	}
	/* continue with operation */
	{
		/* We want to avoid listing a group as a memberOf itself
		 * in case someone set up a circular grouping.
		 */
		if (0 == memberof_compare(config, &this_dn_val, &to_dn_val))
		{
			slapi_log_error( SLAPI_LOG_PLUGIN,
				MEMBEROF_PLUGIN_SUBSYSTEM,
				"memberof_modop_one_replace_r: not processing memberOf "
				"operations on self entry: %s\n", this_dn_val);
			goto bail;
		}

		/* For add and del modify operations, we just regenerate the
		 * memberOf attribute. */
		if(LDAP_MOD_DELETE == mod_op || LDAP_MOD_ADD == mod_op)
		{
			/* find parent groups and replace our member attr */
			memberof_fix_memberof_callback(e, config);
		} else {
			/* single entry - do mod */
			mod_pb = slapi_pblock_new();

			mods[0] = &mod;
			if(LDAP_MOD_REPLACE == mod_op)
			{
				mods[1] = &replace_mod;
				mods[2] = 0;
			}
			else
			{
				mods[1] = 0;
			}

			val[0] = op_this;
			val[1] = 0;
			mod.mod_op = LDAP_MOD_REPLACE == mod_op?LDAP_MOD_DELETE:mod_op;
			mod.mod_type = config->memberof_attr;
			mod.mod_values = val;

			if(LDAP_MOD_REPLACE == mod_op)
			{
				replace_val[0] = replace_with;
				replace_val[1] = 0;

				replace_mod.mod_op = LDAP_MOD_ADD;
				replace_mod.mod_type = config->memberof_attr;
				replace_mod.mod_values = replace_val;
			}

			slapi_modify_internal_set_pb(
				mod_pb, op_to,
				mods, 0, 0,
				memberof_get_plugin_id(), 0);

			slapi_modify_internal_pb(mod_pb);

			slapi_pblock_get(mod_pb,
				SLAPI_PLUGIN_INTOP_RESULT,
				&rc);

			slapi_pblock_destroy(mod_pb);
		}
	}

bail:
	slapi_sdn_free(&op_to_sdn);
	slapi_value_free(&to_dn_val);
	slapi_value_free(&this_dn_val);
	slapi_entry_free(e);
	return rc;
}


/*
 * memberof_add_one()
 *
 * Add addthis DN to the memberof attribute of addto
 *
 */
int memberof_add_one(Slapi_PBlock *pb, MemberOfConfig *config, char *addthis, char *addto)
{
	return memberof_modop_one(pb, config, LDAP_MOD_ADD, addthis, addto);
}

/*
 * memberof_del_one()
 *
 * Delete delthis DN from the memberof attribute of delfrom
 *
 */
int memberof_del_one(Slapi_PBlock *pb, MemberOfConfig *config, char *delthis, char *delfrom)
{
	return memberof_modop_one(pb, config, LDAP_MOD_DELETE, delthis, delfrom);
}

/*
 * memberof_mod_smod_list()
 *
 * Perform mod for group DN to the memberof attribute of the list of targets
 *
 */
int memberof_mod_smod_list(Slapi_PBlock *pb, MemberOfConfig *config, int mod,
	char *group_dn, Slapi_Mod *smod)
{
	int rc = 0;
	struct berval *bv = slapi_mod_get_first_value(smod);
	int last_size = 0;
	char *last_str = 0;

	while(bv)
	{
		char *dn_str = 0;

		if(last_size > bv->bv_len)
		{
			dn_str = last_str;
		}
		else
		{
			int the_size = (bv->bv_len * 2) + 1;

			if(last_str)
				slapi_ch_free_string(&last_str);

			dn_str = (char*)slapi_ch_malloc(the_size);

			last_str = dn_str;
			last_size = the_size;
		}

		memset(dn_str, 0, last_size);

		strncpy(dn_str, bv->bv_val, (size_t)bv->bv_len);

		memberof_modop_one(pb, config, mod, group_dn, dn_str);

		bv = slapi_mod_get_next_value(smod);
	}

	if(last_str)
		slapi_ch_free_string(&last_str);

	return rc;
}

/*
 * memberof_add_smod_list()
 *
 * Add group DN to the memberof attribute of the list of targets
 *
 */
int memberof_add_smod_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *groupdn, Slapi_Mod *smod)
{
	return memberof_mod_smod_list(pb, config, LDAP_MOD_ADD, groupdn, smod);
}


/*
 * memberof_del_smod_list()
 *
 * Remove group DN from the memberof attribute of the list of targets
 *
 */
int memberof_del_smod_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *groupdn, Slapi_Mod *smod)
{
	return memberof_mod_smod_list(pb, config, LDAP_MOD_DELETE, groupdn, smod);
}

/**
 * Plugin identity mgmt
 */
void memberof_set_plugin_id(void * plugin_id) 
{
	_PluginID=plugin_id;
}

void * memberof_get_plugin_id()
{
	return _PluginID;
}


/*
 * memberof_mod_attr_list()
 *
 * Perform mod for group DN to the memberof attribute of the list of targets
 *
 */
int memberof_mod_attr_list(Slapi_PBlock *pb, MemberOfConfig *config, int mod,
	char *group_dn, Slapi_Attr *attr)
{
	return memberof_mod_attr_list_r(pb, config, mod, group_dn, group_dn, attr, 0);
}

int memberof_mod_attr_list_r(Slapi_PBlock *pb, MemberOfConfig *config, int mod,
	char *group_dn, char *op_this, Slapi_Attr *attr, memberofstringll *stack)
{
	int rc = 0;
	Slapi_Value *val = 0;
	Slapi_Value *op_this_val = 0;
	int last_size = 0;
	char *last_str = 0;
	int hint = slapi_attr_first_value(attr, &val);

	op_this_val = slapi_value_new_string(op_this);

	while(val)
	{
		char *dn_str = 0;
		struct berval *bv = 0;

		/* We don't want to process a memberOf operation on ourselves. */
		if(0 != memberof_compare(config, &val, &op_this_val))
		{
			bv = (struct berval *)slapi_value_get_berval(val);

			if(last_size > bv->bv_len)
			{
				dn_str = last_str;
			}
			else
			{
				int the_size = (bv->bv_len * 2) + 1;

				if(last_str)
					slapi_ch_free_string(&last_str);

				dn_str = (char*)slapi_ch_malloc(the_size);

				last_str = dn_str;
				last_size = the_size;
			}

			memset(dn_str, 0, last_size);

			strncpy(dn_str, bv->bv_val, (size_t)bv->bv_len);

			/* If we're doing a replace (as we would in the MODRDN case), we need
			 * to specify the new group DN value */
			if(mod == LDAP_MOD_REPLACE)
			{
				memberof_modop_one_replace_r(pb, config, mod, group_dn, op_this,
						group_dn, dn_str, stack);
			}
			else
			{
				memberof_modop_one_r(pb, config, mod, group_dn, op_this, dn_str, stack);
			}
		}

		hint = slapi_attr_next_value(attr, hint, &val);
	}

	slapi_value_free(&op_this_val);

	if(last_str)
		slapi_ch_free_string(&last_str);

	return rc;
}

/*
 * memberof_add_attr_list()
 *
 * Add group DN to the memberof attribute of the list of targets
 *
 */
int memberof_add_attr_list(Slapi_PBlock *pb, MemberOfConfig *config, char *groupdn,
	Slapi_Attr *attr)
{
	return memberof_mod_attr_list(pb, config, LDAP_MOD_ADD, groupdn, attr);
}

/*
 * memberof_del_attr_list()
 *
 * Remove group DN from the memberof attribute of the list of targets
 *
 */
int memberof_del_attr_list(Slapi_PBlock *pb, MemberOfConfig *config, char *groupdn,
	Slapi_Attr *attr)
{
	return memberof_mod_attr_list(pb, config, LDAP_MOD_DELETE, groupdn, attr);
}

/*
 * memberof_moddn_attr_list()
 *
 * Perform mod for group DN to the memberof attribute of the list of targets
 *
 */
int memberof_moddn_attr_list(Slapi_PBlock *pb, MemberOfConfig *config,
	char *pre_dn, char *post_dn, Slapi_Attr *attr)
{
	int rc = 0;
	Slapi_Value *val = 0;
	int last_size = 0;
	char *last_str = 0;
	int hint = slapi_attr_first_value(attr, &val);

	while(val)
	{
		char *dn_str = 0;
		struct berval *bv = (struct berval *)slapi_value_get_berval(val);

		if(last_size > bv->bv_len)
		{
			dn_str = last_str;
		}
		else
		{
			int the_size = (bv->bv_len * 2) + 1;

			if(last_str)
				slapi_ch_free_string(&last_str);

			dn_str = (char*)slapi_ch_malloc(the_size);

			last_str = dn_str;
			last_size = the_size;
		}

		memset(dn_str, 0, last_size);

		strncpy(dn_str, bv->bv_val, (size_t)bv->bv_len);

		memberof_modop_one_replace_r(pb, config, LDAP_MOD_REPLACE,
			post_dn, pre_dn, post_dn, dn_str, 0);

		hint = slapi_attr_next_value(attr, hint, &val);
	}

	if(last_str)
		slapi_ch_free_string(&last_str);

	return rc;
}

/* memberof_get_groups()
 *
 * Gets a list of all groups that an entry is a member of.
 * This is done by looking only at member attribute values.
 * A Slapi_ValueSet* is returned.  It is up to the caller to
 * free it.
 */
Slapi_ValueSet *memberof_get_groups(MemberOfConfig *config, char *memberdn)
{
	Slapi_Value *memberdn_val = slapi_value_new_string(memberdn);
	Slapi_ValueSet *groupvals = slapi_valueset_new();
	memberof_get_groups_data data = {config, memberdn_val, &groupvals};

	memberof_get_groups_r(config, memberdn, &data);

	slapi_value_free(&memberdn_val);

	return groupvals;
}

int memberof_get_groups_r(MemberOfConfig *config, char *memberdn, memberof_get_groups_data *data)
{
	/* Search for member=<memberdn>
	 * For each match, add it to the list, recurse and do same search */
	return memberof_call_foreach_dn(NULL, memberdn, config->groupattr,
		memberof_get_groups_callback, data);
}

/* memberof_get_groups_callback()
 *
 * Callback to perform work of memberof_get_groups()
 */
int memberof_get_groups_callback(Slapi_Entry *e, void *callback_data)
{
	char *group_dn = slapi_entry_get_dn(e);
	Slapi_Value *group_dn_val = 0;
	Slapi_ValueSet *groupvals = *((memberof_get_groups_data*)callback_data)->groupvals;

	/* get the DN of the group */
	group_dn_val = slapi_value_new_string(group_dn);

	/* check if e is the same as our original member entry */
	if (0 == memberof_compare(((memberof_get_groups_data*)callback_data)->config,
		&((memberof_get_groups_data*)callback_data)->memberdn_val, &group_dn_val))
	{
		/* A recursive group caused us to find our original
		 * entry we passed to memberof_get_groups().  We just
		 * skip processing this entry. */
		slapi_log_error( SLAPI_LOG_PLUGIN, MEMBEROF_PLUGIN_SUBSYSTEM,
			"memberof_get_groups_callback: group recursion"
			" detected in %s\n" ,group_dn);
		slapi_value_free(&group_dn_val);
		goto bail;

	}

	/* have we been here before? */
	if (groupvals &&
		slapi_valueset_find(((memberof_get_groups_data*)callback_data)->config->group_slapiattr,
		groupvals, group_dn_val))
	{
		/* we either hit a recursive grouping, or an entry is
		 * a member of a group through multiple paths.  Either
		 * way, we can just skip processing this entry since we've
		 * already gone through this part of the grouping hierarchy. */
		slapi_log_error( SLAPI_LOG_PLUGIN, MEMBEROF_PLUGIN_SUBSYSTEM,
			"memberof_get_groups_callback: possible group recursion"
			" detected in %s\n" ,group_dn);
		slapi_value_free(&group_dn_val);
		goto bail;
	}

	/* Push group_dn_val into the valueset.  This memory is now owned
	 * by the valueset. */ 
	slapi_valueset_add_value_ext(groupvals, group_dn_val, SLAPI_VALUE_FLAG_PASSIN);

	/* now recurse to find parent groups of e */
	memberof_get_groups_r(((memberof_get_groups_data*)callback_data)->config,
		group_dn, callback_data);

	bail:
		return 0;
}

/* memberof_is_direct_member()
 *
 * tests for direct membership of memberdn in group groupdn
 * returns non-zero when true, zero otherwise
 */
int memberof_is_direct_member(MemberOfConfig *config, Slapi_Value *groupdn,
	Slapi_Value *memberdn)
{
	int rc = 0;
	Slapi_DN *sdn = 0;
	char *attrlist[2] = {config->groupattr,0};
	Slapi_Entry *group_e = 0;
	Slapi_Attr *attr = 0;

	sdn = slapi_sdn_new_dn_byref(slapi_value_get_string(groupdn));

	slapi_search_internal_get_entry(sdn, attrlist,
		&group_e, memberof_get_plugin_id());

	if(group_e)
	{
		slapi_entry_attr_find(group_e, config->groupattr, &attr );
		if(attr)
		{
			rc = 0 == slapi_attr_value_find(
				attr, slapi_value_get_berval(memberdn));
		}
		slapi_entry_free(group_e);
	}

	slapi_sdn_free(&sdn);
	return rc;
}

/* memberof_test_membership()
 *
 * Finds all entries who are a "memberOf" the group
 * represented by "group_dn".  For each matching entry, we
 * call memberof_test_membership_callback().
 *
 * for each attribute in the memberof attribute
 * determine if the entry is still a member.
 * 
 * test each for direct membership
 * move groups entry is memberof to member group
 * test remaining groups for membership in member groups
 * iterate until a pass fails to move a group over to member groups
 * remaining groups should be deleted 
 */
int memberof_test_membership(Slapi_PBlock *pb, MemberOfConfig *config, char *group_dn)
{
	return memberof_call_foreach_dn(pb, group_dn, config->memberof_attr, 
		memberof_test_membership_callback , config);
}

/*
 * memberof_test_membership_callback()
 *
 * A callback function to do the work of memberof_test_membership().
 * Note that this not only tests membership, but updates the memberOf
 * attributes in the entry to be correct.
 */
int memberof_test_membership_callback(Slapi_Entry *e, void *callback_data)
{
	int rc = 0;
	Slapi_Attr *attr = 0;
	int total = 0;
	Slapi_Value **member_array = 0;
	Slapi_Value **candidate_array = 0;
	Slapi_Value *entry_dn = 0;
	MemberOfConfig *config = (MemberOfConfig *)callback_data;

	entry_dn = slapi_value_new_string(slapi_entry_get_dn(e));

	if(0 == entry_dn)
	{
		goto bail;
	}

	/* divide groups into member and non-member lists */
	slapi_entry_attr_find(e, config->memberof_attr, &attr );
	if(attr)
	{
		slapi_attr_get_numvalues( attr, &total);
		if(total)
		{
			Slapi_Value *val = 0;
			int hint = 0;
			int c_index = 0;
			int m_index = 0;
			int member_found = 1;
			int outer_index = 0;

			candidate_array =
				(Slapi_Value**)
				slapi_ch_malloc(sizeof(Slapi_Value*)*total);
			memset(candidate_array, 0, sizeof(Slapi_Value*)*total);
			member_array =
				(Slapi_Value**)
				slapi_ch_malloc(sizeof(Slapi_Value*)*total);
			memset(member_array, 0, sizeof(Slapi_Value*)*total);

			hint = slapi_attr_first_value(attr, &val);

			while(val)
			{
				/* test for direct membership */
				if(memberof_is_direct_member(config, val, entry_dn))
				{
					/* it is a member */
					member_array[m_index] = val;
					m_index++;
				}
				else
				{
					/* not a member, still a candidate */
					candidate_array[c_index] = val;
					c_index++;
				}

				hint = slapi_attr_next_value(attr, hint, &val);
			}	

			/* now iterate over members testing for membership
			   in candidate groups and moving candidates to members
			   when successful, quit when a full iteration adds no
			   new members
			*/
			while(member_found)
			{				
				member_found = 0;

				/* For each group that this entry is a verified member of, see if
				 * any of the candidate groups are members.  If they are, add them
				 * to the list of verified groups that this entry is a member of.
				 */
				while(outer_index < m_index)
				{
					int inner_index = 0;

					while(inner_index < c_index)
					{
						/* Check for a special value in this position
						 * that indicates that the candidate was moved
						 * to the member array. */
						if((void*)1 ==
							candidate_array[inner_index])
						{
							/* was moved, skip */
							inner_index++;
							continue;
						}

						if(memberof_is_direct_member(
							config,
							candidate_array[inner_index],
							member_array[outer_index]))
						{
							member_array[m_index] =
								candidate_array
									[inner_index];
							m_index++;

							candidate_array[inner_index] =
								(void*)1;
				
							member_found = 1;
						}

						inner_index++;
					}

					outer_index++;
				}				
			}

			/* here we are left only with values to delete
			   from the memberof attribute in the candidate list
			*/
			outer_index = 0;
			while(outer_index < c_index)
			{
				/* Check for a special value in this position
				 * that indicates that the candidate was moved
				 * to the member array. */
				if((void*)1 == candidate_array[outer_index])
				{
					/* item moved, skip */
					outer_index++;
					continue;
				}

				memberof_del_one(
					0, config,
					(char*)slapi_value_get_string(
						candidate_array[outer_index]),
					(char*)slapi_value_get_string(entry_dn));

				outer_index++;
			}
			{
				/* crazyness follows:
				 * strict-aliasing doesn't like the required cast
				 * to void for slapi_ch_free so we are made to
				 * juggle to get a normal thing done
				 */
				void *pmember_array = member_array;
				void *pcandidate_array = candidate_array;
				slapi_ch_free(&pcandidate_array);
				slapi_ch_free(&pmember_array);
				candidate_array = 0;
				member_array = 0;
			}
		}
	}

bail:
	slapi_value_free(&entry_dn);

	return rc;
}

/*
 * memberof_replace_list()
 *
 * Perform replace the group DN list in the memberof attribute of the list of targets
 *
 */
int memberof_replace_list(Slapi_PBlock *pb, MemberOfConfig *config, char *group_dn)
{
	struct slapi_entry *pre_e = NULL;
	struct slapi_entry *post_e = NULL;
	Slapi_Attr *pre_attr = 0;
	Slapi_Attr *post_attr = 0;

	slapi_pblock_get( pb, SLAPI_ENTRY_PRE_OP, &pre_e );
	slapi_pblock_get( pb, SLAPI_ENTRY_POST_OP, &post_e );
		
	if(pre_e && post_e)
	{
		slapi_entry_attr_find( pre_e, config->groupattr, &pre_attr );
		slapi_entry_attr_find( post_e, config->groupattr, &post_attr );
	}

	if(pre_attr || post_attr)
	{
		int pre_total = 0;
		int post_total = 0;
		Slapi_Value **pre_array = 0;
		Slapi_Value **post_array = 0;
		int pre_index = 0;
		int post_index = 0;

		/* create arrays of values */
		if(pre_attr)
		{
			slapi_attr_get_numvalues( pre_attr, &pre_total);
		}

		if(post_attr)
		{
			slapi_attr_get_numvalues( post_attr, &post_total);
		}

		/* Stash a plugin global pointer here and have memberof_qsort_compare
		 * use it.  We have to do this because we use memberof_qsort_compare
		 * as the comparator function for qsort, which requires the function
		 * to only take two void* args.  This is thread-safe since we only
		 * store and use the pointer while holding the memberOf operation
		 * lock. */
		qsortConfig = config;

		if(pre_total)
		{
			pre_array =
				(Slapi_Value**)
				slapi_ch_malloc(sizeof(Slapi_Value*)*pre_total);
			memberof_load_array(pre_array, pre_attr);
			qsort(
				pre_array,
				pre_total,
				sizeof(Slapi_Value*),
				memberof_qsort_compare);
		}

		if(post_total)
		{
			post_array =
				(Slapi_Value**)
				slapi_ch_malloc(sizeof(Slapi_Value*)*post_total);
			memberof_load_array(post_array, post_attr);
			qsort(
				post_array, 
				post_total, 
				sizeof(Slapi_Value*), 
				memberof_qsort_compare);
		}

		qsortConfig = 0;


		/* 	work through arrays, following these rules:
			in pre, in post, do nothing
			in pre, not in post, delete from entry
			not in pre, in post, add to entry
		*/
		while(pre_index < pre_total || post_index < post_total)
		{
			if(pre_index == pre_total)
			{
				/* add the rest of post */
				memberof_add_one(
					pb, config, 
					group_dn, 
					(char*)slapi_value_get_string(
						post_array[post_index]));

				post_index++;
			}
			else if(post_index == post_total)
			{
				/* delete the rest of pre */
				memberof_del_one(
					pb, config,
					group_dn, 
					(char*)slapi_value_get_string(
						pre_array[pre_index]));

				pre_index++;
			}
			else
			{
				/* decide what to do */
				int cmp = memberof_compare(
						config,
						&(pre_array[pre_index]),
						&(post_array[post_index]));

				if(cmp < 0)
				{
					/* delete pre array */
					memberof_del_one(
						pb, config, 
						group_dn, 
						(char*)slapi_value_get_string(
							pre_array[pre_index]));

					pre_index++;
				}
				else if(cmp > 0)
				{
					/* add post array */
					memberof_add_one(
						pb, config,
						group_dn, 
						(char*)slapi_value_get_string(
							post_array[post_index]));

					post_index++;
				}
				else
				{
					/* do nothing, advance */
					pre_index++;
					post_index++;
				}
			}
		}
		slapi_ch_free((void **)&pre_array);
		slapi_ch_free((void **)&post_array);
	}
	
	return 0;
}

/* memberof_load_array()
 * 
 * put attribute values in array structure
 */
void memberof_load_array(Slapi_Value **array, Slapi_Attr *attr)
{
	Slapi_Value *val = 0;
	int hint = slapi_attr_first_value(attr, &val);

	while(val)
	{
		*array = val;
		array++;
		hint = slapi_attr_next_value(attr, hint, &val);
	}
}

/* memberof_compare()
 * 
 * compare two attr values
 */
int memberof_compare(MemberOfConfig *config, const void *a, const void *b)
{
	Slapi_Value *val1 = *((Slapi_Value **)a);
	Slapi_Value *val2 = *((Slapi_Value **)b);

	return slapi_attr_value_cmp(
		config->group_slapiattr,
		slapi_value_get_berval(val1),
		slapi_value_get_berval(val2));
}

/* memberof_qsort_compare()
 *
 * This is a version of memberof_compare that uses a plugin
 * global copy of the config.  We'd prefer to pass in a copy
 * of config that is local to the running thread, but we can't
 * do this since qsort is using us as a comparator function.
 * We should only use this function when using qsort, and only
 * when the memberOf lock is acquired.
 */
int memberof_qsort_compare(const void *a, const void *b)
{
	Slapi_Value *val1 = *((Slapi_Value **)a);
	Slapi_Value *val2 = *((Slapi_Value **)b);

	return slapi_attr_value_cmp(
		qsortConfig->group_slapiattr, 
		slapi_value_get_berval(val1), 
		slapi_value_get_berval(val2));
}

void memberof_lock()
{
	slapi_lock_mutex(memberof_operation_lock);
}

void memberof_unlock()
{
	slapi_unlock_mutex(memberof_operation_lock);
}

typedef struct _task_data
{
	char *dn;
	char *filter_str;
} task_data;

void memberof_fixup_task_thread(void *arg)
{
	MemberOfConfig configCopy = {0, 0, 0, 0};
	Slapi_Task *task = (Slapi_Task *)arg;
	task_data *td = NULL;
	int rc = 0;

	/* Fetch our task data from the task */
	td = (task_data *)slapi_task_get_data(task);

	slapi_task_begin(task, 1);
	slapi_task_log_notice(task, "Memberof task starts (arg: %s) ...\n", 
								td->filter_str);

	/* We need to get the config lock first.  Trying to get the
	 * config lock after we already hold the op lock can cause
	 * a deadlock. */
	memberof_rlock_config();
	/* copy config so it doesn't change out from under us */
	memberof_copy_config(&configCopy, memberof_get_config());
	memberof_unlock_config();

	/* get the memberOf operation lock */
	memberof_lock();

	/* do real work */
	rc = memberof_fix_memberof(&configCopy, td->dn, td->filter_str);
 
	/* release the memberOf operation lock */
	memberof_unlock();

	memberof_free_config(&configCopy);

	slapi_task_log_notice(task, "Memberof task finished.");
	slapi_task_log_status(task, "Memberof task finished.");
	slapi_task_inc_progress(task);

	/* this will queue the destruction of the task */
	slapi_task_finish(task, rc);
}

/* extract a single value from the entry (as a string) -- if it's not in the
 * entry, the default will be returned (which can be NULL).
 * you do not need to free anything returned by this.
 */
const char *fetch_attr(Slapi_Entry *e, const char *attrname,
                                              const char *default_val)
{
	Slapi_Attr *attr;
	Slapi_Value *val = NULL;

	if (slapi_entry_attr_find(e, attrname, &attr) != 0)
		return default_val;
	slapi_attr_first_value(attr, &val);
	return slapi_value_get_string(val);
}

int memberof_task_add(Slapi_PBlock *pb, Slapi_Entry *e,
                    Slapi_Entry *eAfter, int *returncode, char *returntext,
                    void *arg)
{
	PRThread *thread = NULL;
	int rv = SLAPI_DSE_CALLBACK_OK;
	task_data *mytaskdata = NULL;
	Slapi_Task *task = NULL;
	const char *filter;
	const char *dn = 0;

	*returncode = LDAP_SUCCESS;
	/* get arg(s) */
	if ((dn = fetch_attr(e, "basedn", 0)) == NULL)
	{
		*returncode = LDAP_OBJECT_CLASS_VIOLATION;
		rv = SLAPI_DSE_CALLBACK_ERROR;
		goto out;
	}

	if ((filter = fetch_attr(e, "filter", "(objectclass=inetuser)")) == NULL)
	{
		*returncode = LDAP_OBJECT_CLASS_VIOLATION;
		rv = SLAPI_DSE_CALLBACK_ERROR;
		goto out;
	}

	/* setup our task data */
	mytaskdata = (task_data*)slapi_ch_malloc(sizeof(task_data));
	if (mytaskdata == NULL)
	{
		*returncode = LDAP_OPERATIONS_ERROR;
		rv = SLAPI_DSE_CALLBACK_ERROR;
		goto out;
	}
	mytaskdata->dn = slapi_ch_strdup(dn);
	mytaskdata->filter_str = slapi_ch_strdup(filter);

	/* allocate new task now */
	task = slapi_new_task(slapi_entry_get_ndn(e));

	/* register our destructor for cleaning up our private data */
	slapi_task_set_destructor_fn(task, memberof_task_destructor);

	/* Stash a pointer to our data in the task */
	slapi_task_set_data(task, mytaskdata);

	/* start the sample task as a separate thread */
	thread = PR_CreateThread(PR_USER_THREAD, memberof_fixup_task_thread,
		(void *)task, PR_PRIORITY_NORMAL, PR_GLOBAL_THREAD,
		PR_UNJOINABLE_THREAD, SLAPD_DEFAULT_THREAD_STACKSIZE);
	if (thread == NULL)
	{
		slapi_log_error( SLAPI_LOG_FATAL, MEMBEROF_PLUGIN_SUBSYSTEM,
			"unable to create task thread!\n");
		*returncode = LDAP_OPERATIONS_ERROR;
		rv = SLAPI_DSE_CALLBACK_ERROR;
		slapi_task_finish(task, *returncode);
	} else {
		rv = SLAPI_DSE_CALLBACK_OK;
	}

out:
	return rv;
}

void
memberof_task_destructor(Slapi_Task *task)
{
	if (task) {
		task_data *mydata = (task_data *)slapi_task_get_data(task);
		if (mydata) {
			slapi_ch_free_string(&mydata->dn);
			slapi_ch_free_string(&mydata->filter_str);
			/* Need to cast to avoid a compiler warning */
			slapi_ch_free((void **)&mydata);
		}
	}
}

int memberof_fix_memberof(MemberOfConfig *config, char *dn, char *filter_str)
{
	int rc = 0;
	Slapi_PBlock *search_pb = slapi_pblock_new();

	slapi_search_internal_set_pb(search_pb, dn,
		LDAP_SCOPE_SUBTREE, filter_str, 0, 0,
		0, 0,
		memberof_get_plugin_id(),
		0);	

	rc = slapi_search_internal_callback_pb(search_pb,
		config,
		0, memberof_fix_memberof_callback,
		0);

	slapi_pblock_destroy(search_pb);

	return rc;
}

/* memberof_fix_memberof_callback()
 * Add initial and/or fix up broken group list in entry
 *
 * 1. Remove all present memberOf values
 * 2. Add direct group membership memberOf values
 * 3. Add indirect group membership memberOf values
 */
int memberof_fix_memberof_callback(Slapi_Entry *e, void *callback_data)
{
	int rc = 0;
	char *dn = slapi_entry_get_dn(e);
	MemberOfConfig *config = (MemberOfConfig *)callback_data;
	memberof_del_dn_data del_data = {0, config->memberof_attr};
	Slapi_ValueSet *groups = 0;

	/* get a list of all of the groups this user belongs to */
	groups = memberof_get_groups(config, dn);

	/* If we found some groups, replace the existing memberOf attribute
	 * with the found values.  */
	if (groups && slapi_valueset_count(groups))
	{
		Slapi_PBlock *mod_pb = slapi_pblock_new();
		Slapi_Value *val = 0;
		Slapi_Mod *smod;
		LDAPMod **mods = (LDAPMod **) slapi_ch_malloc(2 * sizeof(LDAPMod *));
		int hint = 0;

		/* NGK - need to allocate the smod */
		smod = slapi_mod_new();
		slapi_mod_init(smod, 0);
		slapi_mod_set_operation(smod, LDAP_MOD_REPLACE | LDAP_MOD_BVALUES);
		slapi_mod_set_type(smod, config->memberof_attr);

		/* Loop through all of our values and add them to smod */
		hint = slapi_valueset_first_value(groups, &val);
		while (val)
		{
			/* this makes a copy of the berval */
			slapi_mod_add_value(smod, slapi_value_get_berval(val));
			hint = slapi_valueset_next_value(groups, hint, &val);
		}
		
		mods[0] = slapi_mod_get_ldapmod_passout(smod);
		mods[1] = 0;

		slapi_modify_internal_set_pb(
			mod_pb, dn, mods, 0, 0,
			memberof_get_plugin_id(), 0);

		slapi_modify_internal_pb(mod_pb);

		slapi_pblock_get(mod_pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);

		ldap_mods_free(mods, 1);
		slapi_mod_free(&smod);
		/* NGK - need to free the smod */
		slapi_pblock_destroy(mod_pb);
	} else { 
		/* No groups were found, so remove the memberOf attribute
		 * from this entry. */
		memberof_del_dn_type_callback(e, &del_data);
	}

	slapi_valueset_free(groups);
	
	return rc;
}

