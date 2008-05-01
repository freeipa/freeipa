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
 * Author: Pete Rowley
 *
 * Copyright (C) 2007 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif


/**
 * Distributed Numeric Assignment plug-in
 */

#include <dirsrv/slapi-plugin.h>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
/*#include "portable.h"*/
#include "nspr.h"
/*#include "slapi-private.h"*/
/*#include "dirlite_strings.h"*/
/*#include "dirver.h"*/

#include "prclist.h"
#include "ldif.h"

/* get file mode flags for unix */
#ifndef _WIN32
#include <sys/stat.h>
#endif

#define DNA_PLUGIN_SUBSYSTEM "ipa-dna-plugin"
#define DNA_PLUGIN_VERSION 0x00010000

/* temporary */
#define DNA_DN "cn=ipa-dna,cn=plugins,cn=config"

#define DNA_SUCCESS 0
#define DNA_FAILURE -1

/**
 * DNA config types
 */
#define DNA_TYPE	"dnaType"
#define DNA_PREFIX	"dnaPrefix"
#define DNA_NEXTVAL	"dnaNextValue"
#define DNA_INTERVAL	"dnaInterval"
#define DNA_GENERATE	"dnaMagicRegen"
#define DNA_FILTER	"dnaFilter"
#define DNA_SCOPE	"dnaScope"

#define FEATURE_DESC	"IPA Distributed Numeric Assignment"
#define PLUGIN_DESC	"IPA Distributed Numeric Assignment plugin"

static Slapi_PluginDesc pdesc = { FEATURE_DESC,
    "FreeIPA project", "FreeIPA/1.0",
    PLUGIN_DESC
};


/**
 * linked list of config entries
 */

struct _defs {
    PRCList list;
    char *dn;
    char *type;
    char *prefix;
    unsigned long nextval;
    unsigned long interval;
    struct slapi_filter *filter;
    char *generate;
    char *scope;
} dna_anchor;
typedef struct _defs configEntry;
static PRCList *config;
static PRRWLock *g_dna_cache_lock;

static void *_PluginID = NULL;
static char *_PluginDN = NULL;


/*
 * new value lock
 */
static Slapi_Mutex *g_new_value_lock;

/**
 *
 * DNA plug-in management functions
 *
 */
int ipa_dna_init(Slapi_PBlock * pb);
static int dna_start(Slapi_PBlock * pb);
static int dna_close(Slapi_PBlock * pb);
static int dna_postop_init(Slapi_PBlock * pb);

/**
 *
 * Local operation functions
 *
 */
static int loadPluginConfig();
static int parseConfigEntry(Slapi_Entry * e);
static void deleteConfig();
static void freeConfigEntry(configEntry ** entry);

/**
 *
 * helpers
 *
 */
static char *dna_get_dn(Slapi_PBlock * pb);
static int dna_dn_is_config(char *dn);
static int dna_get_next_value(configEntry * config_entry,
                              char **next_value_ret);

/**
 *
 * the ops (where the real work is done)
 *
 */
static int dna_config_check_post_op(Slapi_PBlock * pb);
static int dna_pre_op(Slapi_PBlock * pb, int modtype);
static int dna_mod_pre_op(Slapi_PBlock * pb);
static int dna_add_pre_op(Slapi_PBlock * pb);

/**
 * debug functions - global, for the debugger
 */
void dnaDumpConfig();
void dnaDumpConfigEntry(configEntry *);

/**
 * set the debug level
 */
#ifdef _WIN32
int *module_ldap_debug = 0;

void plugin_init_debug_level(int *level_ptr)
{
    module_ldap_debug = level_ptr;
}
#endif

/**
 *
 * Deal with cache locking
 *
 */
void dna_read_lock()
{
    PR_RWLock_Rlock(g_dna_cache_lock);
}

void dna_write_lock()
{
    PR_RWLock_Wlock(g_dna_cache_lock);
}

void dna_unlock()
{
    PR_RWLock_Unlock(g_dna_cache_lock);
}

/**
 *
 * Get the dna plug-in version
 *
 */
int dna_version()
{
    return DNA_PLUGIN_VERSION;
}

/**
 * Plugin identity mgmt
 */
void setPluginID(void *pluginID)
{
    _PluginID = pluginID;
}

void *getPluginID()
{
    return _PluginID;
}

void setPluginDN(char *pluginDN)
{
    _PluginDN = pluginDN;
}

char *getPluginDN()
{
    return _PluginDN;
}

/*
	dna_init
	-------------
	adds our callbacks to the list
*/
int ipa_dna_init(Slapi_PBlock * pb)
{
    int status = DNA_SUCCESS;
    char *plugin_identity = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> ipa_dna_init\n");

        /**
	 * Store the plugin identity for later use.
	 * Used for internal operations
	 */

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_identity);
    PR_ASSERT(plugin_identity);
    setPluginID(plugin_identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) dna_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) dna_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN,
                         (void *) dna_mod_pre_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN,
                         (void *) dna_add_pre_op) != 0 ||
        /* the config change checking post op */
        slapi_register_plugin("postoperation",  /* op type */
                              1,        /* Enabled */
                              "ipa_dna_init",   /* this function desc */
                              dna_postop_init,  /* init func for post op */
                              PLUGIN_DESC,      /* plugin desc */
                              NULL,     /* ? */
                              plugin_identity   /* access control */
        )
        ) {
        slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                        "ipa_dna_init: failed to register plugin\n");
        status = DNA_FAILURE;
    }

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- ipa_dna_init\n");
    return status;
}


static int dna_postop_init(Slapi_PBlock * pb)
{
    int status = DNA_SUCCESS;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
                         (void *) dna_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODRDN_FN,
                         (void *) dna_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN,
                         (void *) dna_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN,
                         (void *) dna_config_check_post_op) != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                        "dna_postop_init: failed to register plugin\n");
        status = DNA_FAILURE;
    }

    return status;
}

/*
	dna_start
	--------------
	Kicks off the config cache.
	It is called after dna_init.
*/
static int dna_start(Slapi_PBlock * pb)
{
    char *plugindn = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_start\n");

    config = &dna_anchor.list;
    g_dna_cache_lock = PR_NewRWLock(PR_RWLOCK_RANK_NONE, "dna");
    g_new_value_lock = slapi_new_mutex();

    if (!g_dna_cache_lock || !g_new_value_lock) {
        slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                        "dna_start: lock creation failed\n");

        return DNA_FAILURE;
    }

        /**
	 *	Get the plug-in target dn from the system
	 *	and store it for future use. This should avoid
	 *	hardcoding of DN's in the code.
	 */
    slapi_pblock_get(pb, SLAPI_TARGET_DN, &plugindn);
    if (plugindn == NULL || strlen(plugindn) == 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                        "dna_start: had to use hard coded config dn\n");
        plugindn = DNA_DN;
    } else {
        slapi_log_error(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                        "dna_start: config at %s\n", plugindn);

    }

    setPluginDN(plugindn);

        /**
	 * Load the config for our plug-in
	 */
    PR_INIT_CLIST(config);
    if (loadPluginConfig() != DNA_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                        "dna_start: unable to load plug-in configuration\n");
        return DNA_FAILURE;
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                    "dna: ready for service\n");
    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_start\n");

    return DNA_SUCCESS;
}

/*
	dna_close
	--------------
	closes down the cache
*/
static int dna_close(Slapi_PBlock * pb)
{
    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_close\n");

    deleteConfig();

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_close\n");

    return DNA_SUCCESS;
}

/*
 * config looks like this
 * - cn=myplugin
 * --- ou=posix
 * ------ cn=accounts
 * ------ cn=groups
 * --- cn=samba
 * --- cn=etc
 * ------ cn=etc etc
 */
static int loadPluginConfig()
{
    int status = DNA_SUCCESS;
    int result;
    int i;
    Slapi_PBlock *search_pb;
    Slapi_Entry **entries = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> loadPluginConfig\n");

    dna_write_lock();
    deleteConfig();

    search_pb = slapi_pblock_new();

    slapi_search_internal_set_pb(search_pb, DNA_DN, LDAP_SCOPE_SUBTREE,
                                 "objectclass=*", NULL, 0, NULL, NULL,
                                 getPluginID(), 0);
    slapi_search_internal_pb(search_pb);
    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

    if (status != DNA_SUCCESS) {
        status = DNA_SUCCESS;
        goto cleanup;
    }

    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);
    if (NULL == entries || entries[0] == NULL) {
        status = DNA_SUCCESS;
        goto cleanup;
    }

    for (i = 0; (entries[i] != NULL); i++) {
        status = parseConfigEntry(entries[i]);
    }

  cleanup:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    dna_unlock();
    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- loadPluginConfig\n");

    return status;
}

static int parseConfigEntry(Slapi_Entry * e)
{
    char *value = NULL;
    configEntry *entry = NULL;
    configEntry *config_entry = NULL;
    PRCList *list = NULL;
    int entry_added = 0;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> parseConfigEntry\n");

    entry = (configEntry *) slapi_ch_calloc(1, sizeof(configEntry));
    if (0 == entry)
        goto bail;

    value = slapi_entry_get_ndn(e);
    if (value) {
        entry->dn = strdup(value);
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dn [%s] \n", entry->dn, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_TYPE);
    if (value) {
        entry->type = value;
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaType [%s] \n", entry->type, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_NEXTVAL);
    if (value) {
        entry->nextval = strtoul(value, 0, 0);
        slapi_ch_free_string(&value);
        value = 0;
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaNextValue [%d] \n", entry->nextval, 0,
                    0);

    value = slapi_entry_attr_get_charptr(e, DNA_PREFIX);
    if (value) {
        entry->prefix = value;
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaPrefix [%s] \n", entry->prefix, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_INTERVAL);
    if (value) {
        entry->interval = strtoul(value, 0, 0);
        slapi_ch_free_string(&value);
        value = 0;
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaInterval [%s] \n", value, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_GENERATE);
    if (value) {
        entry->generate = value;
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaMagicRegen [%s] \n", entry->generate,
                    0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_FILTER);
    if (value) {
        entry->filter = slapi_str2filter(value);
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaFilter [%s] \n", value, 0, 0);

    slapi_ch_free_string(&value);
    value = 0;

    value = slapi_entry_attr_get_charptr(e, DNA_SCOPE);
    if (value) {
        char *canonical_dn = slapi_dn_normalize(value);
        entry->scope = canonical_dn;
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaScope [%s] \n", entry->scope, 0, 0);


        /**
	 * Finally add the entry to the list
	 * we group by type then by filter
	 * and finally sort by dn length with longer dn's
	 * first - this allows the scope checking
	 * code to be simple and quick and
	 * cunningly linear
	 */
    if (!PR_CLIST_IS_EMPTY(config)) {
        list = PR_LIST_HEAD(config);
        while (list != config) {
            config_entry = (configEntry *) list;

            if (slapi_attr_type_cmp(config_entry->type, entry->type, 1))
                goto next;

            if (slapi_filter_compare(config_entry->filter, entry->filter))
                goto next;

            if (slapi_dn_issuffix(entry->scope, config_entry->scope)) {
                PR_INSERT_BEFORE(&(entry->list), list);
                slapi_log_error(SLAPI_LOG_CONFIG,
                                DNA_PLUGIN_SUBSYSTEM,
                                "store [%s] before [%s] \n", entry->scope,
                                config_entry->scope, 0);
                entry_added = 1;
                break;
            }

          next:
            list = PR_NEXT_LINK(list);

            if (config == list) {
                /* add to tail */
                PR_INSERT_BEFORE(&(entry->list), list);
                slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                                "store [%s] at tail\n", entry->scope, 0,
                                0);
                entry_added = 1;
                break;
            }
        }
    } else {
        /* first entry */
        PR_INSERT_LINK(&(entry->list), config);
        slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                        "store [%s] at head \n", entry->scope, 0, 0);
        entry_added = 1;
    }

  bail:
    if (0 == entry_added) {
        slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                        "config entry [%s] skipped\n", entry->dn, 0, 0);
        freeConfigEntry(&entry);
    }

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- parseConfigEntry\n");

    return DNA_SUCCESS;
}

static void freeConfigEntry(configEntry ** entry)
{
    configEntry *e = *entry;

    if (e->dn) {
        slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                        "freeing config entry [%s]\n", e->dn, 0, 0);
        slapi_ch_free_string(&e->dn);
    }

    if (e->type)
        slapi_ch_free_string(&e->type);

    if (e->prefix)
        slapi_ch_free_string(&e->prefix);

    if (e->filter)
        slapi_filter_free(e->filter, 1);

    if (e->generate)
        slapi_ch_free_string(&e->generate);

    if (e->scope)
        slapi_ch_free_string(&e->scope);

    slapi_ch_free((void **) entry);
}

static void deleteConfigEntry(PRCList * entry)
{
    PR_REMOVE_LINK(entry);
    freeConfigEntry((configEntry **) & entry);
}

static void deleteConfig()
{
    PRCList *list;

    while (!PR_CLIST_IS_EMPTY(config)) {
        list = PR_LIST_HEAD(config);
        deleteConfigEntry(list);
    }

    return;
}


/****************************************************
	Helpers
****************************************************/

static char *dna_get_dn(Slapi_PBlock * pb)
{
    char *dn = 0;
    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_get_dn\n");

    if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn)) {
        slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                        "dna_get_dn: failed to get dn of changed entry");
        goto bail;
    }

/*        slapi_dn_normalize( dn );
*/
  bail:
    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_get_dn\n");

    return dn;
}

/* config check
        matching config dn or a descendent reloads config
*/
static int dna_dn_is_config(char *dn)
{
    int ret = 0;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_is_config\n");

    if (slapi_dn_issuffix(dn, getPluginDN())) {
        ret = 1;
    }

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_is_config\n");

    return ret;
}


/****************************************************
        Functions that actually do things other
        than config and startup
****************************************************/


/*
 * Perform ldap operationally atomic increment
 * Return the next value to be assigned
 * Method:
 * 1. retrieve entry
 * 2. remove current value, add new value in one operation
 * 3. if failed, and less than 3 times, goto 1
 */
static int dna_get_next_value(configEntry * config_entry,
                              char **next_value_ret)
{
    int ret = LDAP_SUCCESS;
    Slapi_DN *dn = 0;
    char *attrlist[3];
    Slapi_Entry *e = 0;
    int attempts = 0;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_get_next_value\n");

    /* get pre-requisites to search */
    dn = slapi_sdn_new_dn_byref(config_entry->dn);
    attrlist[0] = DNA_NEXTVAL;
    attrlist[1] = DNA_INTERVAL;
    attrlist[2] = 0;


    /* the operation is constructed such that race conditions
     * to increment the value are detected and avoided - one wins,
     * one loses - however, there is no need for the server to compete
     * with itself so we lock here
     */

    slapi_lock_mutex(g_new_value_lock);

    while (attempts < 3 && LDAP_SUCCESS == ret) {
        attempts++;

        /* do update */
        if (e) {
            slapi_entry_free(e);
            e = 0;
        }

        ret =
            slapi_search_internal_get_entry(dn, attrlist, &e,
                                            getPluginID());
        if (LDAP_SUCCESS == ret) {
            char *old_value;

            old_value = slapi_entry_attr_get_charptr(e, DNA_NEXTVAL);
            if (old_value) {
                LDAPMod mod_add;
                LDAPMod mod_delete;
                LDAPMod *mods[3];
                Slapi_PBlock *pb = slapi_pblock_new();
                char *delete_val[2];
                char *add_val[2];
                char new_value[16];
                char *interval = 0;

                mods[0] = &mod_delete;
                mods[1] = &mod_add;
                mods[2] = 0;

                if (0 == pb)
                    goto bail;

                interval = slapi_entry_attr_get_charptr(e, DNA_INTERVAL);
                if (0 == interval) {
                    slapi_pblock_destroy(pb);
                    slapi_ch_free_string(&old_value);
                    goto bail;
                }

                /* perform increment */

                sprintf(new_value, "%lu",
                        strtoul(interval, 0, 0) +
                        strtoul(old_value, 0, 0));

                delete_val[0] = old_value;
                delete_val[1] = 0;

                mod_delete.mod_op = LDAP_MOD_DELETE;
                mod_delete.mod_type = DNA_NEXTVAL;
                mod_delete.mod_values = delete_val;

                add_val[0] = new_value;
                add_val[1] = 0;

                mod_add.mod_op = LDAP_MOD_ADD;
                mod_add.mod_type = DNA_NEXTVAL;
                mod_add.mod_values = add_val;


                mods[0] = &mod_delete;
                mods[1] = &mod_add;
                mods[2] = 0;

                slapi_modify_internal_set_pb(pb, config_entry->dn,
                                             mods, 0, 0, getPluginID(), 0);

                slapi_modify_internal_pb(pb);

                slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

                slapi_pblock_destroy(pb);
                slapi_ch_free_string(&interval);

                if (LDAP_SUCCESS == ret) {
                    *next_value_ret = old_value;
                    break;
                } else {
                    slapi_ch_free_string(&old_value);
                    if (LDAP_NO_SUCH_ATTRIBUTE != ret) {
                        /* not the result of a race
                           to change the value
                         */
                        break;
                    } else
                        /* we lost the race to mod
                           try again
                         */
                        ret = LDAP_SUCCESS;
                }
            } else
                break;
        } else
            break;
    }

  bail:

    slapi_unlock_mutex(g_new_value_lock);

    if (dn)
        slapi_sdn_free(&dn);

    if (e)
        slapi_entry_free(e);

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_get_next_value\n");

    return ret;
}

/* for mods and adds:
	where dn's are supplied, the closest in scope
	is used as long as the type and filter
	are identical - otherwise all matches count
*/

static int dna_pre_op(Slapi_PBlock * pb, int modtype)
{
    char *dn = 0;
    PRCList *list = 0;
    configEntry *config_entry = 0;
    struct slapi_entry *e = 0;
    char *last_type = 0;
    char *value = 0;
    int generate = 0;
    Slapi_Mods *smods = 0;
    Slapi_Mod *smod = 0;
    LDAPMod **mods;
    int free_entry = 0;
    int ret = 0;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_pre_op\n");

    if (0 == (dn = dna_get_dn(pb)))
        goto bail;

    if (dna_dn_is_config(dn))
        goto bail;

    if (LDAP_CHANGETYPE_ADD == modtype) {
        slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e);
    } else {
        /* xxxPAR: Ideally SLAPI_MODIFY_EXISTING_ENTRY should be
         * available but it turns out that is only true if you are
         * a dbm backend pre-op plugin - lucky dbm backend pre-op
         * plugins.
         * I think that is wrong since the entry is useful for filter
         * tests and schema checks and this plugin shouldn't be limited
         * to a single backend type, but I don't want that fight right
         * now so we go get the entry here
         *
         slapi_pblock_get( pb, SLAPI_MODIFY_EXISTING_ENTRY, &e);
         */
        Slapi_DN *tmp_dn = slapi_sdn_new_dn_byref(dn);
        if (tmp_dn) {
            slapi_search_internal_get_entry(tmp_dn, 0, &e, getPluginID());
            slapi_sdn_free(&tmp_dn);
            free_entry = 1;
        }

        /* grab the mods - we'll put them back later with
         * our modifications appended
         */
        slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
        smods = slapi_mods_new();
        slapi_mods_init_passin(smods, mods);
    }

    if (0 == e)
        goto bailmod;

    dna_read_lock();

    if (!PR_CLIST_IS_EMPTY(config)) {
        list = PR_LIST_HEAD(config);

        while (list != config && LDAP_SUCCESS == ret) {
            config_entry = (configEntry *) list;

            /* did we already service this type? */
            if (last_type) {
                if (!slapi_attr_type_cmp(config_entry->type, last_type, 1))
                    goto next;
            }

            /* is the entry in scope? */
            if (config_entry->scope) {
                if (!slapi_dn_issuffix(dn, config_entry->scope))
                    goto next;
            }

            /* does the entry match the filter? */
            if (config_entry->filter) {
                if (LDAP_SUCCESS != slapi_vattr_filter_test(pb,
                                                            e,
                                                            config_entry->
                                                            filter, 0))
                    goto next;
            }


            if (LDAP_CHANGETYPE_ADD == modtype) {
                /* does attribute contain the magic value
                   or is the type not there?
                 */
                value =
                    slapi_entry_attr_get_charptr(e, config_entry->type);
                if ((value
                     && !slapi_UTF8CASECMP(config_entry->generate, value))
                    || 0 == value) {
                    generate = 1;
                }
            } else {
                /* check mods for magic value */
                Slapi_Mod *next_mod = slapi_mod_new();
                smod = slapi_mods_get_first_smod(smods, next_mod);
                while (smod) {
                    char *type = (char *)
                        slapi_mod_get_type(smod);

                    if (slapi_attr_types_equivalent(type,
                                                    config_entry->type)) {
                        struct berval *bv =
                            slapi_mod_get_first_value(smod);
                        int len = strlen(config_entry->generate);


                        if (len == bv->bv_len) {
                            if (!slapi_UTF8NCASECMP(bv->bv_val,
                                                    config_entry->
                                                    generate, len))

                                generate = 1;
                            break;
                        }
                    }

                    slapi_mod_done(next_mod);
                    smod = slapi_mods_get_next_smod(smods, next_mod);
                }

                slapi_mod_free(&next_mod);
            }

            if (generate) {
                char *new_value;
                int len;

                /* create the value to add */
                if ((ret = dna_get_next_value(config_entry, &value)))
                    break;

                len = strlen(value) + 1;
                if (config_entry->prefix) {
                    len += strlen(config_entry->prefix);
                }

                new_value = slapi_ch_malloc(len);

                if (config_entry->prefix) {
                    strcpy(new_value, config_entry->prefix);
                    strcat(new_value, value);
                } else
                    strcpy(new_value, value);

                /* do the mod */
                if (LDAP_CHANGETYPE_ADD == modtype) {
                    /* add - add to entry */
                    slapi_entry_attr_set_charptr(e,
                                                 config_entry->type,
                                                 new_value);
                } else {
                    /* mod - add to mods */
                    slapi_mods_add_string(smods,
                                          LDAP_MOD_REPLACE,
                                          config_entry->type, new_value);
                }

                /* free up */
                slapi_ch_free_string(&value);
                slapi_ch_free_string(&new_value);

                /* make sure we don't generate for this
                 * type again
                 */
                if (LDAP_SUCCESS == ret) {
                    last_type = config_entry->type;
                }

                generate = 0;
            }
          next:
            list = PR_NEXT_LINK(list);
        }
    }

    dna_unlock();

  bailmod:
    if (LDAP_CHANGETYPE_MODIFY == modtype) {
        /* these are the mods you made, really,
         * I didn't change them, honest, just had a quick look
         */
        mods = slapi_mods_get_ldapmods_passout(smods);
        slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods);
        slapi_mods_free(&smods);
    }

  bail:

    if (free_entry && e)
        slapi_entry_free(e);

    if (ret)
        slapi_log_error(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                        "dna_pre_op: operation failure [%d]\n", ret);

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_pre_op\n");

    return ret;
}


static int dna_add_pre_op(Slapi_PBlock * pb)
{
    return dna_pre_op(pb, LDAP_CHANGETYPE_ADD);
}

static int dna_mod_pre_op(Slapi_PBlock * pb)
{
    return dna_pre_op(pb, LDAP_CHANGETYPE_MODIFY);
}

static int dna_config_check_post_op(Slapi_PBlock * pb)
{
    char *dn;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_config_check_post_op\n");

    if ((dn = dna_get_dn(pb))) {
        if (dna_dn_is_config(dn))
            loadPluginConfig();
    }

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_config_check_post_op\n");

    return 0;
}

/****************************************************
	End of
	Functions that actually do things other
	than config and startup
****************************************************/

/**
 * debug functions to print config
 */
void dnaDumpConfig()
{
    PRCList *list;

    dna_read_lock();

    if (!PR_CLIST_IS_EMPTY(config)) {
        list = PR_LIST_HEAD(config);
        while (list != config) {
            dnaDumpConfigEntry((configEntry *) list);
            list = PR_NEXT_LINK(list);
        }
    }

    dna_unlock();
}


void dnaDumpConfigEntry(configEntry * entry)
{
    printf("<- type --------------> %s\n", entry->type);
    printf("<---- prefix ---------> %s\n", entry->prefix);
    printf("<---- next value -----> %lu\n", entry->nextval);
    printf("<---- interval -------> %lu\n", entry->interval);
    printf("<---- generate flag --> %s\n", entry->generate);
}
