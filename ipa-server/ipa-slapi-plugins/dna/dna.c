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
#include <errno.h>
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
#define DNA_PLUGIN_VERSION 0x00020000

/* temporary */
#define DNA_DN "cn=ipa-dna,cn=plugins,cn=config"

#define DNA_SUCCESS 0
#define DNA_FAILURE -1

/**
 * DNA config types
 */
#define DNA_TYPE            "dnaType"
#define DNA_PREFIX          "dnaPrefix"
#define DNA_NEXTVAL         "dnaNextValue"
#define DNA_INTERVAL        "dnaInterval"
#define DNA_GENERATE        "dnaMagicRegen"
#define DNA_FILTER          "dnaFilter"
#define DNA_SCOPE           "dnaScope"

/* since v2 */
#define DNA_MAXVAL          "dnaMaxValue"
#define DNA_SHARED_CFG_DN   "dnaSharedCfgDN"

/* Shared Config */
#define DNA_GLOBAL_RANGE    "dnaGlobalRange"
#define DNA_RANGE           "dnaRange"
#define DNA_MAX_RANGE_SIZE  "dnaMaxRangeSize"
#define DNA_CHUNK_SIZE      "dnaChunkSize"



#define FEATURE_DESC    "IPA Distributed Numeric Assignment"
#define PLUGIN_DESC     "IPA Distributed Numeric Assignment plugin"

static Slapi_PluginDesc pdesc = { FEATURE_DESC,
    "FreeIPA project", "FreeIPA/1.0",
    PLUGIN_DESC
};


/**
 * linked list of config entries
 */

struct configEntry {
    PRCList list;
    char *dn;
    char *type;
    char *prefix;
    unsigned long nextval;
    unsigned long interval;
    unsigned long maxval;
    char *filter;
    struct slapi_filter *slapi_filter;
    char *generate;
    char *scope;
};

static PRCList *dna_global_config = NULL;
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
static void freeConfigEntry(struct configEntry ** entry);

/**
 *
 * helpers
 *
 */
static char *dna_get_dn(Slapi_PBlock * pb);
static int dna_dn_is_config(char *dn);
static int dna_get_next_value(struct configEntry * config_entry,
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
void dnaDumpConfigEntry(struct configEntry *);

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
    if (NULL == plugindn || 0 == strlen(plugindn)) {
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
    dna_global_config = (struct configEntry *)
        slapi_ch_calloc(1, sizeof(struct configEntry));
    PR_INIT_CLIST(dna_global_config);

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

    slapi_ch_free((void **)&dna_global_config);

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "<-- dna_close\n");

    return DNA_SUCCESS;
}

/*
 * config looks like this
 * - cn=myplugin
 * --- cn=posix
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

    slapi_search_internal_set_pb(search_pb, getPluginDN(),
                                 LDAP_SCOPE_SUBTREE, "objectclass=*",
                                 NULL, 0, NULL, NULL, getPluginID(), 0);
    slapi_search_internal_pb(search_pb);
    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

    if (LDAP_SUCCESS != result) {
        status = DNA_FAILURE;
        goto cleanup;
    }

    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);
    if (NULL == entries || NULL == entries[0]) {
        status = DNA_SUCCESS;
        goto cleanup;
    }

    for (i = 0; (entries[i] != NULL); i++) {
        status = parseConfigEntry(entries[i]);
        if (DNA_SUCCESS != status)
            break;
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
    char *value;
    struct configEntry *entry;
    struct configEntry *config_entry;
    PRCList *list;
    int entry_added = 0;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> parseConfigEntry\n");

    entry = (struct configEntry *)
	slapi_ch_calloc(1, sizeof(struct configEntry));
    if (NULL == entry)
        goto bail;

    value = slapi_entry_get_ndn(e);
    if (value) {
        entry->dn = strdup(value);
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dn [%s]\n", entry->dn, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_TYPE);
    if (value) {
        entry->type = value;
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaType [%s]\n", entry->type, 0, 0);

    /* FIXME: check the attribute type, it must suport matching rules and be
     * indexed, these are requirements and failure to meet them should result in
     * the configuration to be disarded and an ERROR logged prominently */

    value = slapi_entry_attr_get_charptr(e, DNA_NEXTVAL);
    if (value) {
        entry->nextval = strtoul(value, 0, 0);
        slapi_ch_free_string(&value);
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaNextValue [%d]\n", entry->nextval, 0,
                    0);

    value = slapi_entry_attr_get_charptr(e, DNA_PREFIX);
    if (value && value[0]) {
        entry->prefix = value;
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaPrefix [%s]\n", entry->prefix, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_INTERVAL);
    if (value) {
        entry->interval = strtoul(value, 0, 0);
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaInterval [%s]\n", value, 0, 0);

    slapi_ch_free_string(&value);

    value = slapi_entry_attr_get_charptr(e, DNA_GENERATE);
    if (value) {
        entry->generate = value;
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaMagicRegen [%s]\n", entry->generate,
                    0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_FILTER);
    if (value) {
        entry->filter = value;
        entry->slapi_filter = slapi_str2filter(value);
    } else
        goto bail;

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaFilter [%s]\n", value, 0, 0);

    value = slapi_entry_attr_get_charptr(e, DNA_SCOPE);
    if (value) {
        entry->scope = slapi_dn_normalize(value);
    }

    slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                    "----------> dnaScope [%s]\n", entry->scope, 0, 0);

    /* optional, if not specified set -1  which is converted to the max unisgnee
     * value */
    value = slapi_entry_attr_get_charptr(e, DNA_MAXVAL);
    if (value) {
            entry->maxval = strtoul(value, 0, 0);

            slapi_log_error(SLAPI_LOG_CONFIG, DNA_PLUGIN_SUBSYSTEM,
                        "----------> dnaMaxValue [%ld]\n", value, 0, 0);

            slapi_ch_free_string(&value);
    } else
        entry->maxval = -1;


    /**
     * Finally add the entry to the list
     * we group by type then by filter
     * and finally sort by dn length with longer dn's
     * first - this allows the scope checking
     * code to be simple and quick and
     * cunningly linear
     */
    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        while (list != dna_global_config) {
            config_entry = (struct configEntry *) list;

            if (slapi_attr_type_cmp(config_entry->type, entry->type, 1))
                goto next;

            if (slapi_filter_compare(config_entry->slapi_filter,
                                     entry->slapi_filter))
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

            if (dna_global_config == list) {
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
        PR_INSERT_LINK(&(entry->list), dna_global_config);
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

static void freeConfigEntry(struct configEntry ** entry)
{
    struct configEntry *e = *entry;

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
        slapi_ch_free_string(&e->filter);

    if (e->slapi_filter)
        slapi_filter_free(e->slapi_filter, 1);

    if (e->generate)
        slapi_ch_free_string(&e->generate);

    if (e->scope)
        slapi_ch_free_string(&e->scope);

    slapi_ch_free((void **) entry);
}

static void deleteConfigEntry(PRCList * entry)
{
    PR_REMOVE_LINK(entry);
    freeConfigEntry((struct configEntry **) & entry);
}

static void deleteConfig()
{
    PRCList *list;

    while (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        deleteConfigEntry(list);
    }

    return;
}

/****************************************************
    Distributed ranges Helpers
****************************************************/

static int dna_fix_maxval(Slapi_DN *dn, unsigned long *cur, unsigned long *max)
{
    /* TODO: check the main partition to see if another range
     * is available, and set the new local configuration
     * accordingly.
     * If a new range is not available run the retrieval task
     * and simply return error
     */

    return LDAP_OPERATIONS_ERROR;
}

static void dna_notice_allocation(Slapi_DN *dn, unsigned long new)
{
    /* TODO: check if we passed a new chunk threshold and update
     * the shared configuration on the public partition.
     */

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

#define DNA_LDAP_TAG_SK_REVERSE 0x81L

static LDAPControl *dna_build_sort_control(const char *attr)
{
    LDAPControl *ctrl;
    BerElement *ber;
    int rc;

    ber = ber_alloc();
    if (NULL == ber)
        return NULL;

    rc = ber_printf(ber, "{{stb}}", attr, DNA_LDAP_TAG_SK_REVERSE, 1);
    if (-1 == rc) {
        ber_free(ber, 1);
        return NULL;
    }

    rc = slapi_build_control(LDAP_CONTROL_SORTREQUEST, ber, 1, &ctrl);

    ber_free(ber, 1);

    if (LDAP_SUCCESS != rc)
         return NULL;

    return ctrl;
}

/****************************************************
        Functions that actually do things other
        than config and startup
****************************************************/

/* we do search all values between newval and maxval asking the
 * server to sort them, then we check the first free spot and
 * use it as newval */
static int dna_first_free_value(struct configEntry *config_entry,
                                unsigned long *newval,
                                unsigned long maxval,
				unsigned long increment)
{
    Slapi_Entry **entries = NULL;
    Slapi_PBlock *pb = NULL;
    LDAPControl **ctrls;
    char *attrs[2];
    char *filter;
    char *prefix;
    char *type;
    int preflen;
    int result, status;
    unsigned long tmpval, sval, i;
    char *strval = NULL;

    prefix = config_entry->prefix;
    type = config_entry->type;
    tmpval = *newval;

    attrs[0] = type;
    attrs[1] = NULL;

    ctrls = (LDAPControl **)slapi_ch_calloc(2, sizeof(LDAPControl));
    if (NULL == ctrls)
        return LDAP_OPERATIONS_ERROR;

    ctrls[0] = dna_build_sort_control(config_entry->type);
    if (NULL == ctrls[0]) {
        slapi_ch_free((void **)&ctrls);
        return LDAP_OPERATIONS_ERROR;
    }

    filter = slapi_ch_smprintf("(&%s(&(%s>=%s%llu)(%s<=%s%llu)))",
                               config_entry->filter,
                               type, prefix?prefix:"", tmpval,
                               type, prefix?prefix:"", maxval);
    if (NULL == filter) {
        ldap_control_free(ctrls[0]);
        slapi_ch_free((void **)&ctrls);
        return LDAP_OPERATIONS_ERROR;
    }

    pb = slapi_pblock_new();
    if (NULL == pb) {
        ldap_control_free(ctrls[0]);
        slapi_ch_free((void **)&ctrls);
        slapi_ch_free_string(&filter);
        return LDAP_OPERATIONS_ERROR;
    }

    slapi_search_internal_set_pb(pb, config_entry->scope,
                                 LDAP_SCOPE_SUBTREE, filter,
                                 attrs, 0, ctrls,
                                 NULL, getPluginID(), 0);
    slapi_search_internal_pb(pb);
/*
    ldap_control_free(ctrls[0]);
*/
    slapi_ch_free_string(&filter);

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &result);
    if (LDAP_SUCCESS != result) {
        status = LDAP_OPERATIONS_ERROR;
        goto cleanup;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);

    if (NULL == entries || NULL == entries[0]) {
        /* no values means we already have a good value */
        status = LDAP_SUCCESS;
        goto cleanup;
    }

    /* entries are sorted and filtered for value >= tval therefore if the
     * first one does not match tval it means that the value is free,
     * otherwise we need to cycle through values until we find a mismatch,
     * the first mismatch is the first free pit */

    preflen = prefix?strlen(prefix):0;
    sval = 0;
    for (i = 0; NULL != entries[i]; i++) {
        strval = slapi_entry_attr_get_charptr(entries[i], type);
        if (preflen) {
            if (strlen(strval) <= preflen) {
                /* something very wrong here ... */
                status = LDAP_OPERATIONS_ERROR;
                goto cleanup;
            }
            strval = &strval[preflen-1];
        }

        errno = 0;
        sval = strtoul(strval, 0, 0);
        if (errno) {
            /* something very wrong here ... */
            status = LDAP_OPERATIONS_ERROR;
            goto cleanup;
        }
        slapi_ch_free_string(&strval);

        if (tmpval != sval)
            break;

        if (maxval < sval)
            break;

        tmpval += increment;
    }

    *newval = tmpval;
    status = LDAP_SUCCESS;

cleanup:
    slapi_ch_free_string(&strval);
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);

    return status;
}

/*
 * Perform ldap operationally atomic increment
 * Return the next value to be assigned
 * Method:
 * 1. retrieve entry
 * 2. do increment operations
 * 3. remove current value, add new value in one operation
 * 4. if failed, and less than 3 times, goto 1
 */
static int dna_get_next_value(struct configEntry *config_entry,
                                 char **next_value_ret)
{
    Slapi_PBlock *pb = NULL;
    char *old_value = NULL;
    Slapi_Entry *e = NULL;
    Slapi_DN *dn = NULL;
    char *attrlist[4];
    int attempts;
    int ret;

    slapi_log_error(SLAPI_LOG_TRACE, DNA_PLUGIN_SUBSYSTEM,
                    "--> dna_get_next_value\n");

    /* get pre-requisites to search */
    dn = slapi_sdn_new_dn_byref(config_entry->dn);
    attrlist[0] = DNA_NEXTVAL;
    attrlist[1] = DNA_MAXVAL;
    attrlist[2] = DNA_INTERVAL;
    attrlist[3] = NULL;


    /* the operation is constructed such that race conditions
     * to increment the value are detected and avoided - one wins,
     * one loses - however, there is no need for the server to compete
     * with itself so we lock here
     */

    slapi_lock_mutex(g_new_value_lock);

    for (attempts = 0; attempts < 3; attempts++) {

        LDAPMod mod_add;
        LDAPMod mod_delete;
        LDAPMod *mods[3];
        char *delete_val[2];
        char *add_val[2];
        char new_value[16];
        char *interval;
        char *max_value;
        unsigned long increment = 1; /* default increment */
        unsigned long setval = 0;
        unsigned long newval = 0;
        unsigned long maxval = -1;
        int result;

        /* do update */
        ret = slapi_search_internal_get_entry(dn, attrlist, &e,
                                              getPluginID());
        if (LDAP_SUCCESS != ret) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        old_value = slapi_entry_attr_get_charptr(e, DNA_NEXTVAL);
        if (NULL == old_value) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        setval = strtoul(old_value, 0, 0);

        max_value = slapi_entry_attr_get_charptr(e, DNA_MAXVAL);
        if (max_value) {
            maxval = strtoul(max_value, 0, 0);
            slapi_ch_free_string(&max_value);
        }

        /* if not present the default is 1 */
        interval = slapi_entry_attr_get_charptr(e, DNA_INTERVAL);
        if (NULL != interval) {
            increment = strtoul(interval, 0, 0);
        }

        slapi_entry_free(e);
        e = NULL;

        /* check the value is actually in range */

        /* verify the new value is actually free and get the first
         * one free if not*/
        ret = dna_first_free_value(config_entry, &setval, maxval, increment);
        if (LDAP_SUCCESS != ret)
            goto done;

        /* try for a new range or fail */
        if (setval > maxval) {
            ret = dna_fix_maxval(dn, &setval, &maxval);
            if (LDAP_SUCCESS != ret) {
                slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                                "dna_get_next_value: no more IDs available!!\n");
                goto done;
            }

            /* verify the new value is actually free and get the first
             * one free if not */
            ret = dna_first_free_value(config_entry, &setval, maxval, increment);
            if (LDAP_SUCCESS != ret)
                goto done;
        }

        if (setval > maxval) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        newval = setval + increment;

        /* try for a new range or fail */
        if (newval > maxval) {
            ret = dna_fix_maxval(dn, &newval, &maxval);
            if (LDAP_SUCCESS != ret) {
                slapi_log_error(SLAPI_LOG_FATAL, DNA_PLUGIN_SUBSYSTEM,
                                "dna_get_next_value: no more IDs available!!\n");
                goto done;
            }
        }

        /* try to set the new value */

        sprintf(new_value, "%llu", newval);

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

        pb = slapi_pblock_new();
        if (NULL == pb) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        slapi_modify_internal_set_pb(pb, config_entry->dn,
                                     mods, 0, 0, getPluginID(), 0);

        slapi_modify_internal_pb(pb);

        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

        slapi_pblock_destroy(pb);
        pb = NULL;
        slapi_ch_free_string(&interval);
        slapi_ch_free_string(&old_value);

        if (LDAP_SUCCESS == ret) {
            *next_value_ret = slapi_ch_smprintf("%llu", setval);
            if (NULL == *next_value_ret) {
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            dna_notice_allocation(dn, newval);
            goto done;
        }

        if (LDAP_NO_SUCH_ATTRIBUTE != ret) {
            /* not the result of a race
               to change the value
             */
            goto done;
        }
    }

  done:

    slapi_unlock_mutex(g_new_value_lock);

    if (LDAP_SUCCESS != ret)
        slapi_ch_free_string(&old_value);

    if (dn)
        slapi_sdn_free(&dn);

    if (e)
        slapi_entry_free(e);

    if (pb)
        slapi_pblock_destroy(pb);

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
    struct configEntry *config_entry = 0;
    struct slapi_entry *e = 0;
    char *last_type = 0;
    char *value = 0;
    int generate = 0;
    Slapi_Mods *smods = 0;
    Slapi_Mod *smod = 0;
    LDAPMod **mods;
    int free_entry = 0;
    char *errstr = NULL;
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

    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);

        while (list != dna_global_config && LDAP_SUCCESS == ret) {
            config_entry = (struct configEntry *) list;

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
            if (config_entry->slapi_filter) {
                if (LDAP_SUCCESS != slapi_vattr_filter_test(pb,
                                                            e,
                                                            config_entry->
                                                            slapi_filter, 0))
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
                                                    config_entry->generate,
                                                    len))

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
                ret = dna_get_next_value(config_entry, &value);
                if (DNA_SUCCESS != ret) {
                    errstr = slapi_ch_smprintf("Allocation of a new value for"
                                               " %s failed! Unable to proceed.",
                                               config_entry->type);
                    break;
                }

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

    if (ret) {
        slapi_log_error(SLAPI_LOG_PLUGIN, DNA_PLUGIN_SUBSYSTEM,
                        "dna_pre_op: operation failure [%d]\n", ret);
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
        slapi_ch_free(&errstr);
        ret = DNA_FAILURE;
    }

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

    if (!PR_CLIST_IS_EMPTY(dna_global_config)) {
        list = PR_LIST_HEAD(dna_global_config);
        while (list != dna_global_config) {
            dnaDumpConfigEntry((struct configEntry *) list);
            list = PR_NEXT_LINK(list);
        }
    }

    dna_unlock();
}


void dnaDumpConfigEntry(struct configEntry * entry)
{
    printf("<- type --------------> %s\n", entry->type);
    printf("<---- prefix ---------> %s\n", entry->prefix);
    printf("<---- next value -----> %lu\n", entry->nextval);
    printf("<---- interval -------> %lu\n", entry->interval);
    printf("<---- generate flag --> %s\n", entry->generate);
}
