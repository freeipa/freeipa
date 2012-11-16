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
 * Copyright (C) 2010 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

/**
 * IPA MODRDN plug-in
 */
#include <string.h>
#include <stdbool.h>
#include "slapi-plugin.h"
#include "nspr.h"
#include "prclist.h"
#include <pthread.h>

#include "util.h"

#define IPA_PLUGIN_NAME "ipa-modrdn-plugin"
#define IPAMODRDN_PLUGIN_VERSION 0x00010000

#define IPAMODRDN_DN "cn=IPA MODRDN,cn=plugins,cn=config" /* temporary */

/**
 * IPA MODRDN config types
 */
#define IPAMODRDN_SATTR            "ipaModRDNsourceAttr"
#define IPAMODRDN_TATTR            "ipaModRDNtargetAttr"
#define IPAMODRDN_PREFIX           "ipaModRDNprefix"
#define IPAMODRDN_SUFFIX           "ipaModRDNsuffix"
#define IPAMODRDN_FILTER           "ipaModRDNfilter"
#define IPAMODRDN_SCOPE            "ipaModRDNscope"

#define IPAMODRDN_FEATURE_DESC      "IPA MODRDN"
#define IPAMODRDN_PLUGIN_DESC       "IPA MODRDN plugin"
#define IPAMODRDN_POSTOP_DESC       "IPA MODRDN postop plugin"

static Slapi_PluginDesc pdesc = {
    IPAMODRDN_FEATURE_DESC,
    "Red Hat, Inc.",
    "1.0",
    IPAMODRDN_PLUGIN_DESC
};

/**
 * linked list of config entries
 */

struct configEntry {
    PRCList list;
    char *dn;
    char *sattr;
    char *tattr;
    char *prefix;
    char *suffix;
    char *filter;
    Slapi_Filter *slapi_filter;
    char *scope;
};

static PRCList *ipamodrdn_global_config = NULL;
static pthread_rwlock_t g_ipamodrdn_cache_lock;

static void *_PluginID = NULL;
static char *_PluginDN = NULL;

static int g_plugin_started = 0;


/**
 *
 * management functions
 *
 */
int ipamodrdn_init(Slapi_PBlock * pb);
static int ipamodrdn_start(Slapi_PBlock * pb);
static int ipamodrdn_close(Slapi_PBlock * pb);

/**
 *
 * Local operation functions
 *
 */
static int ipamodrdn_load_plugin_config(void);
static int ipamodrdn_parse_config_entry(Slapi_Entry * e, bool apply);
static void ipamodrdn_delete_config(void);
static void ipamodrdn_free_config_entry(struct configEntry ** entry);

/**
 *
 * helpers
 *
 */
static char *ipamodrdn_get_dn(Slapi_PBlock * pb);
static int ipamodrdn_dn_is_config(char *dn);

/**
 *
 * the ops (where the real work is done)
 *
 */
static int ipamodrdn_config_check_post_op(Slapi_PBlock * pb);
static int ipamodrdn_post_op(Slapi_PBlock * pb);

/**
 * debug functions - global, for the debugger
 */
void ipamodrdn_dump_config(void);
void ipamodrdn_dump_config_entry(struct configEntry *);

/**
 *
 * Deal with cache locking
 *
 */
void ipamodrdn_read_lock(void)
{
    pthread_rwlock_rdlock(&g_ipamodrdn_cache_lock);
}

void ipamodrdn_write_lock(void)
{
    pthread_rwlock_wrlock(&g_ipamodrdn_cache_lock);
}

void ipamodrdn_unlock(void)
{
    pthread_rwlock_unlock(&g_ipamodrdn_cache_lock);
}

/**
 *
 * Get the plug-in version
 *
 */
int ipamodrdn_version(void)
{
    return IPAMODRDN_PLUGIN_VERSION;
}

/**
 * Plugin identity mgmt
 */
void setPluginID(void *pluginID)
{
    _PluginID = pluginID;
}

void *getPluginID(void)
{
    return _PluginID;
}

void setPluginDN(char *pluginDN)
{
    _PluginDN = pluginDN;
}

char *getPluginDN(void)
{
    return _PluginDN;
}

/*
	ipamodrdn_init
	-------------
	adds our callbacks to the list
*/
int
ipamodrdn_init(Slapi_PBlock *pb)
{
    int status = EOK;
    char *plugin_identity = NULL;
    Slapi_Entry *plugin_entry = NULL;
    char *plugin_type = NULL;
    int delfn = SLAPI_PLUGIN_POST_DELETE_FN;
    int mdnfn = SLAPI_PLUGIN_POST_MODRDN_FN;
    int modfn = SLAPI_PLUGIN_POST_MODIFY_FN;
    int addfn = SLAPI_PLUGIN_POST_ADD_FN;

    LOG_TRACE("--in-->\n");

        /**
	 * Store the plugin identity for later use.
	 * Used for internal operations
	 */

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_identity);
    PR_ASSERT(plugin_identity);
    setPluginID(plugin_identity);

    if ((slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &plugin_entry) == 0) &&
        plugin_entry &&
        (plugin_type = slapi_entry_attr_get_charptr(plugin_entry, "nsslapd-plugintype")) &&
        plugin_type && strstr(plugin_type, "betxn"))
    {
        addfn = SLAPI_PLUGIN_BE_TXN_POST_ADD_FN;
        mdnfn = SLAPI_PLUGIN_BE_TXN_POST_MODRDN_FN;
        delfn = SLAPI_PLUGIN_BE_TXN_POST_DELETE_FN;
        modfn = SLAPI_PLUGIN_BE_TXN_POST_MODIFY_FN;
    }
    slapi_ch_free_string(&plugin_type);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) ipamodrdn_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipamodrdn_close) != 0 ||
        slapi_pblock_set(pb, addfn,
                         (void *) ipamodrdn_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, mdnfn,
                         (void *) ipamodrdn_post_op) != 0 ||
        slapi_pblock_set(pb, delfn,
                         (void *) ipamodrdn_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, modfn,
                         (void *) ipamodrdn_config_check_post_op) != 0) {
        LOG_FATAL("failed to register plugin\n");
        status = EFAIL;
    }

    LOG_TRACE("<--out--\n");
    return status;
}


/*
	ipamodrdn_start
	--------------
	Kicks off the config cache.
	It is called after ipamodrdn_init.
*/
static int
ipamodrdn_start(Slapi_PBlock * pb)
{
    char *plugindn = NULL;

    LOG_TRACE("--in-->\n");

    /* Check if we're already started */
    if (g_plugin_started) {
        goto done;
    }

    if (pthread_rwlock_init(&g_ipamodrdn_cache_lock, NULL) != 0) {
        LOG_FATAL("lock creation failed\n");

        return EFAIL;
    }

    /**
	 *	Get the plug-in target dn from the system
	 *	and store it for future use. This should avoid
	 *	hardcoding of DN's in the code.
	 */
    slapi_pblock_get(pb, SLAPI_TARGET_DN, &plugindn);
    if (NULL == plugindn || 0 == strlen(plugindn)) {
        LOG("had to use hard coded config dn\n");
        plugindn = IPAMODRDN_DN;
    } else {
        LOG("config at %s\n", plugindn);

    }

    setPluginDN(plugindn);

    /*
     * Load the config for our plug-in
     */
    ipamodrdn_global_config = (PRCList *)
        slapi_ch_calloc(1, sizeof(struct configEntry));
    PR_INIT_CLIST(ipamodrdn_global_config);

    if (ipamodrdn_load_plugin_config() != EOK) {
        LOG_FATAL("unable to load plug-in configuration\n");
        return EFAIL;
    }

    g_plugin_started = 1;
    LOG("ready for service\n");
    LOG_TRACE("<--out--\n");

done:
    return EOK;
}

/*
	ipamodrdn_close
	--------------
	closes down the cache
*/
static int
ipamodrdn_close(Slapi_PBlock * pb)
{
    LOG_TRACE( "--in-->\n");

    ipamodrdn_delete_config();

    slapi_ch_free((void **)&ipamodrdn_global_config);

    LOG_TRACE("<--out--\n");

    return EOK;
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
static int
ipamodrdn_load_plugin_config(void)
{
    int status = EOK;
    int result;
    int i;
    Slapi_PBlock *search_pb;
    Slapi_Entry **entries = NULL;

    LOG_TRACE("--in-->\n");

    ipamodrdn_write_lock();
    ipamodrdn_delete_config();

    search_pb = slapi_pblock_new();

    slapi_search_internal_set_pb(search_pb, getPluginDN(),
                                 LDAP_SCOPE_SUBTREE, "objectclass=*",
                                 NULL, 0, NULL, NULL, getPluginID(), 0);
    slapi_search_internal_pb(search_pb);
    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

    if (LDAP_SUCCESS != result) {
        status = EFAIL;
        goto cleanup;
    }

    slapi_pblock_get(search_pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES,
                     &entries);
    if (NULL == entries || NULL == entries[0]) {
        status = EOK;
        goto cleanup;
    }

    for (i = 0; (entries[i] != NULL); i++) {
        /* We don't care about the status here because we may have
         * some invalid config entries, but we just want to continue
         * looking for valid ones. */
        ipamodrdn_parse_config_entry(entries[i], true);
    }

  cleanup:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    ipamodrdn_unlock();
    LOG_TRACE("<--out--\n");

    return status;
}

/*
 * ipamodrdn_parse_config_entry()
 *
 * Parses a single config entry.  If apply is non-zero, then
 * we will load and start using the new config.  You can simply
 * validate config without making any changes by setting apply
 * to 0.
 *
 * Returns EOK if the entry is valid and EFAIL
 * if it is invalid.
 */
static int
ipamodrdn_parse_config_entry(Slapi_Entry * e, bool apply)
{
    char *value;
    struct configEntry *entry = NULL;
    struct configEntry *config_entry;
    PRCList *list;
    int entry_added = 0;
    int ret = EOK;

    LOG_TRACE("--in-->\n");

    /* If this is the main MODRDN plug-in config entry, just bail. */
    if (strcasecmp(getPluginDN(), slapi_entry_get_ndn(e)) == 0) {
        ret = EFAIL;
        goto bail;
    }

    entry = (struct configEntry *)
    slapi_ch_calloc(1, sizeof(struct configEntry));
    if (NULL == entry) {
        ret = EFAIL;
        goto bail;
    }

    value = slapi_entry_get_ndn(e);
    if (value) {
        entry->dn = slapi_ch_strdup(value);
    }

    LOG_CONFIG("----------> dn [%s]\n", entry->dn);

    entry->sattr = slapi_entry_attr_get_charptr(e, IPAMODRDN_SATTR);
    if (!entry->sattr) {
        LOG_FATAL("The %s config setting is required for %s.\n",
                  IPAMODRDN_SATTR, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAMODRDN_SATTR, entry->sattr);

    entry->tattr = slapi_entry_attr_get_charptr(e, IPAMODRDN_TATTR);
    if (!entry->tattr) {
        LOG_FATAL("The %s config setting is required for %s.\n",
                  IPAMODRDN_TATTR, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAMODRDN_TATTR, entry->tattr);

    value = slapi_entry_attr_get_charptr(e, IPAMODRDN_PREFIX);
    if (value && value[0]) {
        entry->prefix = value;
    } else {
        entry->prefix = slapi_ch_strdup("");
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAMODRDN_PREFIX, entry->prefix);

    value = slapi_entry_attr_get_charptr(e, IPAMODRDN_SUFFIX);
    if (value && value[0]) {
        entry->suffix = value;
    } else {
        entry->suffix = slapi_ch_strdup("");
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAMODRDN_SUFFIX, entry->suffix);

    value = slapi_entry_attr_get_charptr(e, IPAMODRDN_FILTER);
    if (value) {
        entry->filter = value;
        if (NULL == (entry->slapi_filter = slapi_str2filter(value))) {
            LOG_FATAL("Error: Invalid search filter in entry [%s]: [%s]\n",
                      entry->dn, value);
            ret = EFAIL;
            goto bail;
        }
    } else {
        LOG_FATAL("The %s config setting is required for %s.\n",
                  IPAMODRDN_FILTER, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAMODRDN_FILTER, value);

    value = slapi_entry_attr_get_charptr(e, IPAMODRDN_SCOPE);
    if (value) {
        entry->scope = value;
    } else {
        LOG_FATAL("The %s config config setting is required for %s.\n",
                  IPAMODRDN_SCOPE, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAMODRDN_SCOPE, entry->scope);

    /* If we were only called to validate config, we can
     * just bail out before applying the config changes */
    if (!apply) {
        goto bail;
    }

    /**
     * Finally add the entry to the list.
     * We sort by scope dn length with longer
     * dn's first - this allows the scope
     * checking code to be simple and quick and
     * cunningly linear.
     */
    if (!PR_CLIST_IS_EMPTY(ipamodrdn_global_config)) {
        list = PR_LIST_HEAD(ipamodrdn_global_config);
        while (list != ipamodrdn_global_config) {
            config_entry = (struct configEntry *) list;

            if (slapi_dn_issuffix(entry->scope, config_entry->scope)) {
                PR_INSERT_BEFORE(&(entry->list), list);
                LOG_CONFIG("store [%s] before [%s] \n",
                           entry->scope, config_entry->scope);
                entry_added = 1;
                break;
            }

            list = PR_NEXT_LINK(list);

            if (ipamodrdn_global_config == list) {
                /* add to tail */
                PR_INSERT_BEFORE(&(entry->list), list);
                LOG_CONFIG("store [%s] at tail\n", entry->scope);
                entry_added = 1;
                break;
            }
        }
    } else {
        /* first entry */
        PR_INSERT_LINK(&(entry->list), ipamodrdn_global_config);
        LOG_CONFIG("store [%s] at head \n", entry->scope);
        entry_added = 1;
    }

bail:
    if (0 == entry_added) {
        /* Don't log error if we weren't asked to apply config */
        if (apply && (entry != NULL)) {
            LOG_FATAL("Invalid config entry [%s] skipped\n", entry->dn);
        }
        ipamodrdn_free_config_entry(&entry);
    } else {
        ret = EOK;
    }

    LOG_TRACE("<--out--\n");

    return ret;
}

static void
ipamodrdn_free_config_entry(struct configEntry **entry)
{
    struct configEntry *e;

    if (!entry || !*entry) {
        return;
    }

    e = *entry;

    if (e->dn) {
        LOG_CONFIG("freeing config entry [%s]\n", e->dn);
    }
    slapi_ch_free_string(&e->dn);
    slapi_ch_free_string(&e->sattr);
    slapi_ch_free_string(&e->tattr);
    slapi_ch_free_string(&e->prefix);
    slapi_ch_free_string(&e->suffix);
    slapi_ch_free_string(&e->filter);
    slapi_filter_free(e->slapi_filter, 1);
    slapi_ch_free_string(&e->scope);
    slapi_ch_free((void **)entry);
}

static void
ipamodrdn_delete_configEntry(PRCList *entry)
{
    PR_REMOVE_LINK(entry);
    ipamodrdn_free_config_entry((struct configEntry **) &entry);
}

static void
ipamodrdn_delete_config(void)
{
    PRCList *list;

    while (!PR_CLIST_IS_EMPTY(ipamodrdn_global_config)) {
        list = PR_LIST_HEAD(ipamodrdn_global_config);
        ipamodrdn_delete_configEntry(list);
    }

    return;
}

/****************************************************
	Helpers
****************************************************/

static char *ipamodrdn_get_dn(Slapi_PBlock * pb)
{
    char *dn = NULL;

    LOG_TRACE("--in-->\n");

    if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn)) {
        LOG_FATAL("failed to get dn of changed entry");
    }

    LOG_TRACE("<--out--\n");

    return dn;
}

/* config check
        matching config dn or a descendent reloads config
*/
static int ipamodrdn_dn_is_config(char *dn)
{
    int ret = 0;

    LOG_TRACE("--in-->\n");

    if (slapi_dn_issuffix(dn, getPluginDN())) {
        ret = 1;
    }

    LOG_TRACE("<--out--\n");

    return ret;
}

/****************************************************
        Functions that actually do things other
        than config and startup
****************************************************/

static int
ipamodrdn_change_attr(struct configEntry *cfgentry,
                      char *targetdn, const char *value)
{
    Slapi_PBlock *mod_pb = slapi_pblock_new();
    LDAPMod mod;
    LDAPMod *mods[2];
    char *val[2] = { NULL };
    int ret;

    val[0] = slapi_ch_smprintf("%s%s%s",
                               cfgentry->prefix, value, cfgentry->suffix);
    if (!val[0]) {
        LOG_OOM();
        ret = EFAIL;
        goto done;
    }
    val[1] = 0;

    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = cfgentry->tattr;
    mod.mod_values = val;

    mods[0] = &mod;
    mods[1] = 0;

    LOG("Setting %s to %s in entry (%s)\n", cfgentry->tattr, value, targetdn);

    /* Perform the modify operation. */
    slapi_modify_internal_set_pb(mod_pb, targetdn, mods,
                                 0, 0, getPluginID(), 0);
    slapi_modify_internal_pb(mod_pb);
    slapi_pblock_get(mod_pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != LDAP_SUCCESS) {
        LOG_FATAL("Failed to change attribute with error %d\n", ret);
        ret = EFAIL;
    }
    ret = EOK;

done:
    if (val[0]) slapi_ch_free_string(&(val[0]));
    slapi_pblock_destroy(mod_pb);
    return ret;
}




/* for mods and adds:
	where dn's are supplied, the closest in scope
	is used as long as the type filter matches
        and the attr value has not been generated yet.
*/

static int ipamodrdn_post_op(Slapi_PBlock *pb)
{
    char *dn = NULL;
    PRCList *list = NULL;
    struct configEntry *cfgentry = NULL;
    struct slapi_entry *e = NULL;
    Slapi_Attr *sattr = NULL;
    Slapi_Attr *tattr = NULL;
    int ret = LDAP_SUCCESS;

    LOG_TRACE("--in-->\n");

    /* Just bail if we aren't ready to service requests yet. */
    if (!g_plugin_started) {
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &e);
    if (NULL == e) {
        goto done;
    }

    dn = slapi_entry_get_ndn(e);
    if (NULL == dn) {
        goto done;
    }

    ipamodrdn_read_lock();

    if (!PR_CLIST_IS_EMPTY(ipamodrdn_global_config)) {
        list = PR_LIST_HEAD(ipamodrdn_global_config);

        for(list = PR_LIST_HEAD(ipamodrdn_global_config);
            list != ipamodrdn_global_config;
            list = PR_NEXT_LINK(list)) {
            cfgentry = (struct configEntry *) list;

            /* is the entry in scope? */
            if (cfgentry->scope) {
                if (!slapi_dn_issuffix(dn, cfgentry->scope)) {
                    continue;
                }
            }

            /* does the entry match the filter? */
            if (cfgentry->slapi_filter) {
                ret = slapi_vattr_filter_test(pb, e,
                                              cfgentry->slapi_filter, 0);
                if (ret != LDAP_SUCCESS) {
                    continue;
                }
            }

            if (slapi_entry_attr_find(e, cfgentry->sattr, &sattr) != 0) {
                LOG_TRACE("Source attr %s not found for %s\n",
                          cfgentry->sattr, dn);
                continue;
            }
            if (slapi_entry_attr_find(e, cfgentry->tattr, &tattr) != 0) {
                LOG_TRACE("Target attr %s not found for %s\n",
                          cfgentry->tattr, dn);
            } else {
                Slapi_Value *val;
                const char *strval;

                ret = slapi_attr_first_value(sattr, &val);
                if (ret == -1 || !val) {
                    LOG_FATAL("Source attr %s is empty\n", cfgentry->sattr);
                    continue;
                }
                strval = slapi_value_get_string(val);

                ret = ipamodrdn_change_attr(cfgentry, dn, strval);
                if (ret != EOK) {
                    LOG_FATAL("Failed to set target attr %s for %s\n",
                              cfgentry->tattr, dn);
                }
            }
        }
    }

    ipamodrdn_unlock();

    ret = LDAP_SUCCESS;

done:
    if (ret) {
        LOG("operation failure [%d]\n", ret);
        ret = EFAIL;
    }

    LOG_TRACE("<--out--\n");

    return ret;
}

static int ipamodrdn_config_check_post_op(Slapi_PBlock * pb)
{
    char *dn;

    LOG_TRACE("--in-->\n");

    if ((dn = ipamodrdn_get_dn(pb))) {
        if (ipamodrdn_dn_is_config(dn)) {
            ipamodrdn_load_plugin_config();
        }
    }

    LOG_TRACE("<--out--\n");

    return 0;
}
