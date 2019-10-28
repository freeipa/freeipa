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
 * IPA UUID plug-in
 */
#include <string.h>
#include <stdbool.h>
#include "slapi-plugin.h"
#include "nspr.h"
#include "prclist.h"
#include "uuid/uuid.h"
#include <pthread.h>
#include <plbase64.h>

#include "util.h"

#define IPAUUID_STR_SIZE 36
#define IPAUUID_BASE64_STR_SIZE ((16+2)/3*4)

#define IPAUUID_PLUGIN_NAME "ipa-uuid-plugin"
#define IPAUUID_PLUGIN_VERSION 0x00010000

#define IPAUUID_DN "cn=IPA UUID,cn=plugins,cn=config" /* temporary */

#define IPA_PLUGIN_NAME IPAUUID_PLUGIN_NAME

/**
 * IPA UUID config types
 */
#define IPAUUID_ATTR             "ipaUuidAttr"
#define IPAUUID_PREFIX           "ipaUuidPrefix"
#define IPAUUID_GENERATE         "ipaUuidMagicRegen"
#define IPAUUID_FILTER           "ipaUuidFilter"
#define IPAUUID_SCOPE            "ipaUuidScope"
#define IPAUUID_EXCLUDE_SUBTREE  "ipaUuidExcludeSubtree"
#define IPAUUID_ENFORCE          "ipaUuidEnforce"
#define IPAUUID_ENCODE           "ipaUuidEncode"

#define IPAUUID_FEATURE_DESC      "IPA UUID"
#define IPAUUID_PLUGIN_DESC       "IPA UUID plugin"
#define IPAUUID_INT_PREOP_DESC    "IPA UUID internal preop plugin"
#define IPAUUID_POSTOP_DESC       "IPA UUID postop plugin"

static Slapi_PluginDesc pdesc = {
    IPAUUID_FEATURE_DESC,
    "Red Hat, Inc.",
    "1.0",
    IPAUUID_PLUGIN_DESC
};

/**
 * linked list of config entries
 */

struct configEntry {
    PRCList list;
    char *dn;
    char *attr;
    char *prefix;
    char *filter;
    Slapi_Filter *slapi_filter;
    char *generate;
    char *scope;
    char *exclude_subtree;
    bool enforce;
    bool encode;
};

static PRCList *ipauuid_global_config = NULL;
static pthread_rwlock_t g_ipauuid_cache_lock;

static void *_PluginID = NULL;
static char *_PluginDN = NULL;

static int g_plugin_started = 0;


/**
 *
 * management functions
 *
 */
int ipauuid_init(Slapi_PBlock * pb);
static int ipauuid_start(Slapi_PBlock * pb);
static int ipauuid_close(Slapi_PBlock * pb);
static int ipauuid_internal_preop_init(Slapi_PBlock *pb);
static int ipauuid_postop_init(Slapi_PBlock * pb);

/**
 *
 * Local operation functions
 *
 */
static int ipauuid_load_plugin_config(void);
static int ipauuid_parse_config_entry(Slapi_Entry * e, bool apply);
static void ipauuid_delete_config(void);
static void ipauuid_free_config_entry(struct configEntry ** entry);

/**
 *
 * helpers
 *
 */
static char *ipauuid_get_dn(Slapi_PBlock * pb);
static int ipauuid_dn_is_config(char *dn);
static int ipauuid_list_contains_attr(char **list, char *attr);

/**
 *
 * the ops (where the real work is done)
 *
 */
static int ipauuid_config_check_post_op(Slapi_PBlock * pb);
static int ipauuid_pre_op(Slapi_PBlock * pb, int modtype);
static int ipauuid_mod_pre_op(Slapi_PBlock * pb);
static int ipauuid_add_pre_op(Slapi_PBlock * pb);

/**
 * debug functions - global, for the debugger
 */
void ipauuid_dump_config(void);
void ipauuid_dump_config_entry(struct configEntry *);

/**
 *
 * Deal with cache locking
 *
 */
void ipauuid_read_lock(void)
{
    pthread_rwlock_rdlock(&g_ipauuid_cache_lock);
}

void ipauuid_write_lock(void)
{
    pthread_rwlock_wrlock(&g_ipauuid_cache_lock);
}

void ipauuid_unlock(void)
{
    pthread_rwlock_unlock(&g_ipauuid_cache_lock);
}

/**
 *
 * Get the plug-in version
 *
 */
int ipauuid_version(void)
{
    return IPAUUID_PLUGIN_VERSION;
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
	ipauuid_init
	-------------
	adds our callbacks to the list
*/
int
ipauuid_init(Slapi_PBlock *pb)
{
    int status = EOK;
    char *plugin_identity = NULL;

    LOG_TRACE("--in-->\n");

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
                         (void *) ipauuid_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipauuid_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN,
                         (void *) ipauuid_mod_pre_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN,
                         (void *) ipauuid_add_pre_op) != 0 ||
        /* internal preoperation */
        slapi_register_plugin("internalpreoperation",  /* op type */
                              1,        /* Enabled */
                              "ipauuid_init",   /* this function desc */
                              ipauuid_internal_preop_init,  /* init func */
                              IPAUUID_INT_PREOP_DESC,      /* plugin desc */
                              NULL,     /* ? */
                              plugin_identity   /* access control */
        ) ||
        /* the config change checking post op */
        slapi_register_plugin("postoperation",  /* op type */
                              1,        /* Enabled */
                              "ipauuid_init",   /* this function desc */
                              ipauuid_postop_init,  /* init func for post op */
                              IPAUUID_POSTOP_DESC,      /* plugin desc */
                              NULL,     /* ? */
                              plugin_identity   /* access control */
        )
        ) {
        LOG_FATAL("failed to register plugin\n");
        status = EFAIL;
    }

    LOG_TRACE("<--out--\n");
    return status;
}

static int
ipauuid_internal_preop_init(Slapi_PBlock *pb)
{
    int status = EOK;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_PRE_MODIFY_FN,
                         (void *) ipauuid_mod_pre_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_PRE_ADD_FN,
                         (void *) ipauuid_add_pre_op) != 0) {
        status = EFAIL;
    }

    return status;
}

static int
ipauuid_postop_init(Slapi_PBlock *pb)
{
    int status = EOK;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
                         (void *) ipauuid_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODRDN_FN,
                         (void *) ipauuid_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN,
                         (void *) ipauuid_config_check_post_op) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN,
                         (void *) ipauuid_config_check_post_op) != 0) {
        LOG_FATAL("failed to register plugin\n");
        status = EFAIL;
    }

    return status;
}


/*
	ipauuid_start
	--------------
	Kicks off the config cache.
	It is called after ipauuid_init.
*/
static int
ipauuid_start(Slapi_PBlock * pb)
{
    char *plugindn = NULL;

    LOG_TRACE("--in-->\n");

    /* Check if we're already started */
    if (g_plugin_started) {
        goto done;
    }

    if (pthread_rwlock_init(&g_ipauuid_cache_lock, NULL) != 0) {
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
        plugindn = IPAUUID_DN;
    } else {
        LOG("config at %s\n", plugindn);

    }

    setPluginDN(plugindn);

    /*
     * Load the config for our plug-in
     */
    ipauuid_global_config = (PRCList *)
        slapi_ch_calloc(1, sizeof(struct configEntry));
    PR_INIT_CLIST(ipauuid_global_config);

    if (ipauuid_load_plugin_config() != EOK) {
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
	ipauuid_close
	--------------
	closes down the cache
*/
static int
ipauuid_close(Slapi_PBlock * pb)
{
    LOG_TRACE( "--in-->\n");

    ipauuid_delete_config();

    slapi_ch_free((void **)&ipauuid_global_config);

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
ipauuid_load_plugin_config()
{
    int status = EOK;
    int result;
    int i;
    Slapi_PBlock *search_pb;
    Slapi_Entry **entries = NULL;

    LOG_TRACE("--in-->\n");

    ipauuid_write_lock();
    ipauuid_delete_config();

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
        ipauuid_parse_config_entry(entries[i], true);
    }

  cleanup:
    slapi_free_search_results_internal(search_pb);
    slapi_pblock_destroy(search_pb);
    ipauuid_unlock();
    LOG_TRACE("<--out--\n");

    return status;
}

/*
 * ipauuid_parse_config_entry()
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
ipauuid_parse_config_entry(Slapi_Entry * e, bool apply)
{
    char *value;
    struct configEntry *entry = NULL;
    struct configEntry *config_entry;
    PRCList *list;
    int entry_added = 0;
    int ret = EOK;

    LOG_TRACE("--in-->\n");

    /* If this is the main UUID plug-in config entry, just bail. */
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

    entry->attr = slapi_entry_attr_get_charptr(e, IPAUUID_ATTR);
    if (!entry->attr) {
        LOG_FATAL("The %s config setting is required for %s.\n",
                  IPAUUID_ATTR, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAUUID_ATTR, entry->attr);

    value = slapi_entry_attr_get_charptr(e, IPAUUID_PREFIX);
    if (value && value[0]) {
        entry->prefix = value;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAUUID_PREFIX, entry->prefix);

    value = slapi_entry_attr_get_charptr(e, IPAUUID_GENERATE);
    if (value) {
        entry->generate = value;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAUUID_GENERATE, entry->generate);

    value = slapi_entry_attr_get_charptr(e, IPAUUID_FILTER);
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
                  IPAUUID_FILTER, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAUUID_FILTER, value);

    value = slapi_entry_attr_get_charptr(e, IPAUUID_SCOPE);
    if (value) {
        entry->scope = value;
    } else {
        LOG_FATAL("The %s config config setting is required for %s.\n",
                  IPAUUID_SCOPE, entry->dn);
        ret = EFAIL;
        goto bail;
    }
    LOG_CONFIG("----------> %s [%s]\n", IPAUUID_SCOPE, entry->scope);

    value = slapi_entry_attr_get_charptr(e, IPAUUID_EXCLUDE_SUBTREE);
    entry->exclude_subtree = value;
    LOG_CONFIG("----------> %s [%s]\n", IPAUUID_EXCLUDE_SUBTREE, entry->exclude_subtree);

    entry->enforce = slapi_entry_attr_get_bool(e, IPAUUID_ENFORCE);
    LOG_CONFIG("----------> %s [%s]\n",
               IPAUUID_ENFORCE, entry->enforce ? "True" : "False");

    entry->encode = slapi_entry_attr_get_bool(e, IPAUUID_ENCODE);
    LOG_CONFIG("----------> %s [%s]\n",
               IPAUUID_ENCODE, entry->enforce ? "True" : "False");

    if (entry->encode && entry->prefix) {
        LOG_FATAL("The %s and %s are incompatible for %s.\n",
                  IPAUUID_PREFIX, IPAUUID_ENCODE, entry->dn);
        ret = EFAIL;
        goto bail;
    }
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
    if (!PR_CLIST_IS_EMPTY(ipauuid_global_config)) {
        list = PR_LIST_HEAD(ipauuid_global_config);
        while (list != ipauuid_global_config) {
            config_entry = (struct configEntry *) list;

            if (slapi_dn_issuffix(entry->scope, config_entry->scope)) {
                PR_INSERT_BEFORE(&(entry->list), list);
                LOG_CONFIG("store [%s] before [%s] \n",
                           entry->scope, config_entry->scope);
                entry_added = 1;
                break;
            }

            list = PR_NEXT_LINK(list);

            if (ipauuid_global_config == list) {
                /* add to tail */
                PR_INSERT_BEFORE(&(entry->list), list);
                LOG_CONFIG("store [%s] at tail\n", entry->scope);
                entry_added = 1;
                break;
            }
        }
    } else {
        /* first entry */
        PR_INSERT_LINK(&(entry->list), ipauuid_global_config);
        LOG_CONFIG("store [%s] at head \n", entry->scope);
        entry_added = 1;
    }

bail:
    if (0 == entry_added) {
        /* Don't log error if we weren't asked to apply config */
        if (apply && (entry != NULL)) {
            LOG_FATAL("Invalid config entry [%s] skipped\n", entry->dn);
        }
        ipauuid_free_config_entry(&entry);
    } else {
        ret = EOK;
    }

    LOG_TRACE("<--out--\n");

    return ret;
}

static void
ipauuid_free_config_entry(struct configEntry **entry)
{
    struct configEntry *e;

    if (!entry || !*entry) {
        return;
    }

    e = *entry;

    if (e->dn) {
        LOG_CONFIG("freeing config entry [%s]\n", e->dn);
        slapi_ch_free_string(&e->dn);
    }

    if (e->attr) {
        slapi_ch_free_string(&e->attr);
    }

    if (e->prefix) {
        slapi_ch_free_string(&e->prefix);
    }

    if (e->filter) {
        slapi_ch_free_string(&e->filter);
    }

    if (e->slapi_filter) {
        slapi_filter_free(e->slapi_filter, 1);
    }

    if (e->generate) {
        slapi_ch_free_string(&e->generate);
    }

    if (e->scope) {
        slapi_ch_free_string(&e->scope);
    }

    if (e->exclude_subtree) {
        slapi_ch_free_string(&e->exclude_subtree);
    }

    slapi_ch_free((void **)entry);
}

static void
ipauuid_delete_configEntry(PRCList *entry)
{
    PR_REMOVE_LINK(entry);
    ipauuid_free_config_entry((struct configEntry **) &entry);
}

static void
ipauuid_delete_config()
{
    PRCList *list;

    while (!PR_CLIST_IS_EMPTY(ipauuid_global_config)) {
        list = PR_LIST_HEAD(ipauuid_global_config);
        ipauuid_delete_configEntry(list);
    }

    return;
}

/****************************************************
	Helpers
****************************************************/

static char *ipauuid_get_dn(Slapi_PBlock * pb)
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
static int ipauuid_dn_is_config(char *dn)
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

/*
 * ipauuid_list_contains_attr()
 *
 * Checks if a attr is contained in a list of attrs.
 * Returns 1 if the attr is found, 0 otherwise.
 */
static int
ipauuid_list_contains_attr(char **list, char *attr)
{
    int ret = 0;
    int i = 0;

    if (list && attr) {
        for (i = 0; list[i]; i++) {
            if (slapi_attr_types_equivalent(attr, list[i])) {
                ret = 1;
                break;
            }
        }
    }

    return ret;
}

/* this function must be passed a preallocated buffer of 37 characters in the
 * out parameter */
static void ipauuid_generate_uuid(char *out, bool encode)
{
    uuid_t uu;

    uuid_generate_time(uu);
    if (!encode) {
        uuid_unparse_lower(uu, out);
    } else {
        (void) PL_Base64Encode(uu, 16, out);
        out[IPAUUID_BASE64_STR_SIZE] = '\0';
    }
}

/* for mods and adds:
	where dn's are supplied, the closest in scope
	is used as long as the type filter matches
        and the attr value has not been generated yet.
*/

static int ipauuid_pre_op(Slapi_PBlock *pb, int modtype)
{
    char *dn = NULL;
    PRCList *list = NULL;
    struct configEntry *cfgentry = NULL;
    struct slapi_entry *e = NULL;
    Slapi_Entry *resulting_e = NULL;
    char *value = NULL;
    char **generated_attrs = NULL;
    Slapi_Mods *smods = NULL;
    Slapi_Mod *smod = NULL;
    Slapi_Mod *next_mod;
    LDAPMod **mods;
    bool free_entry = false;
    char *errstr = NULL;
    bool generate;
    int ret = LDAP_SUCCESS;
    bool locked = false;
    bool set_attr;
    int is_repl_op;
    int is_config_dn;

    LOG_TRACE("--in-->\n");

    /* Just bail if we aren't ready to service requests yet. */
    if (!g_plugin_started) {
        goto done;
    }

    dn = ipauuid_get_dn(pb);
    if (!dn) {
        goto done;
    }

    is_config_dn = ipauuid_dn_is_config(dn);

    ret = slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl_op);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed!?\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* pass through if this is a replicated operation */
    if (is_repl_op && !is_config_dn) {
        return 0;
    }

    if (modtype != LDAP_CHANGETYPE_ADD &&
        modtype != LDAP_CHANGETYPE_MODIFY) {
        goto done;
    }

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
            ret = slapi_search_internal_get_entry(tmp_dn, NULL, &e, getPluginID());
            slapi_sdn_free(&tmp_dn);

            if (ret == LDAP_REFERRAL) {
                /* we have a referral so nothing for us to do, but return
                 * success so we allow the MOD to proceed.
                 */
                ret = LDAP_SUCCESS;
                free_entry = true;
                goto done;
            }

            if (ret) {
                /* ok a client tried to modify an entry that doesn't exist.
                 * Nothing to see here, move along ... */
                goto done;
            }

            free_entry = true;
        }

        /* grab the mods - we'll put them back later with
         * our modifications appended
         */
        slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
        smods = slapi_mods_new();
        slapi_mods_init_passin(smods, mods);

        /* We need the resulting entry after the mods are applied to
         * see if the entry is within the scope. */
        if (e) {
            resulting_e = slapi_entry_dup(e);
            if (mods && (slapi_entry_apply_mods(resulting_e, mods) != LDAP_SUCCESS)) {
                /* The mods don't apply cleanly, so we just let this op go
                 * to let the main server handle it. */
                goto done;
            }
        }
    }

    if (NULL == e) {
        goto done;
    }

    if (is_config_dn) {
        /* Validate config changes, but don't apply them.
         * This allows us to reject invalid config changes
         * here at the pre-op stage.  Applying the config
         * needs to be done at the post-op stage. */
        Slapi_Entry *test_e = NULL;

        /* For a MOD, we need to check the resulting entry */
        if (LDAP_CHANGETYPE_ADD == modtype) {
            test_e = e;
        } else {
            test_e = resulting_e;
        }

        if (ipauuid_parse_config_entry(test_e, false) != EOK) {
            /* Refuse the operation if config parsing failed. */
            ret = LDAP_UNWILLING_TO_PERFORM;
            if (LDAP_CHANGETYPE_ADD == modtype) {
                errstr = slapi_ch_smprintf("Not a valid IPA UUID "
                                           "configuration entry.");
            } else {
                errstr = slapi_ch_smprintf("Changes result in an invalid "
                                           "IPA UUID configuration.");
            }
        }

        /* We're done, so just bail. */
        goto done;
    }

    ipauuid_read_lock();
    locked = true;

    if (PR_CLIST_IS_EMPTY(ipauuid_global_config)) {
        goto done;
    }

    list = PR_LIST_HEAD(ipauuid_global_config);

    for(list = PR_LIST_HEAD(ipauuid_global_config);
        list != ipauuid_global_config;
        list = PR_NEXT_LINK(list)) {
        cfgentry = (struct configEntry *) list;
        char *current_dn = NULL;

        generate = false;
        set_attr = false;

        /* Did we already service this attr? */
        if (ipauuid_list_contains_attr(generated_attrs,
                                       cfgentry->attr)) {
            continue;
        }
        /* Current DN may have been reset by
         * slapi_pblock_set(pb, SLAPI_ADD_TARGET,..) see below
         * need to reread it
         */
        current_dn = ipauuid_get_dn(pb);

        /* is the entry in scope? */
        if (cfgentry->scope) {
            if (!slapi_dn_issuffix(current_dn, cfgentry->scope)) {
                continue;
            }
        }

        if (cfgentry->exclude_subtree) {
                if (slapi_dn_issuffix(current_dn, cfgentry->exclude_subtree)) {
                        continue;
                }
        }

        /* does the entry match the filter? */
        if (cfgentry->slapi_filter) {
            Slapi_Entry *test_e = NULL;

            /* For a MOD operation, we need to check the filter
             * against the resulting entry. */
            if (LDAP_CHANGETYPE_ADD == modtype) {
                test_e = e;
            } else {
                test_e = resulting_e;
            }

            ret = slapi_vattr_filter_test(pb, test_e,
                                          cfgentry->slapi_filter, 0);
            if (ret != LDAP_SUCCESS) {
                continue;
            }
        }

        switch(modtype) {
        case LDAP_CHANGETYPE_ADD:
            /* Generate the value if the magic value is set or if the
             * attr is missing. */
            value = slapi_entry_attr_get_charptr(e, cfgentry->attr);

            if (!value ||
                !slapi_UTF8CASECMP(cfgentry->generate, value)) {
                generate = true;
            }

            slapi_ch_free_string(&value);

            /* always true on add if we match the scope */
            set_attr = true;
            break;

        case LDAP_CHANGETYPE_MODIFY:
            /* check mods for magic value */
            next_mod = slapi_mod_new();
            smod = slapi_mods_get_first_smod(smods, next_mod);
            while (smod) {
                char *attr = (char *)slapi_mod_get_type(smod);

                /* See if the attr matches the configured attr. */
                if (!slapi_attr_types_equivalent(cfgentry->attr, attr)) {
                    slapi_mod_done(next_mod);
                    smod = slapi_mods_get_next_smod(smods, next_mod);
                    continue;
                }

                /* ok we found the attr so that means we are going to set it */
                set_attr = true;

                /* If all values are being deleted, we need to
                 * generate a new value. */
                if (SLAPI_IS_MOD_DELETE(slapi_mod_get_operation(smod))) {
                    int numvals = slapi_mod_get_num_values(smod);

                    if (numvals == 0) {
                        generate = true;
                    } else {
                        Slapi_Attr *sattr = NULL;
                        int e_numvals = 0;

                        if ((!slapi_entry_attr_find(e, attr, &sattr)) &&
                            (NULL != sattr)) {
                            slapi_attr_get_numvalues(sattr, &e_numvals);
                            if (numvals >= e_numvals) {
                                generate = true;
                            }
                        }
                    }
                } else {
                    struct berval *bv;

                    /* If this attr is already slated for generation,
                     * a previous mod in this same modify operation
                     * either removed all values or set the magic value.
                     * It's possible that this mod is adding a valid value,
                     * which means we would not want to generate a new one.
                     * It is safe to reset the flag since it will be
                     * re-added here if necessary. */
                    generate = false;

                    /* This is either adding or replacing a value */
                    bv = slapi_mod_get_first_value(smod);
                    /* If we have a value, see if it's the magic value. */
                    if (bv) {
                        if (!slapi_UTF8CASECMP(bv->bv_val,
                                               cfgentry->generate)) {
                            generate = true;

                            /* also remove this mod, as we will add
                             * it again later */
                            slapi_mod_remove_value(next_mod);
                        }
                    } else {
                        /* This is a replace with no new values, so we need
                         * to generate a new value */
                        generate = true;
                    }
                }

                slapi_mod_done(next_mod);
                smod = slapi_mods_get_next_smod(smods, next_mod);
            }

            slapi_mod_free(&next_mod);
            break;

        default:
            /* never reached, just silence compiler */
            LOG_TRACE("File '%s' line %d: Got unexpected value of modtype:"
                      "%d\n", __FILE__, __LINE__, modtype);
            break;
        }

        /* We need to perform one last check for modify operations.
         * If an entry within the scope has not triggered generation yet,
         * we need to see if a value exists for the managed attr in the
         * resulting entry.
         * This will catch a modify operation that brings an entry into
         * scope for a managed range, but doesn't supply a value for the
         * managed attr. */
        if ((LDAP_CHANGETYPE_MODIFY == modtype) && !generate) {
            Slapi_Attr *attr = NULL;
            if (slapi_entry_attr_find(resulting_e,
                                      cfgentry->attr, &attr) != 0) {
                generate = true;
                set_attr = true;
            }
        }

        /* nothing to do keep looping */
        if (!set_attr) {
            continue;
        }

        if (generate) {
            char *new_value;

            /* create the value to add */
            value = slapi_ch_calloc(1, IPAUUID_STR_SIZE + 1);
            if (!value) {
                LOG_OOM();
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            ipauuid_generate_uuid(value, cfgentry->encode);

            if (cfgentry->prefix) {
                new_value = slapi_ch_smprintf("%s%s",
                                              cfgentry->prefix, value);
            } else {
                new_value = slapi_ch_smprintf("%s", value);
            }

            /* do the mod */
            if (LDAP_CHANGETYPE_ADD == modtype) {
                Slapi_DN *sdn;
                Slapi_RDN *rdn;
                char *attr;
                char *nrdn;

                /* add - set in entry */
                slapi_entry_attr_set_charptr(e, cfgentry->attr, new_value);

                /* check to see if we need to change the RDN too */
                rdn = slapi_rdn_new();
                if (!rdn) {
                    LOG_OOM();
                    ret = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                sdn = slapi_sdn_new_dn_byval(current_dn);
                if (!sdn) {
                    LOG_OOM();
                    ret = LDAP_OPERATIONS_ERROR;
                    slapi_rdn_free(&rdn);
                    goto done;
                }
                slapi_rdn_set_sdn(rdn, sdn);
                ret = slapi_rdn_contains_attr(rdn, cfgentry->attr, &attr);
                slapi_rdn_done(rdn);
                if (ret == 1) {
                    /* no need to recheck if it is valid, it will be handled
                     * later by checking the value in the entry */
                    nrdn = slapi_ch_smprintf("%s=%s",
                                             cfgentry->attr, new_value);
                    if (!nrdn) {
                        LOG_OOM();
                        ret = LDAP_OPERATIONS_ERROR;
                        slapi_rdn_free(&rdn);
                        slapi_sdn_free(&sdn);
                        goto done;
                    }

                    slapi_rdn_set_dn(rdn, nrdn);
                    slapi_ch_free_string(&nrdn);
                    slapi_sdn_set_rdn(sdn, rdn);
                    slapi_entry_set_sdn(e, sdn);

                    /* reset the target DN since we've changed it. */
                    if (slapi_pblock_set(pb, SLAPI_ADD_TARGET,
                                             (char*)slapi_sdn_get_ndn(slapi_entry_get_sdn_const(e)))) {
                        LOG_FATAL("slapi_block_set failed!\n");
                        ret = LDAP_OPERATIONS_ERROR;
                        slapi_rdn_free(&rdn);
                        slapi_sdn_free(&sdn);
                        goto done;
                    }
                }
                slapi_rdn_free(&rdn);
                slapi_sdn_free(&sdn);

            } else {
                /* mod - add to mods */
                slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                      cfgentry->attr, new_value);
            }

            /* Make sure we don't generate for this
             * attr again by keeping a list of attrs
             * we have generated for already.
             */
            slapi_ch_array_add(&generated_attrs,
                               slapi_ch_strdup(cfgentry->attr));

            /* free up */
            slapi_ch_free_string(&value);
            slapi_ch_free_string(&new_value);

        } else {
            char *bindDN = NULL;
            int is_root;

            slapi_pblock_get(pb, SLAPI_CONN_DN, &bindDN);
            is_root = slapi_dn_isroot(bindDN);

            /* If not set to the magic value, check enforcement */
            if (cfgentry->enforce && is_root != 1) {
                /* only Directory Manager can set arbitrary values when
                 * enforce is enabled. */
                errstr = slapi_ch_smprintf("Only the Directory Manager "
                                           "can set arbitrary values "
                                           "for %s\n", cfgentry->attr);
                ret = LDAP_INSUFFICIENT_ACCESS;
                goto done;
            }
        }
    }

    ret = LDAP_SUCCESS;

done:
    if (locked) {
        ipauuid_unlock();
    }

    if (smods != NULL) {
        /* Put the updated mods back into place. */
        mods = slapi_mods_get_ldapmods_passout(smods);
        if (slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods)) {
            LOG_FATAL("slapi_pblock_set failed!\n");
            ret = LDAP_OPERATIONS_ERROR;
        }
        slapi_mods_free(&smods);
    }

    slapi_ch_array_free(generated_attrs);
    slapi_ch_free_string(&value);

    if (free_entry && e) {
        slapi_entry_free(e);
    }

    if (resulting_e) {
        slapi_entry_free(resulting_e);
    }

    if (ret) {
        LOG("operation failure [%d]\n", ret);
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
        slapi_ch_free((void **)&errstr);
        ret = EFAIL;
    }

    LOG_TRACE("<--out--\n");

    return ret;
}

static int ipauuid_add_pre_op(Slapi_PBlock * pb)
{
    return ipauuid_pre_op(pb, LDAP_CHANGETYPE_ADD);
}

static int ipauuid_mod_pre_op(Slapi_PBlock * pb)
{
    return ipauuid_pre_op(pb, LDAP_CHANGETYPE_MODIFY);
}

static int ipauuid_config_check_post_op(Slapi_PBlock * pb)
{
    char *dn;

    LOG_TRACE("--in-->\n");

    if ((dn = ipauuid_get_dn(pb))) {
        if (ipauuid_dn_is_config(dn))
            ipauuid_load_plugin_config();
    }

    LOG_TRACE("<--out--\n");

    return 0;
}

