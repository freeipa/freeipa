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

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#define LDAP_DEPRECATED 1

/*
 * Windows Synchronization Plug-in for IPA
 * This plugin allows IPA to intercept operations sent from
 * Windows to the directory server and vice versa.  This allows
 * IPA to intercept new users added to Windows and synced to the
 * directory server, and allows IPA to modify the entry, adding
 * objectclasses and attributes, and changing the DN.
 */

#ifdef WINSYNC_TEST_IPA
#include <slapi-plugin.h>
#include "winsync-plugin.h"
#else
#include <dirsrv/slapi-plugin.h>
#include <dirsrv/winsync-plugin.h>
#endif
#include "ipa-winsync.h"

#include <string.h>
#include <stdlib.h>
#include "plstr.h"

static void
sync_acct_disable(
    void *cbdata, /* the usual domain config data */
    const Slapi_Entry *ad_entry, /* the AD entry */
    Slapi_Entry *ds_entry, /* the DS entry */
    int direction, /* the direction - TO_AD or TO_DS */
    Slapi_Entry *update_entry, /* the entry to update for ADDs */
    Slapi_Mods *smods, /* the mod list for MODIFYs */
    int *do_modify /* set to true if mods were applied */
);

static void
do_force_sync(
    const Slapi_Entry *ad_entry, /* the AD entry */
    Slapi_Entry *ds_entry, /* the DS entry */
    Slapi_Mods *smods, /* the mod list */
    int *do_modify /* set to true if mods were applied */
);

/* This is called when a new agreement is created or loaded
   at startup.
*/
static void *
ipa_winsync_agmt_init(const Slapi_DN *ds_subtree, const Slapi_DN *ad_subtree)
{
    void *cbdata = NULL;
    LOG("--> ipa_winsync_agmt_init [%s] [%s] -- begin\n",
        slapi_sdn_get_dn(ds_subtree),
        slapi_sdn_get_dn(ad_subtree));

    /* do the domain specific configuration based on the ds subtree */
    cbdata = ipa_winsync_config_new_domain(ds_subtree, ad_subtree);

    LOG("<-- ipa_winsync_agmt_init -- end\n");

    return cbdata;
}

static void
ipa_winsync_dirsync_search_params_cb(void *cbdata, const char *agmt_dn,
                                     char **base, int *scope, char **filter,
                                     char ***attrs, LDAPControl ***serverctrls)
{
    LOG("--> ipa_winsync_dirsync_search_params_cb -- begin\n");

    LOG("<-- ipa_winsync_dirsync_search_params_cb -- end\n");

    return;
}

/* called before searching for a single entry from AD - agmt_dn will be NULL */
static void
ipa_winsync_pre_ad_search_cb(void *cbdata, const char *agmt_dn,
                             char **base, int *scope, char **filter,
                             char ***attrs, LDAPControl ***serverctrls)
{
    LOG("--> ipa_winsync_pre_ad_search_cb -- begin\n");

    LOG("<-- ipa_winsync_pre_ad_search_cb -- end\n");

    return;
}

/* called before an internal search to get a single DS entry - agmt_dn will be NULL */
static void
ipa_winsync_pre_ds_search_entry_cb(void *cbdata, const char *agmt_dn,
                                   char **base, int *scope, char **filter,
                                   char ***attrs, LDAPControl ***serverctrls)
{
    LOG("--> ipa_winsync_pre_ds_search_cb -- begin\n");

    LOG("-- ipa_winsync_pre_ds_search_cb - base [%s] "
        "scope [%d] filter [%s]\n",
        *base, *scope, *filter);

    LOG("<-- ipa_winsync_pre_ds_search_cb -- end\n");

    return;
}

/* called before the total update to get all entries from the DS to sync to AD */
static void
ipa_winsync_pre_ds_search_all_cb(void *cbdata, const char *agmt_dn,
                                 char **base, int *scope, char **filter,
                                 char ***attrs, LDAPControl ***serverctrls)
{
    LOG("--> ipa_winsync_pre_ds_search_all_cb -- orig filter [%s] -- begin\n",
        ((filter && *filter) ? *filter : "NULL"));

    /* We only want to grab users from the ds side - no groups */
    slapi_ch_free_string(filter);
    /* maybe use ntUniqueId=* - only get users that have already been
       synced with AD - ntUniqueId and ntUserDomainId are
       indexed for equality only - need to add presence? */
    *filter = slapi_ch_strdup("(&(objectclass=ntuser)(ntUserDomainId=*))");

    LOG("<-- ipa_winsync_pre_ds_search_all_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_user_cb(void *cbdata, const Slapi_Entry *rawentry,
                               Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                               Slapi_Mods *smods, int *do_modify)
{
    LOG("--> ipa_winsync_pre_ad_mod_user_cb -- begin\n");

    sync_acct_disable(cbdata, rawentry, ds_entry, ACCT_DISABLE_TO_AD,
                      NULL, smods, do_modify);

    LOG("<-- ipa_winsync_pre_ad_mod_user_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_group_cb(void *cbdata, const Slapi_Entry *rawentry,
                                Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                                Slapi_Mods *smods, int *do_modify)
{
    LOG("--> ipa_winsync_pre_ad_mod_group_cb -- begin\n");

    LOG("<-- ipa_winsync_pre_ad_mod_group_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_mod_user_cb(void *cbdata, const Slapi_Entry *rawentry,
                               Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                               Slapi_Mods *smods, int *do_modify)
{
    LOG("--> ipa_winsync_pre_ds_mod_user_cb -- begin\n");

    sync_acct_disable(cbdata, rawentry, ds_entry, ACCT_DISABLE_TO_DS,
                      NULL, smods, do_modify);

    do_force_sync(rawentry, ds_entry, smods, do_modify);

    LOG("<-- ipa_winsync_pre_ds_mod_user_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_mod_group_cb(void *cbdata, const Slapi_Entry *rawentry,
                                Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                                Slapi_Mods *smods, int *do_modify)
{
    LOG("--> ipa_winsync_pre_ds_mod_group_cb -- begin\n");

    LOG("<-- ipa_winsync_pre_ds_mod_group_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_add_user_cb(void *cbdata, const Slapi_Entry *rawentry,
                               Slapi_Entry *ad_entry, Slapi_Entry *ds_entry)
{
    IPA_WinSync_Domain_Config *ipaconfig = (IPA_WinSync_Domain_Config *)cbdata;
    Slapi_Attr *attr = NULL;
    Slapi_Attr *e_attr = NULL;
    char *type = NULL;

    LOG("--> ipa_winsync_pre_ds_add_user_cb -- begin\n");

    if (!ipaconfig || !ipaconfig->domain_e || !ipaconfig->realm_name ||
        !ipaconfig->homedir_prefix) {
        LOG_FATAL("Error: configuration failure: cannot map Windows "
                  "entry dn [%s], DS entry dn [%s]\n",
                  slapi_entry_get_dn_const(ad_entry),
                  slapi_entry_get_dn_const(ds_entry));
        return;
    }

    /* add the objectclasses and attributes to the entry */
    for (slapi_entry_first_attr(ipaconfig->domain_e, &attr); attr;
         slapi_entry_next_attr(ipaconfig->domain_e, attr, &attr))
    {
        slapi_attr_get_type(attr, &type);
        if (!type) {
            continue; /* should never happen */
        }
        
        if (!slapi_entry_attr_find(ds_entry, type, &e_attr) && e_attr) {
            /* already has attribute - add missing values */
            Slapi_Value *sv = NULL;
            int ii = 0;
            for (ii = slapi_attr_first_value(attr, &sv); ii != -1;
                 ii = slapi_attr_next_value(attr, ii, &sv))
            {
                if (!slapi_entry_attr_has_syntax_value(ds_entry, type, sv)) {
                    /* attr-value sv not found in ds_entry; add it */
                    LOG("--> ipa_winsync_pre_ds_add_user_cb -- "
                        "adding val for [%s] to new entry [%s]\n",
                        type, slapi_entry_get_dn_const(ds_entry));

                    slapi_entry_add_value(ds_entry, type, sv);
                }
            }
        } else { /* attr not found */
            Slapi_ValueSet *svs = NULL;
            slapi_attr_get_valueset(attr, &svs); /* makes a copy */
            slapi_entry_add_valueset(ds_entry, type, svs);
            slapi_valueset_free(svs); /* free the copy */
        }
    }

    /* add other attributes */
    type = "krbPrincipalName";
    if (slapi_entry_attr_find(ds_entry, type, &e_attr) || !e_attr) {
        char *upn = NULL;
        char *uid = NULL;
        char *samAccountName = NULL;
        /* if the ds_entry already has a uid, use that */
        if ((uid = slapi_entry_attr_get_charptr(ds_entry, "uid"))) {
            upn = slapi_ch_smprintf("%s@%s", uid, ipaconfig->realm_name);
            slapi_ch_free_string(&uid);
        /* otherwise, use the samAccountName from the ad_entry */
        } else if ((samAccountName =
                    slapi_entry_attr_get_charptr(ad_entry, "samAccountName"))) {
            upn = slapi_ch_smprintf("%s@%s", samAccountName, ipaconfig->realm_name);
            slapi_ch_free_string(&samAccountName);
        } else { /* fatal error - nothing to use for krbPrincipalName */
            LOG_FATAL("Error creating %s for realm [%s] for Windows "
                      "entry dn [%s], DS entry dn [%s] - Windows entry "
                      "has no samAccountName, and DS entry has no uid.\n",
                      type, ipaconfig->realm_name,
                      slapi_entry_get_dn_const(ad_entry),
                      slapi_entry_get_dn_const(ds_entry));
        }

        if (upn) {
            slapi_entry_attr_set_charptr(ds_entry, type, upn);
            slapi_ch_free_string(&upn);
        }
    }

    type = "homeDirectory";
    if (slapi_entry_attr_find(ds_entry, type, &e_attr) || !e_attr) {
        char *homeDir = NULL;
        char *uid = NULL;
        char *samAccountName = NULL;
        /* if the ds_entry already has a uid, use that */
        if ((uid = slapi_entry_attr_get_charptr(ds_entry, "uid"))) {
            homeDir = slapi_ch_smprintf("%s/%s", ipaconfig->homedir_prefix, uid);
            slapi_ch_free_string(&uid);
        /* otherwise, use the samAccountName from the ad_entry */
        } else if ((samAccountName =
                    slapi_entry_attr_get_charptr(ad_entry, "samAccountName"))) {
            homeDir = slapi_ch_smprintf("%s/%s", ipaconfig->homedir_prefix,
                                        samAccountName);
            slapi_ch_free_string(&samAccountName);
        } else { /* fatal error - nothing to use for homeDirectory */
            LOG_FATAL("Error creating %s for realm [%s] for Windows "
                      "entry dn [%s], DS entry dn [%s] - Windows entry "
                      "has no samAccountName, and DS entry has no uid.\n",
                      type, ipaconfig->realm_name,
                      slapi_entry_get_dn_const(ad_entry),
                      slapi_entry_get_dn_const(ds_entry));
        }

        if (homeDir) {
            slapi_entry_attr_set_charptr(ds_entry, type, homeDir);
            slapi_ch_free_string(&homeDir);
        }
    }

    /* gecos is not required, but nice to have */
    type = "gecos";
    if (slapi_entry_attr_find(ds_entry, type, &e_attr) || !e_attr) {
        char *cn = NULL;
        char *displayName = NULL;
        /* if the ds_entry already has a cn, use that */
        if ((cn = slapi_entry_attr_get_charptr(ds_entry, "cn"))) {
            slapi_entry_attr_set_charptr(ds_entry, type, cn);
            slapi_ch_free_string(&cn);
        /* otherwise, use the displayName from the ad_entry */
        } else if ((displayName =
                    slapi_entry_attr_get_charptr(ad_entry, "displayName"))) {
            slapi_entry_attr_set_charptr(ds_entry, type, displayName);
            slapi_ch_free_string(&displayName);
        }
    }

    sync_acct_disable(cbdata, rawentry, ds_entry, ACCT_DISABLE_TO_DS,
                      ds_entry, NULL, NULL);
    LOG("<-- ipa_winsync_pre_ds_add_user_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_add_group_cb(void *cbdata, const Slapi_Entry *rawentry,
                                Slapi_Entry *ad_entry, Slapi_Entry *ds_entry)
{
    LOG("--> ipa_winsync_pre_ds_add_group_cb -- begin\n");

    LOG("<-- ipa_winsync_pre_ds_add_group_cb -- end\n");

    return;
}

static void
ipa_winsync_get_new_ds_user_dn_cb(void *cbdata, const Slapi_Entry *rawentry,
                                  Slapi_Entry *ad_entry, char **new_dn_string,
                                  const Slapi_DN *ds_suffix, const Slapi_DN *ad_suffix)
{
    char **rdns = NULL;
    PRBool flatten = PR_TRUE;
    IPA_WinSync_Config *ipaconfig = ipa_winsync_get_config();

    LOG("--> ipa_winsync_get_new_ds_user_dn_cb -- old dn [%s] -- begin\n",
                    *new_dn_string);

    slapi_lock_mutex(ipaconfig->lock);
    flatten = ipaconfig->flatten;
    slapi_unlock_mutex(ipaconfig->lock);

    if (!flatten) {
        return;
    }

    rdns = ldap_explode_dn(*new_dn_string, 0);
    if (!rdns || !rdns[0]) {
        ldap_value_free(rdns);
        return;
    }

    slapi_ch_free_string(new_dn_string);
    *new_dn_string = slapi_ch_smprintf("%s,%s", rdns[0], slapi_sdn_get_dn(ds_suffix));
    ldap_value_free(rdns);

    LOG("<-- ipa_winsync_get_new_ds_user_dn_cb -- new dn [%s] -- end\n",
                    *new_dn_string);

    return;
}

static void
ipa_winsync_get_new_ds_group_dn_cb(void *cbdata, const Slapi_Entry *rawentry,
                                   Slapi_Entry *ad_entry, char **new_dn_string,
                                   const Slapi_DN *ds_suffix, const Slapi_DN *ad_suffix)
{
    LOG("--> ipa_winsync_get_new_ds_group_dn_cb -- begin\n");

    LOG("<-- ipa_winsync_get_new_ds_group_dn_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_user_mods_cb(void *cbdata, const Slapi_Entry *rawentry,
                                    const Slapi_DN *local_dn,
                                    const Slapi_Entry *ds_entry,
                                    LDAPMod * const *origmods,
                                    Slapi_DN *remote_dn, LDAPMod ***modstosend)
{
    Slapi_Mods *smods;

    LOG("--> ipa_winsync_pre_ad_mod_user_mods_cb -- begin\n");

    /* wrap the modstosend in a Slapi_Mods for convenience */
    smods = slapi_mods_new();
    slapi_mods_init_byref(smods, *modstosend);
    sync_acct_disable(cbdata, rawentry, (Slapi_Entry *)ds_entry,
                      ACCT_DISABLE_TO_AD, NULL, smods, NULL);

    /* convert back to LDAPMod ** and clean up */
    *modstosend = slapi_mods_get_ldapmods_passout(smods);
    slapi_mods_free(&smods);
    LOG("<-- ipa_winsync_pre_ad_mod_user_mods_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_group_mods_cb(void *cbdata, const Slapi_Entry *rawentry,
                                     const Slapi_DN *local_dn,
                                     const Slapi_Entry *ds_entry,
                                     LDAPMod * const *origmods,
                                     Slapi_DN *remote_dn, LDAPMod ***modstosend)
{
    LOG("--> ipa_winsync_pre_ad_mod_group_mods_cb -- begin\n");

    LOG("<-- ipa_winsync_pre_ad_mod_group_mods_cb -- end\n");

    return;
}

static int
ipa_winsync_can_add_entry_to_ad_cb(void *cbdata, const Slapi_Entry *local_entry,
                                   const Slapi_DN *remote_dn)
{
    LOG("--> ipa_winsync_can_add_entry_to_ad_cb -- begin\n");

    LOG("<-- ipa_winsync_can_add_entry_to_ad_cb -- end\n");

    return 0; /* false - do not allow entries to be added to ad */
}

static void
ipa_winsync_begin_update_cb(void *cbdata, const Slapi_DN *ds_subtree,
                            const Slapi_DN *ad_subtree, int is_total)
{
    LOG("--> ipa_winsync_begin_update_cb -- begin\n");

    ipa_winsync_config_refresh_domain(cbdata, ds_subtree, ad_subtree);

    LOG("<-- ipa_winsync_begin_update_cb -- end\n");

    return;
}

static void
ipa_winsync_end_update_cb(void *cbdata, const Slapi_DN *ds_subtree,
                          const Slapi_DN *ad_subtree, int is_total)
{
    LOG("--> ipa_winsync_end_update_cb -- begin\n");

    LOG("<-- ipa_winsync_end_update_cb -- end\n");

    return;
}

static void
ipa_winsync_destroy_agmt_cb(void *cbdata, const Slapi_DN *ds_subtree,
                            const Slapi_DN *ad_subtree)
{
    LOG("--> ipa_winsync_destroy_agmt_cb -- begin\n");

    ipa_winsync_config_destroy_domain(cbdata, ds_subtree, ad_subtree);
    
    LOG("<-- ipa_winsync_destroy_agmt_cb -- end\n");

    return;
}

static void *ipa_winsync_api[] = {
    NULL, /* reserved for api broker use, must be zero */
    ipa_winsync_agmt_init,
    ipa_winsync_dirsync_search_params_cb,
    ipa_winsync_pre_ad_search_cb,
    ipa_winsync_pre_ds_search_entry_cb,
    ipa_winsync_pre_ds_search_all_cb,
    ipa_winsync_pre_ad_mod_user_cb,
    ipa_winsync_pre_ad_mod_group_cb,
    ipa_winsync_pre_ds_mod_user_cb,
    ipa_winsync_pre_ds_mod_group_cb,
    ipa_winsync_pre_ds_add_user_cb,
    ipa_winsync_pre_ds_add_group_cb,
    ipa_winsync_get_new_ds_user_dn_cb,
    ipa_winsync_get_new_ds_group_dn_cb,
    ipa_winsync_pre_ad_mod_user_mods_cb,
    ipa_winsync_pre_ad_mod_group_mods_cb,
    ipa_winsync_can_add_entry_to_ad_cb,
    ipa_winsync_begin_update_cb,
    ipa_winsync_end_update_cb,
    ipa_winsync_destroy_agmt_cb
};

/**
 * Plugin identifiers
 */
static Slapi_PluginDesc ipa_winsync_pdesc = {
    "ipa-winsync-plugin",
    "FreeIPA project",
    "FreeIPA/1.0",
    "ipa winsync plugin"
};

static Slapi_ComponentId *ipa_winsync_plugin_id = NULL;

/*
** Plugin identity mgmt
*/

void ipa_winsync_set_plugin_identity(void * identity) 
{
	ipa_winsync_plugin_id=identity;
}

void * ipa_winsync_get_plugin_identity(void)
{
	return ipa_winsync_plugin_id;
}

static int
ipa_winsync_plugin_start(Slapi_PBlock *pb)
{
	int rc;
	Slapi_Entry *config_e = NULL; /* entry containing plugin config */

    LOG("--> ipa_winsync_plugin_start -- begin\n");

	if( slapi_apib_register(WINSYNC_v1_0_GUID, ipa_winsync_api) ) {
            LOG_FATAL("<-- ipa_winsync_plugin_start -- failed to register winsync api -- end\n");
            return -1;
	}
	
    if ( slapi_pblock_get( pb, SLAPI_ADD_ENTRY, &config_e ) != 0 ) {
        LOG_FATAL("missing config entry\n" );
        return( -1 );
    }

    if (( rc = ipa_winsync_config( config_e )) != LDAP_SUCCESS ) {
        LOG_FATAL("configuration failed (%s)\n", ldap_err2string( rc ));
        return( -1 );
    }

    LOG("<-- ipa_winsync_plugin_start -- end\n");
    return 0;
}

static int
ipa_winsync_plugin_close(Slapi_PBlock *pb)
{
    LOG("--> ipa_winsync_plugin_close -- begin\n");

	slapi_apib_unregister(WINSYNC_v1_0_GUID);

    LOG("<-- ipa_winsync_plugin_close -- end\n");
	return 0;
}

/* this is the slapi plugin init function,
   not the one used by the winsync api
*/
int ipa_winsync_plugin_init(Slapi_PBlock *pb)
{
    void *plugin_id = NULL;

    LOG("--> ipa_winsync_plugin_init -- begin\n");

    if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION,
                           SLAPI_PLUGIN_VERSION_01 ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                          (void *) ipa_winsync_plugin_start ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                          (void *) ipa_winsync_plugin_close ) != 0 ||
         slapi_pblock_set( pb, SLAPI_PLUGIN_DESCRIPTION,
                           (void *)&ipa_winsync_pdesc ) != 0 )
    {
        LOG_FATAL("<-- ipa_winsync_plugin_init -- failed to register plugin -- end\n");
        return -1;
    }

    /* Retrieve and save the plugin identity to later pass to
       internal operations */
    if (slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_id) != 0) {
        LOG_FATAL("<-- ipa_winsync_plugin_init -- failed to retrieve plugin identity -- end\n");
        return -1;
    }

    ipa_winsync_set_plugin_identity(plugin_id);

    LOG("<-- ipa_winsync_plugin_init -- end\n");
    return 0;
}

/*
 * Check if the given entry has account lock on (i.e. entry is disabled)
 * Mostly copied from check_account_lock in the server code.
 * Returns: 0 - account is disabled (lock == "true")
 *          1 - account is enabled (lock == "false" or empty)
 *         -1 - some sort of error
 */
static int
ipa_check_account_lock(Slapi_Entry *ds_entry, int *isvirt)
{
    int rc = 1;
    Slapi_ValueSet *values = NULL;
    int type_name_disposition = 0;
    char *actual_type_name = NULL;
    int attr_free_flags = 0;
    char *strval;

    /* first, see if the attribute is a "real" attribute */
    strval = slapi_entry_attr_get_charptr(ds_entry, "nsAccountLock");
    if (strval) { /* value is real */
        *isvirt = 0; /* value is real */
        rc = 1; /* default to enabled */
        if (PL_strncasecmp(strval, "true", 4) == 0) {
            rc = 0; /* account is disabled */
        }
        slapi_ch_free_string(&strval);
        LOG("<-- ipa_check_account_lock - entry [%s] has real "
            "attribute nsAccountLock and entry %s locked\n",
            slapi_entry_get_dn_const(ds_entry),
            rc ? "is not" : "is");
        return rc;
    }

    rc = slapi_vattr_values_get(ds_entry, "nsAccountLock", 
                                &values, 
                                &type_name_disposition, &actual_type_name,
                                SLAPI_VIRTUALATTRS_REQUEST_POINTERS,
                                &attr_free_flags);
    if (rc == 0) {
        Slapi_Value *v = NULL;	
        const struct berval *bvp = NULL;

        rc = 1; /* default is enabled */
        *isvirt = 1; /* value is virtual */
        if ((slapi_valueset_first_value(values, &v) != -1) &&
            (bvp = slapi_value_get_berval(v)) != NULL) {
            if ( (bvp != NULL) && (PL_strncasecmp(bvp->bv_val, "true", 4) == 0) ) {
                slapi_vattr_values_free(&values, &actual_type_name, attr_free_flags);
                rc = 0; /* account is disabled */
            }
        }

        if (values != NULL) {
            slapi_vattr_values_free(&values, &actual_type_name, attr_free_flags);
        }
        LOG("<-- ipa_check_account_lock - entry [%s] has virtual "
            "attribute nsAccountLock and entry %s locked\n",
            slapi_entry_get_dn_const(ds_entry),
            rc ? "is not" : "is");
    } else {
        rc = 1; /* no attr == entry is enabled */
        LOG("<-- ipa_check_account_lock - entry [%s] does not "
            "have attribute nsAccountLock - entry %s locked\n",
            slapi_entry_get_dn_const(ds_entry),
            rc ? "is not" : "is");
    }

    return rc;
}

static int
do_group_modify(const char *dn, const char *modtype, int modop, const char *modval)
{
    int rc = 0;
    LDAPMod mod;
    LDAPMod *mods[2];
    const char *val[2];
    Slapi_PBlock *mod_pb = NULL;

    mod_pb = slapi_pblock_new();

    mods[0] = &mod;
    mods[1] = NULL;

    val[0] = modval;
    val[1] = NULL;

    mod.mod_op = modop;
    mod.mod_type = (char *)modtype;
    mod.mod_values = (char **)val;

    slapi_modify_internal_set_pb(
        mod_pb, dn, mods, 0, 0,
        ipa_winsync_get_plugin_identity(), 0);

    slapi_modify_internal_pb(mod_pb);

    slapi_pblock_get(mod_pb,
                     SLAPI_PLUGIN_INTOP_RESULT,
                     &rc);

    slapi_pblock_destroy(mod_pb);

    LOG("<-- do_group_modify - %s value [%s] in attribute [%s] "
        "in entry [%s] - result (%d: %s)\n",
        (modop & LDAP_MOD_ADD) ? "added" : "deleted",
        modval, modtype, dn,
        rc, ldap_err2string(rc));

    return rc;
}

/*
 * This can be used either in the to ad direction or the to ds direction, since in both
 * cases we have to read both entries and compare the values.
 * ad_entry - entry from AD
 * ds_entry - entry from DS
 * direction - either ACCT_DISABLE_TO_AD or ACCT_DISABLE_TO_DS
 *
 * If smods is given, this is the list of mods to send in the given direction.  The
 * appropriate modify operation will be added to this list or changed to the correct
 * value if it already exists.
 * Otherwise, if a destination entry is given, the value will be written into
 * that entry.
 */
static void
sync_acct_disable(
    void *cbdata, /* the usual domain config data */
    const Slapi_Entry *ad_entry, /* the AD entry */
    Slapi_Entry *ds_entry, /* the DS entry */
    int direction, /* the direction - TO_AD or TO_DS */
    Slapi_Entry *update_entry, /* the entry to update for ADDs */
    Slapi_Mods *smods, /* the mod list for MODIFYs */
    int *do_modify /* if not NULL, set this to true if mods were added */
)
{
    IPA_WinSync_Domain_Config *ipaconfig = (IPA_WinSync_Domain_Config *)cbdata;
    IPA_WinSync_Config *global_ipaconfig = ipa_winsync_get_config();
    int acct_disable;
    int ds_is_enabled = 1; /* default to true */
    int ad_is_enabled = 1; /* default to true */
    unsigned long adval = 0; /* raw account val from ad entry */
    int isvirt = 1; /* default to virt */

    slapi_lock_mutex(global_ipaconfig->lock);
    acct_disable = global_ipaconfig->acct_disable;
    slapi_unlock_mutex(global_ipaconfig->lock);

    if (acct_disable == ACCT_DISABLE_NONE) {
        return; /* not supported */
    }

    /* get the account lock state of the ds entry */
    if (0 == ipa_check_account_lock(ds_entry, &isvirt)) {
        ds_is_enabled = 0;
    }

    /* get the account lock state of the ad entry */
    adval = slapi_entry_attr_get_ulong(ad_entry, "UserAccountControl");
    if (adval & 0x2) {
        /* account is disabled */
        ad_is_enabled = 0;
    }

    if (ad_is_enabled == ds_is_enabled) { /* both have same value - nothing to do */
        return;
    }

    /* have to enable or disable */
    if (direction == ACCT_DISABLE_TO_AD) {
        unsigned long mask;
        /* set the mod or entry */
        if (update_entry) {
            if (ds_is_enabled) {
                mask = ~0x2;
                adval &= mask; /* unset the 0x2 disable bit */
            } else {
                mask = 0x2;
                adval |= mask; /* set the 0x2 disable bit */
            }
            slapi_entry_attr_set_ulong(update_entry, "userAccountControl", adval);
            LOG("<-- sync_acct_disable - %s AD account [%s] - "
                "new value is [%ld]\n",
                (ds_is_enabled) ? "enabled" : "disabled",
                slapi_entry_get_dn_const(update_entry),
                adval);
        } else {
            /* iterate through the mods - if there is already a mod
               for userAccountControl, change it - otherwise, add it */
            char acctvalstr[32];
            LDAPMod *mod = NULL;
            struct berval *mod_bval = NULL;
            for (mod = slapi_mods_get_first_mod(smods); mod;
                 mod = slapi_mods_get_next_mod(smods)) {
                if (!PL_strcasecmp(mod->mod_type, "userAccountControl") &&
                    mod->mod_bvalues && mod->mod_bvalues[0]) {
                    mod_bval = mod->mod_bvalues[0];
                    /* mod_bval points directly to value inside mod list */
                    break;
                }
            }
            if (!mod_bval) { /* not found - add it */
                struct berval tmpbval = {0, NULL};
                Slapi_Mod *smod = slapi_mod_new();
                slapi_mod_init(smod, 1); /* one element */
                slapi_mod_set_type(smod, "userAccountControl");
                slapi_mod_set_operation(smod, LDAP_MOD_REPLACE|LDAP_MOD_BVALUES);
                slapi_mod_add_value(smod, &tmpbval);
                /* add_value makes a copy of the bval - so let's get a pointer
                   to that new value - we will change the bval in place */
                mod_bval = slapi_mod_get_first_value(smod);
                /* mod_bval points directly to value inside mod list */
                /* now add the new mod to smods */
                slapi_mods_add_ldapmod(smods,
                                       slapi_mod_get_ldapmod_passout(smod));
                /* smods now owns the ldapmod */
                slapi_mod_free(&smod);
                if (do_modify) {
                    *do_modify = 1; /* added mods */
                }
            }
            if (mod_bval) {
                /* this is where we set or update the actual value
                   mod_bval points directly into the mod list we are
                   sending */
                if (mod_bval->bv_val && (mod_bval->bv_len > 0)) {
                    /* get the old val */
                    adval = strtol(mod_bval->bv_val, NULL, 10);
                }
                if (ds_is_enabled) {
                    mask = ~0x2;
                    adval &= mask; /* unset the 0x2 disable bit */
                } else {
                    mask = 0x2;
                    adval |= mask; /* set the 0x2 disable bit */
                }
                PR_snprintf(acctvalstr, sizeof(acctvalstr), "%lu", adval);
                slapi_ch_free_string(&mod_bval->bv_val);
                mod_bval->bv_val = slapi_ch_strdup(acctvalstr);
                mod_bval->bv_len = strlen(acctvalstr);
            }
            LOG("<-- sync_acct_disable - %s AD account [%s] - "
                "new value is [%ld]\n",
                (ds_is_enabled) ? "enabled" : "disabled",
                slapi_entry_get_dn_const(ad_entry),
                adval);
        }
    }

    if (direction == ACCT_DISABLE_TO_DS) {
        if (!isvirt) {
            char *attrtype = NULL;
            char *attrval = NULL;
            attrtype = "nsAccountLock";
            if (ad_is_enabled) {
                attrval = NULL; /* will delete the value */
            } else {
                attrval = "true";
            }

            if (update_entry) {
                slapi_entry_attr_set_charptr(update_entry, attrtype, attrval);
                LOG("<-- sync_acct_disable - %s DS account [%s]\n",
                    (ad_is_enabled) ? "enabled" : "disabled",
                    slapi_entry_get_dn_const(ds_entry));
            } else { /* do mod */
                struct berval tmpbval = {0, NULL};
                Slapi_Mod *smod = slapi_mod_new();
                slapi_mod_init(smod, 1); /* one element */
                slapi_mod_set_type(smod, attrtype);
                if (attrval == NULL) {
                    slapi_mod_set_operation(smod, LDAP_MOD_DELETE|LDAP_MOD_BVALUES);
                } else {
                    slapi_mod_set_operation(smod, LDAP_MOD_REPLACE|LDAP_MOD_BVALUES);
                }
                slapi_mod_add_value(smod, &tmpbval);
                slapi_mods_add_ldapmod(smods,
                                       slapi_mod_get_ldapmod_passout(smod));
                slapi_mod_free(&smod);
                LOG("<-- sync_acct_disable - %s DS account [%s]\n",
                    (ad_is_enabled) ? "enabled" : "disabled",
                    slapi_entry_get_dn_const(ds_entry));
                if (do_modify) {
                    *do_modify = 1; /* added mods */
                }
            }
        } else { /* use the virtual attr scheme */
            char *adddn, *deldn;
            const char *dsdn;
            int rc;
            /* in the case of disabling a user, need to remove that user from
               the activated group, if in there, and add to the inactivated group
               however, in the case of enabling a user, we just have to remove
               the user from the inactivated group, if in there - if the user
               is not in any group, the user is activated by default
            */
            if (ad_is_enabled) {
                /* add user to activated group, delete from inactivated group */
                adddn = NULL; /* no group means active by default */
                deldn = ipaconfig->inactivated_group_dn;
            } else {
                /* add user to inactivated group, delete from activated group */
                adddn = ipaconfig->inactivated_group_dn;
                deldn = ipaconfig->activated_group_dn;
            }

            dsdn = slapi_entry_get_dn_const(ds_entry);
            LOG("<-- sync_acct_disable - %s DS account [%s] - "
                "deldn [%s] adddn [%s]\n",
                (ad_is_enabled) ? "enabling" : "disabling",
                slapi_entry_get_dn_const(ds_entry),
                deldn, adddn);
            /* first, delete the user from the deldn group - ignore (but log)
               value not found errors - means the user wasn't there yet */
            rc = do_group_modify(deldn, "member", LDAP_MOD_DELETE, dsdn);
            if (rc == LDAP_NO_SUCH_ATTRIBUTE) {
                /* either the value of the attribute doesn't exist */
                LOG("Could not delete user [%s] from the [%s] group: "
                    "either the user was not in the group already, "
                    "or the group had no members\n",
                    dsdn, deldn);
            } else if (rc != LDAP_SUCCESS) {
                LOG_FATAL("Error deleting user [%s] from the [%s] group: "
                          "(%d - %s)\n", dsdn, deldn, rc,
                          ldap_err2string(rc));
            }
            /* next, add the user to the adddn group - ignore (but log)
               if the user is already in that group */
            if (adddn) {
                rc = do_group_modify(adddn, "member", LDAP_MOD_ADD, dsdn);
            } else {
                rc = LDAP_SUCCESS;
            }
            if (rc == LDAP_TYPE_OR_VALUE_EXISTS) {
                /* user already in that group */
                LOG("Could not add user [%s] to the [%s] group: "
                    "user is already in that group\n",
                    dsdn, adddn);
            } else if (rc != LDAP_SUCCESS) {
                LOG_FATAL("Error adding user [%s] to the [%s] group: "
                          "(%d - %s)\n", dsdn, adddn, rc,
                          ldap_err2string(rc));
            }
#ifndef MEMBEROF_WORKS_FOR_INTERNAL_OPS
            /* memberOf doesn't currently listen for internal operations
               that change group membership - so we manually set the
               memberOf attribute in the ds entry - this should not
               conflict with memberOf */
            {
                Slapi_Value *sv = slapi_value_new();
                slapi_value_init_string(sv, deldn);
                if (slapi_entry_attr_has_syntax_value(ds_entry,
                                                      "memberOf", sv)) {
                    if (smods) {
                        slapi_mods_add_string(smods, LDAP_MOD_DELETE,
                                              "memberOf", deldn);
                        if (do_modify) {
                            *do_modify = 1; /* added mods */
                        }
                    } else if (update_entry) {
                        slapi_entry_delete_string(update_entry,
                                                  "memberOf", deldn);
                    }
                }
                if (adddn) {
                    slapi_value_set_string(sv, adddn);
                    if (!slapi_entry_attr_has_syntax_value(ds_entry,
                                                           "memberOf", sv)) {
                        if (smods) {
                            slapi_mods_add_string(smods, LDAP_MOD_ADD,
                                                  "memberOf", adddn);
                            if (do_modify) {
                                *do_modify = 1; /* added mods */
                            }
                        } else if (update_entry) {
                            slapi_entry_add_string(update_entry,
                                                   "memberOf", adddn);
                        }
                    }
                }
                slapi_value_free(&sv);
            }
#endif /* MEMBEROF_WORKS_FOR_INTERNAL_OPS */
            LOG("<-- sync_acct_disable - %s DS account [%s]\n",
                (ad_is_enabled) ? "enabled" : "disabled",
                slapi_entry_get_dn_const(ds_entry));
        }
    }

    return;
}

/* if entry does not have attribute type and val, and neither
   does the smods, add them to the smods */
static void
find_and_add_mod(Slapi_Entry *ent, Slapi_Mods *smods, const char *type,
                 const char *val, size_t vallen, int *do_modify)
{
    int found = 1;
    Slapi_Value *sv = slapi_value_new();
    LDAPMod *mod = NULL;

    slapi_value_init_string(sv, val);
    if (!slapi_entry_attr_has_syntax_value(ent, type, sv)) {
        /* entry doesn't have type val - see if there is already
           a mod in the mods list that adds it replaces it */
        found = 0; /* not found in entry - see if in mod list */
        for (mod = slapi_mods_get_first_mod(smods);
             !found && mod;
             mod = slapi_mods_get_next_mod(smods)) {
            int ii;
            if (PL_strcasecmp(mod->mod_type, type)) {
                continue; /* skip - not a mod of this type */
            }
            if (!(mod->mod_op & (LDAP_MOD_ADD|LDAP_MOD_REPLACE))) {
                continue; /* skip - not an add or replace op */
            }
            /* now see if val is in the list of vals for this mod op */
            for (ii = 0;
                 !found && mod->mod_bvalues && mod->mod_bvalues[ii];
                 ++ii) {
                if (mod->mod_bvalues[ii]->bv_val) {
                    found = !PL_strncasecmp(mod->mod_bvalues[ii]->bv_val,
                                            val, vallen);
                }
            }
        }
    }
    if (!found) {
        slapi_mods_add_string(smods, LDAP_MOD_ADD, type, val);
        if (do_modify) {
            *do_modify = 1; /* added a mod */
        }
        LOG("<-- find_and_add_mod - added value [%s] "
            "to attribute [%s] in entry [%s]\n",
            val, type, slapi_entry_get_dn_const(ent));
    }
    slapi_value_free(&sv);

    return;
}

/*
 * If force sync is true, any time an entry is being added or modified
 * in DS, we must ensure the entry has the ntUser objectclass, and that
 * it has the ntUserDomainID attribute, and the value of that attribute
 * corresponds to the samAccountName in the AD entry.
 * ad_entry - entry from AD
 * ds_entry - entry from DS
 *
 * The appropriate modify operation will be added to the given smods
 * if it doesn't already exist.
 */
static void
do_force_sync(
    const Slapi_Entry *ad_entry, /* the AD entry */
    Slapi_Entry *ds_entry, /* the DS entry */
    Slapi_Mods *smods, /* the mod list for MODIFYs */
    int *do_modify /* if not NULL, set to true if mods were added */
)
{
    IPA_WinSync_Config *global_ipaconfig = ipa_winsync_get_config();
    PRBool forceSync;

    slapi_lock_mutex(global_ipaconfig->lock);
    forceSync = global_ipaconfig->forceSync;
    slapi_unlock_mutex(global_ipaconfig->lock);

    if (forceSync == PR_FALSE) {
        return; /* not supported */
    }

    LOG("do_force_sync - forcing sync of AD entry [%s] "
        "with DS entry [%s]\n",
        slapi_entry_get_dn_const(ad_entry),
        slapi_entry_get_dn_const(ds_entry));

    find_and_add_mod(ds_entry, smods, "objectClass", "ntUser", (size_t)6, do_modify);

    return;
}
