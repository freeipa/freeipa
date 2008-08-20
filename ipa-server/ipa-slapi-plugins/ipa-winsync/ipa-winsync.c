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

/*
 * Windows Synchronization Plug-in for IPA
 * This plugin allows IPA to intercept operations sent from
 * Windows to the directory server and vice versa.  This allows
 * IPA to intercept new users added to Windows and synced to the
 * directory server, and allows IPA to modify the entry, adding
 * objectclasses and attributes, and changing the DN.
 */

#include <slapi-plugin.h>
#include "winsync-plugin.h"
/*
#include <dirsrv/slapi-plugin.h>
#include <dirsrv/winsync-plugin.h>
*/
#include "ipa-winsync.h"

static char *ipa_winsync_plugin_name = IPA_WINSYNC_PLUGIN_NAME;

/* This is called when a new agreement is created or loaded
   at startup.
*/
static void *
ipa_winsync_agmt_init(const Slapi_DN *ds_subtree, const Slapi_DN *ad_subtree)
{
    void *cbdata = NULL;
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_agmt_init [%s] [%s] -- begin\n",
                    slapi_sdn_get_dn(ds_subtree),
                    slapi_sdn_get_dn(ad_subtree));

    /* do the domain specific configuration based on the ds subtree */
    cbdata = ipa_winsync_config_new_domain(ds_subtree, ad_subtree);

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_agmt_init -- end\n");

    return cbdata;
}

static void
ipa_winsync_dirsync_search_params_cb(void *cbdata, const char *agmt_dn,
                                     char **base, int *scope, char **filter,
                                     char ***attrs, LDAPControl ***serverctrls)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_dirsync_search_params_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_dirsync_search_params_cb -- end\n");

    return;
}

/* called before searching for a single entry from AD - agmt_dn will be NULL */
static void
ipa_winsync_pre_ad_search_cb(void *cbdata, const char *agmt_dn,
                             char **base, int *scope, char **filter,
                             char ***attrs, LDAPControl ***serverctrls)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ad_search_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ad_search_cb -- end\n");

    return;
}

/* called before an internal search to get a single DS entry - agmt_dn will be NULL */
static void
ipa_winsync_pre_ds_search_entry_cb(void *cbdata, const char *agmt_dn,
                                   char **base, int *scope, char **filter,
                                   char ***attrs, LDAPControl ***serverctrls)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_search_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ds_search_cb -- end\n");

    return;
}

/* called before the total update to get all entries from the DS to sync to AD */
static void
ipa_winsync_pre_ds_search_all_cb(void *cbdata, const char *agmt_dn,
                                 char **base, int *scope, char **filter,
                                 char ***attrs, LDAPControl ***serverctrls)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_search_all_cb -- orig filter [%s] -- begin\n",
                    ((filter && *filter) ? *filter : "NULL"));

    /* We only want to grab users from the ds side - no groups */
    slapi_ch_free_string(filter);
    /* maybe use ntUniqueId=* - only get users that have already been
       synced with AD - ntUniqueId and ntUserDomainId are
       indexed for equality only - need to add presence? */
    *filter = slapi_ch_strdup("(&(objectclass=ntuser)(ntUserDomainId=*))");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ds_search_all_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_user_cb(void *cbdata, const Slapi_Entry *rawentry,
                               Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                               Slapi_Mods *smods, int *do_modify)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ad_mod_user_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ad_mod_user_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_group_cb(void *cbdata, const Slapi_Entry *rawentry,
                                Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                                Slapi_Mods *smods, int *do_modify)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ad_mod_group_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ad_mod_group_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_mod_user_cb(void *cbdata, const Slapi_Entry *rawentry,
                               Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                               Slapi_Mods *smods, int *do_modify)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_mod_user_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ds_mod_user_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_mod_group_cb(void *cbdata, const Slapi_Entry *rawentry,
                                Slapi_Entry *ad_entry, Slapi_Entry *ds_entry,
                                Slapi_Mods *smods, int *do_modify)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_mod_group_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ds_mod_group_cb -- end\n");

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
    PRBool flatten = PR_TRUE;
    IPA_WinSync_Config *global_ipaconfig = ipa_winsync_get_config();

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_add_user_cb -- begin\n");

    if (!ipaconfig || !ipaconfig->domain_e || !ipaconfig->realm_name ||
        !ipaconfig->homedir_prefix) {
        slapi_log_error(SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
                        "Error: configuration failure: cannot map Windows "
                        "entry dn [%s], DS entry dn [%s]\n",
                        slapi_entry_get_dn_const(ad_entry),
                        slapi_entry_get_dn_const(ds_entry));
        return;
    }


    slapi_lock_mutex(global_ipaconfig->lock);
    flatten = global_ipaconfig->flatten;
    slapi_unlock_mutex(global_ipaconfig->lock);

    if (flatten) {
        char **rdns = NULL;
        int ii;
        /* grab the ous from the DN and store them in the entry */
        type = "ou";
        rdns = ldap_explode_dn(slapi_entry_get_dn_const(ad_entry), 0);
        for (ii = 0; rdns && rdns[ii]; ++ii) {
            /* go through the DN looking for ou= rdns */
            if (!PL_strncasecmp(rdns[ii], "ou=", 3)) {
                char *val = PL_strchr(rdns[ii], '=');
                Slapi_Value *sv = NULL;
                val++;
                sv = slapi_value_new_string(val);
                /* entry could already have this value */
                if (!slapi_entry_attr_has_syntax_value(ds_entry, type, sv)) {
                    /* attr-value sv not found in ds_entry; add it */
                    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                                    "--> ipa_winsync_pre_ds_add_user_cb -- "
                                    "adding val for [%s] to new entry [%s]\n",
                                    type, slapi_entry_get_dn_const(ds_entry));

                    slapi_entry_add_value(ds_entry, type, sv);
                }
                slapi_value_free(&sv);
            }
        }
        ldap_value_free(rdns);
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
                    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                                    "--> ipa_winsync_pre_ds_add_user_cb -- "
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
            slapi_log_error(SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
                            "Error creating %s for realm [%s] for Windows "
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
            slapi_log_error(SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
                            "Error creating %s for realm [%s] for Windows "
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

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ds_add_user_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ds_add_group_cb(void *cbdata, const Slapi_Entry *rawentry,
                                Slapi_Entry *ad_entry, Slapi_Entry *ds_entry)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_add_group_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ds_add_group_cb -- end\n");

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

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_get_new_ds_user_dn_cb -- old dn [%s] -- begin\n",
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

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_get_new_ds_user_dn_cb -- new dn [%s] -- end\n",
                    *new_dn_string);

    return;
}

static void
ipa_winsync_get_new_ds_group_dn_cb(void *cbdata, const Slapi_Entry *rawentry,
                                   Slapi_Entry *ad_entry, char **new_dn_string,
                                   const Slapi_DN *ds_suffix, const Slapi_DN *ad_suffix)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_get_new_ds_group_dn_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_get_new_ds_group_dn_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_user_mods_cb(void *cbdata, const Slapi_Entry *rawentry,
                                    const Slapi_DN *local_dn, LDAPMod * const *origmods,
                                    Slapi_DN *remote_dn, LDAPMod ***modstosend)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ad_mod_user_mods_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ad_mod_user_mods_cb -- end\n");

    return;
}

static void
ipa_winsync_pre_ad_mod_group_mods_cb(void *cbdata, const Slapi_Entry *rawentry,
                                     const Slapi_DN *local_dn, LDAPMod * const *origmods,
                                     Slapi_DN *remote_dn, LDAPMod ***modstosend)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ad_mod_group_mods_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_pre_ad_mod_group_mods_cb -- end\n");

    return;
}

static int
ipa_winsync_can_add_entry_to_ad_cb(void *cbdata, const Slapi_Entry *local_entry,
                                   const Slapi_DN *remote_dn)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_can_add_entry_to_ad_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_can_add_entry_to_ad_cb -- end\n");

    return 0; /* false - do not allow entries to be added to ad */
}

static void
ipa_winsync_begin_update_cb(void *cbdata, const Slapi_DN *ds_subtree,
                            const Slapi_DN *ad_subtree, int is_total)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_begin_update_cb -- begin\n");

    ipa_winsync_config_refresh_domain(cbdata, ds_subtree, ad_subtree);

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_begin_update_cb -- end\n");

    return;
}

static void
ipa_winsync_end_update_cb(void *cbdata, const Slapi_DN *ds_subtree,
                          const Slapi_DN *ad_subtree, int is_total)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_end_update_cb -- begin\n");

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_end_update_cb -- end\n");

    return;
}

static void
ipa_winsync_destroy_agmt_cb(void *cbdata, const Slapi_DN *ds_subtree,
                            const Slapi_DN *ad_subtree)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_destroy_agmt_cb -- begin\n");

    ipa_winsync_config_destroy_domain(cbdata, ds_subtree, ad_subtree);
    
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_destroy_agmt_cb -- end\n");

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

void * ipa_winsync_get_plugin_identity()
{
	return ipa_winsync_plugin_id;
}

static int
ipa_winsync_plugin_start(Slapi_PBlock *pb)
{
	int rc;
	Slapi_Entry *config_e = NULL; /* entry containing plugin config */

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_plugin_start -- begin\n");

	if( slapi_apib_register(WINSYNC_v1_0_GUID, ipa_winsync_api) ) {
        slapi_log_error( SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
                         "<-- ipa_winsync_plugin_start -- failed to register winsync api -- end\n");
        return -1;
	}
	
    if ( slapi_pblock_get( pb, SLAPI_ADD_ENTRY, &config_e ) != 0 ) {
		slapi_log_error( SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
						 "missing config entry\n" );
		return( -1 );
    }

    if (( rc = ipa_winsync_config( config_e )) != LDAP_SUCCESS ) {
		slapi_log_error( SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
						 "configuration failed (%s)\n", ldap_err2string( rc ));
		return( -1 );
    }

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_plugin_start -- end\n");
	return 0;
}

static int
ipa_winsync_plugin_close(Slapi_PBlock *pb)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_plugin_close -- begin\n");

	slapi_apib_unregister(WINSYNC_v1_0_GUID);

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "<-- ipa_winsync_plugin_close -- end\n");
	return 0;
}

/* this is the slapi plugin init function,
   not the one used by the winsync api
*/
int ipa_winsync_plugin_init(Slapi_PBlock *pb)
{
    void *plugin_id = NULL;

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_plugin_init -- begin\n");

    if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION,
                           SLAPI_PLUGIN_VERSION_01 ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                          (void *) ipa_winsync_plugin_start ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                          (void *) ipa_winsync_plugin_close ) != 0 ||
         slapi_pblock_set( pb, SLAPI_PLUGIN_DESCRIPTION,
                           (void *)&ipa_winsync_pdesc ) != 0 )
    {
        slapi_log_error( SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
                         "<-- ipa_winsync_plugin_init -- failed to register plugin -- end\n");
        return -1;
    }

    /* Retrieve and save the plugin identity to later pass to
       internal operations */
    if (slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_id) != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, ipa_winsync_plugin_name,
                         "<-- ipa_winsync_plugin_init -- failed to retrieve plugin identity -- end\n");
        return -1;
    }

    ipa_winsync_set_plugin_identity(plugin_id);

    slapi_log_error( SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                     "<-- ipa_winsync_plugin_init -- end\n");
    return 0;
}
