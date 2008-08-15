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

#include <dirsrv/slapi-plugin.h>
#include <dirsrv/winsync-plugin.h>
#include <ipa-winsync.h>

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
       synced with AD already - ntUniqueId and ntUserDomainId are
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
    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_pre_ds_add_user_cb -- begin\n");

    /* add the objectclasses to the entry */

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

    slapi_log_error(SLAPI_LOG_PLUGIN, ipa_winsync_plugin_name,
                    "--> ipa_winsync_get_new_ds_user_dn_cb -- old dn [%s] -- begin\n",
                    *new_dn_string);

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
