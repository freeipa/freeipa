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

#ifdef WINSYNC_TEST_IPA
#include <slapi-plugin.h>
#include "winsync-plugin.h"
#else
#include <dirsrv/slapi-plugin.h>
#include <dirsrv/winsync-plugin.h>
#endif
#include "ipa-winsync.h"

#include <string.h>

#define IPA_WINSYNC_CONFIG_FILTER "(objectclass=*)"

/*
 * function prototypes
 */ 
static int ipa_winsync_validate_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
                                        int *returncode, char *returntext, void *arg);
static int ipa_winsync_apply_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
                                     int *returncode, char *returntext, void *arg);
static int ipa_winsync_search (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
                               int *returncode, char *returntext, void *arg)
{
    return SLAPI_DSE_CALLBACK_OK;
}

/*
 * static variables
 */
/* for now, there is only one configuration and it is global to the plugin  */
static IPA_WinSync_Config theConfig;
static int inited = 0;

static int dont_allow_that(Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
						   int *returncode, char *returntext, void *arg)
{
    *returncode = LDAP_UNWILLING_TO_PERFORM;
    return SLAPI_DSE_CALLBACK_ERROR;
}

IPA_WinSync_Config *
ipa_winsync_get_config()
{
    return &theConfig;
}

/*
 * Read configuration and create a configuration data structure.
 * This is called after the server has configured itself so we can check
 * schema and whatnot.
 * Returns an LDAP error code (LDAP_SUCCESS if all goes well).
 */
int
ipa_winsync_config(Slapi_Entry *config_e)
{
    int returncode = LDAP_SUCCESS;
    char returntext[SLAPI_DSE_RETURNTEXT_SIZE];

    if ( inited ) {
        slapi_log_error( SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                         "only one PAM pass through plugin instance can be used\n" );
        return( LDAP_PARAM_ERROR );
    }

    /* initialize fields */
    if ((theConfig.lock = slapi_new_mutex()) == NULL) {
        return( LDAP_LOCAL_ERROR );
    }

    /* init defaults */
    theConfig.config_e = slapi_entry_alloc();
    slapi_entry_init(theConfig.config_e, slapi_ch_strdup(""), NULL);
    theConfig.flatten = PR_TRUE;

    if (SLAPI_DSE_CALLBACK_OK == ipa_winsync_validate_config(NULL, NULL, config_e,
                                                             &returncode, returntext, NULL)) {
        ipa_winsync_apply_config(NULL, NULL, config_e,
                                 &returncode, returntext, NULL);
    }

    /* config DSE must be initialized before we get here */
    if (returncode == LDAP_SUCCESS) {
        const char *config_dn = slapi_entry_get_dn_const(config_e);
        slapi_config_register_callback(SLAPI_OPERATION_MODIFY, DSE_FLAG_PREOP, config_dn, LDAP_SCOPE_BASE,
                                       IPA_WINSYNC_CONFIG_FILTER, ipa_winsync_validate_config,NULL);
        slapi_config_register_callback(SLAPI_OPERATION_MODIFY, DSE_FLAG_POSTOP, config_dn, LDAP_SCOPE_BASE,
                                       IPA_WINSYNC_CONFIG_FILTER, ipa_winsync_apply_config,NULL);
        slapi_config_register_callback(SLAPI_OPERATION_MODRDN, DSE_FLAG_PREOP, config_dn, LDAP_SCOPE_BASE,
                                       IPA_WINSYNC_CONFIG_FILTER, dont_allow_that, NULL);
        slapi_config_register_callback(SLAPI_OPERATION_DELETE, DSE_FLAG_PREOP, config_dn, LDAP_SCOPE_BASE,
                                       IPA_WINSYNC_CONFIG_FILTER, dont_allow_that, NULL);
        slapi_config_register_callback(SLAPI_OPERATION_SEARCH, DSE_FLAG_PREOP, config_dn, LDAP_SCOPE_BASE,
                                       IPA_WINSYNC_CONFIG_FILTER, ipa_winsync_search,NULL);
    }

    inited = 1;

    if (returncode != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error %d: %s\n", returncode, returntext);
    }

    return returncode;
}

/*
  Validate the pending changes in the e entry.
*/
static int
ipa_winsync_validate_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
    int *returncode, char *returntext, void *arg)
{
    char **attrsvals = NULL;
    int ii;
    Slapi_Attr *testattr = NULL;

    *returncode = LDAP_UNWILLING_TO_PERFORM; /* be pessimistic */

    /* get realm filter */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_REALM_FILTER_ATTR, &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_REALM_FILTER_ATTR);
        goto done2;
    }

    /* get realm attr */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_REALM_ATTR_ATTR, &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_REALM_ATTR_ATTR);
        goto done2;
    }

    /* get new_entry_filter */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_NEW_ENTRY_FILTER_ATTR,
                              &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_NEW_ENTRY_FILTER_ATTR);
        goto done2;
    }

    /* get new_user_oc_attr */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_NEW_USER_OC_ATTR,
                              &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_NEW_USER_OC_ATTR);
        goto done2;
    }

    /* get homedir_prefix_attr */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_HOMEDIR_PREFIX_ATTR,
                              &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_HOMEDIR_PREFIX_ATTR);
        goto done2;
    }

    /* get default_group_attr */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_DEFAULTGROUP_ATTR,
                              &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_DEFAULTGROUP_ATTR);
        goto done2;
    }

    /* get default_group_filter */
    if (slapi_entry_attr_find(e, IPA_WINSYNC_DEFAULTGROUP_FILTER_ATTR,
                              &testattr) ||
        (NULL == testattr)) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_DEFAULTGROUP_FILTER_ATTR);
        goto done2;
    }

    /* get the list of attributes & values */
    /* get new_user_oc_attr */
    if (!(attrsvals = slapi_entry_attr_get_charray(
              e, IPA_WINSYNC_NEW_USER_ATTRS_VALS))) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_WINSYNC_PLUGIN_NAME,
                        "Info: no default attributes and values given in [%s]\n",
                        IPA_WINSYNC_NEW_USER_ATTRS_VALS);
    }

    /* format of *attrsvals is "attrname value" */
    /* attrname <space> value */
    /* value may contain spaces - attrname is everything up to the first
       space - value is everything after the first space */
    for (ii = 0; attrsvals && attrsvals[ii]; ++ii) {
        Slapi_Attr *attr = NULL;
        char *oidp = NULL;
        char *val = strchr(attrsvals[ii], ' ');
        if (!val || !*(val+1)) { /* incorrect format or no value */
            PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                        "Error: no value or incorrect value given for [%s] "
                        "value [%s] index [%d] - correct format is attrname SPACE value",
                        IPA_WINSYNC_NEW_USER_ATTRS_VALS,
                        attrsvals[ii], ii);
            goto done2;
        }
        *val = '\0'; /* separate attr from val */
        /* check to make sure attribute is in the schema */
        attr = slapi_attr_new();
        slapi_attr_set_type(attr, attrsvals[ii]);
        slapi_attr_get_oid_copy(attr, &oidp);
        slapi_attr_free(&attr);
        if (oidp == NULL) { /* no such attribute */
            PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                        "Error: invalid attribute name [%s] given for [%s] "
                        "at index [%d] - attribute is not in server schema",
                        attrsvals[ii], IPA_WINSYNC_NEW_USER_ATTRS_VALS,
                        ii);
            goto done2;
        }

        /* attribute is valid - continue */
        slapi_ch_free_string(&oidp);
    }

    /* success */
    *returncode = LDAP_SUCCESS;

done2:
    slapi_ch_array_free(attrsvals);
    attrsvals = NULL;

    if (*returncode != LDAP_SUCCESS) {
        return SLAPI_DSE_CALLBACK_ERROR;
    } else {
        return SLAPI_DSE_CALLBACK_OK;
    }
}

static int
ipa_winsync_apply_config (Slapi_PBlock *pb, Slapi_Entry* entryBefore, Slapi_Entry* e, 
    int *returncode, char *returntext, void *arg)
{
    PRBool flatten = PR_TRUE;
    char *realm_filter = NULL;
    char *realm_attr = NULL;
    char *new_entry_filter = NULL;
    char *new_user_oc_attr = NULL; /* don't care about groups for now */
    char *homedir_prefix_attr = NULL;
    char *default_group_attr = NULL;
    char *default_group_filter = NULL;
    char **attrsvals = NULL;
    int ii;
    Slapi_Attr *testattr = NULL;

    *returncode = LDAP_UNWILLING_TO_PERFORM; /* be pessimistic */

    /* get flatten value */
    if (!slapi_entry_attr_find(e, IPA_WINSYNC_USER_FLATTEN, &testattr) &&
        (NULL != testattr)) {
        flatten = slapi_entry_attr_get_bool(e, IPA_WINSYNC_USER_FLATTEN);
    }

    /* get realm filter */
    if (!(realm_filter = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_REALM_FILTER_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_REALM_FILTER_ATTR);
        goto done3;
    }

    /* get realm attr */
    if (!(realm_attr = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_REALM_ATTR_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_REALM_ATTR_ATTR);
        goto done3;
    }

    /* get new_entry_filter */
    if (!(new_entry_filter = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_NEW_ENTRY_FILTER_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_NEW_ENTRY_FILTER_ATTR);
        goto done3;
    }

    /* get new_user_oc_attr */
    if (!(new_user_oc_attr = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_NEW_USER_OC_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_NEW_USER_OC_ATTR);
        goto done3;
    }

    /* get homedir_prefix_attr */
    if (!(homedir_prefix_attr = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_HOMEDIR_PREFIX_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_HOMEDIR_PREFIX_ATTR);
        goto done3;
    }

    /* get default_group_attr */
    if (!(default_group_attr = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_DEFAULTGROUP_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_DEFAULTGROUP_ATTR);
        goto done3;
    }

    /* get default_group_filter */
    if (!(default_group_filter = slapi_entry_attr_get_charptr(
              e, IPA_WINSYNC_DEFAULTGROUP_FILTER_ATTR))) {
        PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                    "Error: no value given for %s",
                    IPA_WINSYNC_DEFAULTGROUP_FILTER_ATTR);
        goto done3;
    }

    /* get the list of attributes & values */
    /* get new_user_oc_attr */
    if (!(attrsvals = slapi_entry_attr_get_charray(
              e, IPA_WINSYNC_NEW_USER_ATTRS_VALS))) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_WINSYNC_PLUGIN_NAME,
                        "Info: no default attributes and values given in [%s]\n",
                        IPA_WINSYNC_NEW_USER_ATTRS_VALS);
    }

    /* if we got here, we have valid values for everything
       set the config entry */
    slapi_lock_mutex(theConfig.lock);
    slapi_entry_free(theConfig.config_e);
    theConfig.config_e = slapi_entry_alloc();
    slapi_entry_init(theConfig.config_e, slapi_ch_strdup(""), NULL);

    /* format of *attrsvals is "attrname value" */
    /* attrname <space> value */
    /* value may contain spaces - attrname is everything up to the first
       space - value is everything after the first space */
    for (ii = 0; attrsvals && attrsvals[ii]; ++ii) {
        int rc;
        Slapi_Value *sva[2];
        Slapi_Value *sv = NULL;
        char *val = strchr(attrsvals[ii], ' ');
        if (!val || !*(val+1)) { /* incorrect format or no value */
            PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                        "Error: no value or incorrect value given for [%s] "
                        "value [%s] index [%d] - correct format is attrname SPACE value",
                        IPA_WINSYNC_NEW_USER_ATTRS_VALS,
                        attrsvals[ii], ii);
            goto done3;
        }
        *val++ = '\0'; /* separate attr from val */
        sv = slapi_value_new_string(val);
        sva[0] = sv;
        sva[1] = NULL;
        if ((rc = slapi_entry_add_values_sv(theConfig.config_e,
                                            attrsvals[ii], sva)) &&
            (rc != LDAP_SUCCESS)) {
            PR_snprintf(returntext, SLAPI_DSE_RETURNTEXT_SIZE,
                        "Error: could not add value [%s] for attribute name "
                        "[%s] - ldap error [%d: %s]", val, attrsvals[ii],
                        attrsvals[ii], IPA_WINSYNC_NEW_USER_ATTRS_VALS,
                        rc, ldap_err2string(rc));
            slapi_entry_free(theConfig.config_e);
            theConfig.config_e = NULL;
            slapi_value_free(&sv);
            goto done3;
        }
        slapi_value_free(&sv);
    }

    /* all of the attrs and vals have been set - set the other values */
    slapi_ch_free_string(&theConfig.realm_filter);
    theConfig.realm_filter = realm_filter;
    realm_filter = NULL;
    slapi_ch_free_string(&theConfig.realm_attr);
    theConfig.realm_attr = realm_attr;
    realm_attr = NULL;
    slapi_ch_free_string(&theConfig.new_entry_filter);
    theConfig.new_entry_filter = new_entry_filter;
    new_entry_filter = NULL;
    slapi_ch_free_string(&theConfig.new_user_oc_attr);
    theConfig.new_user_oc_attr = new_user_oc_attr;
    new_user_oc_attr = NULL;
    slapi_ch_free_string(&theConfig.homedir_prefix_attr);
    theConfig.homedir_prefix_attr = homedir_prefix_attr;
    homedir_prefix_attr = NULL;
    slapi_ch_free_string(&theConfig.default_group_attr);
    theConfig.default_group_attr = default_group_attr;
    default_group_attr = NULL;
    slapi_ch_free_string(&theConfig.default_group_filter);
    theConfig.default_group_filter = default_group_filter;
    default_group_filter = NULL;
    theConfig.flatten = flatten;

    /* success */
    *returncode = LDAP_SUCCESS;

done3:
    slapi_unlock_mutex(theConfig.lock);

    slapi_ch_free_string(&realm_filter);
    slapi_ch_free_string(&realm_attr);
    slapi_ch_free_string(&new_entry_filter);
    slapi_ch_free_string(&new_user_oc_attr);
    slapi_ch_free_string(&homedir_prefix_attr);
    slapi_ch_free_string(&default_group_attr);
    slapi_ch_free_string(&default_group_filter);
    slapi_ch_array_free(attrsvals);
    attrsvals = NULL;

    if (*returncode != LDAP_SUCCESS) {
        return SLAPI_DSE_CALLBACK_ERROR;
    } else {
        return SLAPI_DSE_CALLBACK_OK;
    }
}

/* create per-domain config object */
void *
ipa_winsync_config_new_domain(
    const Slapi_DN *ds_subtree,
    const Slapi_DN *ad_subtree
)
{
    IPA_WinSync_Domain_Config *iwdc =
        (IPA_WinSync_Domain_Config *)
        slapi_ch_calloc(1, sizeof(IPA_WinSync_Domain_Config));

    return (void *)iwdc;
}

/* destroy per-domain config object */
void
ipa_winsync_config_destroy_domain(
    void *cbdata, const Slapi_DN *ds_subtree,
    const Slapi_DN *ad_subtree
)
{
    IPA_WinSync_Domain_Config *iwdc =
        (IPA_WinSync_Domain_Config *)cbdata;
    slapi_entry_free(iwdc->domain_e);
    iwdc->domain_e = NULL;
    slapi_ch_free_string(&iwdc->realm_name);
    slapi_ch_free_string(&iwdc->homedir_prefix);
    slapi_ch_free((void **)&iwdc);

    return;
}

/*
  return the value(s) of the given attribute in the entry that
  matches the given criteria.  The criteria must match one
  and only one entry.
  Returns:
  -1 - problem doing internal search
  LDAP_UNWILLING_TO_PERFORM - more than one matching entry
  LDAP_NO_SUCH_OBJECT - no entry found that matched
  0 and attrval == NULL - entry found but no attribute
  other ldap error - error doing search for given basedn
*/
static int
internal_find_entry_get_attr_val(const Slapi_DN *basedn, int scope,
                                 const char *filter, const char *attrname,
                                 Slapi_ValueSet **svs, char **attrval)
{
    Slapi_Entry **entries = NULL;
    Slapi_PBlock *pb = NULL;
    const char *search_basedn = slapi_sdn_get_dn(basedn);
    int search_scope = scope;
    int ret = LDAP_SUCCESS;
    const char *attrs[2] = {attrname, NULL};

    if (svs) {
        *svs = NULL;
    }
    if (attrval) {
        *attrval = NULL;
    }
    pb = slapi_pblock_new();
    slapi_search_internal_set_pb(pb, search_basedn, search_scope, filter,
                                 (char **)attrs, 0, NULL, NULL,
                                 ipa_winsync_get_plugin_identity(), 0);
    slapi_search_internal_pb(pb);

    /* This search may return no entries, but should never
       return an error
    */
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
    if (ret != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error [%d:%s] searching for base [%s] filter [%s]"
                        " attr [%s]\n", ret, ldap_err2string(ret),
                        search_basedn, filter, attrs[0]);
        goto out1;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &entries);
    if (entries && entries[0] && entries[1]) {
        /* error - should never be more than one matching entry */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error: more than one entry matches search for "
                        "base [%s] filter [%s] attr [%s]\n",
                        search_basedn, filter, attrs[0]);
        ret = LDAP_UNWILLING_TO_PERFORM;
        goto out1;
    }

    if (entries && entries[0]) { /* found one */
        if (svs) {
            Slapi_Attr *attr = NULL;
            slapi_entry_attr_find(entries[0], attrname, &attr);
            if (attr) {
                /* slapi_attr_get_valueset allocates svs - must be freed later */
                slapi_attr_get_valueset(attr, svs);
            }
        }
        if (attrval) {
            *attrval = slapi_entry_attr_get_charptr(entries[0], attrname);
        }
    } else {
        ret = LDAP_NO_SUCH_OBJECT;
        slapi_log_error(SLAPI_LOG_PLUGIN, IPA_WINSYNC_PLUGIN_NAME,
                        "Did not find an entry for search "
                        "base [%s] filter [%s] attr [%s]\n",
                        search_basedn, filter, attrs[0]);
    }

out1:
    if (pb) {
        slapi_free_search_results_internal(pb);
        slapi_pblock_destroy(pb);
        pb = NULL;
    }

    return ret;
}

/*
 * Perform the agreement/domain specific configuration.
 * IPA stores its configuration in the tree.  We use the
 * ds_subtree to search for the domain/realm specific
 * configuration entries.
 */
void
ipa_winsync_config_refresh_domain(
    void *cbdata, const Slapi_DN *ds_subtree,
    const Slapi_DN *ad_subtree
)
{
    IPA_WinSync_Domain_Config *iwdc =
        (IPA_WinSync_Domain_Config *)cbdata;
    Slapi_DN *config_dn = slapi_sdn_dup(ds_subtree);
    char *realm_filter = NULL;
    char *realm_attr = NULL;
    char *new_entry_filter = NULL;
    char *new_user_oc_attr = NULL; /* don't care about groups for now */
    char *homedir_prefix_attr = NULL;
    char *default_group_attr = NULL;
    char *default_group_filter = NULL;
    char *default_group_name = NULL;
    char *real_group_filter = NULL;
    char *default_gid = NULL;
    Slapi_ValueSet *new_user_objclasses = NULL; /* don't care about groups for now */
    int loopdone = 0;
    int search_scope = LDAP_SCOPE_SUBTREE;
    int ret = LDAP_SUCCESS;
    Slapi_Value *sv = NULL;

    slapi_lock_mutex(theConfig.lock);
    realm_filter = slapi_ch_strdup(theConfig.realm_filter);
    realm_attr = slapi_ch_strdup(theConfig.realm_attr);
    new_entry_filter = slapi_ch_strdup(theConfig.new_entry_filter);
    new_user_oc_attr = slapi_ch_strdup(theConfig.new_user_oc_attr);
    homedir_prefix_attr = slapi_ch_strdup(theConfig.homedir_prefix_attr);
    default_group_attr = slapi_ch_strdup(theConfig.default_group_attr);
    default_group_filter = slapi_ch_strdup(theConfig.default_group_filter);
    slapi_unlock_mutex(theConfig.lock);

    /* starting at ds_subtree, search for the entry
       containing the Kerberos realm to use */
    slapi_ch_free_string(&iwdc->realm_name);
    while(!loopdone && !slapi_sdn_isempty(config_dn)) {
        ret = internal_find_entry_get_attr_val(config_dn, search_scope,
                                               realm_filter, realm_attr,
                                               NULL, &iwdc->realm_name);

        if ((0 == ret) && iwdc->realm_name) {
            loopdone = 1;
        } else if ((LDAP_NO_SUCH_OBJECT == ret) && !iwdc->realm_name) {
            /* try again */
            Slapi_DN *parent_dn = slapi_sdn_new();
            slapi_sdn_get_parent(config_dn, parent_dn);
            slapi_sdn_free(&config_dn);
            config_dn = parent_dn;
        } else { /* error */
            goto out;
        }
    }

    if (!iwdc->realm_name) {
        /* error - could not find the IPA config entry with the realm name */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error: could not find the entry containing the realm name for "
                        "ds subtree [%s] filter [%s] attr [%s]\n",
                        slapi_sdn_get_dn(ds_subtree), realm_filter, realm_attr);
        goto out;
    }

    /* look for the entry containing the default objectclasses
       to add to new entries */
    ret = internal_find_entry_get_attr_val(config_dn, search_scope,
                                           new_entry_filter, new_user_oc_attr,
                                           &new_user_objclasses, NULL);
    if (!new_user_objclasses) {
        /* error - could not find the entry containing list of objectclasses */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error: could not find the entry containing the new user objectclass list for "
                        "ds subtree [%s] filter [%s] attr [%s]\n",
                        slapi_sdn_get_dn(ds_subtree), new_entry_filter, new_user_oc_attr);
        goto out;
    }

    /* get the home directory prefix value */
    /* note - this is in the same entry as the new entry template, so
       use the same filter */
    slapi_ch_free_string(&iwdc->homedir_prefix);
    ret = internal_find_entry_get_attr_val(config_dn, search_scope,
                                           new_entry_filter, homedir_prefix_attr,
                                           NULL, &iwdc->homedir_prefix);
    if (!iwdc->homedir_prefix) {
        /* error - could not find the home dir prefix */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error: could not find the entry containing the home directory prefix for "
                        "ds subtree [%s] filter [%s] attr [%s]\n",
                        slapi_sdn_get_dn(ds_subtree), new_entry_filter, homedir_prefix_attr);
        goto out;
    }

    /* find the default group - the entry above contains the group name, but
       we need the gidNumber for posixAccount - so first find the entry
       and attr value which has the group name, then lookup the group
       number from the group name */
    ret = internal_find_entry_get_attr_val(config_dn, search_scope,
                                           new_entry_filter, default_group_attr,
                                           NULL, &default_group_name);
    if (!default_group_name) {
        /* error - could not find the default group name */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error: could not find the entry containing the default group name for "
                        "ds subtree [%s] filter [%s] attr [%s]\n",
                        slapi_sdn_get_dn(ds_subtree), new_entry_filter, default_group_attr);
        goto out;
    }

    /* next, find the group whose name is default_group_name - construct the filter
       based on the filter attribute value - assumes the group name is stored
       in the cn attribute value, and the gidNumber in the gidNumber attribute value */
    real_group_filter = slapi_ch_smprintf("(&(cn=%s)%s)", default_group_name,
                                          default_group_filter);
    ret = internal_find_entry_get_attr_val(config_dn, search_scope,
                                           real_group_filter, "gidNumber",
                                           NULL, &default_gid);
    if (!default_gid) {
        /* error - could not find the default gidNumber */
        slapi_log_error(SLAPI_LOG_FATAL, IPA_WINSYNC_PLUGIN_NAME,
                        "Error: could not find the entry containing the default gidNumber "
                        "ds subtree [%s] filter [%s] attr [%s]\n",
                        slapi_sdn_get_dn(ds_subtree), new_entry_filter, "gidNumber");
        goto out;
    }

    /* ok, we have our values */
    /* first, clear out the old domain config */
    slapi_entry_free(iwdc->domain_e);
    iwdc->domain_e = NULL;

    /* next, copy the global attr config */
    slapi_lock_mutex(theConfig.lock);
    iwdc->domain_e = slapi_entry_dup(theConfig.config_e);
    slapi_unlock_mutex(theConfig.lock);

    /* set the objectclasses in the domain_e */
    slapi_entry_attr_delete(iwdc->domain_e, "objectclass");
    /* this copies new_user_objclasses */
    slapi_entry_add_valueset(iwdc->domain_e, "objectclass", new_user_objclasses);

    /* set the default gid number */
    sv = slapi_value_new_string_passin(default_gid);
    default_gid = NULL; /* passin owns the memory */
    if (!slapi_entry_attr_has_syntax_value(iwdc->domain_e, "gidNumber", sv)) {
        slapi_entry_add_value(iwdc->domain_e,  "gidNumber", sv);
    }
    slapi_value_free(&sv);
    
out:
    slapi_valueset_free(new_user_objclasses);
    slapi_sdn_free(&config_dn);
    slapi_ch_free_string(&realm_filter);
    slapi_ch_free_string(&realm_attr);
    slapi_ch_free_string(&new_entry_filter);
    slapi_ch_free_string(&new_user_oc_attr);
    slapi_ch_free_string(&homedir_prefix_attr);
    slapi_ch_free_string(&default_group_attr);
    slapi_ch_free_string(&default_group_filter);
    slapi_ch_free_string(&default_group_name);
    slapi_ch_free_string(&real_group_filter);
    slapi_ch_free_string(&default_gid);

    if (LDAP_SUCCESS != ret) {
        slapi_ch_free_string(&iwdc->realm_name);
        slapi_ch_free_string(&iwdc->homedir_prefix);
        slapi_entry_free(iwdc->domain_e);
        iwdc->domain_e = NULL;
    }

    return;
}
