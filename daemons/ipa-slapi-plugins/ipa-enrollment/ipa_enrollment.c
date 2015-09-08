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
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

/*
 * Enroll a host into the IPA domain.
 *
 */

#include <stdio.h>
#include <string.h>
#include <dirsrv/slapi-plugin.h>
#include <krb5.h>

#include "util.h"

#define IPA_PLUGIN_NAME "ipa-enrollment"

/* OID of the extended operation handled by this plug-in */
#define JOIN_OID    "2.16.840.1.113730.3.8.10.3"

Slapi_PluginDesc pdesc = {
    IPA_PLUGIN_NAME,
    "IPA Project",
    "IPA/2.0",
    "IPA Enrollment Extended Operation plugin"
};

static char *ipaenrollment_oid_list[] = {
        JOIN_OID,
        NULL
};

static char *ipaenrollment_name_list[] = {
        "Enrollment Extended Operation",
        NULL
};

static void *ipaenrollment_plugin_id;

static char *realm;
static const char *ipa_realm_dn;

static int
ipaenrollement_secure(Slapi_PBlock *pb, char **errMesg)
{
    int ssf;
    int rc = LDAP_SUCCESS;

    LOG_TRACE("=> ipaenrollment_secure\n");

    /* Allow enrollment on all connections with a Security Strength
     * Factor (SSF) higher than 1 */
    if (slapi_pblock_get(pb, SLAPI_OPERATION_SSF, &ssf) != 0) {
        LOG_TRACE("Could not get SSF from connection\n");
        *errMesg = "Operation requires a secure connection.\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (NULL == realm) {
        *errMesg = "Kerberos realm is not set.\n";
        LOG_FATAL("%s", *errMesg);
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (ssf <= 1) {
        *errMesg = "Operation requires a secure connection.\n";
        rc = LDAP_CONFIDENTIALITY_REQUIRED;
        goto done;
    }

done:
    LOG_TRACE("<= ipaenrollment_secure\n");
    return rc;

}

/* The extop call passes in the FQDN of the host to enroll.
 * We take that and set the krbPrincipalName and add the appropriate
 * objectclasses, then return krbPrincipalName. The caller should take
 * this and pass it to ipa-getkeytab to generate the keytab.
 *
 * The password for the entry is removed by ipa-getkeytab.
 */
static int
ipa_join(Slapi_PBlock *pb)
{
    char *bindDN = NULL;
    char *errMesg = NULL;
    struct berval *extop_value = NULL;
    Slapi_PBlock *pbte = NULL;
    Slapi_PBlock *pbtm = NULL;
    Slapi_Entry *targetEntry=NULL;
    Slapi_DN *sdn;
    Slapi_Backend *be;
    Slapi_Entry **es = NULL;
    int rc=0, ret=0, res, i;
    int is_root=0;
    char *krbLastPwdChange = NULL;
    char *fqdn = NULL;
    Slapi_Mods *smods;
    char *attrlist[] = {"fqdn", "krbPrincipalKey", "krbLastPwdChange", "krbPrincipalName", NULL };
    char * filter;

    int scope = LDAP_SCOPE_SUBTREE;
    char *principal = NULL;
    char *princ_canonical = NULL;
    struct berval retbval;

    if (NULL == realm) {
        errMesg = "Kerberos realm is not set.\n";
        LOG_FATAL("%s", errMesg);
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

    /* Get Bind DN */
    slapi_pblock_get(pb, SLAPI_CONN_DN, &bindDN);

     /* If the connection is bound anonymously we must refuse to process
      * this operation.
      */
    if (bindDN == NULL || *bindDN == '\0') {
        /* Refuse the operation because they're bound anonymously */
        errMesg = "Anonymous Binds are not allowed.\n";
        rc = LDAP_INSUFFICIENT_ACCESS;
        goto free_and_return;
    }

    /* Get the ber value of the extended operation */
    slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &extop_value);

    /* We are passed in the FQDN of the host to enroll. Do an internal
     * search and pull that entry.
     */
    filter = slapi_ch_smprintf("(fqdn=%s)", extop_value->bv_val);
    pbte = slapi_pblock_new();
    slapi_search_internal_set_pb(pbte,
            ipa_realm_dn, scope, filter, attrlist, 0,
            NULL, /* Controls */
            NULL, /* UniqueID */
            ipaenrollment_plugin_id,
            0); /* Flags */

    /* do search the tree */
    ret = slapi_search_internal_pb(pbte);
    slapi_pblock_get(pbte, SLAPI_PLUGIN_INTOP_RESULT, &res);
    if (ret == -1 || res != LDAP_SUCCESS) {
        LOG_TRACE("Search for host failed, err (%d)\n", res?res:ret);
        errMesg = "Host not found (search failed).\n";
        rc = LDAP_NO_SUCH_OBJECT;
        goto free_and_return;
    }

    /* get entries */
    slapi_pblock_get(pbte, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
    if (!es) {
        LOG_TRACE("No entries ?!");
        errMesg = "Host not found (no result returned).\n";
        rc = LDAP_NO_SUCH_OBJECT;
        goto free_and_return;
    }

    /* count entries */
    for (i = 0; es[i]; i++) /* count */ ;

    /* if there is none or more than one, freak out */
    if (i != 1) {
        LOG_TRACE("Too many entries, or entry no found (%d)", i);
        if (i == 0)
            errMesg = "Host not found.\n";
        else
            errMesg = "Host not found (too many entries).\n";
        rc = LDAP_NO_SUCH_OBJECT;
        goto free_and_return;
    }
    targetEntry = es[0];

    /* Is this host already enrolled? */
    krbLastPwdChange = slapi_entry_attr_get_charptr(targetEntry, "krbLastPwdChange");
    if (NULL != krbLastPwdChange) {
        LOG_TRACE("Host already enrolled");
        errMesg = "Host already enrolled.\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

    /* First thing to do is to ask access control if the bound identity has
     * rights to modify the userpassword attribute on this entry. If not,
     * then we fail immediately with insufficient access. This means that
     * we don't leak any useful information to the client such as current
     * password wrong, etc.
     */

    is_root = slapi_dn_isroot(bindDN);
    if (slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, &is_root)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

    /* In order to perform the access control check,
     * we need to select a backend (even though
     * we don't actually need it otherwise).
     */
    sdn = slapi_sdn_new_dn_byval(bindDN);
    be = slapi_be_select(sdn);
    if (slapi_pblock_set(pb, SLAPI_BACKEND, be)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

    /* Access Strategy:
     * If the user has WRITE-ONLY access, a new keytab is set on the entry.
     */

    ret = slapi_access_allowed(pb, targetEntry, "krbPrincipalKey", NULL, SLAPI_ACL_WRITE);
    if (ret != LDAP_SUCCESS) {
        errMesg = "Insufficient access rights\n";
        rc = LDAP_INSUFFICIENT_ACCESS;
        goto free_and_return;
    }

    /* If a principal is already set return the name */
    principal = slapi_entry_attr_get_charptr(targetEntry, "krbPrincipalName");
    if (NULL != principal)
        goto done;

    /* Add the elements needed for enrollment */
    smods = slapi_mods_new();
    fqdn = slapi_entry_attr_get_charptr(targetEntry, "fqdn");
    principal = slapi_ch_smprintf("host/%s@%s", fqdn, realm);
    slapi_mods_add_string(smods, LDAP_MOD_ADD, "krbPrincipalName", principal);
    slapi_mods_add_string(smods, LDAP_MOD_ADD, "objectClass", "krbPrincipalAux");

    /* check for krbCanonicalName attribute. If not present, set it to same
     * value as krbPrincipalName*/
    princ_canonical = slapi_entry_attr_get_charptr(targetEntry,
                                                   "krbCanonicalName");

    if (NULL == princ_canonical) {
        slapi_mods_add_string(smods, LDAP_MOD_ADD, "krbCanonicalName",
                              principal);
    }

    pbtm = slapi_pblock_new();
    slapi_modify_internal_set_pb (pbtm, slapi_entry_get_dn_const(targetEntry),
        slapi_mods_get_ldapmods_byref(smods),
        NULL, /* Controls */
        NULL, /* UniqueID */
        ipaenrollment_plugin_id, /* PluginID */
        0); /* Flags */

    rc = slapi_modify_internal_pb (pbtm);
    if (rc) {
        LOG_TRACE("WARNING: modify error %d on entry '%s'\n",
                  rc, slapi_entry_get_dn_const(targetEntry));
    } else {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &rc);

        if (rc != LDAP_SUCCESS){
            LOG_TRACE("WARNING: modify error %d on entry '%s'\n",
                      rc, slapi_entry_get_dn_const(targetEntry));
        } else {
            LOG_TRACE("<= apply mods: Successful\n");
        }
    }

done:
    /* Return the krbprincipalname */
    retbval.bv_val = principal;
    retbval.bv_len = strlen(principal);

    ret = slapi_pblock_set(pb, SLAPI_EXT_OP_RET_OID, JOIN_OID);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_EXT_OP_RET_VALUE, &retbval);
    if (ret) {
        errMesg = "Could not set return values";
        LOG("%s\n", errMesg);
        rc = SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
    }

    /* Free anything that we allocated above */
free_and_return:

    if (pbte) {
        slapi_free_search_results_internal(pbte);
        slapi_pblock_destroy(pbte);
    }
    if (pbtm) {
        slapi_pblock_destroy(pbtm);
    }

    if (krbLastPwdChange) slapi_ch_free_string(&krbLastPwdChange);

    LOG("%s", errMesg ? errMesg : "success\n");
    slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

    free(principal);

    if (princ_canonical) {
        free(princ_canonical);
    }

    return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

/* Extended operation plug-in */
static int
ipaenrollment_extop(Slapi_PBlock *pb)
{
    char *oid;
    char *errMesg = NULL;
    int rc, ret;

    LOG_TRACE("=> ipaenrollment_extop\n");

    rc = ipaenrollement_secure(pb, &errMesg);
    if (rc) {
        goto free_and_return;
    }

    /* Get the OID and the value included in the request */
    if (slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_OID, &oid ) != 0) {
        errMesg = "Could not get OID and value from request.\n";
        rc = LDAP_OPERATIONS_ERROR;
        LOG("%s", errMesg);
        goto free_and_return;
    }

    if (strcasecmp(oid, JOIN_OID) == 0) {
        ret = ipa_join(pb);
        return ret;
    }

    errMesg = "Request OID does not match supported OIDs.\n";
    rc = LDAP_OPERATIONS_ERROR;

free_and_return:
    LOG("%s", errMesg);
    slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

    return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

static int
ipaenrollment_start(Slapi_PBlock *pb)
{
    krb5_error_code krberr;
    krb5_context krbctx;
    char *config_dn = NULL;
    char *partition_dn = NULL;
    Slapi_Entry *config_entry = NULL;
    int ret = LDAP_SUCCESS;
    Slapi_DN *sdn;
    int rc = 0;

    krberr = krb5_init_context(&krbctx);
    if (krberr) {
        LOG_FATAL("krb5_init_context failed\n");
        /* Yes, we failed, but it is because /etc/krb5.conf doesn't exist
         * or is misconfigured. Start up in a degraded mode.
         */
        goto done;
    }

    krberr = krb5_get_default_realm(krbctx, &realm);
    if (krberr) {
        realm = NULL;
        LOG_FATAL("Failed to get default realm?!\n");
        goto done;
    }

    if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &config_dn) != 0) {
        LOG_FATAL("No config DN?\n");
        goto done;
    }
    sdn = slapi_sdn_new_dn_byref(config_dn);
    if ((rc = slapi_search_internal_get_entry(sdn, NULL, &config_entry,
                                ipaenrollment_plugin_id)) != LDAP_SUCCESS ){
        LOG_TRACE("ipaenrollment_start: No such entry-(%s), err (%d)\n",
                  config_dn, rc);
    }
    slapi_sdn_free(&sdn);

    partition_dn = slapi_entry_attr_get_charptr(config_entry, "nsslapd-realmtree");
    if (!partition_dn) {
        LOG_FATAL("Missing partition configuration entry (nsslapd-realmTree)!\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ipa_realm_dn = slapi_ch_smprintf("cn=computers,cn=accounts,%s", partition_dn);
    slapi_ch_free_string(&partition_dn);
    if (!ipa_realm_dn) {
        LOG_FATAL("Out of memory ?\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

done:
    if (krbctx) krb5_free_context(krbctx);
    if (config_entry) slapi_entry_free(config_entry);

    return ret;
}

int
ipaenrollment_init(Slapi_PBlock *pb)
{
    int ret;

    /* Get the arguments appended to the plugin extendedop directive
     * in the plugin entry.  The first argument
     * (after the standard arguments for the directive) should
     * contain the OID of the extended op.
    */

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ipaenrollment_plugin_id);
    if ((ret != 0) || (NULL == ipaenrollment_plugin_id)) {
        LOG("Could not get identity or identity was NULL\n");
        return -1;
    }

    LOG("Registering plug-in for extended op.\n");

    /* Register the plug-in function as an extended operation
       plug-in function. */
    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *)ipaenrollment_start);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&pdesc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, ipaenrollment_oid_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, ipaenrollment_name_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)ipaenrollment_extop);

    if (ret) {
        LOG("Failed to set plug-in version, function, and OID.\n");
        return -1;
    }

    return 0;
}
