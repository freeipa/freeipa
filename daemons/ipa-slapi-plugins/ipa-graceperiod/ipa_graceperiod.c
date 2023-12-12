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
 * Copyright (C) 2022-2023 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

/**
 * IPA Graceperiod plug-in
 *
 * Limit LDAP operations to password changes while in the grace period.
 *
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include "slapi-plugin.h"
#include "nspr.h"
#include <krb5.h>

#include "util.h"
#include "ipa_pwd.h"

#define IPAGRACEPERIOD_PLUGIN_NAME "ipa-graceperiod-plugin"
#define IPAGRACEPERIOD_PLUGIN_VERSION 0x00010000

#define IPA_PLUGIN_NAME IPAGRACEPERIOD_PLUGIN_NAME

#define IPAGRACEPERIOD_FEATURE_DESC      "IPA Graceperiod"
#define IPAGRACEPERIOD_PLUGIN_DESC       "IPA Graceperiod plugin"
#define IPAGRACEPERIOD_PREOP_DESC        "IPA Graceperiod preop plugin"

static Slapi_PluginDesc pdesc = {
    IPAGRACEPERIOD_FEATURE_DESC,
    "Red Hat, Inc.",
    "1.0",
    IPAGRACEPERIOD_PLUGIN_DESC
};

struct ipa_context {
    bool disable_last_success;
    bool disable_lockout;
};

static void *_PluginID = NULL;

static int g_plugin_started = 0;

#if 0
static struct ipa_context *global_ipactx = NULL;
#endif

static char *ipa_global_policy = NULL;

int ipagraceperiod_getpolicy(Slapi_Entry *target_entry, Slapi_Entry **policy_entry,
                         Slapi_ValueSet** values, char **actual_type_name,
                         const char **policy_dn, int *attr_free_flags,
                         char **errstr);
int ipagraceperiod_version(void);

static void *getPluginID(void);
static void setPluginID(void *pluginID);

#define GENERALIZED_TIME_LENGTH 15

/**
 *
 * management functions
 *
 */
int ipagraceperiod_init(Slapi_PBlock * pb);

static int ipagraceperiod_start(Slapi_PBlock * pb);
static int ipagraceperiod_close(Slapi_PBlock * pb);
static int ipagraceperiod_preop_init(Slapi_PBlock * pb);
static int ipagraceperiod_get_global_config(void);

/**
 *
 * the ops (where the real work is done)
 *
 */
static int ipagraceperiod_preop(Slapi_PBlock *pb);

/**
 *
 * Get the plug-in version
 *
 */
int ipagraceperiod_version(void)
{
    return IPAGRACEPERIOD_PLUGIN_VERSION;
}

/**
 * Plugin identity mgmt
 */
static void setPluginID(void *pluginID)
{
    _PluginID = pluginID;
}

static void *getPluginID(void)
{
    return _PluginID;
}


static int
ipagraceperiod_get_global_config(void)
{
    char *dn = NULL;
    char *basedn = NULL;
    char *realm = NULL;
    Slapi_DN *sdn;
    Slapi_Entry *config_entry = NULL;
    krb5_context krbctx = NULL;
    krb5_error_code krberr;
    int ret;

    /* Get cn=config so we can get the default naming context */
    sdn = slapi_sdn_new_dn_byref("cn=config");

    ret = slapi_search_internal_get_entry(sdn, NULL, &config_entry,
              getPluginID());

    slapi_sdn_free(&sdn);

    if (ret) {
        goto done;
    }

    basedn = slapi_entry_attr_get_charptr(config_entry,
        "nsslapd-defaultnamingcontext");

    slapi_entry_free(config_entry);
    config_entry = NULL;

    if (!basedn) {
        goto done;
    }

    krberr = krb5_init_context(&krbctx);
    if (krberr) {
        LOG_FATAL("krb5_init_context failed (%d)\n", krberr);
        /* Yes, we failed, but it is because /etc/krb5.conf doesn't exist
         * or is misconfigured. Start up in a degraded mode.
         */
    } else {
        krberr = krb5_get_default_realm(krbctx, &realm);
        if (krberr) {
            LOG_FATAL("Failed to get default realm (%d)\n", krberr);
        } else {
            ipa_global_policy =
                slapi_ch_smprintf("cn=global_policy,cn=%s,cn=kerberos,%s",
                                  realm, basedn);
            if (!ipa_global_policy) {
                LOG_OOM();
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }
        }
    }

    ret = 0;

done:
    if (config_entry)
        slapi_entry_free(config_entry);
    free(realm);
    krb5_free_context(krbctx);
    free(dn);
    free(basedn);
    return ret;
}

int ipagraceperiod_getpolicy(Slapi_Entry *target_entry, Slapi_Entry **policy_entry,
                         Slapi_ValueSet** values, char **actual_type_name,
                         const char **policy_dn, int *attr_free_flags,
                         char **errstr)
{
    int ldrc = 0;
    int type_name_disposition = 0;
    Slapi_DN *pdn = NULL;

    /* Only continue if there is a password policy */
    ldrc = slapi_vattr_values_get(target_entry, "krbPwdPolicyReference",
                                values,
                                &type_name_disposition, actual_type_name,
                                SLAPI_VIRTUALATTRS_REQUEST_POINTERS,
                                attr_free_flags);
    if (ldrc == 0) {
        Slapi_Value *sv = NULL;

        if (values != NULL) {
            slapi_valueset_first_value(*values, &sv);
            *policy_dn = slapi_value_get_string(sv);
        }
    } else {
        *policy_dn = ipa_global_policy;
    }

    if (*policy_dn == NULL) {
        LOG_TRACE("No kerberos password policy\n");
        return LDAP_SUCCESS;
    } else {
        pdn = slapi_sdn_new_dn_byref(*policy_dn);
        ldrc = slapi_search_internal_get_entry(pdn, NULL, policy_entry,
                getPluginID());
        slapi_sdn_free(&pdn);
        if (ldrc != LDAP_SUCCESS) {
            LOG_FATAL("Failed to retrieve entry \"%s\": %d\n", *policy_dn, ldrc);
            *errstr = "Failed to retrieve account policy.";
            return LDAP_OPERATIONS_ERROR;
        }
    }

    return LDAP_SUCCESS;
}

int
ipagraceperiod_init(Slapi_PBlock *pb)
{
    int status = EOK;
    char *plugin_identity = NULL;

    LOG_TRACE("--in-->\n");

    slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &plugin_identity);
    PR_ASSERT(plugin_identity);
    setPluginID(plugin_identity);

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                         (void *) ipagraceperiod_start) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                         (void *) ipagraceperiod_close) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_register_plugin("preoperation",
                              1,
                              "ipagraceperiod_init",
                              ipagraceperiod_preop_init,
                              IPAGRACEPERIOD_PREOP_DESC,
                              NULL,
                              plugin_identity
        )
        ) {
        LOG_FATAL("failed to register plugin\n");
        status = EFAIL;
    }

    LOG_TRACE("<--out--\n");
    return status;
}

static int
ipagraceperiod_preop_init(Slapi_PBlock *pb)
{
    int status = EOK;

    if (slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                         SLAPI_PLUGIN_VERSION_01) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                         (void *) &pdesc) != 0 ||
        slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
                         (void *) ipagraceperiod_preop) != 0) {
        status = EFAIL;
    }

    return status;
}

static int
ipagraceperiod_start(Slapi_PBlock * pb)
{
    LOG_TRACE("--in-->\n");

    /* Check if we're already started */
    if (g_plugin_started) {
        goto done;
    }

    g_plugin_started = 1;

    ipagraceperiod_get_global_config();

    LOG("ready for service\n");

done:
    LOG_TRACE("<--out--\n");
    return EOK;
}

static int
ipagraceperiod_close(Slapi_PBlock * pb)
{
    LOG_TRACE( "--in-->\n");

    slapi_ch_free_string(&ipa_global_policy);

    LOG_TRACE("<--out--\n");

    return EOK;
}

/*
 * In the pre-op stage the bind hasn't occurred yet. It is here that
 * we do the lockout enforcement.
 */
static int ipagraceperiod_preop(Slapi_PBlock *pb)
{
    char *dn = NULL;
    const char *policy_dn = NULL;
    Slapi_Entry *target_entry = NULL;
    Slapi_Entry *policy_entry = NULL;
    Slapi_Value *objectclass = NULL;
    Slapi_DN *sdn = NULL;
    char *errstr = NULL;
    int ldrc = 0;
    int rc = 0;
    int ret = LDAP_SUCCESS;
    char *actual_type_name = NULL;
    int attr_free_flags = 0;
    Slapi_ValueSet *values = NULL;
    long grace_limit = 0;
    int grace_user_time;
    char *tmpstr = NULL;
    time_t pwd_expiration;
    int pwresponse_requested = 0;
    Slapi_PBlock *pbtm = NULL;
    Slapi_Mods *smods = NULL;

    LOG_TRACE("--in-->\n");

    /* Just bail if we aren't ready to service requests yet. */
    if (!g_plugin_started) {
        goto done;
    }

    if (slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn) != 0) {
        LOG_FATAL("Error retrieving target DN\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* Client is anonymously bound */
    if (dn == NULL) {
        LOG_TRACE("anonymous bind\n");
        goto done;
    }

    /* Get the entry */
    sdn = slapi_sdn_new_dn_byref(dn);
    if (sdn == NULL) {
        LOG_OOM();
        errstr = "Out of memory.\n";
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ldrc = slapi_search_internal_get_entry(sdn, NULL, &target_entry,
            getPluginID());

    if (ldrc != LDAP_SUCCESS) {
        LOG_TRACE("Failed to retrieve entry \"%s\": %d\n", dn, ldrc);
        goto done;
    }

    /* Only deal with users and sysaccount entries */
    objectclass = slapi_value_new_string("posixAccount");
    if ((slapi_entry_attr_has_syntax_value(target_entry, SLAPI_ATTR_OBJECTCLASS, objectclass)) != 1) {
        LOG_TRACE("Not a posix user\n");
        slapi_value_free(&objectclass);
        objectclass = slapi_value_new_string("simplesecurityobject");
        if ((slapi_entry_attr_has_syntax_value(target_entry, SLAPI_ATTR_OBJECTCLASS, objectclass)) != 1) {
            LOG_TRACE("Not a sysaccount user\n");
            slapi_value_free(&objectclass);
            goto done;
        }
    }
    slapi_value_free(&objectclass);

    tmpstr = slapi_entry_attr_get_charptr(target_entry, "krbPasswordExpiration");
    if (tmpstr == NULL) {
        /* No expiration means nothing to do */
        LOG_TRACE("No krbPasswordExpiration for %s, nothing to do\n", dn);
        goto done;
    }
    pwd_expiration = ipapwd_gentime_to_time_t(tmpstr);
    if (pwd_expiration > time(NULL)) {
        /* Not expired, nothing to see here */
        goto done;
    }

    ldrc = ipagraceperiod_getpolicy(target_entry, &policy_entry,
                                    &values, &actual_type_name,
                                    &policy_dn, &attr_free_flags,
                                    &errstr);
    if (ldrc != LDAP_SUCCESS || policy_dn == NULL) {
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PWPOLICY, &pwresponse_requested);

    /* This returns 0 if the attribute doesn't exist, so no grace but
     * report that logins are not allowed.
     */
    grace_limit = slapi_entry_attr_get_int(policy_entry, "passwordGraceLimit");

    /* -1 means disable grace limit */
    if (grace_limit == -1) {
        LOG_TRACE("grace limit disabled, skipping\n");
        goto done;
    } else if (grace_limit < -1) {
        LOG_FATAL("Invalid passwordGraceLimit value %ld\n", grace_limit);
        return LDAP_OPERATIONS_ERROR;
    }

    grace_user_time = slapi_entry_attr_get_int(target_entry, "passwordGraceUserTime");

    if ((grace_limit > 0) && (grace_user_time < grace_limit)) {
        char graceUserTime[16] = {0};

        grace_user_time++;
        sprintf(graceUserTime, "%d", grace_user_time);
        smods = slapi_mods_new();
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "passwordGraceUserTime", graceUserTime);

        pbtm = slapi_pblock_new();
        slapi_modify_internal_set_pb(pbtm,
                                     slapi_entry_get_dn_const(target_entry),
                                     slapi_mods_get_ldapmods_byref(smods),
                                     NULL, NULL, getPluginID(), 0);

        slapi_modify_internal_pb(pbtm);
        slapi_pblock_get(pbtm, SLAPI_PLUGIN_INTOP_RESULT, &rc);

        if (rc != LDAP_SUCCESS) {
            LOG_TRACE("WARNING: modify error %d on entry '%s'\n",
                      rc, slapi_entry_get_dn_const(target_entry));
        }

        if (pwresponse_requested) {
            slapi_pwpolicy_make_response_control(pb, -1, grace_limit - grace_user_time , -1);
        }
    } else if (grace_user_time >= grace_limit) {
        LOG_PWDPOLICY("%s password is expired and out of grace limit\n", dn);
        errstr = "Password is expired.\n";
        ret = LDAP_INVALID_CREDENTIALS;

        if (pwresponse_requested) {
            slapi_pwpolicy_make_response_control(pb, -1, 0, LDAP_PWPOLICY_PWDEXPIRED);
        }
        goto done;
    }
    slapi_add_pwd_control(pb, LDAP_CONTROL_PWEXPIRED, 0);

done:
    slapi_pblock_destroy(pbtm);
    slapi_mods_free(&smods);
    slapi_entry_free(target_entry);
    slapi_entry_free(policy_entry);
    if (values != NULL) {
        slapi_vattr_values_free(&values, &actual_type_name, attr_free_flags);
    }
    if (sdn) slapi_sdn_free(&sdn);

    LOG("preop returning %d: %s\n", ret, errstr ? errstr : "success\n");

    if (ret) {
        slapi_send_ldap_result(pb, ret, NULL, errstr, 0, NULL);
    }

    LOG_TRACE("<--out--\n");

    return (ret == 0 ? EOK : EFAIL);
}
