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
 * Authors:
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "ipapwd.h"
#include "util.h"

/* Attribute defines */
#define IPA_OTP_USER_AUTH_TYPE "ipaUserAuthType"

/* Type of connection for this operation;*/
#define LDAP_EXTOP_PASSMOD_CONN_SECURE


/* Uncomment the following #undef FOR TESTING:
 * allows non-SSL connections to use the password change extended op */
/* #undef LDAP_EXTOP_PASSMOD_CONN_SECURE */

extern void *ipapwd_plugin_id;
extern const char *ipa_realm_dn;
extern const char *ipa_etc_config_dn;
extern const char *ipa_pwd_config_dn;

/* These are the default enc:salt types if nothing is defined in LDAP */
static const char *ipapwd_def_encsalts[] = {
    "aes256-cts:special",
    "aes128-cts:special",
    NULL
};

static struct ipapwd_krbcfg *ipapwd_getConfig(void)
{
    krb5_error_code krberr;
    struct ipapwd_krbcfg *config = NULL;
    krb5_keyblock *kmkey = NULL;
    Slapi_Entry *realm_entry = NULL;
    Slapi_Entry *config_entry = NULL;
    Slapi_Attr *a;
    Slapi_Value *v;
    BerElement *be = NULL;
    ber_tag_t tag, tvno;
    ber_int_t ttype;
    const struct berval *bval;
    struct berval *mkey = NULL;
    char **encsalts;
    char **tmparray;
    char *tmpstr;
    int i, ret;

    config = calloc(1, sizeof(struct ipapwd_krbcfg));
    if (!config) {
        LOG_OOM();
        goto free_and_error;
    }
    kmkey = calloc(1, sizeof(krb5_keyblock));
    if (!kmkey) {
        LOG_OOM();
        goto free_and_error;
    }
    config->kmkey = kmkey;

    krberr = krb5_init_context(&config->krbctx);
    if (krberr) {
        LOG_FATAL("krb5_init_context failed\n");
        goto free_and_error;
    }

    ret = krb5_get_default_realm(config->krbctx, &config->realm);
    if (ret) {
        LOG_FATAL("Failed to get default realm?!\n");
        goto free_and_error;
    }

    /* get the Realm Container entry */
    ret = ipapwd_getEntry(ipa_realm_dn, &realm_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        LOG_FATAL("No realm Entry?\n");
        goto free_and_error;
    }

    /*** get the Kerberos Master Key ***/

    ret = slapi_entry_attr_find(realm_entry, "krbMKey", &a);
    if (ret == -1) {
        LOG_FATAL("No master key??\n");
        goto free_and_error;
    }

    /* there should be only one value here */
    ret = slapi_attr_first_value(a, &v);
    if (ret == -1) {
        LOG_FATAL("No master key??\n");
        goto free_and_error;
    }

    bval = slapi_value_get_berval(v);
    if (!bval) {
        LOG_FATAL("Error retrieving master key berval\n");
        goto free_and_error;
    }

    be = ber_init(discard_const(bval));
    if (!be) {
        LOG_FATAL("ber_init() failed!\n");
        goto free_and_error;
    }

    tag = ber_scanf(be, "{i{iO}}", &tvno, &ttype, &mkey);
    if (tag == LBER_ERROR) {
        LOG_FATAL("Bad Master key encoding ?!\n");
        goto free_and_error;
    }

    config->mkvno = tvno;
    kmkey->magic = KV5M_KEYBLOCK;
    kmkey->enctype = ttype;
    kmkey->length = mkey->bv_len;
    kmkey->contents = malloc(mkey->bv_len);
    if (!kmkey->contents) {
        LOG_OOM();
        goto free_and_error;
    }
    memcpy(kmkey->contents, mkey->bv_val, mkey->bv_len);
    ber_bvfree(mkey);
    ber_free(be, 1);
    mkey = NULL;
    be = NULL;

    /*** get the Supported Enc/Salt types ***/

    encsalts = slapi_entry_attr_get_charray(realm_entry,
                                            "krbSupportedEncSaltTypes");
    if (encsalts) {
        for (i = 0; encsalts[i]; i++) /* count */ ;
        ret = parse_bval_key_salt_tuples(config->krbctx,
                                         (const char * const *)encsalts, i,
                                         &config->supp_encsalts,
                                         &config->num_supp_encsalts);
        slapi_ch_array_free(encsalts);
    } else {
        LOG("No configured salt types use defaults\n");
        for (i = 0; ipapwd_def_encsalts[i]; i++) /* count */ ;
        ret = parse_bval_key_salt_tuples(config->krbctx,
                                         ipapwd_def_encsalts, i,
                                         &config->supp_encsalts,
                                         &config->num_supp_encsalts);
    }
    if (ret) {
        LOG_FATAL("Can't get Supported EncSalt Types\n");
        goto free_and_error;
    }

    /*** get the Preferred Enc/Salt types ***/

    encsalts = slapi_entry_attr_get_charray(realm_entry,
                                            "krbDefaultEncSaltTypes");
    if (encsalts) {
        for (i = 0; encsalts[i]; i++) /* count */ ;
        ret = parse_bval_key_salt_tuples(config->krbctx,
                                         (const char * const *)encsalts, i,
                                         &config->pref_encsalts,
                                         &config->num_pref_encsalts);
        slapi_ch_array_free(encsalts);
    } else {
        LOG("No configured salt types use defaults\n");
        for (i = 0; ipapwd_def_encsalts[i]; i++) /* count */ ;
        ret = parse_bval_key_salt_tuples(config->krbctx,
                                         ipapwd_def_encsalts, i,
                                         &config->pref_encsalts,
                                         &config->num_pref_encsalts);
    }
    if (ret) {
        LOG_FATAL("Can't get Preferred EncSalt Types\n");
        goto free_and_error;
    }

    slapi_entry_free(realm_entry);

    /* get the Realm Container entry */
    ret = ipapwd_getEntry(ipa_pwd_config_dn, &config_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        LOG_FATAL("No config Entry? Impossible!\n");
        goto free_and_error;
    }
    config->passsync_mgrs =
            slapi_entry_attr_get_charray(config_entry, "passSyncManagersDNs");
    /* now add Directory Manager, it is always added by default */
    tmpstr = slapi_ch_strdup("cn=Directory Manager");
    slapi_ch_array_add(&config->passsync_mgrs, tmpstr);
    if (config->passsync_mgrs == NULL) {
        LOG_OOM();
        goto free_and_error;
    }
    for (i = 0; config->passsync_mgrs[i]; i++) /* count */ ;
    config->num_passsync_mgrs = i;

    slapi_entry_free(config_entry);

    /* get the ipa etc/ipaConfig entry */
    config->allow_nt_hash = false;
    if (ipapwd_fips_enabled()) {
        LOG("FIPS mode is enabled, NT hashes are not allowed.\n");
    } else {
        ret = ipapwd_getEntry(ipa_etc_config_dn, &config_entry, NULL);
        if (ret != LDAP_SUCCESS) {
            LOG_FATAL("No config Entry?\n");
            goto free_and_error;
        } else {
            tmparray = slapi_entry_attr_get_charray(config_entry,
                                                    "ipaConfigString");
            for (i = 0; tmparray && tmparray[i]; i++) {
                if (strcasecmp(tmparray[i], "AllowNThash") == 0) {
                    config->allow_nt_hash = true;
                    continue;
                }
            }
            if (tmparray) slapi_ch_array_free(tmparray);
        }

        slapi_entry_free(config_entry);
    }

    return config;

free_and_error:
    if (mkey) ber_bvfree(mkey);
    if (be) ber_free(be, 1);
    if (kmkey) {
        free(kmkey->contents);
        free(kmkey);
    }
    if (config) {
        if (config->krbctx) {
            if (config->realm)
                krb5_free_default_realm(config->krbctx, config->realm);
            krb5_free_context(config->krbctx);
        }
        free(config->pref_encsalts);
        free(config->supp_encsalts);
        slapi_ch_array_free(config->passsync_mgrs);
        free(config);
    }
    slapi_entry_free(config_entry);
    slapi_entry_free(realm_entry);
    return NULL;
}

/* Easier handling for virtual attributes. You must call pwd_values_free()
 * to free memory allocated here. It must be called before
 * slapi_free_search_results_internal(entries) or
 * slapi_pblock_destroy(pb)
 */
static int pwd_get_values(const Slapi_Entry *ent, const char *attrname,
			  Slapi_ValueSet** results, char** actual_type_name,
			  int *buffer_flags)
{
    int flags=0;
    int type_name_disposition = 0;
    int ret;

    ret = slapi_vattr_values_get((Slapi_Entry *)ent, (char *)attrname,
                                 results, &type_name_disposition,
                                 actual_type_name, flags, buffer_flags);

    return ret;
}

static void pwd_values_free(Slapi_ValueSet** results,
                            char** actual_type_name, int buffer_flags)
{
    slapi_vattr_values_free(results, actual_type_name, buffer_flags);
}

int ipapwd_getPolicy(const char *dn,
                     Slapi_Entry *target,
                     struct ipapwd_policy *policy)
{
    const char *krbPwdPolicyReference;
    char *pdn = NULL;
    Slapi_PBlock *pb = NULL;
    char *attrs[] = { "krbMaxPwdLife", "krbMinPwdLife",
                      "krbPwdMinDiffChars", "krbPwdMinLength",
                      "krbPwdHistoryLength", NULL};
    Slapi_Entry **es = NULL;
    Slapi_Entry *pe = NULL;
    int ret, res, scope, i;
    int buffer_flags=0;
    Slapi_ValueSet* results = NULL;
    char *actual_type_name = NULL;

    LOG_TRACE("Searching policy for [%s]\n", dn);

    pwd_get_values(target, "krbPwdPolicyReference",
                   &results, &actual_type_name, &buffer_flags);
    if (results) {
        Slapi_Value *sv;
        slapi_valueset_first_value(results, &sv);
        krbPwdPolicyReference = slapi_value_get_string(sv);
        pdn = slapi_ch_strdup(krbPwdPolicyReference);
    } else {
        /* Fallback to hardcoded value */
        pdn = slapi_ch_smprintf("cn=global_policy,%s", ipa_realm_dn);
    }
    if (pdn == NULL) {
        LOG_OOM();
        ret = -1;
        goto done;
    }
    LOG_TRACE("Using policy at [%s]\n", pdn);
    scope = LDAP_SCOPE_BASE;

    pb = slapi_pblock_new();
    slapi_search_internal_set_pb(pb,
                                 pdn, scope,
                                 "(objectClass=krbPwdPolicy)",
                                 attrs, 0,
                                 NULL, /* Controls */
                                 NULL, /* UniqueID */
                                 ipapwd_plugin_id,
                                 0); /* Flags */

    /* do search the tree */
    ret = slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
    if (ret == -1 || res != LDAP_SUCCESS) {
        LOG_FATAL("Couldn't find policy, err (%d)\n", res ? res : ret);
        ret = -1;
        goto done;
    }

    /* get entries */
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
    if (!es) {
        LOG_TRACE("No entries ?!");
        ret = -1;
        goto done;
    }

    /* count entries */
    for (i = 0; es[i]; i++) /* count */ ;

    /* if there is only one, return that */
    if (i == 1) {
        pe = es[0];
    } else {
        LOG_TRACE("Multiple entries from a base search ?!");
        ret = -1;
        goto done;
    }

    /* read data out of policy object */
    policy->min_pwd_life = slapi_entry_attr_get_int(pe, "krbMinPwdLife");

    policy->max_pwd_life = slapi_entry_attr_get_int(pe, "krbMaxPwdLife");

    policy->min_pwd_length = slapi_entry_attr_get_int(pe, "krbPwdMinLength");

    policy->history_length = slapi_entry_attr_get_int(pe,
                                                      "krbPwdHistoryLength");

    policy->min_complexity = slapi_entry_attr_get_int(pe,
                                                      "krbPwdMinDiffChars");

    ret = 0;

done:
    if (results) {
        pwd_values_free(&results, &actual_type_name, buffer_flags);
    }
    if (pb) {
        slapi_free_search_results_internal(pb);
        slapi_pblock_destroy(pb);
    }
    slapi_ch_free_string(&pdn);
    return ret;
}


/*==Common-public-functions=============================================*/

int ipapwd_entry_checks(Slapi_PBlock *pb, struct slapi_entry *e,
                        int *is_root, int *is_krb, int *is_smb, int *is_ipant,
                        char *attr, int acc)
{
    Slapi_Value *sval;
    int rc;

    /* Check ACIs */
    slapi_pblock_get(pb, SLAPI_REQUESTOR_ISROOT, is_root);

    if (!*is_root) {
        /* verify this user is allowed to write a user password */
        rc = slapi_access_allowed(pb, e, attr, NULL, acc);
        if (rc != LDAP_SUCCESS) {
            /* we have no business here, the operation will be denied anyway */
            rc = LDAP_SUCCESS;
            goto done;
        }
    }

    /* Check if this is a krbPrincial and therefore needs us to generate other
     * hashes */
    sval = slapi_value_new_string("krbPrincipalAux");
    if (!sval) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    *is_krb = slapi_entry_attr_has_syntax_value(e, SLAPI_ATTR_OBJECTCLASS, sval);
    slapi_value_free(&sval);

    sval = slapi_value_new_string("sambaSamAccount");
    if (!sval) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    *is_smb = slapi_entry_attr_has_syntax_value(e, SLAPI_ATTR_OBJECTCLASS, sval);
    slapi_value_free(&sval);

    sval = slapi_value_new_string("ipaNTUserAttrs");
    if (!sval) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    *is_ipant = slapi_entry_attr_has_syntax_value(e, SLAPI_ATTR_OBJECTCLASS,
                                                  sval);
    slapi_value_free(&sval);

    rc = LDAP_SUCCESS;

done:
    return rc;
}

int ipapwd_gen_checks(Slapi_PBlock *pb, char **errMesg,
                      struct ipapwd_krbcfg **config, int check_flags)
{
    int ret, ssf;
    int rc = LDAP_SUCCESS;
    Slapi_Backend *be;
    const Slapi_DN *psdn;
    Slapi_DN *sdn;
    char *dn = NULL;

    LOG_TRACE("=>\n");

#ifdef LDAP_EXTOP_PASSMOD_CONN_SECURE
    if (check_flags & IPAPWD_CHECK_CONN_SECURE) {
       /* Allow password modify on all connections with a Security Strength
        * Factor (SSF) higher than 1 */
        if (slapi_pblock_get(pb, SLAPI_OPERATION_SSF, &ssf) != 0) {
            LOG("Could not get SSF from connection\n");
            *errMesg = "Operation requires a secure connection.\n";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        if (ssf <= 1) {
            *errMesg = "Operation requires a secure connection.\n";
            rc = LDAP_CONFIDENTIALITY_REQUIRED;
            goto done;
        }
    }
#endif

    if (check_flags & IPAPWD_CHECK_DN) {
        /* check we have a valid DN in the pblock or just abort */
        ret = slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn);
        if (ret) {
            LOG("Tried to change password for an invalid DN [%s]\n",
                dn ? dn : "<NULL>");
            *errMesg = "Invalid DN";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        sdn = slapi_sdn_new_dn_byref(dn);
        if (!sdn) {
            LOG_FATAL("Unable to convert dn to sdn %s", dn ? dn : "<NULL>");
            *errMesg = "Internal Error";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        be = slapi_be_select(sdn);
        slapi_sdn_free(&sdn);

        psdn = slapi_be_getsuffix(be, 0);
        if (!psdn) {
            *errMesg = "Invalid DN";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    /* get the kerberos context and master key */
    *config = ipapwd_getConfig();
    if (NULL == *config) {
        LOG_FATAL("Error Retrieving Master Key");
        *errMesg = "Fatal Internal Error";
        rc = LDAP_OPERATIONS_ERROR;
    }

done:
    return rc;
}

/* check password strenght and history */
int ipapwd_CheckPolicy(struct ipapwd_data *data)
{
    struct ipapwd_policy pol = {0};
    struct ipapwd_policy tmppol = {0};
    time_t acct_expiration;
    time_t pwd_expiration;
    time_t last_pwd_change;
    char **pwd_history;
    char *tmpstr;
    int ret;

    pol.max_pwd_life = IPAPWD_DEFAULT_PWDLIFE;
    pol.min_pwd_length = IPAPWD_DEFAULT_MINLEN;

    switch(data->changetype) {
        case IPA_CHANGETYPE_NORMAL:
            /* Find the entry with the password policy */
            ret = ipapwd_getPolicy(data->dn, data->target, &pol);
            if (ret) {
                LOG_TRACE("No password policy, use defaults");
            }
            break;
	case IPA_CHANGETYPE_ADMIN:
            /* The expiration date needs to be older than the current time
             * otherwise the KDC may not immediately register the password
             * as expired. The last password change needs to match the
             * password expiration otherwise minlife issues will arise.
             */
            data->timeNow -= 1;
            data->expireTime = data->timeNow;

            /* let set the entry password property according to its
             * entry password policy (done with ipapwd_getPolicy)
             * For this intentional fallthrough here
             */
        case IPA_CHANGETYPE_DSMGR:
            /* PassSync agents and Directory Manager can administratively
             * change the password without expiring it.
             *
             * Find password policy for the entry to properly set expiration.
             * Do not store it in resulting policy to avoid aplying password
             * quality checks on administratively set passwords
             */
            ret = ipapwd_getPolicy(data->dn, data->target, &tmppol);
            if (ret) {
                LOG_TRACE("No password policy, use defaults");
            } else {
                pol.max_pwd_life = tmppol.max_pwd_life;
                pol.history_length = tmppol.history_length;
            }
            break;
        default:
            LOG_TRACE("Unknown password change type, use defaults");
            break;
    }

    tmpstr = slapi_entry_attr_get_charptr(data->target,
                                          "krbPrincipalExpiration");
    acct_expiration = ipapwd_gentime_to_time_t(tmpstr);
    slapi_ch_free_string(&tmpstr);

    tmpstr = slapi_entry_attr_get_charptr(data->target,
                                          "krbPasswordExpiration");
    pwd_expiration = ipapwd_gentime_to_time_t(tmpstr);
    slapi_ch_free_string(&tmpstr);

    tmpstr = slapi_entry_attr_get_charptr(data->target,
                                          "krbLastPwdChange");
    last_pwd_change = ipapwd_gentime_to_time_t(tmpstr);
    slapi_ch_free_string(&tmpstr);

    pwd_history = slapi_entry_attr_get_charray(data->target,
                                               "passwordHistory");

    /* check policy */
    ret = ipapwd_check_policy(&pol, data->password,
                                    data->timeNow,
                                    acct_expiration,
                                    pwd_expiration,
                                    last_pwd_change,
                                    pwd_history);

    slapi_ch_array_free(pwd_history);

    if (data->expireTime == 0) {
        if (pol.max_pwd_life > 0) {
            /* max_pwd_life = 0 => never expire
             * set expire time only when max_pwd_life > 0 */
            data->expireTime = data->timeNow + pol.max_pwd_life;
        }
    }

    data->policy = pol;

    return ret;
}

/* Searches the dn in directory,
 *  If found	 : fills in slapi_entry structure and returns 0
 *  If NOT found : returns the search result as LDAP_NO_SUCH_OBJECT
 */
int ipapwd_getEntry(const char *dn, Slapi_Entry **e2, char **attrlist)
{
    Slapi_DN *sdn;
    int search_result = 0;

    LOG_TRACE("=>\n");

    sdn = slapi_sdn_new_dn_byref(dn);
    search_result = slapi_search_internal_get_entry(sdn, attrlist, e2,
                                                    ipapwd_plugin_id);
    if (search_result != LDAP_SUCCESS) {
        LOG_TRACE("No such entry-(%s), err (%d)\n", dn, search_result);
    }

    slapi_sdn_free(&sdn);
    LOG_TRACE("<= result: %d\n", search_result);
    return search_result;
}

int ipapwd_get_cur_kvno(Slapi_Entry *target)
{
    Slapi_Attr *krbPrincipalKey = NULL;
    Slapi_ValueSet *svs;
    Slapi_Value *sv;
    BerElement *be = NULL;
    const struct berval *cbval;
    ber_tag_t tag, tmp;
    ber_int_t tkvno;
    int hint;
    int kvno;
    int ret;

    /* retrieve current kvno and and keys */
    ret = slapi_entry_attr_find(target, "krbPrincipalKey", &krbPrincipalKey);
    if (ret != 0) {
        return 0;
    }

    kvno = 0;

    slapi_attr_get_valueset(krbPrincipalKey, &svs);
    hint = slapi_valueset_first_value(svs, &sv);
    while (hint != -1) {
        cbval = slapi_value_get_berval(sv);
        if (!cbval) {
            LOG_TRACE("Error retrieving berval from Slapi_Value\n");
            goto next;
        }
        be = ber_init(discard_const(cbval));
        if (!be) {
            LOG_TRACE("ber_init() failed!\n");
            goto next;
        }

        tag = ber_scanf(be, "{xxt[i]", &tmp, &tkvno);
        if (tag == LBER_ERROR) {
            LOG_TRACE("Bad OLD key encoding ?!\n");
            ber_free(be, 1);
            goto next;
        }

        if (tkvno > kvno) {
            kvno = tkvno;
        }

        ber_free(be, 1);
next:
        hint = slapi_valueset_next_value(svs, hint, &sv);
    }

    return kvno;
}

int ipapwd_setdate(Slapi_Entry *source, Slapi_Mods *smods, const char *attr,
                   time_t date, bool remove)
{
    char timestr[GENERALIZED_TIME_LENGTH+1];
    struct tm utctime;
    Slapi_Attr *t;
    bool exists;

    exists = (slapi_entry_attr_find(source, attr, &t) == 0);

    if (remove) {
        if (exists) {
             slapi_mods_add_mod_values(smods, LDAP_MOD_DELETE, attr, NULL);
        }
        return LDAP_SUCCESS;
    }

    if (!gmtime_r(&date, &utctime)) {
        LOG_FATAL("failed to convert %s date\n", attr);
        return LDAP_OPERATIONS_ERROR;
    }
    strftime(timestr, GENERALIZED_TIME_LENGTH + 1, "%Y%m%d%H%M%SZ", &utctime);
    slapi_mods_add_string(smods, exists ?  LDAP_MOD_REPLACE : LDAP_MOD_ADD,
                          attr, timestr);
    return LDAP_SUCCESS;
}

/* Modify the Password attributes of the entry */
int ipapwd_SetPassword(struct ipapwd_krbcfg *krbcfg,
                       struct ipapwd_data *data, int is_krb)
{
    int ret = 0;
    Slapi_Mods *smods = NULL;
    Slapi_Value **svals = NULL;
    Slapi_Value **ntvals = NULL;
    Slapi_Value **pwvals = NULL;
    char *nt = NULL;
    int is_smb = 0;
    int is_ipant = 0;
    int is_host = 0;
    Slapi_Value *sambaSamAccount;
    Slapi_Value *ipaNTUserAttrs;
    Slapi_Value *ipaHost;
    char *errMesg = NULL;
    char *modtime = NULL;

    LOG_TRACE("=>\n");

    sambaSamAccount = slapi_value_new_string("sambaSamAccount");
    if (slapi_entry_attr_has_syntax_value(data->target,
                                          "objectClass", sambaSamAccount)) {
        is_smb = 1;
    }
    slapi_value_free(&sambaSamAccount);

    ipaNTUserAttrs = slapi_value_new_string("ipaNTUserAttrs");
    if (slapi_entry_attr_has_syntax_value(data->target,
                                          "objectClass", ipaNTUserAttrs)) {
        is_ipant = 1;
    }
    slapi_value_free(&ipaNTUserAttrs);

    ipaHost = slapi_value_new_string("ipaHost");
    if (slapi_entry_attr_has_syntax_value(data->target,
                                          "objectClass", ipaHost)) {
        is_host = 1;
    }
    slapi_value_free(&ipaHost);

    ret = ipapwd_gen_hashes(krbcfg, data,
                            data->password,
                            is_krb, is_smb, is_ipant,
                            &svals, &nt, &ntvals, &errMesg);
    if (ret) {
        goto free_and_return;
    }

    smods = slapi_mods_new();

    if (svals) {
        slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                  "krbPrincipalKey", svals);

		/* krbLastPwdChange is used to tell whether a host entry has a
		 * keytab so don't set it on hosts.
		 */
        if (!is_host) {
	    /* change Last Password Change field with the current date */
            ret = ipapwd_setdate(data->target, smods, "krbLastPwdChange",
                                 data->timeNow, false);
            if (ret != LDAP_SUCCESS)
                goto free_and_return;

	    /* set Password Expiration date */
            ret = ipapwd_setdate(data->target, smods, "krbPasswordExpiration",
                                 data->expireTime, (data->expireTime == 0));
            if (ret != LDAP_SUCCESS)
                goto free_and_return;
	}
    }

    if (nt && is_smb) {
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "sambaNTPassword", nt);
    }

    if (ntvals && is_ipant) {
        slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                  "ipaNTHash", ntvals);
    }

    if (is_smb) {
        /* with samba integration we need to also set sambaPwdLastSet or
         * samba will decide the user has to change the password again */
        if (data->changetype == IPA_CHANGETYPE_ADMIN) {
            /* if it is an admin change instead we need to let know to
             * samba as well that the use rmust change its password */
            modtime = slapi_ch_smprintf("0");
        } else {
            modtime = slapi_ch_smprintf("%ld", (long)data->timeNow);
        }
        if (!modtime) {
            LOG_FATAL("failed to smprintf string!\n");
            ret = LDAP_OPERATIONS_ERROR;
            goto free_and_return;
        }
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "sambaPwdLastset", modtime);
    }
    if (is_krb) {
        if (data->changetype == IPA_CHANGETYPE_ADMIN) {
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                 "krbLoginFailedCount", "0");
        }
    }
    /* let DS encode the password itself, this allows also other plugins to
     * intercept it to perform operations like synchronization with Active
     * Directory domains through the replication plugin */
    slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "userPassword", data->password);

    /* set password history */
    if (data->policy.history_length > 0) {
        pwvals = ipapwd_setPasswordHistory(smods, data);
        if (pwvals) {
            slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                      "passwordHistory", pwvals);
        }
    }

    /* FIXME:
     * instead of replace we should use a delete/add so that we are
     * completely sure nobody else modified the entry meanwhile and
     * fail if that's the case */

    /* commit changes */
    ret = ipapwd_apply_mods(data->dn, smods);

    LOG_TRACE("<= result: %d\n", ret);

free_and_return:
    if (nt) slapi_ch_free((void **)&nt);
    if (modtime) slapi_ch_free((void **)&modtime);
    slapi_mods_free(&smods);
    ipapwd_free_slapi_value_array(&svals);
    ipapwd_free_slapi_value_array(&ntvals);
    ipapwd_free_slapi_value_array(&pwvals);

    return ret;
}


Slapi_Value **ipapwd_setPasswordHistory(Slapi_Mods *smods,
                                        struct ipapwd_data *data)
{
    Slapi_Value **pH = NULL;
    char **pwd_history = NULL;
    char **new_pwd_history = NULL;
    int n = 0;
    int ret;
    int i;

    pwd_history = slapi_entry_attr_get_charray(data->target,
                                               "passwordHistory");

    ret = ipapwd_generate_new_history(data->password, data->timeNow,
                                      data->policy.history_length,
                                      pwd_history, &new_pwd_history, &n);

    if (ret && data->policy.history_length) {
        LOG_FATAL("failed to generate new password history!\n");
        goto done;
    }

    pH = (Slapi_Value **)slapi_ch_calloc(n + 1, sizeof(Slapi_Value *));
    if (!pH) {
        LOG_OOM();
        goto done;
    }

    for (i = 0; i < n; i++) {
        pH[i] = slapi_value_new_string(new_pwd_history[i]);
        if (!pH[i]) {
            ipapwd_free_slapi_value_array(&pH);
            LOG_OOM();
            goto done;
        }
    }

done:
    slapi_ch_array_free(pwd_history);
    for (i = 0; i < n; i++) {
        free(new_pwd_history[i]);
    }
    free(new_pwd_history);
    return pH;
}

/* Construct Mods pblock and perform the modify operation
 * Sets result of operation in SLAPI_PLUGIN_INTOP_RESULT
 */
int ipapwd_apply_mods(const char *dn, Slapi_Mods *mods)
{
    Slapi_PBlock *pb;
    int ret;

    LOG_TRACE("=>\n");

    if (!mods || (slapi_mods_get_num_mods(mods) == 0)) {
        return -1;
    }

    pb = slapi_pblock_new();
    slapi_modify_internal_set_pb(pb, dn,
                                 slapi_mods_get_ldapmods_byref(mods),
                                 NULL, /* Controls */
                                 NULL, /* UniqueID */
                                 ipapwd_plugin_id, /* PluginID */
                                 0); /* Flags */

    ret = slapi_modify_internal_pb(pb);
    if (ret) {
        LOG_TRACE("WARNING: modify error %d on entry '%s'\n", ret, dn);
    } else {

        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

        if (ret != LDAP_SUCCESS){
            LOG_TRACE("WARNING: modify error %d on entry '%s'\n", ret, dn);
        } else {
            LOG_TRACE("<= Successful\n");
        }
    }

    slapi_pblock_destroy(pb);

    return ret;
}

int ipapwd_set_extradata(const char *dn,
                         const char *principal,
                         time_t unixtime)
{
    Slapi_Mods *smods;
    Slapi_Value *va[2] = { NULL };
    struct berval bv;
    char *xdata;
    int xd_len;
    int p_len;
    int ret;

    p_len = strlen(principal);
    xd_len = 2 + 4 + p_len + 1;
    xdata = malloc(xd_len);
    if (!xdata) {
        return LDAP_OPERATIONS_ERROR;
    }

    smods = slapi_mods_new();

    /* data type id */
    xdata[0] = 0x00;
    xdata[1] = 0x02;

    /* unix timestamp in Little Endian */
    xdata[2] = unixtime & 0xff;
    xdata[3] = (unixtime & 0xff00) >> 8;
    xdata[4] = (unixtime & 0xff0000) >> 16;
    xdata[5] = (unixtime & 0xff000000) >> 24;

    /* append the principal name */
    strncpy(&xdata[6], principal, p_len);

    xdata[xd_len -1] = 0;

    bv.bv_val = xdata;
    bv.bv_len = xd_len;
    va[0] = slapi_value_new_berval(&bv);

    slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "krbExtraData", va);

    ret = ipapwd_apply_mods(dn, smods);

    slapi_value_free(&va[0]);
    slapi_mods_free(&smods);

    return ret;
}

void ipapwd_free_slapi_value_array(Slapi_Value ***svals)
{
    Slapi_Value **sv = *svals;
    int i;

    if (sv) {
        for (i = 0; sv[i]; i++) {
            slapi_value_free(&sv[i]);
        }
    }

    slapi_ch_free((void **)sv);
}

void free_ipapwd_krbcfg(struct ipapwd_krbcfg **cfg)
{
    struct ipapwd_krbcfg *c = *cfg;

    if (!c) return;

    krb5_free_default_realm(c->krbctx, c->realm);
    krb5_free_context(c->krbctx);
    free(c->kmkey->contents);
    free(c->kmkey);
    free(c->supp_encsalts);
    free(c->pref_encsalts);
    slapi_ch_array_free(c->passsync_mgrs);
    free(c);
    *cfg = NULL;
};

