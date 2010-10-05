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
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "ipapwd.h"

/* Type of connection for this operation;*/
#define LDAP_EXTOP_PASSMOD_CONN_SECURE

/* Uncomment the following #undef FOR TESTING:
 * allows non-SSL connections to use the password change extended op */
/* #undef LDAP_EXTOP_PASSMOD_CONN_SECURE */

extern void *ipapwd_plugin_id;
extern const char *ipa_realm_dn;
extern const char *ipa_etc_config_dn;
extern const char *ipa_pwd_config_dn;

/* These are the default enc:salt types if nothing is defined.
 * TODO: retrieve the configure set of ecntypes either from the
 * kfc.conf file or by synchronizing the the file content into
 * the directory */
static const char *ipapwd_def_encsalts[] = {
    "des3-hmac-sha1:normal",
/*    "arcfour-hmac:normal",
    "des-hmac-sha1:normal",
    "des-cbc-md5:normal", */
    "des-cbc-crc:normal",
/*    "des-cbc-crc:v4",
    "des-cbc-crc:afs3", */
    NULL
};

static int new_ipapwd_encsalt(krb5_context krbctx,
                              const char * const *encsalts,
                              struct ipapwd_encsalt **es_types,
                              int *num_es_types)
{
    struct ipapwd_encsalt *es;
    int nes, i;

    for (i = 0; encsalts[i]; i++) /* count */ ;
    es = calloc(i + 1, sizeof(struct ipapwd_encsalt));
    if (!es) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "Out of memory!\n");
        return LDAP_OPERATIONS_ERROR;
    }

    for (i = 0, nes = 0; encsalts[i]; i++) {
        char *enc, *salt;
        krb5_int32 tmpsalt;
        krb5_enctype tmpenc;
        krb5_boolean similar;
        krb5_error_code krberr;
        int j;

        enc = strdup(encsalts[i]);
        if (!enc) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Allocation error\n");
            return LDAP_OPERATIONS_ERROR;
        }
        salt = strchr(enc, ':');
        if (!salt) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Invalid krb5 enc string\n");
            free(enc);
            continue;
        }
        *salt = '\0'; /* null terminate the enc type */
        salt++; /* skip : */

        krberr = krb5_string_to_enctype(enc, &tmpenc);
        if (krberr) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Invalid krb5 enctype\n");
            free(enc);
            continue;
        }

        krberr = krb5_string_to_salttype(salt, &tmpsalt);
        for (j = 0; j < nes; j++) {
            krb5_c_enctype_compare(krbctx, es[j].enc_type, tmpenc, &similar);
            if (similar && (es[j].salt_type == tmpsalt)) {
                break;
            }
        }

        if (j == nes) {
            /* not found */
            es[j].enc_type = tmpenc;
            es[j].salt_type = tmpsalt;
            nes++;
        }

        free(enc);
    }

    *es_types = es;
    *num_es_types = nes;

    return LDAP_SUCCESS;
}

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
    ber_tag_t tag, tmp;
    ber_int_t ttype;
    const struct berval *bval;
    struct berval *mkey = NULL;
    char **encsalts;
    char **tmparray;
    char *tmpstr;
    int i, ret;

    config = calloc(1, sizeof(struct ipapwd_krbcfg));
    if (!config) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "Out of memory!\n");
        goto free_and_error;
    }
    kmkey = calloc(1, sizeof(krb5_keyblock));
    if (!kmkey) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "Out of memory!\n");
        goto free_and_error;
    }
    config->kmkey = kmkey;

    krberr = krb5_init_context(&config->krbctx);
    if (krberr) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__,
                        "krb5_init_context failed\n");
        goto free_and_error;
    }

    ret = krb5_get_default_realm(config->krbctx, &config->realm);
    if (ret) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__,
                        "Failed to get default realm?!\n");
        goto free_and_error;
    }

    /* get the Realm Container entry */
    ret = ipapwd_getEntry(ipa_realm_dn, &realm_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "No realm Entry?\n");
        goto free_and_error;
    }

    /*** get the Kerberos Master Key ***/

    ret = slapi_entry_attr_find(realm_entry, "krbMKey", &a);
    if (ret == -1) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "No master key??\n");
        goto free_and_error;
    }

    /* there should be only one value here */
    ret = slapi_attr_first_value(a, &v);
    if (ret == -1) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "No master key??\n");
        goto free_and_error;
    }

    bval = slapi_value_get_berval(v);
    if (!bval) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__,
                        "Error retrieving master key berval\n");
        goto free_and_error;
    }

    be = ber_init(bval);
    if (!bval) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "ber_init() failed!\n");
        goto free_and_error;
    }

    tag = ber_scanf(be, "{i{iO}}", &tmp, &ttype, &mkey);
    if (tag == LBER_ERROR) {
        slapi_log_error(SLAPI_LOG_TRACE, __func__,
                        "Bad Master key encoding ?!\n");
        goto free_and_error;
    }

    kmkey->magic = KV5M_KEYBLOCK;
    kmkey->enctype = ttype;
    kmkey->length = mkey->bv_len;
    kmkey->contents = malloc(mkey->bv_len);
    if (!kmkey->contents) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "Out of memory!\n");
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
        ret = new_ipapwd_encsalt(config->krbctx,
                                 (const char * const *)encsalts,
                                 &config->supp_encsalts,
                                 &config->num_supp_encsalts);
        slapi_ch_array_free(encsalts);
    } else {
        slapi_log_error(SLAPI_LOG_TRACE, __func__,
                        "No configured salt types use defaults\n");
        ret = new_ipapwd_encsalt(config->krbctx,
                                 ipapwd_def_encsalts,
                                 &config->supp_encsalts,
                                 &config->num_supp_encsalts);
    }
    if (ret) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__,
                        "Can't get Supported EncSalt Types\n");
        goto free_and_error;
    }

    /*** get the Preferred Enc/Salt types ***/

    encsalts = slapi_entry_attr_get_charray(realm_entry,
                                            "krbDefaultEncSaltTypes");
    if (encsalts) {
        ret = new_ipapwd_encsalt(config->krbctx,
                                 (const char * const *)encsalts,
                                 &config->pref_encsalts,
                                 &config->num_pref_encsalts);
        slapi_ch_array_free(encsalts);
    } else {
        slapi_log_error(SLAPI_LOG_TRACE, __func__,
                        "No configured salt types use defaults\n");
        ret = new_ipapwd_encsalt(config->krbctx,
                                 ipapwd_def_encsalts,
                                 &config->pref_encsalts,
                                 &config->num_pref_encsalts);
    }
    if (ret) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__,
                        "Can't get Preferred EncSalt Types\n");
        goto free_and_error;
    }

    slapi_entry_free(realm_entry);

    /* get the Realm Container entry */
    ret = ipapwd_getEntry(ipa_pwd_config_dn, &config_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__,
                        "No config Entry? Impossible!\n");
        goto free_and_error;
    }
    config->passsync_mgrs =
            slapi_entry_attr_get_charray(config_entry, "passSyncManagersDNs");
    /* now add Directory Manager, it is always added by default */
    tmpstr = slapi_ch_strdup("cn=Directory Manager");
    slapi_ch_array_add(&config->passsync_mgrs, tmpstr);
    if (config->passsync_mgrs == NULL) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "Out of memory!\n");
        goto free_and_error;
    }
    for (i = 0; config->passsync_mgrs[i]; i++) /* count */ ;
    config->num_passsync_mgrs = i;

    slapi_entry_free(config_entry);

    /* get the ipa etc/ipaConfig entry */
    config->allow_lm_hash = false;
    config->allow_nt_hash = false;
    ret = ipapwd_getEntry(ipa_etc_config_dn, &config_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, __func__, "No config Entry?\n");
    } else {
        tmparray = slapi_entry_attr_get_charray(config_entry,
                                                "ipaConfigString");
        for (i = 0; tmparray && tmparray[i]; i++) {
            if (strcasecmp(tmparray[i], "AllowLMhash") == 0) {
                config->allow_lm_hash = true;
                continue;
            }
            if (strcasecmp(tmparray[i], "AllowNThash") == 0) {
                config->allow_nt_hash = true;
                continue;
            }
        }
        if (tmparray) slapi_ch_array_free(tmparray);
    }

    slapi_entry_free(config_entry);

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

static int ipapwd_getPolicy(const char *dn,
                            Slapi_Entry *target, Slapi_Entry **e)
{
    const char *krbPwdPolicyReference;
    const char *pdn;
    const Slapi_DN *psdn;
    Slapi_Backend *be;
    Slapi_PBlock *pb = NULL;
    char *attrs[] = { "krbMaxPwdLife", "krbMinPwdLife",
                      "krbPwdMinDiffChars", "krbPwdMinLength",
                      "krbPwdHistoryLength", NULL};
    Slapi_Entry **es = NULL;
    Slapi_Entry *pe = NULL;
    char **edn;
    int ret, res, dist, rdnc, scope, i;
    Slapi_DN *sdn = NULL;
    int buffer_flags=0;
    Slapi_ValueSet* results = NULL;
    char* actual_type_name = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "ipapwd_getPolicy: Searching policy for [%s]\n", dn);

    sdn = slapi_sdn_new_dn_byref(dn);
    if (sdn == NULL) {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_getPolicy: Out of memory on [%s]\n", dn);
        ret = -1;
        goto done;
    }

    pwd_get_values(target, "krbPwdPolicyReference",
                   &results, &actual_type_name, &buffer_flags);
    if (results) {
        Slapi_Value *sv;
        slapi_valueset_first_value(results, &sv);
        krbPwdPolicyReference = slapi_value_get_string(sv);
        pdn = krbPwdPolicyReference;
        scope = LDAP_SCOPE_BASE;
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "ipapwd_getPolicy: using policy reference: %s\n", pdn);
    } else {
        /* Find ancestor base DN */
        be = slapi_be_select(sdn);
        psdn = slapi_be_getsuffix(be, 0);
        if (psdn == NULL) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "ipapwd_getPolicy: Invalid DN [%s]\n", dn);
            ret = -1;
            goto done;
        }
        pdn = slapi_sdn_get_dn(psdn);
        scope = LDAP_SCOPE_SUBTREE;
    }

    *e = NULL;

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
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_getPolicy: Couldn't find policy, err (%d)\n",
                        res ? res : ret);
        ret = -1;
        goto done;
    }

    /* get entries */
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
    if (!es) {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_getPolicy: No entries ?!");
        ret = -1;
        goto done;
    }

    /* count entries */
    for (i = 0; es[i]; i++) /* count */ ;

    /* if there is only one, return that */
    if (i == 1) {
        *e = slapi_entry_dup(es[0]);

        ret = 0;
        goto done;
    }

    /* count number of RDNs in DN */
    edn = ldap_explode_dn(dn, 0);
    if (!edn) {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_getPolicy: ldap_explode_dn(dn) failed ?!");
        ret = -1;
        goto done;
    }
    for (rdnc = 0; edn[rdnc]; rdnc++) /* count */ ;
    ldap_value_free(edn);

    pe = NULL;
    dist = -1;

    /* find closest entry */
    for (i = 0; es[i]; i++) {
        const Slapi_DN *esdn;

        esdn = slapi_entry_get_sdn_const(es[i]);
        if (esdn == NULL) continue;
        if (0 == slapi_sdn_compare(esdn, sdn)) {
            pe = es[i];
            dist = 0;
            break;
        }
        if (slapi_sdn_issuffix(sdn, esdn)) {
            const char *dn1;
            char **e1;
            int c1;

            dn1 = slapi_sdn_get_dn(esdn);
            if (!dn1) continue;
            e1 = ldap_explode_dn(dn1, 0);
            if (!e1) continue;
            for (c1 = 0; e1[c1]; c1++) /* count */ ;
            ldap_value_free(e1);
            if ((dist == -1) ||
                ((rdnc - c1) < dist)) {
                dist = rdnc - c1;
                pe = es[i];
            }
        }
        if (dist == 0) break; /* found closest */
    }

    if (pe == NULL) {
        ret = -1;
        goto done;
    }

    *e = slapi_entry_dup(pe);
    ret = 0;
done:
    if (results) {
        pwd_values_free(&results, &actual_type_name, buffer_flags);
    }
    if (pb) {
        slapi_free_search_results_internal(pb);
        slapi_pblock_destroy(pb);
    }
    if (sdn) slapi_sdn_free(&sdn);
    return ret;
}

static Slapi_Value *ipapwd_strip_pw_date(Slapi_Value *pw)
{
    const char *pwstr;

    pwstr = slapi_value_get_string(pw);
    return slapi_value_new_string(&pwstr[GENERALIZED_TIME_LENGTH]);
}

/* ascii hex output of bytes in "in"
 * out len is 32 (preallocated)
 * in len is 16 */
static const char hexchars[] = "0123456789ABCDEF";
void hexbuf(char *out, const uint8_t *in)
{
    int i;

    for (i = 0; i < 16; i++) {
        out[i*2] = hexchars[in[i] >> 4];
        out[i*2+1] = hexchars[in[i] & 0x0f];
    }
}

/* searches the directory and finds the policy closest to the DN */
/* return 0 on success, -1 on error or if no policy is found */
static int ipapwd_sv_pw_cmp(const void *pv1, const void *pv2)
{
    const char *pw1 = slapi_value_get_string(*((Slapi_Value **)pv1));
    const char *pw2 = slapi_value_get_string(*((Slapi_Value **)pv2));

    return strncmp(pw1, pw2, GENERALIZED_TIME_LENGTH);
}


/*==Common-public-functions=============================================*/

int ipapwd_entry_checks(Slapi_PBlock *pb, struct slapi_entry *e,
                        int *is_root, int *is_krb, int *is_smb,
                        char *attr, int access)
{
    Slapi_Value *sval;
    int rc;

    /* Check ACIs */
    slapi_pblock_get(pb, SLAPI_REQUESTOR_ISROOT, is_root);

    if (!*is_root) {
        /* verify this user is allowed to write a user password */
        rc = slapi_access_allowed(pb, e, attr, NULL, access);
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

    rc = LDAP_SUCCESS;

done:
    return rc;
}

int ipapwd_gen_checks(Slapi_PBlock *pb, char **errMesg,
                      struct ipapwd_krbcfg **config, int check_flags)
{
    int ret, sasl_ssf, is_ssl;
    int rc = LDAP_SUCCESS;
    Slapi_Backend *be;
    const Slapi_DN *psdn;
    Slapi_DN *sdn;
    char *dn = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "=> ipapwd_gen_checks\n");

#ifdef LDAP_EXTOP_PASSMOD_CONN_SECURE
    if (check_flags & IPAPWD_CHECK_CONN_SECURE) {
        /* Allow password modify only for SSL/TLS established connections and
         * connections using SASL privacy layers */
        if (slapi_pblock_get(pb, SLAPI_CONN_SASL_SSF, &sasl_ssf) != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Could not get SASL SSF from connection\n");
            *errMesg = "Operation requires a secure connection.\n";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        if (slapi_pblock_get(pb, SLAPI_CONN_IS_SSL_SESSION, &is_ssl) != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Could not get IS SSL from connection\n");
            *errMesg = "Operation requires a secure connection.\n";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        if ((0 == is_ssl) && (sasl_ssf <= 1)) {
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
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Tried to change password for an invalid DN "
                            "[%s]\n", dn ? dn : "<NULL>");
            *errMesg = "Invalid DN";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        sdn = slapi_sdn_new_dn_byref(dn);
        if (!sdn) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "Unable to convert dn to sdn %s",
                            dn ? dn : "<NULL>");
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
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "Error Retrieving Master Key");
        *errMesg = "Fatal Internal Error";
        rc = LDAP_OPERATIONS_ERROR;
    }

done:
    return rc;
}

/* 90 days default pwd max lifetime */
#define IPAPWD_DEFAULT_PWDLIFE (90 * 24 *3600)
#define IPAPWD_DEFAULT_MINLEN 0

/* check password strenght and history */
int ipapwd_CheckPolicy(struct ipapwd_data *data)
{
    char *krbPrincipalExpiration = NULL;
    char *krbLastPwdChange = NULL;
    char *krbPasswordExpiration = NULL;
    int krbMaxPwdLife = IPAPWD_DEFAULT_PWDLIFE;
    int krbPwdMinLength = IPAPWD_DEFAULT_MINLEN;
    int krbPwdMinDiffChars = 0;
    int krbMinPwdLife = 0;
    int pwdCharLen = 0;
    Slapi_Entry *policy = NULL;
    Slapi_Attr *passwordHistory = NULL;
    struct tm tm;
    int tmp, ret;
    char *old_pw;

    /* check account is not expired. Ignore unixtime = 0 (Jan 1 1970) */
    krbPrincipalExpiration =
        slapi_entry_attr_get_charptr(data->target, "krbPrincipalExpiration");
    if (krbPrincipalExpiration &&
        (strcasecmp("19700101000000Z", krbPrincipalExpiration) != 0)) {
        /* if expiration date is set check it */
        memset(&tm, 0, sizeof(struct tm));
        ret = sscanf(krbPrincipalExpiration,
                     "%04u%02u%02u%02u%02u%02u",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

        if (ret == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;

            if (data->timeNow > timegm(&tm)) {
                slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                                "Account Expired");
                return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDMODNOTALLOWED;
            }
        }
        /* FIXME: else error out ? */
    }
    slapi_ch_free_string(&krbPrincipalExpiration);

    /* find the entry with the password policy */
    ret = ipapwd_getPolicy(data->dn, data->target, &policy);
    if (ret) {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "No password policy");
        goto no_policy;
    }

    /* Retrieve Max History Len */
    data->pwHistoryLen =
                    slapi_entry_attr_get_int(policy, "krbPwdHistoryLength");

    if (data->changetype != IPA_CHANGETYPE_NORMAL) {
        /* We must skip policy checks (Admin change) but
         * force a password change on the next login.
         * But not if Directory Manager */
        if (data->changetype == IPA_CHANGETYPE_ADMIN) {
            data->expireTime = data->timeNow;
        }

        /* skip policy checks */
        slapi_entry_free(policy);
        goto no_policy;
    }

    /* first of all check current password, if any */
    old_pw = slapi_entry_attr_get_charptr(data->target, "userPassword");
    if (old_pw) {
        Slapi_Value *cpw[2] = {NULL, NULL};
        Slapi_Value *pw;

        cpw[0] = slapi_value_new_string(old_pw);
        pw = slapi_value_new_string(data->password);
        if (!pw) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "ipapwd_checkPassword: Out of Memory\n");
            slapi_entry_free(policy);
            slapi_ch_free_string(&old_pw);
            slapi_value_free(&cpw[0]);
            slapi_value_free(&pw);
            return LDAP_OPERATIONS_ERROR;
        }

        ret = slapi_pw_find_sv(cpw, pw);
        slapi_ch_free_string(&old_pw);
        slapi_value_free(&cpw[0]);
        slapi_value_free(&pw);

        if (ret == 0) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "ipapwd_checkPassword: Password in history\n");
            slapi_entry_free(policy);
            return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDINHISTORY;
        }
    }

    krbPasswordExpiration =
        slapi_entry_attr_get_charptr(data->target, "krbPasswordExpiration");
    krbLastPwdChange =
        slapi_entry_attr_get_charptr(data->target, "krbLastPwdChange");
    /* if no previous change, it means this is probably a new account
     * or imported, log and just ignore */
    if (krbLastPwdChange) {

        memset(&tm, 0, sizeof(struct tm));
        ret = sscanf(krbLastPwdChange,
                     "%04u%02u%02u%02u%02u%02u",
                     &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
                     &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

        if (ret == 6) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;
            data->lastPwChange = timegm(&tm);
        }
        /* FIXME: *else* report an error ? */
    } else {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "Warning: Last Password Change Time is not available\n");
    }

    /* Check min age */
    krbMinPwdLife = slapi_entry_attr_get_int(policy, "krbMinPwdLife");
    /* if no default then treat it as no limit */
    if (krbMinPwdLife != 0) {

        /* check for reset cases */
        if (krbLastPwdChange == NULL ||
            ((krbPasswordExpiration != NULL) &&
             strcmp(krbPasswordExpiration, krbLastPwdChange) == 0)) {
            /* Expiration and last change time are the same or
             * missing this happens only when a password is reset
             * by an admin or the account is new or no expiration
             * policy is set, PASS */
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "ipapwd_checkPolicy: Ignore krbMinPwdLife "
                            "Expiration, not enough info\n");

        } else if (data->timeNow < data->lastPwChange + krbMinPwdLife) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_checkPolicy: Too soon to change password\n");
            slapi_entry_free(policy);
            slapi_ch_free_string(&krbPasswordExpiration);
            slapi_ch_free_string(&krbLastPwdChange);
            return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDTOOYOUNG;
        }
    }

    /* free strings or we leak them */
    slapi_ch_free_string(&krbPasswordExpiration);
    slapi_ch_free_string(&krbLastPwdChange);

    /* Retrieve min length */
    tmp = slapi_entry_attr_get_int(policy, "krbPwdMinLength");
    if (tmp != 0) {
        krbPwdMinLength = tmp;
    }

    /* check complexity */
    /* FIXME: this code is partially based on Directory Server code,
     *        the plan is to merge this code later making it available
     *        trough a pulic DS API for slapi plugins */
    krbPwdMinDiffChars =
                    slapi_entry_attr_get_int(policy, "krbPwdMinDiffChars");
    if (krbPwdMinDiffChars != 0) {
        int num_digits = 0;
        int num_alphas = 0;
        int num_uppers = 0;
        int num_lowers = 0;
        int num_specials = 0;
        int num_8bit = 0;
        int num_repeated = 0;
        int max_repeated = 0;
        int num_categories = 0;
        char *p, *pwd;

        pwd = strdup(data->password);

        /* check character types */
        p = pwd;
        while (p && *p) {
            if (ldap_utf8isdigit(p)) {
                num_digits++;
            } else if (ldap_utf8isalpha(p)) {
                num_alphas++;
                if (slapi_utf8isLower((unsigned char *)p)) {
                    num_lowers++;
                } else {
                    num_uppers++;
                }
            } else {
                /* check if this is an 8-bit char */
                if (*p & 128) {
                    num_8bit++;
                } else {
                    num_specials++;
                }
            }

            /* check for repeating characters. If this is the
               first char of the password, no need to check */
            if (pwd != p) {
                int len = ldap_utf8len(p);
                char *prev_p = ldap_utf8prev(p);

                if (len == ldap_utf8len(prev_p)) {
                    if (memcmp(p, prev_p, len) == 0) {
                        num_repeated++;
                        if (max_repeated < num_repeated) {
                            max_repeated = num_repeated;
                        }
                    } else {
                        num_repeated = 0;
                    }
                } else {
                    num_repeated = 0;
                }
            }

            p = ldap_utf8next(p);
        }

        free(pwd);
        p = pwd = NULL;

        /* tally up the number of character categories */
        if (num_digits > 0) ++num_categories;
        if (num_uppers > 0) ++num_categories;
        if (num_lowers > 0) ++num_categories;
        if (num_specials > 0) ++num_categories;
        if (num_8bit > 0) ++num_categories;

        /* FIXME: the kerberos plicy schema does not define separated
         *        threshold values, so just treat anything as a category,
         *        we will fix this when we merge with DS policies */

        if (max_repeated > 1) --num_categories;

        if (num_categories < krbPwdMinDiffChars) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "ipapwd_checkPassword: Password not complex enough\n");
            slapi_entry_free(policy);
            return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_INVALIDPWDSYNTAX;
        }
    }

    /* Check password history */
    ret = slapi_entry_attr_find(data->target,
                                "passwordHistory", &passwordHistory);
    if (ret == 0) {
        int ret, hint, count, i, j;
        const char *pwstr;
        Slapi_Value **pH;
        Slapi_Value *pw;

        hint = 0;
        count = 0;
        ret = slapi_attr_get_numvalues(passwordHistory, &count);
        /* check history only if we have one */
        if (count > 0 && data->pwHistoryLen > 0) {
            pH = calloc(count + 2, sizeof(Slapi_Value *));
            if (!pH) {
                slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                "ipapwd_checkPassword: Out of Memory\n");
                slapi_entry_free(policy);
                return LDAP_OPERATIONS_ERROR;
            }

            i = 0;
            hint = slapi_attr_first_value(passwordHistory, &pw);
            while (hint != -1) {
                pwstr = slapi_value_get_string(pw);
                /* if shorter than GENERALIZED_TIME_LENGTH, it
                 * is garbage, we never set timeless entries */
                if (pwstr &&
                    (strlen(pwstr) > GENERALIZED_TIME_LENGTH)) {
                    pH[i] = pw;
                    i++;
                }
                hint = slapi_attr_next_value(passwordHistory, hint, &pw);
            }

            qsort(pH, i, sizeof(Slapi_Value *), ipapwd_sv_pw_cmp);

            if (i > data->pwHistoryLen) {
                i = data->pwHistoryLen;
                pH[i] = NULL;
            }

            for (j = 0; pH[j]; j++) {
                pH[j] = ipapwd_strip_pw_date(pH[j]);
            }

            pw = slapi_value_new_string(data->password);
            if (!pw) {
                slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                "ipapwd_checkPassword: Out of Memory\n");
                slapi_entry_free(policy);
                free(pH);
                return LDAP_OPERATIONS_ERROR;
            }

            ret = slapi_pw_find_sv(pH, pw);

            for (j = 0; pH[j]; j++) {
                slapi_value_free(&pH[j]);
            }
            slapi_value_free(&pw);
            free(pH);

            if (ret == 0) {
                slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "ipapwd_checkPassword: Password in history\n");
                slapi_entry_free(policy);
                return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDINHISTORY;
            }
        }
    }

    /* Calculate max age */
    tmp = slapi_entry_attr_get_int(policy, "krbMaxPwdLife");
    if (tmp != 0) {
        krbMaxPwdLife = tmp;
    }

    slapi_entry_free(policy);

no_policy:

    /* check min lenght */
    pwdCharLen = ldap_utf8characters(data->password);

    if (pwdCharLen < krbPwdMinLength) {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_checkPassword: Password too short "
                        "(%d < %d)\n", pwdCharLen, krbPwdMinLength);
        return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDTOOSHORT;
    }

    if (data->expireTime == 0) {
        data->expireTime = data->timeNow + krbMaxPwdLife;
    }

    return IPAPWD_POLICY_OK;
}

/* Searches the dn in directory,
 *  If found	 : fills in slapi_entry structure and returns 0
 *  If NOT found : returns the search result as LDAP_NO_SUCH_OBJECT
 */
int ipapwd_getEntry(const char *dn, Slapi_Entry **e2, char **attrlist)
{
    Slapi_DN *sdn;
    int search_result = 0;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "=> ipapwd_getEntry\n");

    sdn = slapi_sdn_new_dn_byref(dn);
    search_result = slapi_search_internal_get_entry(sdn, attrlist, e2,
                                                    ipapwd_plugin_id);
    if (search_result != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "ipapwd_getEntry: No such entry-(%s), err (%d)\n",
                        dn, search_result);
    }

    slapi_sdn_free(&sdn);
    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "<= ipapwd_getEntry: %d\n", search_result);
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
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "Error retrieving berval from Slapi_Value\n");
            goto next;
        }
        be = ber_init(cbval);
        if (!be) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "ber_init() failed!\n");
            goto next;
        }

        tag = ber_scanf(be, "{xxt[i]", &tmp, &tkvno);
        if (tag == LBER_ERROR) {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "Bad OLD key encoding ?!\n");
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

/* Modify the Password attributes of the entry */
int ipapwd_SetPassword(struct ipapwd_krbcfg *krbcfg,
                       struct ipapwd_data *data, int is_krb)
{
    int ret = 0;
    Slapi_Mods *smods;
    Slapi_Value **svals = NULL;
    Slapi_Value **pwvals = NULL;
    struct tm utctime;
    char timestr[GENERALIZED_TIME_LENGTH+1];
    krb5_context krbctx;
    krb5_error_code krberr;
    char *lm = NULL;
    char *nt = NULL;
    int is_smb = 0;
    Slapi_Value *sambaSamAccount;
    char *errMesg = NULL;
    char *modtime = NULL;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "=> ipapwd_SetPassword\n");

    sambaSamAccount = slapi_value_new_string("sambaSamAccount");
    if (slapi_entry_attr_has_syntax_value(data->target,
                                          "objectClass", sambaSamAccount)) {
        is_smb = 1;;
    }
    slapi_value_free(&sambaSamAccount);

    ret = ipapwd_gen_hashes(krbcfg, data,
                            data->password,
                            is_krb, is_smb,
                            &svals, &nt, &lm, &errMesg);
    if (ret) {
        goto free_and_return;
    }

    smods = slapi_mods_new();

    if (svals) {
        slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                  "krbPrincipalKey", svals);

        /* change Last Password Change field with the current date */
        if (!gmtime_r(&(data->timeNow), &utctime)) {
            slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                    "failed to retrieve current date (buggy gmtime_r ?)\n");
            ret = LDAP_OPERATIONS_ERROR;
            goto free_and_return;
        }
        strftime(timestr, GENERALIZED_TIME_LENGTH + 1,
                 "%Y%m%d%H%M%SZ", &utctime);
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "krbLastPwdChange", timestr);

        /* set Password Expiration date */
        if (!gmtime_r(&(data->expireTime), &utctime)) {
            slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                            "failed to convert expiration date\n");
            ret = LDAP_OPERATIONS_ERROR;
            goto free_and_return;
        }
        strftime(timestr, GENERALIZED_TIME_LENGTH + 1,
                 "%Y%m%d%H%M%SZ", &utctime);
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "krbPasswordExpiration", timestr);
    }

    if (lm) {
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "sambaLMPassword", lm);
    }

    if (nt) {
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "sambaNTPassword", nt);
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
            slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                            "failed to smprintf string!\n");
            ret = LDAP_OPERATIONS_ERROR;
            goto free_and_return;
        }
        slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                              "sambaPwdLastset", modtime);
    }
    /* let DS encode the password itself, this allows also other plugins to
     * intercept it to perform operations like synchronization with Active
     * Directory domains through the replication plugin */
    slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "userPassword", data->password);

    /* set password history */
    pwvals = ipapwd_setPasswordHistory(smods, data);
    if (pwvals) {
        slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                  "passwordHistory", pwvals);
    }

    /* FIXME:
     * instead of replace we should use a delete/add so that we are
     * completely sure nobody else modified the entry meanwhile and
     * fail if that's the case */

    /* commit changes */
    ret = ipapwd_apply_mods(data->dn, smods);

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "<= ipapwd_SetPassword: %d\n", ret);

free_and_return:
    if (lm) slapi_ch_free((void **)&lm);
    if (nt) slapi_ch_free((void **)&nt);
    if (modtime) slapi_ch_free((void **)&modtime);
    slapi_mods_free(&smods);
    ipapwd_free_slapi_value_array(&svals);
    ipapwd_free_slapi_value_array(&pwvals);

    return ret;
}

Slapi_Value **ipapwd_setPasswordHistory(Slapi_Mods *smods,
                                        struct ipapwd_data *data)
{
    Slapi_Value **pH = NULL;
    Slapi_Attr *passwordHistory = NULL;
    char timestr[GENERALIZED_TIME_LENGTH+1];
    char *histr, *old_pw;
    struct tm utctime;
    int ret, pc;

    old_pw = slapi_entry_attr_get_charptr(data->target, "userPassword");
    if (!old_pw) {
        /* no old password to store, just return */
        return NULL;
    }

    if (!gmtime_r(&(data->timeNow), &utctime)) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                    "failed to retrieve current date (buggy gmtime_r ?)\n");
        return NULL;
    }
    strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);

    histr = slapi_ch_smprintf("%s%s", timestr, old_pw);
    if (!histr) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "ipapwd_checkPassword: Out of Memory\n");
        return NULL;
    }

    /* retrieve current history */
    ret = slapi_entry_attr_find(data->target,
                                "passwordHistory", &passwordHistory);
    if (ret == 0) {
        int ret, hint, count, i, j;
        const char *pwstr;
        Slapi_Value *pw;

        hint = 0;
        count = 0;
        ret = slapi_attr_get_numvalues(passwordHistory, &count);
        /* if we have one */
        if (count > 0 && data->pwHistoryLen > 0) {
            pH = calloc(count + 2, sizeof(Slapi_Value *));
            if (!pH) {
                slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                "ipapwd_checkPassword: Out of Memory\n");
                free(histr);
                return NULL;
            }

            i = 0;
            hint = slapi_attr_first_value(passwordHistory, &pw);
            while (hint != -1) {
                pwstr = slapi_value_get_string(pw);
                /* if shorter than GENERALIZED_TIME_LENGTH, it
                 * is garbage, we never set timeless entries */
                if (pwstr &&
                    (strlen(pwstr) > GENERALIZED_TIME_LENGTH)) {
                    pH[i] = pw;
                    i++;
                }
                hint = slapi_attr_next_value(passwordHistory, hint, &pw);
            }

            qsort(pH, i, sizeof(Slapi_Value *), ipapwd_sv_pw_cmp);

            if (i >= data->pwHistoryLen) {
                /* need to rotate out the first entry */
                for (j = 0; j < data->pwHistoryLen; j++) {
                    pH[j] = pH[j + 1];
                }

                i = data->pwHistoryLen;
                pH[i] = NULL;
                i--;
            }

            pc = i;

            /* copy only interesting entries */
            for (i = 0; i < pc; i++) {
                pH[i] = slapi_value_dup(pH[i]);
                if (pH[i] == NULL) {
                    slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                    "ipapwd_checkPassword: Out of Memory\n");
                    while (i) {
                        i--;
                        slapi_value_free(&pH[i]);
                    }
                    free(pH);
                    free(histr);
                    return NULL;
                }
            }
        }
    }

    if (pH == NULL) {
        pH = calloc(2, sizeof(Slapi_Value *));
        if (!pH) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "ipapwd_checkPassword: Out of Memory\n");
            free(histr);
            return NULL;
        }
        pc = 0;
    }

    /* add new history value */
    pH[pc] = slapi_value_new_string(histr);

    free(histr);

    return pH;
}

/* Construct Mods pblock and perform the modify operation
 * Sets result of operation in SLAPI_PLUGIN_INTOP_RESULT
 */
int ipapwd_apply_mods(const char *dn, Slapi_Mods *mods)
{
    Slapi_PBlock *pb;
    int ret;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "=> ipapwd_apply_mods\n");

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
        slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                        "WARNING: modify error %d on entry '%s'\n", ret, dn);
    } else {

        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

        if (ret != LDAP_SUCCESS){
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "WARNING: modify error %d on entry '%s'\n",
                            ret, dn);
        } else {
            slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                            "<= ipapwd_apply_mods: Successful\n");
        }
    }

    slapi_pblock_destroy(pb);

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

