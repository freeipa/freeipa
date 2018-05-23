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
#include "../libotp/otp_config.h"
#include "ipa_asn1.h"

/*
 * Password Modify - LDAP Extended Operation.
 * RFC 3062
 *
 *
 * This plugin implements the "Password Modify - LDAP3"
 * extended operation for LDAP. The plugin function is called by
 * the server if an LDAP client request contains the OID:
 * "1.3.6.1.4.1.4203.1.11.1".
 *
 */

/* ber tags for the PasswdModifyRequestValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_USERID	0x80U
#define LDAP_EXTOP_PASSMOD_TAG_OLDPWD	0x81U
#define LDAP_EXTOP_PASSMOD_TAG_NEWPWD	0x82U

/* ber tags for the PasswdModifyResponseValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_GENPWD	0x80U

/* OID of the extended operation handled by this plug-in */
#define EXOP_PASSWD_OID	"1.3.6.1.4.1.4203.1.11.1"

/* OID to retrieve keytabs */
#define KEYTAB_SET_OID "2.16.840.1.113730.3.8.10.1"
#define KEYTAB_RET_OID "2.16.840.1.113730.3.8.10.2"



/* base DN of IPA realm tree */
const char *ipa_realm_tree;
/* dn of Kerberos realm entry */
const char *ipa_realm_dn;
const char *ipa_pwd_config_dn;
const char *ipa_etc_config_dn;
const char *ipa_changepw_principal_dn;

Slapi_PluginDesc ipapwd_plugin_desc = {
    IPAPWD_FEATURE_DESC,
    "FreeIPA project",
    "FreeIPA/1.0",
    IPAPWD_PLUGIN_DESC
};

void *ipapwd_plugin_id;
static int usetxn = 0;

extern struct otp_config *otp_config;

void *ipapwd_get_plugin_id(void)
{
    return ipapwd_plugin_id;
}

static void filter_keys(struct ipapwd_krbcfg *krbcfg,
                        struct ipapwd_keyset *kset)
{
    int i, j;

    for (i = 0; i < kset->num_keys; i++) {
        for (j = 0; j < krbcfg->num_supp_encsalts; j++) {
            if (kset->keys[i].key_data_type[0] ==
                    krbcfg->supp_encsalts[j].ks_enctype) {
                break;
            }
        }
        if (j == krbcfg->num_supp_encsalts) { /* not valid */

            /* free key */
            free(kset->keys[i].key_data_contents[0]);
            free(kset->keys[i].key_data_contents[1]);

            /* move all remaining keys up by one */
            kset->num_keys -= 1;

            for (j = i; j < kset->num_keys; j++) {
                kset->keys[j] = kset->keys[j + 1];
            }

            /* new key has been moved to this position, make sure
             * we do not skip it, by neutralizing next increment */
            i--;
        }
    }
}

static void filter_enctypes(struct ipapwd_krbcfg *krbcfg,
                            krb5_key_salt_tuple *kenctypes,
                            int *num_kenctypes)
{
    /* first filter for duplicates */
    for (int i = 0; i + 1 < *num_kenctypes; i++) {
        for (int j = i + 1; j < *num_kenctypes; j++) {
            if (kenctypes[i].ks_enctype == kenctypes[j].ks_enctype) {
                /* duplicate, filter out */
                for (int k = j; k + 1 < *num_kenctypes; k++) {
                    kenctypes[k].ks_enctype = kenctypes[k + 1].ks_enctype;
                    kenctypes[k].ks_salttype = kenctypes[k + 1].ks_salttype;
                }
                (*num_kenctypes)--;
                j--;
            }
        }
    }

    /* then filter for supported */
    for (int i = 0; i < *num_kenctypes; i++) {
        int j;

        /* Check if supported */
        for (j = 0; j < krbcfg->num_supp_encsalts; j++) {
            if (kenctypes[i].ks_enctype ==
                                    krbcfg->supp_encsalts[j].ks_enctype) {
                break;
            }
        }
        if (j == krbcfg->num_supp_encsalts) {
            /* Unsupported, filter out */
            for (int k = i; k + 1 < *num_kenctypes; k++) {
                kenctypes[k].ks_enctype = kenctypes[k + 1].ks_enctype;
                kenctypes[k].ks_salttype = kenctypes[k + 1].ks_salttype;
            }
            (*num_kenctypes)--;
            i--;
        }
    }
}

static int ipapwd_to_ldap_pwpolicy_error(int ipapwderr)
{
    switch (ipapwderr) {
    case IPAPWD_POLICY_ACCOUNT_EXPIRED:
        return LDAP_PWPOLICY_PWDMODNOTALLOWED;
    case IPAPWD_POLICY_PWD_TOO_YOUNG:
        return LDAP_PWPOLICY_PWDTOOYOUNG;
    case IPAPWD_POLICY_PWD_TOO_SHORT:
        return LDAP_PWPOLICY_PWDTOOSHORT;
    case IPAPWD_POLICY_PWD_IN_HISTORY:
        return LDAP_PWPOLICY_PWDINHISTORY;
    case IPAPWD_POLICY_PWD_COMPLEXITY:
        return LDAP_PWPOLICY_INVALIDPWDSYNTAX;
    }
    /* in case of unhandled error return access denied */
    return LDAP_PWPOLICY_PWDMODNOTALLOWED;
}


static int ipapwd_chpwop(Slapi_PBlock *pb, struct ipapwd_krbcfg *krbcfg)
{
	char 		*bindDN = NULL;
	char		*authmethod = NULL;
	char		*dn = NULL;
	char		*oldPasswd = NULL;
	char		*newPasswd = NULL;
	char		*errMesg = NULL;
	int             ret=0, rc=0, is_root=0;
	ber_tag_t	tag=0;
	ber_len_t	len=-1;
	struct berval	*extop_value = NULL;
	BerElement	*ber = NULL;
	Slapi_Entry *targetEntry=NULL;
	Slapi_Value *objectclass=NULL;
	char *attrlist[] = {"*", "passwordHistory", NULL };
	struct ipapwd_data pwdata;
	int is_krb, is_smb, is_ipant;
	char *principal = NULL;
	Slapi_PBlock *chpwop_pb = NULL;
	Slapi_DN     *target_sdn = NULL;
	const char   *target_dn = NULL;

	/* Get the ber value of the extended operation */
	slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &extop_value);

    if (extop_value == NULL ||
        (extop_value->bv_len == 0 || extop_value->bv_val == NULL)) {
        errMesg = "PasswdModify Request empty.\n";
        rc = LDAP_UNWILLING_TO_PERFORM;
        goto free_and_return;
    }

	if ((ber = ber_init(extop_value)) == NULL)
	{
		errMesg = "PasswdModify Request decode failed.\n";
		rc = LDAP_PROTOCOL_ERROR;
		goto free_and_return;
	}

	/* Format of request to parse
	 *
	 * PasswdModifyRequestValue ::= SEQUENCE {
	 * userIdentity    [0]  OCTET STRING OPTIONAL
	 * oldPasswd       [1]  OCTET STRING OPTIONAL
	 * newPasswd       [2]  OCTET STRING OPTIONAL }
	 *
	 * The request value field is optional. If it is
	 * provided, at least one field must be filled in.
	 */

	/* ber parse code */
	if ( ber_scanf( ber, "{") == LBER_ERROR )
	{
		/* The request field wasn't provided.  We'll
		 * now try to determine the userid and verify
		 * knowledge of the old password via other
		 * means.
		 */
		goto parse_req_done;
	} else {
		tag = ber_peek_tag( ber, &len);
	}

	/* identify userID field by tags */
	if (tag == LDAP_EXTOP_PASSMOD_TAG_USERID )
	{
		if (ber_scanf(ber, "a", &dn) == LBER_ERROR) {
			slapi_ch_free_string(&dn);
			errMesg = "ber_scanf failed at userID parse.\n";
			LOG_FATAL("%s", errMesg);
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}

		tag = ber_peek_tag(ber, &len);
	}

	/* identify oldPasswd field by tags */
	if (tag == LDAP_EXTOP_PASSMOD_TAG_OLDPWD )
	{
		if (ber_scanf(ber, "a", &oldPasswd) == LBER_ERROR) {
			errMesg = "ber_scanf failed at oldPasswd parse.\n";
			LOG_FATAL("%s", errMesg);
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}
		tag = ber_peek_tag(ber, &len);
	}

	/* identify newPasswd field by tags */
	if (tag == LDAP_EXTOP_PASSMOD_TAG_NEWPWD )
	{
		if (ber_scanf(ber, "a", &newPasswd) == LBER_ERROR) {
			errMesg = "ber_scanf failed at newPasswd parse.\n";
			LOG_FATAL("%s", errMesg);
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}
	}

parse_req_done:
	/* Uncomment for debugging, otherwise we don't want to leak the
	 * password values into the log... */
	/* LDAPDebug( LDAP_DEBUG_ARGS, "passwd: dn (%s), oldPasswd (%s),
	 * 		newPasswd (%s)\n", dn, oldPasswd, newPasswd); */


	 /* Get Bind DN */
	 slapi_pblock_get(pb, SLAPI_CONN_DN, &bindDN);

	 /* If the connection is bound anonymously, we must refuse
	  * to process this operation. */
	if (bindDN == NULL || *bindDN == '\0') {
	 	/* Refuse the operation because they're bound anonymously */
		errMesg = "Anonymous Binds are not allowed.\n";
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto free_and_return;
	}

	/* A new password was not supplied in the request, and we do not support
	 * password generation yet.
	 */
	if (newPasswd == NULL || *newPasswd == '\0') {
		errMesg = "Password generation not implemented.\n";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto free_and_return;
	}

	if (oldPasswd == NULL || *oldPasswd == '\0') {
		/* If user is authenticated, they already gave their password during
		the bind operation (or used sasl or client cert auth or OS creds) */
		slapi_pblock_get(pb, SLAPI_CONN_AUTHMETHOD, &authmethod);
		if (!authmethod || !strcmp(authmethod, SLAPD_AUTH_NONE)) {
			errMesg = "User must be authenticated to the directory server.\n";
			rc = LDAP_INSUFFICIENT_ACCESS;
			goto free_and_return;
		}
	}

	/* Determine the target DN for this operation */
	slapi_pblock_get(pb, SLAPI_TARGET_SDN, &target_sdn);
	if (target_sdn != NULL) {
		/* If there is a TARGET_DN we are consuming it */
		slapi_pblock_set(pb, SLAPI_TARGET_SDN, NULL);
		target_dn = slapi_sdn_get_ndn(target_sdn);
	}
	if (target_dn == NULL || *target_dn == '\0') {
		/* Did they give us a DN ? */
		if (dn == NULL || *dn == '\0') {
			/* Get the DN from the bind identity on this connection */
			dn = slapi_ch_strdup(bindDN);
			LOG_TRACE("Missing userIdentity in request, "
				"using the bind DN instead.\n");
		}
		LOG_TRACE("extop dn %s (from ber)\n", dn ? dn : "<empty>");
	} else {
		/* At this point if SLAPI_TARGET_SDN was set that means
		 * that a SLAPI_PLUGIN_PRE_EXTOP_FN plugin sets it
		 * So take this one rather that the raw one that is in the ber
		 */
		LOG_TRACE("extop dn %s was translated to %s\n", dn ? dn : "<empty>", target_dn);
		slapi_ch_free_string(&dn);
		dn = slapi_ch_strdup(target_dn);
	}
	slapi_sdn_free(&target_sdn);

	 if (slapi_pblock_set( pb, SLAPI_ORIGINAL_TARGET, dn )) {
		LOG_FATAL("slapi_pblock_set failed!\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	 }

	if (usetxn) {
                Slapi_DN *sdn = slapi_sdn_new_dn_byref(dn);
                Slapi_Backend *be = slapi_be_select(sdn);
                slapi_sdn_free(&sdn);
                if (be) {
			chpwop_pb = slapi_pblock_new();
			if (slapi_pblock_set(chpwop_pb, SLAPI_BACKEND, be)) {
				LOG_FATAL("slapi_pblock_set failed!\n");
				rc = LDAP_OPERATIONS_ERROR;
				goto free_and_return;
			}
			rc = slapi_back_transaction_begin(chpwop_pb);
			if (rc) {
				LOG_FATAL("failed to start transaction\n");
			}
		} else {
			LOG_FATAL("failed to get be backend from %s\n", dn);
		}
	}

	 /* Now we have the DN, look for the entry */
	 ret = ipapwd_getEntry(dn, &targetEntry, attrlist);
	 /* If we can't find the entry, then that's an error */
	 if (ret) {
	 	/* Couldn't find the entry, fail */
		errMesg = "No such Entry exists.\n" ;
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	 }

    if (dn) {
        Slapi_DN *bind_sdn;

        /* if the user changing the password is self, we must request the
         * old password and verify it matches the current one before
         * proceeding with the password change */
        bind_sdn = slapi_sdn_new_dn_byval(bindDN);
        target_sdn = slapi_sdn_new_dn_byval(dn);

        rc = (!bind_sdn || !target_sdn) ? LDAP_OPERATIONS_ERROR : 0;

        /* this one will normalize and compare, so difference in case will be
         * correctly handled */
        ret = slapi_sdn_compare(bind_sdn, target_sdn);

        slapi_sdn_free(&bind_sdn);
        slapi_sdn_free(&target_sdn);

        /* rc should always be 0 (else slapi_sdn_new_dn_byval should have sigsev)
         * but if we end in rc==LDAP_OPERATIONS_ERROR be sure to stop here
         * because ret is not significant */
        if (rc != 0) {
            LOG_OOM();
            goto free_and_return;
        }

        if (ret == 0) {
            Slapi_Value *cpw[2] = { NULL, NULL };
            Slapi_Value *pw;
            char *cur_pw;

            if (oldPasswd == NULL || *oldPasswd == '\0') {
                LOG_FATAL("Old password was not provided!\n");
                rc = LDAP_INVALID_CREDENTIALS;
                goto free_and_return;
            }

            /* if the user is changing his own password we need to check that
             * oldPasswd matches the current password */
            cur_pw = slapi_entry_attr_get_charptr(targetEntry,
                                                  "userPassword");
            if (!cur_pw) {
                LOG_FATAL("User has no current password?\n");
                rc = LDAP_UNWILLING_TO_PERFORM;
                goto free_and_return;
            }

            cpw[0] = slapi_value_new_string(cur_pw);
            pw = slapi_value_new_string(oldPasswd);
            if (!cpw[0] || !pw) {
                LOG_OOM();
                rc = LDAP_OPERATIONS_ERROR;
                goto free_and_return;
            }

            ret = slapi_pw_find_sv(cpw, pw);

            slapi_value_free(&cpw[0]);
            slapi_value_free(&pw);

            if (ret != 0) {
                LOG_TRACE("Invalid password!\n");
                rc = LDAP_INVALID_CREDENTIALS;
                goto free_and_return;
            }
        }
    } else {
        LOG_TRACE("Undefined target DN!\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

	 rc = ipapwd_entry_checks(pb, targetEntry,
				&is_root, &is_krb, &is_smb, &is_ipant,
				SLAPI_USERPWD_ATTR, SLAPI_ACL_WRITE);
	 if (rc) {
		goto free_and_return;
	 }

	/* When setting the password for host principals do not set kerberos
	 * keys */
	objectclass = slapi_value_new_string("ipaHost");
	if ((slapi_entry_attr_has_syntax_value(targetEntry, SLAPI_ATTR_OBJECTCLASS, objectclass)) == 1) {
		is_krb = 0;
	}
	slapi_value_free(&objectclass);

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

	/* In order to perform the access control check, we need to select a
	 * backend (even though we don't actually need it otherwise).
	 */
	{
		Slapi_Backend *be = NULL;

		be = slapi_be_select(slapi_entry_get_sdn(targetEntry));
		if (NULL == be) {
			errMesg = "Failed to find backend for target entry";
			rc = LDAP_OPERATIONS_ERROR;
			goto free_and_return;
		}
		if (slapi_pblock_set(pb, SLAPI_BACKEND, be)) {
			LOG_FATAL("slapi_pblock_set failed!\n");
			rc = LDAP_OPERATIONS_ERROR;
			goto free_and_return;
		}
	}

	ret = slapi_access_allowed( pb, targetEntry, "krbPrincipalKey", NULL, SLAPI_ACL_WRITE );
	if ( ret != LDAP_SUCCESS ) {
		errMesg = "Insufficient access rights\n";
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto free_and_return;
	}

	/* Now we have the entry which we want to modify
 	 * They gave us a password (old), check it against the target entry
	 * Is the old password valid ?
	 */
	if (oldPasswd && *oldPasswd) {
		/* If user is authenticated, they already gave their password
		 * during the bind operation (or used sasl or client cert auth
		 * or OS creds) */
		LOG_TRACE("oldPasswd provided, but we will ignore it");
	}

	memset(&pwdata, 0, sizeof(pwdata));
	pwdata.target = targetEntry;
	pwdata.dn = dn;
	pwdata.password = newPasswd;
	pwdata.timeNow = time(NULL);
	pwdata.changetype = IPA_CHANGETYPE_NORMAL;

    /*
     *  (technically strcasecmp to compare DNs is not absolutely correct,
     *  but it should work for the cases we care about here)
     */

	/* determine type of password change */
    /* special cases */
    if ((strcasecmp(dn, bindDN) != 0) &&
        (strcasecmp(ipa_changepw_principal_dn, bindDN) != 0)) {
        int i;

        pwdata.changetype = IPA_CHANGETYPE_ADMIN;

        for (i = 0; i < krbcfg->num_passsync_mgrs; i++) {
            if (strcasecmp(krbcfg->passsync_mgrs[i], bindDN) == 0) {
                pwdata.changetype = IPA_CHANGETYPE_DSMGR;
                break;
            }
        }
    }

	/* check the policy */
	ret = ipapwd_CheckPolicy(&pwdata);
	if (ret) {
		errMesg = ipapwd_error2string(ret);
		if (ret == IPAPWD_POLICY_ERROR) {
			errMesg = "Internal error";
			rc = ret;
		} else {
			ret = ipapwd_to_ldap_pwpolicy_error(ret);
			slapi_pwpolicy_make_response_control(pb, -1, -1, ret);
			rc = LDAP_CONSTRAINT_VIOLATION;
		}
		goto free_and_return;
	}

	/* Now we're ready to set the kerberos key material */
	ret = ipapwd_SetPassword(krbcfg, &pwdata, is_krb);
	if (ret != LDAP_SUCCESS) {
		/* Failed to modify the password,
		 * e.g. because insufficient access allowed */
		errMesg = "Failed to update password";
		if (ret > 0) {
			rc = ret;
		} else {
			rc = LDAP_OPERATIONS_ERROR;
		}
		goto free_and_return;
	}

	LOG_TRACE("<= result: %d\n", rc);

    if (pwdata.changetype == IPA_CHANGETYPE_NORMAL) {
        principal = slapi_entry_attr_get_charptr(pwdata.target,
                                                 "krbPrincipalName");
    } else {
        principal = slapi_ch_smprintf("root/admin@%s", krbcfg->realm);
    }
    if (principal)
        ipapwd_set_extradata(pwdata.dn, principal, pwdata.timeNow);

	/* Free anything that we allocated above */
free_and_return:
	if (usetxn && chpwop_pb) {
		if (rc) { /* fails */
			slapi_back_transaction_abort(chpwop_pb);
		} else {
			slapi_back_transaction_commit(chpwop_pb);
		}
		slapi_pblock_destroy(chpwop_pb);
	}
	slapi_ch_free_string(&oldPasswd);
	slapi_ch_free_string(&newPasswd);
	/* Either this is the same pointer that we allocated and set above,
	 * or whoever used it should have freed it and allocated a new
	 * value that we need to free here */
    ret = slapi_pblock_get(pb, SLAPI_ORIGINAL_TARGET, &dn);
    if (ret) {
        LOG_TRACE("Failed to get SLAPI_ORIGINAL_TARGET\n");
    }
	slapi_ch_free_string(&dn);
    ret = slapi_pblock_set(pb, SLAPI_ORIGINAL_TARGET, NULL);
    if (ret) {
        LOG_TRACE("Failed to clear SLAPI_ORIGINAL_TARGET\n");
    }
	slapi_ch_free_string(&authmethod);
    slapi_ch_free_string(&principal);

	if (targetEntry) slapi_entry_free(targetEntry);
	if (ber) ber_free(ber, 1);

	LOG("%s", errMesg ? errMesg : "success");
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;

}

static char *check_service_name(krb5_context krbctx, char *svc)
{
    krb5_principal krbname = NULL;
    krb5_error_code krberr;
    char *name = NULL;

    krberr = krb5_parse_name(krbctx, svc, &krbname);
    if (krberr) {
        LOG_FATAL("krb5_parse_name failed\n");
    } else {
        /* invert so that we get the canonical form (add REALM if not present
         * for example) */
        krberr = krb5_unparse_name(krbctx, krbname, &name);
        if (krberr) {
            LOG_FATAL("krb5_unparse_name failed\n");
        }
    }

    krb5_free_principal(krbctx, krbname);
    return name;
}

static Slapi_Backend *get_realm_backend(void)
{
    Slapi_Backend *be;
    Slapi_DN *sdn;

    sdn = slapi_sdn_new_dn_byval(ipa_realm_dn);
    if (!sdn) return NULL;
    be = slapi_be_select(sdn);
    slapi_sdn_free(&sdn);
    return be;
}

static const char *get_realm_base_dn(void)
{
    const Slapi_DN *bsdn;
    Slapi_Backend *be;

    /* Find ancestor base DN */
    be = get_realm_backend();
    if (!be) return NULL;

    bsdn = slapi_be_getsuffix(be, 0);
    if (!bsdn) return NULL;

    return slapi_sdn_get_dn(bsdn);
}

static Slapi_Entry *get_entry_by_principal(const char *principal)
{
    const char *bdn;
    char *filter = NULL;
    Slapi_PBlock *pb = NULL;
    char *attrlist[] = { "krbPrincipalKey", "krbLastPwdChange",
                         "userPassword", "krbPrincipalName",
                         "krbCanonicalName",
                         "enrolledBy", NULL };
    Slapi_Entry **es = NULL;
    int res, ret, i;
    Slapi_Entry *entry = NULL;

    /* Find ancestor base DN */
    bdn = get_realm_base_dn();
    if (!bdn) {
        LOG_TRACE("Search for Base DN failed\n");
        goto free_and_return;
    }

    filter = slapi_ch_smprintf("(krbPrincipalName=%s)", principal);
    if (!filter) {
        LOG_TRACE("Building filter failed\n");
        goto free_and_return;
    }

    pb = slapi_pblock_new();
    slapi_search_internal_set_pb(pb, bdn, LDAP_SCOPE_SUBTREE, filter,
                                 attrlist, 0,
                                 NULL, /* Controls */ NULL, /* UniqueID */
                                 ipapwd_plugin_id, 0); /* Flags */

    /* do search the tree */
    ret = slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &res);
    if (ret == -1 || res != LDAP_SUCCESS) {
        LOG_TRACE("Search for Principal failed, err (%d)\n", res ? res : ret);
        goto free_and_return;
    }

    /* get entries */
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
    if (!es) {
        LOG_TRACE("No entries ?!");
        goto free_and_return;
    }

    /* count entries */
    for (i = 0; es[i]; i++) /* count */ ;

    /* if there is none or more than one, freak out */
    if (i != 1) {
        LOG_TRACE("Too many entries, or entry no found (%d)", i);
        goto free_and_return;
    }
    entry = slapi_entry_dup(es[0]);

free_and_return:
    if (pb) {
        slapi_free_search_results_internal(pb);
        slapi_pblock_destroy(pb);
    }
    if (filter) slapi_ch_free_string(&filter);
    return entry;
}

static bool is_allowed_to_access_attr(Slapi_PBlock *pb, char *bindDN,
                                      Slapi_Entry *targetEntry,
                                      const char *attrname,
                                      struct berval *value,
                                      int access)
{
    Slapi_Backend *be;
    int is_root = 0;
    int ret;

    is_root = slapi_dn_isroot(bindDN);
    if (slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, &is_root)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
        return false;
    }

    /* In order to perform the access control check, we need to select a
     * backend (even though we don't actually need it otherwise).
     */
    be = get_realm_backend();
    if (!be) {
        LOG_FATAL("Could not fetch REALM backend!");
        return false;
    }
    if (slapi_pblock_set(pb, SLAPI_BACKEND, be)) {
        LOG_FATAL("slapi_pblock_set failed!\n");
        return false;
    }

    ret = slapi_access_allowed(pb, targetEntry, discard_const(attrname),
                               value, access);
    if (ret != LDAP_SUCCESS) {
        LOG_FATAL("slapi_access_allowed does not allow %s to %s%s!\n",
                  (access == SLAPI_ACL_WRITE)?"WRITE":"READ",
                  attrname, value?"(value specified)":"");
        return false;
    }

    return true;
}

static int set_krbLastPwdChange(Slapi_Mods *smods, time_t now)
{
    char tstr[GENERALIZED_TIME_LENGTH + 1];
    struct tm utctime;

    /* change Last Password Change field with the current date */
    if (!gmtime_r(&now, &utctime)) {
        LOG_FATAL("failed to retrieve current date (buggy gmtime_r ?)\n");
        return LDAP_OPERATIONS_ERROR;
    }
    strftime(tstr, GENERALIZED_TIME_LENGTH + 1, "%Y%m%d%H%M%SZ", &utctime);
    slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastPwdChange", tstr);
    return LDAP_SUCCESS;
}

static void remove_user_password(Slapi_Mods *smods,
                                 Slapi_Entry *targetEntry, char *bindDN)
{
    Slapi_Value *objectclass = NULL;
    char *krbLastPwdChange = NULL;
    char *enrolledBy = NULL;
    char *pw = NULL;
    int ret;

    objectclass = slapi_value_new_string("ipaHost");
    pw = slapi_entry_attr_get_charptr(targetEntry, "userPassword");
    ret = slapi_entry_attr_has_syntax_value(targetEntry,
                                            SLAPI_ATTR_OBJECTCLASS,
                                            objectclass);
    if (ret == 1) {
        krbLastPwdChange = slapi_entry_attr_get_charptr(targetEntry,
                                                        "krbLastPwdChange");
        enrolledBy = slapi_entry_attr_get_charptr(targetEntry, "enrolledBy");
        if (!enrolledBy) {
            slapi_mods_add_string(smods, LDAP_MOD_ADD, "enrolledBy", bindDN);
        }
        if ((NULL != pw) && (NULL == krbLastPwdChange)) {
            slapi_mods_add_mod_values(smods, LDAP_MOD_DELETE,
                                      "userPassword", NULL);
            LOG_TRACE("Removing userPassword from host entry\n");
        }
    }
    if (krbLastPwdChange) slapi_ch_free_string(&krbLastPwdChange);
    if (enrolledBy) slapi_ch_free_string(&enrolledBy);
    if (pw) slapi_ch_free_string(&pw);
    if (objectclass) slapi_value_free(&objectclass);
}

static int store_new_keys(Slapi_Entry *target, char *svcname, char *bind_dn,
                          Slapi_Value **svals, char **_err_msg)
{
    int rc = LDAP_OPERATIONS_ERROR;
    char *err_msg = NULL;
    Slapi_Mods *smods = NULL;
    time_t time_now = time(NULL);

    smods = slapi_mods_new();
    slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                              "krbPrincipalKey", svals);
    rc = set_krbLastPwdChange(smods, time_now);
    if (rc) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_FATAL("Failed to set krbLastPwdChange");
        err_msg = "Internal error while storing keytab data\n";
        goto done;
    }

    /* If we are creating a keytab for a host service, attempt to remove
     * the userPassword attribute if it exists
     */
    remove_user_password(smods, target, bind_dn);

    /* commit changes */
    rc = ipapwd_apply_mods(slapi_entry_get_dn_const(target), smods);
    if (rc != LDAP_SUCCESS) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_FATAL("Failed to apply mods");
        err_msg = "Internal error while saving keys\n";
        goto done;
    }

    rc = ipapwd_set_extradata(slapi_entry_get_dn_const(target),
                              svcname, time_now);
    if (rc != LDAP_SUCCESS) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_FATAL("Failed to set extradata");
        err_msg = "Internal error while saving keytab extradata\n";
        goto done;
    }

    rc = LDAP_SUCCESS;

done:
    if (smods) slapi_mods_free(&smods);
    *_err_msg = err_msg;
    return rc;
}

/* Format of request to parse
 *
 * KeytabSetRequest ::= SEQUENCE {
 *     serviceIdentity OCTET STRING
 *     keys            SEQUENCE OF KrbKey,
 *     ...
 * }
 *
 * KrbKey ::= SEQUENCE {
 *     key       [0] EncryptionKey,
 *     salt      [1] KrbSalt OPTIONAL,
 *     s2kparams [2] OCTET STRING OPTIONAL,
 *     ...
 * }
 *
 * EncryptionKey ::= SEQUENCE {
 *     keytype   [0] Int32,
 *     keyvalue  [1] OCTET STRING
 * }
 *
 * KrbSalt ::= SEQUENCE {
 *     type      [0] Int32,
 *     salt      [1] OCTET STRING OPTIONAL
 * }
 */

#define SKREQ_SALT_TAG (LBER_CLASS_CONTEXT | LBER_CONSTRUCTED | 1)
#define SKREQ_SALTVALUE_TAG (LBER_CLASS_CONTEXT | LBER_CONSTRUCTED | 1)
#define SKREQ_S2KPARAMS_TAG (LBER_CLASS_CONTEXT | LBER_CONSTRUCTED | 2)

/* The returned krb5_key_data kvno is set to 0 for all keys, the caller,
 * is responsible for fixing it up if necessary before using the data */
static int decode_setkeytab_request(krb5_context krbctx,
                                    krb5_keyblock *kmkey, int mkvno,
                                    struct berval *extop, char **_svcname,
                                    struct ipapwd_keyset **_kset,
                                    char **_err_msg) {
    int rc = LDAP_OPERATIONS_ERROR;
    char *err_msg = NULL;
    BerElement *ber = NULL;
    char *svcname = NULL;
    ber_tag_t rtag;
    ber_len_t tlen;
    struct ipapwd_keyset *kset = NULL;

    ber = ber_init(extop);
    if (ber == NULL) {
        rc = LDAP_PROTOCOL_ERROR;
        err_msg = "KeytabSet Request decode failed.\n";
        goto done;
    }

    /* ber parse code */
    rtag = ber_scanf(ber, "{a{", &svcname);
    if (rtag == LBER_ERROR) {
        rc = LDAP_PROTOCOL_ERROR;
        LOG_FATAL("ber_scanf failed to fecth service name\n");
        err_msg = "Invalid payload.\n";
        goto done;
    }

    kset = calloc(1, sizeof(struct ipapwd_keyset));
    if (!kset) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_OOM();
        err_msg = "Internal error.\n";
        goto done;
    }

    /* this encoding assumes all keys have the same kvno */
    /* major-vno = 1 and minor-vno = 1 */
    kset->major_vno = 1;
    kset->minor_vno = 1;
    kset->mkvno = mkvno;

    rtag = ber_peek_tag(ber, &tlen);
    for (int i = 0; rtag == LBER_SEQUENCE; i++) {
        krb5_key_data *newset;
        ber_tag_t ctag;
        ber_int_t type;
        krb5_data plain;
        krb5_enc_data cipher;
        struct berval tval;
        krb5_octet *kdata;
        krb5_int16 le_len;
        size_t klen;

        newset = realloc(kset->keys, sizeof(krb5_key_data) * (i + 1));
        if (!newset) {
            rc = LDAP_OPERATIONS_ERROR;
            LOG_OOM();
            err_msg = "Internal error.\n";
            goto done;
        }
        kset->keys = newset;
        kset->num_keys = i + 1;

        memset(&kset->keys[i], 0, sizeof(krb5_key_data));
        kset->keys[i].key_data_ver = 1;
        kset->keys[i].key_data_kvno = 0;

        /* EncryptionKey */
        rtag = ber_scanf(ber, "{t[{t[i]t[o]}]",
                         &ctag, &ctag, &type, &ctag, &tval);
        if (rtag == LBER_ERROR) {
            rc = LDAP_PROTOCOL_ERROR;
            LOG_FATAL("ber_scanf failed fetching key\n");
            err_msg = "Invalid payload.\n";
            goto done;
        }

        kset->keys[i].key_data_type[0] = type;
        plain.length = tval.bv_len;
        plain.data = tval.bv_val;

        rc = krb5_c_encrypt_length(krbctx, kmkey->enctype,
                                   plain.length, &klen);
        if (rc) {
            ber_memfree(tval.bv_val);
            rc = LDAP_OPERATIONS_ERROR;
            LOG_FATAL("krb5_c_encrypt_length failed!\n");
            err_msg = "Internal error.\n";
            goto done;
        }
        kdata = malloc(2 + klen);
        if (!kdata) {
            ber_memfree(tval.bv_val);
            rc = LDAP_OPERATIONS_ERROR;
            LOG_OOM();
            err_msg = "Internal error.\n";
            goto done;
        }
        le_len = htole16(plain.length);
        memcpy(kdata, &le_len, 2);

        kset->keys[i].key_data_length[0] = 2 + klen;
        kset->keys[i].key_data_contents[0] = kdata;

        cipher.ciphertext.length = klen;
        cipher.ciphertext.data = (char *)kdata + 2;

        rc = krb5_c_encrypt(krbctx, kmkey, 0, 0, &plain, &cipher);
        if (rc) {
            ber_memfree(tval.bv_val);
            rc = LDAP_OPERATIONS_ERROR;
            LOG_FATAL("krb5_c_encrypt failed!\n");
            err_msg = "Internal error.\n";
            goto done;
        }

        ber_memfree(tval.bv_val);

        rtag = ber_peek_tag(ber, &tlen);
        /* KrbSalt */
        if (rtag == SKREQ_SALT_TAG) {
            rtag = ber_scanf(ber, "t[{t[i]", &ctag, &ctag, &type);
            if (rtag == LBER_ERROR) {
                rc = LDAP_PROTOCOL_ERROR;
                LOG_FATAL("ber_scanf failed fetching salt\n");
                err_msg = "Invalid payload.\n";
                goto done;
            }

            kset->keys[i].key_data_ver = 2; /* we have a salt */
            kset->keys[i].key_data_type[1] = type;

            rtag = ber_peek_tag(ber, &tlen);
            if (rtag == SKREQ_SALTVALUE_TAG) {
                rtag = ber_scanf(ber, "t[o]}]", &ctag, &tval);
                if (rtag == LBER_ERROR) {
                    rc = LDAP_PROTOCOL_ERROR;
                    LOG_FATAL("ber_scanf failed fetching salt value\n");
                    err_msg = "Invalid payload.\n";
                    goto done;
                }

                kset->keys[i].key_data_length[1] = tval.bv_len;
                kset->keys[i].key_data_contents[1] = malloc(tval.bv_len);
                if (!kset->keys[i].key_data_contents[1]) {
                    ber_memfree(tval.bv_val);
                    rc = LDAP_OPERATIONS_ERROR;
                    LOG_OOM();
                    err_msg = "Internal error.\n";
                    goto done;
                }
                memcpy(kset->keys[i].key_data_contents[1],
                       tval.bv_val, tval.bv_len);
                ber_memfree(tval.bv_val);

                rtag = ber_peek_tag(ber, &tlen);
            }
        }

        /* FIXME: s2kparams - NOT implemented yet */
        if (rtag == SKREQ_S2KPARAMS_TAG) {
            rtag = ber_scanf(ber, "t[x]}", &ctag);
        } else {
            rtag = ber_scanf(ber, "}", &ctag);
        }
        if (rtag == LBER_ERROR) {
            rc = LDAP_PROTOCOL_ERROR;
            LOG_FATAL("ber_scanf failed to read key data termination\n");
            err_msg = "Invalid payload.\n";
            goto done;
        }

        rtag = ber_peek_tag(ber, &tlen);
    }

    rc = LDAP_SUCCESS;

done:
    if (rc != LDAP_SUCCESS) {
        if (kset) ipapwd_keyset_free(&kset);
        free(svcname);
        *_err_msg = err_msg;
    } else {
        *_svcname = svcname;
        *_kset = kset;
    }
    if (ber) ber_free(ber, 1);
    return rc;
}

/* Format of response
 *
 * KeytabGetRequest ::= SEQUENCE {
 * 	new_kvno	Int32
 * 	SEQUENCE OF	KeyTypes
 * }
 *
 * * List of accepted enctypes *
 * KeyTypes ::= SEQUENCE {
 * 	enctype		Int32
 * }
 */

static int encode_setkeytab_reply(struct ipapwd_keyset *kset,
                                  struct berval **_bvp)
{
    int rc = LDAP_OPERATIONS_ERROR;
    struct berval *bvp = NULL;
    BerElement *ber = NULL;

    ber = ber_alloc();
    if (!ber) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_OOM();
        goto done;
    }

    rc = ber_printf(ber, "{i{", (ber_int_t)kset->keys[0].key_data_kvno);
    if (rc == -1) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_FATAL("Failed to ber_printf the kvno");
        goto done;
    }

    for (int i = 0; i < kset->num_keys; i++) {
        rc = ber_printf(ber, "{i}", (ber_int_t)kset->keys[i].key_data_type[0]);
        if (rc == -1) {
            rc = LDAP_OPERATIONS_ERROR;
            LOG_FATAL("Failed to ber_printf the enctype");
            goto done;
        }
    }
    rc = ber_printf(ber, "}}");
    if (rc == -1) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_FATAL("Failed to ber_printf the termination");
        goto done;
    }

    rc = ber_flatten(ber, &bvp);
    if (rc == -1) {
        rc = LDAP_OPERATIONS_ERROR;
        LOG_FATAL("Failed to ber_flatten the buffer");
        goto done;
    }

    rc = LDAP_SUCCESS;

done:
    if (rc != LDAP_SUCCESS) {
        if (bvp) ber_bvfree(bvp);
    } else {
        *_bvp = bvp;
    }
    if (ber) ber_free(ber, 1);
    return rc;
}

/* Password Modify Extended operation plugin function */
static int ipapwd_setkeytab(Slapi_PBlock *pb, struct ipapwd_krbcfg *krbcfg)
{
	char *bindDN = NULL;
	char *serviceName = NULL;
	char *errMesg = NULL;
	struct berval *extop_value = NULL;
	Slapi_Entry *targetEntry=NULL;
	struct berval *bval = NULL;
	Slapi_Value **svals = NULL;
	krb5_context krbctx = NULL;
	krb5_error_code krberr;
	struct ipapwd_keyset *kset = NULL;
    int rc;
    int kvno;
    char *svcname;
    bool allowed_access = false;
    struct berval *bvp = NULL;
    LDAPControl new_ctrl;

	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		LOG_FATAL("krb5_init_context failed\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

	/* Get Bind DN */
	slapi_pblock_get(pb, SLAPI_CONN_DN, &bindDN);

	 /* If the connection is bound anonymously, we must refuse to process
	 * this operation. */
	if (bindDN == NULL || *bindDN == '\0') {
	 	/* Refuse the operation because they're bound anonymously */
		errMesg = "Anonymous Binds are not allowed.\n";
		rc = LDAP_INSUFFICIENT_ACCESS;
		goto free_and_return;
	}

	/* Get the ber value of the extended operation */
	slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &extop_value);

    rc = decode_setkeytab_request(krbctx, krbcfg->kmkey, krbcfg->mkvno,
                                  extop_value, &serviceName, &kset, &errMesg);
    if (rc) {
        goto free_and_return;
    }

    /* make sure it is a valid name */
    svcname = check_service_name(krbctx, serviceName);
    if (!svcname) {
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }
    slapi_ch_free_string(&serviceName);
    serviceName = svcname;

	/* check entry before doing any other decoding */

	/* get Entry by krbPrincipalName */
    targetEntry = get_entry_by_principal(serviceName);
    if (!targetEntry) {
        errMesg = "PrincipalName not found.\n";
        rc = LDAP_NO_SUCH_OBJECT;
        goto free_and_return;
    }

    /* Accesseck strategy:
     * If the user has WRITE access, a new keytab can be set on the entry.
     * If not, then we fail immediately with insufficient access. This
     * means that we don't leak any useful information to the client such
     * as current password wrong, etc.
     */
    allowed_access = is_allowed_to_access_attr(pb, bindDN, targetEntry,
                                               "krbPrincipalKey", NULL,
                                               SLAPI_ACL_WRITE);
    if (!allowed_access) {
        LOG_FATAL("Access not allowed to set keytab on [%s]!\n",
                  serviceName);
        errMesg = "Insufficient access rights\n";
        rc = LDAP_INSUFFICIENT_ACCESS;
        goto free_and_return;
    }

    /* get next kvno for entry (will be 1 if this is new) and fix keyset */
    kvno = ipapwd_get_cur_kvno(targetEntry) + 1;
    for (int i = 0; i < kset->num_keys; i++) {
        kset->keys[i].key_data_kvno = kvno;
    }
    filter_keys(krbcfg, kset);

	/* check if we have any left */
	if (kset->num_keys == 0) {
		LOG_FATAL("keyset filtering rejected all proposed keys\n");
		errMesg = "All enctypes provided are unsupported";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto free_and_return;
	}

	rc = ber_encode_krb5_key_data(kset->keys, kset->num_keys,
                                       kset->mkvno, &bval);
	if (rc != 0) {
		LOG_FATAL("encoding krb5_key_data failed\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

	svals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
	if (!svals) {
		LOG_OOM();
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

	svals[0] = slapi_value_new_berval(bval);
	if (!svals[0]) {
		LOG_FATAL("Converting berval to Slapi_Value\n");
		goto free_and_return;
	}

    rc = store_new_keys(targetEntry, serviceName, bindDN, svals, &errMesg);
    if (rc) {
        goto free_and_return;
    }

    rc = encode_setkeytab_reply(kset, &bvp);
    if (rc) {
        errMesg = "Internal Error.\n";
        goto free_and_return;
    }

    new_ctrl.ldctl_oid = KEYTAB_RET_OID;
    new_ctrl.ldctl_value = *bvp;
    new_ctrl.ldctl_iscritical = 0;
    rc = slapi_pblock_set(pb, SLAPI_ADD_RESCONTROL, &new_ctrl);

	/* Free anything that we allocated above */
free_and_return:
	free(serviceName);
	if (kset) ipapwd_keyset_free(&kset);

	if (bval) ber_bvfree(bval);
	if (bvp) ber_bvfree(bvp);

    if (targetEntry) slapi_entry_free(targetEntry);

	if (svals) {
		for (int i = 0; svals[i]; i++) {
			slapi_value_free(&svals[i]);
		}
		free(svals);
	}

	if (krbctx) krb5_free_context(krbctx);

        if (rc == LDAP_SUCCESS)
            errMesg = NULL;
	LOG("%s", errMesg ? errMesg : "success");
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

/* decode a getkeytab control request using libipaasn1 helpers */
static int decode_getkeytab_request(struct berval *extop, bool *wantold,
                                    char **_svcname, char **_password,
                                    krb5_key_salt_tuple **kenctypes,
                                    int *num_kenctypes, char **_err_msg)
{
    int rc = LDAP_OPERATIONS_ERROR;
    char *err_msg = NULL;
    char *svcname = NULL;
    char *password = NULL;
    long *etypes = NULL;
    int numtypes = 0;
    krb5_key_salt_tuple *enctypes = NULL;
    bool newkt;
    bool ret;
    int i;

    ret = ipaasn1_dec_getkt(extop->bv_val, extop->bv_len, &newkt,
                            &svcname, &password, &etypes, &numtypes);
    if (!ret) {
        err_msg = "Failed to decode GetKeytab Control.\n";
        rc = LDAP_PROTOCOL_ERROR;
        goto done;
    }

    if (newkt) {
        if (numtypes) {
            enctypes = malloc(numtypes * sizeof(krb5_key_salt_tuple));
            if (!enctypes) {
                LOG_FATAL("allocation failed\n");
                err_msg = "Internal error\n";
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            for (i = 0; i < numtypes; i++) {
                enctypes[i].ks_enctype = etypes[i];
                enctypes[i].ks_salttype = KRB5_KDB_SALTTYPE_NORMAL;
            }
        }
    }

    rc = LDAP_SUCCESS;

done:
    free(etypes);
    if (rc != LDAP_SUCCESS) {
        free(password);
        free(svcname);
        free(enctypes);
        *_err_msg = err_msg;
    } else {
        *_password = password;
        *_svcname = svcname;
        *wantold = (newkt == false);
        *kenctypes = enctypes;
        *num_kenctypes = numtypes;
    }
    return rc;
}

static int encode_getkeytab_reply(krb5_context krbctx,
                                  krb5_keyblock *kmkey, int mkvno,
                                  krb5_key_data *keys, int num_keys,
                                  struct berval **_bvp)
{
    int rc = LDAP_OPERATIONS_ERROR;
    struct krb_key_salt ksdata[num_keys];
    struct keys_container ksc = { num_keys, ksdata };
    struct berval *bvp = NULL;
    int kvno;
    bool ret;

    memset(ksdata, '\0', num_keys * sizeof(struct krb_key_salt));

    /* uses last key kvno */
    kvno = keys[num_keys-1].key_data_kvno;

    for (int i = 0; i < num_keys; i++) {
        krb5_enc_data cipher = { 0 };
        krb5_data plain = { 0 };
        krb5_int16 plen;

        /* retrieve plain key */
        memcpy(&plen, keys[i].key_data_contents[0], 2);
        cipher.ciphertext.data = (char *)keys[i].key_data_contents[0] + 2;
        cipher.ciphertext.length = keys[i].key_data_length[0] - 2;
        cipher.enctype = kmkey->enctype;
        cipher.kvno = mkvno;

        plain.length = le16toh(plen);
        plain.data = malloc(plain.length);
        if (!plain.data) {
            LOG_FATAL("Failed to allocate plain buffer\n");
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        rc = krb5_c_decrypt(krbctx, kmkey, 0, 0, &cipher, &plain);
        if (rc) {
            LOG_FATAL("Failed to decrypt keys\n");
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        ksc.ksdata[i].enctype = keys[i].key_data_type[0];
        ksc.ksdata[i].key.enctype = keys[i].key_data_type[0];
        ksc.ksdata[i].key.contents = (void *)plain.data;
        ksc.ksdata[i].key.length = plain.length;

        /* if salt available, add it */
        if (keys[i].key_data_length[1] != 0) {
            ksc.ksdata[i].salttype = keys[i].key_data_type[1];
            ksc.ksdata[i].salt.data = (void *)keys[i].key_data_contents[1];
            ksc.ksdata[i].salt.length = keys[i].key_data_length[1];
        }
    }

    bvp = calloc(1, sizeof(struct berval));
    if (!bvp) goto done;

    ret = ipaasn1_enc_getktreply(kvno, &ksc,
                                 (void **)&bvp->bv_val, &bvp->bv_len);
    if (!ret) goto done;

    rc = LDAP_SUCCESS;

done:
    for (int i = 0; i < ksc.nkeys; i ++) {
        free(ksc.ksdata[i].key.contents);
    }
    if (rc != LDAP_SUCCESS) {
        if (bvp) ber_bvfree(bvp);
    } else {
        *_bvp = bvp;
    }
    return rc;
}

static int get_decoded_key_data(char *svcname,
                                krb5_key_data **_keys, int *_num_keys,
                                int *_mkvno, char **_err_msg)
{
    int rc = LDAP_OPERATIONS_ERROR;
    char *err_msg = NULL;
    krb5_key_data *keys = NULL;
    int num_keys = 0;
    int mkvno = 0;
    Slapi_Entry *target = NULL;
    Slapi_Attr *attr;
    Slapi_Value *keys_value;
    const struct berval *encoded_keys;

    target = get_entry_by_principal(svcname);
    if (!target) {
        err_msg = "PrincipalName disappeared while processing.\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    rc = slapi_entry_attr_find(target, "krbPrincipalKey", &attr);
    if (rc) {
        err_msg = "krbPrincipalKey not found\n";
        rc = LDAP_NO_SUCH_ATTRIBUTE;
        goto done;
    }
    rc = slapi_attr_first_value(attr, &keys_value);
    if (rc) {
        err_msg = "Error retrieving krbPrincipalKey\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    encoded_keys = slapi_value_get_berval(keys_value);
    if (!encoded_keys) {
        err_msg = "Error retrieving encoded krbPrincipalKey\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    rc = ber_decode_krb5_key_data(discard_const(encoded_keys),
                                  &mkvno, &num_keys, &keys);
    if (rc) {
        err_msg = "Error retrieving decoded krbPrincipalKey\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (num_keys <= 0) {
        err_msg = "No krbPrincipalKeys available\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    rc = LDAP_SUCCESS;

done:
    if (rc != LDAP_SUCCESS) {
        if (keys) ipa_krb5_free_key_data(keys, num_keys);
        *_err_msg = err_msg;
    } else {
        *_mkvno = mkvno;
        *_keys = keys;
        *_num_keys = num_keys;
    }
    if (target) slapi_entry_free(target);
    return rc;
}

#define WRITEKEYS_OP_CHECK "ipaProtectedOperation;write_keys"
#define READKEYS_OP_CHECK "ipaProtectedOperation;read_keys"

/* Password Modify Extended operation plugin function */
static int ipapwd_getkeytab(Slapi_PBlock *pb, struct ipapwd_krbcfg *krbcfg)
{
    char *bind_dn = NULL;
    char *err_msg = NULL;
    int rc = 0;
    krb5_context krbctx = NULL;
    krb5_error_code krberr;
    struct berval *extop_value = NULL;
    char *service_name = NULL;
    char *svcname;
    Slapi_Entry *target_entry = NULL;
    bool acl_ok = false;
    char *password = NULL;
    int num_kenctypes = 0;
    krb5_key_salt_tuple *kenctypes = NULL;
    int mkvno = 0;
    int num_keys = 0;
    krb5_key_data *keys = NULL;
    struct ipapwd_data data = { 0 };
    Slapi_Value **svals = NULL;
    struct berval *bvp = NULL;
    LDAPControl new_ctrl;
    bool wantold = false;

    /* Get Bind DN */
    slapi_pblock_get(pb, SLAPI_CONN_DN, &bind_dn);

    /* If the connection is bound anonymously, we must refuse to process
    * this operation. */
    if (bind_dn == NULL || *bind_dn == '\0') {
        /* Refuse the operation because they're bound anonymously */
        err_msg = "Anonymous Binds are not allowed.\n";
        rc = LDAP_INSUFFICIENT_ACCESS;
        goto free_and_return;
    }

    krberr = krb5_init_context(&krbctx);
    if (krberr) {
        LOG_FATAL("krb5_init_context failed\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

    /* Get the ber value of the extended operation */
    slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &extop_value);
    if (!extop_value) {
        LOG_FATAL("Failed to retrieve extended op value from pblock\n");
        err_msg = "Failed to retrieve extended operation value\n";
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }

    rc = decode_getkeytab_request(extop_value, &wantold, &service_name,
                                  &password, &kenctypes, &num_kenctypes,
                                  &err_msg);
    if (rc != LDAP_SUCCESS) {
        goto free_and_return;
    }

    /* make sure it is a valid name */
    svcname = check_service_name(krbctx, service_name);
    if (!svcname) {
        rc = LDAP_OPERATIONS_ERROR;
        goto free_and_return;
    }
    slapi_ch_free_string(&service_name);
    service_name = svcname;

    /* check entry */

    /* get Entry by krbPrincipalName */
    target_entry = get_entry_by_principal(service_name);
    if (!target_entry) {
        err_msg = "PrincipalName not found.\n";
        rc = LDAP_NO_SUCH_OBJECT;
        goto free_and_return;
    }

    /* ok access allowed */
    /* do we need to create new keys ? */
    if (wantold) { /* requesting to retrieve existing ones */

        /* check if we are allowed to *read* keys */
        acl_ok = is_allowed_to_access_attr(pb, bind_dn, target_entry,
                                           READKEYS_OP_CHECK, NULL,
                                           SLAPI_ACL_READ);
        if (!acl_ok) {
            LOG_FATAL("Not allowed to retrieve keytab on [%s] as user [%s]!\n",
                      service_name, bind_dn);
            err_msg = "Insufficient access rights\n";
            rc = LDAP_INSUFFICIENT_ACCESS;
            goto free_and_return;
        }

    } else {

        /* check if we are allowed to *write* keys */
        acl_ok = is_allowed_to_access_attr(pb, bind_dn, target_entry,
                                           WRITEKEYS_OP_CHECK, NULL,
                                           SLAPI_ACL_WRITE);
        if (!acl_ok) {
            LOG_FATAL("Not allowed to set keytab on [%s]!\n",
                      service_name);
            err_msg = "Insufficient access rights\n";
            rc = LDAP_INSUFFICIENT_ACCESS;
            goto free_and_return;
        }

        filter_enctypes(krbcfg, kenctypes, &num_kenctypes);

        /* check if we have any left */
        if (num_kenctypes == 0 && kenctypes != NULL) {
            LOG_FATAL("keyset filtering rejected all proposed keys\n");
            err_msg = "All enctypes provided are unsupported";
            rc = LDAP_UNWILLING_TO_PERFORM;
            goto free_and_return;
        }

        /* only target is used, leave everything else NULL,
         * if password is not provided we want to generate a random key */
        data.target = target_entry;
        data.password = password;

        svals = ipapwd_encrypt_encode_key(krbcfg, &data, service_name,
                                          kenctypes ? num_kenctypes :
                                                krbcfg->num_pref_encsalts,
                                          kenctypes ? kenctypes :
                                                krbcfg->pref_encsalts,
                                          &err_msg);
        if (!svals) {
            rc = LDAP_OPERATIONS_ERROR;
            LOG_FATAL("encrypt_encode_keys failed!\n");
            err_msg = "Internal error while encrypting keys\n";
            goto free_and_return;
        }

        rc = store_new_keys(target_entry, service_name, bind_dn, svals,
                            &err_msg);
        if (rc != LDAP_SUCCESS) {
            goto free_and_return;
        }
    }

    rc = get_decoded_key_data(service_name,
                              &keys, &num_keys, &mkvno, &err_msg);
    if (rc != LDAP_SUCCESS) {
        goto free_and_return;
    }

    rc = encode_getkeytab_reply(krbctx, krbcfg->kmkey, mkvno,
                                keys, num_keys, &bvp);
    if (rc != LDAP_SUCCESS) {
        err_msg = "Internal Error.\n";
        goto free_and_return;
    }

    new_ctrl.ldctl_oid = KEYTAB_GET_OID;
    new_ctrl.ldctl_value = *bvp;
    new_ctrl.ldctl_iscritical = 0;
    rc = slapi_pblock_set(pb, SLAPI_ADD_RESCONTROL, &new_ctrl);

free_and_return:
    if (rc == LDAP_SUCCESS) err_msg = NULL;
    LOG("%s", err_msg ? err_msg : "success");
    slapi_send_ldap_result(pb, rc, NULL, err_msg, 0, NULL);

    /* Free anything that we allocated above */
    if (krbctx) krb5_free_context(krbctx);
    free(kenctypes);
    free(service_name);
    free(password);
    if (target_entry) slapi_entry_free(target_entry);
    if (keys) ipa_krb5_free_key_data(keys, num_keys);
    if (svals) {
        for (int i = 0; svals[i]; i++) {
            slapi_value_free(&svals[i]);
        }
        free(svals);
    }
    if (bvp) ber_bvfree(bvp);

    return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

static int ipapwd_extop(Slapi_PBlock *pb)
{
	struct ipapwd_krbcfg *krbcfg = NULL;
	char *errMesg = NULL;
	char *oid = NULL;
	int rc, ret;

	LOG_TRACE("=>\n");

	rc = ipapwd_gen_checks(pb, &errMesg, &krbcfg, IPAPWD_CHECK_CONN_SECURE);
	if (rc) {
		goto free_and_return;
	}

	/* Before going any further, we'll make sure that the right extended
	 * operation plugin has been called: i.e., the OID shipped whithin the
	 * extended operation request must match this very plugin's OIDs:
	 * EXOP_PASSWD_OID or KEYTAB_SET_OID. */
	if (slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_OID, &oid) != 0) {
		errMesg = "Could not get OID value from request.\n";
		rc = LDAP_OPERATIONS_ERROR;
		LOG("%s", errMesg);
		goto free_and_return;
	} else {
	        LOG("Received extended operation request with OID %s\n", oid);
	}

	if (strcasecmp(oid, EXOP_PASSWD_OID) == 0) {
		ret = ipapwd_chpwop(pb, krbcfg);
		free_ipapwd_krbcfg(&krbcfg);
		return ret;
	}
	if (strcasecmp(oid, KEYTAB_SET_OID) == 0) {
		ret = ipapwd_setkeytab(pb, krbcfg);
		free_ipapwd_krbcfg(&krbcfg);
		return ret;
	}
	if (strcasecmp(oid, KEYTAB_GET_OID) == 0) {
		ret = ipapwd_getkeytab(pb, krbcfg);
		free_ipapwd_krbcfg(&krbcfg);
		return ret;
	}

	errMesg = "Request OID does not match supported OIDs.\n";
	rc = LDAP_OPERATIONS_ERROR;

free_and_return:
	if (krbcfg) free_ipapwd_krbcfg(&krbcfg);

	LOG("%s", errMesg);
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

/* Copied from ipamo_string2filter()
 *
 * ipapwd_string2filter()
 *
 * For some reason slapi_str2filter writes to its input
 * which means you cannot pass in a string constant
 * so this is a fix up function for that
 */
Slapi_Filter *ipapwd_string2filter(char *strfilter)
{
	Slapi_Filter *ret = NULL;
	char *idontbelieveit = slapi_ch_strdup(strfilter);

	ret = slapi_str2filter(idontbelieveit);

	slapi_ch_free_string(&idontbelieveit);

	return ret;
}

/* Init data structs */
static int ipapwd_start( Slapi_PBlock *pb )
{
    krb5_context krbctx = NULL;
    krb5_error_code krberr;
    char *realm = NULL;
    char *config_dn;
    Slapi_Entry *config_entry = NULL;
    int ret;

    krberr = krb5_init_context(&krbctx);
    if (krberr) {
        LOG_FATAL("krb5_init_context failed\n");
        /* Yes, we failed, but it is because /etc/krb5.conf doesn't exist
         * or is misconfigured. Start up in a degraded mode.
         */
        return LDAP_SUCCESS;
    }

    if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &config_dn) != 0) {
        LOG_FATAL("No config DN?\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    if (ipapwd_getEntry(config_dn, &config_entry, NULL) != LDAP_SUCCESS) {
        LOG_FATAL("No config Entry extop?\n");
        ret = LDAP_SUCCESS;
        goto done;
    }

    ipa_realm_tree = slapi_entry_attr_get_charptr(config_entry,
                                                  "nsslapd-realmtree");
    if (!ipa_realm_tree) {
        LOG_FATAL("Missing partition configuration entry "
                  "(nsslapd-realmTree)!\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = krb5_get_default_realm(krbctx, &realm);
    if (ret) {
        LOG_FATAL("Failed to get default realm?!\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    ipa_realm_dn = slapi_ch_smprintf("cn=%s,cn=kerberos,%s",
                                     realm, ipa_realm_tree);
    if (!ipa_realm_dn) {
        LOG_OOM();
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ipa_pwd_config_dn = slapi_ch_strdup(config_dn);
    if (!ipa_pwd_config_dn) {
        LOG_OOM();
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    ipa_changepw_principal_dn = slapi_ch_smprintf("krbprincipalname="
                                                  "kadmin/changepw@%s,%s",
                                                  realm, ipa_realm_dn);
    if (!ipa_changepw_principal_dn) {
        LOG_OOM();
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ipa_etc_config_dn = slapi_ch_smprintf("cn=ipaConfig,cn=etc,%s",
                                          ipa_realm_tree);
    if (!ipa_etc_config_dn) {
        LOG_OOM();
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = LDAP_SUCCESS;

    /* NOTE: We never call otp_config_fini() from a destructor. This is because
     *       it may race with threaded requests at shutdown. This leak should
     *       only occur when the DS is exiting, so it isn't a big deal.
     */
    otp_config = otp_config_init(ipapwd_plugin_id);

done:
    free(realm);
    krb5_free_context(krbctx);
    if (config_entry) slapi_entry_free(config_entry);
    return ret;
}

static char *ipapwd_oid_list[] = {
	EXOP_PASSWD_OID,
	KEYTAB_SET_OID,
	KEYTAB_GET_OID,
	NULL
};


static char *ipapwd_name_list[] = {
	"Password Change Extended Operation",
	"Keytab Retrieval Extended Operation",
	NULL
};

/* Initialization function */
int ipapwd_init( Slapi_PBlock *pb )
{
    int ret;
    Slapi_Entry *plugin_entry = NULL;

    /* get args */
    if ((slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &plugin_entry) == 0) &&
        plugin_entry) {
            usetxn = slapi_entry_attr_get_bool(plugin_entry,
                                                 "nsslapd-pluginbetxn");
    }

    /* Get the arguments appended to the plugin extendedop directive. The first argument
     * (after the standard arguments for the directive) should contain the OID of the
     * extended operation. */

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ipapwd_plugin_id);
    if ((ret != 0) || (NULL == ipapwd_plugin_id)) {
        LOG("Could not get identity or identity was NULL\n");
        return -1;
    }

    if (ipapwd_ext_init() != 0) {
        LOG("Object Extension Operation failed\n");
        return -1;
    }

    /* Register the plug-in function as an extended operation
     * plug-in function that handles the operation identified by
     * OID 1.3.6.1.4.1.4203.1.11.1 .  Also specify the version of the server
     * plug-in */
    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *)ipapwd_start);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&ipapwd_plugin_desc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, ipapwd_oid_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, ipapwd_name_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)ipapwd_extop);
    if (ret) {
        LOG("Failed to set plug-in version, function, and OID.\n" );
        return -1;
    }

    if (usetxn) {
        slapi_register_plugin("betxnpreoperation", 1,
                              "ipapwd_pre_init_betxn", ipapwd_pre_init_betxn,
                              "IPA pwd pre ops betxn", NULL,
                              ipapwd_plugin_id);

        slapi_register_plugin("betxnpostoperation", 1,
                              "ipapwd_post_init_betxn", ipapwd_post_init_betxn,
                              "IPA pwd post ops betxn", NULL,
                              ipapwd_plugin_id);
    } 

    slapi_register_plugin("preoperation", 1,
                          "ipapwd_pre_init", ipapwd_pre_init,
                          "IPA pwd pre ops", NULL,
                          ipapwd_plugin_id);

    slapi_register_plugin("postoperation", 1,
                          "ipapwd_post_init", ipapwd_post_init,
                          "IPA pwd post ops", NULL,
                          ipapwd_plugin_id);

    slapi_register_plugin("internalpostoperation", 1,
                          "ipapwd_intpost_init", ipapwd_intpost_init,
                          "IPA pwd internal post ops", NULL,
                          ipapwd_plugin_id);

    return 0;
}
