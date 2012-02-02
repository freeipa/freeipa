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

static int filter_keys(struct ipapwd_krbcfg *krbcfg,
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

    return 0;
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
	 /* Did they give us a DN ? */
	if (dn == NULL || *dn == '\0') {
	 	/* Get the DN from the bind identity on this connection */
		dn = slapi_ch_strdup(bindDN);
		LOG_TRACE("Missing userIdentity in request, "
                          "using the bind DN instead.\n");
	}

	 if (slapi_pblock_set( pb, SLAPI_ORIGINAL_TARGET, dn )) {
		LOG_FATAL("slapi_pblock_set failed!\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
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
        Slapi_DN *target_sdn;

        /* if the user changing the password is self, we must request the
         * old password and verify it matches the current one before
         * proceeding with the password change */
        bind_sdn = slapi_sdn_new_dn_byref(bindDN);
        target_sdn = slapi_sdn_new_dn_byref(dn);
        if (!bind_sdn || !target_sdn) {
            LOG_OOM();
            rc = LDAP_OPERATIONS_ERROR;
            goto free_and_return;
        }
        /* this one will normalize and compare, so difference in case will be
         * correctly handled */
        ret = slapi_sdn_compare(bind_sdn, target_sdn);
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
    ipapwd_set_extradata(pwdata.dn, principal, pwdata.timeNow);

	/* Free anything that we allocated above */
free_and_return:
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

	LOG(errMesg ? errMesg : "success");
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;

}

/* Password Modify Extended operation plugin function */
static int ipapwd_setkeytab(Slapi_PBlock *pb, struct ipapwd_krbcfg *krbcfg)
{
	char *bindDN = NULL;
	char *serviceName = NULL;
	char *errMesg = NULL;
	int ret=0, rc=0, is_root=0;
	struct berval *extop_value = NULL;
	BerElement *ber = NULL;
	Slapi_PBlock *pbte = NULL;
	Slapi_Entry *targetEntry=NULL;
	struct berval *bval = NULL;
	Slapi_Value **svals = NULL;
	Slapi_Value **evals = NULL;
	const char *bdn;
	const Slapi_DN *bsdn;
	Slapi_DN *sdn;
	Slapi_Backend *be;
	Slapi_Entry **es = NULL;
	int scope, res;
	char *filter;
	char *attrlist[] = {"krbPrincipalKey", "krbLastPwdChange", "userPassword", "krbPrincipalName", "enrolledBy", NULL };
	krb5_context krbctx = NULL;
	krb5_principal krbname = NULL;
	krb5_error_code krberr;
	int i, kvno;
	Slapi_Mods *smods;
	ber_tag_t rtag, ttmp;
	ber_int_t tint;
	ber_len_t tlen;
	struct ipapwd_keyset *kset = NULL;
	struct tm utctime;
	char timestr[GENERALIZED_TIME_LENGTH+1];
	time_t time_now = time(NULL);
	char *pw = NULL;
	Slapi_Value *objectclass;

	svals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
	if (!svals) {
		LOG_OOM();
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

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

	if ((ber = ber_init(extop_value)) == NULL)
	{
		errMesg = "KeytabGet Request decode failed.\n";
		rc = LDAP_PROTOCOL_ERROR;
		goto free_and_return;
	}

	/* Format of request to parse
	 *
	 * KeytabGetRequest ::= SEQUENCE {
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

	/* ber parse code */
	rtag = ber_scanf(ber, "{a{", &serviceName);
	if (rtag == LBER_ERROR) {
		LOG_FATAL("ber_scanf failed\n");
		errMesg = "Invalid payload, failed to decode.\n";
		rc = LDAP_PROTOCOL_ERROR;
		goto free_and_return;
	}

	/* make sure it is a valid name */
	krberr = krb5_parse_name(krbctx, serviceName, &krbname);
	if (krberr) {
		slapi_ch_free_string(&serviceName);
		LOG_FATAL("krb5_parse_name failed\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	} else {
		/* invert so that we get the canonical form
		 * (add REALM if not present for example) */
		char *canonname;
		krberr = krb5_unparse_name(krbctx, krbname, &canonname);
		if (krberr) {
			slapi_ch_free_string(&serviceName);
			LOG_FATAL("krb5_unparse_name failed\n");
			rc = LDAP_OPERATIONS_ERROR;
			goto free_and_return;
		}
		slapi_ch_free_string(&serviceName);
		serviceName = canonname;
	}

	/* check entry before doing any other decoding */

	/* Find ancestor base DN */
	sdn = slapi_sdn_new_dn_byval(ipa_realm_dn);
	be = slapi_be_select(sdn);
	slapi_sdn_free(&sdn);
	bsdn = slapi_be_getsuffix(be, 0);
	if (bsdn == NULL) {
		LOG_TRACE("Search for Base DN failed\n");
		errMesg = "PrincipalName not found.\n";
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	}
	bdn = slapi_sdn_get_dn(bsdn);
	scope = LDAP_SCOPE_SUBTREE;

	/* get Entry by krbPrincipalName */
	filter = slapi_ch_smprintf("(krbPrincipalName=%s)", serviceName);

	pbte = slapi_pblock_new();
	slapi_search_internal_set_pb(pbte,
		bdn, scope, filter, attrlist, 0,
		NULL, /* Controls */
		NULL, /* UniqueID */
		ipapwd_plugin_id,
		0); /* Flags */

	/* do search the tree */
	ret = slapi_search_internal_pb(pbte);
	slapi_pblock_get(pbte, SLAPI_PLUGIN_INTOP_RESULT, &res);
	if (ret == -1 || res != LDAP_SUCCESS) {
		LOG_TRACE("Search for Principal failed, err (%d)\n",
			  res ? res : ret);
		errMesg = "PrincipalName not found.\n";
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	}

	/* get entries */
	slapi_pblock_get(pbte, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
	if (!es) {
		LOG_TRACE("No entries ?!");
		errMesg = "PrincipalName not found.\n";
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	}

	/* count entries */
	for (i = 0; es[i]; i++) /* count */ ;

	/* if there is none or more than one, freak out */
	if (i != 1) {
		LOG_TRACE("Too many entries, or entry no found (%d)", i);
		errMesg = "PrincipalName not found.\n";
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	}
	targetEntry = es[0];

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

	/* increment kvno (will be 1 if this is a new entry) */
	kvno = ipapwd_get_cur_kvno(targetEntry) + 1;

	/* ok access allowed, init kset and continue to parse ber buffer */

	errMesg = "Unable to set key\n";
	rc = LDAP_OPERATIONS_ERROR;

	kset = malloc(sizeof(struct ipapwd_keyset));
	if (!kset) {
		LOG_OOM();
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

	/* this encoding assumes all keys have the same kvno */
	/* major-vno = 1 and minor-vno = 1 */
	kset->major_vno = 1;
	kset->minor_vno = 1;
	kset->mkvno = krbcfg->mkvno;

	kset->keys = NULL;
	kset->num_keys = 0;

	rtag = ber_peek_tag(ber, &tlen);
	while (rtag == LBER_SEQUENCE) {
		krb5_key_data *newset;
		krb5_data plain;
		krb5_enc_data cipher;
		struct berval tval;
		krb5_octet *kdata;
                krb5_int16 t;
		size_t klen;

		i = kset->num_keys;

		newset = realloc(kset->keys, sizeof(krb5_key_data) * (i + 1));
		if (!newset) {
			LOG_OOM();
			goto free_and_return;
		}
		kset->keys = newset;

		kset->num_keys += 1;

		memset(&kset->keys[i], 0, sizeof(krb5_key_data));
		kset->keys[i].key_data_ver = 1;
		kset->keys[i].key_data_kvno = kvno;

		/* EncryptionKey */
		rtag = ber_scanf(ber, "{t[{t[i]t[o]}]", &ttmp, &ttmp, &tint, &ttmp, &tval);
		if (rtag == LBER_ERROR) {
			LOG_FATAL("ber_scanf failed\n");
			errMesg = "Invalid payload, failed to decode.\n";
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}

		kset->keys[i].key_data_type[0] = tint;

		plain.length = tval.bv_len;
		plain.data = tval.bv_val;

		krberr = krb5_c_encrypt_length(krbctx, krbcfg->kmkey->enctype, plain.length, &klen);
		if (krberr) {
			free(tval.bv_val);
			LOG_FATAL("krb encryption failed!\n");
			goto free_and_return;
		}

		kdata = malloc(2 + klen);
		if (!kdata) {
			free(tval.bv_val);
			LOG_OOM();
			goto free_and_return;
		}
		t = htole16(plain.length);
		memcpy(kdata, &t, 2);

		kset->keys[i].key_data_length[0] = 2 + klen;
		kset->keys[i].key_data_contents[0] = (krb5_octet *)kdata;

		cipher.ciphertext.length = klen;
		cipher.ciphertext.data = (char *)kdata + 2;

		krberr = krb5_c_encrypt(krbctx, krbcfg->kmkey, 0, 0, &plain, &cipher);
		if (krberr) {
			free(tval.bv_val);
			LOG_FATAL("krb encryption failed!\n");
			goto free_and_return;
		}

		ber_memfree(tval.bv_val);

		rtag = ber_peek_tag(ber, &tlen);

		/* KrbSalt */
		if (rtag == (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {

			rtag = ber_scanf(ber, "t[{t[i]", &ttmp, &ttmp, &tint);
			if (rtag == LBER_ERROR) {
				LOG_FATAL("ber_scanf failed\n");
				errMesg = "Invalid payload, failed to decode.\n";
				rc = LDAP_PROTOCOL_ERROR;
				goto free_and_return;
			}

			kset->keys[i].key_data_ver = 2; /* we have a salt */
			kset->keys[i].key_data_type[1] = tint;

			rtag = ber_peek_tag(ber, &tlen);
			if (rtag == (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {

				rtag = ber_scanf(ber, "t[o]}]", &ttmp, &tval);
				if (rtag == LBER_ERROR) {
					LOG_FATAL("ber_scanf failed\n");
					errMesg = "Invalid payload, failed to decode.\n";
					rc = LDAP_PROTOCOL_ERROR;
					goto free_and_return;
				}

				kset->keys[i].key_data_length[1] = tval.bv_len;
				kset->keys[i].key_data_contents[1] = malloc(tval.bv_len);
				if (!kset->keys[i].key_data_contents[1]) {
				    LOG_OOM();
				    rc = LDAP_OPERATIONS_ERROR;
				    goto free_and_return;
				}
				memcpy(kset->keys[i].key_data_contents[1],
				       tval.bv_val, tval.bv_len);
				ber_memfree(tval.bv_val);

				rtag = ber_peek_tag(ber, &tlen);
			}
		}

		/* FIXME: s2kparams - NOT implemented yet */
		if (rtag == (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2)) {
			rtag = ber_scanf(ber, "t[x]}", &ttmp);
		} else {
			rtag = ber_scanf(ber, "}", &ttmp);
		}
		if (rtag == LBER_ERROR) {
			LOG_FATAL("ber_scanf failed\n");
			errMesg = "Invalid payload, failed to decode.\n";
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}

		rtag = ber_peek_tag(ber, &tlen);
	}

	ber_free(ber, 1);
	ber = NULL;

	/* filter un-supported encodings */
	ret = filter_keys(krbcfg, kset);
	if (ret) {
		LOG_FATAL("keyset filtering failed\n");
		goto free_and_return;
	}

	/* check if we have any left */
	if (kset->num_keys == 0) {
		LOG_FATAL("keyset filtering rejected all proposed keys\n");
		errMesg = "All enctypes provided are unsupported";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto free_and_return;
	}

	smods = slapi_mods_new();

	/* change Last Password Change field with the current date */
	if (!gmtime_r(&(time_now), &utctime)) {
		LOG_FATAL("failed to retrieve current date (buggy gmtime_r ?)\n");
		slapi_mods_free(&smods);
		goto free_and_return;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastPwdChange", timestr);

	/* FIXME: set Password Expiration date ? */
#if 0
	if (!gmtime_r(&(data->expireTime), &utctime)) {
		LOG_FATAL("failed to convert expiration date\n");
		slapi_ch_free_string(&randPasswd);
		slapi_mods_free(&smods);
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbPasswordExpiration", timestr);
#endif

	ret = ber_encode_krb5_key_data(kset->keys, kset->num_keys,
                                       kset->mkvno, &bval);
	if (ret != 0) {
		LOG_FATAL("encoding krb5_key_data failed\n");
		slapi_mods_free(&smods);
		goto free_and_return;
	}

	svals[0] = slapi_value_new_berval(bval);
	if (!svals[0]) {
		LOG_FATAL("Converting berval to Slapi_Value\n");
		slapi_mods_free(&smods);
		goto free_and_return;
	}

	slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "krbPrincipalKey", svals);

	/* If we are creating a keytab for a host service attempt to remove
	 * the userPassword attribute if it exists
	*/
	pw = slapi_entry_attr_get_charptr(targetEntry, "userPassword");
	objectclass = slapi_value_new_string("ipaHost");
	if ((slapi_entry_attr_has_syntax_value(targetEntry, SLAPI_ATTR_OBJECTCLASS, objectclass)) == 1)
	{
		char * krbLastPwdChange = slapi_entry_attr_get_charptr(targetEntry, "krbLastPwdChange");
		char * enrolledBy = slapi_entry_attr_get_charptr(targetEntry, "enrolledBy");
		if (NULL == enrolledBy) {
			evals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));

			if (!evals) {
				LOG_OOM();
				slapi_mods_free(&smods);
				goto free_and_return;
			}

			evals[0] = slapi_value_new_string(bindDN);
			slapi_mods_add_mod_values(smods, LDAP_MOD_ADD, "enrolledBy", evals);
		} else {
			slapi_ch_free_string(&enrolledBy);
		}
		if ((NULL != pw) && (NULL == krbLastPwdChange)) {
			slapi_mods_add_mod_values(smods, LDAP_MOD_DELETE, "userPassword", NULL);
			LOG_TRACE("Removing userPassword from host entry\n");
			slapi_ch_free_string(&pw);
		}
		slapi_value_free(&objectclass);
	}
	slapi_value_free(&objectclass);

	/* commit changes */
	ret = ipapwd_apply_mods(slapi_entry_get_dn_const(targetEntry), smods);

	if (ret != LDAP_SUCCESS) {
		slapi_mods_free(&smods);
		goto free_and_return;

	}
	slapi_mods_free(&smods);

    ipapwd_set_extradata(slapi_entry_get_dn_const(targetEntry),
                         serviceName, time_now);

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

	errMesg = "Internal Error\n";
	rc = LDAP_OPERATIONS_ERROR;

	ber = ber_alloc();
	if (!ber) {
		goto free_and_return;
	}

	ret = ber_printf(ber, "{i{", (ber_int_t)kvno);
	if (ret == -1) {
		goto free_and_return;
	}

	for (i = 0; i < kset->num_keys; i++) {
		ret = ber_printf(ber, "{i}", (ber_int_t)kset->keys[i].key_data_type[0]);
		if (ret == -1) {
			goto free_and_return;
		}
	}
	ret = ber_printf(ber, "}}");
	if (ret == -1) {
		goto free_and_return;
	}

	if (ret != -1) {
		struct berval *bvp;
		LDAPControl new_ctrl;

		ret = ber_flatten(ber, &bvp);
		if (ret == -1) {
			goto free_and_return;
		}

		new_ctrl.ldctl_oid = KEYTAB_RET_OID;
		new_ctrl.ldctl_value = *bvp;
		new_ctrl.ldctl_iscritical = 0;
		rc= slapi_pblock_set(pb, SLAPI_ADD_RESCONTROL, &new_ctrl);
		ber_bvfree(bvp);
	}

	/* Free anything that we allocated above */
free_and_return:
	free(serviceName);
	if (kset) ipapwd_keyset_free(&kset);

	if (bval) ber_bvfree(bval);
	if (ber) ber_free(ber, 1);

	if (pbte) {
		slapi_free_search_results_internal(pbte);
		slapi_pblock_destroy(pbte);
	}
	if (svals) {
		for (i = 0; svals[i]; i++) {
			slapi_value_free(&svals[i]);
		}
		free(svals);
	}
	if (evals) {
		for (i = 0; evals[i]; i++) {
			slapi_value_free(&evals[i]);
		}
		free(evals);
	}

	if (krbname) krb5_free_principal(krbctx, krbname);
	if (krbctx) krb5_free_context(krbctx);

        if (rc == LDAP_SUCCESS)
            errMesg = NULL;
	LOG(errMesg ? errMesg : "success");
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

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
		LOG(errMesg);
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

	errMesg = "Request OID does not match supported OIDs.\n";
	rc = LDAP_OPERATIONS_ERROR;

free_and_return:
	if (krbcfg) free_ipapwd_krbcfg(&krbcfg);

	LOG(errMesg);
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

done:
    free(realm);
    krb5_free_context(krbctx);
    if (config_entry) slapi_entry_free(config_entry);
    return ret;
}



static char *ipapwd_oid_list[] = {
	EXOP_PASSWD_OID,
	KEYTAB_SET_OID,
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
    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *)ipapwd_start);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&ipapwd_plugin_desc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, ipapwd_oid_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, ipapwd_name_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)ipapwd_extop);
    if (ret) {
        LOG("Failed to set plug-in version, function, and OID.\n" );
        return -1;
    }

    slapi_register_plugin("preoperation", 1,
                          "ipapwd_pre_init", ipapwd_pre_init,
                          "IPA pwd pre ops", NULL,
                          ipapwd_plugin_id);

    slapi_register_plugin("postoperation", 1,
                          "ipapwd_post_init", ipapwd_post_init,
                          "IPA pwd post ops", NULL,
                          ipapwd_plugin_id);

    return 0;
}
