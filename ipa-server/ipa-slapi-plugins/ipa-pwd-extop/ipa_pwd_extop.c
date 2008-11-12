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
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <prio.h>
#include <ssl.h>
#include <dirsrv/slapi-plugin.h>
#define KRB5_PRIVATE 1
#include <krb5.h>
#include <lber.h>
#include <time.h>
#include <iconv.h>
#include <openssl/des.h>
#include <openssl/md4.h>

/* Type of connection for this operation;*/
#define LDAP_EXTOP_PASSMOD_CONN_SECURE

/* Uncomment the following #undef FOR TESTING:
 * allows non-SSL connections to use the password change extended op */
/* #undef LDAP_EXTOP_PASSMOD_CONN_SECURE */

/* ber tags for the PasswdModifyRequestValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_USERID	0x80U
#define LDAP_EXTOP_PASSMOD_TAG_OLDPWD	0x81U
#define LDAP_EXTOP_PASSMOD_TAG_NEWPWD	0x82U

/* ber tags for the PasswdModifyResponseValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_GENPWD	0x80U

/* OID of the extended operation handled by this plug-in */
#define EXOP_PASSWD_OID	"1.3.6.1.4.1.4203.1.11.1"

/* OID to retrieve keytabs */
#define KEYTAB_SET_OID "2.16.840.1.113730.3.8.3.1"
#define KEYTAB_RET_OID "2.16.840.1.113730.3.8.3.2"

/* krbTicketFlags */
#define KTF_DISALLOW_POSTDATED        0x00000001
#define KTF_DISALLOW_FORWARDABLE      0x00000002
#define KTF_DISALLOW_TGT_BASED        0x00000004
#define KTF_DISALLOW_RENEWABLE        0x00000008
#define KTF_DISALLOW_PROXIABLE        0x00000010
#define KTF_DISALLOW_DUP_SKEY         0x00000020
#define KTF_DISALLOW_ALL_TIX          0x00000040
#define KTF_REQUIRES_PRE_AUTH         0x00000080
#define KTF_REQUIRES_HW_AUTH          0x00000100
#define KTF_REQUIRES_PWCHANGE         0x00000200
#define KTF_DISALLOW_SVR              0x00001000
#define KTF_PWCHANGE_SERVICE          0x00002000

/* These are the default enc:salt types if nothing is defined.
 * TODO: retrieve the configure set of ecntypes either from the
 * kfc.conf file or by synchronizing the the file content into
 * the directory */

/* Salt types */
#define KRB5_KDB_SALTTYPE_NORMAL        0
#define KRB5_KDB_SALTTYPE_V4            1
#define KRB5_KDB_SALTTYPE_NOREALM       2
#define KRB5_KDB_SALTTYPE_ONLYREALM     3
#define KRB5_KDB_SALTTYPE_SPECIAL       4
#define KRB5_KDB_SALTTYPE_AFS3          5

#define KRB5P_SALT_SIZE 16

void krb5int_c_free_keyblock_contents(krb5_context context, register krb5_keyblock *key);

static const char *ipapwd_def_encsalts[] = {
	"des3-hmac-sha1:normal",
/*	"arcfour-hmac:normal",
	"des-hmac-sha1:normal",
	"des-cbc-md5:normal", */
	"des-cbc-crc:normal",
/*	"des-cbc-crc:v4",
	"des-cbc-crc:afs3", */
	NULL
};

struct ipapwd_encsalt {
	krb5_int32	enc_type;
	krb5_int32	salt_type;
};

static const char *ipa_realm_dn;
static const char *ipa_pwd_config_dn;
static const char *ipa_changepw_principal_dn;

#define IPAPWD_PLUGIN_NAME   "ipa-pwd-extop"
#define IPAPWD_FEATURE_DESC  "IPA Password Manager"
#define IPAPWD_PLUGIN_DESC   "IPA Password Extended Operation plugin"

static Slapi_PluginDesc pdesc = {
    IPAPWD_FEATURE_DESC,
    "FreeIPA project",
    "FreeIPA/1.0",
    IPAPWD_PLUGIN_DESC
};

static void *ipapwd_plugin_id;

#define IPA_CHANGETYPE_NORMAL 0
#define IPA_CHANGETYPE_ADMIN 1
#define IPA_CHANGETYPE_DSMGR 2

struct ipapwd_krbcfg {
    krb5_context krbctx;
    char *realm;
    krb5_keyblock *kmkey;
    int num_supp_encsalts;
    struct ipapwd_encsalt *supp_encsalts;
    int num_pref_encsalts;
    struct ipapwd_encsalt *pref_encsalts;
    char **passsync_mgrs;
    int num_passsync_mgrs;
};

static void free_ipapwd_krbcfg(struct ipapwd_krbcfg **cfg)
{
    struct ipapwd_krbcfg *c = *cfg;

    if (!c) return;

    krb5_free_default_realm(c->krbctx, c->realm);
    krb5_free_context(c->krbctx);
    free(c->kmkey->contents);
    free(c->kmkey);
    free(c->supp_encsalts);
    free(c->pref_encsalts);
    free(c);
    *cfg = NULL;
};

struct ipapwd_data {
	Slapi_Entry *target;
	char *dn;
	char *password;
	time_t timeNow;
	time_t lastPwChange;
	time_t expireTime;
	int changetype;
	int pwHistoryLen;
};

struct ipapwd_krbkeydata {
	int32_t type;
	struct berval value;
};

struct ipapwd_krbkey {
	struct ipapwd_krbkeydata *salt;
	struct ipapwd_krbkeydata *ekey;
	struct berval s2kparams;
};

struct ipapwd_keyset {
	uint16_t major_vno;
	uint16_t minor_vno;
	uint32_t kvno;
	uint32_t mkvno;
	struct ipapwd_krbkey *keys;
	int num_keys;
};

static void ipapwd_keyset_free(struct ipapwd_keyset **pkset)
{
	struct ipapwd_keyset *kset = *pkset;
	int i;

	if (!kset) return;

	for (i = 0; i < kset->num_keys; i++) {
		if (kset->keys[i].salt) {
			free(kset->keys[i].salt->value.bv_val);
			free(kset->keys[i].salt);
		}
		if (kset->keys[i].ekey) {
			free(kset->keys[i].ekey->value.bv_val);
			free(kset->keys[i].ekey);
		}
		free(kset->keys[i].s2kparams.bv_val);
	}
	free(kset->keys);
	free(kset);
	*pkset = NULL;
}

static int filter_keys(struct ipapwd_krbcfg *krbcfg, struct ipapwd_keyset *kset)
{
	int i, j;

	for (i = 0; i < kset->num_keys; i++) {
		for (j = 0; j < krbcfg->num_supp_encsalts; j++) {
			if (kset->keys[i].ekey->type ==
					krbcfg->supp_encsalts[j].enc_type) {
				break;
			}
		}
		if (j == krbcfg->num_supp_encsalts) { /* not valid */

			/* free key */
			if (kset->keys[i].ekey) {
				free(kset->keys[i].ekey->value.bv_val);
				free(kset->keys[i].ekey);
			}
			if (kset->keys[i].salt) {
				free(kset->keys[i].salt->value.bv_val);
				free(kset->keys[i].salt);
			}
			free(kset->keys[i].s2kparams.bv_val);

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

/* Novell key-format scheme:

   KrbKeySet ::= SEQUENCE {
   attribute-major-vno       [0] UInt16,
   attribute-minor-vno       [1] UInt16,
   kvno                      [2] UInt32,
   mkvno                     [3] UInt32 OPTIONAL,
   keys                      [4] SEQUENCE OF KrbKey,
   ...
   }

   KrbKey ::= SEQUENCE {
   salt      [0] KrbSalt OPTIONAL,
   key       [1] EncryptionKey,
   s2kparams [2] OCTET STRING OPTIONAL,
    ...
   }

   KrbSalt ::= SEQUENCE {
   type      [0] Int32,
   salt      [1] OCTET STRING OPTIONAL
   }

   EncryptionKey ::= SEQUENCE {
   keytype   [0] Int32,
   keyvalue  [1] OCTET STRING
   }

 */

static struct berval *encode_keys(struct ipapwd_keyset *kset)
{
	BerElement *be = NULL;
	struct berval *bval = NULL;
	int ret, i;

	be = ber_alloc_t(LBER_USE_DER);

	if (!be) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"memory allocation failed\n");
		return NULL;
	}

	ret = ber_printf(be, "{t[i]t[i]t[i]t[i]t[{",
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), kset->major_vno,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1), kset->minor_vno,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2), kset->kvno,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 3), kset->mkvno,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 4));
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 vno info failed\n");
		goto done;
	}

	for (i = 0; i < kset->num_keys; i++) {

		ret = ber_printf(be, "{");
		if (ret == -1) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"encoding asn1 EncryptionKey failed\n");
			goto done;
		}

		if (kset->keys[i].salt) {
			ret = ber_printf(be, "t[{t[i]",
					 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
					 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
					 kset->keys[i].salt->type);
			if ((ret != -1) && kset->keys[i].salt->value.bv_len) {
				ret = ber_printf(be, "t[o]",
						 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
						 kset->keys[i].salt->value.bv_val,
						 kset->keys[i].salt->value.bv_len);
			}
			if (ret != -1) {
				ret = ber_printf(be, "}]");
			}
			if (ret == -1) {
				goto done;
			}
		}

		ret = ber_printf(be, "t[{t[i]t[o]}]",
				 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
				 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
				 kset->keys[i].ekey->type,
				 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
				 kset->keys[i].ekey->value.bv_val,
				 kset->keys[i].ekey->value.bv_len);
		if (ret == -1) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"encoding asn1 EncryptionKey failed\n");
			goto done;
		}

		/* FIXME: s2kparams not supported yet */

		ret = ber_printf(be, "}");
		if (ret == -1) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"encoding asn1 EncryptionKey failed\n");
			goto done;
		}
	}

	ret = ber_printf(be, "}]}");
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 end of sequences failed\n");
		goto done;
	}

	ret = ber_flatten(be, &bval);
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"flattening asn1 failed\n");
		goto done;
	}
done:
	ber_free(be, 1);

	return bval;
}

static int ipapwd_get_cur_kvno(Slapi_Entry *target)
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
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
					"Error retrieving berval from Slapi_Value\n");
			goto next;
		}
		be = ber_init(cbval);
		if (!be) {
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
					"ber_init() failed!\n");
			goto next;
		}

		tag = ber_scanf(be, "{xxt[i]", &tmp, &tkvno);
		if (tag == LBER_ERROR) {
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
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

static inline void encode_int16(unsigned int val, unsigned char *p)
{
	p[1] = (val >>  8) & 0xff;
	p[0] = (val      ) & 0xff;
}

static Slapi_Value **encrypt_encode_key(struct ipapwd_krbcfg *krbcfg,
					struct ipapwd_data *data)
{
	krb5_context krbctx;
	const char *krbPrincipalName;
	uint32_t krbMaxTicketLife;
	int kvno, i;
	int krbTicketFlags;
	struct berval *bval = NULL;
	Slapi_Value **svals = NULL;
	krb5_principal princ;
	krb5_error_code krberr;
	krb5_data pwd;
	struct ipapwd_keyset *kset = NULL;

	krbctx = krbcfg->krbctx;

	svals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "memory allocation failed\n");
		return NULL;
	}

	kvno = ipapwd_get_cur_kvno(data->target);

	krbPrincipalName = slapi_entry_attr_get_charptr(data->target, "krbPrincipalName");
	if (!krbPrincipalName) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "no krbPrincipalName present in this entry\n");
		return NULL;
	}

	krberr = krb5_parse_name(krbctx, krbPrincipalName, &princ);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"krb5_parse_name failed [%s]\n",
				krb5_get_error_message(krbctx, krberr));
		goto enc_error;
	}

	krbMaxTicketLife = slapi_entry_attr_get_uint(data->target, "krbMaxTicketLife");
	if (krbMaxTicketLife == 0) {
		/* FIXME: retrieve the default from config (max_life from kdc.conf) */
		krbMaxTicketLife = 86400; /* just set the default 24h for now */
	}

	krbTicketFlags = slapi_entry_attr_get_int(data->target, "krbTicketFlags");

	pwd.data = (char *)data->password;
	pwd.length = strlen(data->password);

	kset = malloc(sizeof(struct ipapwd_keyset));
	if (!kset) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
		goto enc_error;
	}

	/* this encoding assumes all keys have the same kvno */
	/* major-vno = 1 and minor-vno = 1 */
	kset->major_vno = 1;
	kset->minor_vno = 1;
	/* increment kvno (will be 1 if this is a new entry) */
	kset->kvno = kvno + 1;
	/* we also assum mkvno is 0 */
	kset->mkvno = 0;

	kset->num_keys = krbcfg->num_pref_encsalts;
	kset->keys = calloc(kset->num_keys, sizeof(struct ipapwd_krbkey));
	if (!kset->keys) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
		goto enc_error;
	}

	for (i = 0; i < kset->num_keys; i++) {
		krb5_keyblock key;
		krb5_data salt;
		krb5_octet *ptr;
		krb5_data plain;
		krb5_enc_data cipher;
		size_t len;
		const char *p;

		salt.data = NULL;

		switch (krbcfg->pref_encsalts[i].salt_type) {

		case KRB5_KDB_SALTTYPE_ONLYREALM:

			p = strchr(krbPrincipalName, '@');
			if (!p) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
						"Invalid principal name, no realm found!\n");
				goto enc_error;
			}
			p++;
			salt.data = strdup(p);
			if (!salt.data) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
						"memory allocation failed\n");
				goto enc_error;
			}
			salt.length = strlen(salt.data); /* final \0 omitted on purpose */
			break;

		case KRB5_KDB_SALTTYPE_NOREALM:

			krberr = krb5_principal2salt_norealm(krbctx, princ, &salt);
			if (krberr) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
						"krb5_principal2salt failed [%s]\n",
						krb5_get_error_message(krbctx, krberr));
				goto enc_error;
			}
			break;

		case KRB5_KDB_SALTTYPE_NORMAL:

			/* If pre auth is required we can set a random salt, otherwise
			 * we have to use a more conservative approach and set the salt
			 * to be REALMprincipal (the concatenation of REALM and principal
			 * name without any separator) */
#if 0
			if (krbTicketFlags & KTF_REQUIRES_PRE_AUTH) {
				salt.length = KRB5P_SALT_SIZE;
				salt.data = malloc(KRB5P_SALT_SIZE);
				if (!salt.data) {
					slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
							"memory allocation failed\n");
					goto enc_error;
				}
				krberr = krb5_c_random_make_octets(krbctx, &salt);
				if (krberr) {
					slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
							"krb5_c_random_make_octets failed [%s]\n",
							krb5_get_error_message(krbctx, krberr));
					goto enc_error;
				}
			} else {
#endif
				krberr = krb5_principal2salt(krbctx, princ, &salt);
				if (krberr) {
					slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
							"krb5_principal2salt failed [%s]\n",
							krb5_get_error_message(krbctx, krberr));
					goto enc_error;
				}
#if 0
			}
#endif
			break;

		case KRB5_KDB_SALTTYPE_V4:
			salt.length = 0;
			break;

		case KRB5_KDB_SALTTYPE_AFS3:

			p = strchr(krbPrincipalName, '@');
			if (!p) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
						"Invalid principal name, no realm found!\n");
				goto enc_error;
			}
			p++;
			salt.data = strdup(p);
			if (!salt.data) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
						"memory allocation failed\n");
				goto enc_error;
			}
			salt.length = SALT_TYPE_AFS_LENGTH; /* special value */
			break;

		default:
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"Invalid salt type [%d]\n", krbcfg->pref_encsalts[i].salt_type);
			goto enc_error;
		}

		/* need to build the key now to manage the AFS salt.length special case */
		krberr = krb5_c_string_to_key(krbctx, krbcfg->pref_encsalts[i].enc_type, &pwd, &salt, &key);
		if (krberr) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"krb5_c_string_to_key failed [%s]\n",
					krb5_get_error_message(krbctx, krberr));
			krb5_free_data_contents(krbctx, &salt);
			goto enc_error;
		}
		if (salt.length == SALT_TYPE_AFS_LENGTH) {
			salt.length = strlen(salt.data);
		}

		krberr = krb5_c_encrypt_length(krbctx, krbcfg->kmkey->enctype, key.length, &len);
		if (krberr) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"krb5_c_string_to_key failed [%s]\n",
					krb5_get_error_message(krbctx, krberr));
			krb5int_c_free_keyblock_contents(krbctx, &key);
			krb5_free_data_contents(krbctx, &salt);
			goto enc_error;
		}

		if ((ptr = (krb5_octet *) malloc(2 + len)) == NULL) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"memory allocation failed\n");
			krb5int_c_free_keyblock_contents(krbctx, &key);
			krb5_free_data_contents(krbctx, &salt);
			goto enc_error;
		}

		encode_int16(key.length, ptr);

		plain.length = key.length;
		plain.data = (char *)key.contents;

		cipher.ciphertext.length = len;
		cipher.ciphertext.data = (char *)ptr+2;

		krberr = krb5_c_encrypt(krbctx, krbcfg->kmkey, 0, 0, &plain, &cipher);
		if (krberr) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"krb5_c_encrypt failed [%s]\n",
					krb5_get_error_message(krbctx, krberr));
			krb5int_c_free_keyblock_contents(krbctx, &key);
			krb5_free_data_contents(krbctx, &salt);
			free(ptr);
			goto enc_error;
		}

		/* KrbSalt  */
		kset->keys[i].salt = malloc(sizeof(struct ipapwd_krbkeydata));
		if (!kset->keys[i].salt) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
			krb5int_c_free_keyblock_contents(krbctx, &key);
			free(ptr);
			goto enc_error;
		}

		kset->keys[i].salt->type = krbcfg->pref_encsalts[i].salt_type;

		if (salt.length) {
			kset->keys[i].salt->value.bv_len = salt.length;
			kset->keys[i].salt->value.bv_val = salt.data;
		}

		/* EncryptionKey */
		kset->keys[i].ekey = malloc(sizeof(struct ipapwd_krbkeydata));
		if (!kset->keys[i].ekey) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
			krb5int_c_free_keyblock_contents(krbctx, &key);
			free(ptr);
			goto enc_error;
		}
		kset->keys[i].ekey->type = key.enctype;
		kset->keys[i].ekey->value.bv_len = len+2;
		kset->keys[i].ekey->value.bv_val = malloc(len+2);
		if (!kset->keys[i].ekey->value.bv_val) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
			krb5int_c_free_keyblock_contents(krbctx, &key);
			free(ptr);
			goto enc_error;
		}
		memcpy(kset->keys[i].ekey->value.bv_val, ptr, len+2);

		/* make sure we free the memory used now that we are done with it */
		krb5int_c_free_keyblock_contents(krbctx, &key);
		free(ptr);
	}

	bval = encode_keys(kset);
	if (!bval) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 KrbSalt failed\n");
		goto enc_error;
	}

	svals[0] = slapi_value_new_berval(bval);
	if (!svals[0]) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"Converting berval to Slapi_Value\n");
		goto enc_error;
	}

	ipapwd_keyset_free(&kset);
	krb5_free_principal(krbctx, princ);
	ber_bvfree(bval);
	return svals;

enc_error:
	if (kset) ipapwd_keyset_free(&kset);
	krb5_free_principal(krbctx, princ);
	if (bval) ber_bvfree(bval);
	free(svals);
	return NULL;
}

static void ipapwd_free_slapi_value_array(Slapi_Value ***svals)
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


struct ntlm_keys {
	uint8_t lm[16];
	uint8_t nt[16];
};

#define KTF_LM_HASH 0x01
#define KTF_NT_HASH 0x02
#define KTF_DOS_CHARSET "CP850" /* same default as samba */
#define KTF_UTF8 "UTF-8"
#define KTF_UCS2 "UCS-2LE"

static const uint8_t parity_table[128] = {
	  1,  2,  4,  7,  8, 11, 13, 14, 16, 19, 21, 22, 25, 26, 28, 31,
	 32, 35, 37, 38, 41, 42, 44, 47, 49, 50, 52, 55, 56, 59, 61, 62,
	 64, 67, 69, 70, 73, 74, 76, 79, 81, 82, 84, 87, 88, 91, 93, 94,
	 97, 98,100,103,104,107,109,110,112,115,117,118,121,122,124,127,
	128,131,133,134,137,138,140,143,145,146,148,151,152,155,157,158,
	161,162,164,167,168,171,173,174,176,179,181,182,185,186,188,191,
	193,194,196,199,200,203,205,206,208,211,213,214,217,218,220,223,
	224,227,229,230,233,234,236,239,241,242,244,247,248,251,253,254};

static void lm_shuffle(uint8_t *out, uint8_t *in)
{
	out[0] = parity_table[in[0]>>1];
	out[1] = parity_table[((in[0]<<6)|(in[1]>>2)) & 0x7F];
	out[2] = parity_table[((in[1]<<5)|(in[2]>>3)) & 0x7F];
	out[3] = parity_table[((in[2]<<4)|(in[3]>>4)) & 0x7F];
	out[4] = parity_table[((in[3]<<3)|(in[4]>>5)) & 0x7F];
	out[5] = parity_table[((in[4]<<2)|(in[5]>>6)) & 0x7F];
	out[6] = parity_table[((in[5]<<1)|(in[6]>>7)) & 0x7F];
	out[7] = parity_table[in[6] & 0x7F];
}

/* create the lm and nt hashes
   newPassword: the clear text utf8 password
   flags: KTF_LM_HASH | KTF_NT_HASH
*/
static int encode_ntlm_keys(char *newPasswd, unsigned int flags, struct ntlm_keys *keys)
{
	int ret = 0;

	/* do lanman first */
	if (flags & KTF_LM_HASH) {
		iconv_t cd;
		size_t cs, il, ol;
		char *inc, *outc;
		char *upperPasswd;
		char *asciiPasswd;
		DES_key_schedule schedule;
		DES_cblock deskey;
		DES_cblock magic = "KGS!@#$%";

		/* TODO: must store the dos charset somewhere in the directory */
		cd = iconv_open(KTF_DOS_CHARSET, KTF_UTF8);
		if (cd == (iconv_t)(-1)) {
			ret = -1;
			goto done;
		}

		/* the lanman password is upper case */
		upperPasswd = (char *)slapi_utf8StrToUpper((unsigned char *)newPasswd);
		if (!upperPasswd) {
			ret = -1;
			goto done;
		}
		il = strlen(upperPasswd);

		/* an ascii string can only be smaller than or equal to an utf8 one */
		ol = il;
		if (ol < 14) ol = 14;
		asciiPasswd = calloc(ol+1, 1);
		if (!asciiPasswd) {
			slapi_ch_free_string(&upperPasswd);
			ret = -1;
			goto done;
		}

		inc = upperPasswd;
		outc = asciiPasswd;
		cs = iconv(cd, &inc, &il, &outc, &ol);
		if (cs == -1) {
			ret = -1;
			slapi_ch_free_string(&upperPasswd);
			free(asciiPasswd);
			iconv_close(cd);
			goto done;
		}

		/* done with these */
		slapi_ch_free_string(&upperPasswd);
		iconv_close(cd);

		/* we are interested only in the first 14 ASCII chars for lanman */
		if (strlen(asciiPasswd) > 14) {
			asciiPasswd[14] = '\0';
		}

		/* first half */
		lm_shuffle(deskey, (uint8_t *)asciiPasswd);

		DES_set_key_unchecked(&deskey, &schedule);
		DES_ecb_encrypt(&magic, (DES_cblock *)keys->lm, &schedule, DES_ENCRYPT);

		/* second half */
		lm_shuffle(deskey, (uint8_t *)&asciiPasswd[7]);

		DES_set_key_unchecked(&deskey, &schedule);
		DES_ecb_encrypt(&magic, (DES_cblock *)&(keys->lm[8]), &schedule, DES_ENCRYPT);

		/* done with it */
		free(asciiPasswd);

	} else {
		memset(keys->lm, 0, 16);
	}

	if (flags & KTF_NT_HASH) {
		iconv_t cd;
		size_t cs, il, ol, sl;
		char *inc, *outc;
		char *ucs2Passwd;
		MD4_CTX md4ctx;

		/* TODO: must store the dos charset somewhere in the directory */
		cd = iconv_open(KTF_UCS2, KTF_UTF8);
		if (cd == (iconv_t)(-1)) {
			ret = -1;
			goto done;
		}

		il = strlen(newPasswd);

		/* an ucs2 string can be at most double than an utf8 one */
		sl = ol = (il+1)*2;
		ucs2Passwd = calloc(ol, 1);
		if (!ucs2Passwd) {
			ret = -1;
			goto done;
		}

		inc = newPasswd;
		outc = ucs2Passwd;
		cs = iconv(cd, &inc, &il, &outc, &ol);
		if (cs == -1) {
			ret = -1;
			free(ucs2Passwd);
			iconv_close(cd);
			goto done;
		}

		/* done with it */
		iconv_close(cd);

		/* get the final ucs2 string length */
		sl -= ol;
		/* we are interested only in the first 14 wchars for the nt password */
		if (sl > 28) {
			sl = 28;
		}

		ret = MD4_Init(&md4ctx);
		if (ret == 0) {
			ret = -1;
			free(ucs2Passwd);
			goto done;
		}
		ret = MD4_Update(&md4ctx, ucs2Passwd, sl);
		if (ret == 0) {
			ret = -1;
			free(ucs2Passwd);
			goto done;
		}
		ret = MD4_Final(keys->nt, &md4ctx);
		if (ret == 0) {
			ret = -1;
			free(ucs2Passwd);
			goto done;
		}

	} else {
		memset(keys->nt, 0, 16);
	}

	ret = 0;

done:
	return ret;
}

/* searches the directory and finds the policy closest to the DN */
/* return 0 on success, -1 on error or if no policy is found */
static int ipapwd_getPolicy(const char *dn, Slapi_Entry *target, Slapi_Entry **e)
{
	const char *krbPwdPolicyReference;
	const char *pdn;
	const Slapi_DN *psdn;
	Slapi_Backend *be;
	Slapi_PBlock *pb;
	char *attrs[] = { "krbMaxPwdLife", "krbMinPwdLife",
			  "krbPwdMinDiffChars", "krbPwdMinLength",
			  "krbPwdHistoryLength", NULL};
	Slapi_Entry **es = NULL;
	Slapi_Entry *pe = NULL;
	char **edn;
	int ret, res, dist, rdnc, scope, i;
	Slapi_DN *sdn;

	sdn = slapi_sdn_new_dn_byref(dn);

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
			"ipapwd_getPolicy: Searching policy for [%s]\n", dn);

	krbPwdPolicyReference = slapi_entry_attr_get_charptr(target, "krbPwdPolicyReference");
	if (krbPwdPolicyReference) {
		pdn = krbPwdPolicyReference;
		scope = LDAP_SCOPE_BASE;
	} else {
		/* Find ancestor base DN */
		be = slapi_be_select(sdn);
		psdn = slapi_be_getsuffix(be, 0);
		pdn = slapi_sdn_get_dn(psdn);
		scope = LDAP_SCOPE_SUBTREE;
	}

	*e = NULL;

	pb = slapi_pblock_new();
	slapi_search_internal_set_pb (pb,
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_getPolicy: Couldn't find policy, err (%d)\n",
				res?res:ret);
		ret = -1;
		goto done;
	}

	/* get entries */
	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
	if (!es) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
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
	slapi_free_search_results_internal(pb);
	slapi_pblock_destroy(pb);
	slapi_sdn_free(&sdn);
	return ret;
}

#define GENERALIZED_TIME_LENGTH 15

static int ipapwd_sv_pw_cmp(const void *pv1, const void *pv2)
{
	const char *pw1 = slapi_value_get_string(*((Slapi_Value **)pv1));
	const char *pw2 = slapi_value_get_string(*((Slapi_Value **)pv2));

	return strncmp(pw1, pw2, GENERALIZED_TIME_LENGTH);
}

static Slapi_Value **ipapwd_setPasswordHistory(Slapi_Mods *smods, struct ipapwd_data *data)
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
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to retrieve current date (buggy gmtime_r ?)\n");
		return NULL;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);

	histr = slapi_ch_smprintf("%s%s", timestr, old_pw);
	if (!histr) {
		slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
				"ipapwd_checkPassword: Out of Memory\n");
		return NULL;
	}

	/* retrieve current history */
	ret = slapi_entry_attr_find(data->target, "passwordHistory", &passwordHistory);
	if (ret == 0) {
		int ret, hint, count, i;
		const char *pwstr;
		Slapi_Value *pw;

		hint = 0;
		count = 0;
		ret = slapi_attr_get_numvalues(passwordHistory, &count);
		/* if we have one */
		if (count > 0 && data->pwHistoryLen > 0) {
			pH = calloc(count + 2, sizeof(Slapi_Value *));
			if (!pH) {
				slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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
				i = data->pwHistoryLen;
				pH[i] = NULL;
				i--;
			}

			pc = i;

			/* copy only interesting entries */
			for (i = 0; i < pc; i++) {
				pH[i] = slapi_value_dup(pH[i]);
				if (pH[i] == NULL) {
					slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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
			slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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

static Slapi_Value *ipapwd_strip_pw_date(Slapi_Value *pw)
{
	const char *pwstr;

	pwstr = slapi_value_get_string(pw);
	return slapi_value_new_string(&pwstr[GENERALIZED_TIME_LENGTH]);
}

#define IPAPWD_POLICY_MASK 0x0FF
#define IPAPWD_POLICY_ERROR 0x100
#define IPAPWD_POLICY_OK 0

/* 90 days default pwd max lifetime */
#define IPAPWD_DEFAULT_PWDLIFE (90 * 24 *3600)
#define IPAPWD_DEFAULT_MINLEN 0

/* check password strenght and history */
static int ipapwd_CheckPolicy(struct ipapwd_data *data)
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
	krbPrincipalExpiration = slapi_entry_attr_get_charptr(data->target, "krbPrincipalExpiration");
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
				slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "Account Expired");
				return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDMODNOTALLOWED;
			}
		}
		/* FIXME: else error out ? */
	}
	slapi_ch_free_string(&krbPrincipalExpiration);

	/* find the entry with the password policy */
	ret = ipapwd_getPolicy(data->dn, data->target, &policy);
	if (ret) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "No password policy");
		goto no_policy;
	}

	/* Retrieve Max History Len */
	data->pwHistoryLen = slapi_entry_attr_get_int(policy, "krbPwdHistoryLength");

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
			slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_checkPassword: Password in history\n");
			slapi_entry_free(policy);
			return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDINHISTORY;
		}
	}

	krbPasswordExpiration = slapi_entry_attr_get_charptr(data->target, "krbPasswordExpiration");
	krbLastPwdChange = slapi_entry_attr_get_charptr(data->target, "krbLastPwdChange");
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
			"Warning: Last Password Change Time is not available");
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
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_checkPolicy: Ignore krbMinPwdLife Expiration, not enough info\n");

		} else if (data->timeNow < data->lastPwChange + krbMinPwdLife) {
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
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
	krbPwdMinDiffChars = slapi_entry_attr_get_int(policy, "krbPwdMinDiffChars");
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
		while ( p && *p )
		{
			if ( ldap_utf8isdigit( p ) ) {
				num_digits++;
			} else if ( ldap_utf8isalpha( p ) ) {
				num_alphas++;
				if ( slapi_utf8isLower( (unsigned char *)p ) ) {
					num_lowers++;
				} else {
					num_uppers++;
				}
			} else {
				/* check if this is an 8-bit char */
				if ( *p & 128 ) {
					num_8bit++;
				} else {
					num_specials++;
				}
			}

			/* check for repeating characters. If this is the
			   first char of the password, no need to check */
			if ( pwd != p ) {
				int len = ldap_utf8len( p );
				char *prev_p = ldap_utf8prev( p );

				if ( len == ldap_utf8len( prev_p ) )
				{
					if ( memcmp( p, prev_p, len ) == 0 )
                                	{
						num_repeated++;
						if ( max_repeated < num_repeated ) {
							max_repeated = num_repeated;
						}
					} else {
						num_repeated = 0;
					}
				} else {
					num_repeated = 0;
				}
			}

			p = ldap_utf8next( p );
		}

		free(pwd);
		p = pwd = NULL;

		/* tally up the number of character categories */
		if ( num_digits > 0 )
			++num_categories;
		if ( num_uppers > 0 )
			++num_categories;
		if ( num_lowers > 0 )
			++num_categories;
		if ( num_specials > 0 )
			++num_categories;
		if ( num_8bit > 0 )
			++num_categories;

		/* FIXME: the kerberos plicy schema does not define separated threshold values,
		 *        so just treat anything as a category, we will fix this when we merge
		 *        with DS policies */

		if (max_repeated > 1)
			--num_categories;

		if (num_categories < krbPwdMinDiffChars) {
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_checkPassword: Password not complex enough\n");
			slapi_entry_free(policy);
			return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_INVALIDPWDSYNTAX;
		}
	}

	/* Check password history */
	ret = slapi_entry_attr_find(data->target, "passwordHistory", &passwordHistory);
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
				slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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
				slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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
				slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
			"ipapwd_checkPassword: Password too short\n");
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
static int ipapwd_getEntry(const char *dn, Slapi_Entry **e2, char **attrlist)
{
	Slapi_DN *sdn;
	int search_result = 0;

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_getEntry\n");

	sdn = slapi_sdn_new_dn_byref(dn);
	if ((search_result = slapi_search_internal_get_entry( sdn, attrlist, e2,
 					ipapwd_plugin_id)) != LDAP_SUCCESS ){
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_getEntry: No such entry-(%s), err (%d)\n",
				dn, search_result);
	}

	slapi_sdn_free( &sdn );
	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
			"<= ipapwd_getEntry: %d\n", search_result);
	return search_result;
}


/* Construct Mods pblock and perform the modify operation
 * Sets result of operation in SLAPI_PLUGIN_INTOP_RESULT
 */
static int ipapwd_apply_mods(const char *dn, Slapi_Mods *mods)
{
	Slapi_PBlock *pb;
	int ret;

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_apply_mods\n");

	if (!mods || (slapi_mods_get_num_mods(mods) == 0)) {
		return -1;
	}

	pb = slapi_pblock_new();
	slapi_modify_internal_set_pb (pb, dn,
		slapi_mods_get_ldapmods_byref(mods),
		NULL, /* Controls */
		NULL, /* UniqueID */
		ipapwd_plugin_id, /* PluginID */
		0); /* Flags */

	ret = slapi_modify_internal_pb (pb);
	if (ret) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
			"WARNING: modify error %d on entry '%s'\n",
			ret, dn);
	} else {

		slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

		if (ret != LDAP_SUCCESS){
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"WARNING: modify error %d on entry '%s'\n",
				ret, dn);
		} else {
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"<= ipapwd_apply_mods: Successful\n");
		}
	}

	slapi_pblock_destroy(pb);

	return ret;
}

/* ascii hex output of bytes in "in"
 * out len is 32 (preallocated)
 * in len is 16 */
static const char hexchars[] = "0123456789ABCDEF";
static void hexbuf(char *out, const uint8_t *in)
{
	int i;

	for (i = 0; i < 16; i++) {
		out[i*2] = hexchars[in[i] >> 4];
		out[i*2+1] = hexchars[in[i] & 0x0f];
	}
}

/* Modify the Password attributes of the entry */
static int ipapwd_SetPassword(struct ipapwd_krbcfg *krbcfg,
				struct ipapwd_data *data)
{
	int ret = 0, i = 0;
	Slapi_Mods *smods;
	Slapi_Value **svals = NULL;
	Slapi_Value **pwvals = NULL;
	struct tm utctime;
	char timestr[GENERALIZED_TIME_LENGTH+1];
	krb5_context krbctx;
	krb5_error_code krberr;
	char lm[33], nt[33];
	struct ntlm_keys ntlm;
	int ntlm_flags = 0;
	Slapi_Value *sambaSamAccount;

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_SetPassword\n");

	smods = slapi_mods_new();

	/* generate kerberos keys to be put into krbPrincipalKey */
	svals = encrypt_encode_key(krbcfg, data);
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "key encryption/encoding failed\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

	slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "krbPrincipalKey", svals);

	/* change Last Password Change field with the current date */
	if (!gmtime_r(&(data->timeNow), &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to retrieve current date (buggy gmtime_r ?)\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastPwdChange", timestr);

	/* set Password Expiration date */
	if (!gmtime_r(&(data->expireTime), &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to convert expiration date\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbPasswordExpiration", timestr);

	sambaSamAccount = slapi_value_new_string("sambaSamAccount");
	if (slapi_entry_attr_has_syntax_value(data->target, "objectClass", sambaSamAccount)) {
		/* TODO: retrieve if we want to store the LM hash or not */
		ntlm_flags = KTF_LM_HASH | KTF_NT_HASH;
	}
	slapi_value_free(&sambaSamAccount);

	if (ntlm_flags) {
		char *password = strdup(data->password);
		if (encode_ntlm_keys(password, ntlm_flags, &ntlm) != 0) {
			free(password);
			ret = LDAP_OPERATIONS_ERROR;
			goto free_and_return;
		}
		if (ntlm_flags & KTF_LM_HASH) {
			hexbuf(lm, ntlm.lm);
			lm[32] = '\0';
			slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "sambaLMPassword", lm);
		}
		if (ntlm_flags & KTF_NT_HASH) {
			hexbuf(nt, ntlm.nt);
			nt[32] = '\0';
			slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "sambaNTPassword", nt);
		}
		free(password);
	}

	/* let DS encode the password itself, this allows also other plugins to
	 * intercept it to perform operations like synchronization with Active
	 * Directory domains through the replication plugin */
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "userPassword", data->password);

	/* set password history */
	pwvals = ipapwd_setPasswordHistory(smods, data);
	if (pwvals) {
		slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "passwordHistory", pwvals);
	}

	/* FIXME:
	 * instead of replace we should use a delete/add so that we are
	 * completely sure nobody else modified the entry meanwhile and
	 * fail if that's the case */

	/* commit changes */
	ret = ipapwd_apply_mods(data->dn, smods);

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipapwd_SetPassword: %d\n", ret);

free_and_return:
	slapi_mods_free(&smods);
	ipapwd_free_slapi_value_array(&svals);
	ipapwd_free_slapi_value_array(&pwvals);

	return ret;
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
	char *attrlist[] = {"*", "passwordHistory", NULL };
	struct ipapwd_data pwdata;

	/* Get the ber value of the extended operation */
	slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &extop_value);

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
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"ber_scanf failed\n");
			errMesg = "ber_scanf failed at userID parse.\n";
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}

		tag = ber_peek_tag(ber, &len);
	}

	/* identify oldPasswd field by tags */
	if (tag == LDAP_EXTOP_PASSMOD_TAG_OLDPWD )
	{
		if (ber_scanf(ber, "a", &oldPasswd) == LBER_ERROR) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"ber_scanf failed\n");
			errMesg = "ber_scanf failed at oldPasswd parse.\n";
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}
		tag = ber_peek_tag(ber, &len);
	}

	/* identify newPasswd field by tags */
	if (tag == LDAP_EXTOP_PASSMOD_TAG_NEWPWD )
	{
		if (ber_scanf(ber, "a", &newPasswd) == LBER_ERROR) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"ber_scanf failed\n");
			errMesg = "ber_scanf failed at newPasswd parse.\n";
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
			"Missing userIdentity in request, using the bind DN instead.\n");
	 }

	 slapi_pblock_set( pb, SLAPI_ORIGINAL_TARGET, dn );

	 /* Now we have the DN, look for the entry */
	 ret = ipapwd_getEntry(dn, &targetEntry, attrlist);
	 /* If we can't find the entry, then that's an error */
	 if (ret) {
	 	/* Couldn't find the entry, fail */
		errMesg = "No such Entry exists.\n" ;
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	 }

	 /* First thing to do is to ask access control if the bound identity has
	  * rights to modify the userpassword attribute on this entry. If not,
	  * then we fail immediately with insufficient access. This means that
	  * we don't leak any useful information to the client such as current
	  * password wrong, etc.
	  */

	is_root = slapi_dn_isroot(bindDN);
	slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, &is_root);

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
		slapi_pblock_set(pb, SLAPI_BACKEND, be);
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"oldPasswd provided, but we will ignore it");
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
		errMesg = "Password Fails to meet minimum strength criteria";
		if (ret & IPAPWD_POLICY_ERROR) {
			slapi_pwpolicy_make_response_control(pb, -1, -1, ret & IPAPWD_POLICY_MASK);
			rc = LDAP_CONSTRAINT_VIOLATION;
		} else {
			errMesg = "Internal error";
			rc = ret;
		}
		goto free_and_return;
	}

	/* Now we're ready to set the kerberos key material */
	ret = ipapwd_SetPassword(krbcfg, &pwdata);
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

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipapwd_extop: %d\n", rc);

	/* Free anything that we allocated above */
free_and_return:
	slapi_ch_free_string(&oldPasswd);
	slapi_ch_free_string(&newPasswd);
	/* Either this is the same pointer that we allocated and set above,
	 * or whoever used it should have freed it and allocated a new
	 * value that we need to free here */
	slapi_pblock_get(pb, SLAPI_ORIGINAL_TARGET, &dn);
	slapi_ch_free_string(&dn);
	slapi_pblock_set(pb, SLAPI_ORIGINAL_TARGET, NULL);
	slapi_ch_free_string(&authmethod);

	if (targetEntry) slapi_entry_free(targetEntry);
	if (ber) ber_free(ber, 1);

	slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop", errMesg ? errMesg : "success");
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
	const char *bdn;
	const Slapi_DN *bsdn;
	Slapi_DN *sdn;
	Slapi_Backend *be;
	Slapi_Entry **es = NULL;
	int scope, res;
	char *filter;
	char *attrlist[] = {"krbPrincipalKey", "krbLastPwdChange", NULL };
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

	svals = (Slapi_Value **)calloc(2, sizeof(Slapi_Value *));
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"memory allocation failed\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}

	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"krb5_init_context failed\n");
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
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"ber_scanf failed\n");
		errMesg = "Invalid payload, failed to decode.\n";
		rc = LDAP_PROTOCOL_ERROR;
		goto free_and_return;
	}

	/* make sure it is a valid name */
	krberr = krb5_parse_name(krbctx, serviceName, &krbname);
	if (krberr) {
		slapi_ch_free_string(&serviceName);
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"krb5_parse_name failed\n");
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	} else {
		/* invert so that we get the canonical form
		 * (add REALM if not present for example) */
		char *canonname;
		krberr = krb5_unparse_name(krbctx, krbname, &canonname);
		if (krberr) {
			slapi_ch_free_string(&serviceName);
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"krb5_unparse_name failed\n");
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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"Search for Principal failed, err (%d)\n",
				res?res:ret);
		errMesg = "PrincipalName not found.\n";
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	}

	/* get entries */
	slapi_pblock_get(pbte, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
	if (!es) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "No entries ?!");
		errMesg = "PrincipalName not found.\n";
		rc = LDAP_NO_SUCH_OBJECT;
		goto free_and_return;
	}

	/* count entries */
	for (i = 0; es[i]; i++) /* count */ ;

	/* if there is none or more than one, freak out */
	if (i != 1) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"Too many entries, or entry no found (%d)", i);
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
	slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, &is_root);

	/* In order to perform the access control check,
	 * we need to select a backend (even though
	 * we don't actually need it otherwise).
	 */
	slapi_pblock_set(pb, SLAPI_BACKEND, be);

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
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
		goto free_and_return;
	}

	/* this encoding assumes all keys have the same kvno */
	/* major-vno = 1 and minor-vno = 1 */
	kset->major_vno = 1;
	kset->minor_vno = 1;
	kset->kvno = kvno;
	/* we also assum mkvno is 0 */
	kset->mkvno = 0;

	kset->keys = NULL;
	kset->num_keys = 0;

	rtag = ber_peek_tag(ber, &tlen);
	while (rtag == LBER_SEQUENCE) {
		krb5_data plain;
		krb5_enc_data cipher;
		struct berval tval;
		krb5_octet *kdata;
		size_t klen;

		i = kset->num_keys;

		if (kset->keys) {
			struct ipapwd_krbkey *newset;

			newset = realloc(kset->keys, sizeof(struct ipapwd_krbkey) * (i + 1));
			if (!newset) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
				goto free_and_return;
			}
			kset->keys = newset;
		} else {
			kset->keys = malloc(sizeof(struct ipapwd_krbkey));
			if (!kset->keys) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
				goto free_and_return;
			}
		}
		kset->num_keys += 1;

		kset->keys[i].salt = NULL;
		kset->keys[i].ekey = NULL;
		kset->keys[i].s2kparams.bv_len = 0;
		kset->keys[i].s2kparams.bv_val = NULL;

		/* EncryptionKey */
		rtag = ber_scanf(ber, "{t[{t[i]t[o]}]", &ttmp, &ttmp, &tint, &ttmp, &tval);
		if (rtag == LBER_ERROR) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed\n");
			errMesg = "Invalid payload, failed to decode.\n";
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}

		kset->keys[i].ekey = calloc(1, sizeof(struct ipapwd_krbkeydata));
		if (!kset->keys[i].ekey) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
			goto free_and_return;
		}

		kset->keys[i].ekey->type = tint;

		plain.length = tval.bv_len;
		plain.data = tval.bv_val;

		krberr = krb5_c_encrypt_length(krbctx, krbcfg->kmkey->enctype, plain.length, &klen);
		if (krberr) {
			free(tval.bv_val);
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "krb encryption failed!\n");
			goto free_and_return;
		}

		kdata = malloc(2 + klen);
		if (!kdata) {
			free(tval.bv_val);
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
			goto free_and_return;
		}
		encode_int16(plain.length, kdata);

		kset->keys[i].ekey->value.bv_len = 2 + klen;
		kset->keys[i].ekey->value.bv_val = (char *)kdata;

		cipher.ciphertext.length = klen;
		cipher.ciphertext.data = (char *)kdata + 2;

		krberr = krb5_c_encrypt(krbctx, krbcfg->kmkey, 0, 0, &plain, &cipher);
		if (krberr) {
			free(tval.bv_val);
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "krb encryption failed!\n");
			goto free_and_return;
		}

		free(tval.bv_val);

		rtag = ber_peek_tag(ber, &tlen);

		/* KrbSalt */
		if (rtag == (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {

			rtag = ber_scanf(ber, "t[{t[i]", &ttmp, &ttmp, &tint);
			if (rtag == LBER_ERROR) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed\n");
				errMesg = "Invalid payload, failed to decode.\n";
				rc = LDAP_PROTOCOL_ERROR;
				goto free_and_return;
			}

			kset->keys[i].salt = calloc(1, sizeof(struct ipapwd_krbkeydata));
			if (!kset->keys[i].salt) {
				slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "malloc failed!\n");
				goto free_and_return;
			}

			kset->keys[i].salt->type = tint;

			rtag = ber_peek_tag(ber, &tlen);
			if (rtag == (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1)) {

				rtag = ber_scanf(ber, "t[o]}]", &ttmp, &tval);
				if (rtag == LBER_ERROR) {
					slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed\n");
					errMesg = "Invalid payload, failed to decode.\n";
					rc = LDAP_PROTOCOL_ERROR;
					goto free_and_return;
				}

				kset->keys[i].salt->value = tval;

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
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed\n");
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
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"keyset filtering failed\n");
		goto free_and_return;
	}

	/* check if we have any left */
	if (kset->num_keys == 0) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"keyset filtering rejected all proposed keys\n");
		errMesg = "All enctypes provided are unsupported";
		rc = LDAP_UNWILLING_TO_PERFORM;
		goto free_and_return;
	}

	smods = slapi_mods_new();

	/* change Last Password Change field with the current date */
	if (!gmtime_r(&(time_now), &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"failed to retrieve current date (buggy gmtime_r ?)\n");
		slapi_mods_free(&smods);
		goto free_and_return;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastPwdChange", timestr);

	/* FIXME: set Password Expiration date ? */
#if 0
	if (!gmtime_r(&(data->expireTime), &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"failed to convert expiration date\n");
		slapi_ch_free_string(&randPasswd);
		slapi_mods_free(&smods);
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbPasswordExpiration", timestr);
#endif

	bval = encode_keys(kset);
	if (!bval) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 KrbSalt failed\n");
		slapi_mods_free(&smods);
		goto free_and_return;
	}

	svals[0] = slapi_value_new_berval(bval);
	if (!svals[0]) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"Converting berval to Slapi_Value\n");
		slapi_mods_free(&smods);
		goto free_and_return;
	}

	slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "krbPrincipalKey", svals);

	/* commit changes */
	ret = ipapwd_apply_mods(slapi_entry_get_dn_const(targetEntry), smods);

	if (ret != LDAP_SUCCESS) {
		slapi_mods_free(&smods);
		goto free_and_return;

	}
	slapi_mods_free(&smods);

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
		ret = ber_printf(ber, "{i}", (ber_int_t)kset->keys[i].ekey->type);
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
		LDAPControl new_ctrl = {0};

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

	if (krbname) krb5_free_principal(krbctx, krbname);
	if (krbctx) krb5_free_context(krbctx);

	slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop", errMesg ? errMesg : "success");
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

static int new_ipapwd_encsalt(krb5_context krbctx, const char * const *encsalts,
			      struct ipapwd_encsalt **es_types, int *num_es_types)
{
	struct ipapwd_encsalt *es;
	int nes, i;

	for (i = 0; encsalts[i]; i++) /* count */ ;
	es = calloc(i + 1, sizeof(struct ipapwd_encsalt));
	if (!es) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory!\n");
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
			slapi_log_error(SLAPI_LOG_PLUGIN, "ipapwd_start",
					"Allocation error\n");
			return LDAP_OPERATIONS_ERROR;
		}
		salt = strchr(enc, ':');
		if (!salt) {
			slapi_log_error(SLAPI_LOG_PLUGIN, "ipapwd_start",
					"Invalid krb5 enc string\n");
			free(enc);
			continue;
		}
		*salt = '\0'; /* null terminate the enc type */
		salt++; /* skip : */

		krberr = krb5_string_to_enctype(enc, &tmpenc);
		if (krberr) {
			slapi_log_error(SLAPI_LOG_PLUGIN, "ipapwd_start",
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
    char *tmpstr;
    int i, ret;

    config = calloc(1, sizeof(struct ipapwd_krbcfg));
    if (!config) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Out of memory!\n");
        goto free_and_error;
    }
    kmkey = calloc(1, sizeof(krb5_keyblock));
    if (!kmkey) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Out of memory!\n");
        goto free_and_error;
    }
    config->kmkey = kmkey;

    krberr = krb5_init_context(&config->krbctx);
    if (krberr) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "krb5_init_context failed\n");
        goto free_and_error;
    }

    ret = krb5_get_default_realm(config->krbctx, &config->realm);
    if (ret) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Failed to get default realm?!\n");
        goto free_and_error;
    }

    /* get the Realm Container entry */
    ret = ipapwd_getEntry(ipa_realm_dn, &realm_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "No realm Entry?\n");
        goto free_and_error;
    }

    /*** get the Kerberos Master Key ***/

    ret = slapi_entry_attr_find(realm_entry, "krbMKey", &a);
    if (ret == -1) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "No master key??\n");
        goto free_and_error;
    }

    /* there should be only one value here */
    ret = slapi_attr_first_value(a, &v);
    if (ret == -1) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "No master key??\n");
        goto free_and_error;
    }

    bval = slapi_value_get_berval(v);
    if (!bval) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Error retrieving master key berval\n");
        goto free_and_error;
    }

    be = ber_init(bval);
    if (!bval) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "ber_init() failed!\n");
        goto free_and_error;
    }

    tag = ber_scanf(be, "{i{iO}}", &tmp, &ttype, &mkey);
    if (tag == LBER_ERROR) {
        slapi_log_error(SLAPI_LOG_TRACE, "ipapwd_getConfig",
                        "Bad Master key encoding ?!\n");
        goto free_and_error;
    }

    kmkey->magic = KV5M_KEYBLOCK;
    kmkey->enctype = ttype;
    kmkey->length = mkey->bv_len;
    kmkey->contents = malloc(mkey->bv_len);
    if (!kmkey->contents) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Out of memory!\n");
        goto free_and_error;
    }
    memcpy(kmkey->contents, mkey->bv_val, mkey->bv_len);
    ber_bvfree(mkey);
    ber_free(be, 1);
    mkey = NULL;
    be = NULL;

    /*** get the Supported Enc/Salt types ***/

    encsalts = slapi_entry_attr_get_charray(realm_entry, "krbSupportedEncSaltTypes");
    if (encsalts) {
        ret = new_ipapwd_encsalt(config->krbctx,
                                 (const char * const *)encsalts,
                                 &config->supp_encsalts,
                                 &config->num_supp_encsalts);
        slapi_ch_array_free(encsalts);
    } else {
        slapi_log_error(SLAPI_LOG_TRACE, "ipapwd_getConfig",
                        "No configured salt types use defaults\n");
        ret = new_ipapwd_encsalt(config->krbctx,
                                 ipapwd_def_encsalts,
                                 &config->supp_encsalts,
                                 &config->num_supp_encsalts);
    }
    if (ret) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Can't get Supported EncSalt Types\n");
        goto free_and_error;
    }

    /*** get the Preferred Enc/Salt types ***/

    encsalts = slapi_entry_attr_get_charray(realm_entry, "krbDefaultEncSaltTypes");
    if (encsalts) {
        ret = new_ipapwd_encsalt(config->krbctx,
                                 (const char * const *)encsalts,
                                 &config->pref_encsalts,
                                 &config->num_pref_encsalts);
        slapi_ch_array_free(encsalts);
    } else {
        slapi_log_error(SLAPI_LOG_TRACE, "ipapwd_getConfig",
                        "No configured salt types use defaults\n");
        ret = new_ipapwd_encsalt(config->krbctx,
                                 ipapwd_def_encsalts,
                                 &config->pref_encsalts,
                                 &config->num_pref_encsalts);
    }
    if (ret) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Can't get Preferred EncSalt Types\n");
        goto free_and_error;
    }

    slapi_entry_free(realm_entry);

    /* get the Realm Container entry */
    ret = ipapwd_getEntry(ipa_pwd_config_dn, &config_entry, NULL);
    if (ret != LDAP_SUCCESS) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "No config Entry? Impossible!\n");
        goto free_and_error;
    }
    config->passsync_mgrs = slapi_entry_attr_get_charray(config_entry, "passSyncManagersDNs");
    /* now add Directory Manager, it is always added by default */
    tmpstr = slapi_ch_strdup("cn=Directory Manager");
    slapi_ch_array_add(&config->passsync_mgrs, tmpstr);
    if (config->passsync_mgrs == NULL) {
        slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_getConfig",
                        "Out of memory!\n");
        goto free_and_error;
    }
    for (i = 0; config->passsync_mgrs[i]; i++) /* count */ ;
    config->num_passsync_mgrs = i;

    return config;

free_and_error:
    if (mkey) ber_bvfree(mkey);
    if (be) ber_free(be, 1);
    if (kmkey) {
        free(kmkey->contents);
        free(kmkey);
    }
    if (config) {
        if (config->krbctx) krb5_free_context(config->krbctx);
        free(config->pref_encsalts);
        free(config->supp_encsalts);
        free(config->passsync_mgrs);
        free(config);
    }
    if (realm_entry) slapi_entry_free(realm_entry);
    return NULL;
}

static int ipapwd_gen_checks(Slapi_PBlock *pb, char **errMesg,
                             struct ipapwd_krbcfg **config,
			     int check_secure_conn)
{
    int ret, sasl_ssf, is_ssl;
    int rc = LDAP_SUCCESS;

    slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_gen_checks\n");

#ifdef LDAP_EXTOP_PASSMOD_CONN_SECURE
    if (check_secure_conn) {
        /* Allow password modify only for SSL/TLS established connections and
         * connections using SASL privacy layers */
        if (slapi_pblock_get(pb, SLAPI_CONN_SASL_SSF, &sasl_ssf) != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
                            "Could not get SASL SSF from connection\n");
            *errMesg = "Operation requires a secure connection.\n";
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        if (slapi_pblock_get(pb, SLAPI_CONN_IS_SSL_SESSION, &is_ssl) != 0) {
            slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
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

    /* get the kerberos context and master key */
    *config = ipapwd_getConfig();
    if (NULL == *config) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
                        "Error Retrieving Master Key");
        *errMesg = "Fatal Internal Error";
        rc = LDAP_OPERATIONS_ERROR;
    }

done:
    return rc;
}

static int ipapwd_extop(Slapi_PBlock *pb)
{
	struct ipapwd_krbcfg *krbcfg = NULL;
	char *errMesg = NULL;
	char *oid = NULL;
	int rc, ret;

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_extop\n");

	rc = ipapwd_gen_checks(pb, &errMesg, &krbcfg, 1);
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
		slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop", errMesg);
		goto free_and_return;
	} else {
	        slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
				"Received extended operation request with OID %s\n", oid);
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
	slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop", errMesg);
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

/*****************************************************************************
 * pre/post operations to intercept writes to userPassword
 ****************************************************************************/

#define IPAPWD_OP_NULL 0
#define IPAPWD_OP_ADD 1
#define IPAPWD_OP_MOD 2
struct ipapwd_operation {
    struct ipapwd_data pwdata;
    int pwd_op;
    int is_krb;
};

/* structure with information for each extension */
struct ipapwd_op_ext {
    char *object_name;   /* name of the object extended   */
    int object_type;     /* handle to the extended object */
    int handle;          /* extension handle              */
};

static struct ipapwd_op_ext ipapwd_op_ext_list;

static void *ipapwd_op_ext_constructor(void *object, void *parent)
{
    struct ipapwd_operation *ext;

    ext = (struct ipapwd_operation *)slapi_ch_calloc(1, sizeof(struct ipapwd_operation));
    return ext;
}

static void ipapwd_op_ext_destructor(void *ext, void *object, void *parent)
{
    struct ipapwd_operation *pwdop = (struct ipapwd_operation *)ext;
    if (!pwdop)
        return;
    if (pwdop->pwd_op != IPAPWD_OP_NULL) {
        slapi_ch_free_string(&(pwdop->pwdata.dn));
        slapi_ch_free_string(&(pwdop->pwdata.password));

        /* target should never be set, but just in case ... */
        if (pwdop->pwdata.target)
            slapi_entry_free(pwdop->pwdata.target);
    }
    slapi_ch_free((void **)&pwdop);
}

static int ipapwd_entry_checks(Slapi_PBlock *pb, struct slapi_entry *e,
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

static int ipapwd_preop_gen_hashes(struct ipapwd_krbcfg *krbcfg,
                                   struct ipapwd_operation *pwdop,
                                   char *userpw,
                                   int is_krb, int is_smb,
                                   Slapi_Value ***svals,
                                   char **nthash, char **lmhash)
{
    int rc;

    if (is_krb) {

        pwdop->is_krb = 1;

        *svals = encrypt_encode_key(krbcfg, &pwdop->pwdata);

        if (!*svals) {
            slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                            "key encryption/encoding failed\n");
	    rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
    }

    if (is_smb) {
        char lm[33], nt[33];
        struct ntlm_keys ntlm;
        int ntlm_flags = 0;
        int ret;

        /* TODO: retrieve if we want to store the LM hash or not */
        ntlm_flags = KTF_LM_HASH | KTF_NT_HASH;

        ret = encode_ntlm_keys(userpw, ntlm_flags, &ntlm);
        if (ret) {
            slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                            "Failed to generate NT/LM hashes\n");
            rc = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        if (ntlm_flags & KTF_LM_HASH) {
            hexbuf(lm, ntlm.lm);
            lm[32] = '\0';
            *lmhash = slapi_ch_strdup(lm);
        }
        if (ntlm_flags & KTF_NT_HASH) {
            hexbuf(nt, ntlm.nt);
            nt[32] = '\0';
            *nthash = slapi_ch_strdup(nt);
        }
    }

    rc = LDAP_SUCCESS;

done:

    return rc;
}

/* PRE ADD Operation:
 * Gets the clean text password (fail the operation if the password came
 * pre-hashed, unless this is a replicated operation).
 * Check user is authorized to add it otherwise just returns, operation will
 * fail later anyway.
 * Run a password policy check.
 * Check if krb or smb hashes are required by testing if the krb or smb
 * objectclasses are present.
 * store information for the post operation
 */
static int ipapwd_pre_add(Slapi_PBlock *pb)
{
    struct ipapwd_krbcfg *krbcfg = NULL;
    char *errMesg = "Internal operations error\n";
    struct slapi_entry *e = NULL;
    char *userpw = NULL;
    char *dn = NULL;
    struct ipapwd_operation *pwdop = NULL;
    void *op;
    int is_repl_op, is_root, is_krb, is_smb;
    int ret, rc;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME, "=> ipapwd_pre_add\n");

    ret = slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl_op);
    if (ret != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* pass through if this is a replicated operation */
    if (is_repl_op)
        return 0;

    /* retrieve the entry */
    slapi_pblock_get(pb, SLAPI_ADD_ENTRY, &e);
    if (NULL == e)
        return 0;

    /* check this is something interesting for us first */
    userpw = slapi_entry_attr_get_charptr(e, SLAPI_USERPWD_ATTR);
    if (!userpw) {
	/* nothing interesting here */
	return 0;
    }

    /* Ok this is interesting,
     * Check this is a clear text password, or refuse operation */
    if ('{' == userpw[0]) {
        if (0 == strncasecmp(userpw, "{CLEAR}", strlen("{CLEAR}"))) {
            char *tmp = slapi_ch_strdup(&userpw[strlen("{CLEAR}")]);
            if (NULL == tmp) {
                slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                                "Strdup failed, Out of memory\n");
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            slapi_ch_free_string(&userpw);
            userpw = tmp;
        } else if (slapi_is_encoded(userpw)) {

            slapi_ch_free_string(&userpw);

            /* check if we have access to the unhashed user password */
            userpw = slapi_entry_attr_get_charptr(e, "unhashed#user#password");
            if (!userpw) {
                slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                "Pre-Encoded passwords are not valid\n");
                errMesg = "Pre-Encoded passwords are not valid\n";
                rc = LDAP_CONSTRAINT_VIOLATION;
                goto done;
            }
        }
    }

    rc = ipapwd_entry_checks(pb, e,
                             &is_root, &is_krb, &is_smb,
                             NULL, SLAPI_ACL_ADD);
    if (rc) {
        goto done;
    }

    rc = ipapwd_gen_checks(pb, &errMesg, &krbcfg, 0);
    if (rc) {
        goto done;
    }

    /* Get target DN */
    ret = slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn);
    if (ret) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* time to get the operation handler */
    ret = slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    if (ret != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop = slapi_get_object_extension(ipapwd_op_ext_list.object_type,
                                       op, ipapwd_op_ext_list.handle);
    if (NULL == pwdop) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop->pwd_op = IPAPWD_OP_ADD;
    pwdop->pwdata.password = slapi_ch_strdup(userpw);

    if (is_root) {
        pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
    } else {
        char *binddn;
        int i;

        pwdop->pwdata.changetype = IPA_CHANGETYPE_ADMIN;

        /* Check Bind DN */
        slapi_pblock_get(pb, SLAPI_CONN_DN, &binddn);

        /* if it is a passsync manager we also need to skip resets */
        for (i = 0; i < krbcfg->num_passsync_mgrs; i++) {
            if (strcasecmp(krbcfg->passsync_mgrs[i], binddn) == 0) {
                pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
                break;
            }
        }
    }

    pwdop->pwdata.dn = slapi_ch_strdup(dn);
    pwdop->pwdata.timeNow = time(NULL);
    pwdop->pwdata.target = e;

    ret = ipapwd_CheckPolicy(&pwdop->pwdata);
    if (ret) {
        errMesg = "Password Fails to meet minimum strength criteria";
        rc = LDAP_CONSTRAINT_VIOLATION;
        goto done;
    }

    if (is_krb || is_smb) {

        Slapi_Value **svals = NULL;
        char *nt = NULL;
        char *lm = NULL;

        rc = ipapwd_preop_gen_hashes(krbcfg,
                                     pwdop, userpw,
                                     is_krb, is_smb,
                                     &svals, &nt, &lm);
        if (rc) {
            goto done;
        }

        if (svals) {
            /* add/replace values in existing entry */
            ret = slapi_entry_attr_replace_sv(e, "krbPrincipalKey", svals);
            if (ret) {
                slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                                "failed to set encoded values in entry\n");
	        rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            ipapwd_free_slapi_value_array(&svals);
        }

        if (lm) {
            /* set value */
            slapi_entry_attr_set_charptr(e, "sambaLMPassword", lm);
            slapi_ch_free_string(&lm);
        }
        if (nt) {
            /* set value */
            slapi_entry_attr_set_charptr(e, "sambaNTPassword", nt);
            slapi_ch_free_string(&nt);
        }
    }

    /* we do not know if the entry pointer will still be valid after the op
     * make sure we do not reference it by mistake later on */
    pwdop->pwdata.target = NULL;

    rc = LDAP_SUCCESS;

done:
    free_ipapwd_krbcfg(&krbcfg);
    slapi_ch_free_string(&userpw);
    if (rc != LDAP_SUCCESS) {
        slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
        return -1;
    }
    return 0;
}

/* PRE MOD Operation:
 * Gets the clean text password (fail the operation if the password came
 * pre-hashed, unless this is a replicated operation).
 * Check user is authorized to add it otherwise just returns, operation will
 * fail later anyway.
 * Check if krb or smb hashes are required by testing if the krb or smb
 * objectclasses are present.
 * Run a password policy check.
 * store information for the post operation
 */
static int ipapwd_pre_mod(Slapi_PBlock *pb)
{
    struct ipapwd_krbcfg *krbcfg = NULL;
    char *errMesg = NULL;
    LDAPMod **mods;
    Slapi_Mod *smod, *tmod;
    Slapi_Mods *smods;
    char *userpw = NULL;
    char *unhashedpw = NULL;
    char *dn = NULL;
    Slapi_DN *tmp_dn;
    struct slapi_entry *e = NULL;
    struct ipapwd_operation *pwdop = NULL;
    void *op;
    int is_repl_op, is_pwd_op, is_root, is_krb, is_smb;
    int ret, rc;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME, "=> ipapwd_pre_mod\n");

    ret = slapi_pblock_get(pb, SLAPI_IS_REPLICATED_OPERATION, &is_repl_op);
    if (ret != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    /* pass through if this is a replicated operation */
    if (is_repl_op)
        return 0;

    /* grab the mods - we'll put them back later with
     * our modifications appended
     */
    slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &mods);
    smods = slapi_mods_new();
    slapi_mods_init_passin(smods, mods);

    /* In the first pass,
     * only check there is anything we are interested in */
    is_pwd_op = 0;
    tmod = slapi_mod_new();
    smod = slapi_mods_get_first_smod(smods, tmod);
    while (smod) {
        struct berval *bv;
        const char *type;
        int mop;

        type = slapi_mod_get_type(smod);
        if (slapi_attr_types_equivalent(type, SLAPI_USERPWD_ATTR)) {
            mop = slapi_mod_get_operation(smod);
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (mop & 0x0f) {
            case LDAP_MOD_ADD:
            case LDAP_MOD_REPLACE:
                is_pwd_op = 1;
            default:
                break;
            }
        }

        /* we check for unahsehd password here so that we are sure to catch them
         * early, before further checks go on, this helps checking
         * LDAP_MOD_DELETE operations in some corner cases later */
        /* we keep only the last one if multiple are provided for any absurd
	 * reason */
        if (slapi_attr_types_equivalent(type, "unhashed#user#password")) {
            bv = slapi_mod_get_first_value(smod);
            if (!bv) {
                slapi_mod_free(&tmod);
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            slapi_ch_free_string(&unhashedpw);
            unhashedpw = slapi_ch_malloc(bv->bv_len+1);
            if (!unhashedpw) {
                slapi_mod_free(&tmod);
                rc = LDAP_OPERATIONS_ERROR;
                goto done;
            }
            memcpy(unhashedpw, bv->bv_val, bv->bv_len);
            unhashedpw[bv->bv_len] = '\0';
        }
        slapi_mod_done(tmod);
        smod = slapi_mods_get_next_smod(smods, tmod);
    }
    slapi_mod_free(&tmod);

    /* If userPassword is not modified we are done here */
    if (! is_pwd_op) {
        rc = LDAP_SUCCESS;
        goto done;
    }

    /* OK swe have something interesting here, start checking for
     * pre-requisites */

    /* Get target DN */
    ret = slapi_pblock_get(pb, SLAPI_TARGET_DN, &dn);
    if (ret) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    tmp_dn = slapi_sdn_new_dn_byref(dn);
    if (tmp_dn) {
        /* xxxPAR: Ideally SLAPI_MODIFY_EXISTING_ENTRY should be
         * available but it turns out that is only true if you are
         * a dbm backend pre-op plugin - lucky dbm backend pre-op
         * plugins.
         * I think that is wrong since the entry is useful for filter
         * tests and schema checks and this plugin shouldn't be limited
         * to a single backend type, but I don't want that fight right
         * now so we go get the entry here
         *
         slapi_pblock_get( pb, SLAPI_MODIFY_EXISTING_ENTRY, &e);
         */
        ret = slapi_search_internal_get_entry(tmp_dn, 0, &e, ipapwd_plugin_id);
        slapi_sdn_free(&tmp_dn);
        if (ret != LDAP_SUCCESS) {
            slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                            "Failed tpo retrieve entry?!?\n");
           rc = LDAP_NO_SUCH_OBJECT;
           goto done;
        }
    }

    rc = ipapwd_entry_checks(pb, e,
                             &is_root, &is_krb, &is_smb,
                             SLAPI_USERPWD_ATTR, SLAPI_ACL_WRITE);
    if (rc) {
        goto done;
    }

    rc = ipapwd_gen_checks(pb, &errMesg, &krbcfg, 0);
    if (rc) {
        goto done;
    }

    /* run through the mods again and adjust flags if operations affect them */
    tmod = slapi_mod_new();
    smod = slapi_mods_get_first_smod(smods, tmod);
    while (smod) {
        struct berval *bv;
        const char *type;
        int mop;

        type = slapi_mod_get_type(smod);
        if (slapi_attr_types_equivalent(type, SLAPI_USERPWD_ATTR)) {
            mop = slapi_mod_get_operation(smod);
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (mop & 0x0f) {
            case LDAP_MOD_ADD:
                /* FIXME: should we try to track cases where we would end up
                 * with multiple userPassword entries ?? */
            case LDAP_MOD_REPLACE:
                is_pwd_op = 1;
                bv = slapi_mod_get_first_value(smod);
                if (!bv) {
                    slapi_mod_free(&tmod);
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                slapi_ch_free_string(&userpw);
                userpw = slapi_ch_malloc(bv->bv_len+1);
                if (!userpw) {
                    slapi_mod_free(&tmod);
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                memcpy(userpw, bv->bv_val, bv->bv_len);
                userpw[bv->bv_len] = '\0';
                break;
            case LDAP_MOD_DELETE:
                /* reset only if we are deleting all values, or the exact
                 * same value previously set, otherwise we are just trying to
                 * add a new value and delete an existing one */
                bv = slapi_mod_get_first_value(smod);
                if (!bv) {
                    is_pwd_op = 0;
                } else {
                    if (0 == strncmp(userpw, bv->bv_val, bv->bv_len) ||
                        0 == strncmp(unhashedpw, bv->bv_val, bv->bv_len))
                        is_pwd_op = 0;
                }
            default:
                break;
            }
        }

        if (slapi_attr_types_equivalent(type, SLAPI_ATTR_OBJECTCLASS)) {
            mop = slapi_mod_get_operation(smod);
            /* check op filtering out LDAP_MOD_BVALUES */
            switch (mop & 0x0f) {
            case LDAP_MOD_REPLACE:
                /* if objectclasses are replaced we need to start clean with
                 * flags, so we sero them out and see if they get set again */
                is_krb = 0;
                is_smb = 0;

            case LDAP_MOD_ADD:
                bv = slapi_mod_get_first_value(smod);
                if (!bv) {
                    slapi_mod_free(&tmod);
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                do {
                    if (0 == strncasecmp("krbPrincipalAux", bv->bv_val, bv->bv_len))
                        is_krb = 1;
                    if (0 == strncasecmp("sambaSamAccount", bv->bv_val, bv->bv_len))
                        is_smb = 1;
                } while ((bv = slapi_mod_get_next_value(smod)) != NULL);

                break;

            case LDAP_MOD_DELETE:
                /* can this happen for objectclasses ? */
                is_krb = 0;
                is_smb = 0;

            default:
                break;
            }
        }

        slapi_mod_done(tmod);
        smod = slapi_mods_get_next_smod(smods, tmod);
    }
    slapi_mod_free(&tmod);

    /* It seem like we have determined that the end result will be deletion of
     * the userPassword attribute, so we have no more business here */
    if (! is_pwd_op) {
        rc = LDAP_SUCCESS;
        goto done;
    }

    /* Check this is a clear text password, or refuse operation (only if we need
     * to comput other hashes */
    if (! unhashedpw) {
        if ('{' == userpw[0]) {
            if (0 == strncasecmp(userpw, "{CLEAR}", strlen("{CLEAR}"))) {
                unhashedpw = slapi_ch_strdup(&userpw[strlen("{CLEAR}")]);
                if (NULL == unhashedpw) {
                    slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                                    "Strdup failed, Out of memory\n");
                    rc = LDAP_OPERATIONS_ERROR;
                    goto done;
                }
                slapi_ch_free_string(&userpw);

            } else if (slapi_is_encoded(userpw)) {

                slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                "Pre-Encoded passwords are not valid\n");
                errMesg = "Pre-Encoded passwords are not valid\n";
                rc = LDAP_CONSTRAINT_VIOLATION;
                goto done;
            }
        }
    }

    /* time to get the operation handler */
    ret = slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    if (ret != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "slapi_pblock_get failed!?\n");
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop = slapi_get_object_extension(ipapwd_op_ext_list.object_type,
                                       op, ipapwd_op_ext_list.handle);
    if (NULL == pwdop) {
        rc = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    pwdop->pwd_op = IPAPWD_OP_MOD;
    pwdop->pwdata.password = slapi_ch_strdup(unhashedpw);
    pwdop->pwdata.changetype = IPA_CHANGETYPE_NORMAL;

    if (is_root) {
        pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
    } else {
        char *binddn;
        Slapi_DN *bdn, *tdn;
        int i;

        /* Check Bind DN */
        slapi_pblock_get(pb, SLAPI_CONN_DN, &binddn);
        bdn = slapi_sdn_new_dn_byref(binddn);
        tdn = slapi_sdn_new_dn_byref(dn);

        /* if the change is performed by someone else,
         * it is an admin change that will require a new
         * password change immediately as per our IPA policy */
        if (slapi_sdn_compare(bdn, tdn)) {
            pwdop->pwdata.changetype = IPA_CHANGETYPE_ADMIN;

            /* if it is a passsync manager we also need to skip resets */
            for (i = 0; i < krbcfg->num_passsync_mgrs; i++) {
                if (strcasecmp(krbcfg->passsync_mgrs[i], binddn) == 0) {
                    pwdop->pwdata.changetype = IPA_CHANGETYPE_DSMGR;
                    break;
                }
            }

        }

        slapi_sdn_free(&bdn);
        slapi_sdn_free(&tdn);

    }

    pwdop->pwdata.dn = slapi_ch_strdup(dn);
    pwdop->pwdata.timeNow = time(NULL);
    pwdop->pwdata.target = e;

    ret = ipapwd_CheckPolicy(&pwdop->pwdata);
    if (ret) {
        errMesg = "Password Fails to meet minimum strength criteria";
        rc = LDAP_CONSTRAINT_VIOLATION;
        goto done;
    }

    if (is_krb || is_smb) {

        Slapi_Value **svals = NULL;
        char *nt = NULL;
        char *lm = NULL;

        rc = ipapwd_preop_gen_hashes(krbcfg,
                                     pwdop, unhashedpw,
                                     is_krb, is_smb,
                                     &svals, &nt, &lm);
        if (rc) {
            goto done;
        }

        if (svals) {
            /* replace values */
            slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                      "krbPrincipalKey", svals);
            ipapwd_free_slapi_value_array(&svals);
        }

        if (lm) {
            /* replace value */
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                  "sambaLMPassword", lm);
            slapi_ch_free_string(&lm);
        }
        if (nt) {
            /* replace value */
            slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                                  "sambaNTPassword", nt);
            slapi_ch_free_string(&nt);
        }
    }

    rc = LDAP_SUCCESS;

done:
    free_ipapwd_krbcfg(&krbcfg);
    slapi_ch_free_string(&userpw); /* just to be sure */
    if (e) slapi_entry_free(e); /* this is a copy in this function */
    if (pwdop) pwdop->pwdata.target = NULL;

    if (rc != LDAP_SUCCESS) {
        slapi_mods_free(&smods);
        if (!pwdop) {
            slapi_ch_free_string(&unhashedpw);
            slapi_ch_free_string(&dn);
        }
        slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
        return -1;
    }

    /* put back a, possibly modified, set of mods */
    mods = slapi_mods_get_ldapmods_passout(smods);
    slapi_pblock_set(pb, SLAPI_MODIFY_MODS, mods);
    slapi_mods_free(&smods);

    return 0;
}

static int ipapwd_post_op(Slapi_PBlock *pb)
{
    char *errMesg = "Internal operations error\n";
    void *op;
    struct ipapwd_operation *pwdop = NULL;
    Slapi_Mods *smods;
    Slapi_Value **pwvals;
    struct tm utctime;
    char timestr[GENERALIZED_TIME_LENGTH+1];
    int ret;

    slapi_log_error(SLAPI_LOG_TRACE, IPAPWD_PLUGIN_NAME,
                    "=> ipapwd_post_add\n");

    /* time to get the operation handler */
    ret = slapi_pblock_get(pb, SLAPI_OPERATION, &op);
    if (ret != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, IPAPWD_PLUGIN_NAME,
                        "slapi_pblock_get failed!?\n");
        return 0;
    }

    pwdop = slapi_get_object_extension(ipapwd_op_ext_list.object_type,
                                       op, ipapwd_op_ext_list.handle);
    if (NULL == pwdop) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "Internal error, couldn't find pluginextension ?!\n");
        return 0;
    }

    /* not interesting */
    if (IPAPWD_OP_NULL == pwdop->pwd_op)
        return 0;

    if ( ! (pwdop->is_krb)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "Not a kerberos user, ignore krb attributes\n");
        return 0;
    }

    /* prepare changes that can be made only as root */
    smods = slapi_mods_new();

    /* change Last Password Change field with the current date */
    if (!gmtime_r(&(pwdop->pwdata.timeNow), &utctime)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "failed to parse current date (buggy gmtime_r ?)\n");
        slapi_mods_free(&smods);
        return 0;
    }
    strftime(timestr, GENERALIZED_TIME_LENGTH+1,
             "%Y%m%d%H%M%SZ", &utctime);
    slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "krbLastPwdChange", timestr);

    /* set Password Expiration date */
    if (!gmtime_r(&(pwdop->pwdata.expireTime), &utctime)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "failed to parse expiration date (buggy gmtime_r ?)\n");
        slapi_mods_free(&smods);
        return 0;
    }
    strftime(timestr, GENERALIZED_TIME_LENGTH+1,
             "%Y%m%d%H%M%SZ", &utctime);
    slapi_mods_add_string(smods, LDAP_MOD_REPLACE,
                          "krbPasswordExpiration", timestr);

    /* This was a mod operation on an existing entry, make sure we also update
     * the password history based on the entry we saved from the pre-op */
    if (IPAPWD_OP_MOD == pwdop->pwd_op) {
        Slapi_DN *tmp_dn = slapi_sdn_new_dn_byref(pwdop->pwdata.dn);
        if (tmp_dn) {
            ret = slapi_search_internal_get_entry(tmp_dn, 0,
                                                  &pwdop->pwdata.target,
                                                  ipapwd_plugin_id);
            slapi_sdn_free(&tmp_dn);
            if (ret != LDAP_SUCCESS) {
                slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                                "Failed tpo retrieve entry?!?\n");
                slapi_mods_free(&smods);
                return 0;
            }
        }
        pwvals = ipapwd_setPasswordHistory(smods, &pwdop->pwdata);
        if (pwvals) {
            slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE,
                                      "passwordHistory", pwvals);
        }
    }

    ret = ipapwd_apply_mods(pwdop->pwdata.dn, smods);
    if (ret)
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
           "Failed to set additional password attributes in the post-op!\n");

    slapi_mods_free(&smods);
    return 0;
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
	krb5_context krbctx;
	krb5_error_code krberr;
	char *realm;
	char *config_dn;
	char *partition_dn;
	Slapi_Entry *config_entry = NULL;
	int ret;

	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_start", "krb5_init_context failed\n");
		return LDAP_OPERATIONS_ERROR;
	}

	if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &config_dn) != 0) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No config DN?\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	if (ipapwd_getEntry(config_dn, &config_entry, NULL) != LDAP_SUCCESS) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No config Entry?\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	partition_dn = slapi_entry_attr_get_charptr(config_entry, "nsslapd-realmtree");
	if (!partition_dn) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Missing partition configuration entry (nsslapd-realmTree)!\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto done;
	}

	ret = krb5_get_default_realm(krbctx, &realm);
	if (ret) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Failed to get default realm?!\n");
		ret = LDAP_OPERATIONS_ERROR;
		goto done;
	}
	ipa_realm_dn = slapi_ch_smprintf("cn=%s,cn=kerberos,%s", realm, partition_dn);
	if (!ipa_realm_dn) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory ?\n");
		free(realm);
		ret = LDAP_OPERATIONS_ERROR;
		goto done;
	}
	free(realm);

    ipa_pwd_config_dn = slapi_ch_strdup(config_dn);
    if (!ipa_pwd_config_dn) {
        slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory ?\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }
    ipa_changepw_principal_dn =
        slapi_ch_smprintf("krbprincipalname=kadmin/changepw@%s,%s",
                          realm, ipa_realm_dn);
    if (!ipa_changepw_principal_dn) {
        slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory ?\n");
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = LDAP_SUCCESS;

done:
	krb5_free_context(krbctx);
	if (config_entry) slapi_entry_free(config_entry);
	return ret;
}


static int ipapwd_ext_init()
{
    int ret;

    ipapwd_op_ext_list.object_name = SLAPI_EXT_OPERATION;

    ret = slapi_register_object_extension(IPAPWD_PLUGIN_NAME,
                                          SLAPI_EXT_OPERATION,
                                          ipapwd_op_ext_constructor,
                                          ipapwd_op_ext_destructor,
                                          &ipapwd_op_ext_list.object_type,
                                          &ipapwd_op_ext_list.handle);

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

/* Init pre ops */
static int ipapwd_pre_init(Slapi_PBlock *pb)
{
    int ret;

    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&pdesc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN, (void *)ipapwd_pre_add);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN, (void *)ipapwd_pre_mod);

    return ret;
}

/* Init post ops */
static int ipapwd_post_init(Slapi_PBlock *pb)
{
    int ret;

    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&pdesc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN, (void *)ipapwd_post_op);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN, (void *)ipapwd_post_op);

    return ret;
}

/* Initialization function */
int ipapwd_init( Slapi_PBlock *pb )
{
    int ret;

    /* Get the arguments appended to the plugin extendedop directive. The first argument
     * (after the standard arguments for the directive) should contain the OID of the
     * extended operation. */

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ipapwd_plugin_id);
    if ((ret != 0) || (NULL == ipapwd_plugin_id)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "ipapwd_init",
                        "Could not get identity or identity was NULL\n");
        return -1;
    }

    if (ipapwd_ext_init() != 0) {
        slapi_log_error(SLAPI_LOG_PLUGIN, IPAPWD_PLUGIN_NAME,
                        "Object Extension Operation failed\n");
        return -1;
    }

    /* Register the plug-in function as an extended operation
     * plug-in function that handles the operation identified by
     * OID 1.3.6.1.4.1.4203.1.11.1 .  Also specify the version of the server
     * plug-in */
    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, (void *)ipapwd_start);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, (void *)&pdesc);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, ipapwd_oid_list);
    if (!ret) ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, ipapwd_name_list);
    if (!ret) slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN, (void *)ipapwd_extop);
    if (ret) {
        slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_init",
                 "Failed to set plug-in version, function, and OID.\n" );
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
