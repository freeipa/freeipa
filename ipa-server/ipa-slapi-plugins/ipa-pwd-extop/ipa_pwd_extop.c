/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 * 
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
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
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception. 
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
#include <krb5.h>
#include <lber.h>
#include <time.h>
#include <iconv.h>
#include <openssl/des.h>
#include <openssl/md4.h>

/* Type of connection for this operation;*/
#define LDAP_EXTOP_PASSMOD_CONN_SECURE

/* Uncomment the following line FOR TESTING: allows non-SSL connections to use the password change extended op */
/* #undef LDAP_EXTOP_PASSMOD_CONN_SECURE */

/* ber tags for the PasswdModifyRequestValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_USERID	0x80U
#define LDAP_EXTOP_PASSMOD_TAG_OLDPWD	0x81U
#define LDAP_EXTOP_PASSMOD_TAG_NEWPWD	0x82U

/* ber tags for the PasswdModifyResponseValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_GENPWD	0x80U

/* number of bytes used for random password generation */
#define LDAP_EXTOP_PASSMOD_GEN_PASSWD_LEN 8

/* number of random bytes needed to generate password */
#define LDAP_EXTOP_PASSMOD_RANDOM_BYTES	6

/* OID of the extended operation handled by this plug-in */
#define EXOP_PASSWD_OID	"1.3.6.1.4.1.4203.1.11.1"

/* These are thye default enc:salt ypes if nothing is defined.
 * TODO: retrieve the configure set of ecntypes either from the
 * kfc.conf file or by synchronizing the the file content into
 * the directory */

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

/* Salt types */
#define KRB5_KDB_SALTTYPE_NORMAL        0
#define KRB5_KDB_SALTTYPE_V4            1
#define KRB5_KDB_SALTTYPE_NOREALM       2
#define KRB5_KDB_SALTTYPE_ONLYREALM     3
#define KRB5_KDB_SALTTYPE_SPECIAL       4
#define KRB5_KDB_SALTTYPE_AFS3          5

#define KRB5P_SALT_SIZE 16

struct krb5p_keysalt {
	krb5_int32	enc_type;
	krb5_int32	salt_type;	
};

static void *ipapwd_plugin_id;


const char *ipa_realm_dn = NULL;
const char *ipa_realm = NULL;
struct krb5p_keysalt *ipa_keysalts = NULL;
int ipa_n_keysalts = 0;

Slapi_Mutex *ipa_globals = NULL;
krb5_keyblock *ipa_kmkey = NULL;

static int ipapwd_getMasterKey(const char *realm_dn);

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

struct kbvals {
	ber_int_t kvno;
	const struct berval *bval;
};

static int cmpkbvals(const void *p1, const void *p2)
{
	const struct kbvals *k1, *k2;

	k1 = (struct kbvals *)p1;
	k2 = (struct kbvals *)p2;

	return (((int)k1->kvno) - ((int)k2->kvno));
}

static inline void encode_int16(unsigned int val, unsigned char *p)
{
    p[1] = (val >>  8) & 0xff; 
    p[0] = (val      ) & 0xff; 
}

#define IPA_CHANGETYPE_NORMAL 0
#define IPA_CHANGETYPE_ADMIN 1
#define IPA_CHANGETYPE_DSMGR 2

struct ipapwd_data {
	Slapi_Entry *target;
	const char *dn;
	const char *password;
	time_t timeNow;
	time_t lastPwChange;
	time_t expireTime;
	int changetype;
	int pwHistoryLen;
};

static Slapi_Value **encrypt_encode_key(krb5_context krbctx, struct ipapwd_data *data)
{
	krb5_keyblock *kmkey;
	const char *krbPrincipalName;
	uint32_t krbMaxTicketLife;
	Slapi_Attr *krbPrincipalKey = NULL;
	struct kbvals *kbvals = NULL;
	time_t time_now;
	int kvno;
	int num_versions, num_keys;
	int krbTicketFlags;
	BerElement *be = NULL;
	struct berval *bval = NULL;
	Slapi_Value **svals = NULL;
	int svals_no;
	krb5_principal princ;
	krb5_error_code krberr;
	krb5_data pwd;
	int ret, i;

	slapi_lock_mutex(ipa_globals);
	kmkey = ipa_kmkey;
	slapi_unlock_mutex(ipa_globals);

	time_now = time(NULL);

	krbPrincipalName = slapi_entry_attr_get_charptr(data->target, "krbPrincipalName");
	if (!krbPrincipalName) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "no krbPrincipalName present in this entry\n");
		return NULL;
	}

	krbMaxTicketLife = slapi_entry_attr_get_uint(data->target, "krbMaxTicketLife");
	if (krbMaxTicketLife == 0) {
		/* FIXME: retrieve the default from config (max_life from kdc.conf) */
		krbMaxTicketLife = 86400; /* just set the default 24h for now */
	}

	kvno = 0;
	num_keys = 0;
	num_versions = 1;

	/* retrieve current kvno and and keys */
	ret = slapi_entry_attr_find(data->target, "krbPrincipalKey", &krbPrincipalKey);
	if (ret == 0) {
		int i, n, count, idx;
		ber_int_t tkvno;
		Slapi_ValueSet *svs;
		Slapi_Value *sv;
		ber_tag_t tag, tmp;
		const struct berval *cbval;

		slapi_attr_get_valueset(krbPrincipalKey, &svs);
		count = slapi_valueset_count(svs);
		if (count > 0) {
			kbvals = (struct kbvals *)calloc(count, sizeof(struct kbvals));
		}
		n = 0;
		for (i = 0, idx = 0; count > 0 && i < count; i++) {
			if (i == 0) {
				idx = slapi_valueset_first_value(svs, &sv);
			} else {
				idx = slapi_valueset_next_value(svs, idx, &sv);
			}
			if (idx == -1) {
				slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
						"Array of stored keys shorter than expected\n");
				break;
			}
			cbval = slapi_value_get_berval(sv);
			if (!cbval) {
				slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
						"Error retrieving berval from Slapi_Value\n");
				continue;
			}
			be = ber_init(cbval);
			if (!be) {
				slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
						"ber_init() failed!\n");
				continue;
			}

			tag = ber_scanf(be, "{xxt[i]", &tmp, &tkvno);
			if (tag == LBER_ERROR) {
				slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
						"Bad OLD key encoding ?!\n");
				ber_free(be, 1);
				continue;
			}

			kbvals[n].kvno = tkvno;
			kbvals[n].bval = cbval;
			n++;

			if (tkvno > kvno) {
				kvno = tkvno;
			}

			ber_free(be, 1);
		}
		num_keys = n;

		/* now verify how many keys we need to keep around */
		if (num_keys) {
			if (time_now > data->lastPwChange + krbMaxTicketLife) {
				/* the last password change was long ago,
				 * at most only the last entry need to be kept */
				num_versions = 2;
			} else {
				/* we don't know how many changes have happened since
				 * the oldest krbtgt was release, keep all + new */
				num_versions = num_keys + 1;
			}

			/* now reorder by kvno */
			if (num_keys > 1) {
				qsort(kbvals, num_keys, sizeof(struct kbvals), cmpkbvals);
			}
		}
	}

	/* increment kvno (will be 1 if this is a new entry) */
	kvno++;

	svals = (Slapi_Value **)calloc(num_versions + 1, sizeof(Slapi_Value *));
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "memory allocation failed\n");
		return NULL;
	}

	/* set all old keys to save */
	for (svals_no = 0; svals_no < (num_versions - 1); svals_no++) {
		int idx;

		idx = num_keys - (num_versions - 1) + svals_no;
		svals[svals_no] = slapi_value_new_berval(kbvals[idx].bval);
		if (!svals[svals_no]) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"Converting berval to Slapi_Value\n");
			goto enc_error;
		}
	}

	if (kbvals) free(kbvals);

	krberr = krb5_parse_name(krbctx, krbPrincipalName, &princ);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"krb5_parse_name failed [%s]\n",
				krb5_get_error_message(krbctx, krberr));
		goto enc_error;
	}

	krbTicketFlags = slapi_entry_attr_get_int(data->target, "krbTicketFlags");

	pwd.data = (char *)data->password;
	pwd.length = strlen(data->password);

	be = ber_alloc_t( LBER_USE_DER );

	if (!be) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"memory allocation failed\n");
		goto enc_error;
	}

	/* major-vno = 1 and minor-vno = 1 */
	/* this encoding assumes all keys have the same kvno */
	/* we also assum mkvno is 0 */
	ret = ber_printf(be, "{t[i]t[i]t[i]t[i]t[{",
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), 1,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1), 1,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2), kvno,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 3), 0,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 4));
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 vno info failed\n");
		goto enc_error;
	}

	for (i = 0; i < ipa_n_keysalts; i++) {
		krb5_keyblock key;
		krb5_data salt;
		krb5_octet *ptr;
		krb5_data plain;
		krb5_enc_data cipher;
		size_t len;
		const char *p;

		salt.data = NULL;

		switch (ipa_keysalts[i].salt_type) {

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
			if (krbTicketFlags & KTF_REQUIRES_PRE_AUTH) {
				salt.length = KRB5P_SALT_SIZE;
				krberr = krb5_c_random_make_octets(krbctx, &salt);
				if (!krberr) {
					slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
							"krb5_c_random_make_octets failed [%s]\n",
							krb5_get_error_message(krbctx, krberr));
					goto enc_error;
				}
			} else {
				krberr = krb5_principal2salt(krbctx, princ, &salt);
				if (krberr) {
					slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
							"krb5_principal2salt failed [%s]\n",
							krb5_get_error_message(krbctx, krberr));
					goto enc_error;
				}
			}
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
					"Invalid salt type [%d]\n", ipa_keysalts[i].salt_type);
			goto enc_error;
		}

		/* need to build the key now to manage the AFS salt.length special case */
		krberr = krb5_c_string_to_key(krbctx, ipa_keysalts[i].enc_type, &pwd, &salt, &key);
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

		krberr = krb5_c_encrypt_length(krbctx, kmkey->enctype, key.length, &len);
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

		krberr = krb5_c_encrypt(krbctx, kmkey, 0, 0, &plain, &cipher);
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
		if (salt.length) {
			ret = ber_printf(be, "{t[{t[i]t[o]}]",
						(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
							(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), ipa_keysalts[i].salt_type,
							(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1), salt.data, salt.length);
		} else {
			ret = ber_printf(be, "{t[{t[i]}]",
						(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
							(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), ipa_keysalts[i].salt_type);
		}
		if (ret == -1) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"encoding asn1 KrbSalt failed\n");
			krb5int_c_free_keyblock_contents(krbctx, &key);
			krb5_free_data_contents(krbctx, &salt);
			free(ptr);
			goto enc_error;
		}

		/* EncryptionKey */
		ret = ber_printf(be, "t[{t[i]t[o]}]}",
					(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
						(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), key.enctype,
						(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1), ptr, len+2);
		if (ret == -1) {
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
					"encoding asn1 EncryptionKey failed\n");
			krb5int_c_free_keyblock_contents(krbctx, &key);
			krb5_free_data_contents(krbctx, &salt);
			free(ptr);
			goto enc_error;
		}

		/* make sure we free the memory used now that we are done with it */
		krb5int_c_free_keyblock_contents(krbctx, &key);
		krb5_free_data_contents(krbctx, &salt);
		free(ptr);
	}

	ret = ber_printf(be, "}]}");
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 end of sequences failed\n");
		goto enc_error;
	}

	ret = ber_flatten(be, &bval);
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"flattening asn1 failed\n");
		goto enc_error;
	}

	svals[svals_no] = slapi_value_new_berval(bval);
	if (!svals[svals_no]) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"Converting berval to Slapi_Value\n");
		goto enc_error;
	}

	svals_no++;
	svals[svals_no] = NULL;

	krb5_free_principal(krbctx, princ);
	ber_bvfree(bval);
	ber_free(be, 1);
	return svals;

enc_error:
	krb5_free_principal(krbctx, princ);
	if (bval) ber_bvfree(bval);
	if (svals) free(svals);
	if (be) ber_free(be, 1);
	return NULL;
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
		slapi_free_search_results_internal(pb);
		slapi_sdn_free(&sdn);
		return -1;
	}

	/* get entries */
	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &es);
	if (!es) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_getPolicy: No entries ?!");
		slapi_free_search_results_internal(pb);
		slapi_sdn_free(&sdn);
		return -1;
	}

	/* count entries */
	for (i = 0; es[i]; i++) /* count */ ;

	/* if there is only one, return that */
	if (i == 1) {
		*e = slapi_entry_dup(es[0]);

		slapi_free_search_results_internal(pb);
		slapi_sdn_free(&sdn);
		return 0;
	}

	/* count number of RDNs in DN */
	edn = ldap_explode_dn(dn, 0);
	if (!edn) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_getPolicy: ldap_explode_dn(dn) failed ?!");
		slapi_free_search_results_internal(pb);
		slapi_sdn_free(&sdn);
		return -1;
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
		slapi_free_search_results_internal(pb);
		slapi_sdn_free(&sdn);
		return -1;
	}

	*e = slapi_entry_dup(pe);

	slapi_free_search_results_internal(pb);
	slapi_sdn_free(&sdn);
	return 0;
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
		Slapi_Value *pw;

		hint = 0;
		count = 0;
		ret = slapi_attr_get_numvalues(passwordHistory, &count);
		/* if we have one */
		if (count > 0) {
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
				pH[i] = slapi_value_dup(pw);
				i++;
				hint = slapi_attr_next_value(passwordHistory, hint, &pw);
			}

			qsort(pH, i, sizeof(Slapi_Value *), ipapwd_sv_pw_cmp);

			if (count > data->pwHistoryLen) {
				count = data->pwHistoryLen;
			}

			if (count == data->pwHistoryLen) {
				/* replace oldest */
				slapi_value_free(&pH[0]);
				i = 0;
			}

			pc = i;
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
	char *pwstr;

	pwstr = slapi_value_get_string(pw);
	if (strlen(pwstr) <= GENERALIZED_TIME_LENGTH) {
		/* not good, must be garbage, we never set histories without time */
		return NULL;
	}

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
	const char *krbPrincipalExpiration;
	const char *krbLastPwdChange;
	int krbMaxPwdLife = IPAPWD_DEFAULT_PWDLIFE;
	int krbPwdMinLength = IPAPWD_DEFAULT_MINLEN;
	int krbPwdMinDiffChars = 0;
	int krbMinPwdLife = 0;
	int pwdCharLen = 0;
	Slapi_Entry *policy = NULL;
	Slapi_Attr *passwordHistory = NULL;
	struct tm tm;
	int tmp, ret;

	/* check account is not expired */
	krbPrincipalExpiration = slapi_entry_attr_get_charptr(data->target, "krbPrincipalExpiration");
	if (krbPrincipalExpiration) {
		/* if expiration date set check it */
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

	if (data->changetype != IPA_CHANGETYPE_NORMAL) {
		/* We must skip policy checks (Admin change) but
		 * force a password change on the next login.
		 * But not if Directory Manager */
		if (data->changetype == IPA_CHANGETYPE_ADMIN) {
			data->expireTime = data->timeNow;
		}

		/* skip policy checks */
		goto no_policy;
	} 

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
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "Warning: Last Password Change Time is not available");
	}

	/* find the entry with the password policy */
	ret = ipapwd_getPolicy(data->dn, data->target, &policy);
	if (ret) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "No password policy");
		goto no_policy;
	}

	/* Check min age */
	krbMinPwdLife = slapi_entry_attr_get_int(policy, "krbMinPwdLife");
	/* if no default then treat it as no limit */
	if (krbMinPwdLife != 0) {

		if (data->timeNow < data->lastPwChange + krbMinPwdLife) {
			slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop",
				"ipapwd_checkPassword: Too soon to change password\n");
			slapi_entry_free(policy); 
			return IPAPWD_POLICY_ERROR | LDAP_PWPOLICY_PWDTOOYOUNG;
		}
	}

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
		int ret, hint, count, i;
		Slapi_Value **pH;
		Slapi_Value *pw;

		hint = 0;
		count = 0;
		i = 0;
		ret = slapi_attr_get_numvalues(passwordHistory, &count);
		/* check history only if we have one */
		if (count > 0) {
			pH = calloc(count + 1, sizeof(Slapi_Value *));
			if (!pH) {
				slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
						"ipapwd_checkPassword: Out of Memory\n");
				slapi_entry_free(policy); 
				return LDAP_OPERATIONS_ERROR;
			}

			hint = slapi_attr_first_value(passwordHistory, &pw);
			while (hint != -1) {
				pH[i] = ipapwd_strip_pw_date(pw);
				if (pH[i]) i++;
				hint = slapi_attr_next_value(passwordHistory, hint, &pw);
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

			slapi_value_free(&pw);

			for (i = 0; pH[i]; i++) {
				slapi_value_free(&pH[i]);
			}
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

	/* Retrieve History Len */
	data->pwHistoryLen = slapi_entry_attr_get_int(policy, "krbPwdHistoryLength");

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
static int ipapwd_SetPassword(struct ipapwd_data *data)
{
	int ret = 0, i = 0;
	Slapi_Mods *smods;
	Slapi_Value **svals;
	Slapi_Value **pwvals;
	struct tm utctime;
	char timestr[GENERALIZED_TIME_LENGTH+1];
	krb5_context krbctx;
	krb5_error_code krberr;
	char lm[33], nt[33];
	struct ntlm_keys ntlm;
	int ntlm_flags = 0;
	Slapi_Value *sambaSamAccount;
	char *userpwd;
	
	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "krb5_init_context failed\n");
		return LDAP_OPERATIONS_ERROR;
	}

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_SetPassword\n");

	smods = slapi_mods_new();

	/* generate kerberos keys to be put into krbPrincipalKey */
	svals = encrypt_encode_key(krbctx, data);
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "key encryption/encoding failed\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}
	/* done with it */
	krb5_free_context(krbctx);

	slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "krbPrincipalKey", svals);

	/* change Last Password Change field with the current date */
	if (!gmtime_r(&(data->timeNow), &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to retrieve current date (buggy gmtime_r ?)\n");
		free(svals);
		return LDAP_OPERATIONS_ERROR;
	}
	strftime(timestr, GENERALIZED_TIME_LENGTH+1, "%Y%m%d%H%M%SZ", &utctime);
	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastPwdChange", timestr);

	/* set Password Expiration date */
	if (!gmtime_r(&(data->expireTime), &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to convert expiration date\n");
		free(svals);
		return LDAP_OPERATIONS_ERROR;
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
			free(svals);
			free(password);
			return LDAP_OPERATIONS_ERROR;
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

	/* use the default configured encoding */
	userpwd = slapi_encode(data->password, NULL);
	if (!userpwd) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to make userPassword hash\n");
		free(svals);
		return LDAP_OPERATIONS_ERROR;
	}

	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "userPassword", userpwd);

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
 
	slapi_mods_free(&smods);

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipapwd_SetPassword: %d\n", ret);

	for (i = 0; svals[i]; i++) { 
		slapi_value_free(&svals[i]);
	}
	free(svals);
	for (i = 0; pwvals[i]; i++) { 
		slapi_value_free(&pwvals[i]);
	}
	free(pwvals);
	return ret;
}

#if 0 /* Not used right now */

/* Generate a new, basic random password */
static int ipapwd_generate_basic_passwd( int passlen, char **genpasswd )
{
	unsigned char *data = NULL;
	char *enc = NULL;
	int datalen = LDAP_EXTOP_PASSMOD_RANDOM_BYTES;
	int enclen = LDAP_EXTOP_PASSMOD_GEN_PASSWD_LEN + 1;

	if ( genpasswd == NULL ) {
		return LDAP_OPERATIONS_ERROR;
	}

	if ( passlen > 0 ) {
		datalen = passlen * 3 / 4 + 1;
		enclen = datalen * 4; /* allocate the large enough space */
	}

	data = (unsigned char *)slapi_ch_calloc( datalen, 1 );
	enc = (char *)slapi_ch_calloc( enclen, 1 );

	/* get random bytes from NSS */
	PK11_GenerateRandom( data, datalen );

	/* b64 encode the random bytes to get a password made up
	 * of printable characters. ldif_base64_encode() will
	 * zero-terminate the string */
	(void)ldif_base64_encode( data, enc, passlen, -1 );

	/* This will get freed by the caller */
	*genpasswd = slapi_ch_malloc( 1 + passlen );

	/* trim the password to the proper length */
	PL_strncpyz( *genpasswd, enc, passlen + 1 );

	slapi_ch_free( (void **)&data );
	slapi_ch_free_string( &enc );

	return LDAP_SUCCESS;
}
#endif

/* Password Modify Extended operation plugin function */
static int ipapwd_extop(Slapi_PBlock *pb)
{
	char		*oid = NULL;
	char 		*bindDN = NULL;
	char		*authmethod = NULL;
	char		*dn = NULL;
	char		*oldPasswd = NULL;
	char		*newPasswd = NULL;
	char		*errMesg = NULL;
	int             ret=0, rc=0, sasl_ssf=0, is_ssl=0, is_root=0;
	ber_tag_t	tag=0;
	ber_len_t	len=-1;
	struct berval	*extop_value = NULL;
	BerElement	*ber = NULL;
	Slapi_Entry *targetEntry=NULL;
	char *attrlist[] = {"*", "passwordHistory", NULL };
	struct ipapwd_data pwdata;

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_extop\n");

	/* make sure we have the master key */
	if (ipa_kmkey == NULL) {
		ret = ipapwd_getMasterKey(ipa_realm_dn);
		if (ret != LDAP_SUCCESS) {
			errMesg = "Fatal Internal Error Retrieving Master Key";
			rc = LDAP_OPERATIONS_ERROR;
			slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop", errMesg );
			goto free_and_return;
		}
	}
			
	/* Before going any further, we'll make sure that the right extended operation plugin
	 * has been called: i.e., the OID shipped whithin the extended operation request must 
	 * match this very plugin's OID: EXOP_PASSWD_OID. */
	if ( slapi_pblock_get( pb, SLAPI_EXT_OP_REQ_OID, &oid ) != 0 ) {
		errMesg = "Could not get OID value from request.\n";
		rc = LDAP_OPERATIONS_ERROR;
		slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop", 
				 errMesg );
		goto free_and_return;
	} else {
	        slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop", 
				 "Received extended operation request with OID %s\n", oid );
	}
	
	if ( strcasecmp( oid, EXOP_PASSWD_OID ) != 0) {
	        errMesg = "Request OID does not match Passwd OID.\n";
		rc = LDAP_OPERATIONS_ERROR;
		goto free_and_return;
	} else {
	        slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop", 
				 "Password Modify extended operation request confirmed.\n" );
	}
	
	/* Now , at least we know that the request was indeed a Password Modify one. */

#ifdef LDAP_EXTOP_PASSMOD_CONN_SECURE
	/* Allow password modify only for SSL/TLS established connections and
	 * connections using SASL privacy layers */
	if ( slapi_pblock_get(pb, SLAPI_CONN_SASL_SSF, &sasl_ssf) != 0) {
		errMesg = "Could not get SASL SSF from connection\n";
		rc = LDAP_OPERATIONS_ERROR;
		slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
				 errMesg );
		goto free_and_return;
	}

	if (slapi_pblock_get(pb, SLAPI_CONN_IS_SSL_SESSION, &is_ssl) != 0) {
		errMesg = "Could not get IS SSL from connection\n";
		rc = LDAP_OPERATIONS_ERROR;
		slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop",
				 errMesg );
		goto free_and_return;
	}
		
	if ( (is_ssl == 0) && (sasl_ssf <= 1) ) {
		errMesg = "Operation requires a secure connection.\n";
		rc = LDAP_CONFIDENTIALITY_REQUIRED;
		goto free_and_return;
	}
#endif

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
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed :{\n");
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
			slapi_ch_free_string(&oldPasswd);
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed :{\n");
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
			slapi_ch_free_string(&newPasswd);
			slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed :{\n");
			errMesg = "ber_scanf failed at newPasswd parse.\n";
			rc = LDAP_PROTOCOL_ERROR;
			goto free_and_return;
		}
	}

parse_req_done:	
	/* Uncomment for debugging, otherwise we don't want to leak the password values into the log... */
	/* LDAPDebug( LDAP_DEBUG_ARGS, "passwd: dn (%s), oldPasswd (%s) ,newPasswd (%s)\n",
					 dn, oldPasswd, newPasswd); */

	 
	 /* Get Bind DN */
	 slapi_pblock_get(pb, SLAPI_CONN_DN, &bindDN);

	 /* If the connection is bound anonymously, we must refuse to process this operation. */
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
		rc = LDAP_NO_SUCH_OBJECT ;
		goto free_and_return;
	 }
	 
	 /* First thing to do is to ask access control if the bound identity has
	    rights to modify the userpassword attribute on this entry. If not, then
		we fail immediately with insufficient access. This means that we don't
		leak any useful information to the client such as current password
		wrong, etc.
	  */

	is_root = slapi_dn_isroot(bindDN);
	slapi_pblock_set(pb, SLAPI_REQUESTOR_ISROOT, &is_root);

	/* In order to perform the access control check , we need to select a backend (even though
	 * we don't actually need it otherwise).
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

	ret = slapi_access_allowed ( pb, targetEntry, SLAPI_USERPWD_ATTR, NULL, SLAPI_ACL_WRITE );
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
		/* If user is authenticated, they already gave their password during
		the bind operation (or used sasl or client cert auth or OS creds) */
		slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "oldPasswd provided, but we will ignore it");
	}

	memset(&pwdata, 0, sizeof(pwdata));
	pwdata.target = targetEntry;
	pwdata.dn = dn;
	pwdata.password = newPasswd;
	pwdata.timeNow = time(NULL);
	pwdata.changetype = IPA_CHANGETYPE_NORMAL;

	/* determine type of password change */
	if (strcasecmp(dn, bindDN) != 0) {
		char **bindexp;

		pwdata.changetype = IPA_CHANGETYPE_ADMIN;
	
		bindexp = ldap_explode_dn(bindDN, 0);
		if (bindexp) {
			/* special case kpasswd and Directory Manager */
			if ((strncasecmp(bindexp[0], "krbprincipalname=kadmin/changepw@", 33) == 0) &&
			    (strcasecmp(&(bindexp[0][33]), ipa_realm) == 0)) {
				pwdata.changetype = IPA_CHANGETYPE_NORMAL;
			}
			if ((strcasecmp(bindexp[0], "cn=Directory Manager") == 0) &&
			    bindexp[1] == NULL) {
				pwdata.changetype = IPA_CHANGETYPE_DSMGR;
			}
			ldap_value_free(bindexp);
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
	ret = ipapwd_SetPassword(&pwdata);
	if (ret != LDAP_SUCCESS) {
		/* Failed to modify the password, e.g. because insufficient access allowed */
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

	if (targetEntry != NULL) {
		slapi_entry_free(targetEntry); 
	}
	
	if (ber != NULL) {
		ber_free(ber, 1);
		ber = NULL;
	}
	
	slapi_log_error(SLAPI_LOG_PLUGIN, "ipa_pwd_extop", 
			errMesg ? errMesg : "success");
	slapi_send_ldap_result(pb, rc, NULL, errMesg, 0, NULL);
	

	return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;

} /* ipapwd_extop */

/* Novell key-format scheme:
 KrbMKey ::= SEQUENCE {
 kvno    [0] UInt32,
 key     [1] MasterKey
 }

 MasterKey ::= SEQUENCE {
 keytype         [0] Int32,
 keyvalue        [1] OCTET STRING
 }
*/

static int ipapwd_getMasterKey(const char *realm_dn)
{
	krb5_keyblock *kmkey;
	Slapi_Attr *a;
	Slapi_Value *v;
	Slapi_Entry *realm_entry;
	BerElement *be;
	ber_tag_t tag, tmp;
	ber_int_t ttype;
	const struct berval *bval;
	struct berval *mkey;

	kmkey = malloc(sizeof(krb5_keyblock));
	if (!kmkey) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory!\n");
		return LDAP_OPERATIONS_ERROR;
	}

	if (ipapwd_getEntry(realm_dn, &realm_entry, NULL) != LDAP_SUCCESS) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No realm Entry?\n");
		free(kmkey);
		return LDAP_OPERATIONS_ERROR;
	}

	if (slapi_entry_attr_find(realm_entry, "krbMKey", &a) == -1) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No master key??\n");
		free(kmkey);
		slapi_entry_free(realm_entry);
		return LDAP_OPERATIONS_ERROR;
	}

	/* there should be only one value here */
	if (slapi_attr_first_value(a, &v) == -1) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No master key values??\n");
		free(kmkey);
		slapi_entry_free(realm_entry);
		return LDAP_OPERATIONS_ERROR;
	}

	bval = slapi_value_get_berval(v);
	if (!bval) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Error retrieving master key berval\n");
		free(kmkey);
		slapi_entry_free(realm_entry);
		return LDAP_OPERATIONS_ERROR;
	}

	be = ber_init(bval);
	if (!bval) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "ber_init() failed!\n");
		free(kmkey);
		slapi_entry_free(realm_entry);
		return LDAP_OPERATIONS_ERROR;
	}

	tag = ber_scanf(be, "{i{iO}}", &tmp, &ttype, &mkey);
	if (tag == LBER_ERROR) {
		slapi_log_error(SLAPI_LOG_TRACE, "ipapwd_start",
				"Bad Master key encoding ?!\n");
		free(kmkey);
		ber_free(be, 1);
		slapi_entry_free(realm_entry);
		return LDAP_OPERATIONS_ERROR;
	}

	kmkey->magic = KV5M_KEYBLOCK;
	kmkey->enctype = ttype;
	kmkey->length = mkey->bv_len;
	kmkey->contents = malloc(mkey->bv_len);
	if (!kmkey->contents) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory!\n");
		free(kmkey);
		ber_free(be, 1);
		slapi_entry_free(realm_entry);
		return LDAP_OPERATIONS_ERROR;
	}	
	memcpy(kmkey->contents, mkey->bv_val, mkey->bv_len);

	slapi_lock_mutex(ipa_globals);
	ipa_kmkey = kmkey;
	slapi_unlock_mutex(ipa_globals);

	slapi_entry_free(realm_entry);
	ber_bvfree(mkey);
	ber_free(be, 1);
	return LDAP_SUCCESS;
}


static char *ipapwd_oid_list[] = {
	EXOP_PASSWD_OID,
	NULL
};


static char *ipapwd_name_list[] = {
	"ipapwd_extop",
	NULL
};

/* will read this from the krbSupportedEncSaltTypes in the krbRealmContainer later on */
const char *krb_sup_encs[] = {
	"des3-hmac-sha1:normal",
	"arcfour-hmac:normal",
	"des-hmac-sha1:normal",
	"des-cbc-md5:normal",
	"des-cbc-crc:normal",
	"des-cbc-crc:v4",
	"des-cbc-crc:afs3",
	NULL
};

#define KRBCHECK(ctx, err, fname) do { \
		if (err) { \
			slapi_log_error(SLAPI_LOG_PLUGIN, "ipapwd_start", \
				"%s failed [%s]\n", fname, \
				krb5_get_error_message(ctx, err)); \
			return LDAP_OPERATIONS_ERROR; \
		} } while(0)

/* Init data structs */
/* TODO: read input from tree */
static int ipapwd_start( Slapi_PBlock *pb )
{
	int krberr, i;
	krb5_context krbctx;
	char *realm;
	char *realm_dn;
	char *config_dn;
	char *partition_dn;
	Slapi_Entry *config_entry;
	int ret;
	struct krb5p_keysalt *keysalts;
	int n_keysalts;

	ipa_globals = slapi_new_mutex();
	
	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipapwd_start", "krb5_init_context failed\n");
		return LDAP_OPERATIONS_ERROR;
	}
	if (krb5_get_default_realm(krbctx, &realm)) {
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}
	for (i = 0; krb_sup_encs[i]; i++) /* count */ ;
	keysalts = (struct krb5p_keysalt *)malloc(sizeof(struct krb5p_keysalt) * (i + 1));
	if (!keysalts) {
		krb5_free_context(krbctx);
		free(realm);
		return LDAP_OPERATIONS_ERROR;
	}

	for (i = 0, n_keysalts = 0; krb_sup_encs[i]; i++) {
		char *enc, *salt;
		krb5_int32 tmpenc;
		krb5_int32 tmpsalt;
		krb5_boolean similar;
		int j;

		enc = strdup(krb_sup_encs[i]);
		if (!enc) {
			slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_start", "Allocation error\n");
			krb5_free_context(krbctx);
			free(realm);
			return LDAP_OPERATIONS_ERROR;
		}
		salt = strchr(enc, ':');
		if (!salt) {
			slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_start", "Invalid krb5 enc string\n");
			free(enc);
			continue;
		}
		*salt = '\0'; /* null terminate the enc type */
		salt++; /* skip : */

		krberr = krb5_string_to_enctype(enc, &tmpenc);
		if (krberr) {
			slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_start", "Invalid krb5 enctype\n");
			free(enc);
			continue;
		}

		krberr = krb5_string_to_salttype(salt, &tmpsalt);
		for (j = 0; j < n_keysalts; j++) {
			krb5_c_enctype_compare(krbctx, keysalts[j].enc_type, tmpenc, &similar);
			if (similar && (keysalts[j].salt_type == tmpsalt)) {
				break;
			}
		}

		if (j == n_keysalts) {
			/* not found */
			keysalts[j].enc_type = tmpenc;
			keysalts[j].salt_type = tmpsalt;
			n_keysalts++;
		}

		free(enc);
	}

	krb5_free_context(krbctx);

	/*retrieve the master key from the stash file */
	if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &config_dn) != 0) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No config DN?\n");
		krb5_free_context(krbctx);
		free(keysalts);
		free(realm);
		return LDAP_OPERATIONS_ERROR;
	}

	if (ipapwd_getEntry(config_dn, &config_entry, NULL) != LDAP_SUCCESS) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No config Entry?\n");
		krb5_free_context(krbctx);
		free(keysalts);
		free(realm);
		return LDAP_OPERATIONS_ERROR;
	}

	partition_dn = slapi_entry_attr_get_charptr(config_entry, "nsslapd-realmtree");
	if (!partition_dn) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Missing partition configuration entry (nsslapd-targetSubtree)!\n");
		krb5_free_context(krbctx);
		slapi_entry_free(config_entry);
		free(keysalts);
		free(realm);
		return LDAP_OPERATIONS_ERROR;
	}

	realm_dn = slapi_ch_smprintf("cn=%s,cn=kerberos,%s", realm, partition_dn);
	if (!realm_dn) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Out of memory ?\n");
		free(keysalts);
		free(realm);
		return LDAP_OPERATIONS_ERROR;
	}

	ipa_realm = realm;
	ipa_realm_dn = realm_dn;
	ipa_keysalts = keysalts;
	ipa_n_keysalts = n_keysalts;

	ret = ipapwd_getMasterKey(ipa_realm_dn);
	if (ret) {
		slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_start", "Couldn't init master key at start delaying ...");
		ret = LDAP_SUCCESS;
	}

	slapi_entry_free(config_entry);
	return ret;
}

/* Initialization function */
int ipapwd_init( Slapi_PBlock *pb )
{
	/* Get the arguments appended to the plugin extendedop directive. The first argument 
	 * (after the standard arguments for the directive) should contain the OID of the
	 * extended operation.
	 */ 
	if ((slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ipapwd_plugin_id) != 0)
	 || (ipapwd_plugin_id == NULL)) {
		slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_init", "Could not get identity or identity was NULL\n");
		return( -1 );
	}

	/* Register the plug-in function as an extended operation
	 * plug-in function that handles the operation identified by
	 * OID 1.3.6.1.4.1.4203.1.11.1 .  Also specify the version of the server 
	 * plug-in */ 
	if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01 ) != 0 || 
	     slapi_pblock_set( pb, SLAPI_PLUGIN_START_FN, (void *) ipapwd_start ) != 0 ||
	     slapi_pblock_set( pb, SLAPI_PLUGIN_EXT_OP_FN, (void *) ipapwd_extop ) != 0 ||
	     slapi_pblock_set( pb, SLAPI_PLUGIN_EXT_OP_OIDLIST, ipapwd_oid_list ) != 0 ||
	     slapi_pblock_set( pb, SLAPI_PLUGIN_EXT_OP_NAMELIST, ipapwd_name_list ) != 0 ) {

		slapi_log_error( SLAPI_LOG_PLUGIN, "ipapwd_init",
				 "Failed to set plug-in version, function, and OID.\n" );
		return( -1 );
	}
	
	return( 0 );
}
