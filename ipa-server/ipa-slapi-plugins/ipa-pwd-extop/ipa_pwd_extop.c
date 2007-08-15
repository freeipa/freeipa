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

#include <prio.h>
#include <ssl.h>
#include <slapi-plugin.h>
#include <krb5.h>
#include <lber.h>
#include <time.h>
#include <iconv.h>
#include <mhash.h>
#include <openssl/des.h>

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

krb5_keyblock kmkey;

struct krb5p_keysalt *keysalts;
int n_keysalts;

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

static inline void encode_int16(unsigned int val, unsigned char *p)
{
    p[1] = (val >>  8) & 0xff; 
    p[0] = (val      ) & 0xff; 
}

static Slapi_Value **encrypt_encode_key(krb5_context krbctx, Slapi_Entry *e, const char *newPasswd)
{
	struct berval *bval = NULL;
	Slapi_Value **svals = NULL;
	BerElement *be = NULL;
	int num_versions;
	int krbTicketFlags;
	const char *krbPrincipalName;
	krb5_principal princ;
	krb5_error_code krberr;
	krb5_data pwd;
	int ret, i;

	krbPrincipalName = slapi_entry_attr_get_charptr(e, "krbPrincipalName");
	if (!krbPrincipalName) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "no krbPrincipalName present in this entry\n");
		return NULL;
	}

	/* TODO: retrieve current kvno and increment it */
	/* TODO: keep previous version */
	num_versions = 1;

	svals = (Slapi_Value **)calloc(num_versions + 1, sizeof(Slapi_Value *));
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "memory allocation failed\n");
		return NULL;
	}

	svals[1] = NULL;
	
	krberr = krb5_parse_name(krbctx, krbPrincipalName, &princ);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"krb5_parse_name failed [%s]\n",
				krb5_get_error_message(krbctx, krberr));
		goto enc_error;
	}

	krbTicketFlags = slapi_entry_attr_get_int(e, "krbTicketFlags");

	pwd.data = (char *)newPasswd;
	pwd.length = strlen(newPasswd);

	be = ber_alloc_t( LBER_USE_DER );

	if (!be) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"memory allocation failed\n");
		goto enc_error;
	}

	/* major-vno = 1 and minor-von = 1 */
	/* this encoding assumes all keys have the same kvno (currently set at 1) */
	/* we also assum mkvno is 0 */
	ret = ber_printf(be, "{t[i]t[i]t[i]t[i]t[{",
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), 1,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1), 1,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 2), 1,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 3), 0,
				(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 4));
	if (ret == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"encoding asn1 vno info failed\n");
		goto enc_error;
	}

	for (i = 0; i < n_keysalts; i++) {
		krb5_keyblock key;
		krb5_data salt;
		krb5_octet *ptr;
		krb5_data plain;
		krb5_enc_data cipher;
		size_t len;
		const char *p;

		salt.data = NULL;

		switch (keysalts[i].salt_type) {

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
					"Invalid salt type [%d]\n", keysalts[i].salt_type);
			goto enc_error;
		}

		/* need to build the key now to manage the AFS salt.length special case */
		krberr = krb5_c_string_to_key(krbctx, keysalts[i].enc_type, &pwd, &salt, &key);
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

		krberr = krb5_c_encrypt_length(krbctx, kmkey.enctype, key.length, &len);
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

		krberr = krb5_c_encrypt(krbctx, &kmkey, 0, 0, &plain, &cipher);
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
							(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), keysalts[i].salt_type,
							(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1), salt.data, salt.length);
		} else {
			ret = ber_printf(be, "{t[{t[i]}]",
						(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
							(ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0), keysalts[i].salt_type);
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

	svals[0] = slapi_value_new_berval(bval);
	if (!svals[0]) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop",
				"Converting berval to Slapi_Value\n");
		goto enc_error;
	}

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
		MHASH td;

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
		
		td = mhash_init(MHASH_MD4);
		if (td == MHASH_FAILED) {
			ret = -1;
			free(ucs2Passwd);
			goto done;
		}

		mhash(td, ucs2Passwd, sl);
		mhash_deinit(td, keys->nt);

	} else {
		memset(keys->nt, 0, 16);
	}

done:
	return ret;
}

/* Searches the dn in directory, 
 *  If found	 : fills in slapi_entry structure and returns 0
 *  If NOT found : returns the search result as LDAP_NO_SUCH_OBJECT
 */
static int 
ipapwd_getEntry( const char *dn, Slapi_Entry **e2 ) {
	int		search_result = 0;
	Slapi_DN 	*sdn;
	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_getEntry\n");

	sdn = slapi_sdn_new_dn_byref(dn);
	if ((search_result = slapi_search_internal_get_entry( sdn, NULL, e2,
 					ipapwd_plugin_id)) != LDAP_SUCCESS ){
	 slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "ipapwd_getEntry: No such entry-(%s), err (%d)\n",
					 dn, search_result);
	}

	slapi_sdn_free( &sdn );
	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipapwd_getEntry: %d\n", search_result);
	return search_result;
}


/* Construct Mods pblock and perform the modify operation 
 * Sets result of operation in SLAPI_PLUGIN_INTOP_RESULT 
 */
static int ipapwd_apply_mods(const char *dn, Slapi_Mods *mods) 
{
	Slapi_PBlock *pb;
	int ret=0;

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_apply_mods\n");

	if (mods && (slapi_mods_get_num_mods(mods) > 0)) 
	{
		pb = slapi_pblock_new();
		slapi_modify_internal_set_pb (pb, dn, 
		  slapi_mods_get_ldapmods_byref(mods),
		  NULL, /* Controls */
		  NULL, /* UniqueID */
		  ipapwd_plugin_id, /* PluginID */
		  0); /* Flags */ 

	 ret = slapi_modify_internal_pb (pb);

	 slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

	 if (ret != LDAP_SUCCESS){
	  slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "WARNING: modify error %d on entry '%s'\n",
			ret, dn);
	 }

	slapi_pblock_destroy(pb);
 	}
 
 	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipapwd_apply_mods: %d\n", ret);
 
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

/* Modify the userPassword attribute field of the entry */
static int ipapwd_userpassword(Slapi_Entry *targetEntry, const char *newPasswd)
{
	char *dn = NULL;
	int ret = 0, i = 0;
	Slapi_Mods *smods;
	Slapi_Value **svals;
	time_t curtime;
	struct tm utctime;
	char timestr[16];
	krb5_context krbctx;
	krb5_error_code krberr;
	char lm[33], nt[33];
	struct ntlm_keys ntlm;
	int ntlm_flags = 0;
	Slapi_Value *sambaSamAccount;
	
	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "krb5_init_context failed\n");
		return LDAP_OPERATIONS_ERROR;
	}

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipapwd_userpassword\n");

	smods = slapi_mods_new();
	dn = slapi_entry_get_ndn( targetEntry );

	/* generate kerberos keys to be put into krbPrincipalKey */
	svals = encrypt_encode_key(krbctx, targetEntry, newPasswd);
	if (!svals) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "key encryption/encoding failed\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}
	/* done with it */
	krb5_free_context(krbctx);

	slapi_mods_add_mod_values(smods, LDAP_MOD_REPLACE, "krbPrincipalKey", svals);

	/* change Last Password Change field with the current date */
	curtime = time(NULL);
	if (!gmtime_r(&curtime, &utctime)) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "failed to retrieve current date (buggy gmtime_r ?)\n");
		return LDAP_OPERATIONS_ERROR;
	}
	if (utctime.tm_year > 8099 || utctime.tm_mon > 11 || utctime.tm_mday > 31 ||
	    utctime.tm_hour > 23 || utctime.tm_min > 59 || utctime.tm_sec > 59) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "retrieved a bad date (buggy gmtime_r ?)\n");
		return LDAP_OPERATIONS_ERROR;
	}

	snprintf(timestr, 16, "%04d%02d%02d%02d%02d%02dZ", utctime.tm_year+1900, utctime.tm_mon+1,
		utctime.tm_mday, utctime.tm_hour, utctime.tm_min, utctime.tm_sec);

	slapi_mods_add_string(smods, LDAP_MOD_REPLACE, "krbLastPwdChange", timestr);
	/* TODO: krbPasswordExpiration, (krbMaxTicketLife, krbMaxRenewableAge, krbTicketFlags ?) */

	sambaSamAccount = slapi_value_new_string("sambaSamAccount");
	if (slapi_entry_attr_has_syntax_value(targetEntry, "objectClass", sambaSamAccount)) {
		/* TODO: retrieve if we want to store the LM hash or not */
		ntlm_flags = KTF_LM_HASH | KTF_NT_HASH;
	}
	slapi_value_free(&sambaSamAccount);

	if (ntlm_flags) {
		if (encode_ntlm_keys((char *)newPasswd, ntlm_flags, &ntlm) != 0) {
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
	}

	/* TODO !!!
	 * instead of replace we should use a delete/add so that we are
	 * completely sure nobody else modified the entry meanwhile and
	 * fail if that's the case */

	/* commit changes */
	ret = ipapwd_apply_mods(dn, smods);
 
	slapi_mods_free(&smods);

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipapwd_userpassword: %d\n", ret);

	for (i = 0; svals[i]; i++) { 
		slapi_value_free(&svals[i]);
	}
	free(svals);
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
int
ipapwd_extop( Slapi_PBlock *pb )
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
	/* Slapi_DN sdn; */

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "=> ipa_pwd_extop\n");

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
		
	if ( (is_ssl <=1) && (sasl_ssf <= 1) ) {
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
		if ( ber_scanf( ber, "a", &dn) == LBER_ERROR )
		{
		slapi_ch_free_string(&dn);
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed :{\n");
		errMesg = "ber_scanf failed at userID parse.\n";
		rc = LDAP_PROTOCOL_ERROR;
		goto free_and_return;
		}
		
		tag = ber_peek_tag( ber, &len);
	} 
	
	
	/* identify oldPasswd field by tags */
	if (tag == LDAP_EXTOP_PASSMOD_TAG_OLDPWD )
	{
		if ( ber_scanf( ber, "a", &oldPasswd ) == LBER_ERROR )
		{
		slapi_ch_free_string(&oldPasswd);
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "ber_scanf failed :{\n");
		errMesg = "ber_scanf failed at oldPasswd parse.\n";
		rc = LDAP_PROTOCOL_ERROR;
		goto free_and_return;
		}
		tag = ber_peek_tag( ber, &len);
	}
	
	/* identify newPasswd field by tags */
	if (tag ==  LDAP_EXTOP_PASSMOD_TAG_NEWPWD )
	{
		if ( ber_scanf( ber, "a", &newPasswd ) == LBER_ERROR )
		{
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
	 slapi_pblock_get( pb, SLAPI_CONN_DN, &bindDN );

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
	 ret = ipapwd_getEntry(dn, &targetEntry);
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
	

	/* Now we're ready to make actual password change */
	ret = ipapwd_userpassword(targetEntry, newPasswd);
	if (ret != LDAP_SUCCESS) {
		/* Failed to modify the password, e.g. because insufficient access allowed */
		errMesg = "Failed to update password\n";
		rc = ret;
		goto free_and_return;
	}

	slapi_log_error(SLAPI_LOG_TRACE, "ipa_pwd_extop", "<= ipa_pwd_extop: %d\n", rc);
	
	/* Free anything that we allocated above */
	free_and_return:
	slapi_ch_free_string(&oldPasswd);
	slapi_ch_free_string(&newPasswd);
	/* Either this is the same pointer that we allocated and set above,
	 * or whoever used it should have freed it and allocated a new
	 * value that we need to free here */
	slapi_pblock_get( pb, SLAPI_ORIGINAL_TARGET, &dn );
	slapi_ch_free_string(&dn);
	slapi_pblock_set( pb, SLAPI_ORIGINAL_TARGET, NULL );
	slapi_ch_free_string(&authmethod);

	if ( targetEntry != NULL ){
		slapi_entry_free (targetEntry); 
	}
	
	if ( ber != NULL ){
		ber_free(ber, 1);
		ber = NULL;
	}
	
	slapi_log_error( SLAPI_LOG_PLUGIN, "ipa_pwd_extop", 
			errMesg ? errMesg : "success" );
	slapi_send_ldap_result( pb, rc, NULL, errMesg, 0, NULL );
	

	return( SLAPI_PLUGIN_EXTENDED_SENT_RESULT );

}/* ipa_pwd_extop */


static char *ipapwd_oid_list[] = {
	EXOP_PASSWD_OID,
	NULL
};


static char *ipapwd_name_list[] = {
	"ipa_pwd_extop",
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
int ipapwd_start( Slapi_PBlock *pb )
{
	int krberr, i;
	krb5_context krbctx;
	char *config_dn;
	Slapi_Entry *config_entry;
	const char *stash_file;
	int fd;
	ssize_t r;
	uint16_t e;
	unsigned int l;
	unsigned char *o;

	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		slapi_log_error(SLAPI_LOG_FATAL, "ipa_pwd_extop", "krb5_init_context failed\n");
		return LDAP_OPERATIONS_ERROR;
	}

	for (i = 0; krb_sup_encs[i]; i++) /* count */ ;
	keysalts = (struct krb5p_keysalt *)malloc(sizeof(struct krb5p_keysalt) * (i + 1));
	if (!keysalts) {
		krb5_free_context(krbctx);
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

	/*retrieve the master key from the stash file */
	if (slapi_pblock_get(pb, SLAPI_TARGET_DN, &config_dn) != 0) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No config DN?\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}

	if (ipapwd_getEntry(config_dn, &config_entry) != LDAP_SUCCESS) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "No config Entry?\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}

	stash_file = slapi_entry_attr_get_charptr(config_entry, "nsslapd-pluginarg0");
	if (!stash_file) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Missing Master key stash file path configuration entry (nsslapd-pluginarg0)!\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}

	fd = open(stash_file, O_RDONLY);
	if (fd == -1) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Missing Master key stash file!\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}

	r = read(fd, &e, 2); /* read enctype a local endian 16bit value */
	if (r != 2) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Error reading Master key stash file!\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}

	r = read(fd, &l, sizeof(l)); /* read the key length, a horrible sizeof(int) local endian value */
	if (r != sizeof(l)) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Error reading Master key stash file!\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
	}

	if (l == 0 || l > 1024) { /* the maximum key size should be 32 bytes, lets's not accept more than 1k anyway */
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Invalid key lenght, Master key stash file corrupted?\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
        }

	o = malloc(l);
	if (!o) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Memory allocation problem!\n");
		krb5_free_context(krbctx);
		return LDAP_OPERATIONS_ERROR;
        }

	r = read(fd, o, l);
	if (r != l) {
		slapi_log_error( SLAPI_LOG_FATAL, "ipapwd_start", "Error reading Master key stash file!\n");
		krb5_free_context(krbctx);
                return LDAP_OPERATIONS_ERROR;
        }

	close(fd);

	kmkey.magic = KV5M_KEYBLOCK;
	kmkey.enctype = e;
	kmkey.length = l;
	kmkey.contents = o;

	krb5_free_context(krbctx);
	return LDAP_SUCCESS;
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
