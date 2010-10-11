/* Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2007  Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2 only
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#define KRB5_PRIVATE 1
#include <krb5.h>
#ifdef WITH_MOZLDAP
#include <mozldap/ldap.h>
#else
#include <ldap.h>
#endif
#include <sasl/sasl.h>
#include <popt.h>

#include "config.h"
#include <libintl.h>
#define _(STRING) gettext(STRING)

/* Salt types */
#define NO_SALT                        -1
#define KRB5_KDB_SALTTYPE_NORMAL        0
#define KRB5_KDB_SALTTYPE_V4            1
#define KRB5_KDB_SALTTYPE_NOREALM       2
#define KRB5_KDB_SALTTYPE_ONLYREALM     3
#define KRB5_KDB_SALTTYPE_SPECIAL       4
#define KRB5_KDB_SALTTYPE_AFS3          5

#define KEYTAB_SET_OID "2.16.840.1.113730.3.8.3.1"
#define KEYTAB_RET_OID "2.16.840.1.113730.3.8.3.2"

struct krb_key_salt {
    krb5_enctype enctype;
    krb5_int32 salttype;
    krb5_keyblock key;
    krb5_data salt;
};

struct keys_container {
    krb5_int32 nkeys;
    struct krb_key_salt *ksdata;
};

static int ldap_sasl_interact(LDAP *ld, unsigned flags, void *priv_data, void *sit)
{
	sasl_interact_t *in = NULL;
	int ret = LDAP_OTHER;
	krb5_principal princ = (krb5_principal)priv_data;
	krb5_context krbctx;
	char *outname = NULL;

	if (!ld) return LDAP_PARAM_ERROR;

	krb5_init_context(&krbctx);

	for (in = sit; in && in->id != SASL_CB_LIST_END; in++) {
		switch(in->id) {
		case SASL_CB_USER:
			krb5_unparse_name(krbctx, princ, &outname);
			in->result = outname;
			in->len = strlen(outname);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			in->result = princ->realm.data;
			in->len = princ->realm.length;
			ret = LDAP_SUCCESS;
			break;
		default:
			in->result = NULL;
			in->len = 0;
			ret = LDAP_OTHER;
		}
	}
	krb5_free_context(krbctx);
	return ret;
}

static void free_keys_contents(krb5_context krbctx, struct keys_container *keys)
{
    struct krb_key_salt *ksdata;
    int i;

    ksdata = keys->ksdata;
    for (i = 0; i < keys->nkeys; i++) {
        krb5_free_keyblock_contents(krbctx, &ksdata[i].key);
        krb5_free_data_contents(krbctx, &ksdata[i].salt);
    }
    free(ksdata);

    keys->ksdata = NULL;
    keys->nkeys = 0;
}

/* Determines Encryption and Salt types,
 * allocates key_salt data storage,
 * filters out equivalent encodings,
 * returns 0 if no enctypes available, >0 if enctypes are available */
static int prep_ksdata(krb5_context krbctx, const char *str,
                       struct keys_container *keys)
{
    struct krb_key_salt *ksdata;
    krb5_error_code krberr;
    int n, i, j, nkeys;

    if (str == NULL) {
        krb5_enctype *ktypes;

        krberr = krb5_get_permitted_enctypes(krbctx, &ktypes);
        if (krberr) {
            fprintf(stderr, _("No system preferred enctypes ?!\n"));
            return 0;
        }

        for (n = 0; ktypes[n]; n++) /* count */ ;

        ksdata = calloc(n + 1, sizeof(struct krb_key_salt));
        if (NULL == ksdata) {
            fprintf(stderr, _("Out of memory!?\n"));
            return 0;
        }

        for (i = 0; i < n; i++) {
            ksdata[i].enctype = ktypes[i];
            ksdata[i].salttype = KRB5_KDB_SALTTYPE_NORMAL;
        }

        krb5_free_ktypes(krbctx, ktypes);

        nkeys = i;

    } else {
        char *tmp, *t, *p, *q;

        t = tmp = strdup(str);
        if (!tmp) {
            fprintf(stderr, _("Out of memory\n"));
            return 0;
        }

        /* count */
        n = 0;
        while ((p = strchr(t, ','))) {
            t = p+1;
            n++;
        }
        n++; /* count the last one that is 0 terminated instead */

        /* at the end we will have at most n entries + 1 terminating */
        ksdata = calloc(n + 1, sizeof(struct krb_key_salt));
        if (!ksdata) {
            fprintf(stderr, _("Out of memory\n"));
            return 0;
        }

        for (i = 0, j = 0, t = tmp; i < n; i++) {

            p = strchr(t, ',');
            if (p) *p = '\0';

            q = strchr(t, ':');
            if (q) *q++ = '\0';

            krberr = krb5_string_to_enctype(t, &ksdata[j].enctype);
            if (krberr != 0) {
                fprintf(stderr,
                        _("Warning unrecognized encryption type: [%s]\n"), t);
                t = p+1;
                continue;
            }
            t = p+1;

            if (!q) {
                ksdata[j].salttype = KRB5_KDB_SALTTYPE_NORMAL;
                j++;
                continue;
            }

            krberr = krb5_string_to_salttype(q, &ksdata[j].salttype);
            if (krberr != 0) {
                fprintf(stderr,
                        _("Warning unrecognized salt type: [%s]\n"), q);
                continue;
            }

            j++;
        }

        nkeys = j;

        free(tmp);
    }

    /* Check we don't already have a key with a similar encoding,
     * it would just produce redundant data and this is what the
     * MIT code do anyway */

    for (i = 0, n = 0; i < nkeys; i++ ) {
        int similar = 0;

        for (j = 0; j < i; j++) {
            krberr = krb5_c_enctype_compare(krbctx,
                                            ksdata[j].enctype,
                                            ksdata[i].enctype,
                                            &similar);
            if (krberr) {
                free_keys_contents(krbctx, keys);
                fprintf(stderr, _("Enctype comparison failed!\n"));
                return 0;
            }
            if (similar &&
                (ksdata[j].salttype == ksdata[i].salttype)) {
                break;
            }
        }
        if (j < i) {
            /* redundant encoding, remove it, and shift others */
            int x;
            for (x = i; x < nkeys-1; x++) {
                ksdata[x].enctype = ksdata[x+1].enctype;
                ksdata[x].salttype = ksdata[x+1].salttype;
            }
            continue;
        }
        /* count only confirmed enc/salt tuples */
        n++;
    }

    keys->nkeys = n;
    keys->ksdata = ksdata;

    return n;
}

static int create_keys(krb5_context krbctx,
                       krb5_principal princ,
                       char *password,
                       const char *enctypes_string,
                       struct keys_container *keys)
{
    struct krb_key_salt *ksdata;
    krb5_error_code krberr;
    krb5_data key_password;
    krb5_data *realm;
    int i, j, nkeys;
    int ret;

    ret = prep_ksdata(krbctx, enctypes_string, keys);
    if (ret == 0) return 0;

    ksdata = keys->ksdata;
    nkeys = keys->nkeys;

    if (password) {
        key_password.data = password;
        key_password.length = strlen(password);

        realm = krb5_princ_realm(krbctx, princ);
    }

    for (i = 0; i < nkeys; i++) {
        krb5_data *salt;

        if (!password) {
            /* cool, random keys */
            krberr = krb5_c_make_random_key(krbctx,
                                            ksdata[i].enctype,
                                            &ksdata[i].key);
            if (krberr) {
                fprintf(stderr, _("Failed to create random key!\n"));
                return 0;
            }
            /* set the salt to NO_SALT as the key was random */
            ksdata[i].salttype = NO_SALT;
            continue;
        }

        /* Make keys using password and required salt */
        switch (ksdata[i].salttype) {
        case KRB5_KDB_SALTTYPE_ONLYREALM:
            krberr = krb5_copy_data(krbctx, realm, &salt);
            if (krberr) {
                fprintf(stderr, _("Failed to create key!\n"));
                return 0;
            }

            ksdata[i].salt.length = salt->length;
            ksdata[i].salt.data = malloc(salt->length);
            if (!ksdata[i].salt.data) {
                fprintf(stderr, _("Out of memory!\n"));
                return 0;
            }
            memcpy(ksdata[i].salt.data, salt->data, salt->length);
            krb5_free_data(krbctx, salt);
            break;

        case KRB5_KDB_SALTTYPE_NOREALM:
            krberr = krb5_principal2salt_norealm(krbctx, princ, &ksdata[i].salt);
            if (krberr) {
                fprintf(stderr, _("Failed to create key!\n"));
                return 0;
            }
            break;

        case KRB5_KDB_SALTTYPE_NORMAL:
            krberr = krb5_principal2salt(krbctx, princ, &ksdata[i].salt);
            if (krberr) {
                fprintf(stderr, _("Failed to create key!\n"));
                return 0;
            }
            break;

        /* no KRB5_KDB_SALTTYPE_V4, we do not support krb v4 */

        case KRB5_KDB_SALTTYPE_AFS3:
            /* Comment from MIT sources:
             * * Why do we do this? Well, the afs_mit_string_to_key
             * * needs to use strlen, and the realm is not NULL
             * * terminated....
             */
            ksdata[i].salt.data = (char *)malloc(realm->length + 1);
            if (NULL == ksdata[i].salt.data) {
                fprintf(stderr, _("Out of memory!\n"));
                return 0;
            }
            memcpy((char *)ksdata[i].salt.data,
                   (char *)realm->data, realm->length);
            ksdata[i].salt.data[realm->length] = '\0';
            /* AFS uses a special length (UGLY) */
            ksdata[i].salt.length = SALT_TYPE_AFS_LENGTH;
            break;

        default:
            fprintf(stderr, _("Bad or unsupported salt type (%d)!\n"),
                ksdata[i].salttype);
            return 0;
        }

        krberr = krb5_c_string_to_key(krbctx,
                                      ksdata[i].enctype,
                                      &key_password,
                                      &ksdata[i].salt,
                                      &ksdata[i].key);
        if (krberr) {
            fprintf(stderr, _("Failed to create key!\n"));
            return 0;
        }

        /* set back salt length to real value if AFS3 */
        if (ksdata[i].salttype == KRB5_KDB_SALTTYPE_AFS3) {
            ksdata[i].salt.length = realm->length;
        }
    }

    return nkeys;
}

static struct berval *create_key_control(struct keys_container *keys,
                                         const char *principalName)
{
    struct krb_key_salt *ksdata;
    struct berval *bval;
    BerElement *be;
    int ret, i;

    be = ber_alloc_t(LBER_USE_DER);
    if (!be) {
        return NULL;
    }

    ret = ber_printf(be, "{s{", principalName);
    if (ret == -1) {
        ber_free(be, 1);
        return NULL;
    }

    ksdata = keys->ksdata;
    for (i = 0; i < keys->nkeys; i++) {

        /* we set only the EncryptionKey and salt, no s2kparams */

        ret = ber_printf(be, "{t[{t[i]t[o]}]",
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 (ber_int_t)ksdata[i].enctype,
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (char *)ksdata[i].key.contents, (ber_len_t)ksdata[i].key.length);

        if (ret == -1) {
            ber_free(be, 1);
            return NULL;
        }

        if (ksdata[i].salttype == NO_SALT) {
            ret = ber_printf(be, "}");
            continue;
        }

        /* we have to pass a salt structure */
        ret = ber_printf(be, "t[{t[i]t[o]}]}",
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
                 (ber_int_t)ksdata[i].salttype,
                 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
                 (char *)ksdata[i].salt.data, (ber_len_t)ksdata[i].salt.length);

        if (ret == -1) {
            ber_free(be, 1);
            return NULL;
        }
    }

    ret = ber_printf(be, "}}");
    if (ret == -1) {
        ber_free(be, 1);
        return NULL;
    }

    ret = ber_flatten(be, &bval);
    if (ret == -1) {
        ber_free(be, 1);
        return NULL;
    }

    ber_free(be, 1);
    return bval;
}

int filter_keys(krb5_context krbctx, struct keys_container *keys,
                ber_int_t *enctypes)
{
    struct krb_key_salt *ksdata;
    int i, j, n;

    n = keys->nkeys;
    ksdata = keys->ksdata;
    for (i = 0; i < n; i++) {
        if (ksdata[i].enctype == enctypes[i]) continue;
        if (enctypes[i] == 0) {
            /* remove unsupported one */
            krb5_free_keyblock_contents(krbctx, &ksdata[i].key);
            krb5_free_data_contents(krbctx, &ksdata[i].salt);
            for (j = i; j < n-1; j++) {
                keys[j] = keys[j + 1];
            }
            n--;
            /* new key has been moved to this position, make sure
             * we do not skip it, by neutralizing next i increment */
            i--;
        }
    }

    if (n == 0) {
        fprintf(stderr, _("No keys accepted by KDC\n"));
        return 0;
    }

    keys->nkeys = n;
    return n;
}

static int ipa_ldap_init(LDAP ** ld, const char * scheme, const char * servername, const int  port)
{
	char* url = NULL;
	int  url_len = snprintf(url,0,"%s://%s:%d",scheme,servername,port) +1;
       
	url = (char *)malloc (url_len);
	if (!url){
		fprintf(stderr, _("Out of memory \n"));
		return LDAP_NO_MEMORY;
	}
	sprintf(url,"%s://%s:%d",scheme,servername,port);
	int rc = ldap_initialize(ld, url);

	free(url);
	return rc;
}

static int ldap_set_keytab(krb5_context krbctx,
			   const char *servername,
			   const char *principal_name,
			   krb5_principal princ,
			   const char *binddn,
			   const char *bindpw,
			   struct keys_container *keys)
{
	int version;
	LDAP *ld = NULL;
	BerElement *sctrl = NULL;
	struct berval *control = NULL;
	char *retoid = NULL;
	struct berval *retdata = NULL;
	struct timeval tv;
	LDAPMessage *res = NULL;
	LDAPControl **srvctrl = NULL;
	LDAPControl *pprc = NULL;
	char *err = NULL;
	int msgid;
	int ret, rc;
	int kvno, i;
	ber_tag_t rtag;
	ber_int_t *encs = NULL;

	/* cant' return more than nkeys, sometimes less */
	encs = calloc(keys->nkeys + 1, sizeof(ber_int_t));
	if (!encs) {
		fprintf(stderr, _("Out of Memory!\n"));
		return 0;
	}

	/* build password change control */
	control = create_key_control(keys, principal_name);
	if (!control) {
		fprintf(stderr, _("Failed to create control!\n"));
		goto error_out;
	}

	/* TODO: support referrals ? */
	if (binddn) {
		int ssl = LDAP_OPT_X_TLS_HARD;;
		if (ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, "/etc/ipa/ca.crt") != LDAP_OPT_SUCCESS) {
			goto error_out;
		}
 
		if ( ipa_ldap_init(&ld, "ldaps",servername, 636) != LDAP_SUCCESS){
		  goto error_out;
		}
		if (ldap_set_option(ld, LDAP_OPT_X_TLS, &ssl) != LDAP_OPT_SUCCESS) {
			goto error_out;
		}
	} else {
		if (ipa_ldap_init(&ld, "ldap",servername, 389) != LDAP_SUCCESS){
			goto error_out;			
		}
	}

	if(ld == NULL) {
		fprintf(stderr, _("Unable to initialize ldap library!\n"));
		goto error_out;
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        if (ret != LDAP_SUCCESS) {
		fprintf(stderr, _("Unable to set ldap options!\n"));
		goto error_out;
	}

	if (binddn) {
		ret = ldap_bind_s(ld, binddn, bindpw, LDAP_AUTH_SIMPLE);
		if (ret != LDAP_SUCCESS) {
			fprintf(stderr, _("Simple bind failed\n"));
			goto error_out;
		}
	} else {
		ret = ldap_sasl_interactive_bind_s(ld,
						   NULL, "GSSAPI",
						   NULL, NULL,
						   LDAP_SASL_QUIET,
						   ldap_sasl_interact, princ);
		if (ret != LDAP_SUCCESS) {
			fprintf(stderr, _("SASL Bind failed!\n"));
			goto error_out;
		}
	}

	/* find base dn */
	/* TODO: address the case where we have multiple naming contexts */
	tv.tv_sec = 10;
	tv.tv_usec = 0;

	/* perform password change */
	ret = ldap_extended_operation(ld,
					KEYTAB_SET_OID,
					control, NULL, NULL,
					&msgid);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, _("Operation failed! %s\n"),
                                ldap_err2string(ret));
		goto error_out;
	}

	ber_bvfree(control);
	control = NULL;

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	ret = ldap_result(ld, msgid, 1, &tv, &res);
	if (ret == -1) {
		fprintf(stderr, _("Operation failed! %s\n"),
                                ldap_err2string(ret));
		goto error_out;
	}

	ret = ldap_parse_extended_result(ld, res, &retoid, &retdata, 0);
	if(ret != LDAP_SUCCESS) {
		fprintf(stderr, _("Operation failed! %s\n"),
                                ldap_err2string(ret));
		goto error_out;
	}

	ret = ldap_parse_result(ld, res, &rc, NULL, &err, NULL, &srvctrl, 0);
        if(ret != LDAP_SUCCESS || rc != LDAP_SUCCESS) {
		fprintf(stderr, _("Operation failed! %s\n"),
                                err ? err : ldap_err2string(ret));
		goto error_out;
        }

	if (!srvctrl) {
		fprintf(stderr, _("Missing reply control!\n"));
		goto error_out;
	}

	for (i = 0; srvctrl[i]; i++) {
		if (0 == strcmp(srvctrl[i]->ldctl_oid, KEYTAB_RET_OID)) {
			pprc = srvctrl[i];
		}
	}
	if (!pprc) {
		fprintf(stderr, _("Missing reply control!\n"));
		goto error_out;
	}

	sctrl = ber_init(&pprc->ldctl_value);

	if (!sctrl) {
		fprintf(stderr, _("ber_init() failed, Invalid control ?!\n"));
		goto error_out;
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

	rtag = ber_scanf(sctrl, "{i{", &kvno);
	if (rtag == LBER_ERROR) {
		fprintf(stderr, _("ber_scanf() failed, Invalid control ?!\n"));
		goto error_out;
	}

	for (i = 0; i < keys->nkeys; i++) {
		ret = ber_scanf(sctrl, "{i}", &encs[i]);
		if (ret == LBER_ERROR) break;
	}

	ret = filter_keys(krbctx, keys, encs);
	if (ret == 0) goto error_out;

	if (err) ldap_memfree(err);
	ber_free(sctrl, 1);
	ldap_controls_free(srvctrl);
	ldap_msgfree(res);
	ldap_unbind_ext(ld, NULL, NULL);
	return kvno;

error_out:
	if (sctrl) ber_free(sctrl, 1);
	if (srvctrl) ldap_controls_free(srvctrl);
	if (err) ldap_memfree(err);
	if (res) ldap_msgfree(res);
	if (ld) ldap_unbind_ext(ld, NULL, NULL);
	if (control) ber_bvfree(control);
	free(encs);
	return 0;
}

static char *ask_password(krb5_context krbctx)
{
    krb5_prompt ap_prompts[2];
    krb5_data k5d_pw0;
    krb5_data k5d_pw1;
    char pw0[256];
    char pw1[256];
    char *password;

    k5d_pw0.length = sizeof(pw0);
    k5d_pw0.data = pw0;
    ap_prompts[0].prompt = _("New Principal Password");
    ap_prompts[0].hidden = 1;
    ap_prompts[0].reply = &k5d_pw0;

    k5d_pw1.length = sizeof(pw1);
    k5d_pw1.data = pw1;
    ap_prompts[1].prompt = _("Verify Principal Password");
    ap_prompts[1].hidden = 1;
    ap_prompts[1].reply = &k5d_pw1;

    krb5_prompter_posix(krbctx, NULL,
                NULL, NULL,
                2, ap_prompts);

    if (strcmp(pw0, pw1)) {
        fprintf(stderr, _("Passwords do not match!"));
        return NULL;
    }

    password = malloc(k5d_pw0.length + 1);
    if (!password) return NULL;
    memcpy(password, pw0, k5d_pw0.length);
    password[k5d_pw0.length] = '\0';

    return password;
}

int init_gettext(void)
{
    char *c;

    c = setlocale(LC_ALL, "");
    if (!c) {
        return EIO;
    }

    errno = 0;
    c = bindtextdomain(PACKAGE, LOCALEDIR);
    if (c == NULL) {
        return errno;
    }

    errno = 0;
    c = textdomain(PACKAGE);
    if (c == NULL) {
        return errno;
    }

    return 0;
}

int main(int argc, char *argv[])
{
	static const char *server = NULL;
	static const char *principal = NULL;
	static const char *keytab = NULL;
	static const char *enctypes_string = NULL;
	static const char *binddn = NULL;
	static const char *bindpw = NULL;
	int quiet = 0;
	int askpass = 0;
	int permitted_enctypes = 0;
        struct poptOption options[] = {
            { "quiet", 'q', POPT_ARG_NONE, &quiet, 0,
              _("Print as little as possible"), _("Output only on errors")},
            { "server", 's', POPT_ARG_STRING, &server, 0,
              _("Contact this specific KDC Server"),
              _("Server Name") },
            { "principal", 'p', POPT_ARG_STRING, &principal, 0,
              _("The principal to get a keytab for (ex: ftp/ftp.example.com@EXAMPLE.COM)"),
              _("Kerberos Service Principal Name") },
            { "keytab", 'k', POPT_ARG_STRING, &keytab, 0,
              _("File were to store the keytab information"),
              _("Keytab File Name") },
	    { "enctypes", 'e', POPT_ARG_STRING, &enctypes_string, 0,
              _("Encryption types to request"),
              _("Comma separated encryption types list") },
	    { "permitted-enctypes", 0, POPT_ARG_NONE, &permitted_enctypes, 0,
              _("Show the list of permitted encryption types and exit"),
              _("Permitted Encryption Types") },
	    { "password", 'P', POPT_ARG_NONE, &askpass, 0,
              _("Asks for a non-random password to use for the principal") },
	    { "binddn", 'D', POPT_ARG_STRING, &binddn, 0,
              _("LDAP DN"), _("DN to bind as if not using kerberos") },
	    { "bindpw", 'w', POPT_ARG_STRING, &bindpw, 0,
              _("LDAP password"), _("password to use if not using kerberos") },
            POPT_AUTOHELP
            POPT_TABLEEND
	};
	poptContext pc;
	char *ktname;
	char *password = NULL;
	krb5_context krbctx;
	krb5_ccache ccache;
	krb5_principal uprinc;
	krb5_principal sprinc;
	krb5_error_code krberr;
	ber_int_t *enctypes;
	struct keys_container keys;
	krb5_keytab kt;
	int kvno;
	int i, ret;

    ret = init_gettext();
    if (ret) {
        exit(1);
    }

	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		fprintf(stderr, _("Kerberos context initialization failed\n"));
		exit(1);
	}

	pc = poptGetContext("ipa-getkeytab", argc, (const char **)argv, options, 0);
	ret = poptGetNextOpt(pc);
	if (ret == -1 && permitted_enctypes &&
	    !(server || principal || keytab || quiet)) {
		krb5_enctype *ktypes;
		char enc[79]; /* fit std terminal or truncate */

		krberr = krb5_get_permitted_enctypes(krbctx, &ktypes);
		if (krberr) {
			fprintf(stderr, _("No system preferred enctypes ?!\n"));
			exit(1);
		}
		fprintf(stdout, _("Supported encryption types:\n"));
		for (i = 0; ktypes[i]; i++) {
			krberr = krb5_enctype_to_string(ktypes[i], enc, 79);
			if (krberr) {
				fprintf(stderr, _("Warning: "
                                        "failed to convert type (#%d)\n"), i);
				continue;
			}
			fprintf(stdout, "%s\n", enc);
		}
		krb5_free_ktypes(krbctx, ktypes);
		exit (0);
	}

	if (ret != -1 || !server || !principal || !keytab || permitted_enctypes) {
		if (!quiet) {
			poptPrintUsage(pc, stderr, 0);
		}
		exit(2);
	}

	if (NULL!=binddn && NULL==bindpw) {
		fprintf(stderr,
                        _("Bind password required when using a bind DN.\n"));
		if (!quiet)
			poptPrintUsage(pc, stderr, 0);
		exit(10);
	}

        if (askpass) {
		password = ask_password(krbctx);
		if (!password) {
			exit(2);
		}
	} else if (enctypes_string && strchr(enctypes_string, ':')) {
		if (!quiet) {
			fprintf(stderr, _("Warning: salt types are not honored"
                                " with randomized passwords (see opt. -P)\n"));
		}
	}

	ret = asprintf(&ktname, "WRFILE:%s", keytab);
	if (ret == -1) {
		exit(3);
	}

	krberr = krb5_parse_name(krbctx, principal, &sprinc);
	if (krberr) {
		fprintf(stderr, _("Invalid Service Principal Name\n"));
		exit(4);
	}

	if (NULL == bindpw) {
		krberr = krb5_cc_default(krbctx, &ccache);
		if (krberr) {
			fprintf(stderr,
                                _("Kerberos Credential Cache not found. "
				  "Do you have a Kerberos Ticket?\n"));
			exit(5);
		}

		krberr = krb5_cc_get_principal(krbctx, ccache, &uprinc);
		if (krberr) {
			fprintf(stderr,
                                _("Kerberos User Principal not found. "
				  "Do you have a valid Credential Cache?\n"));
			exit(6);
		}
	}

	krberr = krb5_kt_resolve(krbctx, ktname, &kt);
	if (krberr) {
		fprintf(stderr, _("Failed to open Keytab\n"));
		exit(7);
	}

	/* create key material */
	ret = create_keys(krbctx, sprinc, password, enctypes_string, &keys);
	if (!ret) {
		fprintf(stderr, _("Failed to create key material\n"));
		exit(8);
	}

	kvno = ldap_set_keytab(krbctx, server, principal, uprinc, binddn, bindpw, &keys);
	if (!kvno) {
		exit(9);
	}

	for (i = 0; i < keys.nkeys; i++) {
		krb5_keytab_entry kt_entry;
		memset((char *)&kt_entry, 0, sizeof(kt_entry));
		kt_entry.principal = sprinc;
		kt_entry.key = keys.ksdata[i].key;
		kt_entry.vno = kvno;

		krberr = krb5_kt_add_entry(krbctx, kt, &kt_entry);
		if (krberr) {
			fprintf(stderr,
                                _("Failed to add key to the keytab\n"));
			exit (11);
		}
	}

	free_keys_contents(krbctx, &keys);

	krberr = krb5_kt_close(krbctx, kt);
	if (krberr) {
		fprintf(stderr, _("Failed to close the keytab\n"));
		exit (12);
	}

	if (!quiet) {
		fprintf(stderr,
			_("Keytab successfully retrieved and stored in: %s\n"),
			keytab);
	}
	exit(0);
}
