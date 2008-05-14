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
#include <krb5.h>
#ifdef WITH_MOZLDAP
#include <mozldap/ldap.h>
#else
#include <ldap.h>
#endif
#include <sasl/sasl.h>
#include <popt.h>

static int ldap_sasl_interact(LDAP *ld, unsigned flags, void *priv_data, void *sit)
{
	sasl_interact_t *in = NULL;
	int ret = LDAP_OTHER;
	krb5_principal princ = (krb5_principal)priv_data;

	if (!ld) return LDAP_PARAM_ERROR;

	for (in = sit; in && in->id != SASL_CB_LIST_END; in++) {
		switch(in->id) {
		case SASL_CB_USER:
			in->result = princ->data[0].data;
			in->len = princ->data[0].length;
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
        return ret;
}

#define KEYTAB_SET_OID "2.16.840.1.113730.3.8.3.1"
#define KEYTAB_RET_OID "2.16.840.1.113730.3.8.3.2"

/* returns 0 if no enctypes available, >0 if enctypes are available */
static int get_enctypes(krb5_context krbctx, const char *str,
			krb5_enctype **ktypes)
{
	krb5_error_code krberr;
	krb5_enctype *types;
	char *p, *tmp, *t;
	int n, i, j;

	if (str == NULL) {
		krberr = krb5_get_permitted_enctypes(krbctx, ktypes);
		if (krberr) {
			fprintf(stderr, "No system preferred enctypes ?!\n");
			return 0;
		}
		return 1;
	}

	t = tmp = strdup(str);
	if (!tmp) return 0;

	/* count */
	p = t;
	while (p = strchr(t, ',')) {
		t = p+1;
		n++;
	}
	n++; /* count the last one that is 0 terminated instead */

	types = calloc(sizeof(krb5_enctype), n+1);
	if (!types) return 0;

	for (i = 0, j = 0, t = tmp; i < n; i++) {
		p = strchr(t, ',');
		if (p ) *p = '\0';
		krberr = krb5_string_to_enctype(t, &types[j]);
		if (krberr != 0) {
			fprintf(stderr,
				"Warning unrecognized encryption type: [%s]\n",
				t);
		} else {
			j++;
		}
		t = p+1;
	}

	free(tmp);
	*ktypes = types;

	return j;
}

static void free_keys(krb5_context krbctx, krb5_keyblock *keys, int num_keys)
{
	int i;

	for (i = 0; i < num_keys; i++) {
		krb5_free_keyblock_contents(krbctx, &keys[i]);
	}
	free(keys);
}

static int create_keys(krb5_context krbctx, krb5_enctype *ktypes,
			krb5_keyblock **keys)
{
	krb5_error_code krberr;
	krb5_keyblock *key;
	int i, j, k, max_keys;

	for (i = 0; ktypes[i]; i++) /* count max encodings */ ;
	max_keys = i;
	if (!max_keys) {
		fprintf(stderr, "No enctypes available\n");
		return 0;
	}

	key = calloc(max_keys, sizeof(krb5_keyblock));
	if (!key) {
		fprintf(stderr, "Out of Memory!\n");
		return 0;
	}

	k = 0; /* effective number of keys */

	for (i = 0; i < max_keys; i++) {
		krb5_boolean similar;

		/* Check we don't already have a key with a similar encoding,
		 * it would just produce redundant data and this is what the
		 * kerberos libs do anyway */
		similar = 0;
		for (j = 0; j < i; j++) {
			krberr = krb5_c_enctype_compare(krbctx, ktypes[i],
							ktypes[j], &similar);
			if (krberr) {
				free_keys(krbctx, key, i);
				fprintf(stderr, "Enctype comparison failed!\n");
				return 0;
			}
			if (similar) break;
		}
		if (similar) continue;

		krberr = krb5_c_make_random_key(krbctx, ktypes[i], &key[k]);
		if (krberr) {
			free_keys(krbctx, key, k);
			fprintf(stderr, "Making random key failed!\n");
			return 0;
		}
		k++;
	}

	*keys = key;
	return k;
}

static struct berval *create_key_control(krb5_keyblock *keys, int num_keys, const char *principalName)
{
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

	for (i = 0; i < num_keys; i++) {

		/* we set only the EncryptionKey, no salt or s2kparams */
		ret = ber_printf(be, "{t[{t[i]t[o]}]}",
				 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
				 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 0),
				 (ber_int_t)keys[i].enctype,
				 (ber_tag_t)(LBER_CONSTRUCTED | LBER_CLASS_CONTEXT | 1),
				 (char *)keys[i].contents, (ber_len_t)keys[i].length);

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

int filter_keys(krb5_context krbctx, krb5_keyblock *keys, int *num_keys, ber_int_t *enctypes)
{
	int ret, i, j, k;

	k = *num_keys;

	for (i = 0; i < k; i++) {
		for (j = 0; enctypes[j]; j++) {
			if (keys[i].enctype == enctypes[j]) break;
		}
		if (enctypes[j] == 0) { /* unsupported one */
			krb5_free_keyblock_contents(krbctx, &keys[i]);
			/* remove unsupported one */
			k--;
			for (j = i; j < k; j++) {
				keys[j] = keys[j + 1];
			}
			/* new key has been moved to this position, make sure
			 * we do not skip it, by neutralizing next i increment */
			i--;
		}
	}

	if (k == 0) {
		return -1;
	}

	*num_keys = k;
	return 0;
}

static int ldap_set_keytab(const char *servername,
			   const char *principal_name,
			   krb5_principal princ,
			   krb5_keyblock *keys,
			   int num_keys,
			   ber_int_t **enctypes)
{
	int version;
	LDAP *ld = NULL;
	BerElement *ctrl = NULL;
	BerElement *sctrl = NULL;
	struct berval *control = NULL;
	struct berval **ncvals;
	char *ldap_base = NULL;
	char *retoid = NULL;
	struct berval *retdata = NULL;
	struct timeval tv;
	LDAPMessage *entry, *res = NULL;
	LDAPControl **srvctrl = NULL;
	LDAPControl *pprc = NULL;
	char *err = NULL;
	int msgid;
	int ret, rc;
	int kvno, i;
	ber_tag_t rtag;
	struct berval bv;
	ber_int_t *encs = NULL;

	/* cant' return more than num_keys, sometimes less */
	encs = calloc(num_keys + 1, sizeof(ber_int_t));
	if (!encs) {
		fprintf(stderr, "Out of Memory!\n");
		return 0;
	}

	/* build password change control */
	control = create_key_control(keys, num_keys, principal_name);
	if (!control) {
		fprintf(stderr, "Failed to create control!\n");
		goto error_out;
	}

	/* TODO: support referrals ? */
	ld = ldap_init(servername, 389);
	if(ld == NULL) {
		fprintf(stderr, "Unable to initialize ldap library!\n");
		goto error_out;
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "Unable to set ldap options!\n");
		goto error_out;
	}

	ret = ldap_sasl_interactive_bind_s(ld,
					   NULL, "GSSAPI",
					   NULL, NULL,
					   LDAP_SASL_QUIET,
					   ldap_sasl_interact, princ);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "SASL Bind failed!\n");
		goto error_out;
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
		fprintf(stderr, "Operation failed! %s\n", ldap_err2string(ret));
		goto error_out;
	}

	ber_bvfree(control);
	control = NULL;

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	ret = ldap_result(ld, msgid, 1, &tv, &res);
	if (ret == -1) {
		fprintf(stderr, "Operation failed! %s\n", ldap_err2string(ret));
		goto error_out;
	}

	ret = ldap_parse_extended_result(ld, res, &retoid, &retdata, 0);
	if(ret != LDAP_SUCCESS) {
		fprintf(stderr, "Operation failed! %s\n", ldap_err2string(ret));
		goto error_out;
	}

	ret = ldap_parse_result(ld, res, &rc, NULL, &err, NULL, &srvctrl, 0);
        if(ret != LDAP_SUCCESS || rc != LDAP_SUCCESS) {
		fprintf(stderr, "Operation failed! %s\n", err?err:ldap_err2string(ret));
		goto error_out;
        }

	if (!srvctrl) {
		fprintf(stderr, "Missing reply control!\n");
		goto error_out;
	}

	for (i = 0; srvctrl[i]; i++) {
		if (0 == strcmp(srvctrl[i]->ldctl_oid, KEYTAB_RET_OID)) {
			pprc = srvctrl[i];
		}
	}
	if (!pprc) {
		fprintf(stderr, "Missing reply control!\n");
		goto error_out;
	}

	sctrl = ber_init(&pprc->ldctl_value);

	if (!sctrl) {
		fprintf(stderr, "ber_init() failed, Invalid control ?!\n");
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
		fprintf(stderr, "ber_scanf() failed, Invalid control ?!\n");
		goto error_out;
	}

	for (i = 0; i < num_keys; i++) {
		ret = ber_scanf(sctrl, "{i}", &encs[i]);
		if (ret == LBER_ERROR) break;
	}
	*enctypes = encs;

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

int main(int argc, char *argv[])
{
	static const char *server = NULL;
	static const char *principal = NULL;
	static const char *keytab = NULL;
	static const char *enctypes_string = NULL;
	int quiet = 0;
	int permitted_enctypes = 0;
        struct poptOption options[] = {
                { "server", 's', POPT_ARG_STRING, &server, 0, "Contact this specific KDC Server", "Server Name" },
                { "principal", 'p', POPT_ARG_STRING, &principal, 0, "The principal to get a keytab for (ex: ftp/ftp.example.com@EXAMPLE.COM)", "Kerberos Service Principal Name" },
                { "keytab", 'k', POPT_ARG_STRING, &keytab, 0, "File were to store the keytab information", "Keytab File Name" },
		{ "enctypes", 'e', POPT_ARG_STRING, &enctypes_string, 0, "Encryption types to request", "Comma separated encription types list" },
		{ "quiet", 'q', POPT_ARG_NONE, &quiet, 0, "Print as little as possible", "Output only on errors"},
		{ "permitted-enctypes", 0, POPT_ARG_NONE, &permitted_enctypes, 0, "Show the list of permitted encryption types and exit", "Permitted Encryption Types"},
		{ NULL, 0, POPT_ARG_NONE, NULL, 0, NULL, NULL }
	};
	poptContext pc;
	char *ktname;
	krb5_context krbctx;
	krb5_ccache ccache;
	krb5_principal uprinc;
	krb5_principal sprinc;
	krb5_error_code krberr;
	krb5_keyblock *keys = NULL;
	int num_keys = 0;
	ber_int_t *enctypes;
	krb5_enctype *ktypes;
	krb5_keytab kt;
	int kvno;
	int i, ret;

	krberr = krb5_init_context(&krbctx);
	if (krberr) {
		fprintf(stderr, "Kerberos context initialization failed\n");
		exit(1);
	}

	pc = poptGetContext("ipa-getkeytab", argc, (const char **)argv, options, 0);
	ret = poptGetNextOpt(pc);
	if (ret == -1 && permitted_enctypes &&
	    !(server || principal || keytab || quiet)) {
		char enc[79]; /* fit std terminal or truncate */

		krberr = krb5_get_permitted_enctypes(krbctx, &ktypes);
		if (krberr) {
			fprintf(stderr, "No system preferred enctypes ?!\n");
			exit(1);
		}
		fprintf(stdout, "Supported encryption types:\n");
		for (i = 0; ktypes[i]; i++) {
			krberr = krb5_enctype_to_string(ktypes[i], enc, 79);
			if (krberr) {
				fprintf(stderr, "Warning: failed to convert type (#%d)\n", i);
				continue;
			}
			fprintf(stdout, "%s\n", enc);
		}
		exit (0);
	}

	if (ret != -1 || !server || !principal || !keytab || permitted_enctypes) {
		if (!quiet) {
			poptPrintUsage(pc, stderr, 0);
		}
		exit(2);
	}

	ret = asprintf(&ktname, "WRFILE:%s", keytab);
	if (ret == -1) {
		exit(3);
	}

	krberr = krb5_parse_name(krbctx, principal, &sprinc);
	if (krberr) {
		fprintf(stderr, "Invalid Service Principal Name\n");
		exit(4);
	}

	krberr = krb5_cc_default(krbctx, &ccache);
	if (krberr) {
		fprintf(stderr, "Kerberos Credential Cache not found\n"
				"Do you have a Kerberos Ticket?\n");
		exit(5);
	}

	krberr = krb5_cc_get_principal(krbctx, ccache, &uprinc);
	if (krberr) {
		fprintf(stderr, "Kerberos User Principal not found\n"
				"Do you have a valid Credential Cache?\n");
		exit(6);
	}

	krberr = krb5_kt_resolve(krbctx, ktname, &kt);
	if (krberr) {
		fprintf(stderr, "Failed to open Keytab\n");
		exit(7);
	}

	/* create key material */
	ret = get_enctypes(krbctx, enctypes_string, &ktypes);
	if (ret == 0) {
		exit(8);
	}
	num_keys = create_keys(krbctx, ktypes, &keys);
	if (!num_keys) {
		fprintf(stderr, "Failed to create random key material\n");
		exit(8);
	}
	krb5_free_ktypes(krbctx, ktypes);

	kvno = ldap_set_keytab(server, principal, uprinc, keys, num_keys, &enctypes);
	if (!kvno) {
		exit(9);
	}

	ret = filter_keys(krbctx, keys, &num_keys, enctypes);
	if (ret == -1) {
		fprintf(stderr, "No keys accepted by the KDC!\n");
		exit(10);
	}

	for (i = 0; i < num_keys; i++) {
		krb5_keytab_entry kt_entry;
		memset((char *)&kt_entry, 0, sizeof(kt_entry));
		kt_entry.principal = sprinc;
		kt_entry.key = keys[i];
		kt_entry.vno = kvno;

		krberr = krb5_kt_add_entry(krbctx, kt, &kt_entry);
		if (krberr) {
			fprintf(stderr, "Failed to add key to the keytab\n");
			exit (11);
		}
	}

	free_keys(krbctx, keys, num_keys);

	krberr = krb5_kt_close(krbctx, kt);
	if (krberr) {
		fprintf(stderr, "Failed to close the keytab\n");
		exit (12);
	}

	if (!quiet) {
		fprintf(stderr,
			"Keytab successfully retrieved and stored in: %s\n",
			keytab);
	}
	exit(0);
}
