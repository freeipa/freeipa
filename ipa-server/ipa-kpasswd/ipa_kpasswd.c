
/* Kpasswd-LDAP proxy */

/* Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2007, 2008  Red Hat
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
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <krb5.h>
#ifdef WITH_MOZLDAP
#include <mozldap/ldap.h>
#else
#define LDAP_DEPRECATED 1
#include <ldap.h>
#endif
#include <sasl/sasl.h>
#include <ifaddrs.h>

#define DEFAULT_KEYTAB "FILE:/var/kerberos/krb5kdc/kpasswd.keytab"
#define TMP_TEMPLATE "/var/cache/ipa/kpasswd/krb5_cc.XXXXXX"
#define KPASSWD_PORT 464

#ifdef WITH_MOZLDAP
/* From OpenLDAP's ldap.h */
#define LDAP_TAG_EXOP_MODIFY_PASSWD_ID  ((ber_tag_t) 0x80U)
#define LDAP_TAG_EXOP_MODIFY_PASSWD_NEW ((ber_tag_t) 0x82U)
#endif

/* blacklist entries are released only BLCAKLIST_TIMEOUT seconds
 * after the children performing the noperation has finished.
 * this is to avoid races */

#define BLACKLIST_TIMEOUT 5

struct blacklist {
	struct blacklist *next;
	char *address;
	pid_t pid;
	time_t expire;
};

static struct blacklist *global_blacklist = NULL;

struct socklist {
	int fd;
	int socktype;
	int dest_addr_len;
	struct sockaddr_storage dest_addr;
	struct socklist *next;
};

int check_blacklist(char *address)
{
	struct blacklist *bl, *prev_bl;
	time_t now = time(NULL);

	if (!global_blacklist) {
		return 0;
	}

	prev_bl = NULL;
	bl = global_blacklist;
	while (bl) {
		if (bl->expire && (bl->expire < now)) {
			if (prev_bl) {
				prev_bl->next = bl->next;
				free(bl->address);
				free(bl);
				bl = prev_bl->next;
			} else {
				global_blacklist = bl->next;
				free(bl->address);
				free(bl);
				bl = global_blacklist;
			}
			continue;
		}

		if (strcmp(address, bl->address) == 0) {
			return 1;
		}

		prev_bl = bl;
		bl = bl->next;
	}

	return 0;
}

int add_blacklist(pid_t pid, char *address)
{
	struct blacklist *bl, *gbl;

	bl = malloc(sizeof(struct blacklist));
	if (!bl) return -1;

	bl->next = NULL;
	bl->pid = pid;
	bl->expire = 0;
	bl->address = strdup(address);
	if (!bl->address) {
		free(bl);
		return -1;
	}

	if (!global_blacklist) {
		global_blacklist = bl;
		return 0;
	}

	gbl = global_blacklist;
	while (gbl->next) {
		gbl = gbl->next;
	}
	gbl->next = bl;
	return 0;
}

int remove_blacklist(pid_t pid)
{
	struct blacklist *bl;

	if (!global_blacklist) {
		return -1;
	}

	bl = global_blacklist;
	while (bl) {
		if (pid == bl->pid) {
			bl->expire = time(NULL) + BLACKLIST_TIMEOUT;
			return 0;
		}
		bl = bl->next;
	}
	return -1;
}

int debug = 0;
char *srv_pri_name = "kadmin/changepw";
char *keytab_name = NULL;

static int get_krb5_ticket(char *tmp_file)
{
	char *ccname;
	char *realm_name = NULL;
	krb5_context context = NULL;
	krb5_keytab keytab = NULL;
	krb5_ccache ccache = NULL;
	krb5_principal kprincpw;
	krb5_creds my_creds;
	krb5_get_init_creds_opt options;
	int krberr, ret;

	krberr = krb5_init_context(&context);
	if (krberr) {
		syslog(LOG_ERR, "Failed to init kerberos context");
		return -1;
	}

	krberr = krb5_get_default_realm(context, &realm_name);
	if (krberr) {
		syslog(LOG_ERR, "Failed to get default realm name: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	krberr = krb5_build_principal(context, &kprincpw,
				      strlen(realm_name), realm_name,
				      "kadmin", "changepw", NULL);
	if (krberr) {
		syslog(LOG_ERR, "Unable to build principal: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	krberr = krb5_kt_resolve(context, keytab_name, &keytab);
	if (krberr) {
		syslog(LOG_ERR, "Failed to read keytab file: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	ret = asprintf(&ccname, "FILE:%s", tmp_file);
	if (ret == -1) {
		syslog(LOG_ERR, "Out of memory!");
		goto done;
	}

	ret = setenv("KRB5CCNAME", ccname, 1);
	if (ret == -1) {
		syslog(LOG_ERR, "Unable to set env. variable KRB5CCNAME!");
		goto done;
	}

	krberr = krb5_cc_resolve(context, ccname, &ccache);
	if (krberr) {
		syslog(LOG_ERR, "Failed to set cache name: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	memset(&my_creds, 0, sizeof(my_creds));
	memset(&options, 0, sizeof(options));

	krb5_get_init_creds_opt_set_address_list(&options, NULL);
	krb5_get_init_creds_opt_set_forwardable(&options, 0);
	krb5_get_init_creds_opt_set_proxiable(&options, 0);
	/* set a very short lifetime, we don't keep the ticket around */
	krb5_get_init_creds_opt_set_tkt_life(&options, 300);

	krberr = krb5_get_init_creds_keytab(context, &my_creds, kprincpw,
                                          keytab, 0, NULL,
                                          &options);

	if (krberr) {
		syslog(LOG_ERR, "Failed to init credentials: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	krb5_cc_initialize(context, ccache, kprincpw);
	if (krberr) {
		syslog(LOG_ERR, "Failed to init ccache: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	krberr = krb5_cc_store_cred(context, ccache, &my_creds);
	if (krberr) {
		syslog(LOG_ERR, "Failed to store creds: %s",
			krb5_get_error_message(context, krberr));
		ret = -1;
		goto done;
	}

	ret = 0;

done:
	/* TODO: mem cleanup */
	if (keytab) krb5_kt_close(context, keytab);
	if (context) krb5_free_context(context);
	return ret;
}

int ldap_sasl_interact(LDAP *ld, unsigned flags, void *priv_data, void *sit)
{
	sasl_interact_t *in = NULL;
	int ret = LDAP_OTHER;
	char *realm_name = (char *)priv_data;

	if (!ld) return LDAP_PARAM_ERROR;

	for (in = sit; in && in->id != SASL_CB_LIST_END; in++) {
		switch(in->id) {
		case SASL_CB_USER:
			in->result = srv_pri_name;
			in->len = strlen(srv_pri_name);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			in->result = realm_name;
			in->len = strlen(realm_name);
			ret = LDAP_SUCCESS;
			break;
		default:
			if (debug > 0) {
				syslog(LOG_ERR,
					"Unhandled SASL int. option %ld",
					in->id);
			}
			in->result = NULL;
			in->len = 0;
			ret = LDAP_OTHER;
		}
	}
        return ret;
}

/* from DS ldaprot.h */
#define LDAP_TAG_PWP_WARNING    0xA0    /* context specific + constructed + 0 */ 
#define LDAP_TAG_PWP_SECSLEFT   0x80L   /* context specific + primitive */ 
#define LDAP_TAG_PWP_GRCLOGINS  0x81L   /* context specific + primitive + 1 */ 
#define LDAP_TAG_PWP_ERROR      0x81L   /* context specific + primitive + 1 */ 

int ldap_pwd_change(char *client_name, char *realm_name, krb5_data pwd, char **errstr)
{
	char *tmp_file = NULL;
	int version;
	LDAP *ld = NULL;
	BerElement *ctrl = NULL;
	BerElement *sctrl = NULL;
	struct berval *control = NULL;
	struct berval newpw;
	char hostname[1024];
	struct berval **ncvals;
	char *ldap_base = NULL;
	char *filter;
	char *attrs[] = {"krbprincipalname", NULL};
	char *root_attrs[] = {"namingContexts", NULL};
	char *userdn = NULL;
	char *retoid = NULL;
	struct berval *retdata = NULL;
	struct timeval tv;
	LDAPMessage *entry, *res = NULL;
	LDAPControl **srvctrl = NULL;
	char *exterr0 = NULL;
	char *exterr1 = NULL;
	char *exterr2 = NULL;
	char *err = NULL;
	int msgid;
	int ret, rc;
	int fd;
	int kpwd_err = KRB5_KPASSWD_HARDERROR;

	tmp_file = strdup(TMP_TEMPLATE);
	if (!tmp_file) {
		syslog(LOG_ERR, "Out of memory!");
		goto done;
	}

	fd = mkstemp(tmp_file);
	if (fd == -1) {
		syslog(LOG_ERR,
			"Failed to create tmp file with errno: %d", errno);
		goto done;
	}
	/* close mimmediately, we don't need to keep the file open,
	 * just that it exist and has a unique name */
	close(fd);

	/* In the long term we may want to do this in the main daemon
	 * and just renew when needed.
	 * Right now do it at every password change for robustness */
	ret = get_krb5_ticket(tmp_file);
	if (ret) {
		syslog(LOG_ERR, "Unable to kinit!");
		goto done;
	}

	newpw.bv_len = pwd.length;
	newpw.bv_val = pwd.data;

	/* retrieve server name and build uri */
	ret = gethostname(hostname, 1023);
	if (ret == -1) {
		syslog(LOG_ERR, "Unable to get the hostname!");
		goto done;
	}

	/* connect to ldap server */
	/* TODO: support referrals ? */
	ld = ldap_init(hostname, 389);
	if(ld == NULL) {
		syslog(LOG_ERR, "Unable to connect to ldap server");
		goto done;
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to set ldap protocol version");
		goto done;
	}

	ret = ldap_sasl_interactive_bind_s(ld,
					   NULL, "GSSAPI",
					   NULL, NULL,
					   LDAP_SASL_AUTOMATIC,
					   ldap_sasl_interact, realm_name);
	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to bind to ldap server");
		goto done;
	}

	/* find base dn */
	/* TODO: address the case where we have multiple naming contexts */
	tv.tv_sec = 10;
	tv.tv_usec = 0; 

	ret = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE,
				"objectclass=*", root_attrs, 0,
				NULL, NULL, &tv, 0, &res);

	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR,
			"Search for %s on rootdse failed with error %d",
			root_attrs[0], ret);
		goto done;
	}

	/* for now just use the first result we get */
	entry = ldap_first_entry(ld, res);
	ncvals = ldap_get_values_len(ld, entry, root_attrs[0]);
	if (!ncvals) {
		syslog(LOG_ERR, "No values for %s", root_attrs[0]);
		goto done;
	}

	ldap_base = strdup(ncvals[0]->bv_val);

	ldap_value_free_len(ncvals);
	ldap_msgfree(res);

	/* find user dn */
	ret = asprintf(&filter, "krbPrincipalName=%s", client_name);
	if (ret == -1) {
		syslog(LOG_ERR, "Out of memory!");
		goto done;
	}

	tv.tv_sec = 10;
	tv.tv_usec = 0; 

	ret = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE,
				filter, attrs, 1, NULL, NULL, &tv, 0, &res);

	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Search for %s failed with error %d",
			filter, ret);
		if (ret == LDAP_CONSTRAINT_VIOLATION) {
			*errstr = strdup("Password Change Failed");
			kpwd_err = KRB5_KPASSWD_SOFTERROR;
		}
		goto done;
	}
	free(filter);

	/* for now just use the first result we get */
	entry = ldap_first_entry(ld, res);
	userdn = ldap_get_dn(ld, entry);

	ldap_msgfree(res);
	res = NULL;

	if (!userdn) {
		syslog(LOG_ERR, "No userdn, can't change password!");
		goto done;
	}

	/* build password change control */
	ctrl = ber_alloc_t(LBER_USE_DER);
	if (!ctrl) {
		syslog(LOG_ERR, "Out of memory!");
		goto done;
	}

	ber_printf(ctrl, "{tstON}",
		   LDAP_TAG_EXOP_MODIFY_PASSWD_ID, userdn,
		   LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, &newpw);

	ret = ber_flatten(ctrl, &control);
	if (ret < 0) {
		syslog(LOG_ERR, "ber flattening failed!");
		goto done;
	}

	/* perform password change */
	ret = ldap_extended_operation(ld,
					LDAP_EXOP_MODIFY_PASSWD,
					control, NULL, NULL,
					&msgid);
	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap_extended_operation() failed. (%d)", ret);
		goto done;
	}

	tv.tv_sec = 10;
	tv.tv_usec = 0; 

	ret = ldap_result(ld, msgid, 1, &tv, &res);
	if (ret == -1) {
		ldap_get_option(ld, LDAP_OPT_ERROR_NUMBER, &rc);
		syslog(LOG_ERR, "ldap_result() failed. (%d)", rc);
		goto done;
	}

	ret = ldap_parse_extended_result(ld, res, &retoid, &retdata, 0);
	if(ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap_parse_extended_result() failed.");
		ldap_msgfree(res);
		goto done;
	}
	if (retoid || retdata) {
		syslog(LOG_ERR, "ldap_parse_extended_result() returned data, but we don't handle it yet.");
	}

	ret = ldap_parse_result(ld, res, &rc, NULL, &err, NULL, &srvctrl, 0);
        if(ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "ldap_parse_result() failed.");
		goto done;
        }
	if (rc != LDAP_SUCCESS) {
		if (rc == LDAP_CONSTRAINT_VIOLATION) {
			kpwd_err = KRB5_KPASSWD_SOFTERROR;
		}
		ret = LDAP_OPERATIONS_ERROR;
	}
	if (err) {
		syslog(LOG_ERR, "ldap_parse_result(): [%s]", err);
		ldap_memfree(err);
	}

	if (srvctrl) {

		LDAPControl *pprc = NULL;
		int i;

		for (i = 0; srvctrl[i]; i++) {
			if (0 == strcmp(srvctrl[i]->ldctl_oid, LDAP_CONTROL_PASSWORDPOLICYRESPONSE)) {
				pprc = srvctrl[i];
			}
		}
		if (pprc) {
			sctrl = ber_init(&pprc->ldctl_value);
		}

		if (sctrl) {
			/*
			 * PasswordPolicyResponseValue ::= SEQUENCE {
			 * 	warning   [0] CHOICE OPTIONAL {
			 * 		timeBeforeExpiration  [0] INTEGER (0 .. maxInt),
			 * 		graceLoginsRemaining  [1] INTEGER (0 .. maxInt) }
			 * 	error     [1] ENUMERATED OPTIONAL {
			 * 		passwordExpired       (0),
			 * 		accountLocked         (1),
			 * 		changeAfterReset      (2),
			 * 		passwordModNotAllowed (3),
			 * 		mustSupplyOldPassword (4),
			 * 		invalidPasswordSyntax (5),
			 * 		passwordTooShort      (6),
			 * 		passwordTooYoung      (7),
			 *		passwordInHistory     (8) } }
			 */

			ber_tag_t rtag, btag;
			ber_int_t bint;
			rtag = ber_scanf(sctrl, "{t", &btag);
			if (btag == LDAP_TAG_PWP_WARNING) {
				rtag = ber_scanf(sctrl, "{ti}", &btag, &bint);
				if (btag == LDAP_TAG_PWP_SECSLEFT) {
					ret = asprintf(&exterr2, " (%d seconds left before password expires)", bint);
				} else {
					ret = asprintf(&exterr2, " (%d grace logins remaining)", bint);
				}
				if (ret == -1) {
					syslog(LOG_ERR, "OOM while creating error message ...");
					exterr2 = NULL;
				}
				rtag = ber_scanf(sctrl, "t", &btag);
			}
			if (btag == LDAP_TAG_PWP_ERROR) {
				rtag = ber_scanf(sctrl, "e", &bint);
				switch(bint) {
				case 0:
					ret = asprintf(&exterr1, " Err%d: Password Expired.", bint);
					break;
				case 1:
					ret = asprintf(&exterr1, " Err%d: Account locked.", bint);
					break;
				case 2:
					ret = asprintf(&exterr1, " Err%d: Password changed after reset.", bint);
					break;
				case 3:
					ret = asprintf(&exterr1, " Err%d: Password change not allowed.", bint);
					break;
				case 4:
					ret = asprintf(&exterr1, " Err%d: [Shouldn't happen].", bint);
					break;
				case 5:
					ret = asprintf(&exterr1, " Err%d: Password too simple.", bint);
					break;
				case 6:
					ret = asprintf(&exterr1, " Err%d: Password too short.", bint);
					break;
				case 7:
					ret = asprintf(&exterr1, " Err%d: Too soon to change password.", bint);
					break;
				case 8:
					ret = asprintf(&exterr1, " Err%d: Password reuse not permitted.", bint);
					break;
				default:
					ret = asprintf(&exterr1, " Err%d: Unknown Errorcode.", bint);
					break;
				}
				if (ret == -1) {
					syslog(LOG_ERR, "OOM while creating error message ...");
					exterr1 = NULL;
				}
			}
		}
	}

	if (ret == LDAP_SUCCESS) {
		kpwd_err = KRB5_KPASSWD_SUCCESS;
		exterr0 = "Password change succeeded";
	} else {
		exterr0 = "Password change failed";
	}
	ret = asprintf(errstr, "%s%s%s", exterr0, exterr1?exterr1:"", exterr2?exterr2:"");
	if (ret == -1) {
		syslog(LOG_ERR, "OOM while creating error message ...");
		*errstr = NULL;
	}

done:
	if (ctrl) ber_free(ctrl, 1);
	if (sctrl) ber_free(sctrl, 1);
	if (srvctrl) ldap_controls_free(srvctrl);
	if (res) ldap_msgfree(res);
	if (control) ber_bvfree(control);
	free(exterr1);
	free(exterr2);
	free(userdn);
	if (ld) ldap_unbind_ext(ld, NULL, NULL);
	if (tmp_file) {
		unlink(tmp_file);
		free(tmp_file);
	}
	return kpwd_err;
}

void handle_krb_packets(uint8_t *buf, ssize_t buflen,
			struct socklist *sd,
			struct sockaddr_storage *from,
			uint8_t **repbuf, ssize_t *replen)
{
	krb5_auth_context auth_context;
	krb5_context context;
	krb5_keytab keytab;
	krb5_principal kprincpw;
	krb5_ticket *ticket;
	krb5_address lkaddr, rkaddr;
	krb5_data kreq, krep, kenc, kdec;
	krb5_replay_data replay;
	krb5_error krb5err;
	int krberr;
	size_t reqlen;
	size_t verno;
	char *client_name, *realm_name;
	char *result_string;
	int result_err;
	uint8_t *reply;
	ssize_t replylen;

	*replen = 0;

	result_string = NULL;
	auth_context = NULL;
	krep.length = 0;
	krep.data = NULL;
	kdec.length = 0;
	kdec.data = NULL;
	kprincpw = NULL;
	context = NULL;
	ticket = NULL;

	switch(((struct sockaddr *)from)->sa_family) {
	case AF_INET:
		lkaddr.addrtype = ADDRTYPE_INET;
		lkaddr.length = sizeof(((struct sockaddr_in *)&sd->dest_addr)->sin_addr);
		lkaddr.contents = (krb5_octet *) &(((struct sockaddr_in *)&sd->dest_addr)->sin_addr);

		rkaddr.addrtype = ADDRTYPE_INET;
		rkaddr.length = sizeof(((struct sockaddr_in *)from)->sin_addr);
		rkaddr.contents = (krb5_octet *) &(((struct sockaddr_in *)from)->sin_addr);
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED (&((struct sockaddr_in6 *)from)->sin6_addr)) {
			lkaddr.addrtype = ADDRTYPE_INET;
			lkaddr.length = 4;
			lkaddr.contents = 12 + (krb5_octet *) &(((struct sockaddr_in6 *)&sd->dest_addr)->sin6_addr);

			rkaddr.addrtype = ADDRTYPE_INET;
			rkaddr.length = 4;
			rkaddr.contents = 12 + (krb5_octet *) &(((struct sockaddr_in6 *)from)->sin6_addr);
		} else {
			lkaddr.addrtype = ADDRTYPE_INET6;
			lkaddr.length = sizeof(((struct sockaddr_in6 *)&sd->dest_addr)->sin6_addr);
			lkaddr.contents = (krb5_octet *) &(((struct sockaddr_in6 *)&sd->dest_addr)->sin6_addr);

			rkaddr.addrtype = ADDRTYPE_INET6;
			rkaddr.length = sizeof(((struct sockaddr_in6 *)from)->sin6_addr);
			rkaddr.contents = (krb5_octet *) &(((struct sockaddr_in6 *)from)->sin6_addr);
		}
		break;
	default:
		result_string = strdup("Invalid remopte IP address");
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	if (buflen < 4) {
		result_string = strdup("Request truncated");
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	reqlen = (buf[0] << 8) + buf[1];

	if (reqlen != buflen) {
		result_string = strdup("Unmatching request length");
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	verno = (buf[2] << 8) + buf[3];

	if (verno != 1) {
		result_string = strdup("Unsupported version");
		result_err = KRB5_KPASSWD_BAD_VERSION;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	kreq.length = (buf[4] << 8) + buf[5];
	if (kreq.length > (buflen - 6)) {
		result_string = strdup("Request truncated");
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}
	kreq.data = (char *)&buf[6];

	krberr = krb5_init_context(&context);
	if (krberr) {
		result_string = strdup("Failed to init kerberos context");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	krberr = krb5_get_default_realm(context, &realm_name);
	if (krberr) {
		result_string = strdup("Failed to get default realm name");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	krberr = krb5_auth_con_init(context, &auth_context);
	if (krberr) {
		result_string = strdup("Unable to init auth context");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_auth_con_setflags(context, auth_context,
					KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (krberr) {
		result_string = strdup("Unable to init auth context");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_build_principal(context, &kprincpw,
				      strlen(realm_name), realm_name,
				      "kadmin", "changepw", NULL);
	if (krberr) {
		result_string = strdup("Unable to build principal");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_kt_resolve(context, keytab_name, &keytab);
	if (krberr) {
		result_string = strdup("Unable to retrieve keytab");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_rd_req(context, &auth_context, &kreq,
			     kprincpw, keytab, NULL, &ticket);
	if (krberr) {
		result_string = strdup("Unable to read request");
		result_err = KRB5_KPASSWD_AUTHERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	/* build the AP Reply before actually changing the password
	 * this minimize the risk of a fatal error occurring _after_
	 * the password have been successfully changed */
	krberr = krb5_mk_rep(context, auth_context, &krep);
	if (krberr) {
		result_string = strdup("Failed to to build reply");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	/* verify that this is an AS_REQ ticket */
	if (!(ticket->enc_part2->flags & TKT_FLG_INITIAL)) {
		result_string = strdup("Ticket must be derived from a password");
		result_err = KRB5_KPASSWD_AUTHERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto kpreply;
	}

	krberr = krb5_unparse_name(context, ticket->enc_part2->client,
				   &client_name);
	if (krberr) {
		result_string = strdup("Unable to parse client name");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto kpreply;
	}

	krberr = krb5_auth_con_setaddrs(context, auth_context, NULL, &rkaddr);
	if (krberr) {
		result_string = strdup("Failed to set client address");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto kpreply;
	}

	/* decrypt the new password */
	kenc.length = reqlen - kreq.length - 6;
	kenc.data = kreq.data + kreq.length;

	/* rd_priv needs the remote address while mk_priv (used later)
	 * requires the local address (from kadmin code) */
	krberr = krb5_rd_priv(context, auth_context, &kenc, &kdec, &replay);
	if (krberr) {
		result_string = strdup("Failed to decrypt password");
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto kpreply;
	}

	if (debug > 100) {
		syslog(LOG_ERR, "Client %s trying to set password [%*s]",
			client_name, kdec.length, kdec.data);
	}

	/* Actually try to change the password */
	result_err = ldap_pwd_change(client_name, realm_name, kdec, &result_string);
	if (result_string == NULL) {
		result_string = strdup("Server Error while performing LDAP password change");
	}
	syslog(LOG_ERR, "%s", result_string);

	/* make sure password is cleared off before we free the memory */
	memset(kdec.data, 0, kdec.length);
	free(kdec.data);
	kdec.length = 0;

kpreply:

	/* set-up the the clear text reply */
	kdec.length = 2 + strlen(result_string);
	kdec.data = malloc(kdec.length);
	if (!kdec.data) {
		syslog(LOG_ERR, "Out of memory!");
		kdec.length = 0;
		goto done;
	}
	
	kdec.data[0] = (result_err >> 8) & 0xff;
	kdec.data[1] = result_err & 0xff;
	memcpy(&kdec.data[2], result_string, strlen(result_string));

	krberr = krb5_auth_con_setaddrs(context, auth_context, &lkaddr, NULL);
	if (krberr) {
		result_string = strdup("Failed to set local address");
		syslog(LOG_ERR, "%s: %s", result_string, 
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_mk_priv(context, auth_context, &kdec, &kenc, &replay);
	if (krberr) {
		result_string = strdup("Failed to encrypt reply message");
		syslog(LOG_ERR, "%s: %s", result_string, 
			krb5_get_error_message(context, krberr));
		/* encryption was unsuccessful, let's return a krb error */

		/* the ap data is no more useful */
		free(krep.data);
		krep.length = 0;

		/* build a krberror encrypted paylod */
		krb5err.error = KRB5_CHPW_FAIL;
		krb5err.server = kprincpw;
		krb5err.client = NULL;
		krb5err.ctime = 0;
		krb5err.cusec = 0;
		krb5err.susec = 0;
		krberr = krb5_timeofday(context, &krb5err.stime);
		if (krberr) {
			result_string = strdup("Failed to set time of day");
			syslog(LOG_ERR, "%s: %s", result_string, 
				krb5_get_error_message(context, krberr));
			goto done;
		}

		krb5err.text.length = 0;
		krb5err.e_data = kdec;
		krberr = krb5_mk_error(context, &krb5err, &kenc);
		if (krberr) {
			result_string = strdup("Failed to build error message");
			syslog(LOG_ERR, "%s: %s", result_string, 
				krb5_get_error_message(context, krberr));
			goto done;
		}
	}

	replylen = 6 + krep.length + kenc.length;
	reply = malloc(replylen);
	if (!reply) {
		syslog(LOG_ERR, "Out of memory!");
		goto done;
	}
	*repbuf = reply;

	reply[0] = (replylen >> 8) & 0xff;
	reply[1] = replylen & 0xff;
	reply[2] = 0x00;
	reply[3] = 0x01;
	reply[4] = (krep.length >> 8) & 0xff;
	reply[5] = krep.length & 0xff;

	if (krep.length) {
		memcpy(&reply[6], krep.data, krep.length);
	}
	memcpy(&reply[6 + krep.length], kenc.data, kenc.length);

	*replen = replylen;

done:
	free(result_string);
	if (auth_context) krb5_auth_con_free(context, auth_context);
	if (kprincpw) krb5_free_principal(context, kprincpw);
	if (krep.length) free(krep.data);
	if (ticket) krb5_free_ticket(context, ticket);
	if (kdec.length) free(kdec.data);
	if (context) krb5_free_context(context);
}

pid_t handle_conn(struct socklist *sd)
{
	int mfd, tcp;
	pid_t pid;
	char addrto6[INET6_ADDRSTRLEN+1];
	char address[INET6_ADDRSTRLEN+1];
	uint8_t request[1500];
	ssize_t reqlen;
	uint8_t *reply;
	ssize_t replen;
	struct sockaddr_storage from;
	socklen_t fromlen;
	ssize_t sendret;
	int ret;

	fromlen = sizeof(from);
	mfd = 0;
	tcp = 0;
	reqlen = 0;

	/* receive request */
	if (sd->socktype == SOCK_STREAM) {
		tcp = 1;
		mfd = accept(sd->fd, (struct sockaddr *)&from, &fromlen);
		if (mfd == -1) {
			syslog(LOG_ERR, "Accept failed with error (%d) %s",
				errno, strerror(errno));
			return -1;
		}
	} else {
		/* read first to empty the buffer on udp connections */
		reqlen = recvfrom(sd->fd, request, sizeof(request), 0,
				   (struct sockaddr *)&from, &fromlen);
		if (reqlen <= 0) {
			syslog(LOG_ERR, "Error receiving request (%d) %s",
				errno, strerror(errno));
			return -1;
		}

	}

	ret = getnameinfo((struct sockaddr *)&from, fromlen,
			  addrto6, INET6_ADDRSTRLEN+1,
			  NULL, 0, NI_NUMERICHOST);
	if (ret) {
		syslog(LOG_ERR, "Error retrieving host address\n");
		return -1;
	}

	if (debug > 0) {
		syslog(LOG_ERR, "Connection from %s", addrto6);
	}

	if (strchr(addrto6, ':') == NULL) {
		char *prefix6 = "::ffff:";
		/* this is an IPv4 formatted addr
		 * convert to IPv6 mapped addr */
		memcpy(address, prefix6, 7);
		memcpy(&address[7], addrto6, INET6_ADDRSTRLEN-7);
	} else {
		/* regular IPv6 address, copy as is */
		memcpy(address, addrto6, INET6_ADDRSTRLEN);
	}
	/* make sure we have termination */
	address[INET6_ADDRSTRLEN] = '\0';

	/* Check blacklist for requests from the same IP until operations
	 * are finished on the active client.
	 * the password change may be slow and pam_krb5 sends up to 3 UDP
	 * requests waiting 1 sec. each time.
	 * We do not want to start 3 password changes at the same time */

	if (check_blacklist(address)) {
		if (debug > 0) {
			syslog(LOG_ERR, "[%s] blacklisted", address);
		}
		if (tcp) close(mfd);
		return 0;
	}

	/* now read data if it was a TCP connection */
	if (tcp) {
		reqlen = recvfrom(mfd, request, sizeof(request), 0,
				   (struct sockaddr *)&from, &fromlen);
		if (reqlen <= 0) {
			syslog(LOG_ERR, "Error receiving request (%d) %s",
				errno, strerror(errno));
			close(mfd);
			return -1;
		}
	}
#if 1
	/* handle kerberos and ldap operations in childrens */
	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "Fork failed with error (%d) %s",
			errno, strerror(errno));
		if (tcp) close(mfd);
		return 0;
	}
	if (pid != 0) { /* parent */
		if (tcp) close(mfd);
		add_blacklist(pid, address);
		return pid;
	}
#endif

	/* children */
	if (debug > 0) syslog(LOG_ERR, "Servicing %s", address);

	/* TCP packets prepend the lenght as a 32bit network order field,
	 * this information seem to be just redundant, so let's simply
	 * skip it */
        if (tcp) {
		handle_krb_packets(request+4, reqlen-4, sd, &from, &reply, &replen);
	} else {
		handle_krb_packets(request, reqlen, sd, &from, &reply, &replen);
	}

	if (replen) { /* we have something to reply */
		if (tcp) {
			sendret = sendto(mfd, reply, replen, 0, NULL, 0);
		} else {
			sendret = sendto(sd->fd, reply, replen, 0, (struct sockaddr *)&from, fromlen);
		}
		if (sendret == -1) {
			syslog(LOG_ERR, "Error sending reply (%d)", errno);
		}
	}
	if (tcp) close(mfd);
	exit(0);
}

static int create_socket(struct addrinfo *ai, struct socklist **_sds,
			 struct pollfd **_pfds, int *_nfds)
{
	struct socklist *csd, *tsd;
	struct pollfd *pfds;
	int nfds;
	int ret;
	int tru = 1;

	pfds = *_pfds;
	nfds = *_nfds;

	csd = calloc(1, sizeof(struct socklist));
	if (csd == NULL) {
		syslog(LOG_ERR, "Out of memory, can't create socklist\n");
		return 1;
	}
	csd->socktype = ai->ai_socktype;
	csd->dest_addr_len = ai->ai_addrlen;
	memcpy(&csd->dest_addr, ai->ai_addr, ai->ai_addrlen);

	csd->fd = socket(csd->dest_addr.ss_family, csd->socktype, 0);
	if (csd->fd == -1) {
		syslog(LOG_ERR, "Unable to create socket (%s)",
		       strerror(errno));
		goto errout;
	}
	ret = setsockopt(csd->fd, SOL_SOCKET, SO_REUSEADDR,
			 (void *)&tru, sizeof(tru));

	ret = bind(csd->fd, (struct sockaddr *)&csd->dest_addr, csd->dest_addr_len);
	if (ret) {
		if (errno != EADDRINUSE) {
			syslog(LOG_ERR, "Unable to bind to socket");
			close(csd->fd);
			goto errout;
		}
		/* if EADDRINUSE it means we are on a machine
		 * with a dual ipv4/ipv6 stack that does not
		 * allow to bind on both at the same time as the
		 * ipv6 bind already allows connections on ipv4
		 * Just ignore */
		close(csd->fd);
		free(csd);
		return 0;
	}

	if (csd->socktype == SOCK_STREAM) {
		ret = listen(csd->fd, SOMAXCONN);
		if (ret) {
			syslog(LOG_ERR, "Unable to listen to TCP socket (%s)",
			       strerror(errno));
			close(csd->fd);
			goto errout;
		}
	}

	pfds = realloc(pfds, sizeof(struct pollfd) * (nfds +1));
	if (pfds == NULL) {
		syslog(LOG_ERR, "Out of memory, can't alloc pollfd array\n");
		close(csd->fd);
		goto errout;
	}
	pfds[nfds].events = POLLIN;
	pfds[nfds].fd = csd->fd;
	nfds++;

	if (*_sds) {
		for (tsd = *_sds; tsd->next; tsd = tsd->next) /* skip */ ;
		tsd->next = csd;
	} else {
		*_sds = csd;
	}

	*_pfds = pfds;
	*_nfds = nfds;

	return 0;

errout:
	free(csd);
	return 1;
}

int main(int argc, char *argv[])
{
	pid_t pid;
	struct ifaddrs *ifa, *tifa;
	struct addrinfo *ai, *tai;
	struct addrinfo hints;
	char host[NI_MAXHOST];
	struct socklist *sds, *csd;
	struct pollfd *pfds;
	int nfds;
	int ret;
	char *env;

	/* log to syslog */
	openlog("kpasswd", LOG_PID, LOG_DAEMON);

	/* do not keep any fs busy */
	ret = chdir("/");
	if (ret == -1) {
		syslog(LOG_ERR, "Unable to change dir to '/'");
		exit(-1);
	}

	/* daemonize */
	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "Error fork() failed!");
		exit(-1);
	}
	if (pid != 0) { /* parent */
		exit(0);
	}

	/* new session */
	setsid();

	/* close std* descriptors */
	close(0);
	close(1);
	close(2);

	/* fork again to make sure we completely detach from parent process */
	pid = fork();
	if (pid == -1) {
		syslog(LOG_ERR, "Error fork() failed!");
		exit(-1);
	}
	if (pid != 0) { /* parent */
		exit(0);
	}

	/* source env vars */
	env = getenv("KRB5_KTNAME");
	if (!env) {
		env = DEFAULT_KEYTAB;
	}
	keytab_name = strdup(env);
	if (!keytab_name) {
		syslog(LOG_ERR, "Out of memory!");
	}

	env = getenv("IPA_KPASSWD_DEBUG");
	if (env) {
		debug = strtol(env, NULL, 0);
	}

	ret = getifaddrs(&ifa);
	if (ret) {
		syslog(LOG_ERR, "getifaddrs failed: %s", gai_strerror(ret));
		exit(1);
	}

	/* Write out the pid file after the sigterm handler */
	const char *pid_file = "/var/run/ipa_kpasswd.pid";
	FILE *f = fopen(pid_file, "w");
	int fail = 1;
	if (f) {
		int n_bytes = fprintf(f, "%ld\n", (long) getpid());
		if (fclose(f) == 0 && 0 < n_bytes)
			fail = 0;
	}
	if (fail) {
		syslog(LOG_ERR, "Couldn't create pid file %s: %s",
		       pid_file, strerror(errno));
		exit(1);
	}

	nfds = 0;
	pfds = NULL;
	sds = NULL;

	for (tifa = ifa; tifa; tifa = tifa->ifa_next) {

		if (NULL == tifa->ifa_addr)
			/* uhmm no address ?? skip it */
			continue;

		if (tifa->ifa_addr->sa_family != AF_INET &&
		    tifa->ifa_addr->sa_family != AF_INET6) {
			/* not interesting for us */
			continue;
		}

		ret = getnameinfo(tifa->ifa_addr, sizeof(struct sockaddr_storage),
				  host, sizeof(host), NULL, 0, NI_NUMERICHOST);
		if (ret) {
			syslog(LOG_ERR, "Error converting address (%s)",
				gai_strerror(ret));
			continue;
		} else {
			syslog(LOG_INFO, "Setting up socket for [%s]", host);
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_flags = AI_NUMERICHOST;
		hints.ai_family = AF_UNSPEC;

		/* this should return 2 entries, one for UDP and one for TCP */
		ret = getaddrinfo(host, "kpasswd", &hints, &ai);
		if (ret) {
			syslog(LOG_ERR, "Error getting address info (%s) for [%s]",
				gai_strerror(ret), host);
			continue;
		}

		for (tai = ai; tai; tai = tai->ai_next) {
			char *socktype = (tai->ai_socktype==SOCK_STREAM)?"TCP":"UDP";
			ret = create_socket(tai, &sds, &pfds, &nfds);
			if (ret) {
				syslog(LOG_ERR,
				       "Failed to set up %s socket for [%s]",
				       socktype, host);
			}
		}
	}

	if (nfds == 0) {
		syslog(LOG_ERR, "Failed to setup any socket. Aborting");
		exit(1);
	}

	/* now that sockets are set up, enter the poll loop */

	while (1) {
		int cstatus, cid, i;

		ret = poll(pfds, nfds, 3000);

		switch(ret) {
		case 0:
			break;
		case -1:
			if (errno != EINTR) {
				syslog(LOG_ERR,
					"Unexpected error in poll (%d) %s",
					errno, strerror(errno));
				exit(5);
			}
			break;
		default:
			for (i = 0; i < nfds; i++) {
				if (pfds[i].revents & POLLIN) {
					for (csd = sds; csd; csd = csd->next) {
						if (csd->fd == pfds[i].fd) {
							handle_conn(csd);
						}
					}
				}
			}
		}

		/* check for children exiting */
		cid = waitpid(-1, &cstatus, WNOHANG);
		if (cid != -1 && cid != 0) {
			if (debug > 0)
				syslog(LOG_ERR, "pid %d completed operations!\n", cid);
			remove_blacklist(cid);
		}
	}
}
