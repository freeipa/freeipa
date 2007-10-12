
/* Kpasswd-LDAP proxy */

/* (C) Simo Sorce */
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
#include <ldap.h>
#include <sasl/sasl.h>

#define DEFAULT_KEYTAB "FILE:/var/kerberos/krb5kdc/kpasswd.keytab"
#define TMP_TEMPLATE "/tmp/kpasswd.XXXXXX"
#define KPASSWD_PORT 464

struct blacklist {
	struct blacklist *next;
	char *address;
	pid_t pid;
};

static struct blacklist *global_blacklist = NULL;

int check_blacklist(char *address)
{
	struct blacklist *bl;

	if (!global_blacklist) {
		return 0;
	}

	for (bl = global_blacklist; bl; bl = bl->next) {
		if (strcmp(address, bl->address) == 0) {
			return 1;
		}
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
	struct blacklist *bl, *pbl;

	if (!global_blacklist) {
		return -1;
	}

	pbl = NULL;
	bl = global_blacklist;
	while (bl) {
		if (pid == bl->pid) {
			if (pbl == NULL) {
				global_blacklist = bl->next;
			} else {
				pbl->next = bl->next;
			}
			free(bl->address);
			free(bl);
			return 0;
		}
		pbl = bl;
		bl = bl->next;
	}
	return -1;
}

int debug = 1;
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

int ldap_pwd_change(char *client_name, char *realm_name, krb5_data pwd)
{
	char *tmp_file = NULL;
	int version;
	LDAP *ld = NULL;
	BerElement *ctrl = NULL;
	struct berval control;
	struct berval newpw;
	char hostname[1024];
	char *ldap_uri = NULL;
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
	int ret;

	tmp_file = strdup(TMP_TEMPLATE);
	if (!tmp_file) {
		syslog(LOG_ERR, "Out of memory!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	ret = mkstemp(tmp_file);
	if (ret == -1) {
		syslog(LOG_ERR,
			"Failed to create tmp file with errno: %d", errno);
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}
	/* close mimmediately, we don't need to keep the file open,
	 * just that it exist and has a unique name */
	close(ret);

	/* In the long term we may want to do this in the main daemon
	 * and just renew when needed.
	 * Right now do it at every password change for robustness */
	ret = get_krb5_ticket(tmp_file);
	if (ret) {
		syslog(LOG_ERR, "Unable to kinit!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	newpw.bv_len = pwd.length;
	newpw.bv_val = pwd.data;

	/* retrieve server name and build uri */
	ret = gethostname(hostname, 1023);
	if (ret == -1) {
		syslog(LOG_ERR, "Unable to get the hostname!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	ret = asprintf(&ldap_uri, "ldap://%s:389", hostname);
	if (ret == -1) {
		syslog(LOG_ERR, "Out of memory!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	/* connect to ldap server */
	/* TODO: support referrals ? */
	ret = ldap_initialize(&ld, ldap_uri);
	if(ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to connect to ldap server");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        if (ret != LDAP_OPT_SUCCESS) {
		syslog(LOG_ERR, "Unable to set ldap protocol version");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	ret = ldap_sasl_interactive_bind_s(ld,
					   NULL, "GSSAPI",
					   NULL, NULL,
					   LDAP_SASL_AUTOMATIC,
					   ldap_sasl_interact, realm_name);
	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Unable to bind to ldap server");
		ret = KRB5_KPASSWD_HARDERROR;
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
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	/* for now just use the first result we get */
	entry = ldap_first_entry(ld, res);
	ncvals = ldap_get_values_len(ld, entry, root_attrs[0]);
	if (!ncvals) {
		syslog(LOG_ERR, "No values for %s", root_attrs[0]);
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	ldap_base = strdup(ncvals[0]->bv_val);

	ldap_value_free_len(ncvals);
	ldap_msgfree(res);

	/* find user dn */
	ret = asprintf(&filter, "krbPrincipalName=%s", client_name);
	if (ret == -1) {
		syslog(LOG_ERR, "Out of memory!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	tv.tv_sec = 10;
	tv.tv_usec = 0; 

	ret = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUBTREE,
				filter, attrs, 1, NULL, NULL, &tv, 0, &res);

	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "Search for %s failed with error %d",
			filter, ret);
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}
	free(filter);

	/* for now just use the first result we get */
	entry = ldap_first_entry(ld, res);
	userdn = ldap_get_dn(ld, entry);

	ldap_msgfree(res);

	if (!userdn) {
		syslog(LOG_ERR, "No userdn, can't change password!");
		ret = -1;
		goto done;
	}

	/* build password change control */
	ctrl = ber_alloc_t(LBER_USE_DER);
	if (!ctrl) {
		syslog(LOG_ERR, "Out of memory!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}
	ber_printf(ctrl, "{tstON}",
		   LDAP_TAG_EXOP_MODIFY_PASSWD_ID, userdn,
		   LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, &newpw);

	ret = ber_flatten2(ctrl, &control, 0);
	if (ret < 0) {
		syslog(LOG_ERR, "ber flattening failed!");
		ret = -1;
		goto done;
	}

	/* perform password change */
	ret = ldap_extended_operation_s(ld, LDAP_EXOP_MODIFY_PASSWD, &control,
				      NULL, NULL, &retoid, &retdata);

	if (ret != LDAP_SUCCESS) {
		syslog(LOG_ERR, "password change failed!");
		ret = KRB5_KPASSWD_HARDERROR;
		goto done;
	}

	/* TODO: interpret retdata so that we can give back meaningful errors */

done:
	if (userdn) free(userdn);
	if (ctrl) ber_free(ctrl, 1);
	if (ld) ldap_unbind_ext_s(ld, NULL, NULL);
	if (ldap_uri) free(ldap_uri);
	if (tmp_file) {
		unlink(tmp_file);
		free(tmp_file);
	}
	return ret;
}

void handle_krb_packets(uint8_t *buf, ssize_t buflen,
			struct sockaddr_storage *from,
			uint8_t **repbuf, ssize_t *replen)
{
	krb5_auth_context auth_context;
	krb5_context context;
	krb5_keytab keytab;
	krb5_principal kprincpw;
	krb5_ticket *ticket;
	krb5_address **lkaddr, rkaddr;
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

	auth_context = NULL;
	krep.length = 0;
	krep.data = NULL;
	kprincpw = NULL;
	context = NULL;
	ticket = NULL;
	lkaddr = NULL;

	switch(((struct sockaddr *)from)->sa_family) {
	case AF_INET:
		rkaddr.addrtype = ADDRTYPE_INET;
		rkaddr.length = sizeof(((struct sockaddr_in *)from)->sin_addr);
		rkaddr.contents = (krb5_octet *) &(((struct sockaddr_in *)from)->sin_addr);
		break;
	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED (&((struct sockaddr_in6 *)from)->sin6_addr)) {
			rkaddr.addrtype = ADDRTYPE_INET;
			rkaddr.length = 4;
			rkaddr.contents = 12 + (krb5_octet *) &(((struct sockaddr_in6 *)from)->sin6_addr);
		} else {
			rkaddr.addrtype = ADDRTYPE_INET6;
			rkaddr.length = sizeof(((struct sockaddr_in6 *)from)->sin6_addr);
			rkaddr.contents = (krb5_octet *) &(((struct sockaddr_in6 *)from)->sin6_addr);
		}
		break;
	default:
		result_string = "Invalid remopte IP address";
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	if (buflen < 4) {
		result_string = "Request truncated";
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	reqlen = (buf[0] << 8) + buf[1];

	if (reqlen != buflen) {
		result_string = "Unmatching request length";
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	verno = (buf[2] << 8) + buf[3];

	if (verno != 1) {
		result_string = "Unsupported version";
		result_err = KRB5_KPASSWD_BAD_VERSION;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	kreq.length = (buf[4] << 8) + buf[5];
	if (kreq.length > (buflen - 6)) {
		result_string = "Request truncated";
		result_err = KRB5_KPASSWD_MALFORMED;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}
	kreq.data = (char *)&buf[6];

	krberr = krb5_init_context(&context);
	if (krberr) {
		result_string = "Failed to init kerberos context";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	krberr = krb5_get_default_realm(context, &realm_name);
	if (krberr) {
		result_string = "Failed to get default realm name";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto done;
	}

	krberr = krb5_auth_con_init(context, &auth_context);
	if (krberr) {
		result_string = "Unable to init auth context";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_auth_con_setflags(context, auth_context,
					KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (krberr) {
		result_string = "Unable to init auth context";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_build_principal(context, &kprincpw,
				      strlen(realm_name), realm_name,
				      "kadmin", "changepw", NULL);
	if (krberr) {
		result_string = "Unable to build principal";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_kt_resolve(context, keytab_name, &keytab);
	if (krberr) {
		result_string = "Unable to retrieve keytab";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_rd_req(context, &auth_context, &kreq,
			     kprincpw, keytab, NULL, &ticket);
	if (krberr) {
		result_string = "Unable to read request";
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
		result_string = "Failed to to build reply";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	/* verify that this is an AS_REQ ticket */
	if (!(ticket->enc_part2->flags & TKT_FLG_INITIAL)) {
		result_string = "Ticket must be derived from a password";
		result_err = KRB5_KPASSWD_AUTHERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto kpreply;
	}

	krberr = krb5_unparse_name(context, ticket->enc_part2->client,
				   &client_name);
	if (krberr) {
		result_string = "Unable to parse client name";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s", result_string);
		goto kpreply;
	}

	krberr = krb5_auth_con_setaddrs(context, auth_context, NULL, &rkaddr);
	if (krberr) {
		result_string = "Failed to set client address";
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
		result_string = "Failed to decrypt password";
		result_err = KRB5_KPASSWD_HARDERROR;
		syslog(LOG_ERR, "%s: %s", result_string,
			krb5_get_error_message(context, krberr));
		goto kpreply;
	}

	if (debug > 0) {
		syslog(LOG_ERR, "Client %s trying to set password [%*s]",
			client_name, kdec.length, kdec.data);
	}

	/* Actually try to change the password */
	result_err = ldap_pwd_change(client_name, realm_name, kdec);
	if (result_err != KRB5_KPASSWD_SUCCESS) {
		result_string = "Generic error occurred while changing password";
	} else {
		result_string = "";
	}

	/* make sure password is cleared off before we free the memory */
	memset(kdec.data, 0, kdec.length);
	free(kdec.data);

kpreply:

	/* set-up the the clear text reply */
	kdec.length = 2 + strlen(result_string);
	kdec.data = malloc(kdec.length);
	if (!kdec.data) {
		syslog(LOG_ERR, "Out of memory!");
		goto done;
	}
	
	kdec.data[0] = (result_err >> 8) & 0xff;
	kdec.data[1] = result_err & 0xff;
	memcpy(&kdec.data[2], result_string, strlen(result_string));

	/* we listen on ANYADDR, use this retrieve the right address */
        krberr = krb5_os_localaddr(context, &lkaddr);
	if (krberr) {
		result_string = "Failed to retrieve local address";
		syslog(LOG_ERR, "%s: %s", result_string, 
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_auth_con_setaddrs(context, auth_context, lkaddr[0], NULL);
	if (krberr) {
		result_string = "Failed to set local address";
		syslog(LOG_ERR, "%s: %s", result_string, 
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_mk_priv(context, auth_context, &kdec, &kenc, &replay);
	if (krberr) {
		result_string = "Failed to encrypt reply message";
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
			result_string = "Failed to set time of day";
			syslog(LOG_ERR, "%s: %s", result_string, 
				krb5_get_error_message(context, krberr));
			goto done;
		}

		krb5err.text.length = 0;
		krb5err.e_data = kdec;
		krberr = krb5_mk_error(context, &krb5err, &kenc);
		if (krberr) {
			result_string = "Failed to build error message";
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
	if (auth_context) krb5_auth_con_free(context, auth_context);
	if (kprincpw) krb5_free_principal(context, kprincpw);
	if (krep.length) free(krep.data);
	if (ticket) krb5_free_ticket(context, ticket);
	if (kdec.length) free(kdec.data);
	if (lkaddr) krb5_free_addresses(context, lkaddr);
	if (context) krb5_free_context(context);
}

pid_t handle_conn(int fd, int type)
{
	int mfd, tcp;
	pid_t pid;
	char address[INET6_ADDRSTRLEN+1];
	uint8_t request[1500];
	ssize_t reqlen;
	uint8_t *reply;
	ssize_t replen;
	struct sockaddr_storage from;
	socklen_t fromlen;
	ssize_t sendret;

	fromlen = sizeof(from);
	tcp = 0;

	/* receive request */
	if (type == SOCK_STREAM) {
		tcp = 1;
		mfd = accept(fd, (struct sockaddr *)&from, &fromlen);
		if (mfd == -1) {
			syslog(LOG_ERR, "Accept failed with error (%d) %s",
				errno, strerror(errno));
			return -1;
		}
	} else {
		mfd = fd;
	}

	(void) getnameinfo((struct sockaddr *)&from, fromlen,
			  address, INET6_ADDRSTRLEN+1,
			  NULL, 0, NI_NUMERICHOST);

	if (debug > 0) {
		syslog(LOG_ERR, "Connection from %s", address);
	}

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

	reqlen = recvfrom(mfd, request, sizeof(request), 0,
			   (struct sockaddr *)&from, &fromlen);
	if (reqlen <= 0) {
		syslog(LOG_ERR, "Error receiving request (%d) %s",
			errno, strerror(errno));
		if (tcp) close(mfd);
		return -1;
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

	/* TCP packets prepend the lenght as a 32bit network order field,
	 * this information seem to be just redundant, so let's simply
	 * skip it */
        if (tcp) {
		handle_krb_packets(request+4, reqlen-4, &from, &reply, &replen);
	} else {
		handle_krb_packets(request, reqlen, &from, &reply, &replen);
	}

	if (replen) { /* we have something to reply */
		if (tcp) {
			sendret = sendto(mfd, reply, replen, 0, NULL, 0);
		} else {
			sendret = sendto(mfd, reply, replen, 0, (struct sockaddr *)&from, fromlen);
		}
		if (sendret == -1) {
			syslog(LOG_ERR, "Error sending reply (%d)", errno);
		}
	}
	close(mfd);
	exit(0);
}

/* TODO: make this IPv6 aware */

int main(int argc, char *argv[])
{
	pid_t pid;
	struct addrinfo *ai, *tai;
	struct addrinfo hints;
	struct pollfd pfds[4];
	int pfdtype[4];
	int nfds;
	int ret;
	char *key;

	/* log to syslog */
	openlog("kpasswd", LOG_PID, LOG_DAEMON);

	/* do not keep any fs busy */
	ret = chdir("/");
	if (ret == -1) {
		syslog(LOG_ERR, "Unable to chage dir to '/'");
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

	key = getenv("KRB5_KTNAME");
	if (!key) {
		key = DEFAULT_KEYTAB;
	}
	keytab_name = strdup(key);
	if (!keytab_name) {
		syslog(LOG_ERR, "Out of memory!");
	}

	/* set hints */
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

	ret = getaddrinfo (NULL, "kpasswd", &hints, &ai);
	if (ret) {
		syslog(LOG_ERR, "getaddrinfo failed: %s", gai_strerror(ret));
		exit(1);
	}

	tai = ai;
	nfds = 0;
	/* we can have a maximum of 4 sockets (IPv4/IPv6(TCP/UDP)) */
	for (tai = ai; tai != NULL && nfds < 4; tai = tai->ai_next) {
		int tru = 1;

		pfds[nfds].fd = socket( tai->ai_family,
					tai->ai_socktype,
					tai->ai_protocol);
		if (pfds[nfds].fd == -1) {
			syslog(LOG_ERR, "Unable to create socket (%d)", nfds);
			exit(1);
		}
		pfds[nfds].events = POLLIN;
		ret = setsockopt(pfds[nfds].fd, SOL_SOCKET, SO_REUSEADDR,
				 (void *)&tru, sizeof(tru));


		ret = bind(pfds[nfds].fd, tai->ai_addr, tai->ai_addrlen);
		if (ret) {
			if (errno != EADDRINUSE) {
				syslog(LOG_ERR, "Unable to bind to socket");
				exit(1);
			}
			/* if EADDRINUSE it means we are on a machine
			 * with a dual ipv4/ipv6 stack that does not
			 * allow to bind on both at the same time as the
			 * ipv6 bind already allows connections on ipv4
			 * Just ignore */
			close(pfds[nfds].fd);
		} else {
			if (tai->ai_socktype == SOCK_STREAM) {
				ret = listen(pfds[nfds].fd, SOMAXCONN);
				if (ret) {
					syslog(LOG_ERR, "Unable to listen to socket");
					exit(1);
				}
			} 
			pfdtype[nfds] = tai->ai_socktype;
			nfds++;
		}
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
					handle_conn(pfds[i].fd, pfdtype[i]);
				}
			}
		}

		/* check for children exiting */
		cid = waitpid(-1, &cstatus, WNOHANG);
		if (cid != -1 && cid != 0) {
			remove_blacklist(cid);
		}
	}
}
