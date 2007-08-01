
/* Kpasswd-LDAP proxy */

/* (C) Simo Sorce */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <krb5.h>
#include <ldap.h>
#include <sasl/sasl.h>

#define KPASSWD_PORT 464
#define KPASSWD_TCP 1
#define KPASSWD_UDP 2

int debug = 1;
char *srv_pri_name = "kadmin/changepw";
char *keytab_name = "FILE:/var/kerberos/krb5kdc/kpasswd.keytab";
char *realm_name = "BLUEBOX.REDHAT.COM";
char *ldap_uri = "ldap://rc1.bluebox.redhat.com:389";

int ldap_sasl_interact(LDAP *ld, unsigned flags, void *priv_data, void *sit)
{
	sasl_interact_t **in = sit;
	int i, ret = LDAP_OTHER;

	if (!ld) return LDAP_PARAM_ERROR;

	for (i = 0; in[i] && in[i]->id != SASL_CB_LIST_END; i++) {
		switch(in[i]->id) {
		case SASL_CB_USER:
			in[i]->result = srv_pri_name;
			in[i]->len = strlen(srv_pri_name);
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			in[i]->result = realm_name;
			in[i]->len = strlen(realm_name);
			ret = LDAP_SUCCESS;
			break;
		default:
			if (debug > 0) {
				fprintf(stderr,
					"Unhandled SASL int. option %d\n",
					in[i]->id);
			}
			in[i]->result = NULL;
			in[i]->len = 0;
			ret = LDAP_OTHER;
		}
	}
        return ret;
}

int ldap_pwd_change(char *client_name, krb5_data pwd)
{
	int id, version;
	LDAP *ld = NULL;
	BerElement *ctrl = NULL;
	struct berval control;
	struct berval newpw;
	char *userdn = NULL;
	int ret;

	newpw.bv_len = pwd.length;
	newpw.bv_val = pwd.data;

	/* connect to ldap server */
	/* TODO: support referrals ? */
	ret = ldap_initialize(&ld, ldap_uri);
	if(ret != LDAP_SUCCESS) {
		fprintf(stderr, "Unable to connect to ldap server");
		ret = -1;
		goto done;
	}

	version = LDAP_VERSION3;
	ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
        if (ret != LDAP_OPT_SUCCESS) {
		fprintf(stderr, "Unable to set ldap protocol version");
		ret = -1;
		goto done;
	}

	ret = ldap_sasl_interactive_bind_s(ld,
					   NULL, "GSSAPI",
					   NULL, NULL,
					   LDAP_SASL_AUTOMATIC,
					   ldap_sasl_interact, NULL);
	if (ret != LDAP_SUCCESS) {
		fprintf(stderr, "Unable to bind to ldap server");
		ret = -1;
		goto done;
	}

	/* find user dn */

	/* build password change control */
	ctrl = ber_alloc_t(LBER_USE_DER);
	if (!ctrl) {
		fprintf(stderr, "Out of memory!\n");
		ret = -1;
		goto done;
	}
	ber_printf(ctrl, "{tstON}",
		   LDAP_TAG_EXOP_MODIFY_PASSWD_ID, userdn,
		   LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, &newpw);

	ret = ber_flatten2(ctrl, &control, 0);
	if (ret < 0) {
		fprintf(stderr, "ber flattening failed!\n");
		ret = -1;
		goto done;
	}

	/* perform poassword change */
	ret = ldap_extended_operation(ld, LDAP_EXOP_MODIFY_PASSWD,
				      &control, NULL, NULL, &id);
done:
	if (ctrl) ber_free(ctrl, 1);
	if (ld) 
	return ret;
}

void handle_krb_packets(uint8_t *buf, ssize_t buflen,
			struct sockaddr_in *from,
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
	int krberr, err;
	struct sockaddr_in laddr, raddr;
	socklen_t addrlen;
	size_t reqlen;
	size_t verno;
	char *client_name;
	char *result_string;
	int result_err;
	uint8_t *reply;
	ssize_t replylen;

	*replen = 0;

	auth_context = NULL;
	krep.length = 0;
	krep.data = NULL;
	kprincpw = NULL;
	ticket = NULL;
	lkaddr = NULL;

	rkaddr.addrtype = ADDRTYPE_INET;
	rkaddr.length = sizeof(from->sin_addr);
	rkaddr.contents = (krb5_octet *) &from->sin_addr;

	if (buflen < 4) {
		result_string = "Request truncated";
		result_err = KRB5_KPASSWD_MALFORMED;
		fprintf(stderr, "%s\n", result_string);
		goto done;
	}

	reqlen = (buf[0] << 8) + buf[1];

	if (reqlen != buflen) {
		result_string = "Unmatching request length";
		result_err = KRB5_KPASSWD_MALFORMED;
		fprintf(stderr, "%s\n", result_string);
		goto done;
	}

	verno = (buf[2] << 8) + buf[3];

	if (verno != 1) {
		result_string = "Unsupported version";
		result_err = KRB5_KPASSWD_BAD_VERSION;
		fprintf(stderr, "%s\n", result_string);
		goto done;
	}

	kreq.length = (buf[4] << 8) + buf[5];
	if (kreq.length > (buflen - 6)) {
		result_string = "Request truncated";
		result_err = KRB5_KPASSWD_MALFORMED;
		fprintf(stderr, "%s\n", result_string);
		goto done;
	}
	kreq.data = &buf[6];

	krberr = krb5_init_context(&context);
	if (krberr) {
		result_string = "Failed to init kerberos context";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s\n", result_string);
		goto done;
	}

	krberr = krb5_auth_con_init(context, &auth_context);
	if (krberr) {
		result_string = "Unable to init auth context";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s: %s\n", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_auth_con_setflags(context, auth_context,
					KRB5_AUTH_CONTEXT_DO_SEQUENCE);
	if (krberr) {
		result_string = "Unable to init auth context";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s: %s\n", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_build_principal(context, &kprincpw,
				      strlen(realm_name), realm_name,
				      "kadmin", "changepw", NULL);
	if (krberr) {
		result_string = "Unable to build principal";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s: %s\n", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_kt_resolve(context, keytab_name, &keytab);
	if (krberr) {
		result_string = "Unable to retrieve keytab";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s: %s\n", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_rd_req(context, &auth_context, &kreq,
			     kprincpw, keytab, NULL, &ticket);
	if (krberr) {
		result_string = "Unable to read request";
		result_err = KRB5_KPASSWD_AUTHERROR;
		fprintf(stderr, "%s: %s\n", result_string,
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
		fprintf(stderr, "%s: %s\n", result_string,
			krb5_get_error_message(context, krberr));
		goto done;
	}

	/* verify that this is an AS_REQ ticket */
	if (!(ticket->enc_part2->flags & TKT_FLG_INITIAL)) {
		result_string = "Ticket must be derived from a password";
		result_err = KRB5_KPASSWD_AUTHERROR;
		fprintf(stderr, "%s\n", result_string);
		goto kpreply;
	}

	krberr = krb5_unparse_name(context, ticket->enc_part2->client,
				   &client_name);
	if (krberr) {
		result_string = "Unable to parse client name";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s\n", result_string);
		goto kpreply;
	}

	krberr = krb5_auth_con_setaddrs(context, auth_context, NULL, &rkaddr);
	if (krberr) {
		result_string = "Failed to set client address";
		result_err = KRB5_KPASSWD_HARDERROR;
		fprintf(stderr, "%s: %s\n", result_string,
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
		fprintf(stderr, "%s: %s\n", result_string,
			krb5_get_error_message(context, krberr));
		goto kpreply;
	}

	if (debug > 0) {
		fprintf(stderr, "Client %s trying to set password [%*s]\n",
			client_name, kdec.length, kdec.data);
	}

	err = ldap_pwd_change(client_name, kdec);

	/* ok we are done, and the password change was successful! */
	result_err = KRB5_KPASSWD_SUCCESS;
	result_string = "";

	/* make sure password is cleared off before we free the memory */
	memset(kdec.data, 0, kdec.length);
	free(kdec.data);

kpreply:

	/* set-up the the clear text reply */
	kdec.length = 2 + strlen(result_string);
	kdec.data = malloc(kdec.length);
	if (!kdec.data) {
		fprintf(stderr, "Out of memory!\n");
		goto done;
	}
	
	kdec.data[0] = (result_err >> 8) & 0xff;
	kdec.data[1] = result_err & 0xff;
	memcpy(&kdec.data[2], result_string, strlen(result_string));

	/* we listen on ANYADDR, use this retrieve the right address */
        krberr = krb5_os_localaddr(context, &lkaddr);
	if (krberr) {
		result_string = "Failed to retrieve local address";
		fprintf(stderr, "%s: %s\n", result_string, 
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_auth_con_setaddrs(context, auth_context, lkaddr[0], NULL);
	if (krberr) {
		result_string = "Failed to set local address";
		fprintf(stderr, "%s: %s\n", result_string, 
			krb5_get_error_message(context, krberr));
		goto done;
	}

	krberr = krb5_mk_priv(context, auth_context, &kdec, &kenc, &replay);
	if (krberr) {
		result_string = "Failed to encrypt reply message";
		fprintf(stderr, "%s: %s\n", result_string, 
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
			fprintf(stderr, "%s: %s\n", result_string, 
				krb5_get_error_message(context, krberr));
			goto done;
		}

		krb5err.text.length = 0;
		krb5err.e_data = kdec;
		krberr = krb5_mk_error(context, &krb5err, &kenc);
		if (krberr) {
			result_string = "Failed to build error message";
			fprintf(stderr, "%s: %s\n", result_string, 
				krb5_get_error_message(context, krberr));
			goto done;
		}
	}

	replylen = 6 + krep.length + kenc.length;
	reply = malloc(replylen);
	if (!reply) {
		fprintf(stderr, "Out of memory!\n");
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
	krb5_free_context(context);
}

pid_t handle_conn(int fd, int type)
{
	int mfd;
	pid_t pid;
	uint8_t request[1500];
	ssize_t reqlen;
	uint8_t *reply;
	ssize_t replen;
	struct sockaddr_in from;
	socklen_t fromlen;

	fromlen = sizeof(from);

	/* receive request */
	if (type == KPASSWD_TCP) {

		mfd = accept(fd, (struct sockaddr *)&from, &fromlen);
		if (mfd == -1) {
			fprintf(stderr, "Accept failed with error (%d) %s\n",
				errno, strerror(errno));
			return -1;
		}
	} else {
		mfd = fd;
	}

	reqlen = recvfrom(mfd, request, sizeof(request), 0,
			   (struct sockaddr *)&from, &fromlen);
	if (reqlen <= 0) {
		fprintf(stderr, "Error receiving request (%d) %s\n",
			errno, strerror(errno));
		if (type == KPASSWD_TCP) close(mfd);
		return -1;
	}

	if (debug > 0) {
		uint32_t host = ntohl(from.sin_addr.s_addr);
		uint16_t port = ntohs(from.sin_port);
		fprintf(stderr,
			"Connection from %d.%d.%d.%d:%d\n",
			(host & 0xff000000) >> 24,
			(host & 0x00ff0000) >> 16,
			(host & 0x0000ff00) >> 8,
			host & 0x000000ff,
			port);
	}

#if 1
	/* handle kerberos and ldap operations in childrens */
	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Fork failed with error (%d) %s\n",
			errno, strerror(errno));
		if (type == KPASSWD_TCP) close(mfd);
		return 0;
	}
	if (pid != 0) { /* parent */
		if (type == KPASSWD_TCP) close(mfd);
		return pid;
	}
#endif
	/* children */
	handle_krb_packets(request, reqlen, &from, &reply, &replen);

	if (replen) { /* we have something to reply */
		if (type == KPASSWD_TCP) {
			sendto(mfd, reply, replen, 0, NULL, 0);
		} else {
			sendto(mfd, reply, replen, 0, (struct sockaddr *)&from, fromlen);
		}
	}
	close(mfd);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct sockaddr_in addr;
	int tcp_s, udp_s;
	int tru = 1;
	int ret;

	tcp_s = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_s == -1) {
		fprintf(stderr, "Unable to create TCP socket\n");
		exit(1);
	}

	udp_s = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_s == -1) {
		fprintf(stderr, "Unable to create UDP socket\n");
		close(tcp_s);
		exit(1);
	}

	/* make sockets immediately reusable */
        ret = setsockopt(tcp_s, SOL_SOCKET, SO_REUSEADDR,
			 (void *)&tru, sizeof(tru));
	if (ret == -1) {
		fprintf(stderr,
			"Unable to set SO_REUSEADDR for the TCP socket (%d) %s\n",
			errno, strerror(errno));
		close(tcp_s);
		close(udp_s);
		exit(2);
	}

        ret = setsockopt(udp_s, SOL_SOCKET, SO_REUSEADDR,
			 (void *)&tru, sizeof(tru));
	if (ret == -1) {
		fprintf(stderr,
			"Unable to set SO_REUSEADDR for the UDP socket (%d) %s\n",
			errno, strerror(errno));
		close(tcp_s);
		close(udp_s);
		exit(2);
	}

	/* bind sockets */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(KPASSWD_PORT);

	ret = bind(tcp_s, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		fprintf(stderr,
			"Unable to bind the TCP kpasswd port (%d) %s\n",
			errno, strerror(errno));
		close(tcp_s);
		close(udp_s);
		exit(3);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(KPASSWD_PORT);

	ret = bind(udp_s, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		fprintf(stderr,
			"Unable to bind the UDP kpasswd port (%d) %s\n",
			errno, strerror(errno));
		close(tcp_s);
		close(udp_s);
		exit(3);
	}

	ret = listen(tcp_s, 5);
	if (ret == -1) {
		fprintf(stderr,
			"Unable to listen oin the TCP socket (%d) %s\n",
			errno, strerror(errno));
		close(tcp_s);
		close(udp_s);
		exit(4);
	}

	/* now that sockets are set up, enter the select loop */

	while (1) {
		int cstatus;
		fd_set rfd;

		FD_ZERO(&rfd);
		FD_SET(udp_s, &rfd);
		FD_SET(tcp_s, &rfd);

		ret = select(udp_s+1, &rfd, NULL, NULL, NULL);

		switch(ret) {
		case 0:
			break;
		case -1:
			if (errno != EINTR) {
				fprintf(stderr,
					"Unexpected error in select (%d) %s\n",
					errno, strerror(errno));
				exit(5);
			}
			break;
		default:
			if (FD_ISSET(tcp_s, &rfd)) {
				handle_conn(tcp_s, KPASSWD_TCP);
				break;
			}
			if (FD_ISSET(udp_s, &rfd)) {
				handle_conn(udp_s, KPASSWD_UDP);
				break;
			}
			/* what else?? */
			fprintf(stderr, "Select returned but no fd ready\n");
			exit(6);
		}

		/* check for children exiting */
		waitpid(-1, &cstatus, WNOHANG);
	}
}
