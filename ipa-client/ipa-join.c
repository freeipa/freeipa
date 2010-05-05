/* Authors: Rob Crittenden <rcritten@redhat.com>
 *
 * Copyright (C) 2009  Red Hat
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
#define LDAP_DEPRECATED 1

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/utsname.h>
#include <krb5.h>
/* Doesn't work w/mozldap */
#include <ldap.h>
#include <popt.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "xmlrpc-c/base.h"
#include "xmlrpc-c/client.h"

#define NAME "ipa-join"
#define VERSION "1.0"

#define JOIN_OID "2.16.840.1.113730.3.8.3.53"

#define CAFILE "/etc/ipa/ca.crt"

#define IPA_CONFIG "/etc/ipa/default.conf"

char * read_config_file(const char *filename);
char * get_config_entry(char * data, const char *section, const char *key);

static int debug = 0;

/*
 * Translate some IPA exceptions into specific errors in this context.
 */
static int
handle_fault(xmlrpc_env * const envP) {
    if (envP->fault_occurred) {
        switch(envP->fault_code) {
        case 2100: /* unable to add new host entry or write objectClass */
            fprintf(stderr, "No permission to join this host to the IPA domain.\n");
            break;
        default:
            fprintf(stderr, "%s\n", envP->fault_string);
        }
        return 1;
    }
    return 0;
}

/* Get the IPA server from the configuration file.
 * The caller is responsible for freeing this value
 */
static char *
getIPAserver(char * data) {
    return get_config_entry(data, "global", "server");
}

/* Get the IPA realm from the configuration file.
 * The caller is responsible for freeing this value
 */
static char *
getIPArealm(char * data) {
    return get_config_entry(data, "global", "realm");
}

/* Make sure that the keytab is writable before doing anything */
static int check_perms(const char *keytab)
{
    int ret;
    int fd;

    ret = access(keytab, W_OK);
    if (ret == -1) {
        switch(errno) {
            case EACCES:
                fprintf(stderr, "No write permissions on keytab file '%s'\n", keytab);
                break;
            case ENOENT:
                /* file doesn't exist, lets touch it and see if writable */
                fd = open(keytab, O_WRONLY | O_CREAT, 0600);
                if (fd != -1) {
                    close(fd);
                    unlink(keytab);
                    return 0;
                }
                fprintf(stderr, "No write permissions on keytab file '%s'\n", keytab);
                break;
            default:
                fprintf(stderr, "access() on %s failed: errno = %d\n", keytab, errno);
                break;
        }
        return 1;
    }

    return 0;
}

/*
 * Make an XML-RPC call to methodName. This uses the curl client to make
 * a connection over SSL using the CA cert that should have been installed
 * by ipa-client-install.
 */
static void
callRPC(xmlrpc_env *            const envP,
     xmlrpc_server_info * const serverInfoP,
     const char *               const methodName,
     xmlrpc_value *             const paramArrayP,
     xmlrpc_value **            const resultPP) {

    struct xmlrpc_clientparms clientparms;
    struct xmlrpc_curl_xportparms * curlXportParmsP = NULL;
    xmlrpc_client * clientP = NULL;

    memset(&clientparms, 0, sizeof(clientparms));

    XMLRPC_ASSERT(xmlrpc_value_type(paramArrayP) == XMLRPC_TYPE_ARRAY);

    curlXportParmsP = malloc(sizeof(*curlXportParmsP));
    memset(curlXportParmsP, 0, sizeof(*curlXportParmsP));

    /* Have curl do SSL certificate validation */
    curlXportParmsP->no_ssl_verifypeer = 1;
    curlXportParmsP->no_ssl_verifyhost = 1;
    curlXportParmsP->cainfo = "/etc/ipa/ca.crt";

    clientparms.transport = "curl";
    clientparms.transportparmsP = (struct xmlrpc_xportparms *)
            curlXportParmsP;
    clientparms.transportparm_size = XMLRPC_CXPSIZE(cainfo);
    xmlrpc_client_create(envP, XMLRPC_CLIENT_NO_FLAGS, NAME, VERSION,
                         &clientparms, sizeof(clientparms),
                         &clientP);

    /* Set up kerberos negotiate authentication in curl. */
    xmlrpc_server_info_set_user(envP, serverInfoP, ":", "");
    xmlrpc_server_info_allow_auth_negotiate(envP, serverInfoP);

    /* Perform the XML-RPC call */
    if (!envP->fault_occurred) {
        xmlrpc_client_call2(envP, clientP, serverInfoP, methodName, paramArrayP, resultPP);
    }

    /* Cleanup */
    xmlrpc_server_info_free(serverInfoP);
    xmlrpc_client_destroy(clientP);
    free((void*)clientparms.transportparmsP);
}

/* The caller is responsible for unbinding the connection if ld is not NULL */
static LDAP *
connect_ldap(const char *hostname, const char *binddn, const char *bindpw) {
    LDAP *ld = NULL;
    int ssl = LDAP_OPT_X_TLS_HARD;
    int version = LDAP_VERSION3;
    int ret;
    int ldapdebug = 0;
    if (debug) {
        ldapdebug=2;
        ret = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldapdebug);
    }

    if (ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, CAFILE) != LDAP_OPT_SUCCESS)
        goto fail;

    ld = (LDAP *)ldap_init(hostname, 636);
    if (ldap_set_option(ld, LDAP_OPT_X_TLS, &ssl) != LDAP_OPT_SUCCESS) {
        fprintf(stderr, "Unable to enable SSL in LDAP\n");
        goto fail;
    }

    ret = ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (ret != LDAP_SUCCESS) {
        fprintf(stderr, "Unable to set LDAP version\n");
        goto fail;
    }

    ret = ldap_bind_s(ld, binddn, bindpw, LDAP_AUTH_SIMPLE);
    if (ret != LDAP_SUCCESS) {
        int err;

        ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &err);
        if (debug)
            fprintf(stderr, "Bind failed: %s\n", ldap_err2string(err));
        goto fail;
    }

    return ld;

fail:
    if (ld != NULL) {
        ldap_unbind_ext(ld, NULL, NULL);
    }
    return NULL;
}

static int
get_root_dn(const char *ipaserver, char **ldap_base)
{
    LDAP *ld = NULL;
    char *root_attrs[] = {"namingContexts", NULL};
    LDAPMessage *entry, *res = NULL;
    struct berval **ncvals;
    int ret, rval = 0;

    ld = connect_ldap(ipaserver, NULL, NULL);
    if (!ld) {
        rval = 14;
        goto done;
    }

    ret = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE,
                            "objectclass=*", root_attrs, 0,
                            NULL, NULL, NULL, 0, &res);

    if (ret != LDAP_SUCCESS) {
        fprintf(stderr, "Search for %s on rootdse failed with error %d",
                root_attrs[0], ret);
        rval = 14;
        goto done;
    }

    /* for now just use the first result we get */
    entry = ldap_first_entry(ld, res);
    ncvals = ldap_get_values_len(ld, entry, root_attrs[0]);
    if (!ncvals) {
        fprintf(stderr, "No values for %s", root_attrs[0]);
        rval = 14;
        goto done;
    }

    *ldap_base = strdup(ncvals[0]->bv_val);

    ldap_value_free_len(ncvals);

done:
    if (res) ldap_msgfree(res);
    if (ld != NULL) {
        ldap_unbind_ext(ld, NULL, NULL);
    }

    return rval;
}

static int
get_subject(const char *ipaserver, char *ldap_base, char **subject)
{
    LDAP *ld = NULL;
    char *attrs[] = {"ipaCertificateSubjectBase", NULL};
    char base[LINE_MAX];
    LDAPMessage *entry, *res = NULL;
    struct berval **ncvals;
    int ret, rval = 0;

    ld = connect_ldap(ipaserver, NULL, NULL);
    if (!ld) {
        rval = 14;
        goto done;
    }

    strcpy(base, "cn=ipaconfig,cn=etc,");
    strcat(base, ldap_base);

    ret = ldap_search_ext_s(ld, base, LDAP_SCOPE_BASE,
                            "objectclass=*", attrs, 0,
                            NULL, NULL, NULL, 0, &res);

    if (ret != LDAP_SUCCESS) {
        fprintf(stderr, "Search for ipaCertificateSubjectBase failed with error %d",
                attrs[0], ret);
        rval = 14;
        goto done;
    }

    entry = ldap_first_entry(ld, res);
    ncvals = ldap_get_values_len(ld, entry, attrs[0]);
    if (!ncvals) {
        fprintf(stderr, "No values for %s", attrs[0]);
        rval = 14;
        goto done;
    }

    *subject = strdup(ncvals[0]->bv_val);

    ldap_value_free_len(ncvals);

done:
    if (res) ldap_msgfree(res);
    if (ld != NULL) {
        ldap_unbind_ext(ld, NULL, NULL);
    }

    return rval;
}

/* Join a host to the current IPA realm.
 *
 * There are several scenarios for this:
 * 1. You are an IPA admin user with fullrights to add hosts and generate
 *    keytabs.
 * 2. You are an IPA admin user with rights to generate keytabs but not
 *    write hosts.
 * 3. You are a regular IPA user with a password that can be used to
 *   generate the host keytab.
 *
 * If a password is presented it will be used regardless of the rights of
 * the user.
 */

/* If we only have a bindpw then try to join in a bit of a degraded mode.
 * This is going to duplicate some of the server-side code to determine
 * the state of the entry.
 */
static int
join_ldap(const char *ipaserver, const char *hostname, const char ** binddn, const char *bindpw, const char **princ, const char **subject, int quiet)
{
    LDAP *ld;
    char *filter = NULL;
    int rval = 0;
    char *oidresult;
    struct berval valrequest;
    struct berval *valresult = NULL;
    int rc, ret;
    LDAPMessage *result, *e;
    char *ldap_base = NULL;
    char *search_base = NULL;
    char * attrs[] = {"krbPrincipalName", NULL};
    struct berval **ncvals;
    int has_principal = 0;

    *binddn = NULL;

    if (get_root_dn(ipaserver, &ldap_base) != 0) {
        fprintf(stderr, "Unable to determine root DN of %s\n", ipaserver);
        rval = 14;
        goto done;
    }

    if (get_subject(ipaserver, ldap_base, &subject) != 0) {
        fprintf(stderr, "Unable to determine certificate subject of %s\n", ipaserver);
        /* Not a critical failure */
    }

    ld = connect_ldap(ipaserver, NULL, NULL);
    if (!ld) {
        fprintf(stderr, "Unable to make an LDAP connection to %s\n", ipaserver);
        rval = 14;
        goto done;
    }
    /* Search for the entry. */
    asprintf(&filter, "(fqdn=%s)", hostname);
    asprintf(&search_base, "cn=computers,cn=accounts,%s", ldap_base);
    if (debug) {
        fprintf(stderr, "Searching with %s in %s\n", filter, search_base);
    }
    if ((ret = ldap_search_ext_s(ld, ldap_base, LDAP_SCOPE_SUB,
         filter, attrs, 0, NULL, NULL, LDAP_NO_LIMIT,
         LDAP_NO_LIMIT, &result)) != LDAP_SUCCESS) {
        fprintf(stderr, "ldap_search_ext_s: %s\n", ldap_err2string(ret));
        rval = 14;
        goto ldap_done;
    }
    e = ldap_first_entry(ld, result);
    if (!e) {
        fprintf(stderr, "Unable to find host '%s'\n", hostname);
        rval = 14;
        goto ldap_done;
    }
    if ((*binddn = ldap_get_dn(ld, e)) == NULL) {
        fprintf(stderr, "Unable to get binddn for host '%s'\n", hostname);
        rval = 14;
        goto ldap_done;
    }
    ncvals = ldap_get_values_len(ld, e, attrs[0]);
    if (ncvals != NULL) {
        /* This host is probably already registered. The krbprincipalname
         * is not set on password protected entries, but lets try to bind
         * anyway.
         */
        has_principal = 1;
        if (debug)
            fprintf(stderr, "Host already has principal, trying bind anyway\n");
    }

    ldap_value_free_len(ncvals);
    ldap_msgfree(result);
    if (ld != NULL) {
        ldap_unbind_ext(ld, NULL, NULL);
    }

    /* Now rebind as the host */
    ld = connect_ldap(ipaserver, *binddn, bindpw);
    if (!ld) {
        if (has_principal) {
            fprintf(stderr, "Host is already joined.\n");
            rval = 13;
        } else {
            fprintf(stderr, "Incorrect password.\n");
            rval = 15;
        }
        goto done;
    }

    valrequest.bv_val = (char *)hostname;
    valrequest.bv_len = strlen(hostname);

    if ((rc = ldap_extended_operation_s(ld, JOIN_OID, &valrequest, NULL, NULL, &oidresult, &valresult)) != LDAP_SUCCESS) {
        fprintf(stderr, "principal not found in host entry\n");
        if (debug) ldap_perror(ld, "ldap_extended_operation_s");
        rval = 12;
        goto ldap_done;
    }

    /* Get the value from the result returned by the server. */
    *princ = strdup(valresult->bv_val);

ldap_done:

    free(filter);
    free(search_base);
    free(ldap_base);
    free(subject);
    if (ld != NULL) {
        ldap_unbind_ext(ld, NULL, NULL);
    }

done:
    if (valresult) ber_bvfree(valresult);
    return rval;
}

static int
join_krb5(const char *ipaserver, const char *hostname, const char **hostdn, const char **princ, const char **subject, int quiet) {
    xmlrpc_env env;
    xmlrpc_value * argArrayP = NULL;
    xmlrpc_value * paramArrayP = NULL;
    xmlrpc_value * paramP = NULL;
    xmlrpc_value * optionsP = NULL;
    xmlrpc_value * resultP = NULL;
    xmlrpc_value * structP = NULL;
    xmlrpc_server_info * serverInfoP = NULL;
    struct utsname uinfo;
    xmlrpc_value *princP = NULL;
    xmlrpc_value *krblastpwdchangeP = NULL;
    xmlrpc_value *subjectP = NULL;
    xmlrpc_value *hostdnP = NULL;
    const char *krblastpwdchange = NULL;
    char * url = NULL;
    int rval = 0;

    /* Start up our XML-RPC client library. */
    xmlrpc_client_init(XMLRPC_CLIENT_NO_FLAGS, NAME, VERSION);

    uname(&uinfo);

    xmlrpc_env_init(&env);

    xmlrpc_client_setup_global_const(&env);

#if 1
    asprintf(&url, "https://%s:443/ipa/xml", ipaserver);
#else
    asprintf(&url, "http://%s:8888/", ipaserver);
#endif
    serverInfoP = xmlrpc_server_info_new(&env, url);

    argArrayP = xmlrpc_array_new(&env);
    paramArrayP = xmlrpc_array_new(&env);

    if (hostname == NULL)
        paramP = xmlrpc_string_new(&env, uinfo.nodename);
    else
        paramP = xmlrpc_string_new(&env, hostname);
    xmlrpc_array_append_item(&env, argArrayP, paramP);
#ifdef REALM
    if (!quiet)
        printf("Joining %s to IPA realm %s\n", uinfo.nodename, iparealm);
#endif
    xmlrpc_array_append_item(&env, paramArrayP, argArrayP);
    xmlrpc_DECREF(paramP);

    optionsP = xmlrpc_build_value(&env, "{s:s,s:s}",
                                  "nsosversion", uinfo.release,
                                  "nshardwareplatform", uinfo.machine);
    xmlrpc_array_append_item(&env, paramArrayP, optionsP);
    xmlrpc_DECREF(optionsP);

    callRPC(&env, serverInfoP, "join", paramArrayP, &resultP);
    if (handle_fault(&env)) {
        rval = 1;
        goto cleanup_xmlrpc;
    }

    /* Return value is the form of an array. The first value is the
     * DN, the second a struct of attribute values
     */
    xmlrpc_array_read_item(&env, resultP, 0, &hostdnP);
    xmlrpc_read_string(&env, hostdnP, &*hostdn);
    xmlrpc_DECREF(hostdnP);
    xmlrpc_array_read_item(&env, resultP, 1, &structP);

    xmlrpc_struct_find_value(&env, structP, "krbprincipalname", &princP);
    if (princP) {
        xmlrpc_value * singleprincP = NULL;

        /* FIXME: all values are returned as lists currently. Once this is
         * fixed we can read the string directly.
         */
        xmlrpc_array_read_item(&env, princP, 0, &singleprincP);
        xmlrpc_read_string(&env, singleprincP, &*princ);
        xmlrpc_DECREF(princP);
        xmlrpc_DECREF(singleprincP);
    } else {
        fprintf(stderr, "principal not found in XML-RPC response\n");
        rval = 12;
        goto cleanup;
    }
    xmlrpc_struct_find_value(&env, structP, "krblastpwdchange", &krblastpwdchangeP);
    if (krblastpwdchangeP) {
        xmlrpc_value * singleprincP = NULL;

        /* FIXME: all values are returned as lists currently. Once this is
         * fixed we can read the string directly.
         */
        xmlrpc_array_read_item(&env, krblastpwdchangeP, 0, &singleprincP);
        xmlrpc_read_string(&env, singleprincP, &krblastpwdchange);
        xmlrpc_DECREF(krblastpwdchangeP);
        fprintf(stderr, "Host is already joined.\n");
        rval = 13;
        goto cleanup;
    }

    xmlrpc_struct_find_value(&env, structP, "ipacertificatesubjectbase", &subjectP);
    if (subjectP) {
        xmlrpc_value * singleprincP = NULL;

        /* FIXME: all values are returned as lists currently. Once this is
         * fixed we can read the string directly.
         */
        xmlrpc_array_read_item(&env, subjectP, 0, &singleprincP);
        xmlrpc_read_string(&env, singleprincP, *&subject);
        xmlrpc_DECREF(subjectP);
    }

cleanup:
    if (argArrayP) xmlrpc_DECREF(argArrayP);
    if (paramArrayP) xmlrpc_DECREF(paramArrayP);
    if (resultP) xmlrpc_DECREF(resultP);

cleanup_xmlrpc:
    free(url);
//    free((char *)princ);
//    free((char *)hostdn);
    free((char *)krblastpwdchange);
    xmlrpc_env_clean(&env);
    xmlrpc_client_cleanup();

    return rval;
}

static int
join(const char *server, const char *hostname, const char *bindpw, const char *keytab, int quiet)
{
    int rval;
    pid_t childpid = 0;
    int status = 0;
    char *ipaserver = NULL;
    char *iparealm = NULL;
    const char * princ = NULL;
    const char * subject = NULL;
    const char * hostdn = NULL;
    struct utsname uinfo;

    krb5_context krbctx = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal uprinc = NULL;
    krb5_error_code krberr;

    if (server) {
        ipaserver = strdup(server);
    } else {
        char * conf_data = read_config_file(IPA_CONFIG);
        if ((ipaserver = getIPAserver(conf_data)) == NULL) {
            fprintf(stderr, "Unable to determine IPA server from %s\n", IPA_CONFIG);
            exit(1);
        }
        free(conf_data);
    }

    if (NULL == hostname) {
        uname(&uinfo);
        hostname = strdup(uinfo.nodename);
    }

    if (NULL == strstr(hostname, ".")) {
        fprintf(stderr, "The hostname must be fully-qualified: %s\n", hostname);
        rval = 16;
        goto cleanup;
    }

    if (bindpw)
        rval = join_ldap(ipaserver, hostname, &hostdn, bindpw, &princ, &subject, quiet);
    else {
        krberr = krb5_init_context(&krbctx);
        if (krberr) {
            fprintf(stderr, "Unable to join host: Kerberos context initialization failed\n");
            rval = 1;
            goto cleanup;
        }
        krberr = krb5_cc_default(krbctx, &ccache);
        if (krberr) {
            fprintf(stderr, "Unable to join host: Kerberos Credential Cache not found\n");
            rval = 5;
            goto cleanup;
        }

        krberr = krb5_cc_get_principal(krbctx, ccache, &uprinc);
        if (krberr) {
            fprintf(stderr, "Unable to join host: Kerberos User Principal not found and host password not provided.\n");
            rval = 6;
            goto cleanup;
        }
        rval = join_krb5(ipaserver, hostname, &hostdn, &princ, &subject, quiet);
    }

    if (rval) goto cleanup;

    /* Fork off and let ipa-getkeytab generate the keytab for us */
    childpid = fork();

    if (childpid < 0) {
        fprintf(stderr, "fork() failed\n");
        rval = 1;
        goto cleanup;
    }

    if (childpid == 0) {
        char *argv[12];
        char *path = "/usr/sbin/ipa-getkeytab";
        int arg = 0;
        int err;

        argv[arg++] = path;
        argv[arg++] = "-s";
        argv[arg++] = ipaserver;
        argv[arg++] = "-p";
        argv[arg++] = (char *)princ;
        argv[arg++] = "-k";
        argv[arg++] = (char *)keytab;
        if (bindpw) {
            argv[arg++] = "-D";
            argv[arg++] = (char *)hostdn;
            argv[arg++] = "-w";
            argv[arg++] = (char *)bindpw;
        }
        argv[arg++] = NULL;
        err = execv(path, argv);
        if (err == -1) {
            switch(errno) {
                case ENOENT:
                    fprintf(stderr, "ipa-getkeytab not found\n");
                    break;
                case EACCES:
                    fprintf(stderr, "ipa-getkeytab has bad permissions?\n");
                    break;
                default:
                    fprintf(stderr, "executing ipa-getkeytab failed, errno %d\n", errno);
                    break;
            }
        }
    } else {
        wait(&status);
    }

    if WIFEXITED(status) {
        rval = WEXITSTATUS(status);
        if (rval != 0) {
            fprintf(stderr, "child exited with %d\n", rval);
        }
    }

cleanup:
    if (NULL != subject)
        fprintf(stderr, "Certificate subject base is: %s\n", subject);

    free((char *)princ);
    free((char *)subject);
    if (bindpw)
        ldap_memfree((void *)hostdn);
    else
        free((char *)hostdn);
    free((char *)ipaserver);
    free((char *)iparealm);
    if (uprinc) krb5_free_principal(krbctx, uprinc);
    if (ccache) krb5_cc_close(krbctx, ccache);
    if (krbctx) krb5_free_context(krbctx);

    return rval;
}

/*
 * Note, an intention with return values is so that this is compatible with
 * ipa-getkeytab. This is so based on the return value you can distinguish
 * between errors common between the two (no kerbeors ccache) and those
 * unique (host already added).
 */
int
main(int argc, char **argv) {
    static const char *hostname = NULL;
    static const char *server = NULL;
    static const char *keytab = NULL;
    static const char *bindpw = NULL;
    int quiet = 0;
    struct poptOption options[] = {
            { "debug", 'd', POPT_ARG_NONE, &debug, 0, "Print the raw XML-RPC output", "XML-RPC debugging Output"},
            { "quiet", 'q', POPT_ARG_NONE, &quiet, 0, "Print as little as possible", "Output only on errors"},
            { "hostname", 'h', POPT_ARG_STRING, &hostname, 0, "Use this hostname instead of the node name", "Host Name" },
            { "server", 's', POPT_ARG_STRING, &server, 0, "IPA Server to use", "IPA Server Name" },
            { "keytab", 'k', POPT_ARG_STRING, &keytab, 0, "File were to store the keytab information", "Keytab File Name" },
            { "bindpw", 'w', POPT_ARG_STRING, &bindpw, 0, "LDAP password", "password to use if not using kerberos" },
            POPT_AUTOHELP
            POPT_TABLEEND
    };
    poptContext pc;
    int ret;

    pc = poptGetContext("ipa-join", argc, (const char **)argv, options, 0);
    ret = poptGetNextOpt(pc);
    if (ret != -1) {
        if (!quiet) {
            poptPrintUsage(pc, stderr, 0);
        }
        exit(2);
    }
    poptFreeContext(pc);
    if (debug)
        setenv("XMLRPC_TRACE_XML", "1", 1);

    if (!keytab)
        keytab = "/etc/krb5.keytab";

    ret = check_perms(keytab);
    if (ret == 0)
        ret = join(server, hostname, bindpw, keytab, quiet);

    exit(ret);
}
