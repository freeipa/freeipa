/*
 * FreeIPA 2FA companion daemon
 *
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2013  Nathaniel McCallum, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
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
 */

/*
 * This file initializes a systemd socket-activated daemon which receives
 * RADIUS packets on STDIN and either proxies them to a third party RADIUS
 * server or performs authentication directly by binding to the LDAP server.
 * The choice between bind or proxy is made by evaluating LDAP configuration
 * for the given user.
 */

#include "internal.h"

#include <signal.h>
#include <stdbool.h>

/* Our global state. */
struct otpd_context ctx;

/* Implementation function for logging a request's state. See internal.h. */
void otpd_log_req_(const char * const file, int line, krad_packet *req,
                   const char * const tmpl, ...)
{
    const krb5_data *data;
    va_list ap;

#ifdef DEBUG
    if (file != NULL)
        fprintf(stderr, "%8s:%03d: ", file, line);
#else
    (void)file;
    (void)line;
#endif

    data = krad_packet_get_attr(req, krad_attr_name2num("User-Name"), 0);
    if (data == NULL)
        fprintf(stderr, "<unknown>: ");
    else
        fprintf(stderr, "%*s: ", data->length, data->data);

    va_start(ap, tmpl);
    vfprintf(stderr, tmpl, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

/* Implementation function for logging a generic error. See internal.h. */
void otpd_log_err_(const char * const file, int line, krb5_error_code code,
                   const char * const tmpl, ...)
{
    const char *msg;
    va_list ap;

    if (file != NULL)
        fprintf(stderr, "%10s:%03d: ", file, line);

    if (code != 0) {
        msg = krb5_get_error_message(ctx.kctx, code);
        fprintf(stderr, "%s: ", msg);
        krb5_free_error_message(ctx.kctx, msg);
    }

    va_start(ap, tmpl);
    vfprintf(stderr, tmpl, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

static void on_ldap_free(verto_ctx *vctx, verto_ev *ev)
{
    (void)vctx; /* Unused */
    ldap_unbind_ext_s(verto_get_private(ev), NULL, NULL);
}

static void on_signal(verto_ctx *vctx, verto_ev *ev)
{
    (void)ev; /* Unused */
    fprintf(stderr, "Signaled, exiting...\n");
    verto_break(vctx);
}

static char *find_base(LDAP *ldp)
{
    LDAPMessage *results = NULL, *entry;
    struct berval **vals = NULL;
    struct timeval timeout;
    int i, len;
    char *base = NULL, *attrs[] = {
        "namingContexts",
        "defaultNamingContext",
        NULL
    };

    timeout.tv_sec = -1;
    i = ldap_search_ext_s(ldp, "", LDAP_SCOPE_BASE, NULL, attrs,
                          0, NULL, NULL, &timeout, 1, &results);
    if (i != LDAP_SUCCESS) {
        otpd_log_err(0, "Unable to search for query base: %s",
                     ldap_err2string(i));
        goto egress;
    }

    entry = ldap_first_entry(ldp, results);
    if (entry == NULL) {
        otpd_log_err(0, "No entries found");
        goto egress;
    }

    vals = ldap_get_values_len(ldp, entry, "defaultNamingContext");
    if (vals == NULL) {
        vals = ldap_get_values_len(ldp, entry, "namingContexts");
        if (vals == NULL) {
            otpd_log_err(0, "No namingContexts found");
            goto egress;
        }
    }

    len = ldap_count_values_len(vals);
    if (len == 1)
        base = strndup(vals[0]->bv_val, vals[0]->bv_len);
    else
        otpd_log_err(0, "Too many namingContexts found");

    /* TODO: search multiple namingContexts to find the base? */

egress:
    ldap_value_free_len(vals);
    ldap_msgfree(results);
    return base;
}

/* Set up an LDAP connection as a verto event. */
static krb5_error_code setup_ldap(const char *uri, krb5_boolean bind,
                                  verto_callback *io, verto_ev **ev,
                                  char **base)
{
    struct timeval timeout;
    int err, ver, fd;
    char *basetmp;
    LDAP *ldp;

    err = ldap_initialize(&ldp, uri);
    if (err != LDAP_SUCCESS)
        return errno;

    ver = LDAP_VERSION3;
    ldap_set_option(ldp, LDAP_OPT_PROTOCOL_VERSION, &ver);

    if (bind) {
        err = ldap_sasl_bind_s(ldp, NULL, "EXTERNAL", NULL, NULL, NULL, NULL);
        if (err != LDAP_SUCCESS)
            return errno;
    }

    /* Always find the base since this forces open the socket. */
    basetmp = find_base(ldp);
    if (base != NULL) {
        if (basetmp == NULL)
            return ENOTCONN;
        *base = basetmp;
    } else {
        free(basetmp);
    }

    /* Set default timeout to just return immediately for async requests. */
    memset(&timeout, 0, sizeof(timeout));
    err = ldap_set_option(ldp, LDAP_OPT_TIMEOUT, &timeout);
    if (err != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ldp, NULL, NULL);
        return ENOMEM; /* What error code do I use? */
    }

    /* Get the file descriptor. */
    if (ldap_get_option(ldp, LDAP_OPT_DESC, &fd) != LDAP_OPT_SUCCESS) {
        ldap_unbind_ext_s(ldp, NULL, NULL);
        return EINVAL;
    }

    *ev = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                 VERTO_EV_FLAG_IO_ERROR |
                                 VERTO_EV_FLAG_IO_READ,
                       io, fd);
    if (*ev == NULL) {
        ldap_unbind_ext_s(ldp, NULL, NULL);
        return ENOMEM; /* What error code do I use? */
    }

    verto_set_private(*ev, ldp, on_ldap_free);
    return 0;
}

int main(int argc, char **argv)
{
    char hostname[HOST_NAME_MAX + 1];
    krb5_error_code retval;
    krb5_data hndata;
    verto_ev *sig;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ldap_uri>\n", argv[0]);
        return 1;
    } else {
        fprintf(stderr, "LDAP: %s\n", argv[1]);
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.exitstatus = 1;

    if (gethostname(hostname, sizeof(hostname)) < 0) {
        otpd_log_err(errno, "Unable to get hostname");
        goto error;
    }

    retval = krb5_init_context(&ctx.kctx);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to initialize context");
        goto error;
    }

    ctx.vctx = verto_new(NULL, VERTO_EV_TYPE_IO | VERTO_EV_TYPE_SIGNAL);
    if (ctx.vctx == NULL) {
        otpd_log_err(ENOMEM, "Unable to initialize event loop");
        goto error;
    }

    /* Build attrset. */
    retval = krad_attrset_new(ctx.kctx, &ctx.attrs);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to initialize attrset");
        goto error;
    }

    /* Set NAS-Identifier. */
    hndata.data = hostname;
    hndata.length = strlen(hndata.data);
    retval = krad_attrset_add(ctx.attrs, krad_attr_name2num("NAS-Identifier"),
                              &hndata);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to set NAS-Identifier");
        goto error;
    }

    /* Set Service-Type. */
    retval = krad_attrset_add_number(ctx.attrs,
                                     krad_attr_name2num("Service-Type"),
                                     KRAD_SERVICE_TYPE_AUTHENTICATE_ONLY);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to set Service-Type");
        goto error;
    }

    /* Radius Client */
    retval = krad_client_new(ctx.kctx, ctx.vctx, &ctx.client);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to initialize radius client");
        goto error;
    }

    /* Signals */
    sig = verto_add_signal(ctx.vctx, VERTO_EV_FLAG_NONE, on_signal, SIGTERM);
    if (sig == NULL) {
        otpd_log_err(ENOMEM, "Unable to initialize signal event");
        goto error;
    }
    sig = verto_add_signal(ctx.vctx, VERTO_EV_FLAG_NONE, on_signal, SIGINT);
    if (sig == NULL) {
        otpd_log_err(ENOMEM, "Unable to initialize signal event");
        goto error;
    }

    /* Standard IO */
    ctx.stdio.reader = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                              VERTO_EV_FLAG_IO_ERROR |
                                              VERTO_EV_FLAG_IO_READ,
                                    otpd_on_stdin_readable, STDIN_FILENO);
    if (ctx.stdio.reader == NULL) {
        otpd_log_err(ENOMEM, "Unable to initialize reader event");
        goto error;
    }
    ctx.stdio.writer = verto_add_io(ctx.vctx, VERTO_EV_FLAG_PERSIST |
                                              VERTO_EV_FLAG_IO_ERROR |
                                              VERTO_EV_FLAG_IO_READ,
                                    otpd_on_stdout_writable, STDOUT_FILENO);
    if (ctx.stdio.writer == NULL) {
        otpd_log_err(ENOMEM, "Unable to initialize writer event");
        goto error;
    }

    /* LDAP (Query) */
    retval = setup_ldap(argv[1], TRUE, otpd_on_query_io,
                        &ctx.query.io, &ctx.query.base);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to initialize LDAP (Query)");
        goto error;
    }

    /* LDAP (Bind) */
    retval = setup_ldap(argv[1], FALSE, otpd_on_bind_io,
                        &ctx.bind.io, NULL);
    if (retval != 0) {
        otpd_log_err(retval, "Unable to initialize LDAP (Bind)");
        goto error;
    }

    ctx.exitstatus = 0;
    verto_run(ctx.vctx);

error:
    krad_client_free(ctx.client);
    otpd_queue_free_items(&ctx.stdio.responses);
    otpd_queue_free_items(&ctx.query.requests);
    otpd_queue_free_items(&ctx.query.responses);
    otpd_queue_free_items(&ctx.bind.requests);
    otpd_queue_free_items(&ctx.bind.responses);
    free(ctx.query.base);
    verto_free(ctx.vctx);
    krb5_free_context(ctx.kctx);
    return ctx.exitstatus;
}

