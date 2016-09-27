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
 * This file receives requests (from stdio.c) and queries the LDAP server for
 * the user's configuration. When the user's configuration is received, it is
 * parsed (parse.c). Once the configuration is parsed, the request packet is
 * either forwarded to a third-party RADIUS server (forward.c) or authenticated
 * directly via an LDAP bind (bind.c) based on the configuration received.
 */

#define _GNU_SOURCE 1 /* for asprintf() */
#include "internal.h"
#include <ctype.h>

#define DEFAULT_TIMEOUT 15
#define DEFAULT_RETRIES 3

static char *user[] = {
    "uid",
    "ipatokenRadiusUserName",
    "ipatokenRadiusConfigLink",
    NULL
};

static char *radius[] = {
    "ipatokenRadiusServer",
    "ipatokenRadiusSecret",
    "ipatokenRadiusTimeout",
    "ipatokenRadiusRetries",
    "ipatokenUserMapAttribute",
    NULL
};

/* Send queued LDAP requests to the server. */
static void on_query_writable(verto_ctx *vctx, verto_ev *ev)
{
    struct otpd_queue *push = &ctx.stdio.responses;
    const krb5_data *princ = NULL;
    char *filter = NULL, *attrs[2];
    int i = LDAP_SUCCESS;
    struct otpd_queue_item *item;
    (void)vctx;

    item = otpd_queue_pop(&ctx.query.requests);
    if (item == NULL) {
        verto_set_flags(ctx.query.io, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ);
        return;
    }

    if (item->user.dn == NULL) {
        princ = krad_packet_get_attr(item->req,
                                     krad_attr_name2num("User-Name"), 0);
        if (princ == NULL)
            goto error;

        otpd_log_req(item->req, "user query start");

        if (asprintf(&filter, "(&(objectClass=Person)(krbPrincipalName=%*s))",
                     princ->length, princ->data) < 0)
            goto error;

        i = ldap_search_ext(verto_get_private(ev), ctx.query.base,
                            LDAP_SCOPE_SUBTREE, filter, user, 0, NULL,
                            NULL, NULL, 1, &item->msgid);
        free(filter);

    } else if (item->radius.ipatokenRadiusSecret == NULL) {
        otpd_log_req(item->req, "radius query start: %s",
                item->user.ipatokenRadiusConfigLink);

        i = ldap_search_ext(verto_get_private(ev),
                            item->user.ipatokenRadiusConfigLink,
                            LDAP_SCOPE_BASE, NULL, radius, 0, NULL,
                            NULL, NULL, 1, &item->msgid);

    } else if (item->radius.ipatokenUserMapAttribute != NULL) {
        otpd_log_req(item->req, "username query start: %s",
                item->radius.ipatokenUserMapAttribute);

        attrs[0] = item->radius.ipatokenUserMapAttribute;
        attrs[1] = NULL;
        i = ldap_search_ext(verto_get_private(ev), item->user.dn,
                            LDAP_SCOPE_BASE, NULL, attrs, 0, NULL,
                            NULL, NULL, 1, &item->msgid);
    }

    if (i == LDAP_SUCCESS) {
        item->sent++;
        push = &ctx.query.responses;
    }

error:
    otpd_queue_push(push, item);
}

/* Read LDAP responses from the server. */
static void on_query_readable(verto_ctx *vctx, verto_ev *ev)
{
    struct otpd_queue *push = &ctx.stdio.responses;
    verto_ev *event = ctx.stdio.writer;
    LDAPMessage *results, *entry;
    struct otpd_queue_item *item = NULL;
    const char *err;
    LDAP *ldp;
    int i;
    (void)vctx;

    ldp = verto_get_private(ev);

    i = ldap_result(ldp, LDAP_RES_ANY, 0, NULL, &results);
    if (i != LDAP_RES_SEARCH_ENTRY && i != LDAP_RES_SEARCH_RESULT) {
        if (i <= 0)
            results = NULL;
        ldap_msgfree(results);
        otpd_log_err(EIO, "IO error received on query socket");
        verto_break(ctx.vctx);
        ctx.exitstatus = 1;
        return;
    }

    item = otpd_queue_pop_msgid(&ctx.query.responses, ldap_msgid(results));
    if (item == NULL)
        goto egress;

    if (i == LDAP_RES_SEARCH_ENTRY) {
        entry = ldap_first_entry(ldp, results);
        if (entry == NULL)
            goto egress;

        err = NULL;
        switch (item->sent) {
        case 1:
            err = otpd_parse_user(ldp, entry, item);
            break;
        case 2:
            err = otpd_parse_radius(ldp, entry, item);
            break;
        case 3:
            err = otpd_parse_radius_username(ldp, entry, item);
            break;
        default:
            ldap_msgfree(entry);
            goto egress;
        }

        ldap_msgfree(entry);

        if (err != NULL) {
            if (item->error != NULL)
                free(item->error);
            item->error = strdup(err);
            if (item->error == NULL)
                goto egress;
        }

        otpd_queue_push_head(&ctx.query.responses, item);
        return;
    }

    item->msgid = -1;

    switch (item->sent) {
    case 1:
        otpd_log_req(item->req, "user query end: %s",
                item->error == NULL ? item->user.dn : item->error);
        if (item->user.dn == NULL || item->user.uid == NULL)
            goto egress;
        break;
    case 2:
        otpd_log_req(item->req, "radius query end: %s",
                item->error == NULL
                    ? item->radius.ipatokenRadiusServer
                    : item->error);
        if (item->radius.ipatokenRadiusServer == NULL ||
            item->radius.ipatokenRadiusSecret == NULL)
            goto egress;
        break;
    case 3:
        otpd_log_req(item->req, "username query end: %s",
                item->error == NULL ? item->user.other : item->error);
        break;
    default:
        goto egress;
    }

    if (item->error != NULL)
        goto egress;

    if (item->sent == 1 && item->user.ipatokenRadiusConfigLink != NULL) {
        push = &ctx.query.requests;
        event = ctx.query.io;
        goto egress;
    } else if (item->sent == 2 &&
               item->radius.ipatokenUserMapAttribute != NULL &&
               item->user.ipatokenRadiusUserName == NULL) {
        push = &ctx.query.requests;
        event = ctx.query.io;
        goto egress;
    }

    /* Forward to RADIUS if necessary. */
    i = otpd_forward(&item);
    if (i != 0)
        goto egress;

    push = &ctx.bind.requests;
    event = ctx.bind.io;

egress:
    ldap_msgfree(results);
    otpd_queue_push(push, item);

    if (item != NULL)
        verto_set_flags(event, VERTO_EV_FLAG_PERSIST |
                               VERTO_EV_FLAG_IO_ERROR |
                               VERTO_EV_FLAG_IO_READ |
                               VERTO_EV_FLAG_IO_WRITE);
}

/* Handle the reading/writing of LDAP query requests asynchronously. */
void otpd_on_query_io(verto_ctx *vctx, verto_ev *ev)
{
    verto_ev_flag flags;

    flags = verto_get_fd_state(ev);
    if (flags & VERTO_EV_FLAG_IO_WRITE)
        on_query_writable(vctx, ev);
    if (flags & (VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_IO_ERROR))
        on_query_readable(vctx, ev);
}
