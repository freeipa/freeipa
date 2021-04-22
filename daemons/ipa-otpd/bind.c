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
 * This file takes requests from query.c and performs an LDAP bind on behalf
 * of the user. The results are placed in the stdout queue (stdio.c).
 */

#include "internal.h"
#include "../ipa-slapi-plugins/ipa-pwd-extop/otpctrl.h"

static void on_bind_writable(verto_ctx *vctx, verto_ev *ev)
{
    LDAPControl control = { OTP_REQUIRED_OID, {}, true };
    LDAPControl *ctrls[] = { &control, NULL };
    struct otpd_queue *push = &ctx.stdio.responses;
    const krb5_data *data;
    struct berval cred;
    struct otpd_queue_item *item;
    int i;
    (void)vctx;

    item = otpd_queue_pop(&ctx.bind.requests);
    if (item == NULL) {
        verto_set_flags(ctx.bind.io, VERTO_EV_FLAG_PERSIST |
                                     VERTO_EV_FLAG_IO_ERROR |
                                     VERTO_EV_FLAG_IO_READ);
        return;
    }

    if (item->user.dn == NULL)
        goto error;

    data = krad_packet_get_attr(item->req,
                                krad_attr_name2num("User-Password"), 0);
    if (data == NULL)
        goto error;

    cred.bv_val = data->data;
    cred.bv_len = data->length;
    i = ldap_sasl_bind(verto_get_private(ev), item->user.dn, LDAP_SASL_SIMPLE,
                       &cred, ctrls, NULL, &item->msgid);
    if (i != LDAP_SUCCESS) {
        otpd_log_err(errno, "Unable to initiate bind: %s", ldap_err2string(i));
        verto_break(ctx.vctx);
        ctx.exitstatus = 1;
    }

    otpd_log_req(item->req, "bind start: %s", item->user.dn);
    push = &ctx.bind.responses;

error:
    otpd_queue_push(push, item);
}

static void on_bind_readable(verto_ctx *vctx, verto_ev *ev)
{
    const char *errstr = "error";
    LDAPMessage *results;
    struct otpd_queue_item *item = NULL;
    int i, rslt;
    (void)vctx;

    rslt = ldap_result(verto_get_private(ev), LDAP_RES_ANY, 0, NULL, &results);
    if (rslt != LDAP_RES_BIND) {
        if (rslt <= 0)
            results = NULL;
        ldap_msgfree(results);
        otpd_log_err(EIO, "IO error received on bind socket: %s", ldap_err2string(rslt));
        verto_break(ctx.vctx);
        /* if result is -1 or 0, connection was closed by the server side
	 * or the server is down and we should exit gracefully */
        ctx.exitstatus = (rslt <= 0) ? 0 : 1;
        return;
    }

    item = otpd_queue_pop_msgid(&ctx.bind.responses, ldap_msgid(results));
    if (item == NULL) {
        ldap_msgfree(results);
        return;
    }
    item->msgid = -1;

    rslt = ldap_parse_result(verto_get_private(ev), results, &i,
                             NULL, NULL, NULL, NULL, 0);
    if (rslt != LDAP_SUCCESS) {
        errstr = ldap_err2string(rslt);
        goto error;
    }

    rslt = i;
    if (rslt != LDAP_SUCCESS) {
        errstr = ldap_err2string(rslt);
        goto error;
    }

    item->sent = 0;
    i = krad_packet_new_response(ctx.kctx, SECRET,
                                 krad_code_name2num("Access-Accept"),
                                 NULL, item->req, &item->rsp);
    if (i != 0) {
        errstr = krb5_get_error_message(ctx.kctx, i);
        goto error;
    }

error:
    if (item != NULL)
        otpd_log_req(item->req, "bind end: %s",
                item->rsp != NULL ? "success" : errstr);

    ldap_msgfree(results);
    otpd_queue_push(&ctx.stdio.responses, item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);
}

void otpd_on_bind_io(verto_ctx *vctx, verto_ev *ev)
{
    verto_ev_flag flags;

    flags = verto_get_fd_state(ev);
    if (flags & VERTO_EV_FLAG_IO_WRITE)
        on_bind_writable(vctx, ev);
    if (flags & (VERTO_EV_FLAG_IO_READ | VERTO_EV_FLAG_IO_ERROR))
        on_bind_readable(vctx, ev);
}
