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
 * This file proxies the incoming RADIUS request (stdio.c/query.c) to a
 * third-party RADIUS server if the user is configured for forwarding. The
 * result is placed in the stdout queue (stdio.c).
 */

#include "internal.h"

static void forward_cb(krb5_error_code retval, const krad_packet *request,
                       const krad_packet *response, void *data)
{
    krad_code code, acpt;
    struct otpd_queue_item *item = data;
    (void)request;

    acpt = krad_code_name2num("Access-Accept");
    code = krad_packet_get_code(response);
    if (retval == 0 && code == acpt) {
        item->sent = 0;
        retval = krad_packet_new_response(ctx.kctx, SECRET, acpt,
                                          NULL, item->req, &item->rsp);
    }

    otpd_log_req(item->req, "forward end: %s",
            retval == 0
                ? krad_code_num2name(code)
                : krb5_get_error_message(ctx.kctx, retval));

    otpd_queue_push(&ctx.stdio.responses, item);
    verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                      VERTO_EV_FLAG_IO_ERROR |
                                      VERTO_EV_FLAG_IO_READ |
                                      VERTO_EV_FLAG_IO_WRITE);
}

krb5_error_code otpd_forward(struct otpd_queue_item **item)
{
    krad_attr usernameid, passwordid;
    const krb5_data *password;
    krb5_error_code retval;
    char *username;
    krb5_data data;

    /* Find the username. */
    username = (*item)->user.ipatokenRadiusUserName;
    if (username == NULL) {
        username = (*item)->user.other;
        if (username == NULL)
            username = (*item)->user.uid;
    }

    /* Check to see if we are supposed to forward. */
    if ((*item)->radius.ipatokenRadiusServer == NULL ||
        (*item)->radius.ipatokenRadiusSecret == NULL ||
        username == NULL)
        return 0;

    otpd_log_req((*item)->req, "forward start: %s / %s", username,
            (*item)->radius.ipatokenRadiusServer);

    usernameid = krad_attr_name2num("User-Name");
    passwordid = krad_attr_name2num("User-Password");

    /* Set User-Name. */
    data.data = username;
    data.length = strlen(data.data);
    retval = krad_attrset_add(ctx.attrs, usernameid, &data);
    if (retval != 0)
        goto error;

    /* Set User-Password. */
    password = krad_packet_get_attr((*item)->req, passwordid, 0);
    if (password == NULL) {
        krad_attrset_del(ctx.attrs, usernameid, 0);
        goto error;
    }
    retval = krad_attrset_add(ctx.attrs, passwordid, password);
    if (retval != 0) {
        krad_attrset_del(ctx.attrs, usernameid, 0);
        goto error;
    }

    /* Forward the request to the RADIUS server. */
    retval = krad_client_send(ctx.client,
                              krad_code_name2num("Access-Request"),
                              ctx.attrs,
                              (*item)->radius.ipatokenRadiusServer,
                              (*item)->radius.ipatokenRadiusSecret,
                              (*item)->radius.ipatokenRadiusTimeout,
                              (*item)->radius.ipatokenRadiusRetries,
                              forward_cb, *item);
    krad_attrset_del(ctx.attrs, usernameid, 0);
    krad_attrset_del(ctx.attrs, passwordid, 0);
    if (retval == 0)
        *item = NULL;

error:
    if (retval != 0)
        otpd_log_req((*item)->req, "forward end: %s",
                krb5_get_error_message(ctx.kctx, retval));
    return retval;
}
