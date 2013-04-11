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
 * This file reads and writes RADIUS packets on STDIN/STDOUT.
 *
 * Incoming requests are placed into a "query" queue to look up the user's
 * configuration from LDAP (query.c).
 */

#include "internal.h"

static const struct otpd_queue *const queues[] = {
    &ctx.stdio.responses,
    &ctx.query.requests,
    &ctx.query.responses,
    &ctx.bind.requests,
    &ctx.bind.responses,
    NULL
};

/* Read a RADIUS request from stdin. */
void otpd_on_stdin_readable(verto_ctx *vctx, verto_ev *ev)
{
    static char _buffer[KRAD_PACKET_SIZE_MAX];
    static krb5_data buffer = { .data = _buffer, .length = 0 };
    (void)vctx;

    const krad_packet *dup;
    const krb5_data *data;
    struct otpd_queue_iter *iter;
    struct otpd_queue_item *item;
    krad_packet *req;
    ssize_t pktlen;
    int i;

    pktlen = krad_packet_bytes_needed(&buffer);
    if (pktlen < 0) {
        otpd_log_err(EBADMSG, "Received a malformed packet");
        goto shutdown;
    }

    /* Read the item. */
    i = read(verto_get_fd(ev), buffer.data + buffer.length, pktlen);
    if (i < 1) {
        /* On EOF, shutdown gracefully. */
        if (i == 0) {
            fprintf(stderr, "Socket closed, shutting down...\n");
            verto_break(ctx.vctx);
            return;
        }

        if (errno != EAGAIN && errno != EINTR) {
            otpd_log_err(errno, "Error receiving packet");
            goto shutdown;
        }

        return;
    }

    /* If we have a partial read or just the header, try again. */
    buffer.length += i;
    pktlen = krad_packet_bytes_needed(&buffer);
    if (pktlen > 0)
        return;

    /* Create the iterator. */
    i = otpd_queue_iter_new(queues, &iter);
    if (i != 0) {
        otpd_log_err(i, "Unable to create iterator");
        goto shutdown;
    }

    /* Decode the item. */
    i = krad_packet_decode_request(ctx.kctx, SECRET, &buffer,
                                   otpd_queue_iter_func, iter, &dup, &req);
    buffer.length = 0;
    if (i == EAGAIN)
        return;
    else if (i != 0) {
        otpd_log_err(i, "Unable to decode item");
        goto shutdown;
    }

    /* Drop duplicate requests. */
    if (dup != NULL) {
        krad_packet_free(req);
        return;
    }

    /* Ensure the packet has the User-Name attribute. */
    data = krad_packet_get_attr(req, krad_attr_name2num("User-Name"), 0);
    if (data == NULL) {
        krad_packet_free(req);
        return;
    }

    /* Create the new queue item. */
    i = otpd_queue_item_new(req, &item);
    if (i != 0) {
        krad_packet_free(req);
        return;
    }

    /* Push it to the query queue. */
    otpd_queue_push(&ctx.query.requests, item);
    verto_set_flags(ctx.query.io, VERTO_EV_FLAG_PERSIST |
                                  VERTO_EV_FLAG_IO_ERROR |
                                  VERTO_EV_FLAG_IO_READ |
                                  VERTO_EV_FLAG_IO_WRITE);

    otpd_log_req(req, "request received");
    return;

shutdown:
    verto_break(ctx.vctx);
    ctx.exitstatus = 1;
}

/* Send a RADIUS response to stdout. */
void otpd_on_stdout_writable(verto_ctx *vctx, verto_ev *ev)
{
    const krb5_data *data;
    struct otpd_queue_item *item;
    int i;
    (void)vctx;

    item = otpd_queue_peek(&ctx.stdio.responses);
    if (item == NULL) {
        verto_set_flags(ctx.stdio.writer, VERTO_EV_FLAG_PERSIST |
                                          VERTO_EV_FLAG_IO_ERROR |
                                          VERTO_EV_FLAG_IO_READ);
        return;
    }

    /* If no response has been generated thus far, send Access-Reject. */
    if (item->rsp == NULL) {
        item->sent = 0;
        i = krad_packet_new_response(ctx.kctx, SECRET,
                                     krad_code_name2num("Access-Reject"),
                                     NULL, item->req, &item->rsp);
        if (i != 0) {
            otpd_log_err(errno, "Unable to craft response");
            goto shutdown;
        }
    }

    /* Send the packet. */
    data = krad_packet_encode(item->rsp);
    i = write(verto_get_fd(ev), data->data + item->sent,
              data->length - item->sent);
    if (i < 0) {
        switch (errno) {
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EAGAIN - EWOULDBLOCK != 0)
        case EWOULDBLOCK:
#endif
#if defined(EAGAIN)
        case EAGAIN:
#endif
        case ENOBUFS:
        case EINTR:
            /* In this case, we just need to try again. */
            return;
        default:
            /* Unrecoverable. */
            break;
        }

        otpd_log_err(errno, "Error writing to stdout!");
        goto shutdown;
    }

    /* If the packet was completely sent, free the response. */
    item->sent += i;
    if (item->sent == data->length) {
        otpd_log_req(item->req, "response sent: %s",
                krad_code_num2name(krad_packet_get_code(item->rsp)));
        otpd_queue_item_free(otpd_queue_pop(&ctx.stdio.responses));
    }

    return;

shutdown:
    verto_break(ctx.vctx);
    ctx.exitstatus = 1;
}
