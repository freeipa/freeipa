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

#pragma once

#include "krad.h"

#include <ldap.h>

#include <errno.h>

#define SECRET ""
#define otpd_log_req(req, ...) \
    otpd_log_req_(__FILE__, __LINE__, (req), __VA_ARGS__)
#define otpd_log_err(errnum, ...) \
    otpd_log_err_(__FILE__, __LINE__, (errnum), __VA_ARGS__)

struct otpd_queue_iter;

struct otpd_queue_item {
    struct otpd_queue_item *next;
    krad_packet *req;
    krad_packet *rsp;
    size_t sent;
    char *error;

    struct {
        char *dn;
        char *uid;
        char *ipatokenRadiusUserName;
        char *ipatokenRadiusConfigLink;
        char *other;
    } user;

    struct {
        char *ipatokenUserMapAttribute;
        char *ipatokenRadiusSecret;
        char *ipatokenRadiusServer;
        time_t ipatokenRadiusTimeout;
        size_t ipatokenRadiusRetries;
    } radius;
    int msgid;
};

struct otpd_queue {
    struct otpd_queue_item *head;
    struct otpd_queue_item *tail;
};

/* This structure contains our global state. The most important part is the
 * queues. When a request comes in (stdio.c), it is placed into an item object.
 * This item exists in only one queue at a time as it flows through this
 * daemon.
 *
 * The flow is: stdin => query => (forward (no queue) or bind) => stdout.
 */
struct otpd_context {
    verto_ctx *vctx;
    krb5_context kctx;
    krad_client *client;
    krad_attrset *attrs;
    int exitstatus;

    struct {
        verto_ev *reader;
        verto_ev *writer;
        struct otpd_queue responses;
    } stdio;

    struct {
        char *base;
        verto_ev *io;
        struct otpd_queue requests;
        struct otpd_queue responses;
    } query;

    struct {
        verto_ev *io;
        struct otpd_queue requests;
        struct otpd_queue responses;
    } bind;
};

extern struct otpd_context ctx;

void otpd_log_req_(const char * const file, int line, krad_packet *req,
                   const char * const tmpl, ...);

void otpd_log_err_(const char * const file, int line, krb5_error_code code,
                   const char * const tmpl, ...);

krb5_error_code otpd_queue_item_new(krad_packet *req,
                                    struct otpd_queue_item **item);

void otpd_queue_item_free(struct otpd_queue_item *item);

krb5_error_code otpd_queue_iter_new(const struct otpd_queue * const *queues,
                                    struct otpd_queue_iter **iter);

const krad_packet *otpd_queue_iter_func(void *data, krb5_boolean cancel);

void otpd_queue_push(struct otpd_queue *q, struct otpd_queue_item *item);

void otpd_queue_push_head(struct otpd_queue *q, struct otpd_queue_item *item);

struct otpd_queue_item *otpd_queue_peek(struct otpd_queue *q);

struct otpd_queue_item *otpd_queue_pop(struct otpd_queue *q);

struct otpd_queue_item *otpd_queue_pop_msgid(struct otpd_queue *q, int msgid);

void otpd_queue_free_items(struct otpd_queue *q);

void otpd_on_stdin_readable(verto_ctx *vctx, verto_ev *ev);

void otpd_on_stdout_writable(verto_ctx *vctx, verto_ev *ev);

void otpd_on_query_io(verto_ctx *vctx, verto_ev *ev);

void otpd_on_bind_io(verto_ctx *vctx, verto_ev *ev);

krb5_error_code otpd_forward(struct otpd_queue_item **i);

const char *otpd_parse_user(LDAP *ldp, LDAPMessage *entry,
                            struct otpd_queue_item *item);

const char *otpd_parse_radius(LDAP *ldp, LDAPMessage *entry,
                              struct otpd_queue_item *item);

const char *otpd_parse_radius_username(LDAP *ldp, LDAPMessage *entry,
                                       struct otpd_queue_item *item);
