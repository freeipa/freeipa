/** BEGIN COPYRIGHT BLOCK
 * This program is free software; you can redistribute it and/or modify
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
 *
 * Additional permission under GPLv3 section 7:
 *
 * In the following paragraph, "GPL" means the GNU General Public
 * License, version 3 or any later version, and "Non-GPL Code" means
 * code that is governed neither by the GPL nor a license
 * compatible with the GPL.
 *
 * You may link the code of this Program with Non-GPL Code and convey
 * linked combinations including the two, provided that such Non-GPL
 * Code only links to the code of this Program through those well
 * defined interfaces identified in the file named EXCEPTION found in
 * the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline
 * functions from the Approved Interfaces without causing the resulting
 * work to be covered by the GPL. Only the copyright holders of this
 * Program may make changes or additions to the list of Approved
 * Interfaces.
 *
 * Authors:
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "ipa_cldap.h"
#include <poll.h>
#include <lber.h>

/* pre allocate some space for answers, default to increment 3 at a time */
static int ipa_cldap_more_kvps(struct kvp_list *kvps)
{
    struct kvp *pairs;

    if (kvps->allocated - kvps->top > 0) {
        return 0;
    }

    pairs = realloc(kvps->pairs, (kvps->allocated + 3) * sizeof(struct kvp));
    if (!pairs) {
        return ENOMEM;
    }
    kvps->pairs = pairs;
    kvps->allocated += 3;

    return 0;
}

static void ipa_cldap_free_kvps(struct kvp_list *kvps)
{
    free(kvps->pairs);
    kvps->pairs = NULL;
    kvps->allocated = 0;
    kvps->top = 0;
}

static int ipa_cldap_get_kvp(BerElement *be, struct kvp_list *kvps)
{
    ber_tag_t tag;
    int ret;

    ret = ipa_cldap_more_kvps(kvps);
    if (ret) {
        return ret;
    }

    tag = ber_scanf(be, "{mm}",
                    &(kvps->pairs[kvps->top].attr),
                    &(kvps->pairs[kvps->top].value));
    if (tag == LBER_ERROR) {
        LOG_TRACE("Invalid filter\n");
        ret = EINVAL;
    } else {
        kvps->top++;
    }

    return ret;
}

static int ipa_cldap_get_tree(BerElement *be, struct kvp_list *kvps)
{
    ber_tag_t tag;
    ber_tag_t len;
    char *cookie;
    int ret;

    tag = ber_peek_tag(be, &len);
    if (tag == LDAP_FILTER_EQUALITY) {
        /* Special case of a single clause filter, eg. (NtVer=\06\00\00\00) */
        ret = ipa_cldap_get_kvp(be, kvps);
        if (ret == 0) {
            return 0;
        }
    }

    tag = ber_first_element(be, &len, &cookie);
    while (tag != LBER_DEFAULT) {
        tag = ber_peek_tag(be, &len);
        switch (tag) {
        case LDAP_FILTER_EQUALITY:
            ret = ipa_cldap_get_kvp(be, kvps);
            break;
        case LDAP_FILTER_AND:
            ret = ipa_cldap_get_tree(be, kvps);
            break;
        default:
            LOG_TRACE("Unsupported filter\n");
            ret = EINVAL;
            break;
        }

        if (ret) {
            return ret;
        }

        tag = ber_next_element(be, &len, cookie);
    }

    return 0;
}

static int ipa_cldap_decode(struct ipa_cldap_req *req)
{
    struct berval bv;
    BerElement *be;
    ber_tag_t tag;
    ber_len_t len;
    ber_int_t scope;
    ber_int_t deref;
    ber_int_t sizelimit;
    ber_int_t timelimit;
    ber_int_t typesonly;
    struct berval base;
    struct berval attr;
    int ret = EINVAL;

    bv.bv_val = req->dgram;
    bv.bv_len = req->dgsize;

    be = ber_alloc_t(0);
    if (!be) {
        LOG_FATAL("Out of memory!\n");
        goto done;
    }

    ber_init2(be, &bv, 0);

    tag = ber_skip_tag(be, &len);
    if (tag != LDAP_TAG_MESSAGE) {
        LOG_TRACE("Invalid message (%d)\n", (int)tag);
        goto done;
    }

    tag = ber_get_int(be, &req->id);
    if (tag != LDAP_TAG_MSGID) {
        LOG_TRACE("Failed to get id\n");
        goto done;
    }

    tag = ber_peek_tag(be, &len);
    if (tag != LDAP_REQ_SEARCH) {
        LOG_TRACE("Unexpected message type (%d)\n", (int)tag);
        goto done;
    }

    tag = ber_scanf(be, "{meeiib",
                    &base, &scope, &deref, &sizelimit, &timelimit, &typesonly);
    if (tag == LBER_ERROR) {
        LOG_TRACE("Failed to parse message\n");
        goto done;
    }

    if ((base.bv_len != 0) ||
        (scope != 0) ||
        (typesonly != 0)){
        LOG_TRACE("Unexpected request\n");
        goto done;
    }

    ret = ipa_cldap_get_tree(be, &req->kvps);
    if (ret) {
        LOG_TRACE("Failed to parse filter\n");
        goto done;
    }

    tag = ber_scanf(be, "{m}}", &attr);
    if (tag == LBER_ERROR) {
        LOG_TRACE("Failed to parse message\n");
        goto done;
    }

    if (strncasecmp(attr.bv_val, "netlogon", attr.bv_len) != 0) {
        LOG_TRACE("Unexpected request\n");
        goto done;
    }

done:
    ber_free(be, 0);
    return ret;
}

static void ipa_cldap_respond(struct ipa_cldap_ctx *ctx,
                              struct ipa_cldap_req *req,
                              struct berval *nbtblob)
{
    struct berval *bv = NULL;
    BerElement *be;
    int ret;

    be = ber_alloc_t(0);
    if (!be) {
        LOG_OOM();
        return;
    }

    if (nbtblob->bv_len != 0) {
        /* result */
        ret = ber_printf(be, "{it{s{{s[O]}}}}", req->id,
                         LDAP_RES_SEARCH_ENTRY, "", "netlogon", nbtblob);
        if (ret == LBER_ERROR) {
            LOG("Failed to encode CLDAP reply\n");
            goto done;
        }
    }
    /* done */
    /* As per MS-ADTS 6.3.3.3 always return SUCCESS even for invalid filters */
    ret = ber_printf(be, "{it{ess}}", req->id,
                         LDAP_RES_SEARCH_RESULT, 0, "", "");
    if (ret == LBER_ERROR) {
        LOG("Failed to encode CLDAP reply\n");
        goto done;
    }
    /* get data blob */
    ret = ber_flatten(be, &bv);
    if (ret == LBER_ERROR) {
        LOG("Failed to encode CLDAP reply\n");
        goto done;
    }

    ret = sendto(ctx->sd, bv->bv_val, bv->bv_len, 0,
                 (struct sockaddr *)&req->ss, req->ss_len);
    if (ret == -1) {
        LOG("Failed to send CLDAP reply (%d, %s)\n", errno, strerror(errno));
    }

done:
    ber_bvfree(bv);
    ber_free(be, 1);
}

static void ipa_cldap_process(struct ipa_cldap_ctx *ctx,
                              struct ipa_cldap_req *req)
{
    struct berval reply;
    int ret;

    ret = ipa_cldap_decode(req);
    if (ret) {
        goto done;
    }

    LOG_TRACE("CLDAP Request received");

    ret = ipa_cldap_netlogon(ctx, req, &reply);

done:
    if (ret != 0) {
        /* bad request, or internal error, return empty reply */
        /* as Windows does per MS-ADTS 6.3.3.3 */
        memset(&reply, 0, sizeof(struct berval));
    }

    ipa_cldap_respond(ctx, req, &reply);

    ipa_cldap_free_kvps(&req->kvps);
    free(req);
    return;
}

static struct ipa_cldap_req *ipa_cldap_recv_dgram(struct ipa_cldap_ctx *ctx)
{
    struct ipa_cldap_req *req;

    req = calloc(1, sizeof(struct ipa_cldap_req));
    if (!req) {
        LOG("Failed to allocate memory for req");
        return NULL;
    }

    req->fd = ctx->sd;
    req->ss_len = sizeof(struct sockaddr_storage);

    req->dgsize = recvfrom(req->fd, req->dgram, MAX_DG_SIZE, 0,
                           (struct sockaddr *)&req->ss, &req->ss_len);
    if (req->dgsize == -1) {
        LOG_TRACE("Failed to get datagram\n");
        free(req);
        return NULL;
    }

    return req;
}

void *ipa_cldap_worker(void *arg)
{
    struct ipa_cldap_req *req;
    struct pollfd fds[2];
    bool stop = false;
    struct ipa_cldap_ctx *ctx = (struct ipa_cldap_ctx *) arg;
    int ret;

    while (!stop) {

        fds[0].fd = ctx->stopfd[0];
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = ctx->sd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        /* wait until a request comes in */
        ret = poll(fds, 2, -1);
        if (ret == -1) {
            if (errno != EINTR) {
                LOG_FATAL("poll() failed with [%d, %s]. Can't continue.\n",
                          errno, strerror(errno));
                stop = true;
            }
        }
        if (ret <= 0) {
            continue;
        }

        /* got a stop signal, exit the loop */
        if (fds[0].revents & POLLIN) {
            stop = true;
            continue;
        }

        /* got a CLDAP packet, handle it */
        if (fds[1].revents & POLLIN) {
            req = ipa_cldap_recv_dgram(ctx);
            if (req) {
                ipa_cldap_process(ctx, req);
            }
        }
    }
    return NULL;
}
