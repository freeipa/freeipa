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

static void ipa_cldap_process(struct ipa_cldap_ctx *ctx,
                              struct ipa_cldap_req *req)
{
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

void *ipa_cldap_worker(struct ipa_cldap_ctx *ctx)
{
    struct ipa_cldap_req *req;
    struct pollfd fds[2];
    bool stop = false;
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
