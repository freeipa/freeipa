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

#ifndef _IPA_CLDAP_H_
#define _IPA_CLDAP_H_

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
#include <dirsrv/slapi-plugin.h>
#include "util.h"

#define IPA_CLDAP_PLUGIN_NAME "CLDAP Server"
#define IPA_CLDAP_PLUGIN_DESC "MS/AD introperable CLDAP server"

#define IPA_PLUGIN_NAME IPA_CLDAP_PLUGIN_NAME
#define CLDAP_PORT 389
#define MAX_DG_SIZE 4096

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

struct ipa_cldap_ctx {
    Slapi_ComponentId *plugin_id;
    pthread_t tid;
    char *base_dn;
    int stopfd[2];
    int sd;
};

struct kvp {
    struct berval attr;
    struct berval value;
};

struct kvp_list {
    struct kvp *pairs;
    int allocated;
    int top;
};

struct ipa_cldap_req {
    int fd;

    struct sockaddr_storage ss;
    socklen_t ss_len;

    char dgram[MAX_DG_SIZE];
    size_t dgsize;

    ber_int_t id;

    /* filter members */
    struct kvp_list kvps;
};

void *ipa_cldap_worker(struct ipa_cldap_ctx *ctx);

int ipa_cldap_netlogon(struct ipa_cldap_ctx *ctx,
                       struct ipa_cldap_req *req,
                       struct berval *reply);

#endif /* _IPA_CLDAP_H_ */
