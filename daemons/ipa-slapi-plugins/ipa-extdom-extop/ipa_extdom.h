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
 * Sumit Bose <sbose@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifndef _IPA_EXTDOM_H_
#define _IPA_EXTDOM_H_

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include <samba-4.0/wbclient.h>

#include <dirsrv/slapi-plugin.h>
#include <lber.h>
#include <time.h>

#include <sss_idmap.h>

#define EXOP_EXTDOM_OID "2.16.840.1.113730.3.8.10.4"

#define IPA_EXTDOM_PLUGIN_NAME   "ipa-extdom-extop"
#define IPA_EXTDOM_FEATURE_DESC  "IPA trusted domain ID mapper"
#define IPA_EXTDOM_PLUGIN_DESC   "Support resolving IDs in trusted domains to names and back"

#define IPA_PLUGIN_NAME IPA_EXTDOM_PLUGIN_NAME

enum input_types {
    INP_SID = 1,
    INP_NAME,
    INP_POSIX_UID,
    INP_POSIX_GID
};

enum request_types {
    REQ_SIMPLE = 1,
    REQ_FULL
};

enum response_types {
    RESP_SID = 1,
    RESP_NAME,
    RESP_USER,
    RESP_GROUP
};

struct extdom_req {
    enum input_types input_type;
    enum request_types request_type;
    union {
        char *sid;
        struct {
            char *domain_name;
            char *object_name;
        } name;
        struct {
            char *domain_name;
            uid_t uid;
        } posix_uid;
        struct {
            char *domain_name;
            gid_t gid;
        } posix_gid;
    } data;
};

struct extdom_res {
    enum response_types response_type;
    union {
        char *sid;
        struct {
            const char *domain_name;
            const char *object_name;
        } name;
        struct {
            const char *domain_name;
            const char *user_name;
            uid_t uid;
            gid_t gid;
        } user;
        struct {
            const char *domain_name;
            const char *group_name;
            gid_t gid;
        } group;
    } data;
};

struct ipa_extdom_ctx {
    Slapi_ComponentId *plugin_id;
    char *base_dn;
};

struct domain_info {
    char *flat_name;
    char *sid;
    char *guid;
    struct sss_idmap_ctx *idmap_ctx;
};

int parse_request_data(struct berval *req_val, struct extdom_req **_req);
int handle_request(struct ipa_extdom_ctx *ctx, struct extdom_req *req,
                   struct extdom_res **res);
int create_response(struct extdom_req *req, struct domain_info *domain_info,
                    const char *domain_name,
                    const char *name, struct wbcDomainSid *sid,
                    enum wbcSidType name_type, struct extdom_res **_res);
int pack_response(struct extdom_res *res, struct berval **ret_val);
#endif /* _IPA_EXTDOM_H_ */
