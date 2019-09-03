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

#pragma once

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
#include <pwd.h>
#include <grp.h>

#include <dirsrv/slapi-plugin.h>
#include <lber.h>
#include <time.h>

#include <sss_nss_idmap.h>

#define EXOP_EXTDOM_OID "2.16.840.1.113730.3.8.10.4"
#define EXOP_EXTDOM_V1_OID "2.16.840.1.113730.3.8.10.4.1"
#define EXOP_EXTDOM_V2_OID "2.16.840.1.113730.3.8.10.4.2"

#define IPA_EXTDOM_PLUGIN_NAME   "ipa-extdom-extop"
#define IPA_EXTDOM_FEATURE_DESC  "IPA trusted domain ID mapper"
#define IPA_EXTDOM_PLUGIN_DESC   "Support resolving IDs in trusted domains to names and back"

#define IPA_PLUGIN_NAME IPA_EXTDOM_PLUGIN_NAME

enum extdom_version {
    EXTDOM_V0 = 0,
    EXTDOM_V1,
    EXTDOM_V2
};

enum input_types {
    INP_SID = 1,
    INP_NAME,
    INP_POSIX_UID,
    INP_POSIX_GID,
    INP_CERT,
    INP_USERNAME,
    INP_GROUPNAME
};

enum request_types {
    REQ_SIMPLE = 1,
    REQ_FULL,
    REQ_FULL_WITH_GROUPS
};

enum response_types {
    RESP_SID = 1,
    RESP_NAME,
    RESP_USER,
    RESP_GROUP,
    RESP_USER_GROUPLIST,
    RESP_GROUP_MEMBERS,
    RESP_NAME_LIST
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
        char *cert;
    } data;
    char *err_msg;
};

struct extdom_res {
    enum response_types response_type;
    union {
        char *sid;
        struct {
            char *domain_name;
            char *object_name;
        } name;
        struct {
            char *domain_name;
            char *user_name;
            uid_t uid;
            gid_t gid;
            char *gecos;
            char *home;
            char *shell;
            size_t ngroups;
            char **groups;
        } user;
        struct {
            char *domain_name;
            char *group_name;
            gid_t gid;
            size_t nmembers;
            char **members;
        } group;
    } data;
};

struct nss_ops_ctx;

struct ipa_extdom_ctx {
    Slapi_ComponentId *plugin_id;
    char *base_dn;
    size_t max_nss_buf_size;
    struct nss_ops_ctx *nss_ctx;
    Slapi_Counter *extdom_instance_counter;
    size_t extdom_max_instances;
};

struct domain_info {
    char *flat_name;
    char *sid;
    char *guid;
};

struct pwd_grp {
    enum sss_id_type id_type;
    union {
        struct passwd pwd;
        struct group grp;
    } data;
    int ngroups;
    gid_t *groups;
};

int parse_request_data(struct berval *req_val, struct extdom_req **_req);
void free_req_data(struct extdom_req *req);
int check_request(struct extdom_req *req, enum extdom_version version);
int handle_request(struct ipa_extdom_ctx *ctx, struct extdom_req *req,
                   struct berval **berval);
int pack_response(struct extdom_res *res, struct berval **ret_val);
int get_buffer(size_t *_buf_len, char **_buf);
int getpwnam_r_wrapper(struct ipa_extdom_ctx *ctx, const char *name,
                       struct passwd *pwd, char **_buf, size_t *_buf_len);
int getpwuid_r_wrapper(struct ipa_extdom_ctx *ctx, uid_t uid,
                       struct passwd *pwd, char **_buf, size_t *_buf_len);
int getgrnam_r_wrapper(struct ipa_extdom_ctx *ctx, const char *name,
                       struct group *grp, char **_buf, size_t *_buf_len);
int getgrgid_r_wrapper(struct ipa_extdom_ctx *ctx, gid_t gid,
                       struct group *grp, char **_buf, size_t *_buf_len);
int get_user_grouplist(struct ipa_extdom_ctx *ctx, const char *name, gid_t gid,
                       size_t *_ngroups, gid_t **_groups);
int pack_ber_sid(const char *sid, struct berval **berval);
int pack_ber_name(const char *domain_name, const char *name,
                  struct berval **berval);
int pack_ber_user(struct ipa_extdom_ctx *ctx,
                  enum response_types response_type,
                  const char *domain_name, const char *user_name,
                  uid_t uid, gid_t gid,
                  const char *gecos, const char *homedir,
                  const char *shell, struct sss_nss_kv *kv_list,
                  struct berval **berval);
int pack_ber_group(enum response_types response_type,
                   const char *domain_name, const char *group_name,
                   gid_t gid, char **members, struct sss_nss_kv *kv_list,
                   struct berval **berval);
void set_err_msg(struct extdom_req *req, const char *format, ...);
