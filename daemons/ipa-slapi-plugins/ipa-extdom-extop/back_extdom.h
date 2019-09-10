/*
 * Copyright 2017 Red Hat, Inc.
 *
 * This Program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this Program; if not, write to the
 *
 *   Free Software Foundation, Inc.
 *   59 Temple Place, Suite 330
 *   Boston, MA 02111-1307 USA
 *
 */

#ifndef BACK_EXTDOM_H
#define BACK_EXTDOM_H
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

/* Possible results of lookup using a nss_* function.
 * Note: don't include nss.h as its path gets overriden by NSS library */
enum nss_status {
    NSS_STATUS_TRYAGAIN = -2,
    NSS_STATUS_UNAVAIL,
    NSS_STATUS_NOTFOUND,
    NSS_STATUS_SUCCESS,
    NSS_STATUS_RETURN
};

/* default NSS operation timeout 10s (ipaExtdomMaxNssTimeout) */
#define DEFAULT_MAX_NSS_TIMEOUT (10*1000)

/* NSS backend operations implemented using either nss_sss.so.2 or libsss_nss_idmap API */
struct nss_ops_ctx;

int back_extdom_init_context(struct nss_ops_ctx **nss_context);
void back_extdom_free_context(struct nss_ops_ctx **nss_context);
void back_extdom_set_timeout(struct nss_ops_ctx *nss_context,
                             unsigned int timeout);
unsigned int back_extdom_get_timeout(struct nss_ops_ctx *nss_context);
void back_extdom_evict_user(struct nss_ops_ctx *nss_context,
                            const char *name);
void back_extdom_evict_group(struct nss_ops_ctx *nss_context,
                             const char *name);

enum nss_status back_extdom_getpwnam(struct nss_ops_ctx *nss_context,
                                     const char *name, struct passwd *pwd,
                                     char *buffer, size_t buflen,
                                     struct passwd **result,
                                     int *lerrno);

enum nss_status back_extdom_getpwuid(struct nss_ops_ctx *nss_context,
                                     uid_t uid, struct passwd *pwd,
                                     char *buffer, size_t buflen,
                                     struct passwd **result,
                                     int *lerrno);

enum nss_status back_extdom_getgrnam(struct nss_ops_ctx *nss_context,
                                     const char *name, struct group *grp,
                                     char *buffer, size_t buflen,
                                     struct group **result,
                                     int *lerrno);

enum nss_status back_extdom_getgrgid(struct nss_ops_ctx *nss_context,
                                     gid_t gid, struct group *grp,
                                     char *buffer, size_t buflen,
                                     struct group **result,
                                     int *lerrno);

enum nss_status back_extdom_getgrouplist(struct nss_ops_ctx *nss_context,
                                         const char *name, gid_t group,
                                         gid_t *groups, int *ngroups,
                                         int *lerrno);

#endif /* BACK_EXTDOM_H */
