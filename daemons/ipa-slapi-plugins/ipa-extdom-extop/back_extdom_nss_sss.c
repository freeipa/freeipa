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
 * Copyright (C) 2013-2017 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/param.h>
#include "back_extdom.h"

struct nss_ops_ctx {
    void *dl_handle;
    long int initgroups_start;

    enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrnam_r)(const char *name, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
                                  char *buffer, size_t buflen, int *errnop);
    enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
                                      long int *start, long int *size,
                                      gid_t **groups, long int limit,
                                      int *errnop);
};

void back_extdom_free_context(struct nss_ops_ctx **nss_context)
{
    if ((nss_context == NULL) || (*nss_context == NULL)) {
        return;
    }

    if ((*nss_context)->dl_handle != NULL) {
        dlclose((*nss_context)->dl_handle);
    }

    free((*nss_context));
    *nss_context = NULL;
}

int back_extdom_init_context(struct nss_ops_ctx **nss_context)
{
    struct nss_ops_ctx *ctx = NULL;

    if (nss_context == NULL) {
        return EINVAL;
    }

    ctx = calloc(1, sizeof(struct nss_ops_ctx));
    if (ctx == NULL) {
        return ENOMEM;
    }
    *nss_context = ctx;

    ctx->dl_handle = dlopen("libnss_sss.so.2", RTLD_NOW);
    if (ctx->dl_handle == NULL) {
        goto fail;
    }

    ctx->getpwnam_r = dlsym(ctx->dl_handle, "_nss_sss_getpwnam_r");
    if (ctx->getpwnam_r == NULL) {
        goto fail;
    }

    ctx->getpwuid_r = dlsym(ctx->dl_handle, "_nss_sss_getpwuid_r");
    if (ctx->getpwuid_r == NULL) {
        goto fail;
    }

    ctx->getgrnam_r = dlsym(ctx->dl_handle, "_nss_sss_getgrnam_r");
    if (ctx->getgrnam_r == NULL) {
        goto fail;
    }

    ctx->getgrgid_r = dlsym(ctx->dl_handle, "_nss_sss_getgrgid_r");
    if (ctx->getgrgid_r == NULL) {
        goto fail;
    }

    ctx->initgroups_dyn = dlsym(ctx->dl_handle, "_nss_sss_initgroups_dyn");
    if (ctx->initgroups_dyn == NULL) {
        goto fail;
    }

    return 0;

fail:
    back_extdom_free_context(nss_context);

    return EINVAL;
}


/* Following four functions cannot be implemented with nss_sss.so.2
 * As result, we simply do nothing here */

void back_extdom_set_timeout(struct nss_ops_ctx *nss_context,
                             unsigned int timeout) {
        /* no operation */
}

unsigned int back_extdom_get_timeout(struct nss_ops_ctx *nss_context) {
    return DEFAULT_MAX_NSS_TIMEOUT;
}

void back_extdom_evict_user(struct nss_ops_ctx *nss_context,
                            const char *name) {
        /* no operation */
}

void back_extdom_evict_group(struct nss_ops_ctx *nss_context,
                             const char *name) {
        /* no operation */
}

enum nss_status back_extdom_getpwnam(struct nss_ops_ctx *nss_context,
                                     const char *name, struct passwd *pwd,
                                     char *buffer, size_t buflen,
                                     struct passwd **result,
                                     int *lerrno) {
    enum nss_status ret;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = nss_context->getpwnam_r(name, pwd,
                                  buffer, buflen,
                                  lerrno);

    if ((ret == NSS_STATUS_SUCCESS) && (result != NULL)) {
        *result = pwd;
        *lerrno = 0;
    }

    return ret;
}

enum nss_status back_extdom_getpwuid(struct nss_ops_ctx *nss_context,
                                     uid_t uid, struct passwd *pwd,
                                     char *buffer, size_t buflen,
                                     struct passwd **result,
                                     int *lerrno) {
    enum nss_status ret;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = nss_context->getpwuid_r(uid, pwd,
                                  buffer, buflen,
                                  lerrno);

    if ((ret == NSS_STATUS_SUCCESS) && (result != NULL)) {
        *result = pwd;
        *lerrno = 0;
    }

    return ret;
}

enum nss_status back_extdom_getgrnam(struct nss_ops_ctx *nss_context,
                                     const char *name, struct group *grp,
                                     char *buffer, size_t buflen,
                                     struct group **result,
                                     int *lerrno) {
    enum nss_status ret;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = nss_context->getgrnam_r(name, grp,
                                  buffer, buflen,
                                  lerrno);

    if ((ret == NSS_STATUS_SUCCESS) && (result != NULL)) {
        *result = grp;
        *lerrno = 0;
    }

    return ret;
}

enum nss_status back_extdom_getgrgid(struct nss_ops_ctx *nss_context,
                                     gid_t gid, struct group *grp,
                                     char *buffer, size_t buflen,
                                     struct group **result,
                                     int *lerrno) {

    enum nss_status ret;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = nss_context->getgrgid_r(gid, grp,
                                  buffer, buflen,
                                  lerrno);

    if ((ret == NSS_STATUS_SUCCESS) && (result != NULL)) {
        *result = grp;
        *lerrno = 0;
    }

    return ret;
}

enum nss_status back_extdom_getgrouplist(struct nss_ops_ctx *nss_context,
                                         const char *name, gid_t group,
                                         gid_t *groups, int *ngroups,
                                         int *lerrno) {

    enum nss_status ret = NSS_STATUS_UNAVAIL;
    long int tsize = MAX (1, *ngroups);
    gid_t *newgroups = NULL;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    newgroups = (gid_t *) calloc (tsize, sizeof (gid_t));
    if (newgroups == NULL) {
        *lerrno = ENOMEM;
        return NSS_STATUS_TRYAGAIN;
    }

    newgroups[0] = group;
    nss_context->initgroups_start = 1;

    ret = nss_context->initgroups_dyn(name, group,
                                      &nss_context->initgroups_start,
                                      &tsize, &newgroups,
                                      -1, lerrno);

    (void) memcpy(groups, newgroups,
                  MIN(*ngroups, nss_context->initgroups_start) * sizeof(gid_t));
    free(newgroups);

    if (*ngroups < nss_context->initgroups_start) {
        ret = NSS_STATUS_TRYAGAIN;
        *lerrno = ERANGE;
    }

    *ngroups = (int) nss_context->initgroups_start;

    nss_context->initgroups_start = 0;

    return ret;
}
