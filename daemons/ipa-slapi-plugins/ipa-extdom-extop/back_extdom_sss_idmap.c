/*
 * Copyright 2013-2017 Red Hat, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include "back_extdom.h"

/* SSSD only exposes *_timeout() variants if the following symbol is defined */
#define IPA_389DS_PLUGIN_HELPER_CALLS
#include <sss_nss_idmap.h>

struct nss_ops_ctx {
    unsigned int timeout;
};

static enum nss_status __convert_sss_nss2nss_status(int errcode) {
    switch(errcode) {
    case 0:
        return NSS_STATUS_SUCCESS;
    case ENOENT:
        return NSS_STATUS_NOTFOUND;
    case ERANGE:
        return NSS_STATUS_TRYAGAIN;
    case ETIME:
        /* fall-through */
    case ETIMEDOUT:
        /* fall-through */
    default:
        return NSS_STATUS_UNAVAIL;
    }
    return NSS_STATUS_UNAVAIL;
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
    return 0;
}

void back_extdom_free_context(struct nss_ops_ctx **nss_context)
{
    if ((nss_context == NULL) || (*nss_context == NULL)) {
        return;
    }

    free((*nss_context));
    *nss_context = NULL;
}


void back_extdom_set_timeout(struct nss_ops_ctx *nss_context,
                             unsigned int timeout) {
    if (nss_context == NULL) {
        return;
    }

    nss_context->timeout = timeout;
}

void back_extdom_evict_user(struct nss_ops_ctx *nss_context,
                            const char *name) {
    if (nss_context == NULL) {
        return;
    }

    (void) sss_nss_getpwnam_timeout(name, NULL,
                                    NULL, 0,
                                    NULL,
                                    SSS_NSS_EX_FLAG_INVALIDATE_CACHE,
                                    nss_context->timeout);
}

void back_extdom_evict_group(struct nss_ops_ctx *nss_context,
                             const char *name) {
    if (nss_context == NULL) {
            return;
    }

    (void) sss_nss_getgrnam_timeout(name, NULL,
                                    NULL, 0,
                                    NULL,
                                    SSS_NSS_EX_FLAG_INVALIDATE_CACHE,
                                    nss_context->timeout);
}

enum nss_status back_extdom_getpwnam(struct nss_ops_ctx *nss_context,
                                     const char *name, struct passwd *pwd,
                                     char *buffer, size_t buflen,
                                     struct passwd **result,
                                     int *lerrno) {
    int ret = 0;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = sss_nss_getpwnam_timeout(name, pwd,
                                   buffer, buflen,
                                   result,
                                   SSS_NSS_EX_FLAG_NO_FLAGS,
                                   nss_context->timeout);

    /* SSSD uses the same infrastructure to handle sss_nss_get* calls
     * as nss_sss.so.2 module where 'int *errno' is passed to the helper
     * but writes down errno into return code so we propagate it in case
     * of error and translate the return code */
    if (lerrno != NULL) {
        *lerrno = ret;
    }
    return __convert_sss_nss2nss_status(ret);
}

enum nss_status back_extdom_getpwuid(struct nss_ops_ctx *nss_context,
                                     uid_t uid, struct passwd *pwd,
                                     char *buffer, size_t buflen,
                                     struct passwd **result,
                                     int *lerrno) {

    int ret = 0;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = sss_nss_getpwuid_timeout(uid, pwd,
                                   buffer, buflen,
                                   result,
                                   SSS_NSS_EX_FLAG_NO_FLAGS,
                                   nss_context->timeout);

    /* SSSD uses the same infrastructure to handle sss_nss_get* calls
     * as nss_sss.so.2 module where 'int *errno' is passed to the helper
     * but writes down errno into return code so we propagate it in case
     * of error and translate the return code */
    if (lerrno != NULL) {
        *lerrno = ret;
    }
    return __convert_sss_nss2nss_status(ret);
}

enum nss_status back_extdom_getgrnam(struct nss_ops_ctx *nss_context,
                                     const char *name, struct group *grp,
                                     char *buffer, size_t buflen,
                                     struct group **result,
                                     int *lerrno) {

    int ret = 0;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = sss_nss_getgrnam_timeout(name, grp,
                                   buffer, buflen,
                                   result,
                                   SSS_NSS_EX_FLAG_NO_FLAGS,
                                   nss_context->timeout);

    /* SSSD uses the same infrastructure to handle sss_nss_get* calls
     * as nss_sss.so.2 module where 'int *errno' is passed to the helper
     * but writes down errno into return code so we propagate it in case
     * of error and translate the return code */
    if (lerrno != NULL) {
        *lerrno = ret;
    }
    return __convert_sss_nss2nss_status(ret);
}

enum nss_status back_extdom_getgrgid(struct nss_ops_ctx *nss_context,
                                     gid_t gid, struct group *grp,
                                     char *buffer, size_t buflen,
                                     struct group **result,
                                     int *lerrno) {

    int ret = 0;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = sss_nss_getgrgid_timeout(gid, grp,
                                   buffer, buflen,
                                   result,
                                   SSS_NSS_EX_FLAG_NO_FLAGS,
                                   nss_context->timeout);

    /* SSSD uses the same infrastructure to handle sss_nss_get* calls
     * as nss_sss.so.2 module where 'int *errno' is passed to the helper
     * but writes down errno into return code so we propagate it in case
     * of error and translate the return code */
    if (lerrno != NULL) {
        *lerrno = ret;
    }
    return __convert_sss_nss2nss_status(ret);
}

enum nss_status back_extdom_getgrouplist(struct nss_ops_ctx *nss_context,
                                         const char *name, gid_t group,
                                         gid_t *groups, int *ngroups,
                                         int *lerrno) {
    int ret = 0;

    if (nss_context == NULL) {
        return NSS_STATUS_UNAVAIL;
    }

    ret = sss_nss_getgrouplist_timeout(name, group,
                                       groups, ngroups,
                                       SSS_NSS_EX_FLAG_NO_FLAGS,
                                       nss_context->timeout);

    /* SSSD uses the same infrastructure to handle sss_nss_get* calls
     * as nss_sss.so.2 module where 'int *errno' is passed to the helper
     * but writes down errno into return code so we propagate it in case
     * of error and translate the return code */
    if (lerrno != NULL) {
        *lerrno = ret;
    }
    return __convert_sss_nss2nss_status(ret);
}

