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
 * Copyright (C) 2012 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>

#include <pthread.h>
#include <dirsrv/slapi-plugin.h>

#include "util.h"
#include "ipa_sidgen.h"

#define NSEC_PER_SEC     1000000000UL


#define AT_CN "cn"

Slapi_ComponentId *global_sidgen_plugin_id = NULL;

struct worker_ctx {
    long delay;
    char *base_dn;
    Slapi_ComponentId *plugin_id;
    pthread_t tid;
    char *dom_sid;
    struct range_info **ranges;
};

static const char *ipa_sidgen_fetch_attr(Slapi_Entry *e, const char *attrname,
                                              const char *default_val)
{
    Slapi_Attr *attr;
    Slapi_Value *val = NULL;

    if (slapi_entry_attr_find(e, attrname, &attr) != 0)
        return default_val;

    if (slapi_attr_first_value(attr, &val) == -1)
        return default_val;

    return slapi_value_get_string(val);
}

static void free_pblock(void *arg)
{
    Slapi_PBlock *pb = (Slapi_PBlock *) arg;

    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
}

static int do_work(struct worker_ctx *worker_ctx)
{
    Slapi_PBlock *pb;
    int ret;
    size_t c;
    char *filter = NULL;
    char *attrs[] = { OBJECTCLASS, UID_NUMBER, GID_NUMBER, NULL };
    Slapi_Entry **e = NULL;
    struct timespec ts;

    pb = slapi_pblock_new();
    if (pb == NULL) {
        return ENOMEM;
    }

    pthread_cleanup_push(free_pblock, (void *) pb);

    filter = slapi_ch_smprintf("(&(%s=%s)(!(%s=%s))(|(%s=%s)(%s=%s)(%s=%s))(!(%s=*)))",
                               OBJECTCLASS, IPA_OBJECT,
                               OBJECTCLASS, MEP_MANAGED_ENTRY,
                               OBJECTCLASS, POSIX_ACCOUNT,
                               OBJECTCLASS, POSIX_GROUP,
                               OBJECTCLASS, IPA_ID_OBJECT,
                               IPA_SID);
    if (filter == NULL) {
        LOG_FATAL("Cannot generate search filter for objects without a SID.\n");
        ret = ENOMEM;
        goto done;
    }
    LOG("Base DN: [%s], Filter: [%s].\n", worker_ctx->base_dn, filter);

    slapi_search_internal_set_pb(pb, worker_ctx->base_dn, LDAP_SCOPE_SUBTREE,
                                 filter, attrs, 0, NULL, NULL,
                                 worker_ctx->plugin_id, 0);
    ret = slapi_search_internal_pb(pb);
    if (ret != 0) {
        slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);
        if (ret != 0) {
            LOG_FATAL("Search failed with [%d].\n", ret);
        } else {
            LOG_FATAL("slapi_search_internal_pb failed, "
                      "but no error code available.\n");
            ret = EFAULT;
        }
        goto done;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &e);
    if (ret != 0) {
        LOG_FATAL("slapi_pblock_get failed.\n");
        ret = EFAULT;
        goto done;
    }

    if (e == NULL || e[0] == NULL) {
        LOG("No entry with missing SID found.\n");
        ret = 0;
        goto done;
    }

    for (c = 0; e[c] != NULL; c++) {
        ret = find_sid_for_ldap_entry(e[c], worker_ctx->plugin_id,
                                      worker_ctx->base_dn, worker_ctx->dom_sid,
                                      worker_ctx->ranges);
        if (ret != 0) {
            LOG_FATAL("Cannot add SID to existing entry.\n");
            goto done;
        }

        if (worker_ctx->delay != 0) {
            ts.tv_nsec = worker_ctx->delay % NSEC_PER_SEC;
            ts.tv_sec = (worker_ctx->delay - ts.tv_nsec) / NSEC_PER_SEC;
            nanosleep(&ts, NULL);
        }
    };

done:
    slapi_ch_free_string(&filter);
    pthread_cleanup_pop(1);

    LOG("do_work finished with [%d].\n", ret);

    return ret;
}

static void *sidgen_task_thread(void *arg)
{
    Slapi_Task *task = (Slapi_Task *)arg;
    struct worker_ctx *worker_ctx;
    int ret;

    if (task == NULL) {
        LOG_FATAL("Missing task data!\n");
        ret =SLAPI_DSE_CALLBACK_OK;
        goto done;
    }

    worker_ctx = slapi_task_get_data(task);
    if (worker_ctx == NULL) {
        LOG_FATAL("Missing context!\n");
        ret =SLAPI_DSE_CALLBACK_OK;
        goto done;
    }

    slapi_task_begin(task, 1);
    LOG_FATAL("Sidgen task starts ...\n");

    ret = do_work(worker_ctx);

done:
    LOG_FATAL("Sidgen task finished [%d].\n", ret);
    slapi_task_inc_progress(task);
    slapi_task_finish(task, ret);

    return NULL;
}

static void sidgen_task_destructor(Slapi_Task *task)
{
    struct worker_ctx *worker_ctx;

    if (task != NULL) {
        worker_ctx = slapi_task_get_data(task);
        if (worker_ctx != NULL) {
            free_ranges(&worker_ctx->ranges);
            slapi_ch_free_string(&worker_ctx->dom_sid);
            slapi_ch_free_string(&worker_ctx->base_dn);
            slapi_ch_free((void **) &worker_ctx);
        }
    }
}

int sidgen_task_add(Slapi_PBlock *pb, Slapi_Entry *e,
                    Slapi_Entry *eAfter, int *returncode,
                    char *returntext, void *arg)
{
    int ret = SLAPI_DSE_CALLBACK_ERROR;
    const char *str;
    struct worker_ctx *worker_ctx = NULL;
    char *endptr;
    Slapi_Task *task = NULL;

    *returncode = LDAP_OPERATIONS_ERROR;
    returntext[0] = '\0';

    worker_ctx = (struct worker_ctx *) slapi_ch_calloc(1,
                                                     sizeof(struct worker_ctx));
    if (worker_ctx == NULL) {
        LOG_FATAL("slapi_ch_malloc failed!\n");
        *returncode = LDAP_OPERATIONS_ERROR;
        ret = SLAPI_DSE_CALLBACK_ERROR;
        goto done;
    }

    worker_ctx->plugin_id = global_sidgen_plugin_id;

    str = ipa_sidgen_fetch_attr(e, "delay", NULL);
    if (str != NULL) {
        errno = 0;
        worker_ctx->delay = strtol(str, &endptr, 10);
        if (errno != 0 || worker_ctx->delay < 0) {
            LOG_FATAL("invalid delay [%s]!\n", str);
            *returncode = LDAP_CONSTRAINT_VIOLATION;
            ret = SLAPI_DSE_CALLBACK_ERROR;
            goto done;
        }
    }
    LOG("delay is [%li].\n", worker_ctx->delay);

    str = ipa_sidgen_fetch_attr(e, "nsslapd-basedn", NULL);
    if (str == NULL) {
        LOG_FATAL("Missing nsslapd-basedn!\n");
        *returncode = LDAP_CONSTRAINT_VIOLATION;
        ret = SLAPI_DSE_CALLBACK_ERROR;
        goto done;
    }
    worker_ctx->base_dn = slapi_ch_strdup(str);
    if (worker_ctx->base_dn == NULL) {
        LOG_FATAL("Failed to copy base DN.\n");
        *returncode = LDAP_OPERATIONS_ERROR;
        ret = ENOMEM;
        goto done;
    }

    ret = get_dom_sid(worker_ctx->plugin_id, worker_ctx->base_dn,
                      &worker_ctx->dom_sid);
    if (ret != 0) {
        LOG_FATAL("Cannot find domain SID.\n");
        goto done;
    }

    ret = get_ranges(worker_ctx->plugin_id, worker_ctx->base_dn,
                     &worker_ctx->ranges);
    if (ret != 0) {
        LOG_FATAL("Cannot find ranges.\n");
        goto done;
    }

    task = slapi_new_task(slapi_entry_get_ndn(e));
    if (task == NULL) {
        LOG_FATAL("unable to allocate new task!\n");
        *returncode = LDAP_OPERATIONS_ERROR;
        ret = SLAPI_DSE_CALLBACK_ERROR;
        goto done;
    }

    slapi_task_set_destructor_fn(task, sidgen_task_destructor);
    slapi_task_set_data(task, worker_ctx);

    ret = pthread_create(&worker_ctx->tid, NULL, sidgen_task_thread, task);
    if (ret != 0) {
        LOG_FATAL("unable to create sidgen task thread!\n");
        *returncode = LDAP_OPERATIONS_ERROR;
        ret = SLAPI_DSE_CALLBACK_ERROR;
        slapi_task_finish(task, *returncode);
        goto done;
    }

    ret = SLAPI_DSE_CALLBACK_OK;
    *returncode = LDAP_SUCCESS;

done:
    if (ret != SLAPI_DSE_CALLBACK_OK) {
        slapi_ch_free((void **) &worker_ctx->base_dn);
        slapi_ch_free((void **) &worker_ctx);
    }
    return ret;
}

static int sigden_task_start(Slapi_PBlock *pb)
{
    int ret = 0;

    ret = slapi_task_register_handler("ipa-sidgen-task", sidgen_task_add);

    return ret;
}

int sidgen_task_init(Slapi_PBlock *pb)
{
    int ret = 0;

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY,
                           &global_sidgen_plugin_id);
    if (ret != 0 || global_sidgen_plugin_id == NULL) {
        LOG_FATAL("Plugin identity not available.\n");
        ret = (ret != 0) ? ret : EINVAL;
        goto done;
    }

    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                            (void *) SLAPI_PLUGIN_VERSION_03);

    ret |= slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                            (void *) sigden_task_start);

done:
    if (ret != 0) {
        LOG_FATAL("Failed to initialize plug-in\n" );
    }

    return ret;
}
