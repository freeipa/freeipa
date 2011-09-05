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
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "slapi-plugin.h"
#include "repl-session-plugin.h"
#include "ipa-version.h"
#include "util.h"
#include <string.h>

/* Identify the type of data we're sending, an unsigned int in this case */
#define REPL_VERSION_DATA_GUID "2D562D8B-2F30-4447-AF76-2B721D1D5F6A"

#define IPA_PLUGIN_NAME "ipa_replication_version"
static char *data_version = NULL;

/*
 * Plugin identifiers
 */
static Slapi_PluginDesc repl_version_pdesc = {
    "ipa-repl-version-plugin",
    "Red Hat, Inc.",
    "1.0",
    "IPA Replication version plugin"
};

static Slapi_ComponentId *repl_version_plugin_id = NULL;


/*
 * Replication Version Callbacks
 */

/*
 * This is called on a master when we are about to acquire a
 * replica.
 *
 * Returning non-0 will abort the replication session.  This
 * results in the master going into incremental backoff mode.
 */
static int
repl_version_plugin_pre_acquire_cb(void *cookie, const Slapi_DN *repl_subtree,
                                        int is_total, char **data_guid, struct berval **data)
{
    LOG("repl_version_plugin_pre_acquire_cb() called for suffix \"%s\", "
        "is_total: \"%s\".\n", slapi_sdn_get_ndn(repl_subtree),
        is_total ? "TRUE" : "FALSE");

    /* allocate some data to be sent to the replica */
    *data_guid = slapi_ch_smprintf("%s", REPL_VERSION_DATA_GUID);
    *data = (struct berval *)slapi_ch_malloc(sizeof(struct berval));
    (*data)->bv_val = slapi_ch_smprintf("%s", data_version);
    (*data)->bv_len = strlen((*data)->bv_val) + 1;

    LOG("repl_version_plugin_pre_acquire_cb() sending data: guid: \"%s\" data: \"%s\".\n",
        *data_guid, (*data)->bv_val);

    return 0;
}

/*
 * This is called on a replica when it receives a start replication
 * extended operation from a master.
 *
 * The data sent by the master (version) is compared with our own
 * hardcoded version to determine if replication can proceed or not.
 *
 * The replication plug-in will take care of freeing data_guid and data.
 *
 * Returning non-0 will abort the replication session.  This
 * results in the master going into incremental backoff mode.
 */
static int
repl_version_plugin_recv_acquire_cb(const char *repl_subtree, int is_total,
                                         const char *data_guid, const struct berval *data)
{
    LOG("test_repl_session_plugin_recv_acquire_cb() called for suffix \"%s\", is_total: \"%s\".\n",
        repl_subtree, is_total ? "TRUE" : "FALSE");

    /* compare our data version to the master data version */
    if (data_guid && data && (strcmp(data_guid, REPL_VERSION_DATA_GUID) == 0)) {
        LOG("repl_version_plugin_recv_acquire_cb() received data: guid: \"%s\" data: \"%s\".\n",
            data_guid, data->bv_val);
        if (!(strcmp(data_version, data->bv_val) == 0)) {
            LOG_FATAL("Incompatible IPA versions, pausing replication. "
                      "This server: \"%s\" remote server: \"%s\".\n",
                      data_version, data->bv_val);
            return 1;
        }
    }

    return 0;
}

/*
 * Callback list for registering API
 */
static void *repl_version_api[] = {
    NULL, /* reserved for api broker use, must be zero */
    NULL, /* init cb */
    repl_version_plugin_pre_acquire_cb,
    NULL, /* reply_acquire_cb */
    NULL, /* post_acquire_cb */
    repl_version_plugin_recv_acquire_cb,
    NULL /* destroy cb */
};

/*
 * Plug-in framework functions
 */
static int
repl_version_plugin_start(Slapi_PBlock *pb)
{
    LOG("--> repl_version_plugin_start -- begin\n");

    data_version = slapi_ch_smprintf("%llu", (unsigned long long) DATA_VERSION);

    LOG("<-- repl_version_plugin_start -- end\n");
    return 0;
}

static int
repl_version_plugin_close(Slapi_PBlock *pb)
{
    LOG("--> repl_version_plugin_close -- begin\n");

    slapi_apib_unregister(REPL_SESSION_v1_0_GUID);

    slapi_ch_free_string(&data_version);

    LOG("<-- repl_version_plugin_close -- end\n");
    return 0;
}

int repl_version_plugin_init(Slapi_PBlock *pb)
{
    LOG("--> repl_version_plugin_init -- begin\n");

    if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION,
                           SLAPI_PLUGIN_VERSION_01 ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                          (void *) repl_version_plugin_start ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                          (void *) repl_version_plugin_close ) != 0 ||
         slapi_pblock_set( pb, SLAPI_PLUGIN_DESCRIPTION,
                           (void *)&repl_version_pdesc ) != 0 )
    {
        LOG_FATAL("<-- repl_version_plugin_init -- failed to register plugin -- end\n");
        return -1;
    }

    if( slapi_apib_register(REPL_SESSION_v1_0_GUID, repl_version_api) ) {
        LOG_FATAL("<-- repl_version_plugin_start -- failed to register repl_version api -- end\n");
        return -1;
    }


    /* Retrieve and save the plugin identity to later pass to
       internal operations */
    if (slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &repl_version_plugin_id) != 0) {
        LOG_FATAL("<-- repl_version_plugin_init -- failed to retrieve plugin identity -- end\n");
        return -1;
    }

    LOG("<-- repl_version_plugin_init -- end\n");
    return 0;
}
