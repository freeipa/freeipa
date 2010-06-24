/** BEGIN COPYRIGHT BLOCK
 * This Program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this Program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * In addition, as a special exception, Red Hat, Inc. gives You the additional
 * right to link the code of this Program with code not covered under the GNU
 * General Public License ("Non-GPL Code") and to distribute linked combinations
 * including the two, subject to the limitations in this paragraph. Non-GPL Code
 * permitted under this exception must only link to the code of this Program
 * through those well defined interfaces identified in the file named EXCEPTION
 * found in the source code files (the "Approved Interfaces"). The files of
 * Non-GPL Code may instantiate templates or use macros or inline functions from
 * the Approved Interfaces without causing the resulting work to be covered by
 * the GNU General Public License. Only Red Hat, Inc. may make changes or
 * additions to the list of Approved Interfaces. You must obey the GNU General
 * Public License in all respects for all of the Program code and other code used
 * in conjunction with the Program except the Non-GPL Code covered by this
 * exception. If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so. If you do not wish to
 * provide this exception without modification, you must delete this exception
 * statement from your version and license this file solely under the GPL without
 * exception.
 *
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "slapi-plugin.h"
#include "repl-session-plugin.h"
#include "ipa-version.h"
#include <string.h>

/* Identify the type of data we're sending, an unsigned int in this case */
#define REPL_VERSION_DATA_GUID "2D562D8B-2F30-4447-AF76-2B721D1D5F6A"

static char *repl_version_plugin_name = "ipa_replication_version";
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
    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
        "repl_version_plugin_pre_acquire_cb() called for suffix \"%s\", "
        "is_total: \"%s\".\n", slapi_sdn_get_ndn(repl_subtree),
        is_total ? "TRUE" : "FALSE");

    /* allocate some data to be sent to the replica */
    *data_guid = slapi_ch_smprintf("%s", REPL_VERSION_DATA_GUID);
    *data = (struct berval *)slapi_ch_malloc(sizeof(struct berval));
    (*data)->bv_val = slapi_ch_smprintf("%s", data_version);
    (*data)->bv_len = strlen((*data)->bv_val) + 1;

    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
        "repl_version_plugin_pre_acquire_cb() sending data: guid: \"%s\" data: \"%s\".\n",
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
    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
        "test_repl_session_plugin_recv_acquire_cb() called for suffix \"%s\", is_total: \"%s\".\n",
        repl_subtree, is_total ? "TRUE" : "FALSE");

    /* compare our data version to the master data version */
    if (data_guid && data && (strcmp(data_guid, REPL_VERSION_DATA_GUID) == 0)) {
        slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
            "repl_version_plugin_recv_acquire_cb() received data: guid: \"%s\" data: \"%s\".\n",
            data_guid, data->bv_val);
        if (!(strcmp(data_version, data->bv_val) == 0)) {
            slapi_log_error(SLAPI_LOG_FATAL, repl_version_plugin_name,
                "Incompatible IPA versions, pausing replication. This server: \"%s\" remote server: \"%s\".\n", data_version, data->bv_val);
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
    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
                    "--> repl_version_plugin_start -- begin\n");

    data_version = slapi_ch_smprintf("%llu", DATA_VERSION);

    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
                    "<-- repl_version_plugin_start -- end\n");
    return 0;
}

static int
repl_version_plugin_close(Slapi_PBlock *pb)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
                    "--> repl_version_plugin_close -- begin\n");

    slapi_apib_unregister(REPL_SESSION_v1_0_GUID);

    slapi_ch_free_string(&data_version);

    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
                    "<-- repl_version_plugin_close -- end\n");
    return 0;
}

int repl_version_plugin_init(Slapi_PBlock *pb)
{
    slapi_log_error(SLAPI_LOG_PLUGIN, repl_version_plugin_name,
                    "--> repl_version_plugin_init -- begin\n");

    if ( slapi_pblock_set( pb, SLAPI_PLUGIN_VERSION,
                           SLAPI_PLUGIN_VERSION_01 ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                          (void *) repl_version_plugin_start ) != 0 ||
         slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN,
                          (void *) repl_version_plugin_close ) != 0 ||
         slapi_pblock_set( pb, SLAPI_PLUGIN_DESCRIPTION,
                           (void *)&repl_version_pdesc ) != 0 )
    {
        slapi_log_error( SLAPI_LOG_FATAL, repl_version_plugin_name,
                         "<-- repl_version_plugin_init -- failed to register plugin -- end\n");
        return -1;
    }

    if( slapi_apib_register(REPL_SESSION_v1_0_GUID, repl_version_api) ) {
        slapi_log_error( SLAPI_LOG_FATAL, repl_version_plugin_name,
                         "<-- repl_version_plugin_start -- failed to register repl_version api -- end\n");
        return -1;
    }


    /* Retrieve and save the plugin identity to later pass to
       internal operations */
    if (slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &repl_version_plugin_id) != 0) {
        slapi_log_error(SLAPI_LOG_FATAL, repl_version_plugin_name,
                         "<-- repl_version_plugin_init -- failed to retrieve plugin identity -- end\n");
        return -1;
    }

    slapi_log_error( SLAPI_LOG_PLUGIN, repl_version_plugin_name,
                     "<-- repl_version_plugin_init -- end\n");
    return 0;
}
