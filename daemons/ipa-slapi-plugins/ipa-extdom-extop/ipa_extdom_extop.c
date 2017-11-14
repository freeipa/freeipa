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

#include "ipa_extdom.h"
#include "back_extdom.h"
#include "util.h"

#define DEFAULT_MAX_NSS_BUFFER (128*1024*1024)
#define DEFAULT_MAX_NSS_TIMEOUT (10*1000)

Slapi_PluginDesc ipa_extdom_plugin_desc = {
    IPA_EXTDOM_FEATURE_DESC,
    "FreeIPA project",
    "FreeIPA/1.0",
    IPA_EXTDOM_PLUGIN_DESC
};

static char *ipa_extdom_oid_list[] = {
    EXOP_EXTDOM_OID,
    EXOP_EXTDOM_V1_OID,
    NULL
};

static char *ipa_extdom_name_list[] = {
    IPA_EXTDOM_PLUGIN_DESC,
    NULL
};

static int ipa_extdom_start(Slapi_PBlock *pb)
{
    return LDAP_SUCCESS;
}

static int ipa_extdom_extop(Slapi_PBlock *pb)
{
    char *oid = NULL;
    char *err_msg = NULL;
    int rc;
    int ret;
    struct berval *req_val = NULL;
    struct berval *ret_val = NULL;
    struct extdom_req *req = NULL;
    struct ipa_extdom_ctx *ctx;
    enum extdom_version version;

    ret = slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_OID, &oid);
    if (ret != 0) {
        rc = LDAP_OPERATIONS_ERROR;
        err_msg = "Could not get OID value from request.\n";
        goto done;
    }
    LOG("Received extended operation request with OID %s\n", oid);

    if (strcasecmp(oid, EXOP_EXTDOM_OID) == 0) {
        version = EXTDOM_V0;
    } else if (strcasecmp(oid, EXOP_EXTDOM_V1_OID) == 0) {
        version = EXTDOM_V1;
    } else {
        return SLAPI_PLUGIN_EXTENDED_NOT_HANDLED;
    }

    ret = slapi_pblock_get(pb, SLAPI_EXT_OP_REQ_VALUE, &req_val);
    if (ret != 0) {
        rc = LDAP_UNWILLING_TO_PERFORM;
        err_msg = "Missing request data.\n";
        goto done;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &ctx);
    if (ret != 0) {
        rc = LDAP_OPERATIONS_ERROR;
        err_msg = "Missing plugin context.\n";
        goto done;
    }

    ret = parse_request_data(req_val, &req);
    if (ret != LDAP_SUCCESS) {
        rc = LDAP_UNWILLING_TO_PERFORM;
        err_msg = "Cannot parse request data.\n";
        goto done;
    }

    ret = check_request(req, version);
    if (ret != LDAP_SUCCESS) {
        rc = LDAP_UNWILLING_TO_PERFORM;
        err_msg = "Error in request data.\n";
        goto done;
    }

    ret = handle_request(ctx, req, &ret_val);
    if (ret != LDAP_SUCCESS) {
        if (ret == LDAP_NO_SUCH_OBJECT) {
            rc = LDAP_NO_SUCH_OBJECT;
        } else {
            rc = LDAP_OPERATIONS_ERROR;
            err_msg = "Failed to handle the request.\n";
        }
        goto done;
    }

    ret = slapi_pblock_set(pb, SLAPI_EXT_OP_RET_OID, oid);
    if (ret != 0) {
        rc = LDAP_OPERATIONS_ERROR;
        err_msg = "Failed to set the OID for the response.\n";
        goto done;
    }

    ret = slapi_pblock_set( pb, SLAPI_EXT_OP_RET_VALUE, ret_val);
    if (ret != 0) {
        rc = LDAP_OPERATIONS_ERROR;
        err_msg = "Failed to set the value for the response.\n";
        goto done;
    }

    rc = LDAP_SUCCESS;

done:
    if ((req != NULL) && (req->err_msg != NULL)) {
        err_msg = req->err_msg;
    }
    if (err_msg != NULL) {
        LOG("%s", err_msg);
    }
    slapi_send_ldap_result(pb, rc, NULL, err_msg, 0, NULL);
    ber_bvfree(ret_val);
    free_req_data(req);
    return SLAPI_PLUGIN_EXTENDED_SENT_RESULT;
}

static int ipa_extdom_init_ctx(Slapi_PBlock *pb, struct ipa_extdom_ctx **_ctx)
{
    struct ipa_extdom_ctx *ctx;
    Slapi_Entry *e;
    int ret;
    unsigned int timeout;

    ctx = calloc(1, sizeof(struct ipa_extdom_ctx));
    if (!ctx) {
        return LDAP_OPERATIONS_ERROR;
    }

    ret = slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &ctx->plugin_id);
    if ((ret != 0) || (NULL == ctx->plugin_id)) {
        LOG_FATAL("Could not get identity or identity was NULL\n");
        if (ret == 0) {
            ret = -1;
        }
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &e);
    if (!e) {
        LOG_FATAL("Plugin configuration not found!\n");
        ret = -1;
        goto done;
    }

    ctx->base_dn = slapi_entry_attr_get_charptr(e, "nsslapd-basedn");
    if (!ctx->base_dn) {
        LOG_FATAL("Base DN not found in plugin configuration not found!\n");
        ret = -1;
        goto done;
    }

    ctx->max_nss_buf_size = slapi_entry_attr_get_uint(e,
                                                      "ipaExtdomMaxNssBufSize");
    if (ctx->max_nss_buf_size == 0) {
        ctx->max_nss_buf_size = DEFAULT_MAX_NSS_BUFFER;
    }
    LOG("Maximal nss buffer size set to [%zu]!\n", ctx->max_nss_buf_size);


    ret = back_extdom_init_context(&ctx->nss_ctx);
    if (ret != 0) {
        LOG("Unable to initialize nss interface: returned [%d]!\n", ret);
        goto done;
    }

    timeout = slapi_entry_attr_get_uint(e, "ipaExtdomMaxNssTimeout");
    if (timeout == 0) {
        timeout = DEFAULT_MAX_NSS_TIMEOUT;
    }
    back_extdom_set_timeout(ctx->nss_ctx, timeout);
    LOG("Maximal nss timeout (in ms) set to [%u]!\n", timeout);

    ret = 0;

done:
    if (ret) {
        free(ctx);
    } else {
        *_ctx = ctx;
    }
    return ret;
}

int ipa_extdom_init(Slapi_PBlock *pb)
{
    int ret;
    struct ipa_extdom_ctx *extdom_ctx;

    ret = ipa_extdom_init_ctx(pb, &extdom_ctx);
    if (ret) {
        LOG_FATAL("Failed ot initialize external domain extended operation.\n");
        /* do not cause DS to stop, simply do nothing */
        return 0;
    }

    ret = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_01);
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                               (void *)&ipa_extdom_plugin_desc);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN,
                               (void *)ipa_extdom_start);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_OIDLIST,
                               ipa_extdom_oid_list);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_NAMELIST,
                               ipa_extdom_name_list);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_EXT_OP_FN,
                               (void *)ipa_extdom_extop);
    }
    if (!ret) {
        ret = slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, extdom_ctx);
    }
    if (ret) {
        LOG("Failed to set plug-in version, function, and OID.\n" );
        return -1;
    }

    return 0;
}
