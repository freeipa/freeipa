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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 /* for asprintf() */
#endif

#include <errno.h>
#include <stdio.h>

#include "ipa_extdom.h"
#include "util.h"

int parse_request_data(struct berval *req_val, struct extdom_req **_req)
{
    BerElement *ber = NULL;
    ber_tag_t tag;
    ber_int_t input_type;
    ber_int_t request_type;
    ber_int_t id;
    struct extdom_req *req;

/* We expect the following request:
 * ExtdomRequestValue ::= SEQUENCE {
 *    inputType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix uid (3),
 *        posix gid (3)
 *    },
 *    requestType ENUMERATED {
 *        simple (1),
 *        full (2)
 *    },
 *    data InputData
 * }
 *
 * InputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData
 *    uid PosixUid,
 *    gid PosixGid
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    uid INTEGER
 * }
 *
 * PosixGid ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    gid INTEGER
 * }
 */

    if (req_val == NULL || req_val->bv_val == NULL || req_val->bv_len == 0) {
        return LDAP_PROTOCOL_ERROR;
    }

    ber = ber_init(req_val);
    if (ber == NULL) {
        return LDAP_PROTOCOL_ERROR;
    }

    tag = ber_scanf(ber, "{ee", &input_type, &request_type);
    if (tag == LBER_ERROR) {
        ber_free(ber, 1);
        return LDAP_PROTOCOL_ERROR;
    }

    req = calloc(sizeof(struct extdom_req), 1);
    if (req == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    req->input_type = input_type;
    req->request_type = request_type;

    switch (req->input_type) {
        case INP_NAME:
            tag = ber_scanf(ber, "{aa}}", &req->data.name.domain_name,
                                            &req->data.name.object_name);
            break;
        case INP_SID:
            tag = ber_scanf(ber, "a}", &req->data.sid);
            break;
        case INP_POSIX_UID:
            tag = ber_scanf(ber, "{ai}}", &req->data.posix_uid.domain_name,
                                            &id);
            req->data.posix_uid.uid = (uid_t) id;
            break;
        case INP_POSIX_GID:
            tag = ber_scanf(ber, "{ai}}", &req->data.posix_gid.domain_name,
                                            &id);
            req->data.posix_gid.gid = (gid_t) id;
            break;
        default:
            ber_free(ber, 1);
            return LDAP_PROTOCOL_ERROR;
    }
    ber_free(ber, 1);
    if (tag == LBER_ERROR) {
        return LDAP_PROTOCOL_ERROR;
    }

    *_req = req;

    return LDAP_SUCCESS;
}

static void free_domain_info(struct domain_info *domain_info)
{
    if (domain_info == NULL) {
        return;
    }

    sss_idmap_free(domain_info->idmap_ctx);
    slapi_ch_free((void **) &domain_info->guid);
    slapi_ch_free((void **) &domain_info->sid);
    slapi_ch_free((void **) &domain_info->flat_name);
    free(domain_info);
}

static int set_domain_range(struct ipa_extdom_ctx *ctx, const char *dom_sid_str,
                            struct sss_idmap_range *range)
{
    Slapi_PBlock *pb = NULL;
    Slapi_Entry **e = NULL;
    char *filter = NULL;
    int ret;
    unsigned long ulong_val;

    pb = slapi_pblock_new();
    if (pb == NULL) {
        return ENOMEM;
    }

    ret = asprintf(&filter, "(&(ipaNTTrustedDomainSID=%s)" \
                              "(objectclass=ipaTrustedADDomainRange))",
                            dom_sid_str);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    slapi_search_internal_set_pb(pb, ctx->base_dn,
                                 LDAP_SCOPE_SUBTREE, filter,
                                 NULL, 0, NULL, NULL, ctx->plugin_id, 0);

    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

    if (ret != EOK) {
        ret = ENOENT;
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &e);
    if (!e || !e[0]) {
        /* no matches */
        ret = ENOENT;
        goto done;
    }

    /* TODO: handle more than one range per domain */
    ulong_val = slapi_entry_attr_get_ulong(e[0], "ipaBaseID");
    if (ulong_val >= UINT32_MAX) {
        ret = EINVAL;
        goto done;
    }
    range->min = (uint32_t) ulong_val;

    ulong_val = slapi_entry_attr_get_ulong(e[0], "ipaIDRangeSize");
    if ((range->min + ulong_val -1) >= UINT32_MAX) {
        ret = EINVAL;
        goto done;
    }
    range->max = (range->min + ulong_val -1);

    ret = 0;

done:
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    free(filter);

    return ret;
}

/* TODO: A similar call is used in ipa_cldap_netlogon.c, maybe a candidate for
 * a common library */
static int get_domain_info(struct ipa_extdom_ctx *ctx, const char *domain_name,
                           struct domain_info **_domain_info)
{
    struct domain_info *domain_info = NULL;
    Slapi_PBlock *pb = NULL;
    Slapi_Entry **e = NULL;
    char *filter = NULL;
    int ret;
    enum idmap_error_code err;
    struct sss_idmap_range range;

    pb = slapi_pblock_new();
    if (pb == NULL) {
        return ENOMEM;
    }

    ret = asprintf(&filter, "(&(|(cn=%s)(ipaNTTrustPartner=%s)(ipaNTFlatName=%s))(objectclass=ipaNTTrustedDomain))",
                            domain_name, domain_name, domain_name);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    slapi_search_internal_set_pb(pb, ctx->base_dn,
                                 LDAP_SCOPE_SUBTREE, filter,
                                 NULL, 0, NULL, NULL, ctx->plugin_id, 0);

    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

    if (ret != EOK) {
        ret = ENOENT;
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &e);
    if (!e || !e[0] || e[1]) {
        /* no matches or too many matches */
        ret = ENOENT;
        goto done;
    }

    domain_info = calloc(1, sizeof(struct domain_info));
    if (domain_info == NULL) {
        ret = ENOMEM;
        goto done;
    }

    domain_info->guid = slapi_entry_attr_get_charptr(e[0], "ipaNTDomainGUID");
    domain_info->sid = slapi_entry_attr_get_charptr(e[0],
                                                    "ipaNTTrustedDomainSID");
    domain_info->flat_name = slapi_entry_attr_get_charptr(e[0],
                                                          "ipaNTFlatName");

    /* TODO: read range from LDAP server */
/*
    range.min = 200000;
    range.max = 400000;
*/
    ret = set_domain_range(ctx, domain_info->sid, &range);
    if (ret != 0) {
        goto done;
    }

    err = sss_idmap_init(NULL, NULL, NULL, &domain_info->idmap_ctx);
    if (err == IDMAP_SUCCESS) {
        err = sss_idmap_add_domain(domain_info->idmap_ctx, domain_name,
                                   domain_info->sid, &range);
    }
    if (err != IDMAP_SUCCESS) {
        free_domain_info(domain_info);
        ret = EFAULT;
        goto done;
    }

    *_domain_info = domain_info;

    ret = 0;

done:
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    free(filter);
    return ret;

}

int handle_request(struct ipa_extdom_ctx *ctx, struct extdom_req *req,
                   struct extdom_res **res)
{
    wbcErr werr;
    int ret;
    struct wbcDomainSid sid;
    char *domain_name;
    char *name;
    enum wbcSidType name_type;
    struct domain_info *domain_info = NULL;

    ret = get_domain_info(ctx, req->data.name.domain_name, &domain_info);
    if (ret != 0) {
        return LDAP_OPERATIONS_ERROR;
    }

    switch (req->input_type) {
        case INP_SID:
            werr = wbcStringToSid(req->data.sid, &sid);
            if (!WBC_ERROR_IS_OK(werr)) {
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            werr = wbcLookupSid(&sid, &domain_name, &name, &name_type);
            if (!WBC_ERROR_IS_OK(werr)) {
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            ret = create_response(req, domain_info, domain_name, name, &sid,
                                  name_type, res);
            if (ret != 0) {
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            break;
        case INP_NAME:
            werr = wbcLookupName(domain_info->flat_name,
                                 req->data.name.object_name, &sid, &name_type);
            if (!WBC_ERROR_IS_OK(werr)) {
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            ret = create_response(req, domain_info, req->data.name.domain_name,
                                  req->data.name.object_name, &sid, name_type,
                                  res);
            if (ret != 0) {
                ret = LDAP_OPERATIONS_ERROR;
                goto done;
            }

            break;
        default:
            ret = LDAP_PROTOCOL_ERROR;
            goto done;
    }

    ret = LDAP_SUCCESS;

done:
    free_domain_info(domain_info);

    return ret;
}

int create_response(struct extdom_req *req, struct domain_info *domain_info,
                    const char *domain_name,
                    const char *name, struct wbcDomainSid *sid,
                    enum wbcSidType name_type, struct extdom_res **_res)
{
    int ret = EFAULT;
    int len;
    struct extdom_res *res;
    uint32_t id;
    enum idmap_error_code err;
    char sid_str[WBC_SID_STRING_BUFLEN + 1];

    res = malloc(sizeof(struct extdom_res));
    if (res == NULL) {
        return ENOMEM;
    }

    switch (req->request_type) {
        case REQ_SIMPLE:
            switch (req->input_type) {
                case INP_SID:
                    res->response_type = RESP_NAME;
                    res->data.name.domain_name = domain_name;
                    res->data.name.object_name = name;
                    break;
                case INP_NAME:
                    res->response_type = RESP_SID;

                    len = wbcSidToStringBuf(sid, sid_str,
                                            WBC_SID_STRING_BUFLEN);
                    if (len + 1 > WBC_SID_STRING_BUFLEN) {
                        ret = EINVAL;
                        goto done;
                    }

                    res->data.sid = sid_str;
                    break;
                default:
                    ret = EINVAL;
                    goto done;
            }
            break;
        case REQ_FULL:
            len = wbcSidToStringBuf(sid, sid_str, WBC_SID_STRING_BUFLEN);
            if (len + 1 > WBC_SID_STRING_BUFLEN) {
                ret = EINVAL;
                goto done;
            }

            err = sss_idmap_sid_to_unix(domain_info->idmap_ctx, sid_str, &id);
            if (err != IDMAP_SUCCESS) {
                ret = EINVAL;
                goto done;
            }
            switch (name_type) {
                case WBC_SID_NAME_USER:
                    res->response_type = RESP_USER;
                    res->data.user.domain_name = domain_name;
                    res->data.user.user_name = name;

                    res->data.user.uid = (uid_t) id;

                    /* We use MPGs for external users */
                    res->data.user.gid = (gid_t) id;
                    break;
                case WBC_SID_NAME_DOM_GRP:
                    res->response_type = RESP_GROUP;
                    res->data.group.domain_name = domain_name;
                    res->data.group.group_name = name;

                    res->data.group.gid = (gid_t) id;
                    break;
                default:
                    ret = EINVAL;
                    goto done;
            }
            break;
        default:
            ret = EINVAL;
            goto done;
    }

    ret = 0;

done:
    if (ret == 0) {
        *_res = res;
    } else {
        free(res);
    }

    return ret;
}

int pack_response(struct extdom_res *res, struct berval **ret_val)
{
    BerElement *ber = NULL;
    int ret;

/* We send to follwing response:
 * ExtdomResponseValue ::= SEQUENCE {
 *    responseType ENUMERATED {
 *        sid (1),
 *        name (2),
 *        posix_user (3),
 *        posix_group (4)
 *    },
 *    data OutputData
 * }
 *
 * OutputData ::= CHOICE {
 *    sid OCTET STRING,
 *    name NameDomainData,
 *    user PosixUser,
 *    group PosixGroup
 * }
 *
 * NameDomainData ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    object_name OCTET STRING
 * }
 *
 * PosixUser ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    user_name OCTET STRING,
 *    uid INTEGER
 *    gid INTEGER
 * }
 *
 * PosixGroup ::= SEQUENCE {
 *    domain_name OCTET STRING,
 *    group_name OCTET STRING,
 *    gid INTEGER
 * }
 */

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    switch (res->response_type) {
        case RESP_SID:
            ret = ber_printf(ber,"{es}", res->response_type, res->data.sid);
            break;
        case RESP_NAME:
            ret = ber_printf(ber,"{e{ss}}", res->response_type,
                                            res->data.name.domain_name,
                                            res->data.name.object_name);
            break;
        case RESP_USER:
            ret = ber_printf(ber,"{e{ssii}}", res->response_type,
                                              res->data.user.domain_name,
                                              res->data.user.user_name,
                                              res->data.user.uid,
                                              res->data.user.gid);
            break;
        case RESP_GROUP:
            ret = ber_printf(ber,"{e{ssi}}", res->response_type,
                                             res->data.group.domain_name,
                                             res->data.group.group_name,
                                             res->data.group.gid);
            break;
        default:
            ber_free(ber, 1);
            return LDAP_OPERATIONS_ERROR;
    }

    if (ret == -1) {
        ber_free(ber, 1);
        return LDAP_OPERATIONS_ERROR;
    }

    ret = ber_flatten(ber, ret_val);
    if (ret == -1) {
        ber_free(ber, 1);
        return LDAP_OPERATIONS_ERROR;
    }

    ber_free(ber, 1);

    return LDAP_SUCCESS;
}
