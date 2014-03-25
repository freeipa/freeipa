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

#define MAX(a,b) (((a)>(b))?(a):(b))
#define SSSD_DOMAIN_SEPARATOR '@'

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
            free(req);
            return LDAP_PROTOCOL_ERROR;
    }
    ber_free(ber, 1);
    if (tag == LBER_ERROR) {
        free(req);
        return LDAP_PROTOCOL_ERROR;
    }

    *_req = req;

    return LDAP_SUCCESS;
}

void free_req_data(struct extdom_req *req)
{
    if (req == NULL) {
        return;
    }

    switch (req->input_type) {
    case INP_NAME:
        ber_memfree(req->data.name.domain_name);
        ber_memfree(req->data.name.object_name);
        break;
    case INP_SID:
        ber_memfree(req->data.sid);
        break;
    case INP_POSIX_UID:
        ber_memfree(req->data.posix_uid.domain_name);
        break;
    case INP_POSIX_GID:
        ber_memfree(req->data.posix_gid.domain_name);
        break;
    }

    free(req);
}

int handle_request(struct ipa_extdom_ctx *ctx, struct extdom_req *req,
                   struct extdom_res **res)
{
    int ret;
    char *domain_name = NULL;
    char *sid_str = NULL;
    size_t buf_len;
    char *buf = NULL;
    long pw_max;
    long gr_max;
    struct pwd_grp pg_data;
    struct passwd *pwd_result = NULL;
    struct group *grp_result = NULL;
    enum sss_id_type id_type;
    char *fq_name = NULL;
    char *sep;


    pw_max = sysconf(_SC_GETPW_R_SIZE_MAX);
    gr_max = sysconf(_SC_GETGR_R_SIZE_MAX);

    if (pw_max == -1 && gr_max == -1) {
        buf_len = 16384;
    } else {
        buf_len = MAX(pw_max, gr_max);
    }

    buf = malloc(sizeof(char) * buf_len);
    if (buf == NULL) {
        return LDAP_OPERATIONS_ERROR;
    }

    switch (req->input_type) {
    case INP_POSIX_UID:
        if (req->request_type == REQ_SIMPLE) {
            ret = sss_nss_getsidbyid(req->data.posix_uid.uid, &sid_str,
                                     &id_type);
        } else {
            id_type = SSS_ID_TYPE_UID;
            ret = getpwuid_r(req->data.posix_uid.uid, &pg_data.data.pwd, buf,
                             buf_len, &pwd_result);
        }

        domain_name = strdup(req->data.posix_uid.domain_name);
        break;
    case INP_POSIX_GID:
        if (req->request_type == REQ_SIMPLE) {
            ret = sss_nss_getsidbyid(req->data.posix_uid.uid, &sid_str,
                                     &id_type);
        } else {
            id_type = SSS_ID_TYPE_GID;
            ret = getgrgid_r(req->data.posix_gid.gid, &pg_data.data.grp, buf,
                             buf_len, &grp_result);
        }

        domain_name = strdup(req->data.posix_gid.domain_name);
        break;
    case INP_SID:
        ret = sss_nss_getnamebysid(req->data.sid, &fq_name, &id_type);
        if (ret != 0) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        sep = strrchr(fq_name, SSSD_DOMAIN_SEPARATOR);
        if (sep == NULL) {
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }

        ret = asprintf(&domain_name, "%s", sep+1);
        if (ret == -1) {
            ret = LDAP_OPERATIONS_ERROR;
            domain_name = NULL; /* content is undefined according to
                                   asprintf(3) */
            goto done;
        }

        switch(id_type) {
        case SSS_ID_TYPE_UID:
        case SSS_ID_TYPE_BOTH:
            ret = getpwnam_r(fq_name, &pg_data.data.pwd, buf, buf_len,
                             &pwd_result);
            break;
        case SSS_ID_TYPE_GID:
            ret = getgrnam_r(fq_name, &pg_data.data.grp, buf, buf_len,
                             &grp_result);
            break;
        default:
            ret = LDAP_OPERATIONS_ERROR;
            goto done;
        }
        break;
    case INP_NAME:
        ret = asprintf(&fq_name, "%s%c%s", req->data.name.object_name,
                                           SSSD_DOMAIN_SEPARATOR,
                                           req->data.name.domain_name);
        if (ret == -1) {
            ret = LDAP_OPERATIONS_ERROR;
            fq_name = NULL; /* content is undefined according to
                               asprintf(3) */
            goto done;
        }

        if (req->request_type == REQ_SIMPLE) {
            ret = sss_nss_getsidbyname(fq_name, &sid_str, &id_type);
        } else {
            id_type = SSS_ID_TYPE_UID;
            ret = getpwnam_r(fq_name, &pg_data.data.pwd, buf, buf_len,
                             &pwd_result);
            if (ret == 0 && pwd_result == NULL) { /* no user entry found */
                id_type = SSS_ID_TYPE_GID;
                ret = getgrnam_r(fq_name, &pg_data.data.grp, buf, buf_len,
                                 &grp_result);
            }
        }
        domain_name = strdup(req->data.name.domain_name);
        break;
    default:
        ret = LDAP_PROTOCOL_ERROR;
        goto done;
    }

    if (ret != 0) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    } else if (ret == 0 && pwd_result == NULL && grp_result == NULL &&
               sid_str == NULL) {
        ret = LDAP_NO_SUCH_OBJECT;
        goto done;
    }

    if (domain_name == NULL) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }

    ret = create_response(req, &pg_data, sid_str, id_type, domain_name, res);
    if (ret != 0) {
        ret = LDAP_OPERATIONS_ERROR;
        goto done;
    }


    ret = LDAP_SUCCESS;

done:
    free(buf);
    free(fq_name);
    free(domain_name);
    free(sid_str);

    return ret;
}

int create_response(struct extdom_req *req, struct pwd_grp *pg_data,
                    const char *sid_str, enum sss_id_type id_type,
                    const char *domain_name, struct extdom_res **_res)
{
    int ret = EFAULT;
    char *locat = NULL;
    struct extdom_res *res;

    res = calloc(1, sizeof(struct extdom_res));
    if (res == NULL) {
        return ENOMEM;
    }

    switch (req->request_type) {
        case REQ_SIMPLE:
            switch (req->input_type) {
                case INP_SID:
                    res->response_type = RESP_NAME;
                    res->data.name.domain_name = strdup(domain_name);
                    switch(id_type) {
                    case SSS_ID_TYPE_UID:
                    case SSS_ID_TYPE_BOTH:
                        if ((locat = strchr(pg_data->data.pwd.pw_name, SSSD_DOMAIN_SEPARATOR)) != NULL) {
                            if (strcasecmp(locat+1, domain_name) == 0  ) {
                                locat[0] = 0;
                            } else {
                                ret = LDAP_NO_SUCH_OBJECT;
                                goto done;
                            }
                        }
                        res->data.name.object_name =
                                              strdup(pg_data->data.pwd.pw_name);
                        break;
                    case SSS_ID_TYPE_GID:
                        if ((locat = strchr(pg_data->data.grp.gr_name, SSSD_DOMAIN_SEPARATOR)) != NULL) {
                            if (strcasecmp(locat+1, domain_name) == 0) {
                                locat[0] = 0;
                            } else {
                                ret = LDAP_NO_SUCH_OBJECT;
                                goto done;
                            }
                        }
                        res->data.name.object_name =
                                              strdup(pg_data->data.grp.gr_name);
                        break;
                    default:
                        ret = EINVAL;
                        goto done;
                    }

                    if (res->data.name.domain_name == NULL
                            || res->data.name.object_name == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                    break;
                case INP_NAME:
                case INP_POSIX_UID:
                case INP_POSIX_GID:
                    res->response_type = RESP_SID;
                    res->data.sid = strdup(sid_str);
                    if (res->data.sid == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }
                    break;
                default:
                    ret = EINVAL;
                    goto done;
            }
            break;
        case REQ_FULL:
            switch (id_type) {
                case SSS_ID_TYPE_UID:
                case SSS_ID_TYPE_BOTH:
                    res->response_type = RESP_USER;
                    res->data.user.domain_name = strdup(domain_name);
                    if ((locat = strchr(pg_data->data.pwd.pw_name, SSSD_DOMAIN_SEPARATOR)) != NULL) {
                        if (strcasecmp(locat+1, domain_name) == 0) {
                            locat[0] = 0;
                        } else {
                            ret = LDAP_NO_SUCH_OBJECT;
                            goto done;
                        }
                    }
                    res->data.user.user_name =
                                              strdup(pg_data->data.pwd.pw_name);

                    if (res->data.user.domain_name == NULL
                            || res->data.user.user_name == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    res->data.user.uid = pg_data->data.pwd.pw_uid;
                    res->data.user.gid = pg_data->data.pwd.pw_gid;
                    break;
                case SSS_ID_TYPE_GID:
                    res->response_type = RESP_GROUP;
                    res->data.group.domain_name = strdup(domain_name);
                    if ((locat = strchr(pg_data->data.grp.gr_name, SSSD_DOMAIN_SEPARATOR)) != NULL) {
                        if (strcasecmp(locat+1, domain_name) == 0) {
                            locat[0] = 0;
                        } else {
                            ret = LDAP_NO_SUCH_OBJECT;
                            goto done;
                        }
                    }
                    res->data.group.group_name =
                                              strdup(pg_data->data.grp.gr_name);

                    if (res->data.group.domain_name == NULL
                            || res->data.group.group_name == NULL) {
                        ret = ENOMEM;
                        goto done;
                    }

                    res->data.group.gid = pg_data->data.grp.gr_gid;
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
        free_resp_data(res);
    }

    if (locat != NULL) {
        locat[0] = SSSD_DOMAIN_SEPARATOR;
    }

    return ret;
}

void free_resp_data(struct extdom_res *res)
{
    if (res == NULL) {
        return;
    }

    switch (res->response_type) {
    case RESP_SID:
        free(res->data.sid);
        break;
    case RESP_NAME:
        free(res->data.name.domain_name);
        free(res->data.name.object_name);
        break;
    case RESP_USER:
        free(res->data.user.domain_name);
        free(res->data.user.user_name);
        break;
    case RESP_GROUP:
        free(res->data.group.domain_name);
        free(res->data.group.group_name);
        break;
    }

    free(res);
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
