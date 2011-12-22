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
 * Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc.
 * All rights reserved.
 * END COPYRIGHT BLOCK **/

#include "ipa_cldap.h"
#include <endian.h>
#include <talloc.h>
#include <ctype.h>
#include "gen_ndr/ndr_nbt.h"
#include "gen_ndr/netlogon.h"

static int string_to_guid(char *str, struct GUID *guid)
{
    unsigned int time_low;
    unsigned int time_mid;
    unsigned int time_hi;
    unsigned int seq[2];
    unsigned int node[6];
    int ret;

    ret = sscanf(str, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 &time_low, &time_mid, &time_hi, &seq[0], &seq[1],
                 &node[0], &node[1], &node[2], &node[3], &node[4], &node[5]);
    if (ret != 11) {
        return EINVAL;
    }

    guid->time_low = time_low;
    guid->time_mid = time_mid;
    guid->time_hi_and_version = time_hi;
    guid->clock_seq[0] = seq[0];
    guid->clock_seq[1] = seq[1];
    guid->node[0] = node[0];
    guid->node[1] = node[1];
    guid->node[2] = node[2];
    guid->node[3] = node[3];
    guid->node[4] = node[4];
    guid->node[5] = node[5];

    return 0;
}

static int ipa_cldap_get_domain_entry(struct ipa_cldap_ctx *ctx,
                                      char *domain,
                                      char **guid, char **sid, char **name)
{
    Slapi_PBlock *pb;
    Slapi_Entry **e = NULL;
    char *filter;
    int ret;

    pb = slapi_pblock_new();
    if (!pb) {
        return ENOMEM;
    }

    ret = asprintf(&filter, "(&(cn=%s)(objectclass=ipaNTDomainAttrs))", domain);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    slapi_search_internal_set_pb(pb, ctx->base_dn,
                                 LDAP_SCOPE_SUBTREE, filter,
                                 NULL, 0, NULL, NULL, ctx->plugin_id, 0);

    slapi_search_internal_pb(pb);
    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &ret);

    if (ret) {
        ret = ENOENT;
        goto done;
    }

    slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &e);
    if (!e || !e[0] || e[1]) {
        /* no matches or too many matches */
        ret = ENOENT;
        goto done;
    }

    *guid = slapi_entry_attr_get_charptr(e[0], "ipaNTDomainGUID");
    *sid = slapi_entry_attr_get_charptr(e[0], "ipaNTSecurityIdentifier");
    *name = slapi_entry_attr_get_charptr(e[0], "ipaNTFlatName");

    ret = 0;

done:
    slapi_free_search_results_internal(pb);
    slapi_pblock_destroy(pb);
    free(filter);
    return ret;
}

#define NETLOGON_SAM_LOGON_RESPONSE_EX_pusher \
            (ndr_push_flags_fn_t)ndr_push_NETLOGON_SAM_LOGON_RESPONSE_EX

static int ipa_cldap_encode_netlogon(char *hostname, char *domain,
                                     char *guid, char *sid, char *name,
                                     uint32_t ntver, struct berval *reply)
{
    struct NETLOGON_SAM_LOGON_RESPONSE_EX *nlr;
    enum ndr_err_code ndr_err;
    DATA_BLOB blob;
    char *pdc_name;
    char *p;
    int ret;

    nlr = talloc_zero(NULL, struct NETLOGON_SAM_LOGON_RESPONSE_EX);
    if (!nlr) {
        return ENOMEM;
    }

    if (!(ntver & NETLOGON_NT_VERSION_5EX)) {
        ret = EINVAL;
        goto done;
    }

    nlr->command = LOGON_SAM_LOGON_RESPONSE_EX;
    /* nlr->sbz */
    nlr->server_type = DS_SERVER_PDC |
                        DS_SERVER_GC |
                        DS_SERVER_LDAP |
                        DS_SERVER_DS |
                        DS_SERVER_KDC |
                        DS_SERVER_TIMESERV |
                        DS_SERVER_CLOSEST |
                        DS_SERVER_WRITABLE |
                        DS_SERVER_GOOD_TIMESERV;
    string_to_guid(guid, &nlr->domain_uuid);
    nlr->forest = domain;
    nlr->dns_domain = domain;
    nlr->pdc_dns_name = talloc_asprintf(nlr, "%s.%s", hostname, domain);
    if (!nlr->pdc_dns_name) {
        ret = ENOMEM;
        goto done;
    }
    nlr->domain_name = name;
    pdc_name = talloc_asprintf(nlr, "\\\\%s", hostname);
    for (p = pdc_name; *p; p++) {
        *p = toupper(*p);
    }
    nlr->pdc_name = pdc_name;
    nlr->user_name = "";
    nlr->server_site = "Default-First-Site-Name";
    nlr->client_site = "Default-First-Site-Name";
    /* nlr->sockaddr_size (filled in by ndr_push) */
    nlr->sockaddr.sockaddr_family = 2;
    nlr->sockaddr.pdc_ip = "127.0.0.1";
    nlr->sockaddr.remaining.length = 8;
    nlr->sockaddr.remaining.data = talloc_zero_size(nlr, 8);
    /* nlr->next_closest_site */
    nlr->nt_version = NETLOGON_NT_VERSION_5EX|NETLOGON_NT_VERSION_1;
    nlr->lmnt_token = 0xFFFF;
    nlr->lm20_token = 0xFFFF;

    ndr_err = ndr_push_struct_blob(&blob, nlr, nlr,
                                   NETLOGON_SAM_LOGON_RESPONSE_EX_pusher);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        ret = EFAULT;
        goto done;
    }

    reply->bv_val = malloc(blob.length);
    if (!reply->bv_val) {
        ret = ENOMEM;
        goto done;
    }
    memcpy(reply->bv_val, blob.data, blob.length);
    reply->bv_len = blob.length;
    ret = 0;

done:
    talloc_free(nlr);
    return ret;
}

int ipa_cldap_netlogon(struct ipa_cldap_ctx *ctx,
                       struct ipa_cldap_req *req,
                       struct berval *reply)
{
    char hostname[MAXHOSTNAMELEN + 1]; /* NOTE: lenght hardcoded in kernel */
    char domname[MAXHOSTNAMELEN + 1]; /* NOTE: lenght hardcoded in kernel */
    char *domain = NULL;
    char *guid = NULL;
    char *sid = NULL;
    char *name = NULL;
    uint32_t ntver = 0;
    uint32_t t;
    char *p;
    int ret;
    int len;
    int i;

    /* determine request type */

    for (i = 0; i < req->kvps.top; i++) {
        if (strncasecmp("DnsDomain",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            /* remove trailing dot if any */
            len = req->kvps.pairs[i].value.bv_len;
            if (req->kvps.pairs[i].value.bv_val[len-1] == '.') {
                len--;
            }
            domain = strndup(req->kvps.pairs[i].value.bv_val, len);
            if (!domain) {
                ret = ENOMEM;
                goto done;
            }
            continue;
        }
        if (strncasecmp("Host",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            /* we ignore Host for now */
            continue;
        }
        if (strncasecmp("DomainGUID",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            /* we ignore DomainGUID for now */
            continue;
        }
        if (strncasecmp("DomainSID",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            /* we ignore DomainSID for now */
            continue;
        }
        if (strncasecmp("User",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            /* we ignore User for now */
            continue;
        }
        if (strncasecmp("AAC",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            /* we ignore AAC for now */
            continue;
        }
        if (strncasecmp("NTver",
                        req->kvps.pairs[i].attr.bv_val,
                        req->kvps.pairs[i].attr.bv_len) == 0) {
            if (req->kvps.pairs[i].value.bv_len != 4) {
                ret = EINVAL;
                goto done;
            }
            memcpy(&t, req->kvps.pairs[i].value.bv_val, 4);
            ntver = le32toh(t);
            continue;
        }
        LOG_TRACE("Unknown filter attribute: %s\n",
                  req->kvps.pairs[i].attr.bv_val);
    }

    if (!ntver) {
        ret = EINVAL;
        goto done;
    }

    /* If no domain is provide the client is asking for our own domain,
     * read our own domain name from the system */
    if (!domain) {
        ret = getdomainname(domname, MAXHOSTNAMELEN);
        if (ret == -1) {
            ret = errno;
            goto done;
        }
        domname[MAXHOSTNAMELEN] = '\0';
        p = strchr(hostname, '.');
        if (p) {
            domain = strdup(p + 1);
            if (!domain) {
                ret = ENOMEM;
                goto done;
            }
        }
    }

    /* FIXME: we support only NETLOGON_NT_VERSION_5EX for now */
    if (!(ntver & NETLOGON_NT_VERSION_5EX)) {
        ret = EINVAL;
        goto done;
    }

    ret = ipa_cldap_get_domain_entry(ctx, domain, &guid, &sid, &name);
    if (ret) {
        goto done;
    }

    ret = gethostname(hostname, MAXHOSTNAMELEN);
    if (ret == -1) {
        ret = errno;
        goto done;
    }
    hostname[MAXHOSTNAMELEN] = '\0';
    p = strchr(hostname, '.');
    if (p) {
        *p = '\0';
    }

    ret = ipa_cldap_encode_netlogon(hostname, domain,
                                    guid, sid, name,
                                    ntver, reply);

done:
    free(domain);
    free(guid);
    free(sid);
    free(name);
    return ret;
}
