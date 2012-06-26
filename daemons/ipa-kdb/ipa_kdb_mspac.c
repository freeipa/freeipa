/*
 * MIT Kerberos KDC database backend for FreeIPA
 *
 * Authors: Simo Sorce <ssorce@redhat.com>
 *
 * Copyright (C) 2011  Simo Sorce, Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software you can redistribute it and/or modify
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
 */

#include "ipa_kdb.h"
#include <talloc.h>
#include <syslog.h>
#include "util/time.h"
#include "gen_ndr/ndr_krb5pac.h"


int krb5_klog_syslog(int, const char *, ...);

static char *user_pac_attrs[] = {
    "objectClass",
    "uid",
    "cn",
    "gidNumber",
    "krbPrincipalName",
    "krbCanonicalName",
    "krbTicketPolicyReference",
    "krbPrincipalExpiration",
    "krbPasswordExpiration",
    "krbPwdPolicyReference",
    "krbPrincipalType",
    "krbLastPwdChange",
    "krbPrincipalAliases",
    "krbLastSuccessfulAuth",
    "krbLastFailedAuth",
    "krbLoginFailedCount",
    "krbLastAdminUnlock",
    "krbTicketFlags",
    "ipaNTSecurityIdentifier",
    "ipaNTLogonScript",
    "ipaNTProfilePath",
    "ipaNTHomeDirectory",
    "ipaNTHomeDirectoryDrive",
    NULL
};

char *deref_search_attrs[] = {
    "memberOf",
    NULL
};

static char *memberof_pac_attrs[] = {
    "gidNumber",
    "ipaNTSecurityIdentifier",
    NULL
};

#define SID_ID_AUTHS 6
#define SID_SUB_AUTHS 15
#define MAX(a,b) (((a)>(b))?(a):(b))

static int string_to_sid(char *str, struct dom_sid *sid)
{
    unsigned long val;
    char *s, *t;
    int i;

    memset(sid, '\0', sizeof(struct dom_sid));

    s = str;

    if (strncasecmp(s, "S-", 2) != 0) {
        return EINVAL;
    }
    s += 2;

    val = strtoul(s, &t, 10);
    if (s == t || !t || *t != '-') {
        return EINVAL;
    }
    s = t + 1;
    sid->sid_rev_num = val;

    val = strtoul(s, &t, 10);
    if (s == t || !t) {
        return EINVAL;
    }
    sid->id_auth[2] = (val & 0xff000000) >> 24;
    sid->id_auth[3] = (val & 0x00ff0000) >> 16;
    sid->id_auth[4] = (val & 0x0000ff00) >> 8;
    sid->id_auth[5] = (val & 0x000000ff);

    for (i = 0; i < SID_SUB_AUTHS; i++) {
        switch (*t) {
        case '\0':
            /* no (more) subauths, we are done with it */
            sid->num_auths = i;
            return 0;
        case '-':
            /* there are (more) subauths */
            s = t + 1;;
            break;
        default:
            /* garbage */
            return EINVAL;
        }

        val = strtoul(s, &t, 10);
        if (s == t || !t) {
            return EINVAL;
        }
        sid->sub_auths[i] = val;
    }

    if (*t != '\0') {
        return EINVAL;
    }

    sid->num_auths = i;
    return 0;
}

static char *dom_sid_string(TALLOC_CTX *memctx, const struct dom_sid *dom_sid)
{
    size_t c;
    size_t len;
    int ofs;
    uint32_t ia;
    char *buf;

    if (dom_sid == NULL) {
        return NULL;
    }

    len = 25 + dom_sid->num_auths * 11;

    buf = talloc_zero_size(memctx, len);

    ia = (dom_sid->id_auth[5]) +
         (dom_sid->id_auth[4] << 8 ) +
         (dom_sid->id_auth[3] << 16) +
         (dom_sid->id_auth[2] << 24);

    ofs = snprintf(buf, len, "S-%u-%lu", (unsigned int) dom_sid->sid_rev_num,
                                            (unsigned long) ia);

    for (c = 0; c < dom_sid->num_auths; c++) {
        ofs += snprintf(buf + ofs, MAX(len - ofs, 0), "-%lu",
                                        (unsigned long) dom_sid->sub_auths[c]);
    }

    if (ofs >= len) {
        talloc_free(buf);
        return NULL;
    }

    return buf;
}

static struct dom_sid *dom_sid_dup(TALLOC_CTX *memctx,
                                   const struct dom_sid *dom_sid)
{
    struct dom_sid *new_sid;
    size_t c;

    if (dom_sid == NULL) {
        return NULL;
    }

    new_sid = talloc(memctx, struct dom_sid);
    if (new_sid == NULL) {
        return NULL;
    }

    new_sid->sid_rev_num = dom_sid->sid_rev_num;
    for (c = 0; c < SID_ID_AUTHS; c++) {
        new_sid->id_auth[c] = dom_sid->id_auth[c];
    }
    new_sid->num_auths = dom_sid->num_auths;
    for (c = 0; c < SID_SUB_AUTHS; c++) {
        new_sid->sub_auths[c] = dom_sid->sub_auths[c];
    }

    return new_sid;
}

static int sid_append_rid(struct dom_sid *sid, uint32_t rid)
{
    if (sid->num_auths >= SID_SUB_AUTHS) {
        return EINVAL;
    }

    sid->sub_auths[sid->num_auths++] = rid;
    return 0;
}

/**
* @brief Takes a user sid and removes the rid.
*        The sid is changed by this function,
*        the removed rid is returned too.
*
* @param sid    A user/group SID
* @param rid    The actual RID found.
*
* @return 0 on success, EINVAL otherwise.
*/
static int sid_split_rid(struct dom_sid *sid, uint32_t *rid)
{
    if (sid->num_auths == 0) {
        return EINVAL;
    }

    sid->num_auths--;
    if (rid != NULL) {
        *rid = sid->sub_auths[sid->num_auths];
    }
    sid->sub_auths[sid->num_auths] = 0;

    return 0;
}

static krb5_error_code ipadb_fill_info3(struct ipadb_context *ipactx,
                                        LDAPMessage *lentry,
                                        TALLOC_CTX *memctx,
                                        struct netr_SamInfo3 *info3)
{
    LDAP *lcontext = ipactx->lcontext;
    LDAPDerefRes *deref_results = NULL;
    struct dom_sid sid;
    gid_t prigid = -1;
    time_t timeres;
    char *strres;
    int intres;
    int ret;

    ret = ipadb_ldap_attr_to_int(lcontext, lentry, "gidNumber", &intres);
    if (ret) {
        /* gidNumber is mandatory */
        return ret;
    }
    prigid = intres;


    info3->base.logon_time = 0; /* do not have this info yet */
    info3->base.logoff_time = -1; /* do not force logoff */

/* TODO: is krbPrinciplaExpiration what we want to use in kickoff_time ?
 * Needs more investigation */
#if 0
    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbPrincipalExpiration", &timeres);
    switch (ret) {
    case 0:
        unix_to_nt_time(&info3->base.acct_expiry, timeres);
        break;
    case ENOENT:
        info3->base.acct_expiry = -1;
        break;
    default:
        return ret;
    }
#else
    info3->base.kickoff_time = -1;
#endif

    ret = ipadb_ldap_attr_to_time_t(lcontext, lentry,
                                    "krbLastPwdChange", &timeres);
    switch (ret) {
    case 0:
        unix_to_nt_time(&info3->base.last_password_change, timeres);
        break;
    case ENOENT:
        info3->base.last_password_change = 0;
        break;
    default:
        return ret;
    }

    /* TODO: from pw policy (ied->pol) */
    info3->base.allow_password_change = 0;
    info3->base.force_password_change = -1;

    /* FIXME: handle computer accounts they do not use 'uid' */
    ret = ipadb_ldap_attr_to_str(lcontext, lentry, "uid", &strres);
    if (ret) {
        /* uid is mandatory */
        return ret;
    }
    info3->base.account_name.string = talloc_strdup(memctx, strres);
    free(strres);

    ret = ipadb_ldap_attr_to_str(lcontext, lentry, "cn", &strres);
    switch (ret) {
    case 0:
        info3->base.full_name.string = talloc_strdup(memctx, strres);
        free(strres);
        break;
    case ENOENT:
        info3->base.full_name.string = "";
        break;
    default:
        return ret;
    }

    ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                 "ipaNTLogonScript", &strres);
    switch (ret) {
    case 0:
        info3->base.logon_script.string = talloc_strdup(memctx, strres);
        free(strres);
        break;
    case ENOENT:
        info3->base.logon_script.string = "";
        break;
    default:
        return ret;
    }

    ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                 "ipaNTProfilePath", &strres);
    switch (ret) {
    case 0:
        info3->base.profile_path.string = talloc_strdup(memctx, strres);
        free(strres);
        break;
    case ENOENT:
        info3->base.profile_path.string = "";
        break;
    default:
        return ret;
    }

    ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                 "ipaNTHomeDirectory", &strres);
    switch (ret) {
    case 0:
        info3->base.home_directory.string = talloc_strdup(memctx, strres);
        free(strres);
        break;
    case ENOENT:
        info3->base.home_directory.string = "";
        break;
    default:
        return ret;
    }

    ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                 "ipaNTHomeDirectoryDrive", &strres);
    switch (ret) {
    case 0:
        info3->base.home_drive.string = talloc_strdup(memctx, strres);
        free(strres);
        break;
    case ENOENT:
        info3->base.home_drive.string = "";
        break;
    default:
        return ret;
    }

    info3->base.logon_count = 0; /* we do not have this info yet */
    info3->base.bad_password_count = 0; /* we do not have this info yet */

    ret = ipadb_ldap_attr_to_str(lcontext, lentry,
                                 "ipaNTSecurityIdentifier", &strres);
    if (ret) {
        /* SID is mandatory */
        return ret;
    }
    ret = string_to_sid(strres, &sid);
    free(strres);
    if (ret) {
        return ret;
    }

    ret = sid_split_rid(&sid, &info3->base.rid);
    if (ret) {
        return ret;
    }

    ret = ipadb_ldap_deref_results(lcontext, lentry, &deref_results);
    switch (ret) {
    LDAPDerefRes *dres;
    LDAPDerefVal *dval;
    struct dom_sid gsid;
    uint32_t trid;
    gid_t tgid;
    char *s;
    int count;
    case 0:
        count = 0;
        for (dres = deref_results; dres; dres = dres->next) {
            count++; /* count*/
        }
        info3->base.groups.rids = talloc_array(memctx,
                                        struct samr_RidWithAttribute, count);
        if (!info3->base.groups.rids) {
            ldap_derefresponse_free(deref_results);
            return ENOMEM;
        }

        count = 0;
        info3->base.primary_gid = 0;
        for (dres = deref_results; dres; dres = dres->next) {
            gsid.sid_rev_num = 0;
            tgid = 0;
            for (dval = dres->attrVals; dval; dval = dval->next) {
                if (strcasecmp(dval->type, "gidNumber") == 0) {
                    tgid = strtoul((char *)dval->vals[0].bv_val, &s, 10);
                    if (tgid == 0) {
                        continue;
                    }
                }
                if (strcasecmp(dval->type, "ipaNTSecurityIdentifier") == 0) {
                    ret = string_to_sid((char *)dval->vals[0].bv_val, &gsid);
                    if (ret) {
                        continue;
                    }
                }
            }
            if (tgid && gsid.sid_rev_num) {
                ret = sid_split_rid(&gsid, &trid);
                if (ret) {
                    continue;
                }
                if (tgid == prigid) {
                    info3->base.primary_gid = trid;
                    continue;
                }
                info3->base.groups.rids[count].rid = trid;
                info3->base.groups.rids[count].attributes =
                                            SE_GROUP_ENABLED |
                                            SE_GROUP_MANDATORY |
                                            SE_GROUP_ENABLED_BY_DEFAULT;
                count++;
            }
        }
        info3->base.groups.count = count;

        ldap_derefresponse_free(deref_results);
        break;
    case ENOENT:
        info3->base.groups.count = 0;
        info3->base.groups.rids = NULL;
        break;
    default:
        return ret;
    }

    if (info3->base.primary_gid == 0) {
        if (ipactx->wc.fallback_rid) {
            info3->base.primary_gid = ipactx->wc.fallback_rid;
        } else {
            /* can't give a pack without a primary group rid */
            return ENOENT;
        }
    }

    /* always zero out, only valid flags are for extra sids with Krb */
    info3->base.user_flags = 0; /* netr_UserFlags */

    /* always zero out, not used for Krb, only NTLM */
    memset(&info3->base.key, '\0', sizeof(info3->base.key));

    if (ipactx->wc.flat_server_name) {
        info3->base.logon_server.string =
                    talloc_strdup(memctx, ipactx->wc.flat_server_name);
        if (!info3->base.logon_server.string) {
            return ENOMEM;
        }
    } else {
        /* can't give a pack without Server NetBIOS Name :-| */
        return ENOENT;
    }

    if (ipactx->wc.flat_domain_name) {
        info3->base.logon_domain.string =
                    talloc_strdup(memctx, ipactx->wc.flat_domain_name);
        if (!info3->base.logon_domain.string) {
            return ENOMEM;
        }
    } else {
        /* can't give a pack without Domain NetBIOS Name :-| */
        return ENOENT;
    }

    /* we got the domain SID for the user sid */
    info3->base.domain_sid = talloc_memdup(memctx, &sid, sizeof(sid));

    /* always zero out, not used for Krb, only NTLM */
    memset(&info3->base.LMSessKey, '\0', sizeof(info3->base.key));

    /* TODO: fill based on objectclass, user vs computer, etc... */
    info3->base.acct_flags = ACB_NORMAL; /* samr_AcctFlags */

    info3->base.sub_auth_status = 0;
    info3->base.last_successful_logon = 0;
    info3->base.last_failed_logon = 0;
    info3->base.failed_logon_count = 0; /* We do not have it */
    info3->base.reserved = 0; /* Reserved */

    return 0;
}

static krb5_error_code ipadb_get_pac(krb5_context kcontext,
                                     krb5_db_entry *client,
                                     krb5_pac *pac)
{
    TALLOC_CTX *tmpctx;
    struct ipadb_e_data *ied;
    struct ipadb_context *ipactx;
    LDAPMessage *results = NULL;
    LDAPMessage *lentry;
    DATA_BLOB pac_data;
    krb5_data data;
    union PAC_INFO pac_info;
    krb5_error_code kerr;
    enum ndr_err_code ndr_err;

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    ied = (struct ipadb_e_data *)client->e_data;
    if (ied->magic != IPA_E_DATA_MAGIC) {
        return EINVAL;
    }

    if (!ied->ipa_user) {
        return 0;
    }

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    memset(&pac_info, 0, sizeof(pac_info));
    pac_info.logon_info.info = talloc_zero(tmpctx, struct PAC_LOGON_INFO);
    if (!pac_info.logon_info.info) {
        kerr = ENOMEM;
        goto done;
    }


    /* == Search PAC info == */
    kerr = ipadb_deref_search(ipactx, ied->entry_dn, LDAP_SCOPE_BASE,
                              "(objectclass=*)", user_pac_attrs,
                              deref_search_attrs, memberof_pac_attrs,
                              &results);
    if (kerr) {
        goto done;
    }

    lentry = ldap_first_entry(ipactx->lcontext, results);
    if (!lentry) {
        kerr = ENOENT;
        goto done;
    }

    /* == Fill Info3 == */
    kerr = ipadb_fill_info3(ipactx, lentry, tmpctx,
                            &pac_info.logon_info.info->info3);
    if (kerr) {
        goto done;
    }

    /* == Package PAC == */
    ndr_err = ndr_push_union_blob(&pac_data, tmpctx, &pac_info,
                                  PAC_TYPE_LOGON_INFO,
                                  (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    kerr = krb5_pac_init(kcontext, pac);
    if (kerr) {
        goto done;
    }

    data.magic = KV5M_DATA;
    data.data = (char *)pac_data.data;
    data.length = pac_data.length;

    kerr = krb5_pac_add_buffer(kcontext, *pac, KRB5_PAC_LOGON_INFO, &data);

done:
    ldap_msgfree(results);
    talloc_free(tmpctx);
    return kerr;
}

static bool is_cross_realm_krbtgt(krb5_const_principal princ)
{
    if ((princ->length != 2) ||
        (princ->data[0].length != 6) ||
        (strncasecmp(princ->data[0].data, "krbtgt", 6) != 0)) {
        return false;
    }
    if (princ->data[1].length == princ->realm.length &&
        strncasecmp(princ->data[1].data,
                    princ->realm.data, princ->realm.length) == 0) {
        return false;
    }

    return true;
}

static char *gen_sid_string(TALLOC_CTX *memctx, struct dom_sid *dom_sid,
                            uint32_t rid)
{
    char *str = NULL;
    int ret;

    ret = sid_append_rid(dom_sid, rid);
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "sid_append_rid failed");
        return NULL;
    }

    str = dom_sid_string(memctx, dom_sid);
    ret = sid_split_rid(dom_sid, NULL);
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "sid_split_rid failed");
        talloc_free(str);
        return NULL;
    }

    return str;
}

static int get_group_sids(TALLOC_CTX *memctx,
                          struct PAC_LOGON_INFO_CTR *logon_info,
                          char ***_group_sids)
{
    int ret;
    size_t c;
    size_t p = 0;
    struct dom_sid *domain_sid = NULL;
    char **group_sids = NULL;

    domain_sid = dom_sid_dup(memctx, logon_info->info->info3.base.domain_sid);
    if (domain_sid == NULL) {
        krb5_klog_syslog(LOG_ERR, "dom_sid_dup failed");
        ret = ENOMEM;
        goto done;
    }

    group_sids = talloc_array(memctx, char *,
                                     2 +
                                     logon_info->info->info3.base.groups.count +
                                     logon_info->info->info3.sidcount);
    if (group_sids == NULL) {
        krb5_klog_syslog(LOG_ERR, "talloc_array failed");
        ret = ENOMEM;
        goto done;
    }

    group_sids[p] = gen_sid_string(memctx, domain_sid,
                                  logon_info->info->info3.base.primary_gid);
    if (group_sids[p] == NULL) {
        krb5_klog_syslog(LOG_ERR, "gen_sid_string failed");
        ret = EINVAL;
        goto done;
    }
    p++;

    for (c = 0; c < logon_info->info->info3.base.groups.count; c++) {
        group_sids[p] = gen_sid_string(memctx, domain_sid,
                               logon_info->info->info3.base.groups.rids[c].rid);
        if (group_sids[p] == NULL) {
        krb5_klog_syslog(LOG_ERR, "gen_sid_string 2 failed");
            ret = EINVAL;
            goto done;
        }
        p++;
    }
    for (c = 0; c < logon_info->info->info3.sidcount; c++) {
        group_sids[p] = dom_sid_string(memctx,
                                       logon_info->info->info3.sids[c].sid);
        if (group_sids[p] == NULL) {
        krb5_klog_syslog(LOG_ERR, "dom_sid_string failed");
            ret = EINVAL;
            goto done;
        }
        p++;
    }

    group_sids[p] = NULL;

    *_group_sids = group_sids;

    ret = 0;
done:
    talloc_free(domain_sid);
    if (ret != 0) {
        talloc_free(group_sids);
    }

    return ret;
}

static int add_groups(TALLOC_CTX *memctx,
                      struct PAC_LOGON_INFO_CTR *logon_info,
                      size_t ipa_group_sids_count,
                      struct dom_sid2 *ipa_group_sids)
{
    size_t c;
    struct netr_SidAttr *sids = NULL;

    if (ipa_group_sids_count == 0) {
        return 0;
    }

    sids = talloc_realloc(memctx, logon_info->info->info3.sids,
                       struct netr_SidAttr,
                       logon_info->info->info3.sidcount + ipa_group_sids_count);
    if (sids == NULL) {
        return ENOMEM;
    }


    for (c = 0; c < ipa_group_sids_count; c++) {
        sids[c + logon_info->info->info3.sidcount].sid = &ipa_group_sids[c];
        sids[c + logon_info->info->info3.sidcount].attributes =
                                                    SE_GROUP_ENABLED |
                                                    SE_GROUP_MANDATORY |
                                                    SE_GROUP_ENABLED_BY_DEFAULT;
    }

    logon_info->info->info3.sidcount += ipa_group_sids_count;
    logon_info->info->info3.sids = sids;


    return 0;
}

static int map_groups(TALLOC_CTX *memctx, krb5_context kcontext,
                      char **group_sids, size_t *_ipa_group_sids_count,
                      struct dom_sid **_ipa_group_sids)
{
    struct ipadb_context *ipactx;
    krb5_error_code kerr;
    int ret;
    LDAPMessage *results = NULL;
    LDAPMessage *lentry;
    char *basedn = NULL;
    char *filter = NULL;
    LDAPDerefRes *deref_results = NULL;
    LDAPDerefRes *dres;
    LDAPDerefVal *dval;
    size_t c;
    size_t count = 0;
    size_t sid_index = 0;
    struct dom_sid *sids = NULL;
    char *entry_attrs[] ={"1.1", NULL};
    unsigned long gid;
    struct dom_sid sid;
    char *endptr;

    ipactx = ipadb_get_context(kcontext);
    if (ipactx == NULL) {
        return KRB5_KDB_DBNOTINITED;
    }

    basedn = talloc_asprintf(memctx, "cn=groups,cn=accounts,%s", ipactx->base);
    if (basedn == NULL) {
        krb5_klog_syslog(LOG_ERR, "talloc_asprintf failed.");
        kerr = ENOMEM;
        goto done;
    }

    for (c = 0; group_sids[c] != NULL; c++) {
        talloc_free(filter);
        filter = talloc_asprintf(memctx, "(&(objectclass=ipaExternalGroup)(ipaExternalMember=%s))",
                                 group_sids[c]);
        if (filter == NULL) {
            krb5_klog_syslog(LOG_ERR, "talloc_asprintf failed.");
            kerr = ENOMEM;
            goto done;
        }

        kerr = ipadb_deref_search(ipactx, basedn, LDAP_SCOPE_ONE, filter,
                                  entry_attrs, deref_search_attrs,
                                  memberof_pac_attrs, &results);
        if (kerr != 0) {
            krb5_klog_syslog(LOG_ERR, "ipadb_deref_search failed.");
            goto done;
        }

        lentry = ldap_first_entry(ipactx->lcontext, results);
        if (lentry == NULL) {
            continue;
        }

        ldap_derefresponse_free(deref_results);
        ret = ipadb_ldap_deref_results(ipactx->lcontext, lentry, &deref_results);
        switch (ret) {
            case ENOENT:
                /* No entry found, try next SID */
                break;
            case 0:
                if (deref_results == NULL) {
                    krb5_klog_syslog(LOG_ERR, "No results.");
                    break;
                }

                for (dres = deref_results; dres; dres = dres->next) {
                    count++;
                }

                sids = talloc_realloc(memctx, sids, struct dom_sid, count);
                if (sids == NULL) {
                    krb5_klog_syslog(LOG_ERR, "talloc_realloc failed.");
                    kerr = ENOMEM;
                    goto done;
                }

                for (dres = deref_results; dres; dres = dres->next) {
                    gid = 0;
                    memset(&sid, '\0', sizeof(struct dom_sid));
                    for (dval = dres->attrVals; dval; dval = dval->next) {
                        if (strcasecmp(dval->type, "gidNumber") == 0) {
                            errno = 0;
                            gid = strtoul((char *)dval->vals[0].bv_val,
                                          &endptr,10);
                            if (gid == 0 || gid >= UINT32_MAX || errno != 0 ||
                                *endptr != '\0') {
                                continue;
                            }
                        }
                        if (strcasecmp(dval->type,
                                       "ipaNTSecurityIdentifier") == 0) {
                            kerr = string_to_sid((char *)dval->vals[0].bv_val, &sid);
                            if (kerr != 0) {
                                continue;
                            }
                        }
                    }
                    if (gid != 0 && sid.sid_rev_num != 0) {
                    /* TODO: check if gid maps to sid */
                        if (sid_index >= count) {
                            krb5_klog_syslog(LOG_ERR, "Index larger than "
                                                      "array, this shoould "
                                                      "never happen.");
                            kerr = EFAULT;
                            goto done;
                        }
                        memcpy(&sids[sid_index], &sid, sizeof(struct dom_sid));
                        sid_index++;
                    }
                }

                break;
            default:
                goto done;
        }
    }

    *_ipa_group_sids_count = sid_index;
    *_ipa_group_sids = sids;

    kerr = 0;

done:
    ldap_derefresponse_free(deref_results);
    talloc_free(basedn);
    talloc_free(filter);
    ldap_msgfree(results);
    return kerr;
}

static krb5_error_code filter_pac(krb5_context context, krb5_data *old_data,
                                  krb5_data *new_data)
{
    DATA_BLOB pac_data;
    union PAC_INFO pac_info;
    krb5_error_code kerr;
    enum ndr_err_code ndr_err;
    TALLOC_CTX *tmpctx;
    int ret;
    char **group_sids = NULL;
    size_t ipa_group_sids_count = 0;
    struct dom_sid *ipa_group_sids = NULL;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    pac_data.length = old_data->length;
    pac_data.data = (uint8_t *) old_data->data;

    ndr_err = ndr_pull_union_blob(&pac_data, tmpctx, &pac_info,
                                  PAC_TYPE_LOGON_INFO,
                                  (ndr_pull_flags_fn_t) ndr_pull_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        krb5_klog_syslog(LOG_ERR, "ndr_pull_union_blob failed");
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = get_group_sids(tmpctx, &pac_info.logon_info, &group_sids);
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "get_group_sids failed");
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = map_groups(tmpctx, context, group_sids, &ipa_group_sids_count,
                     &ipa_group_sids);
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "map_groups failed");
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ret = add_groups(tmpctx, &pac_info.logon_info, ipa_group_sids_count,
                     ipa_group_sids);
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "add_groups failed");
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    ndr_err = ndr_push_union_blob(&pac_data, tmpctx, &pac_info,
                                  PAC_TYPE_LOGON_INFO,
                                  (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        krb5_klog_syslog(LOG_ERR, "ndr_push_union_blob failed");
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    new_data->magic = KV5M_DATA;
    new_data->data = malloc(pac_data.length);
    if (new_data->data == NULL) {
        kerr = ENOMEM;
        goto done;
    }
    memcpy(new_data->data, pac_data.data, pac_data.length);
    new_data->length = pac_data.length;

    kerr = 0;

done:
    talloc_free(tmpctx);

    return kerr;
}

static krb5_error_code ipadb_verify_pac(krb5_context context,
                                        unsigned int flags,
                                        krb5_const_principal client_princ,
                                        krb5_db_entry *server,
                                        krb5_db_entry *krbtgt,
                                        krb5_keyblock *server_key,
                                        krb5_keyblock *krbtgt_key,
                                        krb5_timestamp authtime,
                                        krb5_authdata **authdata,
                                        krb5_pac *pac)
{
    krb5_keyblock *srv_key = NULL;
    krb5_keyblock *priv_key = NULL;
    krb5_error_code kerr;
    krb5_ui_4 *buffer_types = NULL;
    size_t num_buffers;
    krb5_pac old_pac = NULL;
    krb5_pac new_pac = NULL;
    krb5_data data;
    krb5_data filtered_data;
    size_t i;

    kerr = krb5_pac_parse(context,
                          authdata[0]->contents,
                          authdata[0]->length,
                          &old_pac);
    if (kerr) {
        goto done;
    }

    memset(&filtered_data, 0, sizeof(filtered_data));
    /* for cross realm trusts cases we need to check the right checksum.
     * when the PAC is signed by our realm, we can always just check it
     * passing our realm krbtgt key as the kdc checksum key (privsvr).
     * But when a trusted realm passes us a PAC the kdc checksum is
     * generated with that realm krbtgt key, so we need to use the cross
     * realm krbtgt to check the 'server' checksum instead. */
    if (is_cross_realm_krbtgt(krbtgt->princ)) {
        /* krbtgt from a trusted realm */

        /* FIXME:
         * We must refuse a PAC that comes signed with a cross realm TGT
         * where the client pretends to be from our realm. It is an attempt
         * at getting us to sign fake credentials with the help of a
         * compromised trusted realm */

        /* TODO: Here is where we need to plug our PAC Filtering, later on */
        srv_key = krbtgt_key;

        kerr = krb5_pac_get_buffer(context, old_pac, KRB5_PAC_LOGON_INFO, &data);
        if (kerr != 0) {
            goto done;
        }

        kerr = filter_pac(context, &data, &filtered_data);
        if (kerr != 0) {
            goto done;
        }
    } else {
        /* krbtgt from our own realm */
        priv_key = krbtgt_key;
    }

    kerr = krb5_pac_verify(context, old_pac, authtime,
                            client_princ, srv_key, priv_key);
    if (kerr) {
        goto done;
    }

    /* extract buffers and rebuilt pac from scratch so that when re-signing
     * with a different cksum type does not cause issues due to mismatching
     * signature buffer lengths */
    kerr = krb5_pac_init(context, &new_pac);
    if (kerr) {
        goto done;
    }

    kerr = krb5_pac_get_types(context, old_pac, &num_buffers, &buffer_types);
    if (kerr) {
        goto done;
    }

    for (i = 0; i < num_buffers; i++) {
        if (buffer_types[i] == KRB5_PAC_SERVER_CHECKSUM ||
            buffer_types[i] == KRB5_PAC_PRIVSVR_CHECKSUM) {
            continue;
        }

        if (buffer_types[i] == KRB5_PAC_LOGON_INFO &&
            filtered_data.length != 0) {
            kerr = krb5_pac_add_buffer(context, new_pac,
                                       buffer_types[i], &filtered_data);
            krb5_free_data_contents(context, &filtered_data);
            if (kerr) {
                krb5_pac_free(context, new_pac);
                goto done;
            }

            continue;
        }

        kerr = krb5_pac_get_buffer(context, old_pac,
                                    buffer_types[i], &data);
        if (kerr == 0) {
            kerr = krb5_pac_add_buffer(context, new_pac,
                                        buffer_types[i], &data);
        }
        krb5_free_data_contents(context, &data);
        if (kerr) {
            krb5_pac_free(context, new_pac);
            goto done;
        }
    }

    *pac = new_pac;

done:
    krb5_free_authdata(context, authdata);
    krb5_pac_free(context, old_pac);
    free(buffer_types);
    return kerr;
}

static krb5_error_code ipadb_sign_pac(krb5_context context,
                                      krb5_const_principal client_princ,
                                      krb5_db_entry *server,
                                      krb5_db_entry *krbtgt,
                                      krb5_keyblock *server_key,
                                      krb5_keyblock *krbtgt_key,
                                      krb5_timestamp authtime,
                                      krb5_pac pac,
                                      krb5_data *pac_data)
{
    krb5_keyblock *right_krbtgt_signing_key = NULL;
    krb5_key_data *right_krbtgt_key;
    krb5_db_entry *right_krbtgt = NULL;
    krb5_principal krbtgt_princ = NULL;
    krb5_error_code kerr;
    char *princ = NULL;
    int ret;

    /* for cross realm trusts cases we need to sign with the right key.
     * we need to fetch the right key on our own until the DAL is fixed
     * to pass us separate check tgt keys and sign tgt keys */

    /* We can only ever create the kdc checksum with our realm tgt key.
     * So, if we get a cross realm tgt we have to fetch our realm tgt
     * instead. */
    if (is_cross_realm_krbtgt(krbtgt->princ)) {

        ret = asprintf(&princ, "krbtgt/%.*s@%.*s",
                       server->princ->realm.length,
                       server->princ->realm.data,
                       server->princ->realm.length,
                       server->princ->realm.data);
        if (ret == -1) {
            princ = NULL;
            kerr = ENOMEM;
            goto done;
        }

        kerr = krb5_parse_name(context, princ, &krbtgt_princ);
        if (kerr) {
            goto done;
        }

        kerr = ipadb_get_principal(context, krbtgt_princ, 0, &right_krbtgt);
        if (kerr) {
            goto done;
        }

        kerr = krb5_dbe_find_enctype(context, right_krbtgt,
                                     -1, -1, 0, &right_krbtgt_key);
        if (kerr) {
            goto done;
        }
        if (!right_krbtgt_key) {
            kerr = KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN;
            goto done;
        }

        right_krbtgt_signing_key = malloc(sizeof(krb5_keyblock));
        if (!right_krbtgt_signing_key) {
            kerr = ENOMEM;
            goto done;
        }

        kerr = krb5_dbe_decrypt_key_data(context, NULL, right_krbtgt_key,
                                         right_krbtgt_signing_key, NULL);
        if (kerr) {
            goto done;
        }

    } else {
        right_krbtgt_signing_key = krbtgt_key;
    }

    kerr = krb5_pac_sign(context, pac, authtime, client_princ,
                         server_key, right_krbtgt_signing_key, pac_data);

done:
    free(princ);
    krb5_free_principal(context, krbtgt_princ);
    ipadb_free_principal(context, right_krbtgt);
    if (right_krbtgt_signing_key != krbtgt_key) {
        krb5_free_keyblock(context, right_krbtgt_signing_key);
    }
    return kerr;
}

krb5_error_code ipadb_sign_authdata(krb5_context context,
                                    unsigned int flags,
                                    krb5_const_principal client_princ,
                                    krb5_db_entry *client,
                                    krb5_db_entry *server,
                                    krb5_db_entry *krbtgt,
                                    krb5_keyblock *client_key,
                                    krb5_keyblock *server_key,
                                    krb5_keyblock *krbtgt_key,
                                    krb5_keyblock *session_key,
                                    krb5_timestamp authtime,
                                    krb5_authdata **tgt_auth_data,
                                    krb5_authdata ***signed_auth_data)
{
    krb5_const_principal ks_client_princ;
    krb5_authdata **pac_auth_data = NULL;
    krb5_authdata *authdata[2] = { NULL, NULL };
    krb5_authdata ad;
    krb5_boolean is_as_req;
    krb5_error_code kerr;
    krb5_pac pac = NULL;
    krb5_data pac_data;

    /* When using s4u2proxy client_princ actually refers to the proxied user
     * while client->princ to the proxy service asking for the TGS on behalf
     * of the proxied user. So always use client_princ in preference */
    if (client_princ != NULL) {
        ks_client_princ = client_princ;
    } else {
        ks_client_princ = client->princ;
    }

    is_as_req = ((flags & KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY) != 0);

    if (is_as_req && (flags & KRB5_KDB_FLAG_INCLUDE_PAC)) {

        kerr = ipadb_get_pac(context, client, &pac);
        if (kerr != 0 && kerr != ENOENT) {
            goto done;
        }
    }

    if (!is_as_req) {
        /* find the existing PAC, if present */
        kerr = krb5_find_authdata(context, tgt_auth_data, NULL,
                                  KRB5_AUTHDATA_WIN2K_PAC, &pac_auth_data);
        if (kerr != 0) {
            goto done;
        }
        /* check or generate pac data */
        if ((pac_auth_data == NULL) || (pac_auth_data[0] == NULL)) {
            if (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) {
                kerr = ipadb_get_pac(context, client, &pac);
                if (kerr != 0 && kerr != ENOENT) {
                    goto done;
                }
            }
        } else {
            if (pac_auth_data[1] != NULL) {
                kerr = KRB5KDC_ERR_BADOPTION; /* FIXME: right error ? */
                goto done;
            }

            kerr = ipadb_verify_pac(context, flags, ks_client_princ,
                                    server, krbtgt, server_key, krbtgt_key,
                                    authtime, pac_auth_data, &pac);
            if (kerr != 0) {
                goto done;
            }
        }
    }

    if (pac == NULL) {
        /* No PAC to deal with, proceed */
        *signed_auth_data = NULL;
        kerr = 0;
        goto done;
    }

    kerr = ipadb_sign_pac(context, ks_client_princ, server, krbtgt,
                          server_key, krbtgt_key, authtime, pac, &pac_data);
    if (kerr != 0) {
        goto done;
    }

    /* put in signed data */
    ad.magic = KV5M_AUTHDATA;
    ad.ad_type = KRB5_AUTHDATA_WIN2K_PAC;
    ad.contents = (krb5_octet *)pac_data.data;
    ad.length = pac_data.length;
    authdata[0] = &ad;

    kerr = krb5_encode_authdata_container(context,
                                          KRB5_AUTHDATA_IF_RELEVANT,
                                          authdata,
                                          signed_auth_data);
    if (kerr != 0) {
        goto done;
    }

    kerr = 0;

done:
    krb5_pac_free(context, pac);
    return kerr;
}

static char *get_server_netbios_name(void)
{
    char hostname[MAXHOSTNAMELEN + 1]; /* NOTE: this is 64, too little ? */
    char *p;
    int ret;

    ret = gethostname(hostname, MAXHOSTNAMELEN);
    if (ret) {
        return NULL;
    }
    /* May miss termination */
    hostname[MAXHOSTNAMELEN] = '\0';
    for (p = hostname; *p; p++) {
        if (*p == '.') {
            *p = 0;
            break;
        } else {
            *p = toupper(*p);
        }
    }

    return strdup(hostname);
}

krb5_error_code ipadb_reinit_mspac(struct ipadb_context *ipactx)
{
    char *dom_attrs[] = { "ipaNTFlatName",
                          "ipaNTFallbackPrimaryGroup",
                          NULL };
    char *grp_attrs[] = { "ipaNTSecurityIdentifier", NULL };
    krb5_error_code kerr;
    LDAPMessage *result = NULL;
    LDAPMessage *lentry;
    struct dom_sid gsid;
    char *resstr;
    int ret;

    /* clean up in case we had old values around */
    free(ipactx->wc.flat_domain_name);
    ipactx->wc.flat_domain_name = NULL;
    free(ipactx->wc.fallback_group);
    ipactx->wc.fallback_group = NULL;
    ipactx->wc.fallback_rid = 0;

    kerr = ipadb_simple_search(ipactx, ipactx->base, LDAP_SCOPE_SUBTREE,
                               "(objectclass=ipaNTDomainAttrs)", dom_attrs,
                                &result);
    if (kerr == KRB5_KDB_NOENTRY) {
        return ENOENT;
    } else if (kerr != 0) {
        return EIO;
    }

    lentry = ldap_first_entry(ipactx->lcontext, result);
    if (!lentry) {
        kerr = ENOENT;
        goto done;
    }

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTFlatName",
                                 &ipactx->wc.flat_domain_name);
    if (ret) {
        kerr = ret;
        goto done;
    }

    free(ipactx->wc.flat_server_name);
    ipactx->wc.flat_server_name = get_server_netbios_name();
    if (!ipactx->wc.flat_server_name) {
        kerr = ENOMEM;
        goto done;
    }

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTFallbackPrimaryGroup",
                                 &ipactx->wc.fallback_group);
    if (ret && ret != ENOENT) {
        kerr = ret;
        goto done;
    }

    /* result and lentry not valid any more from here on */
    ldap_msgfree(result);
    result = NULL;
    lentry = NULL;

    if (ret != ENOENT) {
        kerr = ipadb_simple_search(ipactx, ipactx->wc.fallback_group,
                                   LDAP_SCOPE_BASE,
                                   "(objectclass=posixGroup)",
                                   grp_attrs, &result);
        if (kerr && kerr != KRB5_KDB_NOENTRY) {
            kerr = ret;
            goto done;
        }

        lentry = ldap_first_entry(ipactx->lcontext, result);
        if (!lentry) {
            kerr = ENOENT;
            goto done;
        }

        if (kerr == 0) {
            ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                         "ipaNTSecurityIdentifier",
                                         &resstr);
            if (ret && ret != ENOENT) {
                kerr = ret;
                goto done;
            }
            if (ret == 0) {
                ret = string_to_sid(resstr, &gsid);
                if (ret) {
                    kerr = ret;
                    goto done;
                }
                ret = sid_split_rid(&gsid, &ipactx->wc.fallback_rid);
                if (ret) {
                    kerr = ret;
                    goto done;
                }
            }
        }
    }

    kerr = 0;

done:
    ldap_msgfree(result);
    return kerr;
}
