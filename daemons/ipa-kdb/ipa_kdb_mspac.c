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

#include "config.h"

#include "ipa_hostname.h"
#include "ipa_kdb.h"
#include "ipa_mspac.h"
#include <talloc.h>
#include <unicase.h>
#include "util/time.h"
#include "gen_ndr/ndr_krb5pac.h"

#include "ipa_kdb_mspac_private.h"

static char *user_pac_attrs[] = {
    "objectClass",
    "uid",
    "cn",
    "fqdn",
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
#define MIN(a,b) (((a)<(b))?(a):(b))

#define AUTHZ_DATA_TYPE_PAC "MS-PAC"
#define AUTHZ_DATA_TYPE_PAD "PAD"
#define AUTHZ_DATA_TYPE_NONE "NONE"

void alloc_sid(struct dom_sid **sid)
{
    *sid = malloc(sizeof(struct dom_sid));
}

void free_sid(struct dom_sid **sid)
{
    if (sid != NULL && *sid != NULL) {
        free(*sid);
        *sid = NULL;
    }
}

int ipadb_string_to_sid(const char *str, struct dom_sid *sid)
{
    unsigned long val;
    const char *s;
    char *t;
    int i;

    if (str == NULL) {
        return EINVAL;
    }

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

char *dom_sid_string(TALLOC_CTX *memctx, const struct dom_sid *dom_sid)
{
    int8_t c;
    size_t len;
    size_t ofs;
    uint32_t ia;
    char *buf;

    if (dom_sid == NULL
            || dom_sid->num_auths < 0
            || dom_sid->num_auths > SID_SUB_AUTHS) {
        return NULL;
    }

    len = 25 + dom_sid->num_auths * 11;

    buf = talloc_zero_size(memctx, len);
    if (buf == NULL) {
        return NULL;
    }

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

/* checks if sid1 is a domain of sid2 or compares them exactly if exact_check is true
 * returns
 *    true   -- if sid1 is a domain of sid2 (including full exact match)
 *    false  -- otherwise
 *
 * dom_sid_check() is supposed to be used with sid1 representing domain SID
 * and sid2 being either domain or resource SID in the domain
 */
bool dom_sid_check(const struct dom_sid *sid1, const struct dom_sid *sid2, bool exact_check)
{
    int c, num;

    if (sid1 == sid2) {
        return true;
    }

    if (sid1 == NULL) {
        return false;
    }

    if (sid2 == NULL) {
        return false;
    }

    /* If SIDs have different revisions, they are different */
    if (sid1->sid_rev_num != sid2->sid_rev_num)
        return false;

    /* When number of authorities is different, sids are different
     * if we were asked to check prefix exactly */
    num = sid2->num_auths - sid1->num_auths;
    if (num != 0) {
        if (exact_check) {
            return false;
        } else {
            /* otherwise we are dealing with prefix check
             * and sid2 should have RID compared to the sid1 */
            if (num != 1) {
                return false;
            }
        }
    }

    /* now either sid1->num_auths == sid2->num_auths or sid1 has no RID */

    /* for same size authorities compare them backwards
     * since RIDs are likely different */
    for (c = sid1->num_auths; c >= 0; --c)
        if (sid1->sub_auths[c] != sid2->sub_auths[c])
            return false;

    /* Finally, compare Identifier authorities */
    for (c = 0; c < SID_ID_AUTHS; c++)
        if (sid1->id_auth[c] != sid2->id_auth[c])
            return false;

    return true;
}

static bool dom_sid_is_prefix(const struct dom_sid *sid1, const struct dom_sid *sid2)
{
    int c;

    if (sid1 == sid2) {
        return true;
    }

    if (sid1 == NULL) {
        return false;
    }

    if (sid2 == NULL) {
        return false;
    }

    /* If SIDs have different revisions, they are different */
    if (sid1->sid_rev_num != sid2->sid_rev_num)
        return false;

    if (sid1->num_auths > sid2->num_auths)
        return false;

    /* now sid1->num_auths <= sid2->num_auths */

    /* compare up to sid1->num_auth authorities since RIDs are
     * likely different and we are searching for the prefix */
    for (c = 0; c < sid1->num_auths; c++)
        if (sid1->sub_auths[c] != sid2->sub_auths[c])
            return false;

    /* Finally, compare Identifier authorities */
    for (c = 0; c < SID_ID_AUTHS; c++)
        if (sid1->id_auth[c] != sid2->id_auth[c])
            return false;

    return true;
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

/* Add Asserted Identity SID */
static krb5_error_code ipadb_add_asserted_identity(struct ipadb_context *ipactx,
                                                   unsigned int flags,
                                                   TALLOC_CTX *memctx,
                                                   struct netr_SamInfo3 *info3)
{
    struct netr_SidAttr *arr = NULL;
    uint32_t sidcount = info3->sidcount;
    krb5_error_code ret = 0;

    arr = talloc_realloc(memctx,
                         info3->sids,
                         struct netr_SidAttr,
                         sidcount + 1);
    if (!arr) {
        return ENOMEM;
    }
    arr[sidcount].sid = talloc_zero(arr, struct dom_sid2);
    if (!arr[sidcount].sid) {
        return ENOMEM;
    }

    /* For S4U2Self, add Service Asserted Identity SID
     * otherwise, add Authentication Authority Asserted Identity SID */
    ret = ipadb_string_to_sid((flags & KRB5_KDB_FLAG_PROTOCOL_TRANSITION) ?
                        "S-1-18-2" : "S-1-18-1",
                        arr[sidcount].sid);
    if (ret) {
        return ret;
    }
    arr[sidcount].attributes = SE_GROUP_MANDATORY |
                               SE_GROUP_ENABLED |
                               SE_GROUP_ENABLED_BY_DEFAULT;
    info3->sids = arr;
    info3->sidcount = sidcount + 1;
    info3->base.user_flags |= NETLOGON_EXTRA_SIDS;

    return 0;
}

static krb5_error_code
is_master_host(struct ipadb_context *ipactx, const char *fqdn, bool *result)
{
    int err;
    char *master_host_base = NULL;
    LDAPMessage *ldap_res = NULL;

    err = asprintf(&master_host_base, "cn=%s,cn=masters,cn=ipa,cn=etc,%s",
                                      fqdn, ipactx->base);
    if (err == -1)
        return ENOMEM;

    err = ipadb_simple_search(ipactx, master_host_base, LDAP_SCOPE_BASE,
                              NULL, NULL, &ldap_res);
    free(master_host_base);
    ldap_msgfree(ldap_res);
    if (err != KRB5_KDB_NOENTRY && err != 0)
        return err;

    if (result)
        *result = err != KRB5_KDB_NOENTRY;

    return 0;
}

static krb5_error_code ipadb_fill_info3(struct ipadb_context *ipactx,
                                        LDAPMessage *lentry,
                                        LDAPMessage *sentry,
                                        unsigned int flags,
                                        TALLOC_CTX *memctx,
                                        krb5_timestamp authtime,
                                        struct netr_SamInfo3 *info3)
{
    LDAPDerefRes *deref_results = NULL;
    struct dom_sid sid;
    gid_t prigid = -1;
    time_t timeres;
    char *strres;
    int intres;
    int ret;
    char **objectclasses = NULL;
    size_t c;
    bool is_host = false;
    bool is_user = false;
    bool is_service = false;
    bool is_ipauser = false;
    bool is_idobject = false;
    krb5_principal princ;

    ret = ipadb_ldap_attr_to_strlist(ipactx->lcontext, lentry, "objectClass",
                                     &objectclasses);
    if (ret == 0 && objectclasses != NULL) {
        for (c = 0; objectclasses[c] != NULL; c++) {
            if (strcasecmp(objectclasses[c], "ipaHost") == 0) {
                is_host = true;
            }
            if (strcasecmp(objectclasses[c], "ipaService") == 0) {
                is_service = true;
            }
            if (strcasecmp(objectclasses[c], "ipaNTUserAttrs") == 0) {
                is_user = true;
            }
            if (strcasecmp(objectclasses[c], "ipaIDObject") == 0) {
                is_idobject = true;
            }
            if (strcasecmp(objectclasses[c], "ipaUser") == 0) {
                is_ipauser = true;
            }
            free(objectclasses[c]);
        }
    }
    free(objectclasses);

    /* SMB service on IPA domain member will have both ipaIDOjbect and ipaUser
     * object classes. Such service will have to be treated as a user in order
     * to issue MS-PAC record for it. */
    if (is_idobject && is_ipauser) {
        is_user = true;
    }

    if (!is_host && !is_user && !is_service) {
        /* We only handle users and hosts, and services */
        return ENOENT;
    }

    if (is_host) {
        ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry, "fqdn", &strres);
        if (ret) {
            /* fqdn is mandatory for hosts */
            return ret;
        }
    } else if (is_service) {
        ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                     "krbCanonicalName", &strres);
        if (ret) {
            /* krbCanonicalName is mandatory for services but IPA services
             * created before commit e6ff83e (FreeIPA 4.4.0, ~2016) had no
             * normalization to set krbCanonicalName; services created after
             * that version were upgraded to do have krbCanonicalName.
             *
             * Accept krbPrincipalName alone since they have no alias either */
            ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                         "krbPrincipalName", &strres);
            if (ret)
                return ret;
        }

        ret = krb5_parse_name(ipactx->kcontext, strres, &princ);

        free(strres);
        if (ret) {
            return ENOENT;
        }

        ret = krb5_unparse_name_flags(ipactx->kcontext,
                                      princ, KRB5_PRINCIPAL_UNPARSE_SHORT,
                                      &strres);
        if (ret) {
            return ENOENT;
        }
    } else {
        ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry, "uid", &strres);
        if (ret) {
            /* uid is mandatory */
            return ret;
        }
    }

    info3->base.account_name.string = talloc_strdup(memctx, strres);
    free(strres);

    if (is_host || is_service) {
        prigid = 515; /* Well known RID for domain computers group */
    } else {
        ret = ipadb_ldap_attr_to_int(ipactx->lcontext, lentry,
                                     "gidNumber", &intres);
        if (ret) {
            /* gidNumber is mandatory */
            return ret;
        }
        prigid = intres;
    }

    /* krb5_timestamp must be converted to uint32_t to allow 64-bit time_t
     * to handle time beyond year 2038. See <krb5.h> for details */
    unix_to_nt_time(&info3->base.logon_time, (time_t)(uint32_t) authtime);

    info3->base.logoff_time = INT64_MAX; /* do not force logoff */

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
    info3->base.kickoff_time = INT64_MAX;
#endif

    ret = ipadb_ldap_attr_to_time_t(ipactx->lcontext, lentry,
                                    "krbLastPwdChange", &timeres);
    switch (ret) {
    case 0:
        unix_to_nt_time(&info3->base.last_password_change, timeres);
        break;
    case ENOENT:
        /* If second entry is present, use Kerberos attributes from it */
        if (sentry != NULL) {
            ret = ipadb_ldap_attr_to_time_t(ipactx->lcontext, sentry,
                                            "krbLastPwdChange", &timeres);
            switch (ret) {
            case 0:
                unix_to_nt_time(&info3->base.last_password_change, timeres);
                break;
            default:
            break;
            }
        } else {
            info3->base.last_password_change = 0;
        }
        break;
    default:
        return ret;
    }

    /* TODO: from pw policy (ied->pol) */
    /* AD DCs set allow_password_change to last_password_change, it seems */
    info3->base.allow_password_change = info3->base.last_password_change;
    info3->base.force_password_change = INT64_MAX;

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry, "cn", &strres);
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

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
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

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
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

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
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

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
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

    /* Use AES keys by default to detect changes.
     * This bit is not used by Windows clients and servers so we can
     * clear it after detecting the changes */
    info3->base.acct_flags = ACB_USE_AES_KEYS;

    ret = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTSecurityIdentifier", &strres);
    if (ret) {
        /* SID is mandatory for all but host/services */
        if (!(is_host || is_service)) {
            return ret;
        }
        info3->base.rid = 0;
    } else {
        ret = ipadb_string_to_sid(strres, &sid);
        free(strres);
        if (ret) {
            return ret;
        }
        ret = sid_split_rid(&sid, &info3->base.rid);
        if (ret) {
            return ret;
        }
    }

    /* If SID was present prefer using it even for hosts and services
     * but we still need to set the account flags correctly */
    if ((is_host || is_service)) {
        /* it is either host or service, so get the hostname first */
        char *sep = strchr(info3->base.account_name.string, '/');
        bool is_master;

        ret = is_master_host(ipactx,
                             sep ? sep + 1 : info3->base.account_name.string,
                             &is_master);
        if (ret)
            return ret;

        if (is_master) {
            /* Well known RID of domain controllers group */
            if (info3->base.rid == 0) {
                info3->base.rid = 516;
            }
            info3->base.acct_flags |= ACB_SVRTRUST;
        } else {
            /* Well known RID of domain computers group */
            if (info3->base.rid == 0) {
                info3->base.rid = 515;
            }
            info3->base.acct_flags |= ACB_WSTRUST;
        }
    }

    ret = ipadb_ldap_deref_results(ipactx->lcontext, lentry, &deref_results);
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
                    ret = ipadb_string_to_sid((char *)dval->vals[0].bv_val, &gsid);
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

    if (!ipactx->mspac) {
        /* can't give a PAC without server NetBIOS name or primary group RID */
        return ENOENT;
    }

    if (info3->base.primary_gid == 0) {
        if (is_host || is_service) {
            info3->base.primary_gid = 515;  /* Well known RID for domain computers group */
        } else {
            info3->base.primary_gid = ipactx->mspac->fallback_rid;
        }
    }

    /* always zero out, only valid flags are for extra sids with Krb */
    info3->base.user_flags = 0; /* netr_UserFlags */

    /* always zero out, not used for Krb, only NTLM */
    memset(&info3->base.key, '\0', sizeof(info3->base.key));

    info3->base.logon_server.string =
        talloc_strdup(memctx, ipactx->mspac->flat_server_name);
    if (!info3->base.logon_server.string) {
        return ENOMEM;
    }

    info3->base.logon_domain.string =
        talloc_strdup(memctx, ipactx->mspac->flat_domain_name);
    if (!info3->base.logon_domain.string) {
        return ENOMEM;
    }

    if (is_host || is_service) {
        info3->base.domain_sid = talloc_memdup(memctx, &ipactx->mspac->domsid,
                                               sizeof(ipactx->mspac->domsid));
    } else {
        /* we got the domain SID for the user sid */
        info3->base.domain_sid = talloc_memdup(memctx, &sid, sizeof(sid));
    }

    /* always zero out, not used for Krb, only NTLM */
    memset(&info3->base.LMSessKey, '\0', sizeof(info3->base.LMSessKey));

    /* If account type was not set before, default to ACB_NORMAL */
    if (!(info3->base.acct_flags & ~ACB_USE_AES_KEYS)) {
        info3->base.acct_flags |= ACB_NORMAL; /* samr_AcctFlags */
    }

    /* Clear ACB_USE_AES_KEYS as it is not used by Windows */
    info3->base.acct_flags &= ~ACB_USE_AES_KEYS;
    info3->base.sub_auth_status = 0;
    info3->base.last_successful_logon = 0;
    info3->base.last_failed_logon = 0;
    info3->base.failed_logon_count = 0; /* We do not have it */
    info3->base.reserved = 0; /* Reserved */

    ret = ipadb_add_asserted_identity(ipactx, flags, memctx, info3);
    return ret;
}

#ifdef HAVE_PAC_REQUESTER_SID
static krb5_error_code ipadb_get_requester_sid(krb5_context context,
                                               krb5_pac pac,
                                               struct dom_sid *sid)
{
    enum ndr_err_code ndr_err;
    krb5_error_code ret;
    DATA_BLOB pac_requester_sid_in;
    krb5_data k5pac_requester_sid_in;
    union PAC_INFO info;
    TALLOC_CTX *tmp_ctx;
    struct ipadb_context *ipactx;

    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_REQUESTER_SID,
                              &k5pac_requester_sid_in);
    if (ret != 0) {
        talloc_free(tmp_ctx);
        return ret;
    }

    pac_requester_sid_in = data_blob_const(k5pac_requester_sid_in.data,
                                           k5pac_requester_sid_in.length);

    ndr_err = ndr_pull_union_blob(&pac_requester_sid_in, tmp_ctx, &info,
                                  PAC_TYPE_REQUESTER_SID,
                                  (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
    krb5_free_data_contents(context, &k5pac_requester_sid_in);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
            talloc_free(tmp_ctx);
            return EINVAL;
    }

    *sid = info.requester_sid.sid;

    talloc_free(tmp_ctx);
    return 0;
}
#endif

static krb5_error_code ipadb_get_sid_from_pac(TALLOC_CTX *ctx,
                                              struct PAC_LOGON_INFO *info,
                                              struct dom_sid *sid)
{
    struct dom_sid *client_sid = NULL;
    /* Construct SID from the PAC */
    if (info->info3.base.rid == 0) {
        client_sid = info->info3.sids[0].sid;
    } else {
        client_sid = dom_sid_dup(ctx, info->info3.base.domain_sid);
        if (!client_sid) {
            return ENOMEM;
        }
        sid_append_rid(client_sid, info->info3.base.rid);
    }
    *sid = *client_sid;
    return 0;
}

#ifdef HAVE_PAC_ATTRIBUTES_INFO
static krb5_error_code ipadb_client_requested_pac(krb5_context context,
                                                  krb5_pac pac,
                                                  TALLOC_CTX *mem_ctx,
                                                  krb5_boolean *requested_pac)
{
    enum ndr_err_code ndr_err;
    krb5_data k5pac_attrs_in;
    DATA_BLOB pac_attrs_in;
    union PAC_INFO pac_attrs;
    krb5_error_code ret;

    *requested_pac = true;

    ret = krb5_pac_get_buffer(context, pac, PAC_TYPE_ATTRIBUTES_INFO,
                                &k5pac_attrs_in);
    if (ret != 0) {
            return ret == ENOENT ? 0 : ret;
    }

    pac_attrs_in = data_blob_const(k5pac_attrs_in.data,
                                   k5pac_attrs_in.length);

    ndr_err = ndr_pull_union_blob(&pac_attrs_in, mem_ctx, &pac_attrs,
                                  PAC_TYPE_ATTRIBUTES_INFO,
                                  (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
    krb5_free_data_contents(context, &k5pac_attrs_in);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
            NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
            krb5_klog_syslog(LOG_ERR, "can't parse the PAC ATTRIBUTES_INFO: %s\n",
                                        nt_errstr(nt_status));
            return KRB5_KDB_INTERNAL_ERROR;
    }

    if (pac_attrs.attributes_info.flags & (PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY
                                           | PAC_ATTRIBUTE_FLAG_PAC_WAS_REQUESTED)) {
            *requested_pac = true;
    } else {
            *requested_pac = false;
    }

    return 0;
}

static krb5_error_code ipadb_get_pac_attrs_blob(TALLOC_CTX *mem_ctx,
                                                const krb5_boolean *pac_request,
                                                DATA_BLOB *pac_attrs_data)
{
    union PAC_INFO pac_attrs;
    enum ndr_err_code ndr_err;

    memset(&pac_attrs, 0, sizeof(pac_attrs));

    *pac_attrs_data = data_blob_null;

    /* Set the length of the flags in bits. */
    pac_attrs.attributes_info.flags_length = 2;

    if (pac_request == NULL) {
            pac_attrs.attributes_info.flags
                    |= PAC_ATTRIBUTE_FLAG_PAC_WAS_GIVEN_IMPLICITLY;
    } else if (*pac_request) {
            pac_attrs.attributes_info.flags
                    |= PAC_ATTRIBUTE_FLAG_PAC_WAS_REQUESTED;
    }

    ndr_err = ndr_push_union_blob(pac_attrs_data, mem_ctx, &pac_attrs,
                                    PAC_TYPE_ATTRIBUTES_INFO,
                                    (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
            NTSTATUS nt_status = ndr_map_error2ntstatus(ndr_err);
            krb5_klog_syslog(LOG_ERR, "can't create PAC ATTRIBUTES_INFO: %s\n",
                            nt_errstr(nt_status));
            return KRB5_KDB_INTERNAL_ERROR;
    }

    return 0;
}

#endif

krb5_error_code ipadb_get_pac(krb5_context kcontext,
                              unsigned int flags,
                              krb5_db_entry *client,
                              krb5_db_entry *server,
                              krb5_keyblock *replaced_reply_key,
                              krb5_timestamp authtime,
                              krb5_pac *pac)
{
    TALLOC_CTX *tmpctx;
    struct ipadb_e_data *ied;
    struct ipadb_context *ipactx;
    LDAPMessage *results = NULL, *sresults = NULL;
    LDAPMessage *lentry = NULL, *sentry = NULL;
    DATA_BLOB pac_data;
    krb5_data data;
    union PAC_INFO pac_info;
    krb5_error_code kerr;
    enum ndr_err_code ndr_err;
    union PAC_INFO pac_upn;
    char *principal = NULL;
    struct dom_sid client_sid;

    /* When no client entry is there, we cannot generate MS-PAC */
    if (!client) {
        *pac = NULL;
        return 0;
    }

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        return KRB5_KDB_DBNOTINITED;
    }

    /* Check if PAC generator is initialized */
    if (!ipactx->mspac) {
        return ENOENT;
    }

    ied = (struct ipadb_e_data *)client->e_data;
    if (ied->magic != IPA_E_DATA_MAGIC) {
        return EINVAL;
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

    /* PAC_LOGON_NAME and PAC_TYPE_UPN_DNS_INFO are automatically added
     * by krb5_pac_sign() later on */

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

    {
        bool is_trust_krbtgt;

        /* Trusted domain objects are part of cn=ad,cn=trusts,$BASEDN subtree.
         * Anchor the search string with ',dc=' to prevent matching anything else.
         * This is to avoid a string allocation with expanded base DN. */
        is_trust_krbtgt = strstr(ied->entry_dn, ",cn=ad,cn=trusts,dc=") != NULL;

        if (is_trust_krbtgt) {
            char *sentry_dn = strchr(ied->entry_dn, ',');
            if (sentry_dn != NULL) {
                /* skipped "krbprincipalname=krbtgt/SOME-REALM@AT-REALM," */
                sentry_dn++;
                kerr = ipadb_deref_search(ipactx, sentry_dn, LDAP_SCOPE_BASE,
                                        "(objectclass=*)", user_pac_attrs,
                                        deref_search_attrs, memberof_pac_attrs,
                                        &sresults);
                if (kerr) {
                    goto done;
                }

                sentry = ldap_first_entry(ipactx->lcontext, sresults);
                if (!sentry) {
                    kerr = ENOENT;
                    goto done;
                }

            }
        }
    }

    /* == Fill Info3 == */
    kerr = ipadb_fill_info3(ipactx, sentry ? sentry : lentry, sentry ? lentry : NULL,
                            flags, tmpctx, authtime, &pac_info.logon_info.info->info3);
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

    /* krb5 1.20+ passes in a pre-created PAC structure but for previous
     * versions we have to create it ourselves */
    if (pac != NULL && *pac == NULL) {
        kerr = krb5_pac_init(kcontext, pac);
        if (kerr) {
            goto done;
        }
    }

    data.magic = KV5M_DATA;
    data.data = (char *)pac_data.data;
    data.length = pac_data.length;

    kerr = krb5_pac_add_buffer(kcontext, *pac, KRB5_PAC_LOGON_INFO, &data);

    /* == Package UPN_DNS_LOGON_INFO == */
    memset(&pac_upn, 0, sizeof(pac_upn));
    kerr = krb5_unparse_name(kcontext, client->princ, &principal);
    if (kerr) {
        goto done;
    }

    pac_upn.upn_dns_info.upn_name = talloc_strdup(tmpctx, principal);
    krb5_free_unparsed_name(kcontext, principal);
    if (pac_upn.upn_dns_info.upn_name == NULL) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    pac_upn.upn_dns_info.dns_domain_name = talloc_strdup(tmpctx, ipactx->realm);
    if (pac_upn.upn_dns_info.dns_domain_name == NULL) {
            kerr = KRB5_KDB_INTERNAL_ERROR;
            goto done;
    }

    /* IPA user principals are all constructed */
    if ((pac_info.logon_info.info->info3.base.rid != 515) &&
        (pac_info.logon_info.info->info3.base.rid != 516)) {
        pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_CONSTRUCTED;
    }

    kerr = ipadb_get_sid_from_pac(tmpctx, pac_info.logon_info.info, &client_sid);
    if (kerr) {
        goto done;
    }

#ifdef HAVE_PAC_UPN_DNS_INFO_EX
    /* Add samAccountName and a SID */
    pac_upn.upn_dns_info.flags |= PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID;
    pac_upn.upn_dns_info.ex.sam_name_and_sid.samaccountname = pac_info.logon_info.info->info3.base.account_name.string;
    pac_upn.upn_dns_info.ex.sam_name_and_sid.objectsid = &client_sid;
#endif

    ndr_err = ndr_push_union_blob(&pac_data, tmpctx, &pac_upn,
                                  PAC_TYPE_UPN_DNS_INFO,
                                  (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        kerr = KRB5_KDB_INTERNAL_ERROR;
        goto done;
    }

    data.magic = KV5M_DATA;
    data.data = (char *)pac_data.data;
    data.length = pac_data.length;

    kerr = krb5_pac_add_buffer(kcontext, *pac, KRB5_PAC_UPN_DNS_INFO, &data);

#ifdef HAVE_PAC_ATTRIBUTES_INFO
    /* == Add implicit PAC type attributes info as we always try to generate PAC == */
    {
        DATA_BLOB pac_attrs_data;

        kerr = ipadb_get_pac_attrs_blob(tmpctx, NULL, &pac_attrs_data);
        if (kerr) {
            goto done;
        }
        data.magic = KV5M_DATA;
        data.data = (char *)pac_attrs_data.data;
        data.length = pac_attrs_data.length;

        kerr = krb5_pac_add_buffer(kcontext, *pac, PAC_TYPE_ATTRIBUTES_INFO, &data);
        if (kerr) {
            goto done;
        }
    }
#endif

#ifdef HAVE_PAC_REQUESTER_SID
    /* MS-KILE 3.3.5.6.4.8: add PAC_REQUESTER_SID only in TGT case */
    if (flags & CLIENT_REFERRALS_FLAGS) {
        union PAC_INFO pac_requester_sid;
        /* == Package PAC_REQUESTER_SID == */
        memset(&pac_requester_sid, 0, sizeof(pac_requester_sid));

        pac_requester_sid.requester_sid.sid = client_sid;

        ndr_err = ndr_push_union_blob(&pac_data, tmpctx, &pac_requester_sid,
                                    PAC_TYPE_REQUESTER_SID,
                                    (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
        if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
            kerr = KRB5_KDB_INTERNAL_ERROR;
            goto done;
        }

        data.magic = KV5M_DATA;
        data.data = (char *)pac_data.data;
        data.length = pac_data.length;

        kerr = krb5_pac_add_buffer(kcontext, *pac, PAC_TYPE_REQUESTER_SID, &data);
        if (kerr) {
            goto done;
        }
    }
#endif

done:
    ldap_msgfree(results);
    if (sresults != NULL) {
        ldap_msgfree(sresults);
    }
    talloc_free(tmpctx);
    return kerr;
}

bool ipadb_is_cross_realm_krbtgt(krb5_const_principal princ)
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

static int get_user_and_group_sids(TALLOC_CTX *memctx,
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
                                     3 +
                                     logon_info->info->info3.base.groups.count +
                                     logon_info->info->info3.sidcount);
    if (group_sids == NULL) {
        krb5_klog_syslog(LOG_ERR, "talloc_array failed");
        ret = ENOMEM;
        goto done;
    }

    group_sids[p] = gen_sid_string(memctx, domain_sid,
                                  logon_info->info->info3.base.rid);
    if (group_sids[p] == NULL) {
        krb5_klog_syslog(LOG_ERR, "gen_sid_string failed");
        ret = EINVAL;
        goto done;
    }
    p++;

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

        ldap_msgfree(results);
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

        do {
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
                                kerr = ipadb_string_to_sid((char *)dval->vals[0].bv_val, &sid);
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

            lentry = ldap_next_entry(ipactx->lcontext, lentry);
        } while (lentry != NULL);
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

static krb5_error_code get_logon_info(krb5_context context,
                                      TALLOC_CTX *memctx,
                                      krb5_data *pac_blob,
                                      struct PAC_LOGON_INFO_CTR *info)
{
    DATA_BLOB pac_data;
    enum ndr_err_code ndr_err;

    pac_data.length = pac_blob->length;
    pac_data.data = (uint8_t *)pac_blob->data;

    ndr_err = ndr_pull_union_blob(&pac_data, memctx, info,
                                  PAC_TYPE_LOGON_INFO,
                                  (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    return 0;
}

static krb5_error_code add_local_groups(krb5_context context,
                                        TALLOC_CTX *memctx,
                                        struct PAC_LOGON_INFO_CTR *info)
{
    int ret;
    char **group_sids = NULL;
    size_t ipa_group_sids_count = 0;
    struct dom_sid *ipa_group_sids = NULL;

    ret = get_user_and_group_sids(memctx, info, &group_sids);
    if (ret != 0) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    ret = map_groups(memctx, context, group_sids, &ipa_group_sids_count,
                     &ipa_group_sids);
    if (ret != 0) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    ret = add_groups(memctx, info, ipa_group_sids_count, ipa_group_sids);
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "add_groups failed");
        return KRB5_KDB_INTERNAL_ERROR;
    }

    return 0;
}

static krb5_error_code save_logon_info(krb5_context context,
                                       TALLOC_CTX *memctx,
                                       struct PAC_LOGON_INFO_CTR *info,
                                       krb5_data *pac_blob)
{
    DATA_BLOB pac_data;
    enum ndr_err_code ndr_err;

    ndr_err = ndr_push_union_blob(&pac_data, memctx, info,
                                  PAC_TYPE_LOGON_INFO,
                                  (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    free(pac_blob->data);
    pac_blob->data = malloc(pac_data.length);
    if (pac_blob->data == NULL) {
        pac_blob->length = 0;
        return ENOMEM;
    }
    memcpy(pac_blob->data, pac_data.data, pac_data.length);
    pac_blob->length = pac_data.length;

    return 0;
}

static struct ipadb_adtrusts *get_domain_from_realm(krb5_context context,
                                                    krb5_data *realm)
{
    struct ipadb_context *ipactx;
    struct ipadb_adtrusts *domain;
    size_t i;

    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        return NULL;
    }

    if (!ipactx->mspac) {
        return NULL;
    }

    for (i = 0; i < ipactx->mspac->num_trusts; i++) {
        domain = &ipactx->mspac->trusts[i];
        if (strlen(domain->domain_name) != realm->length) {
            continue;
        }
        if (strncasecmp(domain->domain_name, realm->data, realm->length) == 0) {
            return domain;
        }
    }

    return NULL;
}

static struct ipadb_adtrusts *get_domain_from_realm_update(krb5_context context,
                                                           krb5_data *realm)
{
    struct ipadb_context *ipactx;
    struct ipadb_adtrusts *domain;
    const char *stmsg = NULL;
    krb5_error_code kerr;

    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        return NULL;
    }

    /* re-init MS-PAC info using default update interval */
    kerr = ipadb_reinit_mspac(ipactx, false, &stmsg);
    if (kerr != 0) {
        if (stmsg)
            krb5_klog_syslog(LOG_WARNING, "MS-PAC generator: %s", stmsg);
        return NULL;
    }
    domain = get_domain_from_realm(context, realm);

    return domain;
}

static void filter_logon_info_log_message(struct dom_sid *sid)
{
    char *domstr = NULL;

    domstr = dom_sid_string(NULL, sid);
    if (domstr) {
        krb5_klog_syslog(LOG_ERR, "PAC filtering issue: SID [%s] is not allowed "
                                  "from a trusted source and will be excluded.", domstr);
        talloc_free(domstr);
    } else {
        krb5_klog_syslog(LOG_ERR, "PAC filtering issue: SID is not allowed "
                                  "from a trusted source and will be excluded."
                                  "Unable to allocate memory to display SID.");
    }
}

static void filter_logon_info_log_message_rid(struct dom_sid *sid, uint32_t rid)
{
    char *domstr = NULL;

    domstr = dom_sid_string(NULL, sid);
    if (domstr) {
        krb5_klog_syslog(LOG_ERR, "PAC filtering issue: SID [%s-%d] is not allowed "
                                  "from a trusted source and will be excluded.", domstr, rid);
        talloc_free(domstr);
    } else {
        krb5_klog_syslog(LOG_ERR, "PAC filtering issue: SID is not allowed "
                                  "from a trusted source and will be excluded."
                                  "Unable to allocate memory to display SID.");
    }
}

static krb5_error_code check_logon_info_consistent(krb5_context context,
                                                   TALLOC_CTX *memctx,
                                                   krb5_db_entry *client,
                                                   krb5_boolean is_s4u,
                                                   struct PAC_LOGON_INFO_CTR *info)
{
    krb5_error_code kerr = 0;
    struct ipadb_context *ipactx;
    bool result;
    bool is_from_trusted_domain = false;
    struct ipadb_e_data *ied = NULL;
    int flags = 0;
    struct dom_sid client_sid;
    const char *stmsg = NULL;
#ifdef KRB5_KDB_FLAG_ALIAS_OK
    flags = KRB5_KDB_FLAG_ALIAS_OK;
#endif

    ipactx = ipadb_get_context(context);
    if (!ipactx || !ipactx->mspac) {
        return KRB5_KDB_DBNOTINITED;
    }

    /* We are asked to verify the PAC for our own principal,
     * check that our own view on the PAC details is up to date */
    if (ipactx->mspac->domsid.num_auths == 0) {
        /* Force re-init of KDB's view on our domain */
        kerr = ipadb_reinit_mspac(ipactx, true, &stmsg);
        if (kerr != 0) {
            if (stmsg) {
                krb5_klog_syslog(LOG_ERR, "MS-PAC generator: %s", stmsg);
            } else {
                krb5_klog_syslog(LOG_ERR, "PAC issue: unable to update " \
                                 "realm's view on PAC info");
            }
            return KRB5KDC_ERR_POLICY;
        }
    }

    /* check exact domain SID */
    result = dom_sid_check(&ipactx->mspac->domsid,
                           info->info->info3.base.domain_sid, true);
    if (!result) {
        /* In S4U case we might be dealing with the PAC issued by the trusted domain */
        if (is_s4u && (ipactx->mspac->trusts != NULL)) {
            /* Iterate through list of trusts and check if this SID belongs to
             * one of the domains we trust */
            for(size_t i = 0 ; i < ipactx->mspac->num_trusts ; i++) {
                result = dom_sid_check(&ipactx->mspac->trusts[i].domsid,
                                       info->info->info3.base.domain_sid, true);
                if (result) {
                    is_from_trusted_domain = true;
                    break;
                }
            }
        }

        if (!result) {
            /* memctx is freed by the caller */
            char *sid = dom_sid_string(memctx, info->info->info3.base.domain_sid);
            char *dom = dom_sid_string(memctx, &ipactx->mspac->domsid);
            krb5_klog_syslog(LOG_ERR, "PAC issue: PAC record claims domain SID different "
                                      "to local domain SID or any trusted domain SID: "
                                      "local [%s], PAC [%s]",
                                      dom ? dom : "<failed to display>",
                                      sid ? sid : "<failed to display>");
            return KRB5KDC_ERR_TGT_REVOKED;
        }
    }

    if (client == NULL || (is_s4u && is_from_trusted_domain)) {
        /* If the PAC belongs to a user from the trusted domain, we cannot compare SIDs */
        return 0;
    }

    ied = (struct ipadb_e_data *)client->e_data;
    if (ied == NULL || ied->magic != IPA_E_DATA_MAGIC) {
        krb5_klog_syslog(LOG_ERR, "PAC issue: client e_data fetching failed.");
        kerr = EINVAL;
        goto done;
    }

    if (!ied->has_sid || ied->sid == NULL) {
        /* Kerberos principal might have no SID associated in the DB entry.
         * If this is host or service, we'll associate RID -515 or -516 in PAC
         * depending on whether this is a domain member or domain controller
         * but since this is not recorded in the DB entry, we the check for
         * SID is not needed */
        goto done;
    }


    kerr = ipadb_get_sid_from_pac(memctx, info->info, &client_sid);
    if (kerr) {
        goto done;
    }
    result = dom_sid_check(ied->sid, &client_sid, true);
    if (!result) {
        /* memctx is freed by the caller */
        char *local_sid = dom_sid_string(memctx, ied->sid);
        char *pac_sid = dom_sid_string(memctx, &client_sid);
        krb5_klog_syslog(LOG_ERR, "PAC issue: client principal has a SID "
                                  "different from what PAC claims. "
                                  "local [%s] vs PAC [%s]",
                                  local_sid ? local_sid : "<failed to display>",
                                  pac_sid ? pac_sid : "<failed to display>");
        kerr = KRB5KDC_ERR_TGT_REVOKED;
        goto done;
    }

done:
    return kerr;
}

krb5_error_code filter_logon_info(krb5_context context,
                                  TALLOC_CTX *memctx,
                                  krb5_data *realm,
                                  struct PAC_LOGON_INFO_CTR *info)
{

    /* We must refuse a PAC that comes signed with a cross realm TGT
     * where the client pretends to be from a different realm. It is an
     * attempt at getting us to sign fake credentials with the help of a
     * compromised trusted realm */

    /* NOTE: there are two outcomes from filtering:
     * REJECT TICKET -- ticket is rejected if domain SID of
     *                  the principal with MS-PAC is filtered out or
     *                  its primary group RID is filtered out
     *
     * REMOVE SID    -- SIDs are removed from the list of SIDs associated
     *                  with the principal if they are filtered out
     *                  This applies also to secondary RIDs of the principal
     *                  if domain_sid-<secondary RID> is filtered out
     */

    struct ipadb_context *ipactx;
    struct ipadb_adtrusts *domain;
    int i, j, k, l, count;
    uint32_t rid;
    bool result;
    char *domstr = NULL;

    ipactx = ipadb_get_context(context);
    if (!ipactx || !ipactx->mspac) {
        return KRB5_KDB_DBNOTINITED;
    }

    domain = get_domain_from_realm_update(context, realm);
    if (!domain) {
        return EINVAL;
    }

    /* check exact sid */
    result = dom_sid_check(&domain->domsid, info->info->info3.base.domain_sid, true);
    if (!result) {
        struct ipadb_mspac *mspac_ctx = ipactx->mspac;
        result = FALSE;
        /* Didn't match but perhaps the original PAC was issued by a child domain's DC? */
        for (size_t m = 0; m < mspac_ctx->num_trusts; m++) {
            result = dom_sid_check(&mspac_ctx->trusts[m].domsid,
                             info->info->info3.base.domain_sid, true);
            if (result) {
                domain = &mspac_ctx->trusts[m];
                break;
            }
        }
        if (!result) {
            domstr = dom_sid_string(NULL, info->info->info3.base.domain_sid);
            krb5_klog_syslog(LOG_ERR, "PAC Info mismatch: domain = %s, "
                                      "expected domain SID = %s, "
                                      "found domain SID = %s",
                                      domain->domain_name, domain->domain_sid,
                                      domstr ? domstr : "<failed to display>");
            talloc_free(domstr);
            return EINVAL;
        }
    }

    /* At this point we may have changed the domain we look at, */
    /* check netbios/flat name */
    if (strcasecmp(info->info->info3.base.logon_domain.string,
                   domain->flat_name) != 0) {
        krb5_klog_syslog(LOG_ERR, "PAC Info mismatch: domain = %s, "
                                  "expected flat name = %s, "
                                  "found logon name = %s",
                                  domain->domain_name, domain->flat_name,
                                  info->info->info3.base.logon_domain.string);
        return EINVAL;
    }

    /* Check if this domain has been filtered out by the trust itself*/
    if (domain->parent != NULL) {
        for(k = 0; k < domain->parent->len_sid_blocklist_incoming; k++) {
            result = dom_sid_check(info->info->info3.base.domain_sid,
                                   &domain->parent->sid_blocklist_incoming[k], true);
            if (result) {
                filter_logon_info_log_message(info->info->info3.base.domain_sid);
                return KRB5KDC_ERR_POLICY;
            }
        }
    }

    /* Check if this user's SIDs membership is filtered too */
    for(k = 0; k < domain->len_sid_blocklist_incoming; k++) {
        /* Short-circuit if there are no RIDs. This may happen if we filtered everything already.
         * In normal situation there would be at least primary gid as RID in the RIDs array
         * but if we filtered out the primary RID, this MS-PAC is invalid */
        count = info->info->info3.base.groups.count;
        result = dom_sid_is_prefix(info->info->info3.base.domain_sid,
                                   &domain->sid_blocklist_incoming[k]);
        if (result) {
            i = 0;
            j = 0;
            if (domain->sid_blocklist_incoming[k].num_auths - info->info->info3.base.domain_sid->num_auths != 1) {
                krb5_klog_syslog(LOG_ERR, "Incoming SID blacklist element matching domain [%s with SID %s] "
                                          "has more than one RID component. Invalid check skipped.",
                                 domain->domain_name, domain->domain_sid);
                break;
            }
            rid = domain->sid_blocklist_incoming[k].sub_auths[domain->sid_blocklist_incoming[k].num_auths - 1];
            if (rid == info->info->info3.base.rid) {
                filter_logon_info_log_message_rid(info->info->info3.base.domain_sid, rid);
                /* Actual user's SID is filtered out */
                return KRB5KDC_ERR_POLICY;
            }
            if (rid == info->info->info3.base.primary_gid) {
                /* User's primary group SID is filtered out */
                return KRB5KDC_ERR_POLICY;
            }
            if (count == 0) {
                /* Having checked actual user's SID and primary group SID, and having no other RIDs,
                 * skip checks below and continue to next blacklist element */
                continue;
            }

            do {
                if (rid == info->info->info3.base.groups.rids[i].rid) {
                    filter_logon_info_log_message_rid(info->info->info3.base.domain_sid, rid);
                    /* If this is just a non-primary RID, we simply remove it from the array of RIDs */
                    l = count - i - j - 1;
                    if (l != 0) {
                         memmove(info->info->info3.base.groups.rids+i,
                                 info->info->info3.base.groups.rids+i+1,
                                 sizeof(struct samr_RidWithAttribute)*l);
                    }
                    j++;
                } else {
                    i++;
                }
            } while ((i + j) < count);

            if (j != 0) {
                count = count-j;
                if (count == 0) {
                    /* All RIDs were filtered out. Unusual but MS-KILE 3.3.5.6.3.1 says SHOULD, not MUST for GroupCount */
                    info->info->info3.base.groups.count = 0;
                    talloc_free(info->info->info3.base.groups.rids);
                    info->info->info3.base.groups.rids = NULL;
                } else {
                    info->info->info3.base.groups.rids = talloc_realloc(memctx,
                                                                        info->info->info3.base.groups.rids,
                                                                        struct samr_RidWithAttribute, count);
                    if (!info->info->info3.base.groups.rids) {
                        info->info->info3.base.groups.count = 0;
                        return ENOMEM;
                    }
                    info->info->info3.base.groups.count = count;
                }
            }
        }
    }

    /* According to MS-KILE 25.0, info->info->info3.sids may be non zero, so check
     * should include different possibilities into account
     * */
    if (info->info->info3.sidcount != 0) {
        count = info->info->info3.sidcount;
        i = 0;
        j = 0;
        do {
            /* Compare SID with our domain without taking RID into account */
            result = dom_sid_check(&ipactx->mspac->domsid, info->info->info3.sids[i].sid, false);
            if (result) {
                filter_logon_info_log_message(info->info->info3.sids[i].sid);
            } else {
                /* Go over incoming SID blacklist */
                for(k = 0; k < domain->len_sid_blocklist_incoming; k++) {
                    /* if SID is an exact match, filter it out */
                    result = dom_sid_check(&domain->sid_blocklist_incoming[k], info->info->info3.sids[i].sid, true);
                    if (result) {
                        filter_logon_info_log_message(info->info->info3.sids[i].sid);
                        break;
                    }
                    /* if SID is a suffix of the blacklist element, filter it out*/
                    result = dom_sid_is_prefix(&domain->sid_blocklist_incoming[k], info->info->info3.sids[i].sid);
                    if (result) {
                        filter_logon_info_log_message(info->info->info3.sids[i].sid);
                        break;
                    }
                }
            }
            if (result) {
                k = count - i - j - 1;
                if (k != 0) {
                    memmove(info->info->info3.sids+i,
                            info->info->info3.sids+i+1,
                            sizeof(struct netr_SidAttr)*k);
                }
                j++;
            } else {
                i++;
            }
        } while ((i + j) < count);

        if (j != 0) {
            count = count-j;
            if (count == 0) {
                /* All SIDs were filtered out */
                info->info->info3.sidcount = 0;
                talloc_free(info->info->info3.sids);
                info->info->info3.sids = NULL;
            } else {
                info->info->info3.sids = talloc_realloc(memctx,
                                                        info->info->info3.sids,
                                                        struct netr_SidAttr, count);
                if (!info->info->info3.sids) {
                    info->info->info3.sidcount = 0;
                    return ENOMEM;
                }
                info->info->info3.sidcount = count;
            }
        }
    }

    /* According to MS-KILE, ResourceGroups must be zero, so check
     * that it is the case here */
#ifdef HAVE_STRUCT_PAC_DOMAIN_GROUP_MEMBERSHIP
    if (info->info->resource_groups.domain_sid != NULL &&
        info->info->resource_groups.groups.count != 0) {
        return EINVAL;
    }
#else
    if (info->info->res_group_dom_sid != NULL &&
        info->info->res_groups.count != 0) {
        return EINVAL;
    }
#endif

    return 0;
}


static krb5_error_code ipadb_check_logon_info(krb5_context context,
                                              krb5_db_entry *client,
                                              krb5_db_entry *signing_krbtgt,
                                              krb5_boolean is_cross_realm,
                                              krb5_boolean is_s4u,
                                              krb5_data *pac_blob,
                                              struct dom_sid *requester_sid)
{
    struct PAC_LOGON_INFO_CTR info;
    krb5_error_code kerr;
    TALLOC_CTX *tmpctx;
    krb5_data origin_realm = {0};
    bool result;

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }

    kerr = get_logon_info(context, tmpctx, pac_blob, &info);
    if (kerr) {
        goto done;
    }

    /* Check that requester SID is the same as in the PAC entry */
    if (requester_sid != NULL) {
        struct dom_sid client_sid;
        bool is_from_trusted_domain = false;
        kerr = ipadb_get_sid_from_pac(tmpctx, info.info, &client_sid);
        if (kerr) {
            goto done;
        }
        result = dom_sid_check(&client_sid, requester_sid, true);
        if (!result) {
            struct ipadb_context *ipactx = ipadb_get_context(context);
            if (!ipactx || !ipactx->mspac) {
                return KRB5_KDB_DBNOTINITED;
            }
            /* In S4U case we might be dealing with the PAC issued by the trusted domain */
            if (ipactx->mspac->trusts) {
                /* Iterate through list of trusts and check if this SID belongs to
                * one of the domains we trust */
                for(size_t i = 0 ; i < ipactx->mspac->num_trusts ; i++) {
                    result = dom_sid_check(&ipactx->mspac->trusts[i].domsid,
                                           &client_sid, false);
                    if (result) {
                        is_from_trusted_domain = true;
                        break;
                    }
                }
            }

            if (!is_from_trusted_domain && !is_s4u) {
                /* memctx is freed by the caller */
                char *pac_sid = dom_sid_string(tmpctx, &client_sid);
                char *req_sid = dom_sid_string(tmpctx, requester_sid);
                krb5_klog_syslog(LOG_ERR, "PAC issue: PAC has a SID "
                                        "different from what PAC requester claims. "
                                        "PAC [%s] vs PAC requester [%s]",
                                        pac_sid ? pac_sid : "<failed to display>",
                                        req_sid ? req_sid : "<failed to display>");
                kerr = KRB5KDC_ERR_TGT_REVOKED;
                goto done;
            }
        }
    }

    if (!is_cross_realm) {
        /* For local realm case we need to check whether the PAC is for our user
         * but we don't need to process further. In S4U2Proxy case when the client
         * is ours but operates on behalf of the cross-realm principal, we will
         * search through the trusted domains but otherwise skip the exact SID check
         * as we are not responsible for the principal from the trusted domain */
        kerr = check_logon_info_consistent(context, tmpctx, client, is_s4u, &info);
        goto done;
    }

    if (client != NULL) {
        origin_realm = client->princ->realm;
    } else {
        origin_realm = signing_krbtgt->princ->realm;
    }

    kerr = filter_logon_info(context, tmpctx, &origin_realm, &info);
    if (kerr) {
        goto done;
    }

    kerr = add_local_groups(context, tmpctx, &info);
    if (kerr) {
        goto done;
    }

    kerr = save_logon_info(context, tmpctx, &info, pac_blob);
    if (kerr) {
        goto done;
    }

done:
    talloc_free(tmpctx);
    return kerr;
}

static krb5_error_code get_delegation_info(krb5_context context,
                                TALLOC_CTX *memctx, krb5_data *pac_blob,
                                struct PAC_CONSTRAINED_DELEGATION_CTR *info)
{
    DATA_BLOB pac_data;
    enum ndr_err_code ndr_err;

    pac_data.length = pac_blob->length;
    pac_data.data = (uint8_t *)pac_blob->data;

    ndr_err = ndr_pull_union_blob(&pac_data, memctx, info,
                                  PAC_TYPE_CONSTRAINED_DELEGATION,
                                  (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    return 0;
}

static krb5_error_code save_delegation_info(krb5_context context,
                                TALLOC_CTX *memctx,
                                struct PAC_CONSTRAINED_DELEGATION_CTR *info,
                                krb5_data *pac_blob)
{
    DATA_BLOB pac_data;
    enum ndr_err_code ndr_err;

    ndr_err = ndr_push_union_blob(&pac_data, memctx, info,
                                  PAC_TYPE_CONSTRAINED_DELEGATION,
                                  (ndr_push_flags_fn_t)ndr_push_PAC_INFO);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        return KRB5_KDB_INTERNAL_ERROR;
    }

    free(pac_blob->data);
    pac_blob->data = malloc(pac_data.length);
    if (pac_blob->data == NULL) {
        pac_blob->length = 0;
        return ENOMEM;
    }
    memcpy(pac_blob->data, pac_data.data, pac_data.length);
    pac_blob->length = pac_data.length;

    return 0;
}

static krb5_error_code ipadb_add_transited_service(krb5_context context,
                                                   krb5_db_entry *proxy,
                                                   krb5_db_entry *server,
                                                   krb5_pac old_pac,
                                                   krb5_pac new_pac)
{
    struct PAC_CONSTRAINED_DELEGATION_CTR info;
    krb5_data pac_blob = { 0 , 0, NULL };
    krb5_error_code kerr;
    TALLOC_CTX *tmpctx;
    uint32_t i;
    char *tmpstr;

    /* When proxy is NULL, authdata flag on the service principal was cleared
     * by an admin. We don't generate MS-PAC in this case */
    if (proxy == NULL) {
        return 0;
    }

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        kerr = ENOMEM;
        goto done;
    }

    kerr = krb5_pac_get_buffer(context, old_pac,
                               KRB5_PAC_DELEGATION_INFO, &pac_blob);
    if (kerr != 0 && kerr != ENOENT) {
        goto done;
    }

    if (pac_blob.length != 0) {
        kerr = get_delegation_info(context, tmpctx, &pac_blob, &info);
        if (kerr != 0) {
            goto done;
        }
    } else {
        info.info = talloc_zero(tmpctx, struct PAC_CONSTRAINED_DELEGATION);
        if (!info.info) {
            kerr = ENOMEM;
            goto done;
        }
    }

    krb5_free_data_contents(context, &pac_blob);
    memset(&pac_blob, 0, sizeof(krb5_data));

    kerr = krb5_unparse_name_flags(context, proxy->princ,
                                   KRB5_PRINCIPAL_UNPARSE_NO_REALM |
                                   KRB5_PRINCIPAL_UNPARSE_DISPLAY,
                                   &tmpstr);
    if (kerr != 0) {
        goto done;
    }

    info.info->proxy_target.string = talloc_strdup(tmpctx, tmpstr);
    krb5_free_unparsed_name(context, tmpstr);
    if (!info.info->proxy_target.string) {
        kerr = ENOMEM;
        goto done;
    }

    i = info.info->num_transited_services;

    info.info->transited_services = talloc_realloc(tmpctx,
                                                info.info->transited_services,
                                                struct lsa_String, i + 1);
    if (!info.info->transited_services) {
        kerr = ENOMEM;
        goto done;
    }

    kerr = krb5_unparse_name(context, server->princ, &tmpstr);
    if (kerr != 0) {
        goto done;
    }

    info.info->transited_services[i].string = talloc_strdup(tmpctx, tmpstr);
    krb5_free_unparsed_name(context, tmpstr);
    if (!info.info->transited_services[i].string) {
        kerr = ENOMEM;
        goto done;
    }
    info.info->num_transited_services = i + 1;

    kerr = save_delegation_info(context, tmpctx, &info, &pac_blob);
    if (kerr != 0) {
        goto done;
    }

    kerr = krb5_pac_add_buffer(context, new_pac,
                               KRB5_PAC_DELEGATION_INFO, &pac_blob);
    if (kerr) {
        goto done;
    }

done:
    krb5_free_data_contents(context, &pac_blob);
    talloc_free(tmpctx);
    return kerr;
}

krb5_error_code ipadb_common_verify_pac(krb5_context context,
                                        unsigned int flags,
                                        krb5_db_entry *client,
                                        krb5_db_entry *server,
                                        krb5_db_entry *signing_krbtgt,
                                        krb5_keyblock *krbtgt_key,
                                        krb5_timestamp authtime,
                                        krb5_pac old_pac,
                                        krb5_pac *pac)
{
    krb5_error_code kerr;
    krb5_ui_4 *types = NULL;
    size_t num_buffers;
    krb5_pac new_pac = NULL;
    krb5_data data;
    krb5_data pac_blob = { 0 , 0, NULL};
    bool is_cross_realm = false;
    size_t i;
    struct dom_sid *requester_sid = NULL;
    struct dom_sid req_sid;
    TALLOC_CTX *tmpctx = NULL;

    if (signing_krbtgt != NULL &&
        ipadb_is_cross_realm_krbtgt(signing_krbtgt->princ)) {
        /* krbtgt from a trusted realm */
        is_cross_realm = true;
    }

    /* In krb5 1.20+ the PAC signatures are verified prior to call to issue_pac().
     * In krb5 before 1.20, we do verify PAC signatures before ipadb_common_verify_pac().
     * Now we can do additional checks.
     * Augment it with additional info if it is coming from a different realm */
    kerr = krb5_pac_get_buffer(context, old_pac,
                               KRB5_PAC_LOGON_INFO, &pac_blob);
    if (kerr != 0) {
        goto done;
    }

    memset(&req_sid, '\0', sizeof(struct dom_sid));
#ifdef HAVE_PAC_REQUESTER_SID
    kerr = ipadb_get_requester_sid(context, old_pac, &req_sid);
    if (kerr == 0) {
        requester_sid = &req_sid;
    }
#endif

    kerr = ipadb_check_logon_info(context,
                                  client,
                                  signing_krbtgt,
                                  is_cross_realm,
                                  (flags & KRB5_KDB_FLAGS_S4U),
                                  &pac_blob,
                                  requester_sid);
    if (kerr != 0) {
        goto done;
    }

    /* krb5 1.20+ passes in a pre-created PAC structure but for previous
     * versions we have to create it ourselves */
    if (pac != NULL && *pac == NULL) {
        /* extract buffers and rebuilt pac from scratch so that when re-signing
        * with a different cksum type does not cause issues due to mismatching
        * signature buffer lengths */
        kerr = krb5_pac_init(context, &new_pac);
        if (kerr) {
            goto done;
        }
    } else {
        new_pac = *pac;
    }

    kerr = krb5_pac_get_types(context, old_pac, &num_buffers, &types);
    if (kerr) {
        goto done;
    }

    tmpctx = talloc_new(NULL);
    if (tmpctx == NULL) {
        kerr = ENOMEM;
        goto done;
    }

    for (i = 0; i < num_buffers; i++) {
        if (types[i] == KRB5_PAC_SERVER_CHECKSUM ||
            types[i] == KRB5_PAC_PRIVSVR_CHECKSUM ||
#ifdef KRB5_PAC_FULL_CHECKSUM
            types[i] == KRB5_PAC_FULL_CHECKSUM ||
#endif
	    types[i] == KRB5_PAC_CLIENT_INFO) {
            continue;
        }

        if (types[i] == KRB5_PAC_LOGON_INFO &&
            pac_blob.length != 0) {
            kerr = krb5_pac_add_buffer(context, new_pac, types[i], &pac_blob);
            if (kerr) {
                goto done;
            }

            continue;
        }

#ifdef HAVE_PAC_ATTRIBUTES_INFO
        if (types[i] == PAC_TYPE_ATTRIBUTES_INFO &&
            pac_blob.length != 0) {
            /* == Check whether PAC was requested or given implicitly == */
            DATA_BLOB pac_attrs_data;
            krb5_boolean pac_requested;

            kerr = ipadb_client_requested_pac(context, old_pac, tmpctx, &pac_requested);
            if (kerr)
                goto done;

            kerr = ipadb_get_pac_attrs_blob(tmpctx, &pac_requested, &pac_attrs_data);
            if (kerr)
                goto done;

            data.magic = KV5M_DATA;
            data.data = (char *)pac_attrs_data.data;
            data.length = pac_attrs_data.length;

            kerr = krb5_pac_add_buffer(context, new_pac, PAC_TYPE_ATTRIBUTES_INFO, &data);
            if (kerr)
                goto done;

            continue;
        }
#endif

        if (types[i] == KRB5_PAC_DELEGATION_INFO &&
            (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION)) {
            /* skip it here, we will add it explicitly later */
            continue;
        }

        kerr = krb5_pac_get_buffer(context, old_pac, types[i], &data);
        if (kerr == 0) {
            kerr = krb5_pac_add_buffer(context, new_pac, types[i], &data);
            krb5_free_data_contents(context, &data);
        }
        if (kerr) {
            goto done;
        }
    }

#if !defined(KRB5_KDB_FLAG_CLIENT)
    if (flags & KRB5_KDB_FLAG_CONSTRAINED_DELEGATION) {
        if (client == NULL) {
            if (new_pac != *pac) {
                krb5_pac_free(context, new_pac);
            }
            *pac = NULL;
            kerr = 0;
            goto done;
        }

        kerr = ipadb_add_transited_service(context, client, server,
                                           old_pac, new_pac);
        if (kerr) {
            goto done;
        }
    }
#endif

    *pac = new_pac;

done:
    if (kerr != 0 && (new_pac != *pac)) {
        krb5_pac_free(context, new_pac);
    }
    if (tmpctx)
        talloc_free(tmpctx);
    krb5_free_data_contents(context, &pac_blob);
    free(types);
    return kerr;
}

void get_authz_data_types(krb5_context context, krb5_db_entry *entry,
                          bool *_with_pac, bool *_with_pad)
{
    struct ipadb_e_data *ied = NULL;
    struct ipadb_context *ipactx;
    size_t c;
    bool none_found = false;
    bool srv_none_found = false;
    char **authz_data_list;
    bool with_pac = false;
    bool srv_with_pac = false;
    bool with_pad = false;
    bool srv_with_pad = false;
    char *sep;
    krb5_data *service_type;
    char *authz_data_type;
    bool service_specific;

    if (entry != NULL) {
        ied = (struct ipadb_e_data *) entry->e_data;
    }

    if (ied == NULL || ied->authz_data == NULL) {
        const struct ipadb_global_config *gcfg = NULL;
        char **tmp = NULL;

        if (context == NULL) {
            krb5_klog_syslog(LOG_ERR, "Missing Kerberos context, no " \
                                      "authorization data will be added.");
            goto done;
        }

        ipactx = ipadb_get_context(context);
        if (ipactx != NULL) {
            gcfg = ipadb_get_global_config(ipactx);
            if (gcfg != NULL)
                tmp = gcfg->authz_data;
        }
        if (ipactx == NULL || tmp == NULL) {
            krb5_klog_syslog(LOG_ERR, "No default authorization data types " \
                                      "available, no authorization data will " \
                                      "be added.");
            goto done;
        }

        authz_data_list = tmp;
    } else {
        authz_data_list = ied->authz_data;
    }


    for (c = 0; authz_data_list[c]; c++) {
        service_specific = false;
        authz_data_type = authz_data_list[c];
        sep = strchr(authz_data_list[c], ':');
        if (sep != NULL && entry != NULL) {
            if (entry->princ == NULL) {
                krb5_klog_syslog(LOG_ERR, "Missing principal in database "
                                          "entry, no authorization data will " \
                                          "be added.");
                goto done;
            }

            service_type = krb5_princ_component(context, entry->princ, 0);
            if (service_type == NULL) {
                krb5_klog_syslog(LOG_ERR, "Missing service type in database "
                                          "entry, no authorization data will " \
                                          "be added.");
                goto done;
            }

            if (service_type->length == (sep - authz_data_list[c]) &&
                strncmp(authz_data_list[c], service_type->data,
                        service_type->length) == 0) {
                service_specific = true;
                authz_data_type = sep + 1;
            } else {
                /* Service specific default does not apply, skipping this
                 * entry. */
                continue;
            }
        }

        if (strcmp(authz_data_type, AUTHZ_DATA_TYPE_PAC) == 0) {
            if (service_specific) {
                srv_with_pac = true;
            } else {
                with_pac = true;
            }
        } else if (strcmp(authz_data_type, AUTHZ_DATA_TYPE_PAD) == 0) {
            if (service_specific) {
                srv_with_pad = true;
            } else {
                with_pad = true;
            }
        } else if (strcmp(authz_data_type, AUTHZ_DATA_TYPE_NONE) == 0) {
            if (service_specific) {
                srv_none_found = true;
            } else {
                none_found = true;
            }
        } else {
            /* for out-of-realm entries we suppress warnings in our defaults */
            if (entry != NULL) {
                krb5_klog_syslog(LOG_ERR, "Ignoring unsupported " \
                                        "authorization data type [%s].",
                                        authz_data_list[c]);
            }
        }
    }

done:
    if (srv_none_found || srv_with_pac || srv_with_pad) {
        none_found = srv_none_found;
        with_pac = srv_with_pac;
        with_pad = srv_with_pad;
    }

    if (none_found) {
        with_pac = false;
        with_pad = false;
    }

    if (_with_pac != NULL) {
        *_with_pac = with_pac;
    }
    if (_with_pad != NULL) {
        *_with_pad = with_pad;
    }

}


static char *get_server_netbios_name(struct ipadb_context *ipactx)
{
    char hostname[IPA_HOST_FQDN_LEN + 1]; /* NOTE: long enough for DNS name */
    char *p;

    strncpy(hostname, ipactx->kdc_hostname, IPA_HOST_FQDN_LEN);
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

void ipadb_mspac_struct_free(struct ipadb_mspac **mspac)
{
    size_t i, j;

    if (!*mspac) return;

    free((*mspac)->flat_domain_name);
    free((*mspac)->flat_server_name);
    free((*mspac)->fallback_group);

    if ((*mspac)->num_trusts) {
        for (i = 0; i < (*mspac)->num_trusts; i++) {
            free((*mspac)->trusts[i].domain_name);
            free((*mspac)->trusts[i].flat_name);
            free((*mspac)->trusts[i].domain_sid);
            free((*mspac)->trusts[i].sid_blocklist_incoming);
            free((*mspac)->trusts[i].sid_blocklist_outgoing);
            free((*mspac)->trusts[i].parent_name);
            (*mspac)->trusts[i].parent = NULL;
            if ((*mspac)->trusts[i].upn_suffixes) {
                for (j = 0; (*mspac)->trusts[i].upn_suffixes[j]; j++) {
                    free((*mspac)->trusts[i].upn_suffixes[j]);
                }
                free((*mspac)->trusts[i].upn_suffixes);
                free((*mspac)->trusts[i].upn_suffixes_len);
            }
        }
        free((*mspac)->trusts);
    }
    free(*mspac);

    *mspac = NULL;
}

static krb5_error_code
ipadb_adtrusts_fill_sid_blacklist(char **source_sid_blacklist,
                                  struct dom_sid **result_sids,
                                  int *result_length)
{
    int len, i;
    char **source;
    struct dom_sid *sid_blacklist;

    if (source_sid_blacklist) {
        source = source_sid_blacklist;
    } else {
        /* Use default hardcoded list */
        source = ipa_mspac_well_known_sids;
    }
    len = 0;
    for (i = 0; source && source[i]; i++) {
        len++;
    }

    sid_blacklist = calloc(len, sizeof(struct dom_sid));
    if (sid_blacklist == NULL) {
        return ENOMEM;
    }

    for (i = 0; i < len; i++) {
         (void) ipadb_string_to_sid(source[i], &sid_blacklist[i]);
    }

    *result_sids = sid_blacklist;
    *result_length = len;
    return 0;
}

static krb5_error_code
ipadb_adtrusts_fill_sid_blacklists(struct ipadb_adtrusts *adtrust,
                                   char **sid_blocklist_incoming,
                                   char **sid_blocklist_outgoing)
{
    krb5_error_code kerr;

    kerr = ipadb_adtrusts_fill_sid_blacklist(sid_blocklist_incoming,
                                             &adtrust->sid_blocklist_incoming,
                                             &adtrust->len_sid_blocklist_incoming);
    if (kerr) {
        return kerr;
    }

    kerr = ipadb_adtrusts_fill_sid_blacklist(sid_blocklist_outgoing,
                                             &adtrust->sid_blocklist_outgoing,
                                             &adtrust->len_sid_blocklist_outgoing);
    if (kerr) {
        return kerr;
    }

    return 0;
}

static krb5_error_code
ipadb_mspac_check_trusted_domains(struct ipadb_context *ipactx)
{
    char *attrs[] = { NULL };
    char *filter = "(objectclass=ipaNTTrustedDomain)";
    char *base = NULL;
    LDAPMessage *result = NULL;
    int ret;

    ret = asprintf(&base, "cn=ad,cn=trusts,%s", ipactx->base);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    /* Run a quick search if there is any trust defined */
    ret = ipadb_simple_search(ipactx, base, LDAP_SCOPE_SUBTREE,
                              filter, attrs, &result);

done:
    ldap_msgfree(result);
    free(base);
    return ret;
}

static void ipadb_free_sid_blacklists(char ***sid_blocklist_incoming, char ***sid_blocklist_outgoing)
{
    int i;

    if (sid_blocklist_incoming && *sid_blocklist_incoming) {
        for (i = 0; *sid_blocklist_incoming && (*sid_blocklist_incoming)[i]; i++) {
            free((*sid_blocklist_incoming)[i]);
        }
        free(*sid_blocklist_incoming);
        *sid_blocklist_incoming = NULL;
    }

    if (sid_blocklist_outgoing && *sid_blocklist_outgoing) {
        for (i = 0; *sid_blocklist_outgoing && (*sid_blocklist_outgoing)[i]; i++) {
            free((*sid_blocklist_outgoing)[i]);
        }
        free(*sid_blocklist_outgoing);
        *sid_blocklist_outgoing = NULL;
    }
}

static krb5_error_code
ipadb_mspac_get_trusted_domains(struct ipadb_context *ipactx)
{
    struct ipadb_adtrusts *t;
    LDAP *lc = NULL;
    char *attrs[] = { "cn", "ipaNTTrustPartner", "ipaNTFlatName",
                      "ipaNTTrustedDomainSID", "ipaNTSIDBlacklistIncoming",
                      "ipaNTSIDBlacklistOutgoing", "ipaNTAdditionalSuffixes", NULL };
    char *filter = "(objectclass=ipaNTTrustedDomain)";
    krb5_error_code kerr;
    LDAPMessage *res = NULL;
    LDAPMessage *le;
    LDAPRDN rdn;
    char *base = NULL;
    char *dnstr = NULL;
    char *dnl = NULL;
    LDAPDN dn = NULL;
    char **sid_blocklist_incoming = NULL;
    char **sid_blocklist_outgoing = NULL;
    size_t i, n;
    int ret;

    ret = asprintf(&base, "cn=ad,cn=trusts,%s", ipactx->base);
    if (ret == -1) {
        ret = ENOMEM;
        goto done;
    }

    kerr = ipadb_simple_search(ipactx, base, LDAP_SCOPE_SUBTREE,
                               filter, attrs, &res);
    if (kerr == KRB5_KDB_NOENTRY) {
        /* nothing to do, there are no trusts */
        ret = 0;
        goto done;
    } else if (kerr != 0) {
        ret = EIO;
        goto done;
    }

    lc = ipactx->lcontext;
    for (le = ldap_first_entry(lc, res); le; le = ldap_next_entry(lc, le)) {
        dnstr = ldap_get_dn(lc, le);

        if (dnstr == NULL) {
            ret = ENOMEM;
            goto done;
        }

        n = ipactx->mspac->num_trusts;
        ipactx->mspac->num_trusts++;
        t = realloc(ipactx->mspac->trusts,
                    sizeof(struct ipadb_adtrusts) * ipactx->mspac->num_trusts);
        if (!t) {
            ret = ENOMEM;
            goto done;
        }
        ipactx->mspac->trusts = t;

        memset(&t[n], 0, sizeof(t[n]));

        ret = ipadb_ldap_attr_to_str(lc, le, "cn",
                                     &t[n].domain_name);
        if (ret) {
            ret = EINVAL;
            goto done;
        }

        t[n].flat_name = NULL;
        ret = ipadb_ldap_attr_to_str(lc, le, "ipaNTFlatName",
                                     &t[n].flat_name);
        if (ret && ret != ENOENT) {
            ret = EINVAL;
            goto done;
        }

        t[n].domain_sid = NULL;
        ret = ipadb_ldap_attr_to_str(lc, le, "ipaNTTrustedDomainSID",
                                     &t[n].domain_sid);
        if (ret && ret != ENOENT) {
            ret = EINVAL;
            goto done;
        }

        ret = ipadb_string_to_sid(t[n].domain_sid, &t[n].domsid);
        if (ret && t[n].domain_sid != NULL) {
            ret = EINVAL;
            goto done;
        }

        ret = ipadb_ldap_attr_to_strlist(lc, le, "ipaNTAdditionalSuffixes",
                                         &t[n].upn_suffixes);

        if (ret) {
            if (ret == ENOENT) {
                /* This attribute is optional */
                ret = 0;
                t[n].upn_suffixes = NULL;
            } else {
                ret = EINVAL;
                goto done;
            }
        }

        t[n].upn_suffixes_len = NULL;
        if (t[n].upn_suffixes != NULL) {
            size_t len = 0;

            for (; t[n].upn_suffixes[len] != NULL; len++);

            if (len != 0) {
                t[n].upn_suffixes_len = calloc(len, sizeof(size_t));
                if (t[n].upn_suffixes_len == NULL) {
                    ret = ENOMEM;
                    goto done;
                }
                for (i = 0; i < len; i++) {
                    t[n].upn_suffixes_len[i] = strlen(t[n].upn_suffixes[i]);
                }
            }
        }

        ret = ipadb_ldap_attr_to_strlist(lc, le, "ipaNTSIDBlacklistIncoming",
                                         &sid_blocklist_incoming);

        if (ret) {
            if (ret == ENOENT) {
                /* This attribute is optional */
                ret = 0;
                sid_blocklist_incoming = NULL;
            } else {
                ret = EINVAL;
                goto done;
            }
        }

        ret = ipadb_ldap_attr_to_strlist(lc, le, "ipaNTSIDBlacklistOutgoing",
                                         &sid_blocklist_outgoing);

        if (ret) {
            if (ret == ENOENT) {
                /* This attribute is optional */
                ret = 0;
                sid_blocklist_outgoing = NULL;
            } else {
                ret = EINVAL;
                goto done;
            }
        }

        ret = ipadb_adtrusts_fill_sid_blacklists(&t[n],
                                                 sid_blocklist_incoming,
                                                 sid_blocklist_outgoing);
        if (ret) {
            goto done;
        }
        ipadb_free_sid_blacklists(&sid_blocklist_incoming,
                                  &sid_blocklist_outgoing);

        /* Parse first two RDNs of the entry to find its parent */
        dnl = strcasestr(dnstr, base);
        if (dnl == NULL) {
            goto done;
        }

        dnl--; dnl[0] = '\0';
        /* Create a DN, which is now everything before the base,
         * to get list of rdn values -- the last one would be a root domain.
         * Since with cross-forest trust we have to route everything via root
         * domain, that is enough for us to assign parentship. */
        ret = ldap_str2dn(dnstr, &dn, LDAP_DN_FORMAT_LDAPV3);
        if (ret) {
            goto done;
        }

        rdn = NULL;
        for (i = 0; dn[i] != NULL; i++) {
            rdn = dn[i];
        }

        /* We should have a single AVA in the domain RDN */
        if (rdn == NULL) {
            ldap_dnfree(dn);
            ret = EINVAL;
            goto done;
        }

        t[n].parent_name = strndup(rdn[0]->la_value.bv_val, rdn[0]->la_value.bv_len);

        ldap_dnfree(dn);

        free(dnstr);
        dnstr = NULL;
    }

    /* Traverse through all trusts and resolve parents */
    t = ipactx->mspac->trusts;
    for (i = 0; i < ipactx->mspac->num_trusts; i++) {
        if (t[i].parent_name != NULL) {
            for (n = 0; n < ipactx->mspac->num_trusts; n++) {
                if (strcasecmp(t[i].parent_name, t[n].domain_name) == 0) {
                    t[i].parent = &t[n];
                }
            }
        }
    }

    ret = 0;

done:
    if (ret != 0) {
        krb5_klog_syslog(LOG_ERR, "Failed to read list of trusted domains");
    }
    free(dnstr);
    free(base);
    ipadb_free_sid_blacklists(&sid_blocklist_incoming,
                              &sid_blocklist_outgoing);
    ldap_msgfree(res);
    return ret;
}

krb5_error_code
ipadb_reinit_mspac(struct ipadb_context *ipactx, bool force_reinit,
                   const char **stmsg)
{
    char *dom_attrs[] = { "ipaNTFlatName",
                          "ipaNTFallbackPrimaryGroup",
                          "ipaNTSecurityIdentifier",
                          NULL };
    char *grp_attrs[] = { "ipaNTSecurityIdentifier", NULL };
    LDAPMessage *result = NULL;
    LDAPMessage *lentry;
    struct dom_sid gsid, domsid;
    char *resstr = NULL;
    char *flat_domain_name = NULL;
    char *flat_server_name = NULL;
    char *fallback_group = NULL;
    uint32_t fallback_rid;
    time_t now;
    const char *in_stmsg = NULL;
    int err;
    krb5_error_code trust_kerr = 0;


    /* Do not update the mspac struct more than once a minute. This would
     * avoid heavy load on the directory server if there are lots of requests
     * from domains which we do not trust. */
    now = time(NULL);

    if (ipactx->mspac) {
        if (!force_reinit &&
            (now > ipactx->mspac->last_update) &&
            (now - ipactx->mspac->last_update) < 60) {
            /* SKIP */
            err = 0;
            goto end;
        }

        if (ipactx->mspac->num_trusts == 0) {
            /* Check if there is any trust configured. If not, just return
             * and do not re-initialize the MS-PAC structure. */
            err = ipadb_mspac_check_trusted_domains(ipactx);
            if (err) {
                if (err == KRB5_KDB_NOENTRY) {
                    /* SKIP */
                    err = 0;
                } else {
                    in_stmsg = "Failed to fetch trusted domains information";
                }
                goto end;
            }
        }
    }

    err = ipadb_simple_search(ipactx, ipactx->base, LDAP_SCOPE_SUBTREE,
                              "(objectclass=ipaNTDomainAttrs)", dom_attrs,
                              &result);
    if (err == KRB5_KDB_NOENTRY) {
        err = ENOENT;
        in_stmsg = "Local domain NT attributes not configured";
        goto end;
    } else if (err) {
        err = EIO;
        in_stmsg = "Failed to fetch local domain NT attributes";
        goto end;
    }

    lentry = ldap_first_entry(ipactx->lcontext, result);
    if (!lentry) {
        err = ENOENT;
        in_stmsg = "Local domain NT attributes not configured";
        goto end;
    }

    err = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry, "ipaNTFlatName",
                                 &flat_domain_name);
    if (err) {
        in_stmsg = "Local domain NT flat name not configured";
        goto end;
    }

    err = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTSecurityIdentifier", &resstr);
    if (err) {
        in_stmsg = "Local domain SID not configured";
        goto end;
    }

    err = ipadb_string_to_sid(resstr, &domsid);
    if (err) {
        in_stmsg = "Malformed local domain SID";
        goto end;
    }

    free(resstr);
    resstr = NULL;

    flat_server_name = get_server_netbios_name(ipactx);
    if (!flat_server_name) {
        err = ENOMEM;
        goto end;
    }

    err = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTFallbackPrimaryGroup", &fallback_group);
    if (err) {
        in_stmsg = (err == ENOENT)
          ? "Local fallback primary group not configured"
          : "Failed to fetch local fallback primary group";
        goto end;
    }

    /* result and lentry not valid any more from here on */
    ldap_msgfree(result);
    result = NULL;
    lentry = NULL;

    err = ipadb_simple_search(ipactx, fallback_group, LDAP_SCOPE_BASE,
                              "(objectclass=posixGroup)", grp_attrs, &result);
    if (err) {
        in_stmsg = (err == KRB5_KDB_NOENTRY)
          ? "Local fallback primary group has no POSIX definition"
          : "Failed to fetch SID of POSIX group mapped as local fallback " \
            "primary group";
        goto end;
    }

    lentry = ldap_first_entry(ipactx->lcontext, result);
    if (!lentry) {
        err = ENOENT;
        goto end;
    }

    err = ipadb_ldap_attr_to_str(ipactx->lcontext, lentry,
                                 "ipaNTSecurityIdentifier", &resstr);
    if (err) {
        in_stmsg = (err == ENOENT)
          ? "The POSIX group set as fallback primary group has no SID " \
            "configured"
          : "Failed to fetch SID of POSIX group set as local fallback " \
            "primary group";
        goto end;
    }

    err = ipadb_string_to_sid(resstr, &gsid);
    if (err) {
        in_stmsg = "Malformed SID of POSIX group set as local fallback " \
                   "primary group";
        goto end;
    }

    err = sid_split_rid(&gsid, &fallback_rid);
    if (err) {
        in_stmsg = "Malformed SID of POSIX group mapped as local fallback " \
                   "primary group";
        goto end;
    }

    /* clean up in case we had old values around */
    ipadb_mspac_struct_free(&ipactx->mspac);

    ipactx->mspac = calloc(1, sizeof(struct ipadb_mspac));
    if (!ipactx->mspac) {
        err = ENOMEM;
        goto end;
    }

    ipactx->mspac->last_update      = now;
    ipactx->mspac->flat_domain_name = flat_domain_name;
    ipactx->mspac->flat_server_name = flat_server_name;
    ipactx->mspac->domsid           = domsid;
    ipactx->mspac->fallback_group   = fallback_group;
    ipactx->mspac->fallback_rid     = fallback_rid;

    trust_kerr = ipadb_mspac_get_trusted_domains(ipactx);
    if (trust_kerr)
        in_stmsg = "Failed to assemble trusted domains information";

end:
    if (stmsg)
        *stmsg = in_stmsg;

    if (resstr) free(resstr);
    ldap_msgfree(result);

    if (err) {
        if (flat_domain_name) free(flat_domain_name);
        if (flat_server_name) free(flat_server_name);
        if (fallback_group)   free(fallback_group);
    }

    return err ? (krb5_error_code)err : trust_kerr;
}

krb5_error_code ipadb_check_transited_realms(krb5_context kcontext,
					     const krb5_data *tr_contents,
					     const krb5_data *client_realm,
					     const krb5_data *server_realm)
{
	struct ipadb_context *ipactx;
	bool has_transited_contents, has_client_realm, has_server_realm;
        size_t i;
        krb5_error_code ret;

        ipactx = ipadb_get_context(kcontext);
        if (!ipactx) {
            return KRB5_KDB_DBNOTINITED;
        }

	has_transited_contents = false;
	has_client_realm = false;
	has_server_realm = false;

	/* First, compare client or server realm with ours */
	if (strncasecmp(client_realm->data, ipactx->realm, client_realm->length) == 0) {
		has_client_realm = true;
	}
	if (strncasecmp(server_realm->data, ipactx->realm, server_realm->length) == 0) {
		has_server_realm = true;
	}

	if ((tr_contents->length == 0) || (tr_contents->data[0] == '\0')) {
		/* For in-realm case allow transition */
		if (has_client_realm && has_server_realm) {
			return 0;
		}
		/* Since transited realm is empty, we don't need to check for it, it is a direct trust case */
		has_transited_contents = true;
	}

	if (!ipactx->mspac || !ipactx->mspac->trusts) {
		return KRB5_PLUGIN_NO_HANDLE;
	}

	/* Iterate through list of trusts and check if any of input belongs to any of the trust */
	for(i=0; i < ipactx->mspac->num_trusts ; i++) {
		if (!has_transited_contents &&
		    (strncasecmp(tr_contents->data, ipactx->mspac->trusts[i].domain_name, tr_contents->length) == 0)) {
			has_transited_contents = true;
		}
		if (!has_client_realm &&
		    (strncasecmp(client_realm->data, ipactx->mspac->trusts[i].domain_name, client_realm->length) == 0)) {
			has_client_realm = true;
		}
		if (!has_server_realm &&
		    (strncasecmp(server_realm->data, ipactx->mspac->trusts[i].domain_name, server_realm->length) == 0)) {
			has_server_realm = true;
		}
	}

	/* Tell to KDC that we don't handle this transition so that rules in krb5.conf could play its role */
	ret = KRB5_PLUGIN_NO_HANDLE;
	if (has_client_realm && has_transited_contents && has_server_realm) {
		ret = 0;
	}
	return ret;
}

/* Checks whether a principal's realm is one of trusted domains' realm or NetBIOS name
 * and returns the realm of the matched trusted domain in 'trusted_domain'
 * Returns 0 in case of success and KRB5_KDB_NOENTRY otherwise
 * If DAL driver is not initialized, returns KRB5_KDB_DBNOTINITED */
krb5_error_code ipadb_is_princ_from_trusted_realm(krb5_context kcontext,
						  const char *test_realm, size_t size,
						  char **trusted_realm)
{
	struct ipadb_context *ipactx;
	size_t i, j, length;
	const char *name;
	bool result = false;

	if (test_realm == NULL || test_realm[0] == '\0') {
		return KRB5_KDB_NOENTRY;
	}

	ipactx = ipadb_get_context(kcontext);
	if (!ipactx || !ipactx->mspac) {
		return KRB5_KDB_DBNOTINITED;
	}

	/* First, compare realm with ours, it would not be from a trusted realm then */
	if (strncasecmp(test_realm, ipactx->realm, size) == 0) {
		return KRB5_KDB_NOENTRY;
	}

	if (!ipactx->mspac || !ipactx->mspac->trusts) {
		return KRB5_KDB_NOENTRY;
	}

	/* Iterate through list of trusts and check if input realm belongs to any of the trust */
	for(i = 0 ; i < ipactx->mspac->num_trusts ; i++) {
		size_t len = 0;
		result = strncasecmp(test_realm,
				     ipactx->mspac->trusts[i].domain_name,
				     size) == 0;

		if (!result) {
			len = strlen(ipactx->mspac->trusts[i].domain_name);
			if ((size > len) && (test_realm[size - len - 1] == '.')) {
				result = strncasecmp(test_realm + (size - len),
						     ipactx->mspac->trusts[i].domain_name,
						     len) == 0;
			}
		}

                if (!result && (ipactx->mspac->trusts[i].flat_name != NULL)) {
			result = strncasecmp(test_realm,
					     ipactx->mspac->trusts[i].flat_name,
					     size) == 0;
		}

		if (!result && (ipactx->mspac->trusts[i].upn_suffixes != NULL)) {
			for (j = 0; ipactx->mspac->trusts[i].upn_suffixes[j]; j++) {
				result = strncasecmp(test_realm,
						     ipactx->mspac->trusts[i].upn_suffixes[j],
						     size) == 0;
				if (!result) {
					/* if UPN suffix did not match exactly, find if it is
					 * superior to the test_realm, e.g. if test_realm ends
					 * with the UPN suffix prefixed with dot*/
					len = ipactx->mspac->trusts[i].upn_suffixes_len[j];
					if ((size > len) && (test_realm[size - len - 1] == '.')) {
						result = strncasecmp(test_realm + (size - len),
								     ipactx->mspac->trusts[i].upn_suffixes[j],
								     len) == 0;
					}
				}
				if (result)
					break;
			}
		}

		if (result) {
			/* return the realm if caller supplied a place for it */
			if (trusted_realm != NULL) {
				name = (ipactx->mspac->trusts[i].parent_name != NULL) ?
					ipactx->mspac->trusts[i].parent_name :
					ipactx->mspac->trusts[i].domain_name;
				length = strlen(name) + 1;
				*trusted_realm = calloc(1, length);
				if (*trusted_realm != NULL) {
					for (j = 0; j < length; j++) {
						(*trusted_realm)[j] = toupper(name[j]);
					}
				} else {
					return KRB5_KDB_NOENTRY;
				}
			}
			return 0;
		}
	}

	return KRB5_KDB_NOENTRY;
}

static krb5_error_code
check_for_pac(krb5_context kcontext, krb5_authdata **authdata, bool *pac_present)
{
    krb5_error_code kerr = ENOENT;
    size_t i, j;
    krb5_authdata **ifrel = NULL;

    for (i = 0; authdata && authdata[i]; ++i) {
        if (authdata[i]->ad_type != KRB5_AUTHDATA_IF_RELEVANT) {
            continue;
        }

        kerr = krb5_decode_authdata_container(kcontext,
                                              KRB5_AUTHDATA_IF_RELEVANT,
                                              authdata[i], &ifrel);
        if (kerr) {
            goto end;
        }

        for (j = 0; ifrel[j]; ++j) {
            if (ifrel[j]->ad_type == KRB5_AUTHDATA_WIN2K_PAC) {
                break;
            }
        }
        if (ifrel[j]) {
            break;
        }

        krb5_free_authdata(kcontext, ifrel);
        ifrel = NULL;
    }

    *pac_present = ifrel;
    kerr = 0;

end:
    krb5_free_authdata(kcontext, ifrel);
    return kerr;
}

krb5_error_code
ipadb_enforce_pac(krb5_context kcontext, const krb5_ticket *ticket,
                  const char **status)
{
    struct ipadb_context *ipactx;
    bool pac_present;
    krb5_error_code kerr;

    /* Filter TGTs only */
    if (!ipadb_is_tgs_princ(kcontext, ticket->server)) {
        kerr = 0;
        goto end;
    }

    /* Get IPA context */
    ipactx = ipadb_get_context(kcontext);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto end;
    }

    /* If local TGT but PAC generator not initialized, skip PAC enforcement */
    if (krb5_realm_compare(kcontext, ipactx->local_tgs, ticket->server) &&
        !ipactx->mspac)
    {
        krb5_klog_syslog(LOG_WARNING, "MS-PAC not available. This makes "
                         "FreeIPA vulnerable to privilege escalation exploit "
                         "(CVE-2025-7493). Please generate SIDs to enable PAC "
                         "support.");
        kerr = 0;
        goto end;
    }

    /* Search for the PAC, fail if it cannot be found */
    kerr = check_for_pac(kcontext, ticket->enc_part2->authorization_data,
                         &pac_present);
    if (kerr) {
        *status = "PAC_ENFORCEMENT_CANNOT_DECODE_TGT_AUTHDATA";
    } else if (!pac_present) {
        kerr = ENOENT;
        *status = "PAC_ENFORCEMENT_TGT_WITHOUT_PAC";
    }

end:
    return kerr;
}
