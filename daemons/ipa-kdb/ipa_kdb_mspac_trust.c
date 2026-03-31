/*
 * MIT Kerberos KDC database backend for FreeIPA - Trust PAC checks
 *
 * Authors: Julien Rische <jrische@redhat.com>
 *
 * Copyright (C) 2026  Red Hat
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
#include "gen_ndr/ndr_krb5pac.h"
#include <assert.h>
#include <lber.h>
#include <ldap.h>

#include "ipa_kdb_mspac_private.h"

/* Cross-realm TGT information extracted from ticket and PAC for validation */
struct crossrealm_tgt_info {
    TALLOC_CTX *memctx;

    /* Ticket cname principal */
    krb5_const_principal client_princ;
    bool is_enterprise_princ;

    /* PAC_LOGON_INFO (Type 1) - mandatory
     * Present since Windows 2000 */
    bool logon_info_present;
    const char *account_name;
    struct dom_sid logon_info_sid;
    char *logon_info_sid_string;

    /* PAC_CLIENT_INFO (Type 10) - mandatory
     * Present since Windows 2000 */
    bool client_info_present;
    const char *client_name;

    /* PAC_UPN_DNS_INFO (Type 12) - optional
     * Present since Windows Server 2008 */
    bool upn_dns_info_present;
    const char *upn;
    bool upn_is_qualified;
    bool upn_is_constructed;
    bool upn_has_sam_and_sid;
    const char *upn_sam_name;
    struct dom_sid upn_sid;

    /* PAC_REQUESTER_SID (Type 18) - optional
     * Present since Windows Server 2019 */
    bool requester_sid_present;
    struct dom_sid requester_sid;
};

/* Initialize PAC check info structure and create talloc context */
static krb5_error_code
ipadb_trust_pac_info_init(struct crossrealm_tgt_info *info)
{
    memset(info, 0, sizeof(struct crossrealm_tgt_info));

    info->memctx = talloc_new(NULL);
    if (!info->memctx)
        return ENOMEM;

    return 0;
}

/* Deinitialize PAC check info structure and free allocated resources */
static void
ipadb_trust_pac_info_deinit(krb5_context context,
                            struct crossrealm_tgt_info *info)
{
    /* Free talloc context which frees all talloc-allocated strings */
    if (info->memctx)
        talloc_free(info->memctx);
}

/* Validate that mandatory PAC attributes are present
 * PAC_LOGON_INFO and PAC_CLIENT_INFO must be present in all AD PACs.
 */
static krb5_error_code
ipadb_validate_pac_attributes(krb5_context context,
                              const struct crossrealm_tgt_info *info,
                              const char **status)
{
    /* PAC_LOGON_INFO is mandatory */
    if (!info->logon_info_present) {
        *status = "TRUST_PAC_MISSING_LOGON_INFO";
        return ENOENT;
    }

    /* Verify account_name was successfully extracted from LOGON_INFO */
    if (!info->account_name) {
        *status = "TRUST_PAC_MISSING_ACCOUNT_NAME";
        return ENOENT;
    }

    /* PAC_CLIENT_INFO is mandatory */
    if (!info->client_info_present) {
        *status = "TRUST_PAC_MISSING_CLIENT_INFO";
        return ENOENT;
    }

    /* Verify client_name was successfully extracted from CLIENT_INFO */
    if (!info->client_name) {
        *status = "TRUST_PAC_MISSING_CLIENT_NAME";
        return ENOENT;
    }

    return 0;
}

/* Extract PAC buffers and populate the check info structure with trust
 * validation data. The info structure will contain pointers to data
 * allocated in info->memctx.
 */
static krb5_error_code
ipadb_extract_crtgt_info(krb5_context context,
                         krb5_const_principal client_princ,
                         const krb5_pac pac,
                         struct crossrealm_tgt_info *info,
                         const char **status)
{
    krb5_error_code kerr = EINVAL;
    krb5_data linfo_blob = {0}, upn_blob = {0}, cinfo_blob = {0};
    krb5_data req_sid_blob = {0};
    DATA_BLOB linfo_data, upn_data, cinfo_data, req_sid_data;
    struct PAC_LOGON_INFO_CTR logon_info;
    union PAC_INFO upn_info;
    union PAC_INFO client_info;
    union PAC_INFO req_sid_info;
    enum ndr_err_code ndr_err;

    /* Store client principal */
    info->client_princ = client_princ;

    /* Set request type flags */
    info->is_enterprise_princ =
        (client_princ->type == KRB5_NT_ENTERPRISE_PRINCIPAL);

    /* Extract Type 1 - PRIMARY SID SOURCE
     * MS-PAC: KERB_VALIDATION_INFO
     * Samba: PAC_LOGON_INFO
     * Wireshark: Logon Info */
    kerr = krb5_pac_get_buffer(context, pac, KRB5_PAC_LOGON_INFO, &linfo_blob);
    if (kerr) {
        info->logon_info_present = false;
    } else {
        info->logon_info_present = true;

        linfo_data.length = linfo_blob.length;
        linfo_data.data = (uint8_t *)linfo_blob.data;
        ndr_err = ndr_pull_union_blob(&linfo_data, info->memctx, &logon_info,
                                      PAC_TYPE_LOGON_INFO,
                                      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
        krb5_free_data_contents(context, &linfo_blob);

        if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
            *status = "TRUST_PAC_CANNOT_PARSE_LOGON_INFO";
            kerr = EINVAL;
            goto end;
        }

        /* Check if logon_info structure is valid */
        if (!logon_info.info) {
            *status = "TRUST_PAC_LOGON_INFO_UNDEFINED";
            kerr = EINVAL;
            goto end;
        }

        /* Store pointer to account name */
        info->account_name = logon_info.info->info3.base.account_name.string;
        if (!info->account_name) {
            *status = "TRUST_PAC_ACCOUNT_NAME_UNDEFINED";
            kerr = EINVAL;
            goto end;
        }

        /* Extract and copy requester SID structure */
        kerr = ipadb_get_sid_from_pac(info->memctx, logon_info.info,
                                      &info->logon_info_sid);
        if (kerr) {
            *status = "TRUST_PAC_CANNOT_EXTRACT_SID";
            goto end;
        }

        /* Convert SID to string and store pointer */
        info->logon_info_sid_string = dom_sid_string(info->memctx,
                                                      &info->logon_info_sid);
        if (!info->logon_info_sid_string) {
            *status = "TRUST_PAC_CANNOT_CONVERT_SID";
            kerr = ENOMEM;
            goto end;
        }
    }

    /* Extract Type 10 - CLIENT NAME
     * MS-PAC: PAC_CLIENT_INFO
     * Samba: PAC_LOGON_NAME
     * Wireshark: Client Info Type */
    kerr = krb5_pac_get_buffer(context, pac, 10, &cinfo_blob);
    if (kerr) {
        info->client_info_present = false;
    } else {
        info->client_info_present = true;

        cinfo_data.length = cinfo_blob.length;
        cinfo_data.data = (uint8_t *)cinfo_blob.data;
        ndr_err = ndr_pull_union_blob(&cinfo_data, info->memctx,
                                      &client_info,
                                      PAC_TYPE_LOGON_NAME,
                                      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
        krb5_free_data_contents(context, &cinfo_blob);

        if (NDR_ERR_CODE_IS_SUCCESS(ndr_err))
            info->client_name = client_info.logon_name.account_name;
    }

    /* Extract Type 12 - PRIMARY UPN SOURCE
     * MS-PAC: UPN_DNS_INFO
     * Samba: PAC_UPN_DNS_INFO
     * Wireshark: UPN DNS Info */
    kerr = krb5_pac_get_buffer(context, pac, KRB5_PAC_UPN_DNS_INFO, &upn_blob);
    if (kerr) {
        info->upn_dns_info_present = false;
    } else {
        info->upn_dns_info_present = true;

        upn_data.length = upn_blob.length;
        upn_data.data = (uint8_t *)upn_blob.data;
        ndr_err = ndr_pull_union_blob(&upn_data, info->memctx, &upn_info,
                                      PAC_TYPE_UPN_DNS_INFO,
                                      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
        krb5_free_data_contents(context, &upn_blob);

        if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
            *status = "TRUST_PAC_CANNOT_PARSE_UPN_DNS_INFO";
            kerr = EINVAL;
            goto end;
        }

        /* Store pointer to UPN string */
        info->upn = upn_info.upn_dns_info.upn_name;
        if (info->upn)
            info->upn_is_qualified = (NULL != strchr(info->upn, '@'));

        /* Extract U flag - indicates constructed UPN */
        info->upn_is_constructed =
            (upn_info.upn_dns_info.flags & PAC_UPN_DNS_FLAG_CONSTRUCTED) != 0;

        /* Check for extended format (S flag) */
        info->upn_has_sam_and_sid =
            (upn_info.upn_dns_info.flags &
             PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID) != 0;

        if (info->upn_has_sam_and_sid) {
            /* Store pointer to SAM name from extended format */
            info->upn_sam_name =
                upn_info.upn_dns_info.ex.sam_name_and_sid.samaccountname;

            /* Copy SID structure from extended format */
            if (upn_info.upn_dns_info.ex.sam_name_and_sid.objectsid)
                memcpy(&info->upn_sid,
                       upn_info.upn_dns_info.ex.sam_name_and_sid.objectsid,
                       sizeof(struct dom_sid));
        }
    }

    /* Extract Type 18 - REQUESTER SID (WS2019+)
     * MS-PAC: PAC_REQUESTER_SID
     * Samba: PAC_REQUESTER_SID
     * Wireshark: Requester Sid */
    kerr = krb5_pac_get_buffer(context, pac, 18, &req_sid_blob);
    if (kerr) {
        info->requester_sid_present = false;
    } else {
        info->requester_sid_present = true;

        req_sid_data.length = req_sid_blob.length;
        req_sid_data.data = (uint8_t *)req_sid_blob.data;

        ndr_err = ndr_pull_union_blob(&req_sid_data, info->memctx,
                                      &req_sid_info,
                                      PAC_TYPE_REQUESTER_SID,
                                      (ndr_pull_flags_fn_t)ndr_pull_PAC_INFO);
        krb5_free_data_contents(context, &req_sid_blob);

        if (NDR_ERR_CODE_IS_SUCCESS(ndr_err))
            memcpy(&info->requester_sid, &req_sid_info.requester_sid.sid,
                   sizeof(struct dom_sid));
    }

    kerr = 0;

end:
    return kerr;
}

/* Cross-validate PAC attributes for consistency
 * All available attributes must match across different PAC buffers.
 * LOGON_INFO and CLIENT_INFO must be present (asserted).
 */
static krb5_error_code
ipadb_cross_validate_pac_attributes(krb5_context context,
                                    const struct crossrealm_tgt_info *info,
                                    const char **status)
{
    krb5_error_code kerr = EINVAL;
    const char *at_sign = NULL;
    char *ticket_cname = NULL;
    size_t name_len;

    /* Mandatory PAC attributes must have been validated already */
    assert(info->logon_info_present);
    assert(info->client_info_present);

    /* Validate UPN matches ticket cname (for enterprise principals) */
    if (info->is_enterprise_princ && info->upn_dns_info_present) {
        /* Unparse client principal name (without realm) */
        kerr = krb5_unparse_name_flags(context, info->client_princ,
                                       KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                       &ticket_cname);
        if (kerr) {
            *status = "TRUST_CANNOT_UNPARSE_CNAME";
            goto end;
        }

        /* Find the @ sign in UPN */
        at_sign = strchr(info->upn, '@');
        if (at_sign) {
            name_len = at_sign - info->upn;

            /* Compare UPN name part with ticket cname */
            if (0 != strncmp(info->upn, ticket_cname, name_len) ||
                ticket_cname[name_len] != '\0') {
                *status = "TRUST_PAC_UPN_CNAME_MISMATCH";
                kerr = EINVAL;
                goto end;
            }
        }

        krb5_free_unparsed_name(context, ticket_cname);
        ticket_cname = NULL;
    }

    /* Cross-validate account names if extended UPN format is available */
    if (info->upn_has_sam_and_sid) {
        if (!info->account_name || !info->upn_sam_name ||
            0 != strcmp(info->account_name, info->upn_sam_name)) {
            *status = "TRUST_PAC_ACCOUNT_NAME_MISMATCH";
            kerr = EINVAL;
            goto end;
        }
    }

    /* Cross-validate client name matches account name */
    if (info->client_info_present) {
        if (!info->client_name || !info->account_name ||
            0 != strcmp(info->client_name, info->account_name)) {
            *status = "TRUST_PAC_CLIENT_NAME_MISMATCH";
            kerr = EINVAL;
            goto end;
        }
    }

    /* Cross-validate SIDs if extended UPN format is available */
    if (info->upn_has_sam_and_sid) {
        if (!dom_sid_check(&info->logon_info_sid,
                           &info->upn_sid, true)) {
            *status = "TRUST_PAC_UPN_SID_MISMATCH";
            kerr = EINVAL;
            goto end;
        }
    }

    /* Cross-validate SID from REQUESTER_SID buffer if present */
    if (info->requester_sid_present) {
        if (!dom_sid_check(&info->logon_info_sid,
                           &info->requester_sid, true)) {
            *status = "TRUST_PAC_REQUESTER_SID_MISMATCH";
            kerr = EINVAL;
            goto end;
        }
    }

    kerr = 0;

end:
    if (ticket_cname)
        krb5_free_unparsed_name(context, ticket_cname);

    return kerr;
}

/* Check Default Trust View override username consistency
 * If a user override exists for this SID in the Default Trust View,
 * verify that the override username matches the ticket cname.
 * LOGON_INFO and CLIENT_INFO must be present (asserted).
 */
static krb5_error_code
ipadb_check_trust_view_override(krb5_context context,
                                 const struct crossrealm_tgt_info *info,
                                 const char **status)
{
    struct ipadb_context *ipactx = NULL;
    krb5_error_code kerr = EINVAL;
    char *basedn = NULL, *filter = NULL, *attrs[] = {"uid", NULL};
    LDAPMessage *res = NULL, *entry = NULL;
    struct berval **uid_values = NULL;
    char *ticket_cname = NULL;
    int count;

    /* Mandatory PAC attributes must have been validated already */
    assert(info->logon_info_present);
    assert(info->client_info_present);

    /* Get IPA context */
    ipactx = ipadb_get_context(context);
    if (!ipactx) {
        kerr = KRB5_KDB_DBNOTINITED;
        goto end;
    }

    /* Build LDAP query to check if this SID has an override in the
     * Default Trust View */
    kerr = asprintf(&basedn, "cn=Default Trust View,cn=views,cn=accounts,%s",
                    ipactx->base);
    if (kerr < 0) {
        *status = "TRUST_OUT_OF_MEMORY";
        kerr = ENOMEM;
        goto end;
    }

    kerr = asprintf(&filter,
                    "(&(objectClass=ipaUserOverride)(ipaAnchorUUID=:SID:%s))",
                    info->logon_info_sid_string);
    if (kerr < 0) {
        *status = "TRUST_OUT_OF_MEMORY";
        kerr = ENOMEM;
        goto end;
    }

    /* Search for user override entry in the Default Trust View */
    kerr = ipadb_simple_search(ipactx, basedn, LDAP_SCOPE_SUBTREE, filter,
                               attrs, &res);
    if (kerr) {
        *status = "TRUST_CANNOT_QUERY_TRUST_VIEW";
        goto end;
    }

    /* Check if any entries found */
    count = ldap_count_entries(ipactx->lcontext, res);

    if (count == 0) {
        /* No override exists - this is fine, just skip the check */
        kerr = 0;
        goto end;
    }

    /* Override exists - verify the username matches the ticket cname */
    entry = ldap_first_entry(ipactx->lcontext, res);
    if (!entry) {
        *status = "TRUST_CANNOT_READ_OVERRIDE_ENTRY";
        kerr = EINVAL;
        goto end;
    }

    uid_values = ldap_get_values_len(ipactx->lcontext, entry, "uid");
    if (!uid_values || !uid_values[0]) {
        *status = "TRUST_OVERRIDE_UID_UNDEFINED";
        kerr = EINVAL;
        goto end;
    }

    /* Unparse client principal name (without realm) */
    kerr = krb5_unparse_name_flags(context, info->client_princ,
                                   KRB5_PRINCIPAL_UNPARSE_NO_REALM,
                                   &ticket_cname);
    if (kerr) {
        *status = "TRUST_CANNOT_UNPARSE_CNAME";
        goto end;
    }

    /* Compare override username with ticket cname */
    if (0 != strncmp(uid_values[0]->bv_val, ticket_cname,
                     uid_values[0]->bv_len) ||
        '\0' != ticket_cname[uid_values[0]->bv_len]) {
        *status = "TRUST_OVERRIDE_UID_CNAME_MISMATCH";
        kerr = KRB5KDC_ERR_POLICY;
        goto end;
    }

    kerr = 0;

end:
    if (uid_values)
        ldap_value_free_len(uid_values);
    if (ticket_cname)
        krb5_free_unparsed_name(context, ticket_cname);
    if (res)
        ldap_msgfree(res);
    if (filter)
        free(filter);
    if (basedn)
        free(basedn);

    return kerr;
}

/* Check that enterprise principal has qualified UPN in PAC
 * UPN MUST be qualified if it is NOT constructed (U flag not set).
 * LOGON_INFO and CLIENT_INFO must be present (asserted).
 */
static krb5_error_code
ipadb_check_upn_qualified(krb5_context context,
                          const struct crossrealm_tgt_info *info,
                          const char **status)
{
    /* Mandatory PAC attributes must have been validated already */
    assert(info->logon_info_present);
    assert(info->client_info_present);

    /* Only enforce for enterprise principals */
    if (!info->is_enterprise_princ)
        return 0;

    /* UPN DNS info MUST be present for enterprise principals */
    if (!info->upn_dns_info_present) {
        *status = "TRUST_ENTERPRISE_PRINCIPAL_WITHOUT_UPN_DNS_INFO";
        return KRB5KDC_ERR_POLICY;
    }

    /* If UPN is constructed (U flag set), it's inherently qualified by AD.
     * Skip qualification check for constructed UPNs.
     */
    if (info->upn_is_constructed)
        return 0;

    /* For explicit (non-constructed) UPNs, MUST be qualified (contain '@') */
    if (!info->upn_is_qualified) {
        *status = "TRUST_ENTERPRISE_PRINCIPAL_WITH_UNQUALIFIED_UPN";
        return KRB5KDC_ERR_POLICY;
    }

    return 0;
}

/* Main function to check trust PAC content
 *
 * Performs security checks on trust TGS-REQ:
 * 1. Cross-validation - verify PAC attributes consistency
 * 2. User registration - requester SID must exist in Default Trust View
 * 3. UPN qualification - enterprise principals must have qualified UPN
 *    (if not constructed)
 */
krb5_error_code
ipadb_check_trust_pac_content(krb5_context context,
                              const krb5_kdc_req *request,
                              const krb5_ticket *ticket,
                              const krb5_pac pac,
                              const char **status)
{
    struct crossrealm_tgt_info info;
    krb5_error_code kerr = EINVAL;

    /* Initialize PAC check info structure and create talloc context */
    kerr = ipadb_trust_pac_info_init(&info);
    if (kerr) {
        *status = "TRUST_OUT_OF_MEMORY";
        goto end;
    }

    /* Extract PAC buffers and populate structure */
    kerr = ipadb_extract_crtgt_info(context, ticket->enc_part2->client,
                                    pac, &info, status);
    if (kerr)
        goto end;

    /* Validate mandatory PAC attributes are present */
    kerr = ipadb_validate_pac_attributes(context, &info, status);
    if (kerr)
        goto end;

    /* Check 1: Cross-validate all PAC attributes for consistency */
    kerr = ipadb_cross_validate_pac_attributes(context, &info, status);
    if (kerr)
        goto end;

    /* Check 2: If user override exists, verify username matches cname */
    kerr = ipadb_check_trust_view_override(context, &info, status);
    if (kerr)
        goto end;

    /* Check 3: Enterprise principal must have qualified UPN
     * (if not constructed) */
    kerr = ipadb_check_upn_qualified(context, &info, status);
    if (kerr)
        goto end;

    /* All checks passed */
    *status = NULL;
    kerr = 0;

end:
    /* Cleanup - frees talloc context and krb5 allocations */
    ipadb_trust_pac_info_deinit(context, &info);

    return kerr;
}
