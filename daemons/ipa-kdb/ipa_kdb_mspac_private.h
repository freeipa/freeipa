/*
 * MIT Kerberos KDC database backend for FreeIPA
 * This head file contains private declarations for ipa_kdb_mspac.c and should
 * be used only there or in unit-test.
 *
 * Authors: Sumit Bose <sbose@redhat.com>
 *
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

#pragma once

struct ipadb_mspac {
    char *flat_domain_name;
    char *flat_server_name;
    struct dom_sid domsid;

    char *fallback_group;
    uint32_t fallback_rid;

    int num_trusts;
    struct ipadb_adtrusts *trusts;
    time_t last_update;
};

struct ipadb_adtrusts {
    char *domain_name;
    char *flat_name;
    char *domain_sid;
    struct dom_sid domsid;
    struct dom_sid *sid_blacklist_incoming;
    int len_sid_blacklist_incoming;
    struct dom_sid *sid_blacklist_outgoing;
    int len_sid_blacklist_outgoing;
    struct ipadb_adtrusts *parent;
    char *parent_name;
    char **upn_suffixes;
};

int string_to_sid(const char *str, struct dom_sid *sid);
char *dom_sid_string(TALLOC_CTX *memctx, const struct dom_sid *dom_sid);
krb5_error_code filter_logon_info(krb5_context context, TALLOC_CTX *memctx,
                                  krb5_data realm, struct PAC_LOGON_INFO_CTR *info);
void get_authz_data_types(krb5_context context, krb5_db_entry *entry,
                          bool *_with_pac, bool *_with_pad);