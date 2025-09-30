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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

/* although we have nothing to do with SECURID yet, there are a
 * couple of TL_DATA Ids that need it to be available.
 * We need them to be avilable even if SECURID is not used for
 * filtering purposes */
#define SECURID 1

#include "config.h"

#include <errno.h>
#include <kdb.h>
#include <ldap.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <endian.h>
#include <unistd.h>
#ifdef HAVE_KRB5_CERTAUTH_PLUGIN
#include <krb5/certauth_plugin.h>
#endif

#include "ipa_krb5.h"
#include "ipa_pwd.h"

/* Difference between krb5 1.20 and previous versions. From
 * krb5 commit a441fbe329ebbd7775eb5d4ccc4a05eef370f08b:
 *   Combine the KRB5_KDB_FLAG_ISSUE_PAC and
 *   KRB5_FLAG_CLIENT_REFERRALS_ONLY flags into KRB5_KDB_FLAG_CLIENT.
 *
 *   Rename the KRB5_KDB_FLAG_CANONICALIZE flag to
 *   KRB5_KDB_FLAG_REFERRAL_OK, and only pass it to get_principal() for
 *   lookup operations that can use a realm referral.
 * */
#if defined(KRB5_KDB_FLAG_CLIENT)
#define CLIENT_REFERRALS_FLAGS (KRB5_KDB_FLAG_REFERRAL_OK)
#else
#define CLIENT_REFERRALS_FLAGS (KRB5_KDB_FLAG_CLIENT_REFERRALS_ONLY)
#endif


/* easier to copy the defines here than to mess with kadm5/admin.h
 * for now */
#define KMASK_PRINCIPAL         0x000001
#define KMASK_PRINC_EXPIRE_TIME 0x000002
#define KMASK_PW_EXPIRATION     0x000004
#define KMASK_LAST_PWD_CHANGE   0x000008
#define KMASK_ATTRIBUTES        0x000010
#define KMASK_MAX_LIFE          0x000020
#define KMASK_MOD_TIME          0x000040
#define KMASK_MOD_NAME          0x000080
#define KMASK_KVNO              0x000100
#define KMASK_MKVNO             0x000200
#define KMASK_AUX_ATTRIBUTES    0x000400
#define KMASK_POLICY            0x000800
#define KMASK_POLICY_CLR        0x001000
/* version 2 masks */
#define KMASK_MAX_RLIFE         0x002000
#define KMASK_LAST_SUCCESS      0x004000
#define KMASK_LAST_FAILED       0x008000
#define KMASK_FAIL_AUTH_COUNT   0x010000
#define KMASK_KEY_DATA          0x020000
#define KMASK_TL_DATA           0x040000
#define KMASK_LOAD              0x200000

#define IPA_SETUP "ipa-setup-override-restrictions"

#define IPA_KRB_AUTHZ_DATA_ATTR "ipaKrbAuthzData"
#define IPA_USER_AUTH_TYPE "ipaUserAuthType"

/* Virtual managed ticket flags like "-allow_tix", are always controlled by the
 * "nsAccountLock" attribute, such flags should never be set in the database.
 * The following expression combine all of them, and is used to filter them
 * out. */
#define IPA_KDB_TKTFLAGS_VIRTUAL_MANAGED_ALL          (KRB5_KDB_DISALLOW_ALL_TIX)

/* Virtual static ticket flags are hard-coded in the KDB driver. */
/*   Virtual static mandatory flags are set systematically and implicitly for all
 *   principals. They are filtered out from database ticket flags updates.
 *   (However, "KRB5_KDB_REQUIRES_PRE_AUTH" can still be unset by the
 *   "KDC:Disable Default Preauth for SPNs" global setting) */
#define IPA_KDB_TKTFLAGS_VIRTUAL_STATIC_MANDATORY     (KRB5_KDB_REQUIRES_PRE_AUTH)
/*   Virtual static default ticket flags are implicitly set for user and non-user
 *   (SPN) principals, and not stored in the database.
 *   (Except if the "IPA_KDB_STRATTR_FINAL_TKTFLAGS" string attribute is "true"
 *   the principal) */
/*     Virtual static default user ticket flags are set for users only. The
 *     "-allow_svr" flag is set to protect them from CVE-2024-3183. */
#define IPA_KDB_TKTFLAGS_VIRTUAL_STATIC_DEFAULTS_USER (KRB5_KDB_DISALLOW_SVR)
#define IPA_KDB_TKTFLAGS_VIRTUAL_STATIC_DEFAULTS_SPN  (0)

/* If this string attribute is set to "true", then only the virtual managed and
 * virtual static mandatory ticket flags are applied and filtered out from
 * database read and write operations for the concerned user principal.
 * Configurable principal ticket flags are applied, but not the configurable
 * global ticket policy flags. */
#define IPA_KDB_STRATTR_FINAL_USER_TKTFLAGS "final_user_tkt_flags"

struct ipadb_mspac;
struct dom_sid;

enum ipadb_user_auth {
  IPADB_USER_AUTH_NONE     = 0,
  IPADB_USER_AUTH_DISABLED = 1 << 0,
  IPADB_USER_AUTH_PASSWORD = 1 << 1,
  IPADB_USER_AUTH_RADIUS   = 1 << 2,
  IPADB_USER_AUTH_OTP      = 1 << 3,
  IPADB_USER_AUTH_PKINIT   = 1 << 4,
  IPADB_USER_AUTH_HARDENED = 1 << 5,
  IPADB_USER_AUTH_IDP      = 1 << 6,
  IPADB_USER_AUTH_PASSKEY  = 1 << 7,
};

enum ipadb_user_auth_idx {
  IPADB_USER_AUTH_IDX_OTP = 0,
  IPADB_USER_AUTH_IDX_RADIUS,
  IPADB_USER_AUTH_IDX_PKINIT,
  IPADB_USER_AUTH_IDX_HARDENED,
  IPADB_USER_AUTH_IDX_IDP,
  IPADB_USER_AUTH_IDX_PASSKEY,
  IPADB_USER_AUTH_IDX_MAX,
};

struct ipadb_global_config {
	time_t last_update;
	bool disable_last_success;
	bool disable_lockout;
	char **authz_data;
	enum ipadb_user_auth user_auth;
    bool disable_preauth_for_spns;
};

enum ipadb_tristate_option {
	IPADB_TRISTATE_FALSE = FALSE,
	IPADB_TRISTATE_TRUE = TRUE,
	IPADB_TRISTATE_UNDEFINED,
};

#define IPA_CONTEXT_MAGIC 0x0c027ea7
struct ipadb_context {
    int magic;
    char *uri;
    char *base;
    char *realm;
    char *realm_base;
    char *accounts_base;
    const char *kdc_hostname;
    LDAP *lcontext;
    krb5_context kcontext;
    bool override_restrictions;
    krb5_key_salt_tuple *supp_encs;
    int n_supp_encs;
    krb5_key_salt_tuple *def_encs;
    int n_def_encs;
    struct ipadb_mspac *mspac;
    enum ipadb_tristate_option optional_pac_tkt_chksum;
#ifdef HAVE_KRB5_CERTAUTH_PLUGIN
    krb5_certauth_moddata certauth_moddata;
#endif

    /* Don't access this directly, use ipadb_get_global_config(). */
    struct ipadb_global_config config;

    krb5_principal local_tgs;
};

struct ipadb_e_pol_limits {
    krb5_deltat max_life;
    krb5_deltat max_renewable_life;
};

#define IPA_E_DATA_MAGIC 0x0eda7a
struct ipadb_e_data {
    int magic;
    bool ipa_user;
    char *entry_dn;
    char *passwd;
    char *user;
    time_t last_pwd_change;
    char *pw_policy_dn;
    char **pw_history;
    struct ipapwd_policy *pol;
    time_t last_admin_unlock;
    char **authz_data;
    bool has_tktpolaux;
    enum ipadb_user_auth user_auth;
    struct ipadb_e_pol_limits pol_limits[IPADB_USER_AUTH_IDX_MAX];
    bool has_sid;
    struct dom_sid *sid;
};

inline static krb5_error_code
ipadb_get_edata(krb5_db_entry *entry, struct ipadb_e_data **ied)
{
    struct ipadb_e_data *in_ied;

    in_ied = (struct ipadb_e_data *)entry->e_data;
    if (!in_ied || in_ied->magic != IPA_E_DATA_MAGIC)
        return EINVAL;

    if (ied)
        *ied = in_ied;

    return 0;
}

struct ipadb_context *ipadb_get_context(krb5_context kcontext);
int ipadb_get_connection(struct ipadb_context *ipactx);

/* COMMON LDAP FUNCTIONS */
char *ipadb_filter_escape(const char *input, bool star);
krb5_error_code ipadb_simple_search(struct ipadb_context *ipactx,
                                    char *basedn, int scope,
                                    char *filter, char **attrs,
                                    LDAPMessage **res);
krb5_error_code ipadb_simple_delete(struct ipadb_context *ipactx, char *dn);
krb5_error_code ipadb_simple_add(struct ipadb_context *ipactx,
                                 char *dn, LDAPMod **mods);
krb5_error_code ipadb_simple_modify(struct ipadb_context *ipactx,
                                    char *dn, LDAPMod **mods);
krb5_error_code ipadb_simple_delete_val(struct ipadb_context *ipactx,
                                        char *dn, char *attr, char *value);
krb5_error_code ipadb_deref_search(struct ipadb_context *ipactx,
                                   char *base_dn, int scope,
                                   char *filter,
                                   char **entry_attrs,
                                   char **deref_attr_names,
                                   char **deref_attrs,
                                   LDAPMessage **res);

int ipadb_ldap_attr_to_int(LDAP *lcontext, LDAPMessage *le,
                           char *attrname, int *result);
int ipadb_ldap_attr_to_uint32(LDAP *lcontext, LDAPMessage *le,
                              char *attrname, uint32_t *result);
int ipadb_ldap_attr_to_str(LDAP *lcontext, LDAPMessage *le,
                           char *attrname, char **result);
int ipadb_ldap_attr_to_strlist(LDAP *lcontext, LDAPMessage *le,
                               char *attrname, char ***result);
int ipadb_ldap_attr_to_bool(LDAP *lcontext, LDAPMessage *le,
                            char *attrname, bool *result);
int ipadb_ldap_attr_to_time_t(LDAP *lcontext, LDAPMessage *le,
                              char *attrname, time_t *result);
int ipadb_ldap_attr_to_krb5_timestamp(LDAP *lcontext, LDAPMessage *le,
                                      char *attrname, krb5_timestamp *result);

int ipadb_ldap_attr_has_value(LDAP *lcontext, LDAPMessage *le,
                              char *attrname, const char *value);
int ipadb_ldap_deref_results(LDAP *lcontext, LDAPMessage *le,
                             LDAPDerefRes **results);

krb5_error_code ipadb_get_tl_data(krb5_db_entry *entry,
                                  krb5_int16 type,
                                  krb5_ui_2 length,
                                  krb5_octet *data);

krb5_error_code ipadb_set_tl_data(krb5_db_entry *entry,
                                  krb5_int16 type,
                                  krb5_ui_2 length,
                                  const krb5_octet *data);

struct ipadb_multires;
krb5_error_code ipadb_multires_init(LDAP *lcontext, struct ipadb_multires **r);
void ipadb_multires_free(struct ipadb_multires *r);
LDAPMessage *ipadb_multires_next_entry(struct ipadb_multires *r);
krb5_error_code ipadb_multibase_search(struct ipadb_context *ipactx,
                                       char **basedns, int scope,
                                       char *filter, char **attrs,
                                       struct ipadb_multires **res,
                                       bool any);

/* PRINCIPALS FUNCTIONS */
krb5_error_code ipadb_get_principal(krb5_context kcontext,
                                    krb5_const_principal search_for,
                                    unsigned int flags,
                                    krb5_db_entry **entry);
void ipadb_free_principal(krb5_context kcontext, krb5_db_entry *entry);
/* Helper function for DAL API 6.1 or later */
void ipadb_free_principal_e_data(krb5_context kcontext, krb5_octet *e_data);
krb5_error_code ipadb_put_principal(krb5_context kcontext,
                                    krb5_db_entry *entry,
                                    char **db_args);
krb5_error_code ipadb_delete_principal(krb5_context kcontext,
                                       krb5_const_principal search_for);
krb5_error_code
ipadb_fetch_principals_with_extra_filter(struct ipadb_context *ipactx,
                                         unsigned int flags,
                                         const char *principal,
                                         const char *filter,
                                         LDAPMessage **result);
krb5_error_code ipadb_find_principal(krb5_context kcontext,
                                     unsigned int flags,
                                     LDAPMessage *res,
                                     char **principal,
                                     LDAPMessage **entry);
#if KRB5_KDB_API_VERSION < 8
krb5_error_code ipadb_iterate(krb5_context kcontext,
                              char *match_entry,
                              int (*func)(krb5_pointer, krb5_db_entry *),
                              krb5_pointer func_arg);
#else
krb5_error_code ipadb_iterate(krb5_context kcontext,
                              char *match_entry,
                              int (*func)(krb5_pointer, krb5_db_entry *),
                              krb5_pointer func_arg, krb5_flags iterflags);
#endif

/* POLICY FUNCTIONS */

krb5_error_code ipadb_get_ipapwd_policy(struct ipadb_context *ipactx,
                                        char *pw_policy_dn,
                                        struct ipapwd_policy **pol);

krb5_error_code ipadb_create_pwd_policy(krb5_context kcontext,
                                        osa_policy_ent_t policy);
krb5_error_code ipadb_get_pwd_policy(krb5_context kcontext, char *name,
                                     osa_policy_ent_t *policy);
krb5_error_code ipadb_put_pwd_policy(krb5_context kcontext,
                                     osa_policy_ent_t policy);
krb5_error_code ipadb_iterate_pwd_policy(krb5_context kcontext,
                                         char *match_entry,
                                         osa_adb_iter_policy_func func,
                                         void *data);
krb5_error_code ipadb_delete_pwd_policy(krb5_context kcontext,
                                        char *policy);
void ipadb_free_pwd_policy(krb5_context kcontext, osa_policy_ent_t val);

krb5_error_code ipadb_check_policy_as(krb5_context kcontext,
                                      krb5_kdc_req *request,
                                      krb5_db_entry *client,
                                      krb5_db_entry *server,
                                      krb5_timestamp kdc_time,
                                      const char **status,
                                      krb5_pa_data ***e_data);

/* MASTER KEY FUNCTIONS */
krb5_error_code ipadb_fetch_master_key(krb5_context kcontext,
                                       krb5_principal mname,
                                       krb5_keyblock *key,
                                       krb5_kvno *kvno,
                                       char *db_args);
krb5_error_code ipadb_store_master_key_list(krb5_context kcontext,
                                            char *db_arg,
                                            krb5_principal mname,
                                            krb5_keylist_node *keylist,
                                            char *master_pwd);

krb5_error_code ipadb_create_master_key(krb5_context kcontext);

/* PASSWORD FUNCTIONS */
krb5_error_code ipadb_change_pwd(krb5_context context,
                                 krb5_keyblock *master_key,
                                 krb5_key_salt_tuple *ks_tuple,
                                 int ks_tuple_count, char *passwd,
                                 int new_kvno, krb5_boolean keepold,
                                 krb5_db_entry *db_entry);

krb5_error_code ipadb_get_pwd_expiration(krb5_context context,
                                         krb5_db_entry *entry,
                                         struct ipadb_e_data *ied,
                                         time_t *expire_time);

/* MS-PAC FUNCTIONS */

#if (KRB5_KDB_DAL_MAJOR_VERSION < 9)
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
                                    krb5_authdata ***signed_auth_data);

#else
/* DAL 9 or later uses issue_pac */
krb5_error_code ipadb_v9_issue_pac(krb5_context context, unsigned int flags,
                                   krb5_db_entry *client,
                                   krb5_keyblock *replaced_reply_key,
                                   krb5_db_entry *server,
                                   krb5_db_entry *signing_krbtgt,
                                   krb5_timestamp authtime, krb5_pac old_pac,
                                   krb5_pac new_pac,
                                   krb5_data ***auth_indicators);
#endif

krb5_error_code ipadb_reinit_mspac(struct ipadb_context *ipactx,
                                   bool force_reinit,
                                   const char **stmsg);

void ipadb_mspac_struct_free(struct ipadb_mspac **mspac);
krb5_error_code ipadb_check_transited_realms(krb5_context kcontext,
					     const krb5_data *tr_contents,
					     const krb5_data *client_realm,
					     const krb5_data *server_realm);
/* Checks whether a principal's realm is one of trusted domains' realm or NetBIOS name
 * and returns the realm of the matched trusted domain in 'trusted_domain'
 * Returns 0 in case of success and KRB5_KDB_NOENTRY otherwise
 * If DAL driver is not initialized, returns KRB5_KDB_DBNOTINITED */
krb5_error_code ipadb_is_princ_from_trusted_realm(krb5_context kcontext,
                                                  const char *test_realm, size_t size,
                                                  char **trusted_realm);

/* Check the ticket provided in a TGS-REQ. In some situations, the ticket is
 * expected to contain a PAC. If it is not the case, or if the function is
 * enable to decode an authorization-data element, it fails.
 * Any failure should result in the TGS-REQ to be rejected. */
krb5_error_code ipadb_enforce_pac(krb5_context kcontext,
                                  const krb5_ticket *ticket,
                                  const char **status);

/* DELEGATION CHECKS */

krb5_error_code ipadb_check_allowed_to_delegate(krb5_context kcontext,
                                                krb5_const_principal client,
                                                const krb5_db_entry *server,
                                                krb5_const_principal proxy);

krb5_error_code ipadb_allowed_to_delegate_from(krb5_context context,
                                               krb5_const_principal client,
                                               krb5_const_principal server,
                                               krb5_pac server_pac,
                                               const krb5_db_entry *proxy);

/* AS AUDIT */

void ipadb_audit_as_req(krb5_context kcontext,
                        krb5_kdc_req *request,
#if (KRB5_KDB_DAL_MAJOR_VERSION >= 7)
                        const krb5_address *local_addr,
                        const krb5_address *remote_addr,
#endif
                        krb5_db_entry *client,
                        krb5_db_entry *server,
                        krb5_timestamp authtime,
                        krb5_error_code error_code);

/* AUTH METHODS */
void ipadb_parse_user_auth(LDAP *lcontext, LDAPMessage *le,
                           enum ipadb_user_auth *user_auth);
const struct ipadb_global_config *
ipadb_get_global_config(struct ipadb_context *ipactx);
int ipadb_get_enc_salt_types(struct ipadb_context *ipactx, LDAPMessage *entry,
                             char *attr, krb5_key_salt_tuple **enc_salt_types,
                             int *n_enc_salt_types);

#ifdef HAVE_KRB5_CERTAUTH_PLUGIN
/* CERTAUTH PLUGIN */
void ipa_certauth_free_moddata(krb5_certauth_moddata *moddata);
#endif

int ipadb_string_to_sid(const char *str, struct dom_sid *sid);
void alloc_sid(struct dom_sid **sid);
void free_sid(struct dom_sid **sid);
bool dom_sid_check(const struct dom_sid *sid1, const struct dom_sid *sid2, bool exact_check);
bool ipadb_is_tgs_princ(krb5_context kcontext, krb5_const_principal princ);
