#define HAVE_IMMEDIATE_STRUCTURES 1
#define LDAP_DEPRECATED 1

#include "config.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <errno.h>
#include <ldap.h>
#include <krb5/krb5.h>

#include <talloc.h>

#include <param.h>
#include <ndr.h>
#include <util/data_blob.h>
#include <util/time.h>
#include <util/debug.h>

#ifndef _SAMBA_UTIL_H_
bool trim_string(char *s, const char *front, const char *back);
char *smb_xstrdup(const char *s);
#endif

#include <core/ntstatus.h>
#include <gen_ndr/security.h>
#include <smbldap.h>

#include <gen_ndr/samr.h>

#include <passdb.h>

#include <sasl/sasl.h>
#include <krb5/krb5.h>
#include <sss_idmap.h>
#include "ipa_asn1.h"
#include "ipa_pwd.h"
#include "ipa_mspac.h"

/* from drsblobs.h */
struct AuthInfoNone {
	uint32_t size;/* [value(0)] */
};

struct AuthInfoNT4Owf {
	uint32_t size;/* [value(16)] */
	struct samr_Password password;
};

struct AuthInfoClear {
	uint32_t size;
	uint8_t *password;
};

struct AuthInfoVersion {
	uint32_t size;/* [value(4)] */
	uint32_t version;
};

union AuthInfo {
	struct AuthInfoNone none;/* [case(TRUST_AUTH_TYPE_NONE)] */
	struct AuthInfoNT4Owf nt4owf;/* [case(TRUST_AUTH_TYPE_NT4OWF)] */
	struct AuthInfoClear clear;/* [case(TRUST_AUTH_TYPE_CLEAR)] */
	struct AuthInfoVersion version;/* [case(TRUST_AUTH_TYPE_VERSION)] */
}/* [nodiscriminant] */;

struct AuthenticationInformation {
	NTTIME LastUpdateTime;
	enum lsa_TrustAuthType AuthType;
	union AuthInfo AuthInfo;/* [switch_is(AuthType)] */
	DATA_BLOB _pad;/* [flag(LIBNDR_FLAG_ALIGN4)] */
}/* [public] */;

struct AuthenticationInformationArray {
	uint32_t count;
	struct AuthenticationInformation *array;
}/* [gensize,nopush,public,nopull] */;

struct trustAuthInOutBlob {
	uint32_t count;
	uint32_t current_offset;/* [value((count>0)?12:0)] */
	uint32_t previous_offset;/* [value((count>0)?12+ndr_size_AuthenticationInformationArray(&current,ndr->flags):0)] */
	struct AuthenticationInformationArray current;/* [subcontext_size((previous_offset)-(current_offset)),subcontext(0)] */
	struct AuthenticationInformationArray previous;/* [subcontext(0),flag(LIBNDR_FLAG_REMAINING)] */
}/* [gensize,public,nopush] */;

/* from generated idmap.h - hopefully OK */
enum id_type {
	ID_TYPE_NOT_SPECIFIED,
	ID_TYPE_UID,
	ID_TYPE_GID,
	ID_TYPE_BOTH
};

struct unixid {
	uint32_t id;
	enum id_type type;
}/* [public] */;

enum ndr_err_code ndr_pull_trustAuthInOutBlob(struct ndr_pull *ndr, int ndr_flags, struct trustAuthInOutBlob *r); /*available in libndr-samba.so */
bool sid_check_is_builtin(const struct dom_sid *sid); /* available in libpdb.so */
/* available in libpdb.so, renamed from sid_check_is_domain() in c43505b621725c9a754f0ee98318d451b093f2ed */
bool sid_linearize(char *outbuf, size_t len, const struct dom_sid *sid); /* available in libsmbconf.so */
char *escape_ldap_string(TALLOC_CTX *mem_ctx, const char *s); /* available in libsmbconf.so */
bool secrets_store(const char *key, const void *data, size_t size); /* available in libpdb.so */
void idmap_cache_set_sid2unixid(const struct dom_sid *sid, struct unixid *unix_id); /* available in libsmbconf.so */
bool E_md4hash(const char *passwd, uint8_t p16[16]); /* available in libcliauth-samba4.so */

#define LDAP_OBJ_SAMBASAMACCOUNT "ipaNTUserAttrs"
#define LDAP_OBJ_TRUSTED_DOMAIN "ipaNTTrustedDomain"
#define LDAP_OBJ_ID_OBJECT "ipaIDobject"
#define LDAP_ATTRIBUTE_TRUST_SID "ipaNTTrustedDomainSID"
#define LDAP_ATTRIBUTE_SID "ipaNTSecurityIdentifier"
#define LDAP_OBJ_GROUPMAP "ipaNTGroupAttrs"

#define IPA_KEYTAB_SET_OID "2.16.840.1.113730.3.8.10.1"
#define IPA_KEYTAB_SET_OID_OLD "2.16.840.1.113730.3.8.3.1"
#define IPA_MAGIC_ID_STR "-1"

#define LDAP_ATTRIBUTE_CN "cn"
#define LDAP_ATTRIBUTE_UID "uid"
#define LDAP_ATTRIBUTE_TRUST_TYPE "ipaNTTrustType"
#define LDAP_ATTRIBUTE_TRUST_ATTRIBUTES "ipaNTTrustAttributes"
#define LDAP_ATTRIBUTE_TRUST_DIRECTION "ipaNTTrustDirection"
#define LDAP_ATTRIBUTE_TRUST_POSIX_OFFSET "ipaNTTrustPosixOffset"
#define LDAP_ATTRIBUTE_SUPPORTED_ENC_TYPE "ipaNTSupportedEncryptionTypes"
#define LDAP_ATTRIBUTE_TRUST_PARTNER "ipaNTTrustPartner"
#define LDAP_ATTRIBUTE_FLAT_NAME "ipaNTFlatName"
#define LDAP_ATTRIBUTE_TRUST_AUTH_OUTGOING "ipaNTTrustAuthOutgoing"
#define LDAP_ATTRIBUTE_TRUST_AUTH_INCOMING "ipaNTTrustAuthIncoming"
#define LDAP_ATTRIBUTE_SECURITY_IDENTIFIER "ipaNTSecurityIdentifier"
#define LDAP_ATTRIBUTE_TRUST_FOREST_TRUST_INFO "ipaNTTrustForestTrustInfo"
#define LDAP_ATTRIBUTE_FALLBACK_PRIMARY_GROUP "ipaNTFallbackPrimaryGroup"
#define LDAP_ATTRIBUTE_OBJECTCLASS "objectClass"
#define LDAP_ATTRIBUTE_HOME_DRIVE "ipaNTHomeDirectoryDrive"
#define LDAP_ATTRIBUTE_HOME_PATH "ipaNTHomeDirectory"
#define LDAP_ATTRIBUTE_HOMEDIRECTORY "homeDirectory"
#define LDAP_ATTRIBUTE_LOGON_SCRIPT "ipaNTLogonScript"
#define LDAP_ATTRIBUTE_PROFILE_PATH "ipaNTProfilePath"
#define LDAP_ATTRIBUTE_SID_BLACKLIST_INCOMING "ipaNTSIDBlacklistIncoming"
#define LDAP_ATTRIBUTE_SID_BLACKLIST_OUTGOING "ipaNTSIDBlacklistOutgoing"
#define LDAP_ATTRIBUTE_NTHASH "ipaNTHash"
#define LDAP_ATTRIBUTE_UIDNUMBER "uidnumber"
#define LDAP_ATTRIBUTE_GIDNUMBER "gidnumber"
#define LDAP_ATTRIBUTE_ASSOCIATED_DOMAIN "associatedDomain"

#define LDAP_OBJ_KRB_PRINCIPAL "krbPrincipal"
#define LDAP_OBJ_KRB_PRINCIPAL_AUX "krbPrincipalAux"
#define LDAP_OBJ_KRB_TICKET_POLICY_AUX "krbTicketPolicyAux"
#define LDAP_ATTRIBUTE_KRB_CANONICAL "krbCanonicalName"
#define LDAP_ATTRIBUTE_KRB_PRINCIPAL "krbPrincipalName"
#define LDAP_ATTRIBUTE_KRB_TICKET_FLAGS "krbTicketFlags"
#define LDAP_ATTRIBUTE_IPAOPALLOW "ipaAllowedToPerform;read_keys"

#define LDAP_OBJ_IPAOBJECT "ipaObject"
#define LDAP_OBJ_IPAHOST "ipaHost"
#define LDAP_OBJ_POSIXACCOUNT "posixAccount"

#define LDAP_OBJ_GROUPOFNAMES "groupOfNames"
#define LDAP_OBJ_NESTEDGROUP "nestedGroup"
#define LDAP_OBJ_IPAUSERGROUP "ipaUserGroup"
#define LDAP_OBJ_POSIXGROUP "posixGroup"
#define LDAP_OBJ_DOMAINRELATED "domainRelatedObject"
#define LDAP_OBJ_IPAOPALLOW "ipaAllowedOperations"

#define LDAP_CN_REALM_DOMAINS "cn=Realm Domains,cn=ipa,cn=etc"

#define LDAP_CN_ADTRUST_AGENTS "cn=adtrust agents,cn=sysaccounts,cn=etc"
#define LDAP_CN_ADTRUST_ADMINS "cn=trust admins,cn=groups,cn=accounts"

#define HAS_KRB_PRINCIPAL (1<<0)
#define HAS_KRB_PRINCIPAL_AUX (1<<1)
#define HAS_IPAOBJECT (1<<2)
#define HAS_IPAHOST (1<<3)
#define HAS_POSIXACCOUNT (1<<4)
#define HAS_GROUPOFNAMES (1<<5)
#define HAS_NESTEDGROUP (1<<6)
#define HAS_IPAUSERGROUP (1<<7)
#define HAS_POSIXGROUP (1<<8)
#define HAS_KRB_TICKET_POLICY_AUX (1<<9)

/* krbTicketFlags flag to don't allow issuing any ticket, keep in decimal form for LDAP use*/
#define IPASAM_DISALLOW_ALL_TIX 64

const struct dom_sid global_sid_Builtin = { 1, 1, {0,0,0,0,0,5},
					   {32,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};

/* With Samba 4.7 ldapsam_privates structure is not public anymore.
 * FreeIPA needs to use own structure */

struct ipasam_private {
	struct smbldap_state *ldap_state;
	/* Former statics */
	LDAPMessage *result;
	LDAPMessage *entry;

	const char *domain_name;
	struct dom_sid domain_sid;

	char *domain_dn;
	char *realm;
	char *base_dn;
	char *trust_dn;
	char *flat_name;
	struct dom_sid fallback_primary_group;
	char *fallback_primary_group_gid_str;
	char *server_princ;
	char *client_princ;
	struct sss_idmap_ctx *idmap_ctx;
	uint32_t supported_enctypes;
	bool fips_enabled;
};


static NTSTATUS ipasam_get_domain_name(struct ipasam_private *ipasam_state,
				       TALLOC_CTX *mem_ctx,
				       char **domain_name);


static void *idmap_talloc(size_t size, void *pvt)
{
	return talloc_size(pvt, size);
}

static void idmap_talloc_free(void *ptr, void *pvt)
{
	talloc_free(ptr);
}

static void sid_copy(struct dom_sid *dst, const struct dom_sid *src)
{
	size_t c;

	memset(dst, 0, sizeof(*dst));

	dst->sid_rev_num = src->sid_rev_num;
	dst->num_auths = src->num_auths;
	memcpy(&dst->id_auth[0], &src->id_auth[0], sizeof(src->id_auth));

	for (c = 0; c < src->num_auths; c++) {
		dst->sub_auths[c] = src->sub_auths[c];
	}
}

static bool sid_compose(struct dom_sid *dst, const struct dom_sid *dom_sid,
			uint32_t rid)
{
	if (dom_sid->num_auths >= 15) {
		return false;
	}

	sid_copy(dst, dom_sid);

	dst->sub_auths[dst->num_auths++] = rid;

	return true;
}

static char *sid_talloc_string(struct sss_idmap_ctx *ctx, void *final_ctx, const struct dom_sid *dom_sid)
{
	enum idmap_error_code ret;
	char *result = NULL;
	ret = sss_idmap_smb_sid_to_sid(ctx, discard_const(dom_sid), &result);
	if (ret != IDMAP_SUCCESS) {
		return NULL;
	}

	return talloc_move(final_ctx, &result);
}

static bool is_null_sid(const struct dom_sid *sid)
{
	size_t c;

	if (sid->sid_rev_num != 0 || sid->num_auths != 0) {
		return false;
	}

	for (c = 0; c < 6; c++) {
		if (sid->id_auth[c] != 0) {
			return false;
		}
	}

	for (c = 0; c < 15; c++) {
		if (sid->sub_auths[c] != 0) {
			return false;
		}
	}

	return true;
}

static int dom_sid_compare_domain(const struct dom_sid *sid1,
				  const struct dom_sid *sid2)
{
	size_t c;
	size_t n_sub_auths;

	if (sid1->sid_rev_num != sid2->sid_rev_num) {
		return sid1->sid_rev_num - sid2->sid_rev_num;
	}

	for (c = 0; c < 6; c++) {
		if (sid1->id_auth[c] != sid2->id_auth[c]) {
			return sid1->id_auth[c] - sid2->id_auth[c];
		}
	}

	n_sub_auths = (sid1->num_auths < sid2->num_auths) ? sid1->num_auths :
							sid2->num_auths;

	for (c = 0; c < n_sub_auths; c++) {
		if (sid1->sub_auths[c] != sid2->sub_auths[c]) {
			return sid1->sub_auths[c] - sid2->sub_auths[c];
		}
	}

	return 0;
}

static bool sid_peek_check_rid(const struct dom_sid *exp_dom_sid,
			       const struct dom_sid *sid, uint32_t *rid)
{
	if((exp_dom_sid->num_auths + 1) != sid->num_auths ||
	    sid->num_auths <= 0) {
		return false;
	}

	if (dom_sid_compare_domain(exp_dom_sid, sid) != 0) {
		return false;
	}

	*rid = sid->sub_auths[sid->num_auths - 1];

	return true;
}

static bool strnequal(const char *s1, const char *s2, size_t n) {
	if (s1 == s2) {
		return true;
	}

	if (s1 == NULL || s2 == NULL || n == 0) {
		return false;
	}

	if (strncasecmp(s1, s2, n) == 0) {
		return true;
	}

	return false;
}

static LDAP *_smbldap_get_ldap(struct smbldap_state *state) {
#ifdef HAVE_SMBLDAP_GET_LDAP
	return smbldap_get_ldap(state);
#else
	return state->ldap_struct;
#endif

}

static bool _smbldap_get_paged_results(struct smbldap_state *state) {
#ifdef HAVE_SMBLDAP_GET_LDAP
	return smbldap_get_paged_results(state);
#else
	return state->paged_results;
#endif
}

static void _smbldap_set_paged_results(struct smbldap_state *state,
			       bool paged_results) {
#ifdef HAVE_SMBLDAP_GET_LDAP
	smbldap_set_paged_results(state, paged_results);
#else
	state->paged_results = paged_results;
#endif
}

static LDAP *priv2ld(struct ipasam_private *priv)
{
	return _smbldap_get_ldap(priv->ldap_state);
}

/*
 * get_attribute_values() returns array of all values of the attribute
 * allocated over mem_ctx
 */
static char **get_attribute_values(TALLOC_CTX *mem_ctx, LDAP *ldap_struct,
				   LDAPMessage *entry, const char *attribute, int *num_values)
{
	struct berval **values;
	int count, i;
	char **result = NULL;
	size_t conv_size;

	if (attribute == NULL || entry == NULL) {
		return NULL;
	}

	values = ldap_get_values_len(ldap_struct, entry, attribute);
	if (values == NULL) {
		DEBUG(10, ("Attribute [%s] not found.\n", attribute));
		return NULL;
	}

	count = ldap_count_values_len(values);
	if (count == 0) {
		goto done;
	}

	result = talloc_array(mem_ctx, char *, count);
	if (result == NULL) {
		goto done;
	}

	*num_values = count;
	for (i = 0; i < count; i++) {
		if (!convert_string_talloc(result, CH_UTF8, CH_UNIX,
					   values[i]->bv_val, values[i]->bv_len,
					   &result[i], &conv_size)) {
			DEBUG(10, ("Failed to convert %dth value of [%s] out of %d.\n",
				   i, attribute, count));
			talloc_free(result);
			result = NULL;
			goto done;
		}
	}

done:
	ldap_value_free_len(values);
	return result;
}

static char *get_single_attribute(TALLOC_CTX *mem_ctx, LDAP *ldap_struct,
				  LDAPMessage *entry, const char *attribute)
{
	struct berval **values;
	int c;
	char *result = NULL;
	size_t conv_size;

	if (attribute == NULL || entry == NULL) {
		return NULL;
	}

	values = ldap_get_values_len(ldap_struct, entry, attribute);
	if (values == NULL) {
		DEBUG(10, ("Attribute [%s] not found.\n", attribute));
		return NULL;
	}

	c = ldap_count_values_len(values);
	if (c != 1) {
		DEBUG(10, ("Found [%d] values for attribute [%s] but expected only 1.\n",
			   c, attribute));
		goto done;
	}

	if (!convert_string_talloc(mem_ctx, CH_UTF8, CH_UNIX,
				   values[0]->bv_val, values[0]->bv_len,
				   &result, &conv_size)) {
		DEBUG(10, ("Failed to convert value of [%s].\n", attribute));
		result = NULL;
		goto done;
	}

done:
	ldap_value_free_len(values);
	return result;
}

static char *get_dn(TALLOC_CTX *mem_ctx, LDAP *ld, LDAPMessage *entry)
{
	char *utf8_dn;
	char *unix_dn = NULL;
	size_t conv_size;

	utf8_dn = ldap_get_dn(ld, entry);
	if (utf8_dn == NULL) {
		DEBUG (10, ("ldap_get_dn failed\n"));
		return NULL;
	}
	if (!convert_string_talloc(mem_ctx, CH_UTF8, CH_UNIX,
				   utf8_dn, strlen(utf8_dn) + 1,
				   &unix_dn, &conv_size)) {
		DEBUG (10, ("Failed to convert [%s]\n", utf8_dn));
		unix_dn = NULL;
		goto done;
	}

done:
	ldap_memfree(utf8_dn);
	return unix_dn;
}





static bool ldapsam_extract_rid_from_entry(LDAP *ldap_struct,
					   LDAPMessage *entry,
					   struct sss_idmap_ctx *idmap_ctx,
					   const struct dom_sid *domain_sid,
					   uint32_t *rid)
{
	char *str = NULL;
	struct dom_sid *sid = NULL;
	bool res = false;
	enum idmap_error_code err;

	str = get_single_attribute(NULL, ldap_struct, entry,
				   LDAP_ATTRIBUTE_SID);
	if (str == NULL) {
		DEBUG(10, ("Could not find SID attribute\n"));
		res = false;
		goto done;
	}

	err = sss_idmap_sid_to_smb_sid(idmap_ctx, str, &sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(10, ("Could not convert string %s to sid\n", str));
		res = false;
		goto done;
	}

	if (dom_sid_compare_domain(sid, domain_sid) != 0) {
		char *debug_domain_sid = NULL;
		err = sss_idmap_smb_sid_to_sid(idmap_ctx,
					       discard_const(domain_sid),
					       &debug_domain_sid);
		if (err != IDMAP_SUCCESS) {
			DEBUG(10, ("SID %s is not in expected domain.\n",
				   str));
		} else {
			DEBUG(10, ("SID %s is not in expected domain %s\n",
				   str, debug_domain_sid));
			talloc_free(debug_domain_sid);
		}
		res = false;
		goto done;
	}

	if (sid->num_auths <= 0) {
		DEBUG(10, ("Invalid num_auths in SID %s.\n", str));
		res = false;
		goto done;
	}

	*rid = sid->sub_auths[sid->num_auths - 1];

	res = true;
done:
	talloc_free(sid);
	talloc_free(str);
	return res;
}

static NTSTATUS ldapsam_lookup_rids(struct pdb_methods *methods,
				    const struct dom_sid *domain_sid,
				    int num_rids,
				    uint32_t *rids,
				    const char **names,
				    enum lsa_SidType *attrs)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	LDAPMessage *msg = NULL;
	LDAPMessage *entry;
	char *allsids = NULL;
	int i, rc, num_mapped;
	NTSTATUS result = NT_STATUS_NO_MEMORY;
	TALLOC_CTX *mem_ctx;
	LDAP *ld;
	bool is_builtin;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		DEBUG(0, ("talloc_new failed\n"));
		goto done;
	}

	if (!sid_check_is_builtin(domain_sid) &&
	     dom_sid_compare_domain(&ipasam_state->domain_sid, domain_sid) != 0) {
		result = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (num_rids == 0) {
		result = NT_STATUS_NONE_MAPPED;
		goto done;
	}

	for (i=0; i<num_rids; i++)
		attrs[i] = SID_NAME_UNKNOWN;

	allsids = talloc_strdup(mem_ctx, "");
	if (allsids == NULL) {
		goto done;
	}

	for (i=0; i<num_rids; i++) {
		struct dom_sid sid;
		sid_compose(&sid, domain_sid, rids[i]);
		allsids = talloc_asprintf_append_buffer(
			allsids, "(%s=%s)",
			LDAP_ATTRIBUTE_SID,
			sid_talloc_string(ipasam_state->idmap_ctx, mem_ctx, &sid));
		if (allsids == NULL) {
			goto done;
		}
	}

	/* First look for users */

	{
		char *filter;
		const char *ldap_attrs[] = { "uid", LDAP_ATTRIBUTE_SID, NULL };

		filter = talloc_asprintf(
			mem_ctx, ("(&(objectClass=%s)(|%s))"),
			LDAP_OBJ_SAMBASAMACCOUNT, allsids);

		if (filter == NULL) {
			goto done;
		}

		rc = smbldap_search(ipasam_state->ldap_state,
				    ipasam_state->base_dn,
				    LDAP_SCOPE_SUBTREE, filter, ldap_attrs, 0,
				    &msg);
		smbldap_talloc_autofree_ldapmsg(mem_ctx, msg);
	}

	if (rc != LDAP_SUCCESS)
		goto done;

	ld = priv2ld(ipasam_state);
	num_mapped = 0;

	for (entry = ldap_first_entry(ld, msg);
	     entry != NULL;
	     entry = ldap_next_entry(ld, entry)) {
		uint32_t rid;
		int rid_index;
		const char *name;

		if (!ldapsam_extract_rid_from_entry(ld, entry,
						    ipasam_state->idmap_ctx,
						    domain_sid,
						    &rid)) {
			DEBUG(2, ("Could not find sid from ldap entry\n"));
			continue;
		}

		name = get_single_attribute(names, ld, entry, "uid");
		if (name == NULL) {
			DEBUG(2, ("Could not retrieve uid attribute\n"));
			continue;
		}

		for (rid_index = 0; rid_index < num_rids; rid_index++) {
			if (rid == rids[rid_index])
				break;
		}

		if (rid_index == num_rids) {
			DEBUG(2, ("Got a RID not asked for: %d\n", rid));
			continue;
		}

		attrs[rid_index] = SID_NAME_USER;
		names[rid_index] = name;
		num_mapped += 1;
	}

	if (num_mapped == num_rids) {
		/* No need to look for groups anymore -- we're done */
		result = NT_STATUS_OK;
		goto done;
	}

	/* Same game for groups */

	{
		char *filter;
		const char *ldap_attrs[] = { "cn", "displayName",
					     LDAP_ATTRIBUTE_SID,
					     NULL };

		filter = talloc_asprintf(
			mem_ctx, "(&(objectClass=%s)(|%s))",
			LDAP_OBJ_GROUPMAP, allsids);
		if (filter == NULL) {
			goto done;
		}

		rc = smbldap_search(ipasam_state->ldap_state,
				    ipasam_state->base_dn,
				    LDAP_SCOPE_SUBTREE, filter, ldap_attrs, 0,
				    &msg);
		smbldap_talloc_autofree_ldapmsg(mem_ctx, msg);
	}

	if (rc != LDAP_SUCCESS)
		goto done;

	/* ldap_struct might have changed due to a reconnect */

	ld = priv2ld(ipasam_state);

	/* For consistency checks, we already checked we're only domain or builtin */

	is_builtin = sid_check_is_builtin(domain_sid);

	for (entry = ldap_first_entry(ld, msg);
	     entry != NULL;
	     entry = ldap_next_entry(ld, entry))
	{
		uint32_t rid;
		int rid_index;
		const char *attr;
		enum lsa_SidType type;
		const char *dn = get_dn(mem_ctx, ld, entry);

		type = SID_NAME_DOM_GRP;

		/* Consistency checks */
		if ((is_builtin && (type != SID_NAME_ALIAS)) ||
		    (!is_builtin && ((type != SID_NAME_ALIAS) &&
				     (type != SID_NAME_DOM_GRP)))) {
			DEBUG(2, ("Rejecting invalid group mapping entry %s\n", dn));
		}

		if (!ldapsam_extract_rid_from_entry(ld, entry,
						    ipasam_state->idmap_ctx,
						    domain_sid, &rid)) {
			DEBUG(2, ("Could not find sid from ldap entry %s\n", dn));
			continue;
		}

		attr = get_single_attribute(names, ld, entry, "displayName");

		if (attr == NULL) {
			DEBUG(10, ("Could not retrieve 'displayName' attribute from %s\n",
				   dn));
			attr = get_single_attribute(names, ld, entry, "cn");
		}

		if (attr == NULL) {
			DEBUG(2, ("Could not retrieve naming attribute from %s\n",
				  dn));
			continue;
		}

		for (rid_index = 0; rid_index < num_rids; rid_index++) {
			if (rid == rids[rid_index])
				break;
		}

		if (rid_index == num_rids) {
			DEBUG(2, ("Got a RID not asked for: %d\n", rid));
			continue;
		}

		attrs[rid_index] = type;
		names[rid_index] = attr;
		num_mapped += 1;
	}

	result = NT_STATUS_NONE_MAPPED;

	if (num_mapped > 0)
		result = (num_mapped == num_rids) ?
			NT_STATUS_OK : STATUS_SOME_UNMAPPED;
 done:
	TALLOC_FREE(mem_ctx);
	return result;
}

static bool ldapsam_sid_to_id(struct pdb_methods *methods,
			      const struct dom_sid *sid,
			      struct unixid *id)
{
	struct ipasam_private *priv =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	char *filter;
	const char *attrs[] = { "objectClass", "gidNumber", "uidNumber",
				NULL };
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	bool ret = false;
	char *value;
	struct berval **values;
	size_t c;
	int rc;

	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		DEBUG(0, ("talloc_new failed\n"));
		return false;
	}

	filter = talloc_asprintf(mem_ctx,
				 "(&(%s=%s)"
				 "(|(objectClass=%s)(objectClass=%s)))",
				 LDAP_ATTRIBUTE_SID,
				 sid_talloc_string(priv->idmap_ctx, mem_ctx, sid),
				 LDAP_OBJ_GROUPMAP, LDAP_OBJ_SAMBASAMACCOUNT);
	if (filter == NULL) {
		DEBUG(5, ("talloc_asprintf failed\n"));
		goto done;
	}

	rc = smbldap_search_suffix(priv->ldap_state, filter,
				   attrs, &result);
	if (rc != LDAP_SUCCESS) {
		goto done;
	}
	smbldap_talloc_autofree_ldapmsg(mem_ctx, result);

	if (ldap_count_entries(priv2ld(priv), result) != 1) {
		DEBUG(10, ("Got %d entries, expected one\n",
			   ldap_count_entries(priv2ld(priv), result)));
		goto done;
	}

	entry = ldap_first_entry(priv2ld(priv), result);

	values = ldap_get_values_len(priv2ld(priv), entry, "objectClass");
	if (values == NULL) {
		DEBUG(10, ("Cannot find any objectclasses.\n"));
		goto done;
	}

	for (c = 0; values[c] != NULL; c++) {
		if (strncasecmp(LDAP_OBJ_GROUPMAP, values[c]->bv_val,
						   values[c]->bv_len) == 0) {
			break;
		}
	}

	if (values[c] != NULL) {
		const char *gid_str;
		/* It's a group */

		gid_str = get_single_attribute(mem_ctx, priv2ld(priv), entry,
					       "gidNumber");
		if (gid_str == NULL) {
			DEBUG(1, ("%s has no gidNumber\n",
				  get_dn(mem_ctx, priv2ld(priv), entry)));
			goto done;
		}

		unixid_from_gid(id, strtoul(gid_str, NULL, 10));

		idmap_cache_set_sid2unixid(sid, id);

		ret = true;
		goto done;
	}

	/* It must be a user */

	value = get_single_attribute(mem_ctx, priv2ld(priv), entry,
				     "uidNumber");
	if (value == NULL) {
		DEBUG(1, ("Could not find uidNumber in %s\n",
			  get_dn(mem_ctx, priv2ld(priv), entry)));
		goto done;
	}

	unixid_from_uid(id, strtoul(value, NULL, 10));

	idmap_cache_set_sid2unixid(sid, id);

	ret = true;
 done:

	TALLOC_FREE(mem_ctx);
	return ret;
}

static bool ipasam_uid_to_sid(struct pdb_methods *methods, uid_t uid,
			       struct dom_sid *sid)
{
	struct ipasam_private *priv =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	char *filter;
	const char *attrs[] = { LDAP_ATTRIBUTE_SID, NULL };
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	bool ret = false;
	char *user_sid_string;
	struct dom_sid *user_sid = NULL;
	int rc;
	enum idmap_error_code err;
	struct unixid id;

	TALLOC_CTX *tmp_ctx = talloc_new(priv);
	if (tmp_ctx == NULL) {
		goto done;
	}

	/* Fast fail if we get a request for uidNumber=0 because it currently
	 * will never exist in the directory
	 * Saves an expensive LDAP call of which failure will never be cached
	 */
	if (uid == 0) {
		DEBUG(3, ("ERROR: Received request for uid %u, "
			  "fast failing as it will never exist\n",
			  (unsigned int)uid));
		goto done;
	}

	filter = talloc_asprintf(tmp_ctx,
				 "(&(uidNumber=%u)"
				 "(objectClass=%s)"
				 "(objectClass=%s))",
				 (unsigned int)uid,
				 LDAP_OBJ_POSIXACCOUNT,
				 LDAP_OBJ_SAMBASAMACCOUNT);
	if (filter == NULL) {
		DEBUG(3, ("talloc_asprintf failed\n"));
		goto done;
	}

	rc = smbldap_search_suffix(priv->ldap_state, filter, attrs, &result);
	if (rc != LDAP_SUCCESS) {
		goto done;
	}
	smbldap_talloc_autofree_ldapmsg(tmp_ctx, result);

	if (ldap_count_entries(priv2ld(priv), result) != 1) {
		DEBUG(3, ("ERROR: Got %d entries for uid %u, expected one\n",
			   ldap_count_entries(priv2ld(priv), result),
			   (unsigned int)uid));
		goto done;
	}

	entry = ldap_first_entry(priv2ld(priv), result);

	user_sid_string = get_single_attribute(tmp_ctx, priv2ld(priv), entry,
					       LDAP_ATTRIBUTE_SID);
	if (user_sid_string == NULL) {
		DEBUG(1, ("Could not find SID in object '%s'\n",
			  get_dn(tmp_ctx, priv2ld(priv), entry)));
		goto done;
	}

	err = sss_idmap_sid_to_smb_sid(priv->idmap_ctx,
				       user_sid_string, &user_sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(3, ("Error creating sid structure for sid '%s'\n",
			  user_sid_string));
		goto done;
	}

	sid_copy(sid, user_sid);

	unixid_from_uid(&id, uid);

	idmap_cache_set_sid2unixid(sid, &id);

	ret = true;

done:
	talloc_free(user_sid);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static bool ipasam_gid_to_sid(struct pdb_methods *methods, gid_t gid,
			       struct dom_sid *sid)
{
	struct ipasam_private *priv =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	char *filter;
	const char *attrs[] = { LDAP_ATTRIBUTE_SID, LDAP_ATTRIBUTE_OBJECTCLASS, NULL };
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	bool ret = false;
	char *group_sid_string = NULL;
	struct dom_sid *group_sid = NULL;
	struct berval **values;
	size_t c;
	int rc;
	enum idmap_error_code err;
	struct unixid id;

	TALLOC_CTX *tmp_ctx = talloc_new(priv);
	if (tmp_ctx == NULL) {
		goto done;
	}

	filter = talloc_asprintf(tmp_ctx,
				 "(|(&(gidNumber=%u)"
				     "(objectClass=%s))"
				   "(&(uidNumber=%u)"
				     "(objectClass=%s)"
				     "(objectClass=%s)))",
				 (unsigned int)gid,
				 LDAP_OBJ_GROUPMAP,
				 (unsigned int)gid,
				 LDAP_OBJ_POSIXACCOUNT,
				 LDAP_OBJ_SAMBASAMACCOUNT);
	if (filter == NULL) {
		DEBUG(3, ("talloc_asprintf failed\n"));
		goto done;
	}

	rc = smbldap_search_suffix(priv->ldap_state, filter, attrs, &result);
	if (rc != LDAP_SUCCESS) {
		goto done;
	}
	smbldap_talloc_autofree_ldapmsg(tmp_ctx, result);

	if (ldap_count_entries(priv2ld(priv), result) == 0) {
		DEBUG(3, ("ERROR: Got %d entries for gid %u, expected at least one\n",
			   ldap_count_entries(priv2ld(priv), result),
			   (unsigned int)gid));
		goto done;
	}

	for (entry = ldap_first_entry(priv2ld(priv), result);
		 entry != NULL;
		 entry = ldap_next_entry(priv2ld(priv), entry)) {

		values = ldap_get_values_len(priv2ld(priv), entry, "objectClass");
		if (values == NULL) {
			DEBUG(10, ("Cannot find any objectclasses.\n"));
			goto done;
		}

		for (c = 0; values[c] != NULL; c++) {
			if (strncasecmp(LDAP_OBJ_GROUPMAP, values[c]->bv_val,
							   values[c]->bv_len) == 0) {
				goto found;
			}
		}

	}

found:
	/* If we didn't find a group we found a user - so this is a primary group
	 * For user private group, use fallback group */
	if (entry == NULL) {

		DEBUG(10, ("Did not find user private group %u, "
			   "returning fallback group.\n", (unsigned int)gid));

		sid_copy(sid,
			 &priv->fallback_primary_group);
		ret = true;
		goto done;

	}

	group_sid_string = get_single_attribute(tmp_ctx, priv2ld(priv), entry,
						LDAP_ATTRIBUTE_SID);
	if (group_sid_string == NULL) {
		DEBUG(1, ("Could not find SID in object '%s'\n",
			  get_dn(tmp_ctx, priv2ld(priv), entry)));
		goto done;
	}

	err = sss_idmap_sid_to_smb_sid(priv->idmap_ctx,
				       group_sid_string, &group_sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(3, ("Error creating sid structure for sid '%s'\n",
			  group_sid_string));
		goto done;
	}

	sid_copy(sid, group_sid);

	unixid_from_gid(&id, gid);

	idmap_cache_set_sid2unixid(sid, &id);

	ret = true;

done:
	talloc_free(group_sid);
	TALLOC_FREE(tmp_ctx);
	return ret;
}

#if PASSDB_INTERFACE_VERSION >= 24
/* Since version 24, uid_to_sid() and gid_to_sid() were removed in favor of id_to_sid() */
static bool ipasam_id_to_sid(struct pdb_methods *methods, struct unixid *id, struct dom_sid *sid)
{
	bool result = false;

	if (id->type != ID_TYPE_GID) {
		result = ipasam_uid_to_sid(methods, id->id, sid);
	}
	if (!result && id->type != ID_TYPE_UID) {
		result = ipasam_gid_to_sid(methods, id->id, sid);
	}

	return result;
}
#endif

static char *get_ldap_filter(TALLOC_CTX *mem_ctx, const char *username)
{
	char *escaped = NULL;
	char *result = NULL;

	escaped = escape_ldap_string(mem_ctx, username);
	if (escaped == NULL) {
		return NULL;
	}

	result = talloc_asprintf(mem_ctx, "(&(uid=%s)(objectclass=%s))",
					  escaped, LDAP_OBJ_SAMBASAMACCOUNT);

	TALLOC_FREE(escaped);

	return result;
}

static const char **talloc_attrs(TALLOC_CTX *mem_ctx, ...)
{
	int i, num = 0;
	va_list ap;
	const char **result;

	va_start(ap, mem_ctx);
	while (va_arg(ap, const char *) != NULL)
		num += 1;
	va_end(ap);

	if ((result = talloc_array(mem_ctx, const char *, num+1)) == NULL) {
		return NULL;
	}

	va_start(ap, mem_ctx);
	for (i=0; i<num; i++) {
		result[i] = talloc_strdup(result, va_arg(ap, const char*));
		if (result[i] == NULL) {
			talloc_free(result);
			va_end(ap);
			return NULL;
		}
	}
	va_end(ap);

	result[num] = NULL;
	return result;
}


struct ldap_search_state {
	struct smbldap_state *connection;

	uint32_t acct_flags;
	uint16_t group_type;

	const char *base;
	int scope;
	const char *filter;
	const char **attrs;
	int attrsonly;
	void *pagedresults_cookie;
	struct sss_idmap_ctx *idmap_ctx;
	const struct dom_sid *dom_sid;

	LDAPMessage *entries, *current_entry;
	bool (*ldap2displayentry)(struct ldap_search_state *state,
				  TALLOC_CTX *mem_ctx,
				  LDAP *ld, LDAPMessage *entry,
				  struct samr_displayentry *result);
};

static bool ipasam_search_firstpage(struct pdb_search *search)
{
	struct ldap_search_state *state =
		talloc_get_type_abort(search->private_data, struct ldap_search_state);
	LDAP *ld;
	int rc = LDAP_OPERATIONS_ERROR;

	state->entries = NULL;

	if (_smbldap_get_paged_results(state->connection)) {
		rc = smbldap_search_paged(state->connection, state->base,
					  state->scope, state->filter,
					  state->attrs, state->attrsonly,
					  LDAP_PAGE_SIZE, &state->entries,
					  &state->pagedresults_cookie);
	}

	if ((rc != LDAP_SUCCESS) || (state->entries == NULL)) {

		if (state->entries != NULL) {
			/* Left over from unsuccessful paged attempt */
			ldap_msgfree(state->entries);
			state->entries = NULL;
		}

		rc = smbldap_search(state->connection, state->base,
				    state->scope, state->filter, state->attrs,
				    state->attrsonly, &state->entries);

		if ((rc != LDAP_SUCCESS) || (state->entries == NULL))
			return false;

		/* Ok, the server was lying. It told us it could do paged
		 * searches when it could not. */
		_smbldap_set_paged_results(state->connection, false);
	}

        ld = _smbldap_get_ldap(state->connection);
        if ( ld == NULL) {
                DEBUG(5, ("Don't have an LDAP connection right after a "
			  "search\n"));
                return false;
        }
        state->current_entry = ldap_first_entry(ld, state->entries);

	return true;
}

static bool ipasam_search_nextpage(struct pdb_search *search)
{
	struct ldap_search_state *state =
		talloc_get_type_abort(search->private_data, struct ldap_search_state);
	LDAP *ld;
	int rc;

	if (!_smbldap_get_paged_results(state->connection)) {
		/* There is no next page when there are no paged results */
		return false;
	}

	rc = smbldap_search_paged(state->connection, state->base,
				  state->scope, state->filter, state->attrs,
				  state->attrsonly, LDAP_PAGE_SIZE,
				  &state->entries,
				  &state->pagedresults_cookie);

	if ((rc != LDAP_SUCCESS) || (state->entries == NULL))
		return false;

        ld = _smbldap_get_ldap(state->connection);
        if ( ld == NULL) {
                DEBUG(5, ("Don't have an LDAP connection right after a "
			  "search\n"));
                return false;
        }
	state->current_entry = ldap_first_entry(ld,
						state->entries);

	if (state->current_entry == NULL) {
		ldap_msgfree(state->entries);
		state->entries = NULL;
		return false;
	}

	return true;
}

static bool ipasam_search_next_entry(struct pdb_search *search,
				      struct samr_displayentry *entry)
{
	struct ldap_search_state *state =
		talloc_get_type_abort(search->private_data, struct ldap_search_state);
	bool result;
	LDAP *ld;

 retry:
	if ((state->entries == NULL) && (state->pagedresults_cookie == NULL))
		return false;

	if ((state->entries == NULL) &&
	    !ipasam_search_nextpage(search))
		    return false;

	if (state->current_entry == NULL) {
		return false;
	}

        ld = _smbldap_get_ldap(state->connection);
        if ( ld == NULL) {
                DEBUG(5, ("Don't have an LDAP connection right after a "
			  "search\n"));
                return false;
        }
	result = state->ldap2displayentry(state, search,
					  ld,
					  state->current_entry, entry);

	if (!result) {
		char *dn;
		dn = ldap_get_dn(ld, state->current_entry);
		DEBUG(5, ("Skipping entry %s\n", dn != NULL ? dn : "<NULL>"));
		if (dn != NULL) ldap_memfree(dn);
	}

	state->current_entry = ldap_next_entry(ld,
					       state->current_entry);

	if (state->current_entry == NULL) {
		ldap_msgfree(state->entries);
		state->entries = NULL;
	}

	if (!result) goto retry;

	return true;
}

static void ipasam_search_end(struct pdb_search *search)
{
	struct ldap_search_state *state =
		talloc_get_type_abort(search->private_data, struct ldap_search_state);
	int rc;

	if (state->pagedresults_cookie == NULL)
		return;

	if (state->entries != NULL)
		ldap_msgfree(state->entries);

	state->entries = NULL;
	state->current_entry = NULL;

	if (!_smbldap_get_paged_results(state->connection))
		return;

	/* Tell the LDAP server we're not interested in the rest anymore. */

	rc = smbldap_search_paged(state->connection, state->base, state->scope,
				  state->filter, state->attrs,
				  state->attrsonly, 0, &state->entries,
				  &state->pagedresults_cookie);

	if (rc != LDAP_SUCCESS)
		DEBUG(5, ("Could not end search properly\n"));

}

static bool ldapuser2displayentry(struct ldap_search_state *state,
				  TALLOC_CTX *mem_ctx,
				  LDAP *ld, LDAPMessage *entry,
				  struct samr_displayentry *result)
{
	char **vals;
	size_t converted_size;
	struct dom_sid *sid = NULL;
	enum idmap_error_code err;
	bool res;

/* FIXME: SB try to figure out which flags to set instead of hardcode them */
	result->acct_flags = 66048;
	result->account_name = "";
	result->fullname = "";
	result->description = "";

	vals = ldap_get_values(ld, entry, "uid");
	if ((vals == NULL) || (vals[0] == NULL)) {
		DEBUG(5, ("\"uid\" not found\n"));
		return false;
	}
	if (!pull_utf8_talloc(mem_ctx,
			      discard_const_p(char *, &result->account_name),
			      vals[0], &converted_size))
	{
		DEBUG(0,("ldapuser2displayentry: pull_utf8_talloc failed: %s",
			 strerror(errno)));
	}

	ldap_value_free(vals);

	vals = ldap_get_values(ld, entry, "displayName");
	if ((vals == NULL) || (vals[0] == NULL))
		DEBUG(8, ("\"displayName\" not found\n"));
	else if (!pull_utf8_talloc(mem_ctx,
				   discard_const_p(char *, &result->fullname),
				   vals[0], &converted_size))
	{
		DEBUG(0,("ldapuser2displayentry: pull_utf8_talloc failed: %s",
			 strerror(errno)));
	}

	ldap_value_free(vals);

	vals = ldap_get_values(ld, entry, "description");
	if ((vals == NULL) || (vals[0] == NULL))
		DEBUG(8, ("\"description\" not found\n"));
	else if (!pull_utf8_talloc(mem_ctx,
				   discard_const_p(char *, &result->description),
				   vals[0], &converted_size))
	{
		DEBUG(0,("ldapuser2displayentry: pull_utf8_talloc failed: %s",
			 strerror(errno)));
	}

	ldap_value_free(vals);

	if ((result->account_name == NULL) ||
	    (result->fullname == NULL) ||
	    (result->description == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}

	vals = ldap_get_values(ld, entry, LDAP_ATTRIBUTE_SID);
	if ((vals == NULL) || (vals[0] == NULL)) {
		DEBUG(0, ("\"objectSid\" not found\n"));
		return false;
	}

	err = sss_idmap_sid_to_smb_sid(state->idmap_ctx, vals[0], &sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(0, ("Could not convert %s to SID\n", vals[0]));
		ldap_value_free(vals);
		return false;
	}
	ldap_value_free(vals);

	res = sid_peek_check_rid(state->dom_sid, sid, &result->rid);
	talloc_free(sid);
	if (!res) {
		DEBUG(0, ("sid does not belong to our domain\n"));
		return false;
	}

	return true;
}

static bool ipasam_search_users(struct pdb_methods *methods,
				 struct pdb_search *search,
				 uint32_t acct_flags)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	struct ldap_search_state *state;

	state = talloc(search, struct ldap_search_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}

	state->connection = ipasam_state->ldap_state;

	state->base = talloc_strdup(search, ipasam_state->base_dn);

	state->acct_flags = acct_flags;
	state->scope = LDAP_SCOPE_SUBTREE;
	state->filter = get_ldap_filter(search, "*");
	state->attrs = talloc_attrs(search, "uid", LDAP_ATTRIBUTE_SID,
				    "displayName", "description",
				    NULL);
	state->attrsonly = 0;
	state->pagedresults_cookie = NULL;
	state->entries = NULL;
	state->idmap_ctx = ipasam_state->idmap_ctx;
	state->dom_sid = &ipasam_state->domain_sid;
	state->ldap2displayentry = ldapuser2displayentry;

	if ((state->filter == NULL) || (state->attrs == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}

	search->private_data = state;
	search->next_entry = ipasam_search_next_entry;
	search->search_end = ipasam_search_end;

	return ipasam_search_firstpage(search);
}

static bool ldapgroup2displayentry(struct ldap_search_state *state,
				   TALLOC_CTX *mem_ctx,
				   LDAP *ld, LDAPMessage *entry,
				   struct samr_displayentry *result)
{
	char **vals = NULL;
	size_t converted_size;
	struct dom_sid *sid = NULL;
	uint16_t group_type;
	enum idmap_error_code err;

	result->account_name = "";
	result->fullname = "";
	result->description = "";

	group_type = SID_NAME_DOM_GRP;

	if ((state->group_type != 0) &&
	    ((state->group_type != group_type))) {
		ldap_value_free(vals);
		return false;
	}

	ldap_value_free(vals);

	/* display name is the NT group name */

	vals = ldap_get_values(ld, entry, "displayName");
	if ((vals == NULL) || (vals[0] == NULL)) {
		DEBUG(8, ("\"displayName\" not found\n"));

		/* fallback to the 'cn' attribute */
		vals = ldap_get_values(ld, entry, "cn");
		if ((vals == NULL) || (vals[0] == NULL)) {
			DEBUG(5, ("\"cn\" not found\n"));
			return false;
		}
		if (!pull_utf8_talloc(mem_ctx,
				      discard_const_p(char *,
						    &result->account_name),
				      vals[0], &converted_size))
		{
			DEBUG(0,("ldapgroup2displayentry: pull_utf8_talloc "
				  "failed: %s", strerror(errno)));
		}
	}
	else if (!pull_utf8_talloc(mem_ctx,
				   discard_const_p(char *,
						 &result->account_name),
				   vals[0], &converted_size))
	{
		DEBUG(0,("ldapgroup2displayentry: pull_utf8_talloc failed: %s",
			  strerror(errno)));
	}

	ldap_value_free(vals);

	vals = ldap_get_values(ld, entry, "description");
	if ((vals == NULL) || (vals[0] == NULL))
		DEBUG(8, ("\"description\" not found\n"));
	else if (!pull_utf8_talloc(mem_ctx,
				   discard_const_p(char *, &result->description),
				   vals[0], &converted_size))
	{
		DEBUG(0,("ldapgroup2displayentry: pull_utf8_talloc failed: %s",
			  strerror(errno)));
	}
	ldap_value_free(vals);

	if ((result->account_name == NULL) ||
	    (result->fullname == NULL) ||
	    (result->description == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}

	vals = ldap_get_values(ld, entry, LDAP_ATTRIBUTE_SID);
	if ((vals == NULL) || (vals[0] == NULL)) {
		DEBUG(0, ("\"objectSid\" not found\n"));
		if (vals != NULL) {
			ldap_value_free(vals);
		}
		return false;
	}

	err = sss_idmap_sid_to_smb_sid(state->idmap_ctx, vals[0], &sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(0, ("Could not convert %s to SID\n", vals[0]));
		ldap_value_free(vals);
		return false;
	}

	ldap_value_free(vals);

	switch (group_type) {
		case SID_NAME_DOM_GRP:
		case SID_NAME_ALIAS:

			if (!sid_peek_check_rid(state->dom_sid, sid, &result->rid) &&
			    !sid_peek_check_rid(&global_sid_Builtin, sid, &result->rid))
			{
				talloc_free(sid);
				DEBUG(0, ("SID is not in our domain\n"));
				return false;
			}
			break;

		default:
			DEBUG(0,("unknown group type: %d\n", group_type));
			talloc_free(sid);
			return false;
	}
	talloc_free(sid);

	result->acct_flags = 0;

	return true;
}

static bool ipasam_search_grouptype(struct pdb_methods *methods,
				     struct pdb_search *search,
				     const struct dom_sid *sid,
				     enum lsa_SidType type)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	struct ldap_search_state *state;

	state = talloc(search, struct ldap_search_state);
	if (state == NULL) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}

	state->base = talloc_strdup(search, ipasam_state->base_dn);
	state->connection = ipasam_state->ldap_state;
	state->scope = LDAP_SCOPE_SUBTREE;
	state->filter =	talloc_asprintf(search, "(&(objectclass=%s)(%s=%s*))",
					LDAP_OBJ_GROUPMAP, LDAP_ATTRIBUTE_SID,
					sid_talloc_string(
						ipasam_state->idmap_ctx,
						search, sid));
	state->attrs = talloc_attrs(search, "cn", LDAP_ATTRIBUTE_SID,
				    "displayName", "description",
				     NULL);
	state->attrsonly = 0;
	state->pagedresults_cookie = NULL;
	state->entries = NULL;
	state->group_type = type;
	state->idmap_ctx = ipasam_state->idmap_ctx;
	state->dom_sid = &ipasam_state->domain_sid;
	state->ldap2displayentry = ldapgroup2displayentry;

	if ((state->filter == NULL) || (state->attrs == NULL)) {
		DEBUG(0, ("talloc failed\n"));
		return false;
	}

	search->private_data = state;
	search->next_entry = ipasam_search_next_entry;
	search->search_end = ipasam_search_end;

	return ipasam_search_firstpage(search);
}

static bool ipasam_search_groups(struct pdb_methods *methods,
				  struct pdb_search *search)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);

	return ipasam_search_grouptype(methods, search,
					&ipasam_state->domain_sid,
                                        SID_NAME_DOM_GRP);
}

static bool ipasam_search_aliases(struct pdb_methods *methods,
				   struct pdb_search *search,
				   const struct dom_sid *sid)
{
	return ipasam_search_grouptype(methods, search,
				       sid, SID_NAME_ALIAS);
}

static char *trusted_domain_dn(TALLOC_CTX *mem_ctx,
			       struct ipasam_private *ipasam_state,
			       const char *domain)
{
	return talloc_asprintf(mem_ctx, "%s=%s,%s",
			       LDAP_ATTRIBUTE_CN, domain,
			       ipasam_state->trust_dn);
}

static NTSTATUS ipasam_get_objectclasses(struct ipasam_private *ipasam_state,
					 const char *dn, LDAPMessage *entry,
					 uint32_t *has_objectclass)
{
	struct berval **bervals;
	size_t c;

	bervals = ldap_get_values_len(priv2ld(ipasam_state), entry,
					LDAP_ATTRIBUTE_OBJECTCLASS);
	if (bervals == NULL) {
		DEBUG(0, ("Entry [%s] does not have any objectclasses.\n", dn));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	*has_objectclass = 0;
	for (c = 0; bervals[c] != NULL; c++) {
		if (strnequal(bervals[c]->bv_val, LDAP_OBJ_KRB_PRINCIPAL, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_KRB_PRINCIPAL;
		} else if (strnequal(bervals[c]->bv_val,
			   LDAP_OBJ_KRB_PRINCIPAL_AUX, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_KRB_PRINCIPAL_AUX;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_IPAOBJECT, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_IPAOBJECT;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_IPAHOST, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_IPAHOST;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_POSIXACCOUNT, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_POSIXACCOUNT;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_GROUPOFNAMES, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_GROUPOFNAMES;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_NESTEDGROUP, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_NESTEDGROUP;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_IPAUSERGROUP, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_IPAUSERGROUP;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_POSIXGROUP, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_POSIXGROUP;
		} else if (strnequal(bervals[c]->bv_val, LDAP_OBJ_KRB_TICKET_POLICY_AUX, bervals[c]->bv_len)) {
			*has_objectclass |= HAS_KRB_TICKET_POLICY_AUX;
		}
	}
	ldap_value_free_len(bervals);

	return NT_STATUS_OK;
}

static bool search_krb_princ(struct ipasam_private *ipasam_state,
			     TALLOC_CTX *mem_ctx,
			     const char *princ, const char *base_dn,
			     LDAPMessage **entry)
{
	int rc;
	LDAPMessage *result = NULL;
	uint32_t num_result;
	char *filter;

	filter = talloc_asprintf(mem_ctx, "%s=%s",
				 LDAP_ATTRIBUTE_KRB_PRINCIPAL, princ);
	if (filter == NULL) {
		return false;
	}

	rc = smbldap_search(ipasam_state->ldap_state, base_dn,
			    LDAP_SCOPE_SUBTREE, filter, NULL, 0, &result);

	if (result != NULL) {
		smbldap_talloc_autofree_ldapmsg(mem_ctx, result);
	}

	if (rc == LDAP_NO_SUCH_OBJECT) {
		*entry = NULL;
		return true;
	}

	if (rc != LDAP_SUCCESS) {
		return false;
	}

	num_result = ldap_count_entries(priv2ld(ipasam_state), result);

	if (num_result > 1) {
		DEBUG(1, ("search_krb_princ: more than one object found "
			  "with filter '%s'?!\n", filter));
		return false;
	}

	if (num_result == 0) {
		DEBUG(1, ("get_trusted_domain_int: no object found "
			  "with filter '%s'.\n", filter));
		*entry = NULL;
	} else {
		*entry = ldap_first_entry(priv2ld(ipasam_state), result);
	}

	return true;
}

/* Please keep ENCTYPE_ARCFOUR_HMAC the last in the list
 * of the default encryption types so that we can exclude
 * it when running in a FIPS mode where it is not allowed
 */
#define DEF_ENCTYPE_NUM 3
long default_enctypes[DEF_ENCTYPE_NUM] = {
    ENCTYPE_AES256_CTS_HMAC_SHA1_96,
    ENCTYPE_AES128_CTS_HMAC_SHA1_96,
    ENCTYPE_ARCFOUR_HMAC
};

static int set_cross_realm_pw(struct ipasam_private *ipasam_state,
			      const char *princ,
			      const char *pwd)
{
	int ret;
        size_t buflen;
        void *buffer = NULL;
	struct berval reqdata = { 0 };
	struct berval *retdata = NULL;
        char *retoid;
	int enctypes_num = DEF_ENCTYPE_NUM;

        if (ipasam_state->fips_enabled) {
		DEBUG(1, ("FIPS mode enabled: TDO account credentials will not have RC4-HMAC!\n"));
                enctypes_num = DEF_ENCTYPE_NUM - 1;
        }
        ret = ipaasn1_enc_getkt(true, princ, pwd,
                                default_enctypes, enctypes_num,
                                &buffer, &buflen);
        if (!ret) goto done;

        reqdata.bv_len = buflen;
        reqdata.bv_val = buffer;

	ret = smbldap_extended_operation(ipasam_state->ldap_state,
					 KEYTAB_GET_OID, &reqdata, NULL, NULL,
					 &retoid, &retdata);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("smbldap_extended_operation failed!\n"));
		goto done;
	}

	/* So far we do not care about the result */
	ldap_memfree(retoid);
	if (retdata != NULL) {
		ber_bvfree(retdata);
	}

	ret = 0;
done:
        free(buffer);
	return ret;
}

#define KRB_PRINC_CREATE_DEFAULT            0x00000000
#define KRB_PRINC_CREATE_DISABLED           0x00000001
#define KRB_PRINC_CREATE_AGENT_PERMISSION   0x00000002


static bool set_krb_princ(struct ipasam_private *ipasam_state,
			  TALLOC_CTX *mem_ctx,
			  const char *princ, const char *alias,
			  const char *pwd,
			  const char *base_dn,
			  uint32_t   create_flags)
{
	LDAPMessage *entry = NULL;
	LDAPMod **mods = NULL;
	char *dn = NULL;
	int ret;
	uint32_t has_objectclass = 0;
	NTSTATUS status;

	if (!search_krb_princ(ipasam_state, mem_ctx, princ, base_dn, &entry)) {
		return false;
	}

	if (entry) {
		dn = get_dn(mem_ctx, priv2ld(ipasam_state), entry);
		if (!dn) {
			return false;
		}

		status = ipasam_get_objectclasses(ipasam_state, dn, entry,
						  &has_objectclass);
		if (!NT_STATUS_IS_OK(status)) {
			return false;
		}
	} else {
		dn = talloc_asprintf(mem_ctx, "%s=%s,%s",
				     LDAP_ATTRIBUTE_KRB_PRINCIPAL, princ,
				     base_dn);
		if (!dn) {
			return false;
		}
	}

	if (!(has_objectclass & HAS_KRB_PRINCIPAL)) {
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_OBJECTCLASS,
				LDAP_OBJ_KRB_PRINCIPAL);
	}

	if (!(has_objectclass & HAS_KRB_PRINCIPAL_AUX)) {
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_OBJECTCLASS,
				LDAP_OBJ_KRB_PRINCIPAL_AUX);
	}

	if (!(has_objectclass & HAS_KRB_TICKET_POLICY_AUX)) {
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_OBJECTCLASS,
				LDAP_OBJ_KRB_TICKET_POLICY_AUX);
	}

	smbldap_set_mod(&mods, LDAP_MOD_ADD,
			 LDAP_ATTRIBUTE_KRB_CANONICAL, princ);
	smbldap_set_mod(&mods, LDAP_MOD_ADD,
			 LDAP_ATTRIBUTE_KRB_PRINCIPAL, princ);
	if (alias) {
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_KRB_PRINCIPAL, alias);
	}

	if ((create_flags & KRB_PRINC_CREATE_DISABLED)) {
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_KRB_TICKET_FLAGS,
				__TALLOC_STRING_LINE2__(IPASAM_DISALLOW_ALL_TIX));
	}

	if ((create_flags & KRB_PRINC_CREATE_AGENT_PERMISSION)) {
		char *agent_dn = NULL;
		agent_dn = talloc_asprintf(mem_ctx, LDAP_CN_ADTRUST_AGENTS",%s", ipasam_state->base_dn);
		if (agent_dn == NULL) {
			DEBUG(1, ("error configuring cross realm principal data!\n"));
			return false;
		}
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_OBJECTCLASS,
				LDAP_OBJ_IPAOPALLOW);
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_IPAOPALLOW,
				agent_dn);
		agent_dn = talloc_asprintf(mem_ctx, LDAP_CN_ADTRUST_ADMINS",%s", ipasam_state->base_dn);
		if (agent_dn == NULL) {
			DEBUG(1, ("error configuring cross realm principal data for trust admins!\n"));
			return false;
		}
		smbldap_set_mod(&mods, LDAP_MOD_ADD,
				LDAP_ATTRIBUTE_IPAOPALLOW,
				agent_dn);
	}

	if (entry == NULL) {
		ret = smbldap_add(ipasam_state->ldap_state, dn, mods);
	} else {
		ret = smbldap_modify(ipasam_state->ldap_state, dn, mods);
	}
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("error writing cross realm principal data!\n"));
		return false;
	}

	ret = set_cross_realm_pw(ipasam_state, princ, pwd);
	if (ret != 0) {
		DEBUG(1, ("set_cross_realm_pw failed.\n"));
		return false;
	}

	return true;
}

static bool del_krb_princ(struct ipasam_private *ipasam_state,
			  TALLOC_CTX *mem_ctx,
			  const char *princ, const char *base_dn)
{
	LDAPMessage *entry = NULL;
	char *dn = NULL;
	int ret;

	if (!search_krb_princ(ipasam_state, mem_ctx, princ, base_dn, &entry)) {
		return false;
	}

	if (entry) {
		dn = get_dn(mem_ctx, priv2ld(ipasam_state), entry);
		if (!dn) {
			return false;
		}

		ret = smbldap_delete(ipasam_state->ldap_state, dn);
		if (ret != LDAP_SUCCESS) {
			return false;
		}
	}

	return true;
}

enum princ_mod {
	SET_PRINC,
	DEL_PRINC
};

static bool handle_cross_realm_princs(struct ipasam_private *ipasam_state,
				      const char *domain, const char *flat_name,
				      const char *pwd_incoming,
				      const char *pwd_outgoing,
				      uint32_t trust_direction,
				      enum princ_mod mod)
{
	char *trusted_dn;
	char *princ_l;
	char *princ_r;
	char *princ_r_tdo, *princ_l_tdo;
	char *remote_realm;
	bool ok;
        int failed = 0;
	TALLOC_CTX *tmp_ctx;
	const char *r_tdo_alias, *l_tdo_alias;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return false;
	}

	remote_realm = talloc_strdup_upper(tmp_ctx, domain);
	if (remote_realm == NULL) {
		ok = false;
		goto done;
	}

	trusted_dn = trusted_domain_dn(tmp_ctx, ipasam_state, domain);

	princ_l = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s",
				  remote_realm, ipasam_state->realm);
	princ_l_tdo = talloc_asprintf(tmp_ctx, "%s$@%s",
				      flat_name, ipasam_state->realm);
	l_tdo_alias = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s",
				      flat_name, ipasam_state->realm);

	princ_r = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s",
				  ipasam_state->realm, remote_realm);
	princ_r_tdo = talloc_asprintf(tmp_ctx, "%s$@%s",
				      ipasam_state->flat_name, remote_realm);

	r_tdo_alias = talloc_asprintf(tmp_ctx, "krbtgt/%s@%s",
			ipasam_state->flat_name, remote_realm);

	if (trusted_dn == NULL || princ_l == NULL || princ_l_tdo == NULL ||
		l_tdo_alias == NULL || princ_r == NULL || princ_r_tdo == NULL ||
		r_tdo_alias == NULL) {
		ok = false;
		goto done;
	}

	switch (mod) {
		case SET_PRINC:
			/* We must use two sets by two principals here because
			 * they are used for different needs and must have
			 * different salts */

			failed = 0;
			/* INBOUND TRUST */
			if ((trust_direction & LSA_TRUST_DIRECTION_INBOUND) != 0) {
				/* First: krbtgt/<OUR REALM>@<REMOTE REALM>, enabled by default
				 * in case of the inboud trust */
				failed += !set_krb_princ(ipasam_state, tmp_ctx, princ_r, NULL,
							 pwd_outgoing, trusted_dn,
							 KRB_PRINC_CREATE_DEFAULT);

				/* Second: <OUR FLATNAME$>@<REMOTE REALM> is only used
				 * for SSSD to be able to talk to AD DCs but it has to
				 * have canonical name set to <OUR FLATNAME>$ because
				 * this is the salt used by AD DCs when using this
				 * principal, otherwise authentication will fail.
				 *
				 * *disable* use of this principal on our side as it is
				 * only used to retrieve trusted domain credentials by
				 * AD Trust Agents across the IPA topology */
				failed += !set_krb_princ(ipasam_state, tmp_ctx,
							 r_tdo_alias, princ_r_tdo,
							 pwd_incoming, trusted_dn,
							 (KRB_PRINC_CREATE_DISABLED |
							  KRB_PRINC_CREATE_AGENT_PERMISSION));

	                        ok = (failed == 0);
				if (!ok) {
					goto done;
				}
			}

			failed = 0;
			/* OUTBOUND TRUST */
			if ((trust_direction & LSA_TRUST_DIRECTION_OUTBOUND) != 0) {
				/* First: krbtgt/<REMOTE REALM>@<OUR REALM>, enabled by default */
				failed += !set_krb_princ(ipasam_state, tmp_ctx,
							 princ_l, NULL,
							 pwd_outgoing, trusted_dn,
							 KRB_PRINC_CREATE_DEFAULT);

				/* Second: <REMOTE FLAT NAME>$@<OUR REALM>, enabled by default
				 * as it is used for a remote DC to authenticate against IPA Samba
				 *
				 * A local account for the outbound trust must have
				 * POSIX and SMB identities associated with our domain but we associate
				 * them with the trust domain object itself */
				failed += !set_krb_princ(ipasam_state, tmp_ctx,
							 princ_l_tdo, l_tdo_alias,
							 pwd_incoming, trusted_dn,
							 KRB_PRINC_CREATE_DEFAULT);

	                        ok = (failed == 0);
				if (!ok) {
					goto done;
				}
			}
			break;
		case DEL_PRINC:
			failed = 0;
			if ((trust_direction & LSA_TRUST_DIRECTION_INBOUND) != 0) {
				failed += !del_krb_princ(ipasam_state, tmp_ctx, princ_r, trusted_dn);
				failed += !del_krb_princ(ipasam_state, tmp_ctx, princ_r_tdo, trusted_dn);

	                        ok = (failed == 0);
				if (!ok) {
					goto done;
				}
			}

			failed = 0;
			if ((trust_direction & LSA_TRUST_DIRECTION_OUTBOUND) != 0) {
				failed += !del_krb_princ(ipasam_state, tmp_ctx, princ_l, trusted_dn);
				failed += !del_krb_princ(ipasam_state, tmp_ctx, princ_l_tdo, trusted_dn);

	                        ok = (failed == 0);
				if (!ok) {
					goto done;
				}
			}
			break;
		default:
			DEBUG(1, ("unknown operation.\n"));
			ok = false;
			goto done;
	}

	ok = true;
done:
	talloc_free(tmp_ctx);
	return ok;
}

static bool set_cross_realm_princs(struct ipasam_private *ipasam_state,
				   const char *domain, const char* flat_name,
				   const char *pwd_incoming, const char *pwd_outgoing,
				   uint32_t trust_direction)
{
	return handle_cross_realm_princs(ipasam_state, domain, flat_name,
					 pwd_incoming,
					 pwd_outgoing,
					 trust_direction, SET_PRINC);
}

static bool del_cross_realm_princs(struct ipasam_private *ipasam_state,
				   const char *domain, const char *flat_name)
{
	uint32_t trust_direction = LSA_TRUST_DIRECTION_INBOUND | LSA_TRUST_DIRECTION_OUTBOUND;
	return handle_cross_realm_princs(ipasam_state, domain, flat_name,
					 NULL, NULL, trust_direction, DEL_PRINC);
}

static bool get_trusted_domain_int(struct ipasam_private *ipasam_state,
				   TALLOC_CTX *mem_ctx,
				   const char *filter, LDAPMessage **entry)
{
	int rc;
	LDAPMessage *result = NULL;
	uint32_t num_result;

	rc = smbldap_search(ipasam_state->ldap_state,
			    ipasam_state->trust_dn,
			    LDAP_SCOPE_SUBTREE, filter, NULL, 0, &result);

	if (result != NULL) {
		smbldap_talloc_autofree_ldapmsg(mem_ctx, result);
	}

	if (rc == LDAP_NO_SUCH_OBJECT) {
		*entry = NULL;
		return true;
	}

	if (rc != LDAP_SUCCESS) {
		return false;
	}

	num_result = ldap_count_entries(priv2ld(ipasam_state), result);

	if (num_result > 1) {
		DEBUG(1, ("get_trusted_domain_int: more than one "
			  "%s object with filter '%s'?!\n",
			  LDAP_OBJ_TRUSTED_DOMAIN, filter));
		return false;
	}

	if (num_result == 0) {
		DEBUG(1, ("get_trusted_domain_int: no "
			  "%s object with filter '%s'.\n",
			  LDAP_OBJ_TRUSTED_DOMAIN, filter));
		*entry = NULL;
	} else {
		*entry = ldap_first_entry(priv2ld(ipasam_state), result);
	}

	return true;
}

static bool get_trusted_domain_by_name_int(struct ipasam_private *ipasam_state,
					  TALLOC_CTX *mem_ctx,
					  const char *domain,
					  LDAPMessage **entry)
{
	char *filter = NULL;
	bool ok;

	filter = talloc_asprintf(mem_ctx,
				 "(&(objectClass=%s)(|(%s=%s)(%s=%s)(cn=%s)))",
				 LDAP_OBJ_TRUSTED_DOMAIN,
				 LDAP_ATTRIBUTE_FLAT_NAME, domain,
				 LDAP_ATTRIBUTE_TRUST_PARTNER, domain, domain);
	if (filter == NULL) {
		return false;
	}

	ok = get_trusted_domain_int(ipasam_state, mem_ctx, filter, entry);
	talloc_free(filter);

	return ok;
}

static bool get_trusted_domain_by_sid_int(struct ipasam_private *ipasam_state,
					   TALLOC_CTX *mem_ctx,
					   const char *sid, LDAPMessage **entry)
{
	char *filter = NULL;
	bool ok;

	filter = talloc_asprintf(mem_ctx, "(&(objectClass=%s)(%s=%s))",
				 LDAP_OBJ_TRUSTED_DOMAIN,
				 LDAP_ATTRIBUTE_TRUST_SID, sid);
	if (filter == NULL) {
		return false;
	}

	ok = get_trusted_domain_int(ipasam_state, mem_ctx, filter, entry);
	talloc_free(filter);

	return ok;
}

static bool get_uint32_t_from_ldap_msg(struct ipasam_private *ipasam_state,
				       LDAPMessage *entry,
				       const char *attr,
				       uint32_t *val)
{
	char *dummy;
	long int l;
	char *endptr;

	dummy = get_single_attribute(NULL, priv2ld(ipasam_state), entry, attr);
	if (dummy == NULL) {
		DEBUG(9, ("Attribute %s not present.\n", attr));
		*val = 0;
		return true;
	}

	l = strtoul(dummy, &endptr, 10);

	if (l < 0 || l > UINT32_MAX || *endptr != '\0') {
		TALLOC_FREE(dummy);
		return false;
	}
	TALLOC_FREE(dummy);

	*val = l;

	return true;
}

static bool fill_pdb_trusted_domain(TALLOC_CTX *mem_ctx,
				    struct ipasam_private *ipasam_state,
				    LDAPMessage *entry,
				    struct pdb_trusted_domain **_td)
{
	char *dummy;
	bool res;
	struct pdb_trusted_domain *td;
	struct dom_sid *sid = NULL;
	enum idmap_error_code err;

	if (entry == NULL) {
		return false;
	}

	td = talloc_zero(mem_ctx, struct pdb_trusted_domain);
	if (td == NULL) {
		return false;
	}

	/* All attributes are MAY */

	dummy = get_single_attribute(NULL, priv2ld(ipasam_state), entry,
				     LDAP_ATTRIBUTE_TRUST_SID);
	if (dummy == NULL) {
		DEBUG(9, ("Attribute %s not present.\n",
			  LDAP_ATTRIBUTE_TRUST_SID));
	} else {
		err = sss_idmap_sid_to_smb_sid(ipasam_state->idmap_ctx,
					       dummy, &sid);
		TALLOC_FREE(dummy);
		if (err != IDMAP_SUCCESS) {
			return false;
		}
		sid_copy(&td->security_identifier, sid);
		talloc_free(sid);
	}

	if (!smbldap_talloc_single_blob(td, priv2ld(ipasam_state), entry,
					LDAP_ATTRIBUTE_TRUST_AUTH_INCOMING,
					&td->trust_auth_incoming)) {
		DEBUG(9, ("Failed to set incoming auth info.\n"));
	}


	if (!smbldap_talloc_single_blob(td, priv2ld(ipasam_state), entry,
					LDAP_ATTRIBUTE_TRUST_AUTH_OUTGOING,
					&td->trust_auth_outgoing)) {
		DEBUG(9, ("Failed to set outgoing auth info.\n"));
	}

	td->netbios_name = get_single_attribute(td, priv2ld(ipasam_state), entry,
						LDAP_ATTRIBUTE_FLAT_NAME);
	if (td->netbios_name == NULL) {
		DEBUG(9, ("Attribute %s not present.\n",
			  LDAP_ATTRIBUTE_FLAT_NAME));
	}

	td->domain_name = get_single_attribute(td, priv2ld(ipasam_state), entry,
					       LDAP_ATTRIBUTE_TRUST_PARTNER);
	if (td->domain_name == NULL) {
		DEBUG(9, ("Attribute %s not present.\n",
			  LDAP_ATTRIBUTE_TRUST_PARTNER));
	}

	res = get_uint32_t_from_ldap_msg(ipasam_state, entry,
					 LDAP_ATTRIBUTE_TRUST_DIRECTION,
					 &td->trust_direction);
	if (!res) {
		return false;
	}
	if (td->trust_direction == 0) {
		/* attribute wasn't present, set default value */
		td->trust_direction = LSA_TRUST_DIRECTION_INBOUND | LSA_TRUST_DIRECTION_OUTBOUND;
	}

	res = get_uint32_t_from_ldap_msg(ipasam_state, entry,
					 LDAP_ATTRIBUTE_TRUST_ATTRIBUTES,
					 &td->trust_attributes);
	if (!res) {
		return false;
	}
	if (td->trust_attributes == 0) {
		/* attribute wasn't present, set default value */
		td->trust_attributes = LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE;
	}

	res = get_uint32_t_from_ldap_msg(ipasam_state, entry,
					 LDAP_ATTRIBUTE_TRUST_TYPE,
					 &td->trust_type);
	if (!res) {
		return false;
	}
	if (td->trust_type == 0) {
		/* attribute wasn't present, set default value */
		td->trust_type = LSA_TRUST_TYPE_UPLEVEL;
	}

	td->trust_posix_offset = talloc_zero(td, uint32_t);
	if (td->trust_posix_offset == NULL) {
		return false;
	}
	res = get_uint32_t_from_ldap_msg(ipasam_state, entry,
					 LDAP_ATTRIBUTE_TRUST_POSIX_OFFSET,
					 td->trust_posix_offset);
	if (!res) {
		return false;
	}

	td->supported_enc_type = talloc_zero(td, uint32_t);
	if (td->supported_enc_type == NULL) {
		return false;
	}
	res = get_uint32_t_from_ldap_msg(ipasam_state, entry,
					 LDAP_ATTRIBUTE_SUPPORTED_ENC_TYPE,
					 td->supported_enc_type);
	if (!res) {
		return false;
	}
	if (*td->supported_enc_type == 0) {
		*td->supported_enc_type = ipasam_state->supported_enctypes;
	}

	if (!smbldap_talloc_single_blob(td, priv2ld(ipasam_state), entry,
					LDAP_ATTRIBUTE_TRUST_FOREST_TRUST_INFO,
					&td->trust_forest_trust_info)) {
		DEBUG(9, ("Failed to set forest trust info.\n"));
	}

	*_td = td;

	return true;
}

static NTSTATUS ipasam_get_trusted_domain(struct pdb_methods *methods,
					  TALLOC_CTX *mem_ctx,
					  const char *domain,
					  struct pdb_trusted_domain **td)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	LDAPMessage *entry = NULL;

	DEBUG(10, ("ipasam_get_trusted_domain called for domain %s\n", domain));

	if (!get_trusted_domain_by_name_int(ipasam_state, mem_ctx, domain,
					    &entry)) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (entry == NULL) {
		DEBUG(5, ("ipasam_get_trusted_domain: no such trusted domain: "
			  "%s\n", domain));
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	if (!fill_pdb_trusted_domain(mem_ctx, ipasam_state, entry, td)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static NTSTATUS ipasam_get_trusted_domain_by_sid(struct pdb_methods *methods,
						 TALLOC_CTX *mem_ctx,
						 struct dom_sid *sid,
						 struct pdb_trusted_domain **td)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	LDAPMessage *entry = NULL;
	char *sid_str;
	bool ok;

	sid_str = sid_talloc_string(ipasam_state->idmap_ctx, mem_ctx, sid);
	if (sid_str == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10, ("ipasam_get_trusted_domain_by_sid called for sid %s\n",
		   sid_str));

	ok = get_trusted_domain_by_sid_int(ipasam_state, mem_ctx, sid_str,
					   &entry);
	talloc_free(sid_str);
	if (!ok) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	if (entry == NULL) {
		DEBUG(5, ("ipasam_get_trusted_domain_by_sid: no trusted domain "
			  "with sid: %s\n", sid_str));
		return NT_STATUS_NO_SUCH_DOMAIN;
	}

	ok = fill_pdb_trusted_domain(mem_ctx, ipasam_state, entry, td);
	if (!ok) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}

static bool smbldap_make_mod_uint32_t(LDAP *ldap_struct, LDAPMessage *entry,
				      LDAPMod ***mods, const char *attribute,
				      const uint32_t val)
{
	char *dummy;

	dummy = talloc_asprintf(NULL, "%lu", (unsigned long) val);
	if (dummy == NULL) {
		return false;
	}
	smbldap_make_mod(ldap_struct, entry, mods, attribute, dummy);
	TALLOC_FREE(dummy);

	return true;
}

static NTSTATUS get_trust_pwd(TALLOC_CTX *mem_ctx, const DATA_BLOB *auth_blob,
			      char **pwd, NTTIME *last_update)
{
	NTSTATUS status;
	struct trustAuthInOutBlob iopw;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *tmp_ctx;
	char *trustpw;
	size_t converted_size;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ndr_err = ndr_pull_struct_blob(auth_blob, tmp_ctx, &iopw,
			(ndr_pull_flags_fn_t)ndr_pull_trustAuthInOutBlob);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	if (iopw.count != 0 && iopw.current.count != 0 &&
	    iopw.current.array[0].AuthType == TRUST_AUTH_TYPE_CLEAR) {
		if (pwd != NULL) {
			if (!convert_string_talloc(tmp_ctx, CH_UTF16, CH_UNIX,
				iopw.current.array[0].AuthInfo.clear.password,
				iopw.current.array[0].AuthInfo.clear.size,
				&trustpw, &converted_size)) {

				status = NT_STATUS_NO_MEMORY;
				goto done;
			}

			*pwd = talloc_strndup(mem_ctx, trustpw, converted_size);
			if (*pwd == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto done;
			}
		}

		if (last_update != NULL) {
			*last_update = iopw.current.array[0].LastUpdateTime;
		}
	} else {
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	status = NT_STATUS_OK;

done:
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS ipasam_set_trusted_domain(struct pdb_methods *methods,
					  const char* domain,
					  const struct pdb_trusted_domain *td)
{
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	LDAPMessage *entry = NULL;
	LDAPMod **mods;
	bool res;
	char *trusted_dn = NULL;
	int ret, i, count;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	char *trustpw_incoming, *trustpw_outgoing;
	char *sid, *tda_name;
	char **in_blacklist = NULL;
	char **out_blacklist = NULL;
	uint32_t enctypes, trust_offset;

	DEBUG(10, ("ipasam_set_trusted_domain called for domain %s\n", domain));

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	res = get_trusted_domain_by_name_int(ipasam_state, tmp_ctx, domain,
					     &entry);
	if (!res) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	mods = NULL;
	if (entry == NULL) {
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods, "objectClass",
				 LDAP_OBJ_TRUSTED_DOMAIN);
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods, "objectClass",
				 LDAP_OBJ_ID_OBJECT);
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods, "objectClass",
				 LDAP_OBJ_POSIXACCOUNT);
	}

	if (entry != NULL) {
		sid = get_single_attribute(tmp_ctx, priv2ld(ipasam_state), entry,
					   LDAP_ATTRIBUTE_SID);
	}
	if (entry == NULL || sid == NULL) {
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
				 LDAP_ATTRIBUTE_UIDNUMBER, IPA_MAGIC_ID_STR);
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
		                 LDAP_ATTRIBUTE_GIDNUMBER,
				 ipasam_state->fallback_primary_group_gid_str);
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
		                 LDAP_ATTRIBUTE_HOMEDIRECTORY,
				 "/dev/null");
	}

	if (td->netbios_name != NULL) {
		tda_name = talloc_asprintf(tmp_ctx, "%s$", td->netbios_name);
		if (!tda_name) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
				 LDAP_ATTRIBUTE_FLAT_NAME,
				 td->netbios_name);
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
				 LDAP_ATTRIBUTE_UID,
				 tda_name);
	}

	if (td->domain_name != NULL) {
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
				 LDAP_ATTRIBUTE_TRUST_PARTNER,
				 td->domain_name);
	}

	if (!is_null_sid(&td->security_identifier)) {
		smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
				 LDAP_ATTRIBUTE_TRUST_SID,
				 sid_talloc_string(ipasam_state->idmap_ctx,
						   tmp_ctx, &td->security_identifier));
	}

	if (td->trust_type != 0) {
		res = smbldap_make_mod_uint32_t(priv2ld(ipasam_state), entry,
						&mods, LDAP_ATTRIBUTE_TRUST_TYPE,
						td->trust_type);
		if (!res) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	if (td->trust_attributes != 0) {
		res = smbldap_make_mod_uint32_t(priv2ld(ipasam_state), entry,
						&mods,
						LDAP_ATTRIBUTE_TRUST_ATTRIBUTES,
						td->trust_attributes);
		if (!res) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	if (td->trust_direction != 0) {
		res = smbldap_make_mod_uint32_t(priv2ld(ipasam_state), entry,
						&mods,
						LDAP_ATTRIBUTE_TRUST_DIRECTION,
						td->trust_direction);
		if (!res) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	trust_offset = 0;
	if (td->trust_posix_offset != NULL) {
		trust_offset = *td->trust_posix_offset;
	}

	res = smbldap_make_mod_uint32_t(priv2ld(ipasam_state), entry,
					&mods,
					LDAP_ATTRIBUTE_TRUST_POSIX_OFFSET,
					trust_offset);
	if (!res) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	enctypes = ipasam_state->supported_enctypes;
	if (td->supported_enc_type != NULL) {
		enctypes = *td->supported_enc_type;
	}

	res = smbldap_make_mod_uint32_t(priv2ld(ipasam_state), entry,
					&mods,
					LDAP_ATTRIBUTE_SUPPORTED_ENC_TYPE,
					enctypes);
	if (!res) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (td->trust_auth_outgoing.data != NULL) {
		smbldap_make_mod_blob(priv2ld(ipasam_state), entry, &mods,
				      LDAP_ATTRIBUTE_TRUST_AUTH_OUTGOING,
				      &td->trust_auth_outgoing);
	}

	if (td->trust_auth_incoming.data != NULL) {
		smbldap_make_mod_blob(priv2ld(ipasam_state), entry, &mods,
				      LDAP_ATTRIBUTE_TRUST_AUTH_INCOMING,
				      &td->trust_auth_incoming);
	}

	if (td->trust_forest_trust_info.data != NULL) {
		smbldap_make_mod_blob(priv2ld(ipasam_state), entry, &mods,
				      LDAP_ATTRIBUTE_TRUST_FOREST_TRUST_INFO,
				      &td->trust_forest_trust_info);
	}


	/* Only add default blacklists for incoming and outgoing SIDs but don't modify existing ones */
	in_blacklist = get_attribute_values(tmp_ctx, priv2ld(ipasam_state), entry,
						LDAP_ATTRIBUTE_SID_BLACKLIST_INCOMING, &count);
	out_blacklist = get_attribute_values(tmp_ctx, priv2ld(ipasam_state), entry,
						LDAP_ATTRIBUTE_SID_BLACKLIST_OUTGOING, &count);

	for (i = 0; ipa_mspac_well_known_sids[i]; i++) {
		if (in_blacklist == NULL) {
			smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
					      LDAP_ATTRIBUTE_SID_BLACKLIST_INCOMING,
					      ipa_mspac_well_known_sids[i]);
		}
		if (out_blacklist == NULL) {
			smbldap_make_mod(priv2ld(ipasam_state), entry, &mods,
					      LDAP_ATTRIBUTE_SID_BLACKLIST_OUTGOING,
					      ipa_mspac_well_known_sids[i]);
		}
	}

	smbldap_talloc_autofree_ldapmod(tmp_ctx, mods);

	if (mods != NULL) {
		trusted_dn = trusted_domain_dn(tmp_ctx, ipasam_state, domain);
		if (trusted_dn == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}

		if (entry == NULL) {
			ret = smbldap_add(ipasam_state->ldap_state, trusted_dn, mods);
		} else {
			ret = smbldap_modify(ipasam_state->ldap_state, trusted_dn, mods);
		}
		if (ret != LDAP_SUCCESS) {
			DEBUG(1, ("error writing trusted domain data!\n"));
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	if (entry == NULL) { /* FIXME: allow password updates here */
		status = get_trust_pwd(tmp_ctx, &td->trust_auth_incoming,
				       &trustpw_incoming, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		status = get_trust_pwd(tmp_ctx, &td->trust_auth_outgoing,
				       &trustpw_outgoing, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			goto done;
		}
		res = set_cross_realm_princs(ipasam_state, td->domain_name, td->netbios_name,
					     trustpw_incoming, trustpw_outgoing,
					     td->trust_direction);
		{
			/* Replace memset() use by an explicit loop to avoid
			 * both compile time and link time optimisations.
			 * We could have used memset_s() from C++11 but it is
			 * currently not implemented by GCC or glibc.
			 */
			volatile char *p = (void *) trustpw_incoming;
			volatile char *q = (void *) trustpw_outgoing;
			size_t plen = strlen(trustpw_incoming);
			size_t qlen = strlen(trustpw_outgoing);

			while (plen--) {
				*p++ = '\0';
			}

			while (qlen--) {
				*q++ = '\0';
			}
		}

		if (!res) {
			DEBUG(1, ("error writing cross realm principals!\n"));
			status = NT_STATUS_UNSUCCESSFUL;
			goto done;
		}
	}

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return status;
}

static int delete_subtree(struct ipasam_private *ipasam_state, char* dn)
{
	LDAP *state = priv2ld(ipasam_state);
	int rc;
	char *filter = NULL;
	int scope = LDAP_SCOPE_SUBTREE;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	char *entry_dn = NULL;

	/* use 'dn' for a temporary talloc context */
	filter = talloc_asprintf(dn, "(objectClass=*)");
	if (filter == NULL) {
		return LDAP_NO_MEMORY;
	}

	rc = smbldap_search(ipasam_state->ldap_state, dn, scope, filter, NULL, 0, &result);
	TALLOC_FREE(filter);

	if (rc != LDAP_SUCCESS) {
		return rc;
	}

	if (result == NULL) {
		return LDAP_NO_MEMORY;
	}

	smbldap_talloc_autofree_ldapmsg(dn, result);

	for (entry = ldap_first_entry(state, result);
	     entry != NULL;
	     entry = ldap_next_entry(state, entry)) {
		entry_dn = get_dn(dn, state, entry);
		/* remove child entries */
		if ((entry_dn != NULL) && (strcmp(entry_dn, dn) != 0)) {
			rc = smbldap_delete(ipasam_state->ldap_state, entry_dn);
			if (rc != LDAP_SUCCESS) {
				return rc;
			}
		}
	}
	rc = smbldap_delete(ipasam_state->ldap_state, dn);

	/* caller will destroy dn */
	return rc;
}

static NTSTATUS ipasam_del_trusted_domain(struct pdb_methods *methods,
					   const char *domain)
{
	int ret;
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	LDAPMessage *entry = NULL;
	char *dn;
	const char *domain_name, *flat_name;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!get_trusted_domain_by_name_int(ipasam_state, tmp_ctx, domain,
					    &entry)) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (entry == NULL) {
		DEBUG(5, ("ipasam_del_trusted_domain: no such trusted domain: "
			  "%s\n", domain));
		status = NT_STATUS_NO_SUCH_DOMAIN;
		goto done;
	}

	dn = get_dn(tmp_ctx, priv2ld(ipasam_state), entry);
	if (dn == NULL) {
		DEBUG(0,("ipasam_del_trusted_domain: Out of memory!\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	domain_name = get_single_attribute(tmp_ctx, priv2ld(ipasam_state), entry,
					   LDAP_ATTRIBUTE_TRUST_PARTNER);
	if (domain_name == NULL) {
		DEBUG(1, ("Attribute %s not present.\n",
			  LDAP_ATTRIBUTE_TRUST_PARTNER));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}

	flat_name = get_single_attribute(tmp_ctx, priv2ld(ipasam_state), entry,
					 LDAP_ATTRIBUTE_FLAT_NAME);
	if (flat_name == NULL) {
		DEBUG(1, ("Attribute %s not present.\n",
			  LDAP_ATTRIBUTE_FLAT_NAME));
		status = NT_STATUS_INVALID_PARAMETER;
		goto done;
	}


	if (!del_cross_realm_princs(ipasam_state, domain_name, flat_name)) {
		DEBUG(1, ("error deleting cross realm principals!\n"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = smbldap_delete(ipasam_state->ldap_state, dn);
	if (ret == LDAP_NOT_ALLOWED_ON_NONLEAF) {
		/* delete_subtree will use 'dn' as temporary context too */
		ret = delete_subtree(ipasam_state, dn);
	}

	if (ret != LDAP_SUCCESS) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	status = NT_STATUS_OK;
done:
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS ipasam_enum_trusted_domains(struct pdb_methods *methods,
					    TALLOC_CTX *mem_ctx,
					    uint32_t *num_domains,
					    struct pdb_trusted_domain ***domains)
{
	int rc;
	struct ipasam_private *ipasam_state =
		talloc_get_type_abort(methods->private_data, struct ipasam_private);
	char *filter = NULL;
	int scope = LDAP_SCOPE_SUBTREE;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	struct pdb_trusted_domain **tmp;

	filter = talloc_asprintf(mem_ctx, "(objectClass=%s)",
				 LDAP_OBJ_TRUSTED_DOMAIN);
	if (filter == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	rc = smbldap_search(ipasam_state->ldap_state,
			    ipasam_state->trust_dn,
			    scope, filter, NULL, 0, &result);
	TALLOC_FREE(filter);

	if (result != NULL) {
		smbldap_talloc_autofree_ldapmsg(mem_ctx, result);
	}

	if (rc == LDAP_NO_SUCH_OBJECT) {
		*num_domains = 0;
		*domains = NULL;
		return NT_STATUS_OK;
	}

	if (rc != LDAP_SUCCESS) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	*num_domains = 0;
	if (!(*domains = talloc_array(mem_ctx, struct pdb_trusted_domain *, 1))) {
		DEBUG(1, ("talloc failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	for (entry = ldap_first_entry(priv2ld(ipasam_state), result);
	     entry != NULL;
	     entry = ldap_next_entry(priv2ld(ipasam_state), entry))
	{
		struct pdb_trusted_domain *dom_info;

		if (!fill_pdb_trusted_domain(*domains, ipasam_state, entry,
					     &dom_info)) {
			talloc_free(*domains);
			return NT_STATUS_UNSUCCESSFUL;
		}

		tmp = talloc_realloc(*domains, *domains,
		                     struct pdb_trusted_domain *,
		                     (*(num_domains))+1);
		if (tmp == NULL) {
			talloc_free(*domains);
			return NT_STATUS_NO_MEMORY;
		}
		*domains = tmp;
		(*(domains))[*(num_domains)] = dom_info;
		(*(num_domains)) += 1;
	}

	DEBUG(5, ("ipasam_enum_trusted_domains: got %d domains\n", *num_domains));
	return NT_STATUS_OK;
}

static NTSTATUS ipasam_enum_trusteddoms(struct pdb_methods *methods,
					 TALLOC_CTX *mem_ctx,
					 uint32_t *num_domains,
					 struct trustdom_info ***domains)
{
	NTSTATUS status;
	struct pdb_trusted_domain **td;
	int i;

	status = ipasam_enum_trusted_domains(methods, mem_ctx,
					     num_domains, &td);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (*num_domains == 0) {
		return NT_STATUS_OK;
	}

	if (!(*domains = talloc_array(mem_ctx, struct trustdom_info *,
				      *num_domains))) {
		DEBUG(1, ("talloc failed\n"));
		goto fail;
	}

	for (i = 0; i < *num_domains; i++) {
		struct trustdom_info *dom_info;

		dom_info = talloc(*domains, struct trustdom_info);
		if (dom_info == NULL) {
			DEBUG(1, ("talloc failed\n"));
			goto fail;
		}

		dom_info->name = talloc_steal(mem_ctx, td[i]->netbios_name);
		sid_copy(&dom_info->sid, &td[i]->security_identifier);

		(*domains)[i] = dom_info;
	}

	return NT_STATUS_OK;

fail:
	talloc_free(td);
	talloc_free(*domains);

	return NT_STATUS_NO_MEMORY;
}

static uint32_t pdb_ipasam_capabilities(struct pdb_methods *methods)
{
	return PDB_CAP_STORE_RIDS | PDB_CAP_ADS | PDB_CAP_TRUSTED_DOMAINS_EX;
}

static bool init_sam_from_td(struct samu *user, struct pdb_trusted_domain *td,
			     LDAPMessage *entry,
			     struct ipasam_private *ipasam_state)
{
	NTSTATUS status;
	struct dom_sid *u_sid;
	struct dom_sid *g_sid;
	char *name;
	char *trustpw = NULL;
	uint8_t nt_key[16];
	bool res;
	char *sid_str;
	enum idmap_error_code err;

	if (!pdb_set_acct_ctrl(user, ACB_DOMTRUST | ACB_TRUSTED_FOR_DELEGATION,
			      PDB_SET)) {
		return false;
	}

	if (!pdb_set_domain(user, ipasam_state->domain_name, PDB_DEFAULT)) {
		return false;
	}

	name = talloc_asprintf(user, "%s$", td->netbios_name);
	if (name == NULL) {
		return false;
	}

	if (!pdb_set_username(user, name, PDB_SET)) {
		return false;
	}

	if (!pdb_set_nt_username(user, name, PDB_SET)) {
		return false;
	}

	sid_str = get_single_attribute(user, priv2ld(ipasam_state), entry,
				       LDAP_ATTRIBUTE_SID);
	if (sid_str == NULL) {
		DEBUG(5, ("Missing SID for trusted domain object.\n"));
		return false;
	}

	err = sss_idmap_sid_to_smb_sid(ipasam_state->idmap_ctx,
				       sid_str, &u_sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(10, ("Could not convert string %s to sid.\n", sid_str));
		talloc_free(sid_str);
		return false;
	}
	talloc_free(sid_str);

	if (!pdb_set_user_sid(user, u_sid, PDB_SET)) {
		talloc_free(u_sid);
		return false;
	}
	talloc_free(u_sid);

	g_sid = &ipasam_state->fallback_primary_group;
	if (!pdb_set_group_sid(user, g_sid, PDB_SET)) {
		return false;
	}

	status = get_trust_pwd(user, &td->trust_auth_incoming, &trustpw, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (!E_md4hash(trustpw, nt_key)) {
		res = false;
		goto done;
	}

	if (!pdb_set_nt_passwd(user, nt_key, PDB_SET)) {
		res = false;
		goto done;
	}

	res = true;
done:
	if (trustpw != NULL) {
		memset(trustpw, 0, strlen(trustpw));
		talloc_free(trustpw);
	}

	return res;
}

static bool ipasam_nthash_retrieve(struct ipasam_private *ipasam_state,
				       TALLOC_CTX *mem_ctx,
				       char *entry_dn,
				       DATA_BLOB *nthash)
{
	int ret;
	bool retval;
	LDAPMessage *result;
	LDAPMessage *entry = NULL;
	int count;
	struct smbldap_state *ldap_state = ipasam_state->ldap_state;
	const char *attr_list[] = {
					LDAP_ATTRIBUTE_NTHASH,
					NULL
				  };

	ret = smbldap_search(ldap_state, entry_dn,
			     LDAP_SCOPE_BASE, "(objectclass=*)", attr_list, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("Failed to get NT hash: %s\n",
			  ldap_err2string (ret)));
		return false;
	}

	count = ldap_count_entries(priv2ld(ipasam_state), result);

	if (count != 1) {
		DEBUG(1, ("Unexpected number of results [%d] for NT hash "
			  "of the single entry search.\n", count));
		ldap_msgfree(result);
		return false;
	}

	entry = ldap_first_entry(priv2ld(ipasam_state), result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get entry\n"));
		ldap_msgfree(result);
		return false;
	}

	retval = smbldap_talloc_single_blob(mem_ctx,
					priv2ld(ipasam_state),
					entry, LDAP_ATTRIBUTE_NTHASH,
					nthash);
	ldap_msgfree(result);
	return retval;
}

static bool ipasam_nthash_regen(struct ipasam_private *ipasam_state,
				TALLOC_CTX *mem_ctx,
				char * entry_dn)
{
	LDAPMod **mods = NULL;
	int ret;

	smbldap_set_mod(&mods, LDAP_MOD_ADD, LDAP_ATTRIBUTE_NTHASH, "MagicRegen");
	smbldap_talloc_autofree_ldapmod(mem_ctx, mods);

	ret = smbldap_modify(ipasam_state->ldap_state, entry_dn, mods);
	if (ret != LDAP_SUCCESS) {
		DEBUG(5, ("ipasam: attempt to regen ipaNTHash failed\n"));
	}
	return (ret == LDAP_SUCCESS);
}

static int ipasam_get_sid_by_gid(struct ipasam_private *ipasam_state,
				 uint32_t gid,
				 struct dom_sid *_sid)
{
	int ret;
	char *filter;
	TALLOC_CTX *tmp_ctx;
	LDAPMessage *entry = NULL;
	LDAPMessage *result = NULL;
	char *sid_str = NULL;
	struct dom_sid *sid = NULL;
	int count;
	enum idmap_error_code err;
	struct unixid id;

	tmp_ctx = talloc_init("ipasam_get_sid_by_gid");
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(%s=%s)(%s=%lu))",
					  LDAP_ATTRIBUTE_OBJECTCLASS,
					  LDAP_OBJ_POSIXGROUP,
					  LDAP_ATTRIBUTE_OBJECTCLASS,
					  LDAP_OBJ_GROUPMAP,
					  LDAP_ATTRIBUTE_GIDNUMBER,
					  (unsigned long) gid);
	if (filter == NULL) {
		ret = ENOMEM;
		goto done;
	}

	ret = smbldap_search(ipasam_state->ldap_state,
			     ipasam_state->base_dn,
			     LDAP_SCOPE_SUBTREE,filter, NULL, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		ret = ENOENT;
		goto done;
	}

	count = ldap_count_entries(priv2ld(ipasam_state), result);
	if (count != 1) {
		ret = ENOENT;
		goto done;
	}

	entry = ldap_first_entry(priv2ld(ipasam_state), result);
	if (entry == NULL) {
		ret = ENOENT;
		goto done;
	}

	sid_str = get_single_attribute(tmp_ctx,
				       priv2ld(ipasam_state),
				       entry, LDAP_ATTRIBUTE_SID);
	if (sid_str == NULL) {
		ret = ENOENT;
		goto done;
	}

	err = sss_idmap_sid_to_smb_sid(ipasam_state->idmap_ctx,
				       sid_str, &sid);
	if (err != IDMAP_SUCCESS) {
		ret = EFAULT;
		goto done;
	}
	sid_copy(_sid, sid);

	unixid_from_gid(&id, gid);

	idmap_cache_set_sid2unixid(sid, &id);

	ret = 0;

done:
	talloc_free(sid);
	ldap_msgfree(result);
	talloc_free(tmp_ctx);

	return ret;
}

static int ipasam_get_primary_group_sid(TALLOC_CTX *mem_ctx,
					struct ipasam_private *ipasam_state,
					LDAPMessage *entry,
					struct dom_sid **_group_sid)
{
	int ret;
	uint32_t uid;
	uint32_t gid;
	struct dom_sid *group_sid;
	struct unixid id;

	TALLOC_CTX *tmp_ctx = talloc_init("ipasam_get_primary_group_sid");
	if (tmp_ctx == NULL) {
		return ENOMEM;
	}

	if (!get_uint32_t_from_ldap_msg(ipasam_state, entry,
					LDAP_ATTRIBUTE_UIDNUMBER, &uid)) {
		ret = ENOENT;
		DEBUG(1, ("No uidnumber attribute found for this user!\n"));
		goto done;
	}

	if (!get_uint32_t_from_ldap_msg(ipasam_state, entry,
					LDAP_ATTRIBUTE_GIDNUMBER, &gid)) {
		ret = ENOENT;
		DEBUG(1, ("No gidnumber attribute found for this user!\n"));
		goto done;
	}

	group_sid = talloc(tmp_ctx, struct dom_sid);
	if (group_sid == NULL) {
		ret = ENOMEM;
		goto done;
	}

	if (uid == gid) { /* User private group, use default fallback group */
		sid_copy(group_sid,
			 &ipasam_state->fallback_primary_group);
		ret = 0;
		goto done;
	} else {
		ret = ipasam_get_sid_by_gid(ipasam_state, gid, group_sid);
		if (ret != 0) {
			goto done;
		}
	}

	unixid_from_gid(&id, gid);

	idmap_cache_set_sid2unixid(group_sid, &id);

	ret = 0;
done:

	if (ret == 0) {
		*_group_sid = talloc_steal(mem_ctx, group_sid);
	}

	talloc_free(tmp_ctx);

	return ret;
}

static bool init_sam_from_ldap(struct ipasam_private *ipasam_state,
				struct samu * sampass,
				LDAPMessage * entry)
{
	char *username = NULL;
	char *domain = NULL;
	char *nt_username = NULL;
	char *fullname = NULL;
	char *homedir = NULL;
	char *dir_drive = NULL;
	char *logon_script = NULL;
	char *profile_path = NULL;
	char *temp = NULL;
	bool ret = false;
	bool retval = false;
	int status;
	DATA_BLOB nthash;
	struct dom_sid *group_sid;

	TALLOC_CTX *tmp_ctx = talloc_init("init_sam_from_ldap");
	if (!tmp_ctx) {
		return false;
	}
	if (sampass == NULL || ipasam_state == NULL || entry == NULL) {
		DEBUG(0, ("init_sam_from_ldap: NULL parameters found!\n"));
		goto fn_exit;
	}

	if (priv2ld(ipasam_state) == NULL) {
		DEBUG(0, ("init_sam_from_ldap: ipasam_state->ldap_state->"
			  "ldap_struct is NULL!\n"));
		goto fn_exit;
	}

	if (!(username = smbldap_talloc_first_attribute(priv2ld(ipasam_state),
					entry, LDAP_ATTRIBUTE_UID, tmp_ctx))) {
		DEBUG(1, ("init_sam_from_ldap: No uid attribute found for "
			  "this user!\n"));
		goto fn_exit;
	}

	DEBUG(2, ("init_sam_from_ldap: Entry found for user: %s\n", username));

	nt_username = talloc_strdup(tmp_ctx, username);
	if (!nt_username) {
		goto fn_exit;
	}

	domain = talloc_strdup(tmp_ctx, ipasam_state->domain_name);
	if (!domain) {
		goto fn_exit;
	}

	pdb_set_username(sampass, username, PDB_SET);

	pdb_set_domain(sampass, domain, PDB_DEFAULT);
	pdb_set_nt_username(sampass, nt_username, PDB_SET);

	if ((temp = smbldap_talloc_single_attribute(
			priv2ld(ipasam_state),
			entry, LDAP_ATTRIBUTE_SECURITY_IDENTIFIER,
			tmp_ctx)) != NULL) {
		pdb_set_user_sid_from_string(sampass, temp, PDB_SET);

		status = ipasam_get_primary_group_sid(tmp_ctx, ipasam_state,
						      entry, &group_sid);
		if (status != 0) {
			goto fn_exit;
		}
	} else {
		goto fn_exit;
	}

	fullname = smbldap_talloc_single_attribute(
			priv2ld(ipasam_state),
			entry,
			LDAP_ATTRIBUTE_CN,
			tmp_ctx);
	if (fullname) {
		pdb_set_fullname(sampass, fullname, PDB_SET);
	}

	dir_drive = smbldap_talloc_single_attribute(
			priv2ld(ipasam_state),
			entry, LDAP_ATTRIBUTE_HOME_DRIVE, tmp_ctx);
	if (dir_drive) {
		pdb_set_dir_drive(sampass, dir_drive, PDB_SET);
	}

	homedir = smbldap_talloc_single_attribute(
			priv2ld(ipasam_state),
			entry, LDAP_ATTRIBUTE_HOME_PATH, tmp_ctx);
	if (homedir) {
		pdb_set_homedir(sampass, homedir, PDB_SET);
	}

	logon_script = smbldap_talloc_single_attribute(
			priv2ld(ipasam_state),
			entry, LDAP_ATTRIBUTE_LOGON_SCRIPT, tmp_ctx);
	if (logon_script) {
		pdb_set_logon_script(sampass, logon_script, PDB_SET);
	}

	profile_path = smbldap_talloc_single_attribute(
			priv2ld(ipasam_state),
			entry, LDAP_ATTRIBUTE_PROFILE_PATH, tmp_ctx);
	if (profile_path) {
		pdb_set_profile_path(sampass, profile_path, PDB_SET);
	}


	pdb_set_acct_ctrl(sampass, ACB_NORMAL, PDB_SET);

	retval = smbldap_talloc_single_blob(tmp_ctx,
					priv2ld(ipasam_state),
					entry, LDAP_ATTRIBUTE_NTHASH,
					&nthash);
	if (!retval) {
		/* NT Hash is not in place. Attempt to retrieve it from
		 * the RC4-HMAC key if that exists in Kerberos credentials.
		 * IPA 389-ds plugin allows to ask for it by setting
		 * ipaNTHash to MagicRegen value.
		 * */
		temp = smbldap_talloc_dn(tmp_ctx, priv2ld(ipasam_state), entry);
		if (temp) {
			retval = ipasam_nthash_regen(ipasam_state,
						     tmp_ctx, temp);
			if (retval) {
				retval = ipasam_nthash_retrieve(ipasam_state,
								tmp_ctx, temp, &nthash);
			}
		}
	}

	if (!retval) {
		DEBUG(5, ("Failed to read NT hash form LDAP response.\n"));
	}

	if (nthash.length != NT_HASH_LEN && nthash.length != 0) {
		DEBUG(5, ("NT hash from LDAP has the wrong size. Perhaps password was not re-set?\n"));
	} else {
		if (!pdb_set_nt_passwd(sampass, nthash.data, PDB_SET)) {
			DEBUG(5, ("Failed to set NT hash.\n"));
		}
	}
/* FIXME: */
	if (!pdb_set_pass_last_set_time(sampass, (time_t) 1, PDB_SET)) {
		DEBUG(5, ("Failed to set last time set.\n"));
	}

	ret = true;

fn_exit:

	talloc_free(tmp_ctx);
	return ret;
}

static NTSTATUS getsam_interdom_trust_account(struct pdb_methods *methods,
					      struct samu *user,
					      const char *sname, int lastidx)
{
	char *dom_name;
	struct ipasam_private *ipasam_state =
			talloc_get_type_abort(methods->private_data, struct ipasam_private);
	TALLOC_CTX *tmp_ctx;
	struct pdb_trusted_domain *td;
	NTSTATUS status;
	LDAPMessage *entry = NULL;

	/* The caller must check that (sname[lastidx] == '.') || (sname[lastidx] == '$'))
	 * before calling this function.
	 */

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	dom_name = talloc_strdup(tmp_ctx, sname);
	if (dom_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}
	dom_name[lastidx] = '\0';

	if (!get_trusted_domain_by_name_int(ipasam_state, tmp_ctx, dom_name,
					    &entry)) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	if (entry == NULL) {
		DEBUG(5, ("getsam_interdom_trust_account: no such trusted " \
                          "domain: %s\n", dom_name));
		status = NT_STATUS_NO_SUCH_DOMAIN;
		goto done;
	}

	if (!fill_pdb_trusted_domain(tmp_ctx, ipasam_state, entry, &td)) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!init_sam_from_td(user, td, entry, ipasam_state)) {
		DEBUG(5, ("init_sam_from_td failed.\n"));
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	status = NT_STATUS_OK;

done:
	talloc_free(tmp_ctx);
	return status;
}

static NTSTATUS ipasam_getsampwnam(struct pdb_methods *methods,
				    struct samu *user,
				    const char *sname)
{
	struct ipasam_private *ipasam_state =
			talloc_get_type_abort(methods->private_data, struct ipasam_private);
	int lastidx;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	char *filter;
	char *escaped_user;
	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	int ret;
	int count;

	lastidx = strlen(sname);
	if (lastidx > 0) {
		lastidx--;
	} else {
		/* strlen() must return >= 0 so it means we've got an empty name */
		return NT_STATUS_NO_SUCH_USER;
	}
	if ((sname[lastidx] == '.') || (sname[lastidx] == '$')) {
		status = getsam_interdom_trust_account(methods, user, sname, lastidx);
		/* If last character was '$', we should ignore failure and continue
		 * as this could still be a machine account */
		if ((sname[lastidx] == '.') || NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	escaped_user = escape_ldap_string(tmp_ctx, sname);
	if (escaped_user == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	filter = talloc_asprintf(tmp_ctx, "(&(%s=%s)(%s=%s))",
					  LDAP_ATTRIBUTE_OBJECTCLASS,
					  LDAP_OBJ_SAMBASAMACCOUNT,
					  LDAP_ATTRIBUTE_UID, escaped_user);
	if (filter == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	ret = smbldap_search(ipasam_state->ldap_state,
			     ipasam_state->base_dn,
			     LDAP_SCOPE_SUBTREE,filter, NULL, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	count = ldap_count_entries(priv2ld(ipasam_state), result);
	if (count != 1) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	entry = ldap_first_entry(priv2ld(ipasam_state), result);
	if (entry == NULL) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	if (!init_sam_from_ldap(ipasam_state, user, entry)) {
		status = NT_STATUS_NO_SUCH_USER;
		goto done;
	}

	status = NT_STATUS_OK;

done:
	ldap_msgfree(result);
	talloc_free(tmp_ctx);
	return status;
}

static bool ipasam_get_trusteddom_pw(struct pdb_methods *methods,
				      const char *domain,
				      char** pwd,
				      struct dom_sid *sid,
				      time_t *pass_last_set_time)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	struct pdb_trusted_domain *td;
	bool ret = false;
	char *trustpw;
	NTTIME last_update;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return false;
	}

	status = ipasam_get_trusted_domain(methods, tmp_ctx, domain, &td);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		goto done;
	}

	status = get_trust_pwd(tmp_ctx, &td->trust_auth_incoming,
			       &trustpw, &last_update);
	if (!NT_STATUS_IS_OK(status)) {
		ret = false;
		goto done;
	}

	/* trusteddom_pw routines do not use talloc yet... */
	if (pwd != NULL) {
		*pwd = strdup(trustpw);
		memset(trustpw, 0, strlen(trustpw));
		talloc_free(trustpw);
		if (*pwd == NULL) {
			ret =false;
			goto done;
		}
	}

	if (pass_last_set_time != NULL) {
		*pass_last_set_time = nt_time_to_unix(last_update);
	}

	if (sid != NULL) {
		sid_copy(sid, &td->security_identifier);
	}

	ret = true;
done:
	talloc_free(tmp_ctx);
	return ret;
}

static bool ipasam_set_trusteddom_pw(struct pdb_methods *methods,
				      const char* domain,
				      const char* pwd,
				      const struct dom_sid *sid)
{
	return false;
}

static bool ipasam_del_trusteddom_pw(struct pdb_methods *methods,
				      const char *domain)
{
	return false;
}

static struct pdb_domain_info *pdb_ipasam_get_domain_info(struct pdb_methods *pdb_methods,
							  TALLOC_CTX *mem_ctx)
{
	struct pdb_domain_info *info;
	struct ipasam_private *ipasam_state =
			talloc_get_type_abort(pdb_methods->private_data, struct ipasam_private);
	char sid_buf[24];
	DATA_BLOB sid_blob;
	NTSTATUS status;

	info = talloc(mem_ctx, struct pdb_domain_info);
	if (info == NULL) {
		DEBUG(1, ("talloc failed\n"));
		return NULL;
	}

	info->name = talloc_strdup(info, ipasam_state->flat_name);
	if (info->name == NULL) {
		DEBUG(1, ("talloc_strdup domain_name failed\n"));
		goto fail;
	}

	status = ipasam_get_domain_name(ipasam_state, info, &info->dns_domain);
	if (!NT_STATUS_IS_OK(status) || (info->dns_domain == NULL)) {
		goto fail;
	}
	info->dns_forest = talloc_strdup(info, info->dns_domain);

	/* we expect a domain SID to have 4 sub IDs */
	if (ipasam_state->domain_sid.num_auths != 4) {
		goto fail;
	}

	sid_copy(&info->sid, &ipasam_state->domain_sid);

	if (!sid_linearize(sid_buf, sizeof(sid_buf), &info->sid)) {
		goto fail;
	}

	/* the first 8 bytes of the linearized SID are not random,
	 * so we skip them */
	sid_blob.data = (uint8_t *) sid_buf + 8 ;
	sid_blob.length = 16;

	status = GUID_from_ndr_blob(&sid_blob, &info->guid);
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	return info;

fail:
	TALLOC_FREE(info);
	return NULL;
}

static void ipasam_free_private_data(void **vp)
{
	struct ipasam_private **ipasam_state = (struct ipasam_private **)vp;

	smbldap_free_struct(&(*ipasam_state)->ldap_state);

	if ((*ipasam_state)->result != NULL) {
		ldap_msgfree((*ipasam_state)->result);
		(*ipasam_state)->result = NULL;
	}
	if ((*ipasam_state)->domain_dn != NULL) {
		free((*ipasam_state)->domain_dn);
		(*ipasam_state)->domain_dn = NULL;
	}

	*ipasam_state = NULL;

	/* No need to free any further, as it is talloc()ed */
}

static struct dom_sid *get_fallback_group_sid(TALLOC_CTX *mem_ctx,
					      struct smbldap_state *ldap_state,
					      struct sss_idmap_ctx *idmap_ctx,
					      LDAPMessage *dom_entry,
					      char **fallback_group_gid_str)
{
	char *dn;
	char *sid;
	char *gidnumber;
	int ret;
	const char *filter = "objectClass=*";
	const char *attr_list[] = {
					LDAP_ATTRIBUTE_SID,
					LDAP_ATTRIBUTE_GIDNUMBER,
					NULL};
	LDAPMessage *result;
	LDAPMessage *entry;
	LDAP *ld = NULL;
	enum idmap_error_code err;
	struct dom_sid *fallback_group_sid;

	ld = _smbldap_get_ldap(ldap_state);
	dn = get_single_attribute(mem_ctx, ld,
				  dom_entry,
				  LDAP_ATTRIBUTE_FALLBACK_PRIMARY_GROUP);
	if (dn == NULL) {
		DEBUG(0, ("Missing mandatory attribute %s.\n",
			  LDAP_ATTRIBUTE_FALLBACK_PRIMARY_GROUP));
		return NULL;
	}

	ret = smbldap_search(ldap_state, dn, LDAP_SCOPE_BASE, filter, attr_list,
			     0, &result);
	talloc_free(dn);
	if (ret != LDAP_SUCCESS) {
		DEBUG(2,("Failed to read faillback group [%s].", dn));
		return NULL;
	}

	ld = _smbldap_get_ldap(ldap_state);
	entry = ldap_first_entry(ld, result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get fallback group entry\n"));
		ldap_msgfree(result);
		return NULL;
	}

	sid = get_single_attribute(mem_ctx, ld,
				  entry, LDAP_ATTRIBUTE_SID);
	if (sid == NULL) {
		DEBUG(0, ("Missing mandatory attribute %s.\n",
			  LDAP_ATTRIBUTE_SID));
		ldap_msgfree(result);
		return NULL;
	}

	err = sss_idmap_sid_to_smb_sid(idmap_ctx, sid, &fallback_group_sid);
	if (err != IDMAP_SUCCESS) {
		DEBUG(1, ("SID [%s] could not be converted\n", sid));
		ldap_msgfree(result);
		talloc_free(sid);
		return NULL;
	}
	talloc_free(sid);

	gidnumber = get_single_attribute(mem_ctx, ld,
					entry, LDAP_ATTRIBUTE_GIDNUMBER);
	if (gidnumber == NULL) {
		DEBUG(0, ("Missing mandatory attribute %s.\n",
			  LDAP_ATTRIBUTE_GIDNUMBER));
		ldap_msgfree(result);
		return NULL;
	}

	*fallback_group_gid_str = gidnumber;

	ldap_msgfree(result);

	return fallback_group_sid;
}

static NTSTATUS ipasam_search_domain_info(struct smbldap_state *ldap_state,
					    LDAPMessage ** result)
{
	const char *filter = "objectClass=ipaNTDomainAttrs";
	const char *attr_list[] = {
					LDAP_ATTRIBUTE_FLAT_NAME,
					LDAP_ATTRIBUTE_SID,
					LDAP_ATTRIBUTE_FALLBACK_PRIMARY_GROUP,
					LDAP_ATTRIBUTE_OBJECTCLASS,
					NULL};
	int count;
	int ret;

	ret = smbldap_search_suffix(ldap_state, filter, attr_list , result);

	if (ret != LDAP_SUCCESS) {
		DEBUG(2,("ipasam_search_domain_info: "
			 "smbldap_search_suffix failed: %s\n",
			 ldap_err2string (ret)));
		DEBUG(2,("ipasam_search_domain_info: Query was: %s\n", filter));
		return NT_STATUS_UNSUCCESSFUL;
	}

	count = ldap_count_entries(_smbldap_get_ldap(ldap_state), *result);

	if (count == 1) {
		return NT_STATUS_OK;
	}

	DEBUG(0, ("iapsam_search_domain_info: Got [%d] domain info entries, "
		  "but expected only 1.\n", count));

	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ipasam_get_base_dn(struct smbldap_state *ldap_state,
				   TALLOC_CTX *mem_ctx, char **base_dn)
{
	int ret;
	LDAPMessage *result;
	LDAPMessage *entry = NULL;
	LDAP *ld = NULL;
	int count;
	char *nc;
	const char *attr_list[] = {
					"namingContexts",
					"defaultNamingContext",
					NULL
				  };

	ret = smbldap_search(ldap_state, "", LDAP_SCOPE_BASE,
			     "(objectclass=*)", attr_list, 0, &result);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("Failed to get base DN from RootDSE: %s\n",
			  ldap_err2string (ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ld = _smbldap_get_ldap(ldap_state);
	count = ldap_count_entries(ld, result);

	if (count != 1) {
		DEBUG(1, ("Unexpected number of results [%d] for base DN "
			  "search.\n", count));
		ldap_msgfree(result);
		return NT_STATUS_OK;
	}

	entry = ldap_first_entry(ld, result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get RootDSE entry\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	nc = get_single_attribute(mem_ctx, ld, entry,
				  "defaultNamingContext");
	if (nc != NULL) {
		*base_dn = nc;
		ldap_msgfree(result);
		return NT_STATUS_OK;
	}

	nc = get_single_attribute(mem_ctx, ld, entry,
				  "namingContexts");
	if (nc != NULL) {
		*base_dn = nc;
		ldap_msgfree(result);
		return NT_STATUS_OK;
	}

	ldap_msgfree(result);
	return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS ipasam_get_domain_name(struct ipasam_private *ipasam_state,
				       TALLOC_CTX *mem_ctx,
				       char **domain_name)
{
	int ret;
	LDAPMessage *result;
	LDAPMessage *entry = NULL;
	LDAP *ld = NULL;
	int count;
	char *cn;
	struct smbldap_state *ldap_state = ipasam_state->ldap_state;
	const char *attr_list[] = {
					LDAP_ATTRIBUTE_ASSOCIATED_DOMAIN,
					NULL
				  };

	ret = smbldap_search(ldap_state,
			     ipasam_state->base_dn,
			     LDAP_SCOPE_BASE,
			     "objectclass=" LDAP_OBJ_DOMAINRELATED, attr_list, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("Failed to get domain name: %s\n",
			  ldap_err2string (ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ld = _smbldap_get_ldap(ldap_state);
	count = ldap_count_entries(ld, result);

	if (count != 1) {
		DEBUG(1, ("Unexpected number of results [%d] for domain name "
			  "search.\n", count));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ld, result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get domainRelatedObject entry\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	cn = get_single_attribute(mem_ctx, ld, entry,
				  LDAP_ATTRIBUTE_ASSOCIATED_DOMAIN);
	if (cn == NULL) {
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*domain_name = cn;
	ldap_msgfree(result);
	return NT_STATUS_OK;
}

static NTSTATUS ipasam_get_enctypes(struct ipasam_private *ipasam_state,
				    uint32_t *enctypes)
{
	int ret;
	LDAPMessage *result;
	LDAPMessage *entry = NULL;
	LDAP *ld = NULL;
	int count, i;
	char **enctype_list, *dn;
	krb5_enctype enctype;
	krb5_error_code err;
	struct smbldap_state *ldap_state = ipasam_state->ldap_state;
	const char *attr_list[] = {
					"krbDefaultEncSaltTypes",
					NULL
				  };

	dn = talloc_asprintf(ipasam_state, "cn=%s,cn=kerberos,%s",
			     ipasam_state->realm,
			     ipasam_state->base_dn);

	if (dn == NULL) {
		DEBUG(1, ("Failed to construct DN to the realm's kerberos container\n"));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ret = smbldap_search(ldap_state, dn, LDAP_SCOPE_BASE,
			     "objectclass=krbrealmcontainer", attr_list, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("Failed to get kerberos realm encryption types: %s\n",
			  ldap_err2string (ret)));
		talloc_free(dn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ld = _smbldap_get_ldap(ldap_state);
	count = ldap_count_entries(ld, result);

	if (count != 1) {
		DEBUG(1, ("Unexpected number of results [%d] for realm "
			  "search.\n", count));
		ldap_msgfree(result);
		talloc_free(dn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ld, result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get krbrealmcontainer entry\n"));
		ldap_msgfree(result);
		talloc_free(dn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	enctype_list = get_attribute_values(dn, ld, entry,
					    "krbDefaultEncSaltTypes", &count);
	ldap_msgfree(result);
	if (enctype_list == NULL) {
		talloc_free(dn);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*enctypes = 0;
	for (i = 0; i < count ; i++) {
		char *enc = strchr(enctype_list[i], ':');
		if (enc != NULL) {
			*enc = '\0';
		}
		err = krb5_string_to_enctype(enctype_list[i], &enctype);
		if (enc != NULL) {
			*enc = ':';
		}
		if (err) {
			continue;
		}
		switch (enctype) {
			case ENCTYPE_DES_CBC_CRC:
				*enctypes |= KERB_ENCTYPE_DES_CBC_CRC;
				break;
			case ENCTYPE_DES_CBC_MD5:
				*enctypes |= KERB_ENCTYPE_DES_CBC_MD5;
				break;
			case ENCTYPE_ARCFOUR_HMAC:
				if (!ipasam_state->fips_enabled) {
					*enctypes |= KERB_ENCTYPE_RC4_HMAC_MD5;
				}
				break;
			case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
				*enctypes |= KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96;
				break;
			case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
				*enctypes |= KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
				break;
			default:
				break;
		}
	}

	talloc_free(dn);
	return NT_STATUS_OK;
}

static NTSTATUS ipasam_get_realm(struct ipasam_private *ipasam_state,
				 char **realm)
{
	int ret;
	LDAPMessage *result;
	LDAPMessage *entry = NULL;
	LDAP *ld = NULL;
	int count;
	char *cn;
	struct smbldap_state *ldap_state = ipasam_state->ldap_state;
	const char *attr_list[] = {
					"cn",
					NULL
				  };

	ret = smbldap_search(ldap_state,
			     ipasam_state->base_dn,
			     LDAP_SCOPE_SUBTREE,
			     "objectclass=krbrealmcontainer", attr_list, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("Failed to get realm: %s\n",
			  ldap_err2string (ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ld = _smbldap_get_ldap(ldap_state);
	count = ldap_count_entries(ld, result);

	if (count != 1) {
		DEBUG(1, ("Unexpected number of results [%d] for realm "
			  "search.\n", count));
		ldap_msgfree(result);
		return NT_STATUS_OK;
	}

	entry = ldap_first_entry(ld, result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get krbrealmcontainer entry\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	cn = get_single_attribute(ipasam_state, ld,
				  entry,
				  "cn");
	if (cn == NULL) {
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	*realm = cn;
	ldap_msgfree(result);
	return NT_STATUS_OK;
}

#ifdef HAVE_PDB_ENUM_UPN_SUFFIXES
static NTSTATUS ipasam_enum_upn_suffixes(struct pdb_methods *pdb_methods,
					 TALLOC_CTX *mem_ctx,
					 uint32_t *num_suffixes,
					 char ***suffixes)
{
	int ret;
	LDAPMessage *result;
	LDAPMessage *entry = NULL;
	LDAP *ld = NULL;
	int count, i;
	char *realmdomains_dn = NULL;
	char **domains = NULL;
	struct ipasam_private *ipasam_state;
	struct smbldap_state *ldap_state;
	const char *attr_list[] = {
					LDAP_ATTRIBUTE_ASSOCIATED_DOMAIN,
					NULL
				  };

	if ((suffixes == NULL) || (num_suffixes == NULL)) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	ipasam_state = talloc_get_type_abort(pdb_methods->private_data, struct ipasam_private);
	ldap_state = ipasam_state->ldap_state;

	realmdomains_dn = talloc_asprintf(mem_ctx, "%s,%s", LDAP_CN_REALM_DOMAINS,
					  ipasam_state->base_dn);
	if (realmdomains_dn == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = smbldap_search(ldap_state,
			     realmdomains_dn,
			     LDAP_SCOPE_BASE,
			     "objectclass=" LDAP_OBJ_DOMAINRELATED, attr_list, 0,
			     &result);
	if (ret != LDAP_SUCCESS) {
		DEBUG(1, ("Failed to get list of realm domains: %s\n",
			  ldap_err2string (ret)));
		return NT_STATUS_UNSUCCESSFUL;
	}

	ld = _smbldap_get_ldap(ldap_state);
	count = ldap_count_entries(ld, result);
	if (count != 1) {
		DEBUG(1, ("Unexpected number of results [%d] for realm domains "
			  "search.\n", count));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	entry = ldap_first_entry(ld, result);
	if (entry == NULL) {
		DEBUG(0, ("Could not get domainRelatedObject entry\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	domains = get_attribute_values(mem_ctx, ld, entry,
					LDAP_ATTRIBUTE_ASSOCIATED_DOMAIN, &count);
	if (domains == NULL) {
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Since associatedDomain has attributeType MUST, there must be at least one domain */
	for (i = 0; i < count ; i++) {
		/* TODO: use comparison function friendly to IDN */
		if (strcasecmp(ipasam_state->domain_name, domains[i]) == 0) {
			break;
		}
	}

	if (i < count) {
		/* If we found our primary domain in the list and it is alone, exit with empty list */
		if (count == 1) {
			ldap_msgfree(result);
			talloc_free(domains);
			return NT_STATUS_UNSUCCESSFUL;
		}

		talloc_free(domains[i]);

		/* if i is not last element, move everything down */
		if (i != (count - 1)) {
			memmove(domains + i, domains + i + 1, sizeof(char *) * (count - i - 1));
		}

		/* we don't resize whole list, only reduce number of elements in it
		 * since sizing down a single pointer will not reduce memory usage in talloc
		 */
		domains[count - 1] = NULL;
		*suffixes = domains;
		*num_suffixes = count - 1;
	} else {
		/* There is no our primary domain in the list */
		*suffixes = domains;
		*num_suffixes = count;
	}

	ldap_msgfree(result);
	return NT_STATUS_OK;
}
#endif /* HAVE_PDB_ENUM_UPN_SUFFIXES */


#define SECRETS_DOMAIN_SID    "SECRETS/SID"
static char *sec_key(TALLOC_CTX *mem_ctx, const char *d)
{
	char *tmp;
	char *res;

	tmp = talloc_asprintf(mem_ctx, "%s/%s", SECRETS_DOMAIN_SID, d);
	res = talloc_strdup_upper(mem_ctx, tmp);
	talloc_free(tmp);

	return res;
}

static NTSTATUS save_sid_to_secret(struct ipasam_private *ipasam_state)
{
	char hostname[255];
	int ret;
	char *p;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	tmp_ctx =talloc_new(NULL);
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (!secrets_store(sec_key(tmp_ctx, ipasam_state->domain_name),
			   &ipasam_state->domain_sid, sizeof(struct dom_sid))) {
		DEBUG(1, ("Failed to store domain SID"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	if (!secrets_store(sec_key(tmp_ctx,
				   ipasam_state->flat_name),
			   &ipasam_state->domain_sid, sizeof(struct dom_sid))) {
		DEBUG(1, ("Failed to store domain SID"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	ret = gethostname(hostname, sizeof(hostname));
	if (ret == -1) {
		DEBUG(1, ("gethostname failed.\n"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	hostname[sizeof(hostname)-1] = '\0';
	p = strchr(hostname, '.');
	if (p != NULL) {
		*p = '\0';
	}

	if (!secrets_store(sec_key(tmp_ctx, hostname),
			   &ipasam_state->domain_sid, sizeof(struct dom_sid))) {
		DEBUG(1, ("Failed to store domain SID"));
		status = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	status = NT_STATUS_OK;

done:
	talloc_free(tmp_ctx);
	return status;
}

struct ipasam_sasl_interact_priv {
	krb5_context context;
	krb5_principal principal;
	krb5_keytab keytab;
	krb5_get_init_creds_opt *options;
	krb5_creds creds;
	krb5_ccache ccache;
	const char *name;
	int name_len;
};

static int ldap_sasl_interact(LDAP *ld, unsigned flags, void *priv_data, void *sit)
{
	sasl_interact_t *in = NULL;
	int ret = LDAP_OTHER;
	struct ipasam_sasl_interact_priv *data = (struct ipasam_sasl_interact_priv*) priv_data;

	if (!ld) return LDAP_PARAM_ERROR;

	for (in = sit; in && in->id != SASL_CB_LIST_END; in++) {
		switch(in->id) {
		case SASL_CB_USER:
			in->result = data->name;
			in->len = data->name_len;
			ret = LDAP_SUCCESS;
			break;
		case SASL_CB_GETREALM:
			in->result = data->principal->realm.data;
			in->len = data->principal->realm.length;
			ret = LDAP_SUCCESS;
			break;
		default:
			in->result = NULL;
			in->len = 0;
			ret = LDAP_OTHER;
		}
	}
	return ret;
}


static void bind_callback_cleanup_creds(struct ipasam_sasl_interact_priv *datap) {
	krb5_free_cred_contents(datap->context, &datap->creds);

	if (datap->options) {
		krb5_get_init_creds_opt_free(datap->context, datap->options);
		datap->options = NULL;
	}
}

static void bind_callback_cleanup(struct ipasam_sasl_interact_priv *datap, krb5_error_code rc) {
	const char *errstring = NULL;

	if (!datap->context) {
		return;
	}

	if (rc) {
		errstring = krb5_get_error_message(datap->context, rc);
		DEBUG(0,("kerberos error: code=%d, message=%s\n", rc, errstring));
		krb5_free_error_message(datap->context, errstring);
	}

	bind_callback_cleanup_creds(datap);

	if (datap->keytab) {
		krb5_kt_close(datap->context, datap->keytab);
		datap->keytab = NULL;
	}

	if (datap->ccache) {
		krb5_cc_close(datap->context, datap->ccache);
		datap->ccache = NULL;
	}

	if (datap->principal) {
		krb5_free_principal(datap->context, datap->principal);
		datap->principal = NULL;
	}

	krb5_free_context(datap->context);
	datap->context = NULL;
}

static krb5_error_code bind_callback_obtain_creds(struct ipasam_sasl_interact_priv *datap) {
	krb5_error_code rc;

	rc = krb5_get_init_creds_opt_alloc(datap->context, &datap->options);
	if (rc) {
		return rc;
	}

	rc = krb5_get_init_creds_opt_set_out_ccache(datap->context, datap->options, datap->ccache);
	if (rc) {
		return rc;
	}

	rc = krb5_get_init_creds_keytab(datap->context, &datap->creds, datap->principal, datap->keytab,
					0, NULL, datap->options);
	return rc;
}

extern const char * lp_dedicated_keytab_file(void);
static int bind_callback(LDAP *ldap_struct, struct smbldap_state *ldap_state, void* ipasam_priv) {
	krb5_error_code rc;
	krb5_creds *out_creds = NULL;
	krb5_creds in_creds;

	struct ipasam_sasl_interact_priv data;
	struct ipasam_private *ipasam_state = NULL;
	int ret;

	memset(&data, 0, sizeof(struct ipasam_sasl_interact_priv));
	memset(&in_creds, 0, sizeof(krb5_creds));

	ipasam_state = talloc_get_type_abort(ipasam_priv, struct ipasam_private);

	if ((ipasam_state->client_princ == NULL) ||
	    (ipasam_state->server_princ == NULL)) {
		DEBUG(0, ("bind_callback: ipasam service principals are not set, cannot use GSSAPI bind\n"));
		return LDAP_LOCAL_ERROR;
	}

	data.name = ipasam_state->client_princ;
	data.name_len = strlen(data.name);

	rc = krb5_init_context(&data.context);
	if (rc) {
		return LDAP_LOCAL_ERROR;
	}

	rc = krb5_parse_name(data.context, data.name, &data.principal);
	if (rc) {
		bind_callback_cleanup(&data, rc);
		return LDAP_LOCAL_ERROR;
	}

	rc = krb5_cc_default(data.context, &data.ccache);

	if (rc) {
		bind_callback_cleanup(&data, rc);
		return LDAP_LOCAL_ERROR;
	}

	rc = krb5_kt_resolve(data.context, lp_dedicated_keytab_file(), &data.keytab);
	if (rc) {
		bind_callback_cleanup(&data, rc);
		return LDAP_LOCAL_ERROR;
	}

	rc = krb5_parse_name(data.context, ipasam_state->client_princ, &in_creds.client);
	if (rc) {
		krb5_free_principal(data.context, data.creds.client);
		bind_callback_cleanup(&data, rc);
		return LDAP_LOCAL_ERROR;
	}

	rc = krb5_parse_name(data.context, ipasam_state->server_princ, &in_creds.server);
	if (rc) {
		krb5_free_principal(data.context, in_creds.server);
		bind_callback_cleanup(&data, rc);
		return LDAP_LOCAL_ERROR;
	}

	rc = krb5_get_credentials(data.context, KRB5_GC_CACHED, data.ccache, &in_creds, &out_creds);
	krb5_free_principal(data.context, in_creds.server);
	krb5_free_principal(data.context, in_creds.client);

	if (rc != 0 && rc != KRB5KRB_AP_ERR_TKT_NYV && rc != KRB5KRB_AP_ERR_TKT_EXPIRED) {
		rc = bind_callback_obtain_creds(&data);
		if (rc) {
			bind_callback_cleanup(&data, rc);
			return LDAP_LOCAL_ERROR;
		}
	}

	ret = ldap_sasl_interactive_bind_s(ldap_struct,
					   NULL, "GSSAPI",
					   NULL, NULL,
					   LDAP_SASL_QUIET,
					   ldap_sasl_interact, &data);

	/* By now we have 'ret' for LDAP result and 'rc' for Kerberos result
	 * if LDAP_API_ERROR(ret) is true, LDAP server rejected our ccache. There may be several issues:
	 *
	 * 1. Credentials are invalid due to outdated ccache leftover from previous install or ticket is from future
	 *    Wipe out old ccache and start again
	 *
	 * 2. Key in the keytab is not enough to obtain ticket for cifs/FQDN@REALM service
	 *    Cannot continue without proper keytab
	 *
	 * Only process (1) because (2) and other errors will be taken care of by smbd after multiple retries.
	 *
	 * Since both smbd and winbindd will use this passdb module, on startup both will try to access the same
	 * ccache. It may happen that if ccache was missing or contained invalid cached credentials, that one of
	 * them will complain loudly about missing ccache file at the time when the other one will be creating
	 * a new ccache file by the above call of bind_callback_obtain_creds(). This is expected and correct behavior.
	 *
	 */

	if (LDAP_API_ERROR(ret) &&
	    ((rc == 0) || (rc == KRB5KRB_AP_ERR_TKT_NYV) || (rc == KRB5KRB_AP_ERR_TKT_EXPIRED))) {
		bind_callback_cleanup_creds(&data);
		rc = bind_callback_obtain_creds(&data);
		if (rc) {
			bind_callback_cleanup(&data, rc);
			return LDAP_LOCAL_ERROR;
		}
		ret = ldap_sasl_interactive_bind_s(ldap_struct,
						   NULL, "GSSAPI",
						   NULL, NULL,
						   LDAP_SASL_QUIET,
						   ldap_sasl_interact, &data);
	}

	if (LDAP_SECURITY_ERROR(ret)) {
		DEBUG(0, ("bind_callback: cannot perform interactive SASL bind with GSSAPI. LDAP security error is %d\n", ret));
	}

	if (out_creds) {
		krb5_free_creds(data.context, out_creds);
	}
	bind_callback_cleanup(&data, 0);
	return ret;
}

static NTSTATUS ipasam_generate_principals(struct ipasam_private *ipasam_state) {

	krb5_error_code rc;
	int ret;
	krb5_context context;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	char hostname[255];
	char *default_realm = NULL;

	if (!ipasam_state) {
		return status;
	}

	rc = krb5_init_context(&context);
	if (rc) {
		return status;
	}

	ret = gethostname(hostname, sizeof(hostname));
	if (ret == -1) {
		DEBUG(1, ("gethostname failed.\n"));
		goto done;
	}
	hostname[sizeof(hostname)-1] = '\0';

	rc = krb5_get_default_realm(context, &default_realm);
	if (rc) {
		goto done;
	};

	if (ipasam_state->client_princ) {
		talloc_free(ipasam_state->client_princ);
		ipasam_state->client_princ = NULL;
	}

	ipasam_state->client_princ = talloc_asprintf(ipasam_state,
						     "cifs/%s@%s",
						     hostname,
						     default_realm);

	if (ipasam_state->client_princ == NULL) {
		DEBUG(0, ("Failed to create ipasam client principal.\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (ipasam_state->server_princ) {
		talloc_free(ipasam_state->server_princ);
		ipasam_state->server_princ = NULL;
	}

	ipasam_state->server_princ = talloc_asprintf(ipasam_state,
						     "ldap/%s@%s",
						     hostname,
						     default_realm);

	if (ipasam_state->server_princ == NULL) {
		DEBUG(0, ("Failed to create ipasam server principal.\n"));
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	status = NT_STATUS_OK;

done:

	if (default_realm) {
		krb5_free_default_realm(context, default_realm);
	}

	if (context) {
		krb5_free_context(context);
	}
	return status;
}

static NTSTATUS pdb_init_ipasam(struct pdb_methods **pdb_method,
				const char *location)
{
	struct ipasam_private *ipasam_state;

	char *uri;
	NTSTATUS status;
	char *dn = NULL;
	char *domain_sid_string = NULL;
	struct dom_sid *ldap_domain_sid = NULL;
	struct dom_sid *fallback_group_sid = NULL;
	char *fallback_group_gid_str = NULL;

	LDAPMessage *result = NULL;
	LDAPMessage *entry = NULL;
	enum idmap_error_code err;
	uint32_t enctypes = 0;

	status = make_pdb_method(pdb_method);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	(*pdb_method)->name = "ipasam";

	if ( !(ipasam_state = talloc_zero(*pdb_method, struct ipasam_private)) ) {
		DEBUG(0, ("pdb_init_ipasam: talloc() failed for ipasam private_data!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	uri = talloc_strdup(ipasam_state, location );
	if (uri == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	trim_string( uri, "\"", "\"" );

	status = ipasam_generate_principals(ipasam_state);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to generate kerberos principal for LDAP authentication.\n"));
		return status;
	} else {
		/* We authenticate via GSSAPI and thus will use kerberos principal to bind our access */
		status = smbldap_init(*pdb_method, pdb_get_tevent_context(),
				      uri, false, NULL, NULL,
				      &ipasam_state->ldap_state);
		if (NT_STATUS_IS_OK(status)) {
#ifdef HAVE_SMBLDAP_SET_BIND_CALLBACK
			smbldap_set_bind_callback(ipasam_state->ldap_state, bind_callback, ipasam_state);
#else
			ipasam_state->ldap_state->bind_callback = bind_callback;
			ipasam_state->ldap_state->bind_callback_data = ipasam_state;
#endif
		}
	}

	talloc_free(uri);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	(*pdb_method)->private_data = ipasam_state;
	(*pdb_method)->free_private_data = ipasam_free_private_data;

	status = ipasam_get_base_dn(ipasam_state->ldap_state,
				    ipasam_state,
				    &ipasam_state->base_dn);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to get base DN.\n"));
		return status;
	}

	if (!(smbldap_has_extension(priv2ld(ipasam_state), IPA_KEYTAB_SET_OID) ||
	      smbldap_has_extension(priv2ld(ipasam_state), IPA_KEYTAB_SET_OID_OLD))) {
		DEBUG(0, ("Server is not an IPA server.\n"));
		return NT_STATUS_INVALID_PARAMETER;
	}

	ipasam_state->fips_enabled = ipapwd_fips_enabled();
	ipasam_state->trust_dn = talloc_asprintf(ipasam_state,
						 "cn=ad,cn=trusts,%s",
						 ipasam_state->base_dn);
	if (ipasam_state->trust_dn == NULL) {
		DEBUG(0, ("Failed to create trsut DN.\n"));
		return NT_STATUS_NO_MEMORY;
	}

	status = ipasam_get_domain_name(ipasam_state, ipasam_state,
					(char**) &ipasam_state->domain_name);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to get domain name.\n"));
		return status;
	}

	status = ipasam_get_realm(ipasam_state,
				  &ipasam_state->realm);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("Failed to get realm.\n"));
		return status;
	}

	status = ipasam_search_domain_info(ipasam_state->ldap_state, &result);

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0, ("pdb_init_ldapsam: WARNING: Could not get domain "
			  "info, nor add one to the domain. "
			  "We cannot work reliably without it.\n"));
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	entry = ldap_first_entry(priv2ld(ipasam_state), result);
	if (entry == NULL) {
		DEBUG(0, ("pdb_init_ipasam: Could not get domain info "
			  "entry\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	dn = get_dn(ipasam_state, priv2ld(ipasam_state), entry);
	if (dn == NULL) {
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ipasam_state->domain_dn = smb_xstrdup(dn);
	talloc_free(dn);

	ipasam_state->flat_name = get_single_attribute(ipasam_state,
						       priv2ld(ipasam_state),
						       entry,
						       LDAP_ATTRIBUTE_FLAT_NAME);
	if (ipasam_state->flat_name == NULL) {
		DEBUG(0, ("Missing mandatory attribute %s.\n",
			  LDAP_ATTRIBUTE_FLAT_NAME));
		ldap_msgfree(result);
		return NT_STATUS_INVALID_PARAMETER;
	}

	err = sss_idmap_init(idmap_talloc, ipasam_state,
			     idmap_talloc_free,
			     &ipasam_state->idmap_ctx);
	if (err != IDMAP_SUCCESS) {
		DEBUG(1, ("Failed to setup idmap context.\n"));
		ldap_msgfree(result);
		return NT_STATUS_UNSUCCESSFUL;
	}

	fallback_group_sid = get_fallback_group_sid(ipasam_state,
					ipasam_state->ldap_state,
					ipasam_state->idmap_ctx,
					result,
					&fallback_group_gid_str);
	if (fallback_group_sid == NULL) {
		DEBUG(0, ("Cannot find SID of fallback group.\n"));
		ldap_msgfree(result);
		return NT_STATUS_INVALID_PARAMETER;
	}
	sid_copy(&ipasam_state->fallback_primary_group, fallback_group_sid);
	talloc_free(fallback_group_sid);

	if (fallback_group_gid_str == NULL) {
		DEBUG(0, ("Cannot find gidNumber of fallback group.\n"));
		ldap_msgfree(result);
		return NT_STATUS_INVALID_PARAMETER;
	}
	ipasam_state->fallback_primary_group_gid_str = fallback_group_gid_str;

	domain_sid_string = get_single_attribute(ipasam_state,
						 priv2ld(ipasam_state),
						 entry,
						 LDAP_ATTRIBUTE_SID);

	if (domain_sid_string) {
		err = sss_idmap_sid_to_smb_sid(ipasam_state->idmap_ctx,
					       domain_sid_string,
					       &ldap_domain_sid);
		if (err != IDMAP_SUCCESS) {
			DEBUG(1, ("pdb_init_ldapsam: SID [%s] could not be "
				  "read as a valid SID\n", domain_sid_string));
			ldap_msgfree(result);
			TALLOC_FREE(domain_sid_string);
			return NT_STATUS_INVALID_PARAMETER;
		}
		sid_copy(&ipasam_state->domain_sid, ldap_domain_sid);
		talloc_free(ldap_domain_sid);
		talloc_free(domain_sid_string);

		status = save_sid_to_secret(ipasam_state);
		if (!NT_STATUS_IS_OK(status)) {
			ldap_msgfree(result);
			return status;
		}
	}

	ldap_msgfree(result);

	status = ipasam_get_enctypes(ipasam_state,
				     &enctypes);

	if (!NT_STATUS_IS_OK(status)) {
		enctypes = KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96 |
			   KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96;
		if (!ipasam_state->fips_enabled) {
			enctypes |= KERB_ENCTYPE_RC4_HMAC_MD5;
		}
	}

	ipasam_state->supported_enctypes = enctypes;

	(*pdb_method)->getsampwnam = ipasam_getsampwnam;
	(*pdb_method)->search_users = ipasam_search_users;
	(*pdb_method)->search_groups = ipasam_search_groups;
	(*pdb_method)->search_aliases = ipasam_search_aliases;
	(*pdb_method)->lookup_rids = ldapsam_lookup_rids;
	(*pdb_method)->sid_to_id = ldapsam_sid_to_id;
#if PASSDB_INTERFACE_VERSION >= 24
/* Since version 24, uid_to_sid() and gid_to_sid() were removed in favor of id_to_sid() */
	(*pdb_method)->id_to_sid = ipasam_id_to_sid;
#else
	(*pdb_method)->uid_to_sid = ipasam_uid_to_sid;
	(*pdb_method)->gid_to_sid = ipasam_gid_to_sid;
#endif

	(*pdb_method)->capabilities = pdb_ipasam_capabilities;
	(*pdb_method)->get_domain_info = pdb_ipasam_get_domain_info;

	(*pdb_method)->get_trusteddom_pw = ipasam_get_trusteddom_pw;
	(*pdb_method)->set_trusteddom_pw = ipasam_set_trusteddom_pw;
	(*pdb_method)->del_trusteddom_pw = ipasam_del_trusteddom_pw;
	(*pdb_method)->enum_trusteddoms = ipasam_enum_trusteddoms;

	(*pdb_method)->get_trusted_domain = ipasam_get_trusted_domain;
	(*pdb_method)->get_trusted_domain_by_sid = ipasam_get_trusted_domain_by_sid;
	(*pdb_method)->set_trusted_domain = ipasam_set_trusted_domain;
	(*pdb_method)->del_trusted_domain = ipasam_del_trusted_domain;
	(*pdb_method)->enum_trusted_domains = ipasam_enum_trusted_domains;
#ifdef HAVE_PDB_ENUM_UPN_SUFFIXES
	(*pdb_method)->enum_upn_suffixes = ipasam_enum_upn_suffixes;
	DEBUG(1, ("pdb_init_ipasam: support for pdb_enum_upn_suffixes "
		  "enabled for domain %s\n", ipasam_state->domain_name));
#endif

	return NT_STATUS_OK;
}

NTSTATUS samba_module_init(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "ipasam",
				   pdb_init_ipasam);
}

NTSTATUS samba_init_module(void)
{
	return smb_register_passdb(PASSDB_INTERFACE_VERSION, "ipasam",
				   pdb_init_ipasam);
}
