/*
    Authors:
        Alexander Bokovoy <abokovoy@redhat.com>

    Copyright (C) 2026  Red Hat

    Unit tests for ipa_kdb_s4u_x509.c

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* Pull in the implementation under test, including all static functions. */
#include "../ipa_kdb_s4u_x509.c"

/* ------------------------------------------------------------------ *
 * Stubs for external IPA-KDB functions used by ipa_kdb_s4u_x509.c   *
 * ------------------------------------------------------------------ */

/* Fake context used across tests */
static struct ipadb_context g_fake_ctx = {
    .magic = IPA_CONTEXT_MAGIC,
};

int krb5_klog_syslog(int l, const char *format, ...)
{
    va_list ap;
    char *s = NULL;
    int ret;

    va_start(ap, format);
    ret = vasprintf(&s, format, ap);
    va_end(ap);
    if (ret >= 0) {
        fprintf(stderr, "%s\n", s);
        free(s);
    }
    return 0;
}

struct ipadb_context *ipadb_get_context(krb5_context kcontext)
{
    return (struct ipadb_context *)mock();
}

krb5_error_code ipadb_get_principal(krb5_context kcontext,
                                    krb5_const_principal search_for,
                                    unsigned int flags,
                                    krb5_db_entry **entry)
{
    krb5_db_entry *e = (krb5_db_entry *)mock();
    if (!e) {
        *entry = NULL;
        return KRB5_KDB_NOENTRY;
    }
    *entry = e;
    return 0;
}

void ipadb_free_principal(krb5_context kcontext, krb5_db_entry *entry)
{
    /* In tests the entries are stack/heap allocated and freed by the test. */
}

krb5_error_code ipadb_simple_search(struct ipadb_context *ipactx,
                                    char *basedn, int scope,
                                    char *filter, char **attrs,
                                    LDAPMessage **res)
{
    *res = (LDAPMessage *)mock();
    return (krb5_error_code)(uintptr_t)mock();
}

/*
 * krb5_dbe_decrypt_key_data: return a fresh copy of the keyblock supplied
 * via will_return().  The copy is malloc'd so krb5_free_keyblock_contents()
 * can free it normally.
 */
krb5_error_code
krb5_dbe_decrypt_key_data(krb5_context context,
                           const krb5_keyblock *mkey,
                           const krb5_key_data *key_data,
                           krb5_keyblock *dbkey,
                           krb5_keysalt *keysalt)
{
    const krb5_keyblock *src = (const krb5_keyblock *)mock();
    if (!src)
        return KRB5KDC_ERR_PREAUTH_FAILED;
    dbkey->magic    = KV5M_KEYBLOCK;
    dbkey->enctype  = src->enctype;
    dbkey->length   = src->length;
    dbkey->contents = malloc(src->length);
    if (!dbkey->contents)
        return ENOMEM;
    memcpy(dbkey->contents, src->contents, src->length);
    return 0;
}

/* LDAP stubs used by verify_host_key_registered() */

LDAPMessage *ldap_first_entry(LDAP *ld, LDAPMessage *chain)
{
    return (LDAPMessage *)mock();
}

struct berval **ldap_get_values_len(LDAP *ld, LDAPMessage *entry,
                                    const char *attr)
{
    return (struct berval **)mock();
}

/* Test berval arrays are stack-allocated in the test — nothing to free. */
void ldap_value_free_len(struct berval **vals) {}

int ldap_msgfree(LDAPMessage *msg) { return 0; }

/* ------------------------------------------------------------------ *
 * DER building helpers (test-only)                                    *
 *                                                                     *
 * These construct raw DER bytes to feed into                          *
 * d2i_KERBEROS_SERVICE_ISSUER_BINDING and d2i_SSH_AUTHN_CONTEXT,     *
 * allowing us to test parse error paths (truncated, bad version,      *
 * etc.) without calling i2d_* in reverse.                             *
 * ------------------------------------------------------------------ */

static int tder_write_length(unsigned char *out, size_t len)
{
    if (len < 128) {
        out[0] = (unsigned char)len;
        return 1;
    } else if (len < 256) {
        out[0] = 0x81;
        out[1] = (unsigned char)len;
        return 2;
    } else {
        out[0] = 0x82;
        out[1] = (unsigned char)(len >> 8);
        out[2] = (unsigned char)(len & 0xFF);
        return 3;
    }
}

static size_t tder_wrap(unsigned char *out, int tag,
                        const unsigned char *content, size_t clen)
{
    out[0] = (unsigned char)tag;
    int ll = tder_write_length(out + 1, clen);
    memcpy(out + 1 + ll, content, clen);
    return (size_t)(1 + ll + clen);
}

static size_t tder_sequence(unsigned char *out,
                            const unsigned char *content, size_t clen)
{
    return tder_wrap(out, 0x30, content, clen);
}

static size_t tder_integer(unsigned char *out, long val)
{
    unsigned char tmp[sizeof(long) + 1];
    size_t n = 0;

    if (val == 0) {
        tmp[0] = 0;
        n = 1;
    } else {
        long v = val;
        while (v > 0) {
            tmp[n++] = (unsigned char)(v & 0xFF);
            v >>= 8;
        }
        /* reverse bytes to big-endian */
        for (size_t i = 0; i < n / 2; i++) {
            unsigned char t = tmp[i];
            tmp[i] = tmp[n - 1 - i];
            tmp[n - 1 - i] = t;
        }
        /* prepend 0x00 if the high bit is set (avoid sign misinterpretation) */
        if (tmp[0] & 0x80) {
            memmove(tmp + 1, tmp, n);
            tmp[0] = 0;
            n++;
        }
    }
    return tder_wrap(out, 0x02, tmp, n);
}

static size_t tder_utf8string(unsigned char *out, const char *str)
{
    return tder_wrap(out, 0x0C,
                     (const unsigned char *)str, strlen(str));
}

static size_t tder_octet_string(unsigned char *out,
                                const unsigned char *data, size_t dlen)
{
    return tder_wrap(out, 0x04, data, dlen);
}

/* [N] EXPLICIT CONSTRUCTED */
static size_t tder_explicit(unsigned char *out, int tag_num,
                            const unsigned char *content, size_t clen)
{
    return tder_wrap(out, 0xA0 | tag_num, content, clen);
}

/*
 * Build the DER value bytes for id-ce-kerberosServiceIssuerBinding.
 * Returns the number of bytes written into out[].
 * out must be at least 4096 bytes.
 *
 * sigAlg is always id-Ed25519 (OID 1.3.101.112).
 */
static size_t build_issuer_binding_der(unsigned char *out,
                                       long version,
                                       const char *service_type,
                                       const char *principal,
                                       long enctype, long kvno,
                                       const unsigned char *spki_der,
                                       size_t spki_len,
                                       const unsigned char *binding,
                                       size_t binding_len)
{
    unsigned char body[4096];
    size_t blen = 0;

    /* version INTEGER */
    blen += tder_integer(body + blen, version);
    /* serviceType UTF8String */
    blen += tder_utf8string(body + blen, service_type);
    /* principal UTF8String */
    blen += tder_utf8string(body + blen, principal);
    /* enctype INTEGER */
    blen += tder_integer(body + blen, enctype);
    /* kvno INTEGER */
    blen += tder_integer(body + blen, kvno);
    /* sigAlg: SEQUENCE { OID id-Ed25519 }; OID bytes: 06 03 2B 65 70 */
    {
        unsigned char oid_tlv[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
        blen += tder_sequence(body + blen, oid_tlv, sizeof(oid_tlv));
    }
    /* serviceKey SubjectPublicKeyInfo (raw SPKI DER) */
    memcpy(body + blen, spki_der, spki_len);
    blen += spki_len;
    /* binding OCTET STRING */
    blen += tder_octet_string(body + blen, binding, binding_len);

    return tder_sequence(out, body, blen);
}

/*
 * Build the DER value bytes for id-ce-sshAuthnInfo.
 * key_fingerprint and client_address may be NULL (optional fields).
 */
static size_t build_authn_info_der(unsigned char *out,
                                   long version,
                                   const char *auth_method,
                                   const unsigned char *session_id,
                                   size_t sid_len,
                                   const char *key_fingerprint,
                                   const char *client_address)
{
    unsigned char body[1024];
    size_t blen = 0;

    blen += tder_integer(body + blen, version);
    blen += tder_utf8string(body + blen, auth_method);
    blen += tder_octet_string(body + blen, session_id, sid_len);

    if (key_fingerprint) {
        unsigned char inner[256];
        size_t ilen = tder_utf8string(inner, key_fingerprint);
        blen += tder_explicit(body + blen, 0, inner, ilen);
    }
    if (client_address) {
        unsigned char inner[256];
        size_t ilen = tder_utf8string(inner, client_address);
        blen += tder_explicit(body + blen, 1, inner, ilen);
    }

    return tder_sequence(out, body, blen);
}

/*
 * Encode an EVP_PKEY as an OpenSSH authorized_keys line ("type base64 comment").
 * Returns a heap-allocated string.  Only supports Ed25519.
 */
static char *pkey_to_ssh_pubkey_line(EVP_PKEY *pkey)
{
    unsigned char raw[32];
    size_t rawlen = sizeof(raw);

    if (EVP_PKEY_get_raw_public_key(pkey, raw, &rawlen) <= 0 ||
        rawlen != 32)
        return NULL;

    /* SSH wire format: uint32(len) || "ssh-ed25519" || uint32(32) || raw */
    unsigned char blob[4 + 11 + 4 + 32];
    unsigned char *p = blob;
    uint32_t slen;

    slen = htonl(11);
    memcpy(p, &slen, 4); p += 4;
    memcpy(p, "ssh-ed25519", 11); p += 11;
    slen = htonl(32);
    memcpy(p, &slen, 4); p += 4;
    memcpy(p, raw, 32); p += 32;

    size_t bloblen = (size_t)(p - blob);
    size_t b64max = (bloblen / 3 + 1) * 4 + 4;
    char *b64 = malloc(b64max);
    if (!b64)
        return NULL;

    int n = EVP_EncodeBlock((unsigned char *)b64, blob, (int)bloblen);
    b64[n] = '\0';

    char *line = NULL;
    if (asprintf(&line, "ssh-ed25519 %s test-key", b64) < 0)
        line = NULL;
    free(b64);
    return line;
}

/* ------------------------------------------------------------------ *
 * Tests for d2i_KERBEROS_SERVICE_ISSUER_BINDING()                     *
 * ------------------------------------------------------------------ */

static void test_parse_issuer_binding_valid(void **state)
{
    /* Generate an Ed25519 key so we have a real SPKI */
    unsigned char seed[32];
    memset(seed, 0xAB, sizeof(seed));
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   seed, 32);
    assert_non_null(pkey);

    unsigned char *spki_der = NULL;
    int spki_len = i2d_PUBKEY(pkey, &spki_der);
    assert_true(spki_len > 0);
    EVP_PKEY_free(pkey);

    unsigned char binding[32];
    memset(binding, 0, sizeof(binding));

    unsigned char ext_der[4096];
    size_t ext_len = build_issuer_binding_der(ext_der,
                         0,     /* version */
                         "ssh", /* serviceType */
                         "host/testhost.example.com@EXAMPLE.COM",
                         18,    /* enctype: AES256-CTS-HMAC-SHA1-96 */
                         1,     /* kvno */
                         spki_der, (size_t)spki_len,
                         binding, sizeof(binding));
    OPENSSL_free(spki_der);
    assert_true(ext_len > 0);

    const unsigned char *p = ext_der;
    KERBEROS_SERVICE_ISSUER_BINDING *ib =
        d2i_KERBEROS_SERVICE_ISSUER_BINDING(NULL, &p, (long)ext_len);
    assert_non_null(ib);

    assert_int_equal(ASN1_INTEGER_get(ib->version), 0);
    assert_string_equal(
        (const char *)ASN1_STRING_get0_data(ib->service_type), "ssh");
    assert_string_equal(
        (const char *)ASN1_STRING_get0_data(ib->principal),
        "host/testhost.example.com@EXAMPLE.COM");
    assert_int_equal(ASN1_INTEGER_get(ib->enctype), 18);
    assert_int_equal(ASN1_INTEGER_get(ib->kvno), 1);
    assert_int_equal(OBJ_obj2nid(ib->sig_alg->algorithm), NID_ED25519);
    assert_non_null(X509_PUBKEY_get0(ib->service_key));
    assert_non_null(ib->binding);
    assert_int_equal(ib->binding->length, 32);
    assert_memory_equal(ib->binding->data, binding, 32);

    KERBEROS_SERVICE_ISSUER_BINDING_free(ib);
}

static void test_parse_issuer_binding_bad_version(void **state)
{
    unsigned char seed[32];
    memset(seed, 0xCD, sizeof(seed));
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   seed, 32);
    assert_non_null(pkey);
    unsigned char *spki_der = NULL;
    int spki_len = i2d_PUBKEY(pkey, &spki_der);
    assert_true(spki_len > 0);
    EVP_PKEY_free(pkey);

    unsigned char binding[32] = { 0 };
    unsigned char ext_der[4096];
    size_t ext_len = build_issuer_binding_der(ext_der,
                         99,    /* bad version */
                         "ssh", /* serviceType */
                         "host/h@REALM",
                         18, 1,
                         spki_der, (size_t)spki_len,
                         binding, sizeof(binding));
    OPENSSL_free(spki_der);

    /*
     * d2i_KERBEROS_SERVICE_ISSUER_BINDING parses successfully — version is
     * just an INTEGER field.  The caller (ipadb_get_s4u_x509_principal) is
     * responsible for rejecting non-zero versions.
     */
    const unsigned char *p = ext_der;
    KERBEROS_SERVICE_ISSUER_BINDING *ib =
        d2i_KERBEROS_SERVICE_ISSUER_BINDING(NULL, &p, (long)ext_len);
    assert_non_null(ib);
    assert_int_not_equal(ASN1_INTEGER_get(ib->version), 0);
    KERBEROS_SERVICE_ISSUER_BINDING_free(ib);
}

static void test_parse_issuer_binding_truncated(void **state)
{
    /* Feed a SEQUENCE tag with a declared length longer than the buffer. */
    unsigned char ext_der[] = { 0x30, 0x40, 0x02, 0x01, 0x00 };
    const unsigned char *p = ext_der;
    KERBEROS_SERVICE_ISSUER_BINDING *ib =
        d2i_KERBEROS_SERVICE_ISSUER_BINDING(NULL, &p, (long)sizeof(ext_der));
    assert_null(ib);
}

/* ------------------------------------------------------------------ *
 * Tests for d2i_SSH_AUTHN_CONTEXT()                                   *
 * ------------------------------------------------------------------ */

static void test_parse_authn_info_full(void **state)
{
    unsigned char session_id[16];
    memset(session_id, 0x42, sizeof(session_id));

    unsigned char ext_der[1024];
    size_t ext_len = build_authn_info_der(ext_der,
                         0, /* version */
                         "publickey",
                         session_id, sizeof(session_id),
                         "SHA256:AAABBBCCC=",
                         "192.168.1.100:22");
    assert_true(ext_len > 0);

    const unsigned char *p = ext_der;
    SSH_AUTHN_CONTEXT *ai = d2i_SSH_AUTHN_CONTEXT(NULL, &p, (long)ext_len);
    assert_non_null(ai);

    assert_int_equal(ASN1_INTEGER_get(ai->version), 0);
    assert_string_equal(
        (const char *)ASN1_STRING_get0_data(ai->auth_method), "publickey");
    assert_non_null(ai->key_fingerprint);
    assert_string_equal(
        (const char *)ASN1_STRING_get0_data(ai->key_fingerprint),
        "SHA256:AAABBBCCC=");
    assert_non_null(ai->client_address);
    assert_string_equal(
        (const char *)ASN1_STRING_get0_data(ai->client_address),
        "192.168.1.100:22");

    SSH_AUTHN_CONTEXT_free(ai);
}

static void test_parse_authn_info_no_optionals(void **state)
{
    unsigned char session_id[16];
    memset(session_id, 0x00, sizeof(session_id));

    unsigned char ext_der[1024];
    size_t ext_len = build_authn_info_der(ext_der,
                         0, /* version */
                         "password",
                         session_id, sizeof(session_id),
                         NULL,  /* no keyFingerprint */
                         NULL); /* no clientAddress */
    assert_true(ext_len > 0);

    const unsigned char *p = ext_der;
    SSH_AUTHN_CONTEXT *ai = d2i_SSH_AUTHN_CONTEXT(NULL, &p, (long)ext_len);
    assert_non_null(ai);
    assert_string_equal(
        (const char *)ASN1_STRING_get0_data(ai->auth_method), "password");
    assert_null(ai->key_fingerprint);
    assert_null(ai->client_address);

    SSH_AUTHN_CONTEXT_free(ai);
}

static void test_parse_authn_info_bad_version(void **state)
{
    unsigned char session_id[4] = { 0 };
    unsigned char ext_der[256];
    size_t ext_len = build_authn_info_der(ext_der,
                         5, /* bad version */
                         "publickey",
                         session_id, sizeof(session_id),
                         NULL, NULL);

    /*
     * Parse succeeds; version rejection is the caller's responsibility.
     */
    const unsigned char *p = ext_der;
    SSH_AUTHN_CONTEXT *ai = d2i_SSH_AUTHN_CONTEXT(NULL, &p, (long)ext_len);
    assert_non_null(ai);
    assert_int_not_equal(ASN1_INTEGER_get(ai->version), 0);
    SSH_AUTHN_CONTEXT_free(ai);
}

/* ------------------------------------------------------------------ *
 * Tests for parse_openssh_pubkey()                                    *
 * ------------------------------------------------------------------ */

static void test_parse_openssh_pubkey_ed25519(void **state)
{
    /* Generate a known Ed25519 key, encode as SSH pubkey line, round-trip. */
    unsigned char seed[32];
    memset(seed, 0x77, sizeof(seed));

    EVP_PKEY *orig = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   seed, 32);
    assert_non_null(orig);

    char *line = pkey_to_ssh_pubkey_line(orig);
    assert_non_null(line);

    EVP_PKEY *parsed = parse_openssh_pubkey((const unsigned char *)line,
                                              strlen(line));
    free(line);
    assert_non_null(parsed);

    assert_int_equal(EVP_PKEY_eq(orig, parsed), 1);

    EVP_PKEY_free(orig);
    EVP_PKEY_free(parsed);
}

static void test_parse_openssh_pubkey_bad_type(void **state)
{
    const char *bad = "ssh-unknown AAAAB3NzaC1yc2E= comment";
    EVP_PKEY *parsed = parse_openssh_pubkey((const unsigned char *)bad,
                                             strlen(bad));
    assert_null(parsed);
}

static void test_parse_openssh_pubkey_no_space(void **state)
{
    EVP_PKEY *parsed = parse_openssh_pubkey(
        (const unsigned char *)"noseparator", strlen("noseparator"));
    assert_null(parsed);
}

/* ------------------------------------------------------------------ *
 * Tests for hkdf_sha256()                                             *
 * ------------------------------------------------------------------ */

static void test_hkdf_sha256_deterministic(void **state)
{
    unsigned char ikm[32];
    unsigned char out1[32], out2[32];
    const char *salt = "test-salt";
    const unsigned char info[] = "test-info";

    memset(ikm, 0x5A, sizeof(ikm));

    krb5_error_code ret;
    ret = hkdf_sha256(ikm, sizeof(ikm),
                      salt, strlen(salt),
                      info, sizeof(info) - 1,
                      out1, sizeof(out1));
    assert_int_equal(ret, 0);

    ret = hkdf_sha256(ikm, sizeof(ikm),
                      salt, strlen(salt),
                      info, sizeof(info) - 1,
                      out2, sizeof(out2));
    assert_int_equal(ret, 0);

    assert_memory_equal(out1, out2, sizeof(out1));
    assert_memory_not_equal(out1, ikm, sizeof(out1));
}

static void test_hkdf_sha256_different_info(void **state)
{
    unsigned char ikm[32];
    unsigned char out1[32], out2[32];
    const char *salt = "test-salt";

    memset(ikm, 0x3C, sizeof(ikm));

    krb5_error_code ret;
    ret = hkdf_sha256(ikm, sizeof(ikm), salt, strlen(salt),
                      (const unsigned char *)"infoA", 5, out1, sizeof(out1));
    assert_int_equal(ret, 0);

    ret = hkdf_sha256(ikm, sizeof(ikm), salt, strlen(salt),
                      (const unsigned char *)"infoB", 5, out2, sizeof(out2));
    assert_int_equal(ret, 0);

    assert_memory_not_equal(out1, out2, sizeof(out1));
}

/* ------------------------------------------------------------------ *
 * Tests for derive_attestation_key()                                  *
 * ------------------------------------------------------------------ */

static void test_derive_attestation_key_ed25519(void **state)
{
    unsigned char ikm[32];
    memset(ikm, 0xDE, sizeof(ikm));

    EVP_PKEY *pkey = NULL;
    krb5_error_code ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        1,  /* kvno */
        0,  /* non-FIPS: Ed25519 */
        &pkey);

    assert_int_equal(ret, 0);
    assert_non_null(pkey);
    assert_int_equal(EVP_PKEY_base_id(pkey), EVP_PKEY_ED25519);

    /* Same inputs produce the same key (deterministic) */
    EVP_PKEY *pkey2 = NULL;
    ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        1, 0, &pkey2);
    assert_int_equal(ret, 0);
    assert_non_null(pkey2);
    assert_int_equal(EVP_PKEY_eq(pkey, pkey2), 1);

    /* Different kvno → different key */
    EVP_PKEY *pkey3 = NULL;
    ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        2, 0, &pkey3);
    assert_int_equal(ret, 0);
    assert_non_null(pkey3);
    assert_int_not_equal(EVP_PKEY_eq(pkey, pkey3), 1);

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(pkey3);
}

static void test_derive_attestation_key_p256(void **state)
{
    unsigned char ikm[32];
    memset(ikm, 0xDE, sizeof(ikm));

    EVP_PKEY *pkey = NULL;
    krb5_error_code ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        1,  /* kvno */
        1,  /* FIPS: P-256 */
        &pkey);

    assert_int_equal(ret, 0);
    assert_non_null(pkey);
    assert_int_equal(EVP_PKEY_base_id(pkey), EVP_PKEY_EC);

    /* Same inputs produce the same key (deterministic) */
    EVP_PKEY *pkey2 = NULL;
    ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        1, 1, &pkey2);
    assert_int_equal(ret, 0);
    assert_non_null(pkey2);
    assert_int_equal(EVP_PKEY_eq(pkey, pkey2), 1);

    /* Different kvno → different key */
    EVP_PKEY *pkey3 = NULL;
    ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        2, 1, &pkey3);
    assert_int_equal(ret, 0);
    assert_non_null(pkey3);
    assert_int_not_equal(EVP_PKEY_eq(pkey, pkey3), 1);

    /* P-256 and Ed25519 keys derived from the same IKM must differ */
    EVP_PKEY *pkey_ed = NULL;
    ret = derive_attestation_key(
        ikm, sizeof(ikm),
        "ssh-attestation-v1",
        "testhost.example.com", "EXAMPLE.COM",
        1, 0, &pkey_ed);
    assert_int_equal(ret, 0);
    assert_non_null(pkey_ed);
    assert_int_not_equal(EVP_PKEY_eq(pkey, pkey_ed), 1);

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(pkey3);
    EVP_PKEY_free(pkey_ed);
}

/* Smoke-test: create a fresh P-256 key (as the SSH server would), sign a
 * minimal X.509 certificate with it, then verify the signature. */
static void test_p256_sign_verify(void **state)
{
    (void)state;

    /* Create a fresh ECDSA P-256 signing key (simulating the SSH server key) */
    EVP_PKEY *sign_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    assert_non_null(sign_key);

    /* Build a minimal X.509 certificate */
    X509 *cert = X509_new();
    assert_non_null(cert);
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
    X509_NAME_add_entry_by_NID(X509_get_subject_name(cert),
                                NID_commonName, MBSTRING_UTF8,
                                (unsigned char *)"test", 4, -1, 0);
    X509_NAME_add_entry_by_NID(X509_get_issuer_name(cert),
                                NID_commonName, MBSTRING_UTF8,
                                (unsigned char *)"test", 4, -1, 0);

    /* Set an ephemeral P-256 subject public key (distinct from signing key) */
    EVP_PKEY *subject_key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    assert_non_null(subject_key);
    assert_int_equal(X509_set_pubkey(cert, subject_key), 1);
    EVP_PKEY_free(subject_key);

    /* Sign with the SSH P-256 key */
    assert_true(X509_sign(cert, sign_key, EVP_sha256()) > 0);

    /* Verify with the same P-256 key */
    assert_int_equal(X509_verify(cert, sign_key), 1);

    X509_free(cert);
    EVP_PKEY_free(sign_key);
}

/* ------------------------------------------------------------------ *
 * Tests for verify_binding_signature()                                *
 *                                                                     *
 * Helper: sign_binding() mirrors the digest construction inside       *
 * verify_binding_signature() and returns the signature as an         *
 * ASN1_OCTET_STRING suitable for passing to the verifier.            *
 * ------------------------------------------------------------------ */

static ASN1_OCTET_STRING *sign_binding(EVP_PKEY *privkey,
                                       X509_PUBKEY *spki,
                                       const char *binding_label,
                                       const char *principal,
                                       uint32_t kvno)
{
    unsigned char  digest[SHA256_DIGEST_LENGTH];
    unsigned int   digest_len = SHA256_DIGEST_LENGTH;
    uint32_t       kvno_be = htonl(kvno);
    unsigned char *spki_der = NULL;
    int            spki_len;
    ASN1_OCTET_STRING *result = NULL;

    /* Re-encode SPKI the same way verify_binding_signature() does */
    spki_len = i2d_X509_PUBKEY(spki, &spki_der);
    if (spki_len <= 0)
        return NULL;

    /* Build the binding digest */
    EVP_MD_CTX *sha_ctx = EVP_MD_CTX_new();
    if (!sha_ctx)
        goto out;

    if (EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(sha_ctx, spki_der, (size_t)spki_len) <= 0 ||
        EVP_DigestUpdate(sha_ctx, binding_label,
                         strlen(binding_label)) <= 0 ||
        EVP_DigestUpdate(sha_ctx, principal, strlen(principal)) <= 0 ||
        EVP_DigestUpdate(sha_ctx, &kvno_be, 4) <= 0 ||
        EVP_DigestFinal_ex(sha_ctx, digest, &digest_len) <= 0) {
        EVP_MD_CTX_free(sha_ctx);
        goto out;
    }
    EVP_MD_CTX_free(sha_ctx);

    /* Sign the digest */
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        goto out;

    int key_id = EVP_PKEY_base_id(privkey);
    const EVP_MD *md = (key_id == EVP_PKEY_ED25519) ? NULL : EVP_sha256();

    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, privkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        goto out;
    }

    size_t sig_len = (size_t)EVP_PKEY_size(privkey);
    unsigned char *sig = malloc(sig_len);
    if (sig && EVP_DigestSign(mdctx, sig, &sig_len,
                               digest, SHA256_DIGEST_LENGTH) > 0) {
        result = ASN1_OCTET_STRING_new();
        if (result)
            ASN1_OCTET_STRING_set(result, sig, (int)sig_len);
    }
    free(sig);
    EVP_MD_CTX_free(mdctx);

out:
    OPENSSL_free(spki_der);
    return result;
}

static void test_verify_binding_signature_valid(void **state)
{
    unsigned char ikm[32];
    memset(ikm, 0xBE, sizeof(ikm));

    const char *hostname = "myhost.example.com";
    const char *realm    = "EXAMPLE.COM";
    const char *princ    = "host/myhost.example.com@EXAMPLE.COM";
    const char *label    = "ssh-attestation-binding-v1";
    uint32_t kvno = 2;

    EVP_PKEY *pkey = NULL;
    krb5_error_code ret = derive_attestation_key(
        ikm, sizeof(ikm), "ssh-attestation-v1", hostname, realm, kvno, 0, &pkey);
    assert_int_equal(ret, 0);

    /* Wrap the public key as X509_PUBKEY (what the binding extension carries) */
    X509_PUBKEY *xpk = NULL;
    assert_int_equal(X509_PUBKEY_set(&xpk, pkey), 1);

    ASN1_OCTET_STRING *binding = sign_binding(pkey, xpk, label, princ, kvno);
    assert_non_null(binding);

    ret = verify_binding_signature(pkey, xpk, princ, kvno, label, binding);
    assert_int_equal(ret, 0);

    ASN1_OCTET_STRING_free(binding);
    X509_PUBKEY_free(xpk);
    EVP_PKEY_free(pkey);
}

static void test_verify_binding_signature_bad_sig(void **state)
{
    unsigned char ikm[32];
    memset(ikm, 0xCA, sizeof(ikm));

    const char *label = "ssh-attestation-binding-v1";

    EVP_PKEY *pkey = NULL;
    krb5_error_code ret = derive_attestation_key(
        ikm, sizeof(ikm), "ssh-attestation-v1",
        "host.example.com", "EXAMPLE.COM", 1, 0, &pkey);
    assert_int_equal(ret, 0);

    X509_PUBKEY *xpk = NULL;
    assert_int_equal(X509_PUBKEY_set(&xpk, pkey), 1);

    ASN1_OCTET_STRING *binding = sign_binding(
        pkey, xpk, label, "host/host.example.com@EXAMPLE.COM", 1);
    assert_non_null(binding);

    /* Corrupt one byte of the signature */
    binding->data[0] ^= 0xFF;

    ret = verify_binding_signature(pkey, xpk,
                                   "host/host.example.com@EXAMPLE.COM",
                                   1, label, binding);
    assert_int_not_equal(ret, 0);

    ASN1_OCTET_STRING_free(binding);
    X509_PUBKEY_free(xpk);
    EVP_PKEY_free(pkey);
}

static void test_verify_binding_signature_wrong_kvno(void **state)
{
    unsigned char ikm[32];
    memset(ikm, 0xEF, sizeof(ikm));

    const char *label = "ssh-attestation-binding-v1";

    EVP_PKEY *pkey = NULL;
    krb5_error_code ret = derive_attestation_key(
        ikm, sizeof(ikm), "ssh-attestation-v1",
        "host.example.com", "EXAMPLE.COM", 1, 0, &pkey);
    assert_int_equal(ret, 0);

    X509_PUBKEY *xpk = NULL;
    assert_int_equal(X509_PUBKEY_set(&xpk, pkey), 1);

    const char *princ = "host/host.example.com@EXAMPLE.COM";

    /* Sign with kvno=1 */
    ASN1_OCTET_STRING *binding = sign_binding(pkey, xpk, label, princ, 1);
    assert_non_null(binding);

    /* Verify with kvno=2 — digest mismatch */
    ret = verify_binding_signature(pkey, xpk, princ, 2, label, binding);
    assert_int_not_equal(ret, 0);

    ASN1_OCTET_STRING_free(binding);
    X509_PUBKEY_free(xpk);
    EVP_PKEY_free(pkey);
}

/* ------------------------------------------------------------------ *
 * Helpers for the full end-to-end pipeline test                       *
 *                                                                     *
 * These mirror the SSH client-side functions in gss-s4u-x509.c so    *
 * that we can build a valid attestation certificate entirely within   *
 * the test binary, without depending on OpenSSH library code.         *
 * ------------------------------------------------------------------ */

/*
 * Add a custom X.509 extension with a raw DER-encoded value.
 * Mirrors add_raw_extension() in gss-s4u-x509.c exactly.
 */
static int
add_raw_extension(X509 *cert, const char *oid_str, int critical,
                  const unsigned char *der, int der_len)
{
    ASN1_OBJECT       *obj = OBJ_txt2obj(oid_str, 1);
    ASN1_OCTET_STRING *val = ASN1_OCTET_STRING_new();
    X509_EXTENSION    *ext = NULL;
    int                ret = -1;

    if (!obj || !val)
        goto done;
    if (!ASN1_STRING_set(val, der, der_len))
        goto done;
    ext = X509_EXTENSION_create_by_OBJ(NULL, obj, critical, val);
    if (!ext)
        goto done;
    if (X509_add_ext(cert, ext, -1))
        ret = 0;
done:
    ASN1_OBJECT_free(obj);
    ASN1_OCTET_STRING_free(val);
    X509_EXTENSION_free(ext);
    return ret;
}

/*
 * Build a DER-encoded attestation certificate that mirrors what
 * ssh_gssapi_s4u_x509_build_cert() produces, without OpenSSH library
 * dependencies (no sshbuf, no sshkey).
 *
 * host_ed25519_seed: 32-byte private-key seed for the SSH host key.
 *
 * On success, returns a malloc'd DER buffer and sets *cert_der_len_out.
 * On failure, returns NULL.
 */
static unsigned char *
build_test_attestation_cert(const unsigned char *ikm, size_t ikm_len,
                             krb5_enctype enctype, uint32_t kvno,
                             const char *hostname, const char *realm,
                             const char *user,
                             const char *auth_method,
                             const unsigned char *session_id,
                             size_t session_id_len,
                             const char *key_fingerprint,
                             const char *client_address,
                             const unsigned char *host_ed25519_seed,
                             EVP_PKEY *user_pubkey,  /* subject key; NULL = ephemeral */
                             int fips_mode,
                             int *cert_der_len_out)
{
    EVP_PKEY                        *derived_key  = NULL;
    EVP_PKEY                        *host_privkey = NULL;
    X509_PUBKEY                     *host_spki    = NULL;
    KERBEROS_SERVICE_ISSUER_BINDING *ib           = NULL;
    SSH_AUTHN_CONTEXT               *ai           = NULL;
    ASN1_OCTET_STRING  *binding      = NULL;
    X509               *cert         = NULL;
    unsigned char      *ib_der       = NULL;
    unsigned char      *ai_der       = NULL;
    int                 ib_len       = 0;
    int                 ai_len       = 0;
    unsigned char      *cert_der     = NULL;
    char               *principal    = NULL;

    *cert_der_len_out = 0;

    if (asprintf(&principal, "host/%s@%s", hostname, realm) < 0)
        goto done;

    /* Derive the attestation signing key — same derivation as the KDC */
    if (derive_attestation_key(ikm, ikm_len, "ssh-attestation-v1",
                               hostname, realm, kvno, fips_mode,
                               &derived_key) != 0)
        goto done;

    /* Build the SSH host key SPKI from its Ed25519 private-key seed */
    host_privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                 host_ed25519_seed, 32);
    if (!host_privkey || X509_PUBKEY_set(&host_spki, host_privkey) != 1)
        goto done;

    /* ---- Build id-ce-kerberosServiceIssuerBinding ---- */
    ib = KERBEROS_SERVICE_ISSUER_BINDING_new();
    if (!ib ||
        !ASN1_INTEGER_set(ib->version, 0) ||
        !ASN1_STRING_set(ib->service_type, "ssh", 3) ||
        !ASN1_STRING_set(ib->principal, principal, (int)strlen(principal)) ||
        !ASN1_INTEGER_set(ib->enctype, (long)enctype) ||
        !ASN1_INTEGER_set(ib->kvno, (long)kvno))
        goto done;

    X509_ALGOR_set0(ib->sig_alg,
                    OBJ_nid2obj(fips_mode ? NID_ecdsa_with_SHA256
                                          : NID_ED25519),
                    V_ASN1_UNDEF, NULL);

    /* Transfer host SPKI ownership into ib (mirrors the SSH client) */
    X509_PUBKEY_free(ib->service_key);
    ib->service_key = host_spki;
    host_spki = NULL;

    /*
     * Compute the binding signature using the shared sign_binding() helper.
     * This produces the same digest as verify_binding_signature() on the KDC.
     */
    binding = sign_binding(derived_key, ib->service_key,
                           "ssh-attestation-binding-v1", principal, kvno);
    if (!binding)
        goto done;
    ASN1_OCTET_STRING_free(ib->binding);
    ib->binding = binding;
    binding = NULL;

    ib_len = i2d_KERBEROS_SERVICE_ISSUER_BINDING(ib, &ib_der);
    KERBEROS_SERVICE_ISSUER_BINDING_free(ib);
    ib = NULL;
    if (!ib_der || ib_len <= 0)
        goto done;

    /* ---- Build id-ce-sshAuthnContext ---- */
    ai = SSH_AUTHN_CONTEXT_new();
    if (!ai ||
        !ASN1_INTEGER_set(ai->version, 0) ||
        !ASN1_STRING_set(ai->auth_method, auth_method,
                         (int)strlen(auth_method)) ||
        !ASN1_STRING_set(ai->session_id, session_id, (int)session_id_len))
        goto done;

    if (key_fingerprint) {
        if (!ai->key_fingerprint)
            ai->key_fingerprint = ASN1_UTF8STRING_new();
        if (!ai->key_fingerprint ||
            !ASN1_STRING_set(ai->key_fingerprint, key_fingerprint,
                             (int)strlen(key_fingerprint)))
            goto done;
    }
    if (client_address) {
        if (!ai->client_address)
            ai->client_address = ASN1_UTF8STRING_new();
        if (!ai->client_address ||
            !ASN1_STRING_set(ai->client_address, client_address,
                             (int)strlen(client_address)))
            goto done;
    }

    ai_len = i2d_SSH_AUTHN_CONTEXT(ai, &ai_der);
    SSH_AUTHN_CONTEXT_free(ai);
    ai = NULL;
    if (!ai_der || ai_len <= 0)
        goto done;

    /* ---- Assemble X.509 certificate ---- */
    cert = X509_new();
    if (!cert)
        goto done;

    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);

    /* Issuer CN = host principal, Subject CN = user (→ user lookup) */
    X509_NAME_add_entry_by_NID(X509_get_issuer_name(cert),
                                NID_commonName, MBSTRING_UTF8,
                                (unsigned char *)principal,
                                (int)strlen(principal), -1, 0);
    X509_NAME_add_entry_by_NID(X509_get_subject_name(cert),
                                NID_commonName, MBSTRING_UTF8,
                                (unsigned char *)user, (int)strlen(user),
                                -1, 0);

    /* Subject SPKI: user's registered public key (publickey auth) or ephemeral */
    {
        EVP_PKEY *epkey = NULL;
        EVP_PKEY *spkey = user_pubkey;
        if (!spkey) {
            epkey = fips_mode
                ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")
                : EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
            spkey = epkey;
        }
        if (!spkey)
            goto done;
        X509_set_pubkey(cert, spkey);
        EVP_PKEY_free(epkey);
    }

    if (add_raw_extension(cert, OID_KERBEROS_SERVICE_ISSUER_BINDING, 0,
                          ib_der, ib_len) != 0)
        goto done;
    if (add_raw_extension(cert, OID_SSH_AUTHN_CONTEXT, 0,
                          ai_der, ai_len) != 0)
        goto done;

    /* Sign with the derived key; Ed25519 uses implicit digest (NULL),
     * ECDSA P-256 requires an explicit hash (SHA-256). */
    if (X509_sign(cert, derived_key,
                  fips_mode ? EVP_sha256() : NULL) <= 0)
        goto done;

    {
        int len = i2d_X509(cert, NULL);
        if (len <= 0)
            goto done;
        cert_der = malloc((size_t)len);
        if (!cert_der)
            goto done;
        unsigned char *p = cert_der;
        i2d_X509(cert, &p);
        *cert_der_len_out = len;
    }

done:
    free(principal);
    OPENSSL_free(ib_der);
    OPENSSL_free(ai_der);
    EVP_PKEY_free(derived_key);
    EVP_PKEY_free(host_privkey);
    X509_PUBKEY_free(host_spki);
    X509_free(cert);
    KERBEROS_SERVICE_ISSUER_BINDING_free(ib);
    SSH_AUTHN_CONTEXT_free(ai);
    ASN1_OCTET_STRING_free(binding);
    return cert_der;
}

/* ------------------------------------------------------------------ *
 * Tests for ipadb_get_s4u_x509_principal()                           *
 * ------------------------------------------------------------------ */

static void test_get_s4u_x509_principal_as_req_path(void **state)
{
    /*
     * CLIENT_REFERRALS_FLAGS (KRB5_KDB_FLAG_REFERRAL_OK) marks the AS-REQ
     * KANAME realm-identification exchange ([MS-SFU] §3.1.5.1.1.1).
     * The function must NOT return KRB5_PLUGIN_NO_HANDLE for this case —
     * it must proceed into normal processing.  With a NULL krb5_context the
     * first thing it does after the flag check is call ipadb_get_context(),
     * so we expect KRB5_KDB_DBNOTINITED, not KRB5_PLUGIN_NO_HANDLE.
     */
    will_return(ipadb_get_context, NULL);

    unsigned char dummy_cert[] = { 0x30, 0x00 };
    krb5_data cert = { 0, sizeof(dummy_cert), (char *)dummy_cert };
    krb5_db_entry *entry = NULL;

    krb5_error_code ret =
        ipadb_get_s4u_x509_principal(NULL,
                                     &cert,
                                     NULL,
                                     CLIENT_REFERRALS_FLAGS,
                                     &entry);
    assert_int_equal(ret, KRB5_KDB_DBNOTINITED);
    assert_null(entry);
}

static void test_get_s4u_x509_principal_null_context(void **state)
{
    /*
     * When ipadb_get_context() returns NULL the function must fail
     * with KRB5_KDB_DBNOTINITED.
     */
    will_return(ipadb_get_context, NULL);

    unsigned char dummy_cert[] = { 0x30, 0x00 };
    krb5_data cert = { 0, sizeof(dummy_cert), (char *)dummy_cert };
    krb5_db_entry *entry = NULL;

    krb5_error_code ret =
        ipadb_get_s4u_x509_principal(NULL,
                                     &cert,
                                     NULL,
                                     0,
                                     &entry);
    assert_int_equal(ret, KRB5_KDB_DBNOTINITED);
    assert_null(entry);
}

static void test_get_s4u_x509_principal_bad_cert_der(void **state)
{
    /*
     * A cert buffer that is not valid DER must fail with PREAUTH_FAILED
     * before any LDAP or KDB calls are made.
     */
    will_return(ipadb_get_context, &g_fake_ctx);

    unsigned char garbage[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    krb5_data cert = { 0, sizeof(garbage), (char *)garbage };
    krb5_db_entry *entry = NULL;

    krb5_error_code ret =
        ipadb_get_s4u_x509_principal(NULL,
                                     &cert,
                                     NULL,
                                     0,
                                     &entry);
    assert_int_equal(ret, KRB5KDC_ERR_PREAUTH_FAILED);
    assert_null(entry);
}

static void test_get_s4u_x509_principal_missing_extension(void **state)
{
    /*
     * A valid self-signed X.509 cert without the sshKerberosIssuerBinding
     * extension must fail with PREAUTH_FAILED.
     */
    will_return(ipadb_get_context, &g_fake_ctx);

    unsigned char seed[32];
    memset(seed, 0x11, sizeof(seed));
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                   seed, 32);
    assert_non_null(pkey);

    X509 *cert = X509_new();
    assert_non_null(cert);
    X509_set_version(cert, X509_VERSION_3);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 3600);

    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"testhost", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_set_pubkey(cert, pkey);
    X509_sign(cert, pkey, NULL);  /* Ed25519 ignores the md arg */

    unsigned char *cert_der = NULL;
    int cert_len = i2d_X509(cert, &cert_der);
    assert_true(cert_len > 0);
    X509_free(cert);
    EVP_PKEY_free(pkey);

    krb5_data cert_data = { 0, (unsigned int)cert_len, (char *)cert_der };
    krb5_db_entry *entry = NULL;

    krb5_error_code ret =
        ipadb_get_s4u_x509_principal(NULL,
                                     &cert_data,
                                     NULL,
                                     0,
                                     &entry);
    OPENSSL_free(cert_der);

    assert_int_equal(ret, KRB5KDC_ERR_PREAUTH_FAILED);
    assert_null(entry);
}

static void run_full_pipeline_test(int fips_mode)
{
    /*
     * Fixed test vectors — all deterministic so the test is reproducible.
     */
    static const unsigned char ikm[32] = {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    };
    static const unsigned char host_seed[32] = {
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    };
    static const unsigned char session_id[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    };

    const char *hostname  = "testhost.example.com";
    const char *realm     = "EXAMPLE.COM";
    const char *user      = "testuser";
    const krb5_enctype enctype = 18;  /* AES256-CTS-HMAC-SHA1-96 */
    const uint32_t kvno = 1;

    static const unsigned char user_seed[32] = {
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    };

    krb5_context kctx = NULL;
    krb5_principal hint_princ = NULL;
    unsigned char *cert_der = NULL;
    int cert_der_len = 0;
    EVP_PKEY *host_privkey = NULL;
    EVP_PKEY *user_privkey = NULL;
    char *pubkey_line = NULL;
    char *user_pubkey_line = NULL;
    krb5_data user_ssh_key_data = { 0 };
    krb5_db_entry *entry_out = NULL;

    /*
     * Generate the user's Ed25519 SSH key (deterministic seed) so the cert's
     * subject SPKI can be set to the user's actual SSH public key.
     * We encode it as an OpenSSH authorized_keys line and later (after user_s4u
     * is declared) wire it into user_s4u.ssh_pubkeys so ssh_s4u_verify_context()
     * can perform the strong-assertion key comparison without a second LDAP call.
     */
    user_privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                user_seed, sizeof(user_seed));
    assert_non_null(user_privkey);
    user_pubkey_line = pkey_to_ssh_pubkey_line(user_privkey);
    assert_non_null(user_pubkey_line);

    /* ---- Build the attestation certificate ---- */

    cert_der = build_test_attestation_cert(
        ikm, sizeof(ikm),
        enctype, kvno,
        hostname, realm,
        user,
        "publickey",
        session_id, sizeof(session_id),
        "SHA256:AAABBBCCC=",
        "192.168.1.100:22",
        host_seed,
        user_privkey,  /* user's SSH public key as cert subject SPKI */
        fips_mode,
        &cert_der_len);
    assert_non_null(cert_der);
    assert_true(cert_der_len > 0);

    /* ---- Prepare mock data ---- */

    /* keyblock the KDC will see after decrypting the host key entry */
    krb5_keyblock test_keyblock;
    memset(&test_keyblock, 0, sizeof(test_keyblock));
    test_keyblock.magic    = KV5M_KEYBLOCK;
    test_keyblock.enctype  = enctype;
    test_keyblock.length   = (unsigned int)sizeof(ikm);
    test_keyblock.contents = (krb5_octet *)ikm;  /* stub copies it */

    /* key_data entry in the fake host KDB entry */
    krb5_key_data host_key_data;
    memset(&host_key_data, 0, sizeof(host_key_data));
    host_key_data.key_data_type[0] = (krb5_int16)enctype;
    host_key_data.key_data_kvno    = (krb5_ui_2)kvno;

    /*
     * Build the SSH authorized_keys line for the host's public key.
     * This is stored in host_s4u.ssh_pubkeys[] — pre-fetched from LDAP
     * by ipadb_parse_s4u_data() at get_principal() time, just as for
     * user entries.  No separate LDAP search is needed.
     */
    host_privkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                                 host_seed, 32);
    assert_non_null(host_privkey);
    pubkey_line = pkey_to_ssh_pubkey_line(host_privkey);
    assert_non_null(pubkey_line);

    /* s4u block for the host principal (ipasshpubkey pre-fetched from LDAP) */
    struct ipadb_s4u_data host_s4u;
    memset(&host_s4u, 0, sizeof(host_s4u));
    krb5_data host_ssh_key_data = {
        .magic  = KV5M_DATA,
        .data   = pubkey_line,
        .length = (unsigned int)strlen(pubkey_line),
    };
    host_s4u.ssh_pubkeys   = &host_ssh_key_data;
    host_s4u.n_ssh_pubkeys = 1;

    /* ipadb_e_data for the host principal */
    struct ipadb_e_data host_ied;
    memset(&host_ied, 0, sizeof(host_ied));
    host_ied.magic = IPA_E_DATA_MAGIC;
    host_ied.s4u   = &host_s4u;

    /* fake host KDB entry */
    krb5_db_entry fake_host_entry;
    memset(&fake_host_entry, 0, sizeof(fake_host_entry));
    fake_host_entry.n_key_data = 1;
    fake_host_entry.key_data   = &host_key_data;
    fake_host_entry.e_data     = (krb5_octet *)&host_ied;

    /* s4u block for the user principal (ipasshpubkey pre-fetched from LDAP) */
    struct ipadb_s4u_data user_s4u;
    memset(&user_s4u, 0, sizeof(user_s4u));

    /* Wire the user's registered SSH public key into s4u */
    user_ssh_key_data.magic  = KV5M_DATA;
    user_ssh_key_data.data   = user_pubkey_line;
    user_ssh_key_data.length = (unsigned int)strlen(user_pubkey_line);
    user_s4u.ssh_pubkeys     = &user_ssh_key_data;
    user_s4u.n_ssh_pubkeys   = 1;

    /* ipadb_e_data for the user principal */
    struct ipadb_e_data user_ied;
    memset(&user_ied, 0, sizeof(user_ied));
    user_ied.magic = IPA_E_DATA_MAGIC;
    user_ied.s4u   = &user_s4u;

    /* fake user KDB entry */
    krb5_db_entry fake_user_entry;
    memset(&fake_user_entry, 0, sizeof(fake_user_entry));
    fake_user_entry.e_data = (krb5_octet *)&user_ied;

    /* ---- Set up cmocka mock return values (in call order) ---- */

    will_return(ipadb_get_context, &g_fake_ctx);
    /* host principal lookup */
    will_return(ipadb_get_principal, &fake_host_entry);
    /* key decryption */
    will_return(krb5_dbe_decrypt_key_data, &test_keyblock);
    /* user principal lookup */
    will_return(ipadb_get_principal, &fake_user_entry);

    /* ---- Initialize a real krb5 context for principal operations ---- */

    assert_int_equal(krb5_init_context(&kctx), 0);

    /* hint_princ = "testuser@EXAMPLE.COM" */
    assert_int_equal(
        krb5_build_principal(kctx, &hint_princ,
                             (unsigned int)strlen(realm), realm,
                             user, (char *)NULL),
        0);

    /* ---- Call the function under test ---- */

    krb5_data cert_data = { 0, (unsigned int)cert_der_len, (char *)cert_der };

    krb5_error_code ret =
        ipadb_get_s4u_x509_principal_impl(kctx, &cert_data, hint_princ, 0,
                                          &entry_out, fips_mode);

    /* ---- Verify results ---- */

    assert_int_equal(ret, 0);
    assert_non_null(entry_out);

    struct ipadb_e_data *ied = (struct ipadb_e_data *)entry_out->e_data;
    assert_non_null(ied);
    assert_int_equal(ied->magic, IPA_E_DATA_MAGIC);
    assert_non_null(ied->s4u);
    assert_true(ied->s4u->attested);
    assert_non_null(ied->s4u->service_type);
    assert_string_equal(ied->s4u->service_type, "ssh");
    assert_non_null(ied->s4u->auth_method);
    assert_string_equal(ied->s4u->auth_method, "publickey");
    assert_non_null(ied->s4u->ssh_key_fingerprint);
    assert_string_equal(ied->s4u->ssh_key_fingerprint, "SHA256:AAABBBCCC=");
    assert_non_null(ied->s4u->ssh_client_address);
    assert_string_equal(ied->s4u->ssh_client_address, "192.168.1.100:22");

    /* ---- Cleanup ---- */

    free(ied->s4u->service_type);
    free(ied->s4u->auth_method);
    free(ied->s4u->ssh_key_fingerprint);
    free(ied->s4u->ssh_client_address);
    /* ied->s4u is stack-allocated (user_s4u) in this test; do not free */
    free(pubkey_line);
    free(user_pubkey_line);  /* user_ssh_key_data.data; zeroed by freeing here */
    free(cert_der);
    EVP_PKEY_free(host_privkey);
    EVP_PKEY_free(user_privkey);
    krb5_free_principal(kctx, hint_princ);
    krb5_free_context(kctx);
}

static void test_get_s4u_x509_principal_full_pipeline(void **state)
{
    (void)state;
    run_full_pipeline_test(0);
}

static void test_get_s4u_x509_principal_full_pipeline_fips(void **state)
{
    (void)state;
    run_full_pipeline_test(1);
}

/* ------------------------------------------------------------------ *
 * Test: ssh_s4u_verify_context() mismatch path                        *
 *                                                                     *
 * Verifies that supplying a cert whose Subject CN differs from the    *
 * S4U2Self hint principal is rejected with                            *
 * KRB5KDC_ERR_CLIENT_NAME_MISMATCH — the core anti-substitution gate. *
 * ------------------------------------------------------------------ */
static void test_ssh_s4u_verify_context_mismatch(void **state)
{
    (void)state;

    krb5_context kctx = NULL;
    assert_int_equal(krb5_init_context(&kctx), 0);

    /* Build a minimal cert whose Subject CN is "alice" */
    X509 *cert = X509_new();
    assert_non_null(cert);
    X509_NAME_add_entry_by_NID(X509_get_subject_name(cert),
                                NID_commonName, MBSTRING_UTF8,
                                (unsigned char *)"alice", 5, -1, 0);

    /* Hint principal is "bob@EXAMPLE.COM" — different from cert CN */
    krb5_principal hint = NULL;
    assert_int_equal(krb5_parse_name(kctx, "bob@EXAMPLE.COM", &hint), 0);

    krb5_db_entry *entry_out = NULL;
    krb5_error_code ret = ssh_s4u_verify_context(kctx, &s4u_handlers[0],
                                                   cert, hint,
                                                   KRB5_KDB_FLAG_CLIENT,
                                                   NULL, &entry_out);

    assert_int_equal(ret, KRB5KDC_ERR_CLIENT_NAME_MISMATCH);
    assert_null(entry_out);

    X509_free(cert);
    krb5_free_principal(kctx, hint);
    krb5_free_context(kctx);
}

/* ------------------------------------------------------------------ *
 * main                                                                *
 * ------------------------------------------------------------------ */

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* d2i_KERBEROS_SERVICE_ISSUER_BINDING */
        cmocka_unit_test(test_parse_issuer_binding_valid),
        cmocka_unit_test(test_parse_issuer_binding_bad_version),
        cmocka_unit_test(test_parse_issuer_binding_truncated),
        /* d2i_SSH_AUTHN_CONTEXT */
        cmocka_unit_test(test_parse_authn_info_full),
        cmocka_unit_test(test_parse_authn_info_no_optionals),
        cmocka_unit_test(test_parse_authn_info_bad_version),
        /* parse_openssh_pubkey */
        cmocka_unit_test(test_parse_openssh_pubkey_ed25519),
        cmocka_unit_test(test_parse_openssh_pubkey_bad_type),
        cmocka_unit_test(test_parse_openssh_pubkey_no_space),
        /* hkdf_sha256 */
        cmocka_unit_test(test_hkdf_sha256_deterministic),
        cmocka_unit_test(test_hkdf_sha256_different_info),
        /* derive_attestation_key */
        cmocka_unit_test(test_derive_attestation_key_ed25519),
        cmocka_unit_test(test_derive_attestation_key_p256),
        cmocka_unit_test(test_p256_sign_verify),
        /* verify_binding_signature */
        cmocka_unit_test(test_verify_binding_signature_valid),
        cmocka_unit_test(test_verify_binding_signature_bad_sig),
        cmocka_unit_test(test_verify_binding_signature_wrong_kvno),
        /* ssh_s4u_verify_context */
        cmocka_unit_test(test_ssh_s4u_verify_context_mismatch),
        /* ipadb_get_s4u_x509_principal */
        cmocka_unit_test(test_get_s4u_x509_principal_as_req_path),
        cmocka_unit_test(test_get_s4u_x509_principal_null_context),
        cmocka_unit_test(test_get_s4u_x509_principal_bad_cert_der),
        cmocka_unit_test(test_get_s4u_x509_principal_missing_extension),
        cmocka_unit_test(test_get_s4u_x509_principal_full_pipeline),
        cmocka_unit_test(test_get_s4u_x509_principal_full_pipeline_fips),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
