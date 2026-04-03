/*
 * MIT Kerberos KDC database backend for FreeIPA
 *
 * S4U2Self X.509 attestation certificate verification.
 *
 * Authors: Alexander Bokovoy <abokovoy@redhat.com>
 *
 * Copyright (C) 2026  Red Hat, Inc.
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

#ifdef BUILD_IPA_S4U_X509

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>

#include "ipa_kdb.h"

/*
 * OID strings for the custom X.509 extensions.
 * Placed under the IPA Kerberos certificate extensions sub-arc.
 */
#define OID_KERBEROS_SERVICE_ISSUER_BINDING "2.16.840.1.113730.3.8.15.3.1"
#define OID_SSH_AUTHN_CONTEXT               "2.16.840.1.113730.3.8.15.3.2"
#define OID_OIDC_AUTHN_CONTEXT              "2.16.840.1.113730.3.8.15.3.3"


/* ------------------------------------------------------------------ *
 * ASN.1 type definitions for the custom X.509 extensions.
 *
 * id-ce-kerberosServiceIssuerBinding:
 *   SEQUENCE {
 *     version     INTEGER (0),
 *     serviceType UTF8String,        -- "ssh", "oidc", "pam", ...
 *     principal   UTF8String,
 *     enctype     INTEGER,
 *     kvno        INTEGER,
 *     sigAlg      AlgorithmIdentifier,
 *     serviceKey  SubjectPublicKeyInfo,
 *     binding     OCTET STRING
 *   }
 *
 * id-ce-sshAuthnContext (OID ...3.2):
 *   SEQUENCE {
 *     version         INTEGER (0),
 *     authMethod      UTF8String,
 *     sessionId       OCTET STRING,
 *     keyFingerprint  [0] EXPLICIT UTF8String OPTIONAL,
 *     clientAddress   [1] EXPLICIT UTF8String OPTIONAL
 *   }
 *
 * id-ce-oidcAuthnContext (OID ...3.3):
 *   SEQUENCE {
 *     version         INTEGER (0),
 *     issuer          UTF8String,
 *     clientId        UTF8String OPTIONAL,
 *     accessTokenHash OCTET STRING,
 *     amrValues       SEQUENCE OF UTF8String OPTIONAL,
 *     clientAddress   [0] EXPLICIT UTF8String OPTIONAL
 *   }
 *   clientId (0x0C) and accessTokenHash (0x04) carry distinct tags so the
 *   optional clientId is unambiguous to decoders.  amrValues is decoded as
 *   ASN1_SEQUENCE_ANY (STACK_OF(ASN1_TYPE)) to avoid a nested typedef.
 * ------------------------------------------------------------------ */

typedef struct kerberos_service_issuer_binding_st {
    ASN1_INTEGER      *version;
    ASN1_UTF8STRING   *service_type;   /* "ssh", "oidc", "pam", ... */
    ASN1_UTF8STRING   *principal;
    ASN1_INTEGER      *enctype;
    ASN1_INTEGER      *kvno;
    X509_ALGOR        *sig_alg;
    X509_PUBKEY       *service_key;
    ASN1_OCTET_STRING *binding;
} KERBEROS_SERVICE_ISSUER_BINDING;

DECLARE_ASN1_FUNCTIONS(KERBEROS_SERVICE_ISSUER_BINDING)

ASN1_SEQUENCE(KERBEROS_SERVICE_ISSUER_BINDING) = {
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, version,      ASN1_INTEGER),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, service_type, ASN1_UTF8STRING),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, principal,    ASN1_UTF8STRING),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, enctype,      ASN1_INTEGER),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, kvno,         ASN1_INTEGER),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, sig_alg,      X509_ALGOR),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, service_key,  X509_PUBKEY),
    ASN1_SIMPLE(KERBEROS_SERVICE_ISSUER_BINDING, binding,      ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KERBEROS_SERVICE_ISSUER_BINDING)

IMPLEMENT_ASN1_FUNCTIONS(KERBEROS_SERVICE_ISSUER_BINDING)

typedef struct ssh_authn_context_st {
    ASN1_INTEGER      *version;
    ASN1_UTF8STRING   *auth_method;
    ASN1_OCTET_STRING *session_id;
    ASN1_UTF8STRING   *key_fingerprint;  /* [0] EXPLICIT OPTIONAL */
    ASN1_UTF8STRING   *client_address;   /* [1] EXPLICIT OPTIONAL */
} SSH_AUTHN_CONTEXT;

DECLARE_ASN1_FUNCTIONS(SSH_AUTHN_CONTEXT)

ASN1_SEQUENCE(SSH_AUTHN_CONTEXT) = {
    ASN1_SIMPLE(SSH_AUTHN_CONTEXT, version,          ASN1_INTEGER),
    ASN1_SIMPLE(SSH_AUTHN_CONTEXT, auth_method,      ASN1_UTF8STRING),
    ASN1_SIMPLE(SSH_AUTHN_CONTEXT, session_id,       ASN1_OCTET_STRING),
    ASN1_EXP_OPT(SSH_AUTHN_CONTEXT, key_fingerprint, ASN1_UTF8STRING, 0),
    ASN1_EXP_OPT(SSH_AUTHN_CONTEXT, client_address,  ASN1_UTF8STRING, 1),
} ASN1_SEQUENCE_END(SSH_AUTHN_CONTEXT)

IMPLEMENT_ASN1_FUNCTIONS(SSH_AUTHN_CONTEXT)

typedef struct oidc_authn_context_st {
    ASN1_INTEGER        *version;
    ASN1_UTF8STRING     *issuer;
    ASN1_UTF8STRING     *client_id;          /* OPTIONAL, no explicit tag */
    ASN1_OCTET_STRING   *access_token_hash;
    STACK_OF(ASN1_TYPE) *amr_values;         /* OPTIONAL SEQUENCE OF UTF8String */
    ASN1_UTF8STRING     *client_address;     /* [0] EXPLICIT OPTIONAL */
} OIDC_AUTHN_CONTEXT;

DECLARE_ASN1_FUNCTIONS(OIDC_AUTHN_CONTEXT)

ASN1_SEQUENCE(OIDC_AUTHN_CONTEXT) = {
    ASN1_SIMPLE(OIDC_AUTHN_CONTEXT, version,           ASN1_INTEGER),
    ASN1_SIMPLE(OIDC_AUTHN_CONTEXT, issuer,            ASN1_UTF8STRING),
    ASN1_OPT(OIDC_AUTHN_CONTEXT,   client_id,          ASN1_UTF8STRING),
    ASN1_SIMPLE(OIDC_AUTHN_CONTEXT, access_token_hash, ASN1_OCTET_STRING),
    ASN1_OPT(OIDC_AUTHN_CONTEXT,   amr_values,         ASN1_SEQUENCE_ANY),
    ASN1_EXP_OPT(OIDC_AUTHN_CONTEXT, client_address,  ASN1_UTF8STRING, 0),
} ASN1_SEQUENCE_END(OIDC_AUTHN_CONTEXT)

IMPLEMENT_ASN1_FUNCTIONS(OIDC_AUTHN_CONTEXT)

/* ------------------------------------------------------------------ *
 * id-pkinit-san (1.3.6.1.5.2.2) PKINIT Subject Alternative Name     *
 *                                                                      *
 * KRB5PrincipalName ::= SEQUENCE {                                    *
 *     realm [0] EXPLICIT GeneralString,                               *
 *     principalName [1] EXPLICIT PrincipalName                        *
 * }                                                                   *
 * PrincipalName ::= SEQUENCE {                                        *
 *     name-type   [0] EXPLICIT INTEGER,                               *
 *     name-string [1] EXPLICIT SEQUENCE OF GeneralString              *
 * }                                                                   *
 * ------------------------------------------------------------------ */
#define OID_PKINIT_SAN "1.3.6.1.5.2.2"

/* Minimal DER TLV reader: reads tag+length, returns pointer to content. */
static int
der_tlv_read(const unsigned char **p, const unsigned char *end,
             int expected_tag,
             const unsigned char **content, size_t *content_len)
{
    if (*p >= end || (int)**p != expected_tag)
        return -1;
    (*p)++;
    if (*p >= end)
        return -1;
    size_t len;
    if (**p & 0x80) {
        int nb = **p & 0x7f;
        (*p)++;
        if (nb < 1 || nb > 3 || *p + nb > end)
            return -1;
        len = 0;
        while (nb--)
            len = (len << 8) | *(*p)++;
    } else {
        len = *(*p)++;
    }
    if (*p + len > end)
        return -1;
    *content = *p;
    *content_len = len;
    *p += len;
    return 0;
}

/*
 * Parse a KRB5PrincipalName DER blob (the SEQUENCE content inside the
 * id-pkinit-san OtherName value) and reconstruct the principal string.
 *
 * For a single-component name "alice@REALM" the result is "alice@REALM".
 * For a two-component name the result is "comp0/comp1@REALM" (service form).
 *
 * The caller must free *princ_str_out.
 */
static int
parse_krb5_principal_name(const unsigned char *der, size_t derlen,
                           char **princ_str_out)
{
    const unsigned char *p = der, *end = der + derlen;
    const unsigned char *seq, *c0, *c1, *gs, *inner, *c1a, *c1b, *ns;
    size_t seq_len, c0_len, c1_len, gs_len, inner_len, c1a_len, c1b_len;
    size_t ns_len;
    char *realm = NULL;
    int ret = -1;

    /* Outer SEQUENCE */
    if (der_tlv_read(&p, end, 0x30, &seq, &seq_len) < 0)
        goto out;

    {
        const unsigned char *sp = seq, *se = seq + seq_len;

        /* [0] EXPLICIT GeneralString (realm) */
        if (der_tlv_read(&sp, se, 0xa0, &c0, &c0_len) < 0)
            goto out;
        {
            const unsigned char *cp = c0, *ce = c0 + c0_len;
            if (der_tlv_read(&cp, ce, 0x1b, &gs, &gs_len) < 0)
                goto out;
            realm = strndup((const char *)gs, gs_len);
            if (!realm)
                goto out;
        }

        /* [1] EXPLICIT SEQUENCE (PrincipalName) */
        if (der_tlv_read(&sp, se, 0xa1, &c1, &c1_len) < 0)
            goto out;
        {
            const unsigned char *cp = c1, *ce = c1 + c1_len;
            if (der_tlv_read(&cp, ce, 0x30, &inner, &inner_len) < 0)
                goto out;
            {
                const unsigned char *ip = inner, *ie = inner + inner_len;
                /* [0] EXPLICIT INTEGER (name-type) — skip */
                if (der_tlv_read(&ip, ie, 0xa0, &c1a, &c1a_len) < 0)
                    goto out;
                /* [1] EXPLICIT SEQUENCE OF GeneralString (name-string) */
                if (der_tlv_read(&ip, ie, 0xa1, &c1b, &c1b_len) < 0)
                    goto out;
                {
                    const unsigned char *np = c1b, *ne = c1b + c1b_len;
                    if (der_tlv_read(&np, ne, 0x30, &ns, &ns_len) < 0)
                        goto out;
                    {
                        const unsigned char *gp = ns, *ge = ns + ns_len;
                        /* Collect name-string components */
                        char *buf = NULL;
                        size_t buflen = 0;
                        FILE *ms = open_memstream(&buf, &buflen);
                        if (!ms) goto out;
                        bool first = true;
                        while (gp < ge) {
                            const unsigned char *comp;
                            size_t comp_len;
                            if (der_tlv_read(&gp, ge, 0x1b,
                                             &comp, &comp_len) < 0) {
                                fclose(ms);
                                free(buf);
                                goto out;
                            }
                            if (!first) fputc('/', ms);
                            fwrite(comp, 1, comp_len, ms);
                            first = false;
                        }
                        fprintf(ms, "@%s", realm);
                        fclose(ms);
                        *princ_str_out = buf;
                        ret = 0;
                    }
                }
            }
        }
    }
out:
    free(realm);
    return ret;
}

/*
 * Extract the Kerberos principal from the id-pkinit-san OtherName in the
 * cert's SubjectAltName extension.  Parses the KRB5PrincipalName DER and
 * calls krb5_parse_name() to produce a krb5_principal.
 *
 * Returns 0 and sets *princ_out on success; caller must free with
 * krb5_free_principal().  Returns KRB5KDC_ERR_PREAUTH_FAILED if no
 * valid id-pkinit-san is found.
 */
static krb5_error_code
cert_get_pkinit_san_principal(krb5_context kcontext, X509 *cert,
                               krb5_principal *princ_out)
{
    STACK_OF(GENERAL_NAME) *sans = NULL;
    ASN1_OBJECT             *oid  = NULL;
    krb5_error_code          ret  = KRB5KDC_ERR_PREAUTH_FAILED;
    char                    *pstr = NULL;

    sans = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (!sans)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    oid = OBJ_txt2obj(OID_PKINIT_SAN, 1);
    if (!oid)
        goto out;

    for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
        GENERAL_NAME *gn = sk_GENERAL_NAME_value(sans, i);
        if (gn->type != GEN_OTHERNAME)
            continue;

        OTHERNAME *oname = gn->d.otherName;
        if (OBJ_cmp(oname->type_id, oid) != 0)
            continue;

        /* oname->value->value.sequence contains KRB5PrincipalName DER */
        if (oname->value->type != V_ASN1_SEQUENCE)
            continue;

        ASN1_STRING *seq = oname->value->value.sequence;
        if (!seq || !seq->data || seq->length <= 0)
            continue;

        if (parse_krb5_principal_name(seq->data, (size_t)seq->length,
                                       &pstr) < 0) {
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: failed to parse PKINIT SAN DER");
            continue;
        }

        ret = krb5_parse_name(kcontext, pstr, princ_out);
        free(pstr);
        pstr = NULL;
        if (ret == 0)
            break;
    }

out:
    ASN1_OBJECT_free(oid);
    sk_GENERAL_NAME_pop_free(sans, GENERAL_NAME_free);
    return ret;
}

/*
 * Forward typedefs used by verify_host_key_registered() and the handler
 * table.  Full struct definition follows after all static helpers.
 */
typedef EVP_PKEY *(*s4u_parse_pubkey_fn)(const unsigned char *data,
                                          size_t len);
struct ipa_s4u_cert_handler;  /* completed below */
typedef krb5_error_code (*s4u_verify_context_fn)(
    krb5_context kcontext,
    const struct ipa_s4u_cert_handler *h,
    X509 *cert,
    krb5_const_principal hint_princ,
    unsigned int flags,
    const void *svc_context,
    krb5_db_entry **entry_out);
/* Parse a service context extension from DER bytes; return opaque pointer or
 * NULL on parse / version failure.  Caller must free via free_context_fn. */
typedef void *(*s4u_parse_context_fn)(const unsigned char *data, size_t len);
typedef void  (*s4u_free_context_fn)(void *ctx);

/* ------------------------------------------------------------------ *
 * Locate a named extension in an X.509 cert and return its value bytes.
 * The returned pointer is into the cert's internal storage (not allocated).
 * ------------------------------------------------------------------ */
static int cert_get_extension(X509 *cert, const char *oid_str,
                              const unsigned char **data_out, size_t *len_out)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid_str, 1 /* require dotted form */);
    if (!obj)
        return -1;

    int idx = X509_get_ext_by_OBJ(cert, obj, -1);
    ASN1_OBJECT_free(obj);
    if (idx < 0)
        return -1;

    X509_EXTENSION *ext = X509_get_ext(cert, idx);
    if (!ext)
        return -1;

    ASN1_OCTET_STRING *val = X509_EXTENSION_get_data(ext);
    if (!val)
        return -1;

    *data_out = ASN1_STRING_get0_data(val);
    *len_out  = (size_t)ASN1_STRING_length(val);
    return 0;
}

/* ------------------------------------------------------------------ *
 * HKDF-SHA256 via OpenSSL 3.x EVP_KDF
 * ------------------------------------------------------------------ */
static krb5_error_code
hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
            const char *salt, size_t salt_len,
            const unsigned char *info, size_t info_len,
            unsigned char *out, size_t out_len)
{
    EVP_KDF     *kdf  = NULL;
    EVP_KDF_CTX *kctx = NULL;
    krb5_error_code ret = KRB5KDC_ERR_PREAUTH_FAILED;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf)
        goto done;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx)
        goto done;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                         "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                          (void *)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                          (void *)salt, salt_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          (void *)info, info_len),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kctx, out, out_len, params) <= 0)
        goto done;

    ret = 0;
done:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/* ------------------------------------------------------------------ *
 * Build the HKDF info field: hostname || '\0' || realm || '\0' || kvno_be32
 * ------------------------------------------------------------------ */
static unsigned char *
build_hkdf_info(const char *hostname, const char *realm, uint32_t kvno,
                size_t *info_len_out)
{
    size_t hlen = strlen(hostname);
    size_t rlen = strlen(realm);
    size_t total = hlen + 1 + rlen + 1 + 4;
    unsigned char *buf = malloc(total);
    if (!buf)
        return NULL;

    unsigned char *p = buf;
    memcpy(p, hostname, hlen); p += hlen;
    *p++ = '\0';
    memcpy(p, realm, rlen);   p += rlen;
    *p++ = '\0';
    uint32_t kvno_be = htonl(kvno);
    memcpy(p, &kvno_be, 4);

    *info_len_out = total;
    return buf;
}

/*
 * NIST P-256 group order n (FIPS 186-4 §D.1.2.3 / SEC2 §2.4.2).
 * Hardcoded to avoid a round-trip through EVP_PKEY_fromdata for parameters.
 * The constant is defined by the curve spec and will never change.
 */
static const unsigned char P256_ORDER[32] = {
    0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    0xBC,0xE6,0xFA,0xAD, 0xA7,0x17,0x9E,0x84,
    0xF3,0xB9,0xCA,0xC2, 0xFC,0x63,0x25,0x51
};

/* ------------------------------------------------------------------ *
 * Derive ECDSA P-256 attestation key from a 48-byte HKDF seed.
 *
 * NIST SP 800-56A Rev 3 §5.6.1.2.2: scalar = (raw mod (n_P256 - 1)) + 1
 * ------------------------------------------------------------------ */
static krb5_error_code
derive_p256_attestation_key(const unsigned char *seed, EVP_PKEY **pkey_out)
{
    BN_CTX         *ctx    = NULL;
    BIGNUM         *raw_bn = NULL;
    BIGNUM         *n      = NULL;
    BIGNUM         *nm1    = NULL;
    BIGNUM         *scalar = NULL;
    EC_GROUP       *group  = NULL;
    EC_POINT       *pub_pt = NULL;
    EVP_PKEY       *pkey   = NULL;
    unsigned char   kbytes[32] = { 0 };
    unsigned char   pub_buf[65];
    krb5_error_code ret = KRB5KDC_ERR_PREAUTH_FAILED;

    ctx    = BN_CTX_new();
    raw_bn = BN_bin2bn(seed, 48, NULL);
    n      = BN_bin2bn(P256_ORDER, sizeof(P256_ORDER), NULL);
    nm1    = BN_new();
    scalar = BN_new();
    group  = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (!ctx || !raw_bn || !n || !nm1 || !scalar || !group) {
        ret = ENOMEM;
        goto cleanup;
    }

    /*
     * raw_bn is derived from a keytab secret via HKDF.  BN_FLG_CONSTTIME
     * requests constant-time arithmetic paths where available (best effort;
     * BN_mod is not guaranteed constant-time in all OpenSSL versions).
     */
    BN_set_flags(raw_bn, BN_FLG_CONSTTIME);

    pub_pt = EC_POINT_new(group);
    if (!pub_pt) {
        ret = ENOMEM;
        goto cleanup;
    }

    /* NIST SP 800-56A Rev 3 §5.6.1.2.2: scalar = (raw mod (n-1)) + 1 */
    if (!BN_copy(nm1, n) ||
        !BN_sub_word(nm1, 1) ||
        !BN_mod(scalar, raw_bn, nm1, ctx) ||
        !BN_add_word(scalar, 1) ||
        BN_bn2binpad(scalar, kbytes, 32) != 32) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: P-256 scalar reduction failed");
        goto cleanup;
    }

    /* EVP_PKEY_fromdata with only the private key does not auto-derive the
     * public key in OpenSSL 3.x (provider behaviour differs from docs).
     * Compute Q = scalar * G explicitly, then supply both components to
     * EVP_PKEY_fromdata so the pairwise consistency check passes and
     * X509_verify() can use the resulting key.
     */
    {
        BIGNUM         *priv_bn = BN_secure_new();
        OSSL_PARAM_BLD *bld     = NULL;
        OSSL_PARAM     *params  = NULL;
        EVP_PKEY_CTX   *kpctx  = NULL;

        if (priv_bn && BN_bin2bn(kbytes, 32, priv_bn) &&
            EC_POINT_mul(group, pub_pt, priv_bn, NULL, NULL, NULL) &&
            EC_POINT_point2oct(group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                               pub_buf, sizeof(pub_buf), NULL) == sizeof(pub_buf) &&
            (bld = OSSL_PARAM_BLD_new()) != NULL &&
            OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                            "P-256", 0) &&
            OSSL_PARAM_BLD_push_BN_pad(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                       priv_bn, 32) &&
            OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                             pub_buf, sizeof(pub_buf)) &&
            (params = OSSL_PARAM_BLD_to_param(bld)) != NULL &&
            (kpctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) != NULL &&
            EVP_PKEY_fromdata_init(kpctx) > 0 &&
            EVP_PKEY_fromdata(kpctx, &pkey, EVP_PKEY_KEYPAIR, params) > 0)
            ret = 0;
        else
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: P-256 key construction from scalar failed");

        BN_clear_free(priv_bn);
        OSSL_PARAM_BLD_free(bld);
        OSSL_PARAM_free(params);
        EVP_PKEY_CTX_free(kpctx);
    }

cleanup:
    OPENSSL_cleanse(kbytes, sizeof(kbytes));
    OPENSSL_cleanse(pub_buf, sizeof(pub_buf));
    EC_POINT_free(pub_pt);
    EC_GROUP_free(group);
    BN_CTX_free(ctx);
    BN_clear_free(raw_bn);
    BN_clear_free(n);
    BN_clear_free(nm1);
    BN_clear_free(scalar);
    if (ret == 0)
        *pkey_out = pkey;
    else
        EVP_PKEY_free(pkey);
    return ret;
}

/* ------------------------------------------------------------------ *
 * Derive the attestation signing key from the keytab key material.
 *
 * Non-FIPS: Ed25519 from 32-byte HKDF seed
 * FIPS:     ECDSA P-256 using NIST SP 800-56A Rev 3 §5.6.1.2.2
 *           (48-byte HKDF output, reduce mod (n_P256 - 1) + 1)
 * ------------------------------------------------------------------ */
static krb5_error_code
derive_attestation_key(const unsigned char *ikm, size_t ikm_len,
                       const char *hkdf_salt,
                       const char *hostname, const char *realm,
                       uint32_t kvno, int fips_mode,
                       EVP_PKEY **pkey_out)
{
    krb5_error_code ret = KRB5KDC_ERR_PREAUTH_FAILED;
    unsigned char   seed[48];
    unsigned char  *info = NULL;
    size_t          info_len = 0;
    EVP_PKEY       *pkey = NULL;

    info = build_hkdf_info(hostname, realm, kvno, &info_len);
    if (!info) {
        ret = ENOMEM;
        goto done;
    }

    ret = hkdf_sha256(ikm, ikm_len,
                      hkdf_salt, strlen(hkdf_salt),
                      info, info_len,
                      seed, fips_mode ? 48 : 32);
    if (ret)
        goto done;

    if (!fips_mode) {
        pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
                                             seed, 32);
        if (!pkey) {
            ret = KRB5KDC_ERR_PREAUTH_FAILED;
            goto done;
        }
        ret = 0;
    } else {
        ret = derive_p256_attestation_key(seed, &pkey);
    }

    if (ret == 0)
        *pkey_out = pkey;
    else
        EVP_PKEY_free(pkey);

done:
    free(info);
    OPENSSL_cleanse(seed, sizeof(seed));
    return ret;
}

/* ------------------------------------------------------------------ *
 * Parse one OpenSSH authorized_keys format key into an EVP_PKEY.
 *
 * Format: "<type> <base64-blob> [comment]"
 * The blob is a sequence of uint32-length-prefixed strings.
 *
 * Supported: ecdsa-sha2-nistp256, ssh-ed25519, ssh-rsa
 * ------------------------------------------------------------------ */

static uint32_t read_u32be(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static const unsigned char *ssh_read_string(const unsigned char *buf,
                                            size_t buflen,
                                            size_t *pos, size_t *slen_out)
{
    if (*pos + 4 > buflen)
        return NULL;
    uint32_t slen = read_u32be(buf + *pos);
    *pos += 4;
    if ((size_t)slen > buflen - *pos)
        return NULL;
    const unsigned char *s = buf + *pos;
    *pos += slen;
    if (slen_out)
        *slen_out = slen;
    return s;
}

static EVP_PKEY *parse_der_spki_pubkey(const unsigned char *data, size_t len)
{
    return d2i_PUBKEY(NULL, &data, (long)len);
}

static EVP_PKEY *parse_openssh_pubkey(const unsigned char *data, size_t len)
{
    /*
     * OpenSSH authorized_keys format is text; make a NUL-terminated copy
     * so that strchr() and strlen() work safely on the LDAP berval bytes.
     */
    char *line = strndup((const char *)data, len);
    if (!line)
        return NULL;

    const char *sp = strchr(line, ' ');
    if (!sp) {
        free(line);
        return NULL;
    }

    size_t type_len = (size_t)(sp - line);
    int is_ecdsa_nistp256 = (type_len == 19 &&
                              strncmp(line, "ecdsa-sha2-nistp256", 19) == 0);
    int is_ed25519        = (type_len == 11 &&
                              strncmp(line, "ssh-ed25519", 11) == 0);
    int is_rsa            = (type_len == 7 &&
                              strncmp(line, "ssh-rsa", 7) == 0);

    if (!is_ecdsa_nistp256 && !is_ed25519 && !is_rsa) {
        free(line);
        return NULL;
    }

    const char *b64_start = sp + 1;
    const char *b64_end   = strchr(b64_start, ' ');
    if (!b64_end)
        b64_end = b64_start + strlen(b64_start);
    while (b64_end > b64_start &&
           (b64_end[-1] == '\n' || b64_end[-1] == '\r'))
        b64_end--;

    size_t b64_len = (size_t)(b64_end - b64_start);
    if (!b64_len)
        return NULL;

    /* Upper bound on decoded size */
    size_t blob_alloc = (b64_len / 4 + 1) * 3;
    unsigned char *blob = malloc(blob_alloc);
    if (!blob)
        return NULL;

    int n = EVP_DecodeBlock(blob, (const unsigned char *)b64_start, (int)b64_len);
    if (n < 0) {
        free(blob);
        return NULL;
    }
    int pad = (b64_len > 0 && b64_start[b64_len-1] == '=') +
              (b64_len > 1 && b64_start[b64_len-2] == '=');
    if (n < pad) {
        free(blob);
        return NULL;
    }
    size_t blob_len = (size_t)(n - pad);

    EVP_PKEY *pkey = NULL;
    size_t pos = 0;

    /* Skip the key-type string at the start of the blob */
    if (!ssh_read_string(blob, blob_len, &pos, NULL))
        goto out;

    if (is_ed25519) {
        size_t raw_len = 0;
        const unsigned char *raw = ssh_read_string(blob, blob_len,
                                                    &pos, &raw_len);
        if (!raw || raw_len != 32)
            goto out;
        pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                            raw, raw_len);
    } else if (is_ecdsa_nistp256) {
        /* Skip curve id ("nistp256") */
        if (!ssh_read_string(blob, blob_len, &pos, NULL))
            goto out;
        size_t pt_len = 0;
        const unsigned char *pt = ssh_read_string(blob, blob_len,
                                                   &pos, &pt_len);
        /* SSH carries the uncompressed EC point (0x04 || x || y) directly */
        if (!pt || !pt_len || pt[0] != 0x04)
            goto out;

        EVP_PKEY_CTX *ec_pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
        if (!ec_pctx)
            goto out;

        OSSL_PARAM ec_params[] = {
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                             "P-256", 0),
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                              (void *)pt, pt_len),
            OSSL_PARAM_construct_end()
        };

        if (EVP_PKEY_fromdata_init(ec_pctx) <= 0 ||
            EVP_PKEY_fromdata(ec_pctx, &pkey, EVP_PKEY_PUBLIC_KEY,
                              ec_params) <= 0) {
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: failed to construct ECDSA P-256 "
                             "public key from LDAP value");
            pkey = NULL;
        }
        EVP_PKEY_CTX_free(ec_pctx);
    } else if (is_rsa) {
        size_t e_len = 0, n_len = 0;
        const unsigned char *e_bytes = ssh_read_string(blob, blob_len,
                                                        &pos, &e_len);
        const unsigned char *n_bytes = ssh_read_string(blob, blob_len,
                                                        &pos, &n_len);
        if (!e_bytes || !n_bytes)
            goto out;

        BIGNUM *e_bn = BN_bin2bn(e_bytes, (int)e_len, NULL);
        BIGNUM *n_bn = BN_bin2bn(n_bytes, (int)n_len, NULL);
        if (!e_bn || !n_bn) {
            BN_free(e_bn);
            BN_free(n_bn);
            goto out;
        }

        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (!bld ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn)) {
            OSSL_PARAM_BLD_free(bld);
            BN_free(e_bn);
            BN_free(n_bn);
            goto out;
        }
        OSSL_PARAM *rsa_params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        BN_free(e_bn);
        BN_free(n_bn);
        if (!rsa_params)
            goto out;

        EVP_PKEY_CTX *rsa_pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (!rsa_pctx) {
            OSSL_PARAM_free(rsa_params);
            goto out;
        }
        if (EVP_PKEY_fromdata_init(rsa_pctx) <= 0 ||
            EVP_PKEY_fromdata(rsa_pctx, &pkey, EVP_PKEY_PUBLIC_KEY,
                              rsa_params) <= 0) {
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: failed to construct RSA public key "
                             "from LDAP value");
            pkey = NULL;
        }
        EVP_PKEY_CTX_free(rsa_pctx);
        OSSL_PARAM_free(rsa_params);
    }

out:
    free(blob);
    free(line);
    return pkey;
}


/* ------------------------------------------------------------------ *
 * Verify the binding signature.
 *
 * binding_digest = SHA256(serviceKey_SPKI_DER || binding_label ||
 *                         principal_utf8        || uint32be(kvno))
 *
 * For Ed25519 the service signs the raw digest bytes (no inner hash).
 * For ECDSA P-256 the service signs the digest bytes and the verifier
 * hashes them again via EVP_sha256(); both sides must use the same convention.
 * ------------------------------------------------------------------ */
static krb5_error_code
verify_binding_signature(EVP_PKEY *derived_key,
                         X509_PUBKEY *spki,
                         const char *principal_str,
                         uint32_t kvno,
                         const char *binding_label,
                         const ASN1_OCTET_STRING *binding)
{
    unsigned char    digest[SHA256_DIGEST_LENGTH];
    unsigned int     digest_len = SHA256_DIGEST_LENGTH;
    uint32_t         kvno_be = htonl(kvno);
    unsigned char   *spki_der = NULL;
    int              spki_len;
    EVP_MD_CTX      *sha_ctx = NULL;
    EVP_MD_CTX      *mdctx = NULL;
    krb5_error_code  ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;

    /* Re-encode the SPKI to get canonical DER for the digest */
    spki_len = i2d_X509_PUBKEY(spki, &spki_der);
    if (spki_len <= 0)
        return KRB5KDC_ERR_CERTIFICATE_MISMATCH;

    sha_ctx = EVP_MD_CTX_new();
    if (!sha_ctx) {
        ret = ENOMEM;
        goto done;
    }
    if (EVP_DigestInit_ex(sha_ctx, EVP_sha256(), NULL) <= 0 ||
        EVP_DigestUpdate(sha_ctx, spki_der, (size_t)spki_len) <= 0 ||
        EVP_DigestUpdate(sha_ctx, binding_label,
                         strlen(binding_label)) <= 0 ||
        EVP_DigestUpdate(sha_ctx, principal_str,
                         strlen(principal_str)) <= 0 ||
        EVP_DigestUpdate(sha_ctx, &kvno_be, 4) <= 0 ||
        EVP_DigestFinal_ex(sha_ctx, digest, &digest_len) <= 0) {
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
        goto done;
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        ret = ENOMEM;
        goto done;
    }

    {
        int key_id = EVP_PKEY_base_id(derived_key);
        const EVP_MD *md = (key_id == EVP_PKEY_ED25519) ? NULL : EVP_sha256();

        if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, derived_key) <= 0)
            goto done;

        if (EVP_DigestVerify(mdctx,
                              binding->data, (size_t)binding->length,
                              digest, SHA256_DIGEST_LENGTH) == 1)
            ret = 0;
        else
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: binding signature verification failed");
    }

done:
    EVP_MD_CTX_free(sha_ctx);
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(spki_der);
    return ret;
}

/* ------------------------------------------------------------------ *
 * Service type handler table                                          *
 *                                                                     *
 * Each handler bundles the per-service-type constants and callbacks   *
 * so the common verification pipeline can dispatch without knowing    *
 * the service type at compile time.                                   *
 *                                                                     *
 * Generic handler (service_type = NULL):                              *
 *   Matches any service type not explicitly registered.  hkdf_salt    *
 *   and binding_label are derived at runtime as                       *
 *   "<serviceType>-attestation-v1" and                                *
 *   "<serviceType>-attestation-binding-v1".                           *
 *   Uses ipaKrbServiceAttestationKey (DER-encoded SPKI, binary).      *
 * ------------------------------------------------------------------ */

/* Which LDAP key store the handler's pubkey matching uses. */
enum s4u_key_store {
    S4U_KEY_STORE_ATTESTATION, /* ipaKrbServiceAttestationKey → keys[]   */
    S4U_KEY_STORE_SSH,         /* ipasshpubkey            → ssh_pubkeys[] */
};

struct ipa_s4u_cert_handler {
    const char             *service_type;    /* NULL = generic fallback */
    enum s4u_key_store      key_store;
    const char             *hkdf_salt;       /* NULL = derive from service type */
    const char             *binding_label;   /* NULL = derive from service type */
    const char             *context_ext_oid; /* NULL = no context extension */
    const char             *ldap_pubkey_attr;
    s4u_parse_pubkey_fn     parse_pubkey;
    s4u_parse_context_fn    parse_context;   /* NULL = no context extension */
    s4u_free_context_fn     free_context;    /* NULL = no context extension */
    s4u_verify_context_fn   verify_context;
};

/* Forward declarations */
static krb5_error_code ssh_s4u_verify_context(krb5_context,
                                               const struct ipa_s4u_cert_handler *,
                                               X509 *,
                                               krb5_const_principal,
                                               unsigned int,
                                               const void *,
                                               krb5_db_entry **);
static krb5_error_code oidc_s4u_verify_context(krb5_context,
                                                const struct ipa_s4u_cert_handler *,
                                                X509 *,
                                                krb5_const_principal,
                                                unsigned int,
                                                const void *,
                                                krb5_db_entry **);
static krb5_error_code svc_s4u_verify_context(krb5_context,
                                               const struct ipa_s4u_cert_handler *,
                                               X509 *,
                                               krb5_const_principal,
                                               unsigned int,
                                               const void *,
                                               krb5_db_entry **);
static EVP_PKEY *parse_openssh_pubkey(const unsigned char *data, size_t len);
static EVP_PKEY *parse_der_spki_pubkey(const unsigned char *data, size_t len);

/* Context parse/free wrappers: DER-decode the extension and check version. */
static void *
parse_ssh_context(const unsigned char *data, size_t len)
{
    SSH_AUTHN_CONTEXT *ctx = d2i_SSH_AUTHN_CONTEXT(NULL, &data, (long)len);
    if (!ctx || ASN1_INTEGER_get(ctx->version) != 0) {
        SSH_AUTHN_CONTEXT_free(ctx);
        return NULL;
    }
    return ctx;
}

static void *
parse_oidc_context(const unsigned char *data, size_t len)
{
    OIDC_AUTHN_CONTEXT *ctx = d2i_OIDC_AUTHN_CONTEXT(NULL, &data, (long)len);
    if (!ctx || ASN1_INTEGER_get(ctx->version) != 0) {
        OIDC_AUTHN_CONTEXT_free(ctx);
        return NULL;
    }
    return ctx;
}

static const struct ipa_s4u_cert_handler s4u_handlers[] = {
    {
        .service_type     = "ssh",
        .key_store        = S4U_KEY_STORE_SSH,
        .hkdf_salt        = "ssh-attestation-v1",
        .binding_label    = "ssh-attestation-binding-v1",
        .context_ext_oid  = OID_SSH_AUTHN_CONTEXT,
        .ldap_pubkey_attr = "ipaSshPubKey",
        .parse_pubkey     = parse_openssh_pubkey,
        .parse_context    = parse_ssh_context,
        .free_context     = (s4u_free_context_fn)SSH_AUTHN_CONTEXT_free,
        .verify_context   = ssh_s4u_verify_context,
    },
    {
        .service_type     = "oidc",
        .key_store        = S4U_KEY_STORE_ATTESTATION,
        .hkdf_salt        = "oidc-attestation-v1",
        .binding_label    = "oidc-attestation-binding-v1",
        .context_ext_oid  = OID_OIDC_AUTHN_CONTEXT,
        .ldap_pubkey_attr = "ipaKrbServiceAttestationKey",
        .parse_pubkey     = parse_der_spki_pubkey,
        .parse_context    = parse_oidc_context,
        .free_context     = (s4u_free_context_fn)OIDC_AUTHN_CONTEXT_free,
        .verify_context   = oidc_s4u_verify_context,
    },
};

#define N_S4U_HANDLERS (sizeof(s4u_handlers) / sizeof(s4u_handlers[0]))

/* Generic fallback: any service type registered via ipaKrbServiceAttestationKey */
static const struct ipa_s4u_cert_handler generic_s4u_handler = {
    .service_type     = NULL,
    .key_store        = S4U_KEY_STORE_ATTESTATION,
    .hkdf_salt        = NULL,   /* derived as "<stype>-attestation-v1" */
    .binding_label    = NULL,   /* derived as "<stype>-attestation-binding-v1" */
    .context_ext_oid  = NULL,   /* no context extension for generic types */
    .ldap_pubkey_attr = "ipaKrbServiceAttestationKey",
    .parse_pubkey     = parse_der_spki_pubkey,
    .verify_context   = svc_s4u_verify_context,
};

static const struct ipa_s4u_cert_handler *
find_handler(const char *service_type)
{
    for (size_t i = 0; i < N_S4U_HANDLERS; i++) {
        if (strcmp(service_type, s4u_handlers[i].service_type) == 0)
            return &s4u_handlers[i];
    }
    return &generic_s4u_handler;
}

/*
 * s4u_lookup_user_by_cn — resolve the client principal from the cert and
 * look it up in the KDB.  Returns the user entry and its ipadb_e_data;
 * caller owns the entry.
 *
 * flags semantics (kdb.h:1393):
 *   KRB5_KDB_FLAG_REFERRAL_OK set  → AS-REQ context (do_as_req.c:145).
 *     princ->realm is the request realm; data components must be ignored.
 *     ipadb_get_principal() is called with flags including REFERRAL_OK so
 *     it can return a thin out-of-realm referral entry (only ->princ set)
 *     for cross-realm users.  No Default Trust View fallback in this context.
 *   KRB5_KDB_FLAG_CLIENT set, KRB5_KDB_FLAG_REFERRAL_OK clear →
 *     TGS/S4U2Self context (kdc_util.c:1592).  Note: CLIENT is set in
 *     both AS-REQ and TGS calls; REFERRAL_OK distinguishes them.
 *     If princ has data components, verify they match the cert-resolved
 *     principal.  Two-pass lookup:
 *       Pass 1: IPA Kerberos principal via ipadb_get_principal().
 *       Pass 2: if Pass 1 returns KRB5_KDB_NOENTRY, search Default Trust
 *               View (ipaOriginalUid=<username>).  Phase 1 returns
 *               KRB5_KDB_NOENTRY for this case pending Phase 2 design work
 *               (see doc/designs/krb-s4u-x509-assertion.md Open Questions).
 */
static krb5_error_code
s4u_lookup_user_by_cn(krb5_context kcontext,
                       X509 *cert,
                       krb5_const_principal hint_princ,
                       unsigned int flags,
                       krb5_db_entry **entry_out,
                       struct ipadb_e_data **ied_out)
{
    krb5_principal user_princ = NULL;
    krb5_db_entry *user_entry = NULL;
    krb5_error_code ret;

    /* Prefer id-pkinit-san OtherName (RFC 4556 §3.1) */
    ret = cert_get_pkinit_san_principal(kcontext, cert, &user_princ);
    if (ret != 0) {
        /* Fall back to Subject CN */
        X509_NAME *subj = X509_get_subject_name(cert);
        char cn_buf[256] = { 0 };

        if (!subj) {
            krb5_klog_syslog(LOG_ERR, "S4U X.509: cert has no Subject");
            return KRB5KDC_ERR_PREAUTH_FAILED;
        }
        if (X509_NAME_get_text_by_NID(subj, NID_commonName,
                                       cn_buf, sizeof(cn_buf)) <= 0) {
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: no PKINIT SAN and no Subject CN");
            return KRB5KDC_ERR_PREAUTH_FAILED;
        }

        const krb5_data *realm = krb5_princ_realm(kcontext, hint_princ);
        ret = krb5_build_principal(kcontext, &user_princ,
                                    (unsigned int)realm->length, realm->data,
                                    cn_buf, (char *)NULL);
        if (ret) {
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: cannot build principal from CN '%s'",
                             cn_buf);
            return ret;
        }
    }

    /*
     * TGS/S4U2Self context: KRB5_KDB_FLAG_CLIENT set AND
     * KRB5_KDB_FLAG_REFERRAL_OK clear (kdc_util.c:1592).
     * princ may have data components; if so, verify they match the principal
     * resolved from the cert.
     *
     * AS-REQ context: KRB5_KDB_FLAG_REFERRAL_OK set (do_as_req.c:145).
     * KRB5_KDB_FLAG_CLIENT is also set in AS-REQ — it is NOT the
     * discriminator.  Only the realm is meaningful; data components must not
     * be compared.
     */
    if ((flags & KRB5_KDB_FLAG_CLIENT) &&
        !(flags & KRB5_KDB_FLAG_REFERRAL_OK) &&
        hint_princ->length > 0) {
        if (!krb5_principal_compare(kcontext, user_princ, hint_princ)) {
            char *princ_str = NULL;
            krb5_unparse_name(kcontext, user_princ, &princ_str);
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: cert principal '%s' does not match "
                             "S4U2Self hint principal",
                             princ_str ? princ_str : "(unknown)");
            krb5_free_unparsed_name(kcontext, princ_str);
            krb5_free_principal(kcontext, user_princ);
            return KRB5KDC_ERR_CLIENT_NAME_MISMATCH;
        }
    }

    /*
     * Save the fully qualified principal name (user@REALM) before freeing
     * user_princ.  ipaOriginalUid in the Default Trust View uses this form
     * (e.g. "alice@AD.DOMAIN.COM"), so Pass 2 needs the full string.
     */
    char *fq_username = NULL;
    krb5_unparse_name(kcontext, user_princ, &fq_username);

    /* Pass 1: IPA Kerberos principal lookup.
     * Forward flags unchanged so ipadb_get_principal() can return a
     * cross-realm referral entry in the AS-REQ context (REFERRAL_OK set). */
    ret = ipadb_get_principal(kcontext, user_princ, flags, &user_entry);
    krb5_free_principal(kcontext, user_princ);

    if (ret == 0 && user_entry) {
        struct ipadb_e_data *ied = NULL;
        if (ipadb_get_edata(user_entry, &ied) != 0) {
            /*
             * No IPA e_data on the returned entry.  In the AS-REQ context
             * (KRB5_KDB_FLAG_REFERRAL_OK set by the KDC for realm
             * discovery), ipadb_get_principal() may return a thin referral
             * entry for a user in a trusted realm.  Return it without
             * attestation indicators so the KDC can issue the cross-realm
             * referral TGT and the S4U2Self chain can continue.
             */
            if ((flags & KRB5_KDB_FLAG_REFERRAL_OK) &&
                !krb5_realm_compare(kcontext, user_entry->princ, hint_princ)) {
                krb5_klog_syslog(LOG_INFO,
                                 "S4U X.509: '%s' is in a trusted realm; "
                                 "returning referral without attestation",
                                 fq_username ? fq_username : "(unknown)");
                *entry_out = user_entry;
                *ied_out   = NULL;
                krb5_free_unparsed_name(kcontext, fq_username);
                return 0;
            }
            ipadb_free_principal(kcontext, user_entry);
            krb5_free_unparsed_name(kcontext, fq_username);
            return KRB5KDC_ERR_PREAUTH_FAILED;
        }
        *entry_out = user_entry;
        *ied_out   = ied;
        krb5_free_unparsed_name(kcontext, fq_username);
        return 0;
    }

    /*
     * Pass 2: Default Trust View fallback — TGS/S4U2Self context only.
     *
     * Search cn=Default Trust View,cn=views,cn=accounts,<base> for an ID
     * override entry matching (ipaOriginalUid=<user@REALM>).  When found,
     * build a minimal krb5_db_entry for the AD user and populate
     * ipadb_s4u_data with the override's ipaSshPubKey values for SSH
     * publickey strong assertion.  MIT Kerberos will issue a cross-realm
     * referral TGT if the user's realm differs from the KDC realm.
     */
    if (ret == KRB5_KDB_NOENTRY &&
        (flags & KRB5_KDB_FLAG_CLIENT) &&
        !(flags & KRB5_KDB_FLAG_REFERRAL_OK) &&
        fq_username) {
        struct ipadb_context *ipactx = ipadb_get_context(kcontext);
        if (ipactx) {
            char *dtv_dn = NULL;
            char *filter = NULL;

            if (asprintf(&dtv_dn,
                         "cn=Default Trust View,cn=views,cn=accounts,%s",
                         ipactx->base) < 0)
                dtv_dn = NULL;

            if (dtv_dn &&
                asprintf(&filter, "(ipaOriginalUid=%s)", fq_username) < 0)
                filter = NULL;

            if (dtv_dn && filter) {
                char *dtv_attrs[] = {
                    "ipaSshPubKey", "userCertificate;binary", NULL
                };
                LDAPMessage *result = NULL;
                krb5_error_code sret = ipadb_simple_search(
                    ipactx, dtv_dn, LDAP_SCOPE_ONELEVEL,
                    filter, dtv_attrs, &result);
                if (sret == 0) {
                    LDAPMessage *lent = ldap_first_entry(ipactx->lcontext,
                                                         result);
                    if (lent) {
                        krb5_klog_syslog(LOG_INFO,
                                         "S4U X.509: user '%s' found in "
                                         "Default Trust View; building "
                                         "entry for attestation",
                                         fq_username);

                        krb5_principal      dtv_princ = NULL;
                        krb5_db_entry      *dtv_entry = NULL;
                        struct ipadb_e_data *dtv_ied  = NULL;

                        do {
                            if (krb5_parse_name(kcontext, fq_username,
                                                &dtv_princ) != 0) {
                                krb5_klog_syslog(LOG_WARNING,
                                                 "S4U X.509: cannot parse "
                                                 "principal '%s'",
                                                 fq_username);
                                break;
                            }

                            dtv_entry = calloc(1, sizeof(*dtv_entry));
                            if (!dtv_entry)
                                break;
                            dtv_entry->princ = dtv_princ;
                            dtv_princ = NULL; /* owned by dtv_entry */

                            dtv_ied = calloc(1, sizeof(*dtv_ied));
                            if (!dtv_ied)
                                break;
                            dtv_ied->magic = IPA_E_DATA_MAGIC;

                            dtv_ied->s4u = calloc(1, sizeof(*dtv_ied->s4u));
                            if (!dtv_ied->s4u)
                                break;

                            /*
                             * Populate ssh_pubkeys[] from the DTV override's
                             * ipaSshPubKey attribute for SSH publickey strong
                             * assertion.  Replicates the pattern used in
                             * ipadb_parse_s4u_data() for regular principals.
                             */
                            struct berval **ssh_vals = ldap_get_values_len(
                                ipactx->lcontext, lent, "ipaSshPubKey");
                            if (ssh_vals && ssh_vals[0]) {
                                int n;
                                for (n = 0; ssh_vals[n]; n++) ;
                                krb5_data *arr = calloc(n, sizeof(krb5_data));
                                if (arr) {
                                    int j, k;
                                    for (j = 0; j < n; j++) {
                                        arr[j].magic  = KV5M_DATA;
                                        arr[j].length =
                                            (unsigned int)ssh_vals[j]->bv_len;
                                        arr[j].data =
                                            malloc(ssh_vals[j]->bv_len);
                                        if (!arr[j].data) {
                                            for (k = 0; k < j; k++)
                                                free(arr[k].data);
                                            free(arr);
                                            arr = NULL;
                                            break;
                                        }
                                        memcpy(arr[j].data,
                                               ssh_vals[j]->bv_val,
                                               ssh_vals[j]->bv_len);
                                    }
                                    if (arr) {
                                        dtv_ied->s4u->ssh_pubkeys = arr;
                                        dtv_ied->s4u->n_ssh_pubkeys = n;
                                    }
                                }
                            }
                            ldap_value_free_len(ssh_vals);

                            /* Attach e_data; ownership transferred. */
                            dtv_entry->e_data = (krb5_octet *)dtv_ied;
                            dtv_ied = NULL;

                            *entry_out = dtv_entry;
                            *ied_out   = (struct ipadb_e_data *)
                                         dtv_entry->e_data;

                            ldap_msgfree(result);
                            free(dtv_dn);
                            free(filter);
                            krb5_free_unparsed_name(kcontext, fq_username);
                            return 0;
                        } while (0);

                        /* Entry construction failed; clean up.
                         * dtv_princ may be non-NULL only when dtv_entry
                         * calloc failed (it is set to NULL after being
                         * stored in dtv_entry->princ).  dtv_ied, when
                         * non-NULL, was never stored in dtv_entry->e_data
                         * so ipadb_free_principal() will not touch it. */
                        krb5_free_principal(kcontext, dtv_princ);
                        if (dtv_ied) {
                            if (dtv_ied->s4u) free(dtv_ied->s4u);
                            free(dtv_ied);
                        }
                        if (dtv_entry)
                            ipadb_free_principal(kcontext, dtv_entry);
                    }
                    ldap_msgfree(result);
                }
            }
            free(dtv_dn);
            free(filter);
        }
    }

    krb5_klog_syslog(LOG_ERR, "S4U X.509: user '%s' not found in KDB",
                     fq_username ? fq_username : "(unknown)");
    krb5_free_unparsed_name(kcontext, fq_username);
    return ret ? ret : KRB5_KDB_NOENTRY;
}

/* ------------------------------------------------------------------ *
 * SSH service context verification callback.                          *
 *                                                                     *
 * Resolves the client principal via s4u_lookup_user_by_cn() (PKINIT  *
 * SAN preferred, Subject CN fallback) and populates the user entry's  *
 * e_data with SSH attestation fields.  flags are forwarded verbatim   *
 * to s4u_lookup_user_by_cn(); see that function for flag semantics.  *
 * ------------------------------------------------------------------ */
static krb5_error_code
ssh_s4u_verify_context(krb5_context kcontext,
                        const struct ipa_s4u_cert_handler *h,
                        X509 *cert,
                        krb5_const_principal hint_princ,
                        unsigned int flags,
                        const void *svc_context,
                        krb5_db_entry **entry_out)
{
    const SSH_AUTHN_CONTEXT *authn = (const SSH_AUTHN_CONTEXT *)svc_context;
    krb5_db_entry *user_entry = NULL;
    struct ipadb_e_data *ied = NULL;
    krb5_error_code ret;

    ret = s4u_lookup_user_by_cn(kcontext, cert, hint_princ, flags,
                                 &user_entry, &ied);
    if (ret)
        return ret;

    /* Cross-realm referral: no IPA e_data, no indicators to set. */
    if (!ied) {
        *entry_out = user_entry;
        return 0;
    }

    if (!ied->s4u) {
        ipadb_free_principal(kcontext, user_entry);
        return ENOMEM;
    }

    ied->s4u->service_type = strdup(h->service_type);
    if (!ied->s4u->service_type)
        krb5_klog_syslog(LOG_WARNING,
                         "S4U X.509: OOM copying service type");

    if (authn) {
        if (authn->auth_method) {
            char *m = strndup((char *)authn->auth_method->data,
                              (size_t)authn->auth_method->length);
            if (m) {
                char **am = calloc(2, sizeof(char *));
                if (am) {
                    am[0] = m;
                    ied->s4u->auth_methods = am;
                } else {
                    free(m);
                    krb5_klog_syslog(LOG_WARNING,
                                     "S4U X.509: OOM allocating auth_methods; "
                                     "audit record will show 'unknown'");
                }
            } else {
                krb5_klog_syslog(LOG_WARNING,
                                 "S4U X.509: OOM copying auth_method; "
                                 "audit record will show 'unknown'");
            }
        }
        if (authn->key_fingerprint) {
            ied->s4u->ssh_key_fingerprint =
                strndup((char *)authn->key_fingerprint->data,
                        (size_t)authn->key_fingerprint->length);
            if (!ied->s4u->ssh_key_fingerprint)
                krb5_klog_syslog(LOG_WARNING,
                                 "S4U X.509: OOM copying key_fingerprint");
        }
        if (authn->client_address) {
            ied->s4u->ssh_client_address =
                strndup((char *)authn->client_address->data,
                        (size_t)authn->client_address->length);
            if (!ied->s4u->ssh_client_address)
                krb5_klog_syslog(LOG_WARNING,
                                 "S4U X.509: OOM copying client_address");
        }
    }

    /*
     * For publickey auth the cert's SubjectPublicKeyInfo is the user's SSH
     * public key (not an ephemeral key).  Emit the strong attestation
     * indicator only when that key is registered in the user's LDAP entry
     * (ipasshpubkey).  For all other auth methods (password, mfa, …) the
     * cert's subject identity is sufficient — set attested unconditionally.
     */
    if (ied->s4u->auth_methods && ied->s4u->auth_methods[0] &&
        strcmp(ied->s4u->auth_methods[0], "publickey") == 0) {
        EVP_PKEY *subject_key = X509_get_pubkey(cert);
        bool key_matched = false;

        if (subject_key) {
            for (int i = 0; i < ied->s4u->n_ssh_pubkeys && !key_matched; i++) {
                EVP_PKEY *ldap_key = parse_openssh_pubkey(
                    (const unsigned char *)ied->s4u->ssh_pubkeys[i].data,
                    (size_t)ied->s4u->ssh_pubkeys[i].length);
                if (!ldap_key)
                    continue;
                if (EVP_PKEY_eq(subject_key, ldap_key) == 1)
                    key_matched = true;
                EVP_PKEY_free(ldap_key);
            }
            EVP_PKEY_free(subject_key);
        }

        if (key_matched) {
            ied->s4u->attested = true;
        } else {
            krb5_klog_syslog(LOG_INFO,
                             "S4U X.509: SSH public key not registered for "
                             "user; no attestation indicator emitted");
        }
    } else {
        ied->s4u->attested = true;
    }

    *entry_out = user_entry;
    return 0;
}

/* ------------------------------------------------------------------ *
 * OIDC service context verification callback.                         *
 *                                                                     *
 * Extracts amrValues from the decoded OidcAuthnContext and produces   *
 * one auth indicator per RFC 8176 §2 AMR value (e.g. "pwd", "otp",  *
 * "mfa").  Falls back to a single "sso" entry when amrValues is      *
 * absent or the context extension was not present.                    *
 * ------------------------------------------------------------------ */

static krb5_error_code
oidc_s4u_verify_context(krb5_context kcontext,
                         const struct ipa_s4u_cert_handler *h,
                         X509 *cert,
                         krb5_const_principal hint_princ,
                         unsigned int flags,
                         const void *svc_context,
                         krb5_db_entry **entry_out)
{
    const OIDC_AUTHN_CONTEXT *authn = (const OIDC_AUTHN_CONTEXT *)svc_context;
    krb5_db_entry *user_entry = NULL;
    struct ipadb_e_data *ied = NULL;
    krb5_error_code ret;

    ret = s4u_lookup_user_by_cn(kcontext, cert, hint_princ, flags,
                                 &user_entry, &ied);
    if (ret)
        return ret;

    /* Cross-realm referral: no IPA e_data, no indicators to set. */
    if (!ied) {
        *entry_out = user_entry;
        return 0;
    }

    if (!ied->s4u) {
        ipadb_free_principal(kcontext, user_entry);
        return ENOMEM;
    }

    ied->s4u->service_type = strdup(h->service_type);
    if (!ied->s4u->service_type)
        krb5_klog_syslog(LOG_WARNING,
                         "S4U X.509: OOM copying service type");

    /*
     * Build auth_methods from every amrValues entry (RFC 8176 §2):
     * one auth indicator per AMR value, e.g. "pwd", "otp", "mfa".
     * Fall back to a single "sso" entry when amrValues is absent or
     * the OIDC context extension was not present.
     */
    if (authn && authn->amr_values &&
        sk_ASN1_TYPE_num(authn->amr_values) > 0) {
        int n = sk_ASN1_TYPE_num(authn->amr_values);
        char **am = calloc((size_t)(n + 1), sizeof(char *));
        if (am) {
            int j = 0;
            for (int i = 0; i < n; i++) {
                ASN1_TYPE *t = sk_ASN1_TYPE_value(authn->amr_values, i);
                if (!t || t->type != V_ASN1_UTF8STRING)
                    continue;
                const ASN1_UTF8STRING *s = t->value.utf8string;
                char *v = strndup((char *)s->data, (size_t)s->length);
                if (v)
                    am[j++] = v;
            }
            am[j] = NULL;
            if (j > 0)
                ied->s4u->auth_methods = am;
            else
                free(am);
        }
    }
    if (!ied->s4u->auth_methods) {
        /* amrValues absent or empty — fall back to "sso" */
        char **am = calloc(2, sizeof(char *));
        if (am) {
            am[0] = strdup("sso");
            if (am[0])
                ied->s4u->auth_methods = am;
            else
                free(am);
        }
        if (!ied->s4u->auth_methods)
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: OOM setting auth_methods; "
                             "audit record will show 'unknown'");
    }

    ied->s4u->attested = true;

    *entry_out = user_entry;
    return 0;
}

/* ------------------------------------------------------------------ *
 * Generic service context verification callback.                      *
 *                                                                     *
 * Used for any service type registered via ipaKrbServiceAttestationKey*
 * (PAM, and future service types).  No service-specific              *
 * context extension is parsed; auth detail is "unknown" until the     *
 * per-type context extensions are defined.                            *
 * ------------------------------------------------------------------ */
static krb5_error_code
svc_s4u_verify_context(krb5_context kcontext,
                        const struct ipa_s4u_cert_handler *h,
                        X509 *cert,
                        krb5_const_principal hint_princ,
                        unsigned int flags,
                        const void *svc_context,
                        krb5_db_entry **entry_out)
{
    (void)h;           /* service type stored via stype in pipeline */
    (void)svc_context; /* no context extension for generic types */

    krb5_db_entry *user_entry = NULL;
    struct ipadb_e_data *ied = NULL;
    krb5_error_code ret;

    ret = s4u_lookup_user_by_cn(kcontext, cert, hint_princ, flags,
                                 &user_entry, &ied);
    if (ret)
        return ret;

    /* Cross-realm referral: no IPA e_data, no indicators to set. */
    if (!ied) {
        *entry_out = user_entry;
        return 0;
    }

    if (!ied->s4u) {
        ipadb_free_principal(kcontext, user_entry);
        return ENOMEM;
    }

    ied->s4u->attested = true;
    /* s4u->service_type and s4u->auth_methods are set by the pipeline after
     * this callback returns, because the service type string lives in
     * transient ASN.1 memory that is freed in the pipeline's done: block. */

    *entry_out = user_entry;
    return 0;
}

/* ------------------------------------------------------------------ *
 * Main attestation pipeline — separated from the vtable entry point  *
 * so that unit tests can call it with an explicit fips_mode without   *
 * relying on the system's FIPS state.                                 *
 * ------------------------------------------------------------------ */
static krb5_error_code
ipadb_get_s4u_x509_principal_impl(krb5_context kcontext,
                                   const krb5_data *client_cert,
                                   krb5_const_principal princ,
                                   unsigned int flags,
                                   krb5_db_entry **entry_out,
                                   int fips_mode)
{
    krb5_error_code                    ret = KRB5KDC_ERR_PREAUTH_FAILED;
    struct ipadb_context              *ipactx = NULL;
    X509                              *cert = NULL;
    KERBEROS_SERVICE_ISSUER_BINDING   *ib = NULL;
    void                              *svc_ctx = NULL; /* opaque parsed context */
    const struct ipa_s4u_cert_handler *h = NULL;
    krb5_db_entry                     *host_entry = NULL;
    krb5_principal                     host_princ = NULL;
    EVP_PKEY                          *derived_key = NULL;
    const char                        *stype = NULL; /* service type, owned by ib */

    *entry_out = NULL;

    /*
     * Two calling contexts (kdb.h:1393):
     *
     * AS-REQ (KRB5_KDB_FLAG_REFERRAL_OK set, do_as_req.c:145):
     *   The cert arrived in an AS-REQ.  princ->realm is the request realm;
     *   data components must be ignored.  We may return a thin out-of-realm
     *   client referral (krb5_db_entry with only ->princ set, other fields
     *   NULL) so the KDC can steer the client to the correct realm.
     *
     * TGS/S4U2Self (KRB5_KDB_FLAG_CLIENT set, KRB5_KDB_FLAG_REFERRAL_OK
     * clear, kdc_util.c:1592): the cert arrived in a TGS-REQ via
     * PA-FOR-X509-USER.  No referral must be returned.  If princ has data
     * components, verify that the principal resolved from the cert matches.
     * Note: CLIENT is also set in AS-REQ; REFERRAL_OK being absent is the
     * discriminator for the TGS path.
     *
     * These flags do NOT indicate PKINIT.  get_s4u_x509_principal is never
     * called for PKINIT AS-REQ pre-authentication (that path goes through
     * get_principal() and the pkinit kdcpreauth plugin exclusively).
     */

    ipactx = ipadb_get_context(kcontext);
    if (!ipactx || ipactx->magic != IPA_CONTEXT_MAGIC)
        return KRB5_KDB_DBNOTINITED;

    /*
     * AS-REQ realm identification fast path (KRB5_KDB_FLAG_REFERRAL_OK set).
     *
     * The KDC is performing realm discovery: it has no TGT for the client yet
     * and calls get_s4u_x509_principal to identify the user's realm from the
     * cert so that it can issue a referral or NEEDED_PREAUTH response.
     * No signature verification or keytab access is required here — the
     * security check happens on the subsequent TGS-REQ.
     *
     * Just parse the cert to extract the user principal and pass it to
     * ipadb_get_principal() (with REFERRAL_OK set) so it can return a thin
     * cross-realm referral entry if needed.
     */
    if (flags & KRB5_KDB_FLAG_REFERRAL_OK) {
        const unsigned char *as_cert_p =
            (const unsigned char *)client_cert->data;
        X509 *as_cert = d2i_X509(NULL, &as_cert_p, (long)client_cert->length);
        if (!as_cert)
            return KRB5KDC_ERR_PREAUTH_FAILED;
        struct ipadb_e_data *ied_unused = NULL;
        krb5_error_code as_ret = s4u_lookup_user_by_cn(kcontext, as_cert,
                                                        princ, flags,
                                                        entry_out,
                                                        &ied_unused);
        X509_free(as_cert);
        return as_ret;
    }

    /* Parse DER attestation cert */
    const unsigned char *cert_p = (const unsigned char *)client_cert->data;
    cert = d2i_X509(NULL, &cert_p, (long)client_cert->length);
    if (!cert) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: failed to parse attestation cert");
        return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Reject expired or not-yet-valid certificates */
    if (X509_cmp_current_time(X509_get_notBefore(cert)) >= 0 ||
        X509_cmp_current_time(X509_get_notAfter(cert)) <= 0) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: attestation cert is outside validity period");
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /* Locate and parse id-ce-kerberosServiceIssuerBinding */
    {
        const unsigned char *ext_data = NULL;
        size_t ext_len = 0;
        if (cert_get_extension(cert, OID_KERBEROS_SERVICE_ISSUER_BINDING,
                               &ext_data, &ext_len) != 0) {
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: cert missing "
                             "kerberosServiceIssuerBinding extension");
            ret = KRB5KDC_ERR_PREAUTH_FAILED;
            goto done;
        }
        ib = d2i_KERBEROS_SERVICE_ISSUER_BINDING(NULL, &ext_data, (long)ext_len);
        if (!ib || ASN1_INTEGER_get(ib->version) != 0) {
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: malformed kerberosServiceIssuerBinding");
            ret = KRB5KDC_ERR_PREAUTH_FAILED;
            goto done;
        }
    }

    /* Select the per-service handler from the serviceType field */
    {
        stype = (const char *)ASN1_STRING_get0_data(ib->service_type);
        /* Reject embedded NUL bytes to prevent type confusion */
        if (!stype ||
            ASN1_STRING_length(ib->service_type) != (int)strlen(stype)) {
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: serviceType contains embedded NUL");
            ret = KRB5KDC_ERR_PREAUTH_FAILED;
            goto done;
        }
        h = find_handler(stype);
        /* find_handler() always returns at least the generic fallback */
    }

    /* Extract fields needed for the rest of the pipeline */
    long sig_nid = OBJ_obj2nid(ib->sig_alg->algorithm);
    long enctype = ASN1_INTEGER_get(ib->enctype);
    long kvno    = ASN1_INTEGER_get(ib->kvno);

    /* ASN1_INTEGER_get() returns -1 on overflow; also reject implausible values */
    if (enctype <= 0 || enctype > 65535) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: enctype %ld out of valid range", enctype);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }
    if (kvno <= 0 || (unsigned long)kvno > UINT32_MAX) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: kvno %ld out of valid range", kvno);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /* principal data is null-terminated by OpenSSL; safe to use as C string */
    const char *principal_str =
        (const char *)ASN1_STRING_get0_data(ib->principal);
    /* Reject embedded NUL bytes: they cause principal name confusion because
     * krb5_parse_name() and strlen() both stop at the first NUL, allowing a
     * cert with binding over "host/foo@REALM\0evil" to authenticate as
     * "host/foo@REALM". */
    if (ASN1_STRING_length(ib->principal) != (int)strlen(principal_str)) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: principal string contains embedded NUL");
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }
    /* cert_service_key is a borrowed reference owned by ib */
    EVP_PKEY *cert_service_key = X509_PUBKEY_get0(ib->service_key);
    if (!cert_service_key) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: failed to decode service public key");
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /* FIPS mode: reject Ed25519-signed certs */
    if (fips_mode && sig_nid == NID_ED25519) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: Ed25519 cert rejected in FIPS mode");
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /* Reject weak enctypes as HKDF input */
    if (enctype < 17) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: enctype %ld too weak for key derivation",
                         enctype);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }
    if (fips_mode && (enctype == 17 || enctype == 19)) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: AES-128 enctype %ld rejected in FIPS mode",
                         enctype);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /* Look up the host principal named in the issuer binding */
    ret = krb5_parse_name(kcontext, principal_str, &host_princ);
    if (ret) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: cannot parse host principal '%s'",
                         principal_str);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    ret = ipadb_get_principal(kcontext, host_princ, 0, &host_entry);
    if (ret || !host_entry) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: host principal '%s' not found",
                         principal_str);
        ret = KRB5_KDB_NOENTRY;
        goto done;
    }

    /* Host e_data: pre-fetched attestation keys, types, and ipasshpubkey values */
    struct ipadb_e_data *hed_s4u = NULL;
    ipadb_get_edata(host_entry, &hed_s4u); /* error handled per-path below */

    /* Find and decrypt the keytab key matching (enctype, kvno) */
    {
        krb5_boolean found = FALSE;

        for (int i = 0; i < host_entry->n_key_data; i++) {
            krb5_key_data *kd = &host_entry->key_data[i];
            if ((krb5_enctype)kd->key_data_type[0] != enctype)
                continue;
            if ((krb5_kvno)kd->key_data_kvno != (krb5_kvno)kvno)
                continue;

            krb5_keyblock keyblock = { 0 };
            krb5_error_code kerr = krb5_dbe_decrypt_key_data(kcontext,
                                                              NULL, kd,
                                                              &keyblock, NULL);
            if (kerr) {
                krb5_klog_syslog(LOG_ERR,
                                 "S4U X.509: key decrypt failed "
                                 "(enctype=%ld kvno=%ld): %d",
                                 enctype, kvno, kerr);
                ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
                goto done;
            }

            /* host/component[0]/hostname[1]@REALM */
            const char *hostname = NULL;
            const char *realm_str = NULL;
            if (krb5_princ_size(kcontext, host_princ) >= 2)
                hostname = krb5_princ_component(kcontext,
                                                host_princ, 1)->data;
            realm_str = krb5_princ_realm(kcontext, host_princ)->data;

            if (!hostname || !realm_str) {
                krb5_free_keyblock_contents(kcontext, &keyblock);
                ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
                goto done;
            }

            /* For the generic handler, derive salt from service type */
            char hkdf_salt_buf[128];
            const char *effective_salt = h->hkdf_salt;
            if (!effective_salt) {
                snprintf(hkdf_salt_buf, sizeof(hkdf_salt_buf),
                         "%s-attestation-v1", stype);
                effective_salt = hkdf_salt_buf;
            }

            ret = derive_attestation_key(keyblock.contents,
                                          (size_t)keyblock.length,
                                          effective_salt,
                                          hostname, realm_str,
                                          (uint32_t)kvno,
                                          fips_mode, &derived_key);
            krb5_free_keyblock_contents(kcontext, &keyblock);

            if (ret) {
                krb5_klog_syslog(LOG_ERR,
                                 "S4U X.509: key derivation failed: %d", ret);
                goto done;
            }
            found = TRUE;
            break;
        }

        if (!found) {
            krb5_klog_syslog(LOG_ERR,
                             "S4U X.509: no key for '%s' "
                             "enctype=%ld kvno=%ld",
                             principal_str, enctype, kvno);
            ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
            goto done;
        }
    }

    /* Verify outer cert signature with derived public key */
    if (X509_verify(cert, derived_key) != 1) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: cert signature invalid for host '%s'",
                         principal_str);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }

    /*
     * Verify that the cert's serviceKey is registered in the host's LDAP entry.
     *
     * Both the generic and SSH handlers use keys pre-fetched by
     * ipadb_get_principal() into hed_s4u->s4u at parse time — no second
     * LDAP round-trip is needed for either path.
     *
     * Generic handler: cert service key (DER SPKI) vs s4u->keys[]
     *                  (ipaKrbServiceAttestationKey, binary)
     * SSH handler:     cert service key (OpenSSH) vs s4u->ssh_pubkeys[]
     *                  (ipasshpubkey, text)
     */
    if (!hed_s4u || !hed_s4u->s4u) {
        krb5_klog_syslog(LOG_WARNING,
                         "S4U X.509: no s4u data for host '%s'",
                         principal_str);
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        goto done;
    }
    if (h->key_store == S4U_KEY_STORE_ATTESTATION) {
        /* DER SPKI path: generic fallback and dedicated handlers (OIDC, …) */
        if (hed_s4u->s4u->n_keys == 0) {
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: no attestation keys registered "
                             "for '%s'", principal_str);
            ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
            goto done;
        }
        /* Generic fallback only: verify the service type is whitelisted.
         * Dedicated handlers (OIDC etc.) have a fixed service_type baked
         * into the handler, so no allowlist check is needed for them. */
        if (h == &generic_s4u_handler) {
            bool type_ok = false;
            char **types = hed_s4u->s4u->types;
            for (int i = 0; types && types[i]; i++) {
                if (strcmp(types[i], stype) == 0) {
                    type_ok = true;
                    break;
                }
            }
            if (!type_ok) {
                krb5_klog_syslog(LOG_WARNING,
                                 "S4U X.509: service type '%s' not "
                                 "registered for '%s'",
                                 stype, principal_str);
                ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
                goto done;
            }
        }
        /* Match the cert's service key against registered DER SPKI values */
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        for (int i = 0; i < hed_s4u->s4u->n_keys; i++) {
            EVP_PKEY *ldap_key = h->parse_pubkey(
                (const unsigned char *)hed_s4u->s4u->keys[i].data,
                (size_t)hed_s4u->s4u->keys[i].length);
            if (!ldap_key)
                continue;
            if (EVP_PKEY_eq(cert_service_key, ldap_key) == 1) {
                EVP_PKEY_free(ldap_key);
                ret = 0;
                break;
            }
            EVP_PKEY_free(ldap_key);
        }
    } else {
        /* SSH: match cert service key against ipasshpubkey values (OpenSSH) */
        if (hed_s4u->s4u->n_ssh_pubkeys == 0) {
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: no SSH public keys registered "
                             "for '%s'", principal_str);
            ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
            goto done;
        }
        ret = KRB5KDC_ERR_CERTIFICATE_MISMATCH;
        for (int i = 0; i < hed_s4u->s4u->n_ssh_pubkeys; i++) {
            EVP_PKEY *ldap_key = h->parse_pubkey(
                (const unsigned char *)hed_s4u->s4u->ssh_pubkeys[i].data,
                (size_t)hed_s4u->s4u->ssh_pubkeys[i].length);
            if (!ldap_key)
                continue;
            if (EVP_PKEY_eq(cert_service_key, ldap_key) == 1) {
                EVP_PKEY_free(ldap_key);
                ret = 0;
                break;
            }
            EVP_PKEY_free(ldap_key);
        }
    }
    if (ret) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: service key not registered for '%s'",
                         principal_str);
        goto done;
    }

    /* Verify the binding signature */
    {
        char binding_label_buf[128];
        const char *effective_label = h->binding_label;
        if (!effective_label) {
            snprintf(binding_label_buf, sizeof(binding_label_buf),
                     "%s-attestation-binding-v1", stype);
            effective_label = binding_label_buf;
        }
        ret = verify_binding_signature(derived_key,
                                        ib->service_key,
                                        principal_str,
                                        (uint32_t)kvno,
                                        effective_label,
                                        ib->binding);
    }
    if (ret) {
        krb5_klog_syslog(LOG_ERR,
                         "S4U X.509: binding signature invalid for '%s'",
                         principal_str);
        goto done;
    }

    /* Parse service context extension (advisory; failures do not abort).
     * Only attempted when the handler registers a context OID and parser. */
    if (h->context_ext_oid && h->parse_context) {
        const unsigned char *ext_data = NULL;
        size_t ext_len = 0;
        if (cert_get_extension(cert, h->context_ext_oid,
                               &ext_data, &ext_len) == 0) {
            svc_ctx = h->parse_context(ext_data, ext_len);
            if (!svc_ctx)
                krb5_klog_syslog(LOG_WARNING,
                                 "S4U X.509: malformed service context "
                                 "extension; proceeding without auth details");
        } else {
            krb5_klog_syslog(LOG_WARNING,
                             "S4U X.509: cert missing service context "
                             "extension; proceeding without auth details");
        }
    }

    /* Resolve user principal and populate e_data via service handler */
    ret = h->verify_context(kcontext, h, cert, princ, flags, svc_ctx, entry_out);
    if (ret == 0) {
        /*
         * For the generic handler, set s4u->service_type and s4u->auth_methods
         * here where stype is still valid (it's owned by ib, freed below).
         * SSH and OIDC handlers set these fields themselves from the parsed
         * context; the generic handler has no context to draw from.
         */
        struct ipadb_e_data *ied = NULL;
        if (h == &generic_s4u_handler && *entry_out &&
            ipadb_get_edata(*entry_out, &ied) == 0 && ied->s4u) {
            if (!ied->s4u->service_type)
                ied->s4u->service_type = strdup(stype);
            if (!ied->s4u->auth_methods) {
                char **am = calloc(2, sizeof(char *));
                if (am) {
                    am[0] = strdup("unknown");
                    if (am[0])
                        ied->s4u->auth_methods = am;
                    else
                        free(am);
                }
            }
        }

        const char *log_method = "unknown";
        if (*entry_out &&
            (ied || ipadb_get_edata(*entry_out, &ied) == 0) && ied->s4u)
            log_method = (ied->s4u->auth_methods && ied->s4u->auth_methods[0])
                         ? ied->s4u->auth_methods[0] : "unknown";
        krb5_klog_syslog(LOG_INFO,
                         "S4U X.509: attested S4U2Self type='%s' "
                         "method='%s' host='%s'",
                         stype, log_method, principal_str);
    }

done:
    KERBEROS_SERVICE_ISSUER_BINDING_free(ib);
    if (svc_ctx && h && h->free_context)
        h->free_context(svc_ctx);
    X509_free(cert);
    EVP_PKEY_free(derived_key);
    krb5_free_principal(kcontext, host_princ);
    if (host_entry)
        ipadb_free_principal(kcontext, host_entry);
    return ret;
}

/* ------------------------------------------------------------------ *
 * Vtable entry point — detects FIPS mode and delegates to the impl.  *
 * ------------------------------------------------------------------ */
krb5_error_code
ipadb_get_s4u_x509_principal(krb5_context kcontext,
                              const krb5_data *client_cert,
                              krb5_const_principal princ,
                              unsigned int flags,
                              krb5_db_entry **entry_out)
{
    return ipadb_get_s4u_x509_principal_impl(
        kcontext, client_cert, princ, flags, entry_out,
        EVP_default_properties_is_fips_enabled(NULL));
}

#endif /* BUILD_IPA_S4U_X509 */
