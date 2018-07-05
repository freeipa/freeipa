from cffi import FFI
import ctypes.util

from ipalib import errors

_ffi = FFI()

_ffi.cdef('''
typedef ... CONF;
typedef ... CONF_METHOD;
typedef ... BIO;
typedef ... ipa_STACK_OF_CONF_VALUE;

/* openssl/conf.h */
typedef struct {
    char *section;
    char *name;
    char *value;
} CONF_VALUE;

CONF *NCONF_new(CONF_METHOD *meth);
void NCONF_free(CONF *conf);
int NCONF_load_bio(CONF *conf, BIO *bp, long *eline);
ipa_STACK_OF_CONF_VALUE *NCONF_get_section(const CONF *conf,
                                        const char *section);
char *NCONF_get_string(const CONF *conf, const char *group, const char *name);

/* openssl/safestack.h */
// int sk_CONF_VALUE_num(ipa_STACK_OF_CONF_VALUE *);
// CONF_VALUE *sk_CONF_VALUE_value(ipa_STACK_OF_CONF_VALUE *, int);

/* openssl/stack.h */
typedef ... _STACK;

int OPENSSL_sk_num(const _STACK *);
void *OPENSSL_sk_value(const _STACK *, int);

int sk_num(const _STACK *);
void *sk_value(const _STACK *, int);

/* openssl/bio.h */
BIO *BIO_new_mem_buf(const void *buf, int len);
int BIO_free(BIO *a);

/* openssl/asn1.h */
typedef struct ASN1_ENCODING_st {
    unsigned char *enc;         /* DER encoding */
    long len;                   /* Length of encoding */
    int modified;               /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;

/* openssl/evp.h */
typedef ... EVP_PKEY;

void EVP_PKEY_free(EVP_PKEY *pkey);

/* openssl/x509.h */
typedef ... ASN1_INTEGER;
typedef ... ASN1_BIT_STRING;
typedef ... ASN1_OBJECT;
typedef ... X509;
typedef ... X509_ALGOR;
typedef ... X509_CRL;
typedef ... X509_NAME;
typedef ... X509_PUBKEY;
typedef ... ipa_STACK_OF_X509_ATTRIBUTE;

typedef struct X509_req_info_st {
    ASN1_ENCODING enc;
    ASN1_INTEGER *version;
    X509_NAME *subject;
    X509_PUBKEY *pubkey;
    /*  d=2 hl=2 l=  0 cons: cont: 00 */
    ipa_STACK_OF_X509_ATTRIBUTE *attributes; /* [ 0 ] */
} X509_REQ_INFO;

typedef struct X509_req_st {
    X509_REQ_INFO *req_info;
    X509_ALGOR *sig_alg;
    ASN1_BIT_STRING *signature;
    int references;
} X509_REQ;

X509_REQ *X509_REQ_new(void);
void X509_REQ_free(X509_REQ *);
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type,
                               const unsigned char *bytes, int len, int loc,
                               int set);
int X509_NAME_entry_count(X509_NAME *name);
int i2d_X509_REQ_INFO(X509_REQ_INFO *a, unsigned char **out);

/* openssl/objects.h */
ASN1_OBJECT *OBJ_txt2obj(const char *s, int no_name);

/* openssl/x509v3.h */
typedef ... X509V3_CONF_METHOD;

typedef struct v3_ext_ctx {
    int flags;
    X509 *issuer_cert;
    X509 *subject_cert;
    X509_REQ *subject_req;
    X509_CRL *crl;
    X509V3_CONF_METHOD *db_meth;
    void *db;
} X509V3_CTX;

void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,
                    X509_REQ *req, X509_CRL *crl, int flags);
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, char *section,
                             X509_REQ *req);

/* openssl/x509v3.h */
unsigned long ERR_get_error(void);
char *ERR_error_string(unsigned long e, char *buf);
''')  # noqa: E501

_libcrypto = _ffi.dlopen(ctypes.util.find_library('crypto'))

NULL = _ffi.NULL

# openssl/conf.h
NCONF_new = _libcrypto.NCONF_new
NCONF_free = _libcrypto.NCONF_free
NCONF_load_bio = _libcrypto.NCONF_load_bio
NCONF_get_section = _libcrypto.NCONF_get_section
NCONF_get_string = _libcrypto.NCONF_get_string

# openssl/stack.h
try:
    sk_num = _libcrypto.OPENSSL_sk_num
    sk_value = _libcrypto.OPENSSL_sk_value
except AttributeError:
    sk_num = _libcrypto.sk_num
    sk_value = _libcrypto.sk_value


def sk_CONF_VALUE_num(sk):
    return sk_num(_ffi.cast("_STACK *", sk))


def sk_CONF_VALUE_value(sk, i):
    return _ffi.cast("CONF_VALUE *", sk_value(_ffi.cast("_STACK *", sk), i))


# openssl/bio.h
BIO_new_mem_buf = _libcrypto.BIO_new_mem_buf
BIO_free = _libcrypto.BIO_free

# openssl/x509.h
X509_REQ_new = _libcrypto.X509_REQ_new
X509_REQ_free = _libcrypto.X509_REQ_free
X509_REQ_set_pubkey = _libcrypto.X509_REQ_set_pubkey
d2i_PUBKEY_bio = _libcrypto.d2i_PUBKEY_bio
i2d_X509_REQ_INFO = _libcrypto.i2d_X509_REQ_INFO
X509_NAME_add_entry_by_OBJ = _libcrypto.X509_NAME_add_entry_by_OBJ
X509_NAME_entry_count = _libcrypto.X509_NAME_entry_count


def X509_REQ_get_subject_name(req):
    return req.req_info.subject


# openssl/objects.h
OBJ_txt2obj = _libcrypto.OBJ_txt2obj

# openssl/evp.h
EVP_PKEY_free = _libcrypto.EVP_PKEY_free

# openssl/asn1.h
MBSTRING_UTF8 = 0x1000

# openssl/x509v3.h
X509V3_set_ctx = _libcrypto.X509V3_set_ctx
X509V3_set_nconf = _libcrypto.X509V3_set_nconf
X509V3_EXT_REQ_add_nconf = _libcrypto.X509V3_EXT_REQ_add_nconf

# openssl/err.h
ERR_get_error = _libcrypto.ERR_get_error
ERR_error_string = _libcrypto.ERR_error_string


def _raise_openssl_errors():
    msgs = []

    code = ERR_get_error()
    while code != 0:
        msg = _ffi.string(ERR_error_string(code, NULL))
        try:
            strmsg = msg.decode('utf-8')
        except UnicodeDecodeError:
            strmsg = repr(msg)
        msgs.append(strmsg)
        code = ERR_get_error()

    raise errors.CSRTemplateError(reason='\n'.join(msgs))


def _parse_dn_section(subj, dn_sk):
    for i in range(sk_CONF_VALUE_num(dn_sk)):
        v = sk_CONF_VALUE_value(dn_sk, i)
        rdn_type = _ffi.string(v.name)

        # Skip past any leading X. X: X, etc to allow for multiple instances
        for idx, c in enumerate(rdn_type):
            if c in b':,.':
                if idx+1 < len(rdn_type):
                    rdn_type = rdn_type[idx+1:]
                break
        if rdn_type.startswith(b'+'):
            rdn_type = rdn_type[1:]
            mval = -1
        else:
            mval = 0

        # convert rdn_type to an OID
        #
        # OpenSSL is fussy about the case of the string.  For example,
        # lower-case 'o' (for "organization name") is not recognised.
        # Therefore, try to convert the given string into an OID.  If
        # that fails, convert it upper case and try again.
        #
        oid = OBJ_txt2obj(rdn_type, 0)
        if oid == NULL:
            oid = OBJ_txt2obj(rdn_type.upper(), 0)
        if oid == NULL:
            raise errors.CSRTemplateError(
                reason='unrecognised attribute type: {}'
                .format(rdn_type.decode('utf-8')))

        if not X509_NAME_add_entry_by_OBJ(
                subj, oid, MBSTRING_UTF8,
                _ffi.cast("unsigned char *", v.value), -1, -1, mval):
            _raise_openssl_errors()

    if not X509_NAME_entry_count(subj):
        raise errors.CSRTemplateError(
            reason='error, subject in config file is empty')


def build_requestinfo(config, public_key_info):
    '''
    Return a cffi buffer containing a DER-encoded CertificationRequestInfo.

    The returned object implements the buffer protocol.

    '''
    reqdata = NULL
    req = NULL
    nconf_bio = NULL
    pubkey_bio = NULL
    pubkey = NULL

    try:
        reqdata = NCONF_new(NULL)
        if reqdata == NULL:
            _raise_openssl_errors()

        nconf_bio = BIO_new_mem_buf(config, len(config))
        errorline = _ffi.new('long[1]', [-1])
        i = NCONF_load_bio(reqdata, nconf_bio, errorline)
        if i < 0:
            if errorline[0] < 0:
                raise errors.CSRTemplateError(reason="Can't load config file")
            else:
                raise errors.CSRTemplateError(
                    reason='Error on line %d of config file' % errorline[0])

        dn_sect = NCONF_get_string(reqdata, b'req', b'distinguished_name')
        if dn_sect == NULL:
            raise errors.CSRTemplateError(
                reason='Unable to find "distinguished_name" key in config')

        dn_sk = NCONF_get_section(reqdata, dn_sect)
        if dn_sk == NULL:
            raise errors.CSRTemplateError(
                reason='Unable to find "%s" section in config' %
                _ffi.string(dn_sect))

        pubkey_bio = BIO_new_mem_buf(public_key_info, len(public_key_info))
        pubkey = d2i_PUBKEY_bio(pubkey_bio, NULL)
        if pubkey == NULL:
            _raise_openssl_errors()

        req = X509_REQ_new()
        if req == NULL:
            _raise_openssl_errors()

        subject = X509_REQ_get_subject_name(req)

        _parse_dn_section(subject, dn_sk)

        if not X509_REQ_set_pubkey(req, pubkey):
            _raise_openssl_errors()

        ext_ctx = _ffi.new("X509V3_CTX[1]")
        X509V3_set_ctx(ext_ctx, NULL, NULL, req, NULL, 0)
        X509V3_set_nconf(ext_ctx, reqdata)

        extn_section = NCONF_get_string(reqdata, b"req", b"req_extensions")
        if extn_section != NULL:
            if not X509V3_EXT_REQ_add_nconf(
                    reqdata, ext_ctx, extn_section, req):
                _raise_openssl_errors()

        der_len = i2d_X509_REQ_INFO(req.req_info, NULL)
        if der_len < 0:
            _raise_openssl_errors()

        der_buf = _ffi.new("unsigned char[%d]" % der_len)
        der_out = _ffi.new("unsigned char **", der_buf)
        der_len = i2d_X509_REQ_INFO(req.req_info, der_out)
        if der_len < 0:
            _raise_openssl_errors()

        return _ffi.buffer(der_buf, der_len)

    finally:
        if reqdata != NULL:
            NCONF_free(reqdata)
        if req != NULL:
            X509_REQ_free(req)
        if nconf_bio != NULL:
            BIO_free(nconf_bio)
        if pubkey_bio != NULL:
            BIO_free(pubkey_bio)
        if pubkey != NULL:
            EVP_PKEY_free(pubkey)
