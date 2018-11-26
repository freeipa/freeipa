#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

import random
import ctypes.util
import binascii
import struct

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cffi import FFI

if six.PY3:
    unicode = str


_ffi = FFI()

_ffi.cdef('''
/* p11-kit/pkcs11.h */

typedef unsigned long CK_FLAGS;

struct _CK_VERSION
{
  unsigned char major;
  unsigned char minor;
};

typedef unsigned long CK_SLOT_ID;
typedef CK_SLOT_ID *CK_SLOT_ID_PTR;

typedef unsigned long CK_SESSION_HANDLE;

typedef unsigned long CK_USER_TYPE;

typedef unsigned long CK_OBJECT_HANDLE;

typedef unsigned long CK_OBJECT_CLASS;

typedef unsigned long CK_KEY_TYPE;

typedef unsigned long CK_ATTRIBUTE_TYPE;

typedef unsigned long ck_flags_t;

typedef unsigned char CK_BBOOL;

typedef unsigned long int CK_ULONG;
typedef CK_ULONG *CK_ULONG_PTR;

struct _CK_ATTRIBUTE
{
  CK_ATTRIBUTE_TYPE type;
  void *pValue;
  unsigned long ulValueLen;
};

typedef unsigned long CK_MECHANISM_TYPE;

struct _CK_MECHANISM
{
  CK_MECHANISM_TYPE mechanism;
  void *pParameter;
  unsigned long ulParameterLen;
};

struct _CK_TOKEN_INFO
{
  unsigned char label[32];
  unsigned char manufacturer_id[32];
  unsigned char model[16];
  unsigned char serial_number[16];
  ck_flags_t flags;
  unsigned long max_session_count;
  unsigned long session_count;
  unsigned long max_rw_session_count;
  unsigned long rw_session_count;
  unsigned long max_pin_len;
  unsigned long min_pin_len;
  unsigned long total_public_memory;
  unsigned long free_public_memory;
  unsigned long total_private_memory;
  unsigned long free_private_memory;
  struct _CK_VERSION hardware_version;
  struct _CK_VERSION firmware_version;
  unsigned char utc_time[16];
};

typedef struct _CK_TOKEN_INFO CK_TOKEN_INFO;
typedef CK_TOKEN_INFO *CK_TOKEN_INFO_PTR;

typedef unsigned long CK_RV;

typedef ... *CK_NOTIFY;

struct _CK_FUNCTION_LIST;

typedef CK_RV (*CK_C_Initialize) (void *init_args);
typedef CK_RV (*CK_C_Finalize) (void *pReserved);
typedef ... *CK_C_GetInfo;
typedef ... *CK_C_GetFunctionList;
CK_RV C_GetFunctionList (struct _CK_FUNCTION_LIST **function_list);
typedef CK_RV (*CK_C_GetSlotList) (CK_BBOOL tokenPresent,
                                   CK_SLOT_ID_PTR pSlotList,
                                   CK_ULONG_PTR pulCount);
typedef ... *CK_C_GetSlotInfo;
typedef CK_RV (*CK_C_GetTokenInfo) (CK_SLOT_ID slotID,
                                    CK_TOKEN_INFO_PTR pInfo);
typedef ... *CK_C_WaitForSlotEvent;
typedef ... *CK_C_GetMechanismList;
typedef ... *CK_C_GetMechanismInfo;
typedef ... *CK_C_InitToken;
typedef ... *CK_C_InitPIN;
typedef ... *CK_C_SetPIN;
typedef CK_RV (*CK_C_OpenSession) (CK_SLOT_ID slotID, CK_FLAGS flags,
                                   void *application, CK_NOTIFY notify,
                                   CK_SESSION_HANDLE *session);
typedef CK_RV (*CK_C_CloseSession) (CK_SESSION_HANDLE session);
typedef ... *CK_C_CloseAllSessions;
typedef ... *CK_C_GetSessionInfo;
typedef ... *CK_C_GetOperationState;
typedef ... *CK_C_SetOperationState;
typedef CK_RV (*CK_C_Login) (CK_SESSION_HANDLE session, CK_USER_TYPE user_type,
                             unsigned char *pin, unsigned long pin_len);
typedef CK_RV (*CK_C_Logout) (CK_SESSION_HANDLE session);
typedef CK_RV (*CK_C_CreateObject) (CK_SESSION_HANDLE session,
                                    struct _CK_ATTRIBUTE *templ,
                                    unsigned long count,
                                    CK_OBJECT_HANDLE *object);
typedef ... *CK_C_CopyObject;
typedef CK_RV (*CK_C_DestroyObject) (CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE object);
typedef ... *CK_C_GetObjectSize;
typedef CK_RV (*CK_C_GetAttributeValue) (CK_SESSION_HANDLE session,
                                         CK_OBJECT_HANDLE object,
                                         struct _CK_ATTRIBUTE *templ,
                                         unsigned long count);
typedef CK_RV (*CK_C_SetAttributeValue) (CK_SESSION_HANDLE session,
                                         CK_OBJECT_HANDLE object,
                                         struct _CK_ATTRIBUTE *templ,
                                         unsigned long count);
typedef CK_RV (*CK_C_FindObjectsInit) (CK_SESSION_HANDLE session,
                                       struct _CK_ATTRIBUTE *templ,
                                       unsigned long count);
typedef CK_RV (*CK_C_FindObjects) (CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE *object,
                                   unsigned long max_object_count,
                                   unsigned long *object_count);
typedef CK_RV (*CK_C_FindObjectsFinal) (CK_SESSION_HANDLE session);
typedef ... *CK_C_EncryptInit;
typedef ... *CK_C_Encrypt;
typedef ... *CK_C_EncryptUpdate;
typedef ... *CK_C_EncryptFinal;
typedef ... *CK_C_DecryptInit;
typedef ... *CK_C_Decrypt;
typedef ... *CK_C_DecryptUpdate;
typedef ... *CK_C_DecryptFinal;
typedef ... *CK_C_DigestInit;
typedef ... *CK_C_Digest;
typedef ... *CK_C_DigestUpdate;
typedef ... *CK_C_DigestKey;
typedef ... *CK_C_DigestFinal;
typedef ... *CK_C_SignInit;
typedef ... *CK_C_Sign;
typedef ... *CK_C_SignUpdate;
typedef ... *CK_C_SignFinal;
typedef ... *CK_C_SignRecoverInit;
typedef ... *CK_C_SignRecover;
typedef ... *CK_C_VerifyInit;
typedef ... *CK_C_Verify;
typedef ... *CK_C_VerifyUpdate;
typedef ... *CK_C_VerifyFinal;
typedef ... *CK_C_VerifyRecoverInit;
typedef ... *CK_C_VerifyRecover;
typedef ... *CK_C_DigestEncryptUpdate;
typedef ... *CK_C_DecryptDigestUpdate;
typedef ... *CK_C_SignEncryptUpdate;
typedef ... *CK_C_DecryptVerifyUpdate;
typedef CK_RV (*CK_C_GenerateKey) (CK_SESSION_HANDLE session,
                                   struct _CK_MECHANISM *mechanism,
                                   struct _CK_ATTRIBUTE *templ,
                                   unsigned long count,
                                   CK_OBJECT_HANDLE *key);
typedef CK_RV (*CK_C_GenerateKeyPair) (CK_SESSION_HANDLE session,
                                       struct _CK_MECHANISM *mechanism,
                                       struct _CK_ATTRIBUTE *
                                        public_key_template,
                                       unsigned long
                                        public_key_attribute_count,
                                       struct _CK_ATTRIBUTE *
                                        private_key_template,
                                       unsigned long
                                        private_key_attribute_count,
                                       CK_OBJECT_HANDLE *public_key,
                                       CK_OBJECT_HANDLE *private_key);
typedef CK_RV (*CK_C_WrapKey) (CK_SESSION_HANDLE session,
                               struct _CK_MECHANISM *mechanism,
                               CK_OBJECT_HANDLE wrapping_key,
                               CK_OBJECT_HANDLE key,
                               unsigned char *wrapped_key,
                               unsigned long *wrapped_key_len);
typedef CK_RV (*CK_C_UnwrapKey) (CK_SESSION_HANDLE session,
                                 struct _CK_MECHANISM *mechanism,
                                 CK_OBJECT_HANDLE unwrapping_key,
                                 unsigned char *wrapped_key,
                                 unsigned long wrapped_key_len,
                                 struct _CK_ATTRIBUTE *templ,
                                 unsigned long attribute_count,
                                 CK_OBJECT_HANDLE *key);
typedef ... *CK_C_DeriveKey;
typedef ... *CK_C_SeedRandom;
typedef ... *CK_C_GenerateRandom;
typedef ... *CK_C_GetFunctionStatus;
typedef ... *CK_C_CancelFunction;

struct _CK_FUNCTION_LIST
{
  struct _CK_VERSION version;
  CK_C_Initialize C_Initialize;
  CK_C_Finalize C_Finalize;
  CK_C_GetInfo C_GetInfo;
  CK_C_GetFunctionList C_GetFunctionList;
  CK_C_GetSlotList C_GetSlotList;
  CK_C_GetSlotInfo C_GetSlotInfo;
  CK_C_GetTokenInfo C_GetTokenInfo;
  CK_C_GetMechanismList C_GetMechanismList;
  CK_C_GetMechanismInfo C_GetMechanismInfo;
  CK_C_InitToken C_InitToken;
  CK_C_InitPIN C_InitPIN;
  CK_C_SetPIN C_SetPIN;
  CK_C_OpenSession C_OpenSession;
  CK_C_CloseSession C_CloseSession;
  CK_C_CloseAllSessions C_CloseAllSessions;
  CK_C_GetSessionInfo C_GetSessionInfo;
  CK_C_GetOperationState C_GetOperationState;
  CK_C_SetOperationState C_SetOperationState;
  CK_C_Login C_Login;
  CK_C_Logout C_Logout;
  CK_C_CreateObject C_CreateObject;
  CK_C_CopyObject C_CopyObject;
  CK_C_DestroyObject C_DestroyObject;
  CK_C_GetObjectSize C_GetObjectSize;
  CK_C_GetAttributeValue C_GetAttributeValue;
  CK_C_SetAttributeValue C_SetAttributeValue;
  CK_C_FindObjectsInit C_FindObjectsInit;
  CK_C_FindObjects C_FindObjects;
  CK_C_FindObjectsFinal C_FindObjectsFinal;
  CK_C_EncryptInit C_EncryptInit;
  CK_C_Encrypt C_Encrypt;
  CK_C_EncryptUpdate C_EncryptUpdate;
  CK_C_EncryptFinal C_EncryptFinal;
  CK_C_DecryptInit C_DecryptInit;
  CK_C_Decrypt C_Decrypt;
  CK_C_DecryptUpdate C_DecryptUpdate;
  CK_C_DecryptFinal C_DecryptFinal;
  CK_C_DigestInit C_DigestInit;
  CK_C_Digest C_Digest;
  CK_C_DigestUpdate C_DigestUpdate;
  CK_C_DigestKey C_DigestKey;
  CK_C_DigestFinal C_DigestFinal;
  CK_C_SignInit C_SignInit;
  CK_C_Sign C_Sign;
  CK_C_SignUpdate C_SignUpdate;
  CK_C_SignFinal C_SignFinal;
  CK_C_SignRecoverInit C_SignRecoverInit;
  CK_C_SignRecover C_SignRecover;
  CK_C_VerifyInit C_VerifyInit;
  CK_C_Verify C_Verify;
  CK_C_VerifyUpdate C_VerifyUpdate;
  CK_C_VerifyFinal C_VerifyFinal;
  CK_C_VerifyRecoverInit C_VerifyRecoverInit;
  CK_C_VerifyRecover C_VerifyRecover;
  CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
  CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
  CK_C_SignEncryptUpdate C_SignEncryptUpdate;
  CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
  CK_C_GenerateKey C_GenerateKey;
  CK_C_GenerateKeyPair C_GenerateKeyPair;
  CK_C_WrapKey C_WrapKey;
  CK_C_UnwrapKey C_UnwrapKey;
  CK_C_DeriveKey C_DeriveKey;
  CK_C_SeedRandom C_SeedRandom;
  CK_C_GenerateRandom C_GenerateRandom;
  CK_C_GetFunctionStatus C_GetFunctionStatus;
  CK_C_CancelFunction C_CancelFunction;
  CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

typedef unsigned char CK_BYTE;
typedef unsigned char CK_UTF8CHAR;
typedef CK_BYTE *CK_BYTE_PTR;

typedef CK_OBJECT_HANDLE *CK_OBJECT_HANDLE_PTR;

typedef struct _CK_ATTRIBUTE CK_ATTRIBUTE;
typedef struct _CK_ATTRIBUTE *CK_ATTRIBUTE_PTR;

typedef struct _CK_MECHANISM CK_MECHANISM;

typedef struct _CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;


/* p11-kit/uri.h */

typedef enum {
    DUMMY   /* ..., */
} P11KitUriType;

typedef ... P11KitUri;

CK_ATTRIBUTE_PTR    p11_kit_uri_get_attributes      (P11KitUri *uri,
                                                     CK_ULONG *n_attrs);

int                 p11_kit_uri_any_unrecognized    (P11KitUri *uri);

P11KitUri*          p11_kit_uri_new                 (void);

int                 p11_kit_uri_parse               (const char *string,
                                                     P11KitUriType uri_type,
                                                     P11KitUri *uri);

void                p11_kit_uri_free                (P11KitUri *uri);


/* p11helper.c */

struct ck_rsa_pkcs_oaep_params {
    CK_MECHANISM_TYPE hash_alg;
    unsigned long mgf;
    unsigned long source;
    void *source_data;
    unsigned long source_data_len;
};

typedef struct ck_rsa_pkcs_oaep_params CK_RSA_PKCS_OAEP_PARAMS;
''')

_libp11_kit = _ffi.dlopen(ctypes.util.find_library('p11-kit'))


# utility

NULL = _ffi.NULL

unsigned_char = _ffi.typeof('unsigned char')
unsigned_long = _ffi.typeof('unsigned long')

sizeof = _ffi.sizeof


def new_ptr(ctype, *args):
    return _ffi.new(_ffi.getctype(ctype, '*'), *args)


def new_array(ctype, *args):
    return _ffi.new(_ffi.getctype(ctype, '[]'), *args)


# p11-kit/pkcs11.h

CK_SESSION_HANDLE = _ffi.typeof('CK_SESSION_HANDLE')

CK_OBJECT_HANDLE = _ffi.typeof('CK_OBJECT_HANDLE')

CKU_USER = 1

CKF_RW_SESSION = 0x2
CKF_SERIAL_SESSION = 0x4

CK_OBJECT_CLASS = _ffi.typeof('CK_OBJECT_CLASS')

CKO_PUBLIC_KEY = 2
CKO_PRIVATE_KEY = 3
CKO_SECRET_KEY = 4
CKO_VENDOR_DEFINED = 0x80000000

CK_KEY_TYPE = _ffi.typeof('CK_KEY_TYPE')

CKK_RSA = 0
CKK_AES = 0x1f

CKA_CLASS = 0
CKA_TOKEN = 1
CKA_PRIVATE = 2
CKA_LABEL = 3
CKA_TRUSTED = 0x86
CKA_KEY_TYPE = 0x100
CKA_ID = 0x102
CKA_SENSITIVE = 0x103
CKA_ENCRYPT = 0x104
CKA_DECRYPT = 0x105
CKA_WRAP = 0x106
CKA_UNWRAP = 0x107
CKA_SIGN = 0x108
CKA_SIGN_RECOVER = 0x109
CKA_VERIFY = 0x10a
CKA_VERIFY_RECOVER = 0x10b
CKA_DERIVE = 0x10c
CKA_MODULUS = 0x120
CKA_MODULUS_BITS = 0x121
CKA_PUBLIC_EXPONENT = 0x122
CKA_VALUE_LEN = 0x161
CKA_EXTRACTABLE = 0x162
CKA_LOCAL = 0x163
CKA_NEVER_EXTRACTABLE = 0x164
CKA_ALWAYS_SENSITIVE = 0x165
CKA_MODIFIABLE = 0x170
CKA_ALWAYS_AUTHENTICATE = 0x202
CKA_WRAP_WITH_TRUSTED = 0x210

CKM_RSA_PKCS_KEY_PAIR_GEN = 0
CKM_RSA_PKCS = 1
CKM_RSA_PKCS_OAEP = 9
CKM_SHA_1 = 0x220
CKM_AES_KEY_GEN = 0x1080

CKR_OK = 0
CKR_ATTRIBUTE_TYPE_INVALID = 0x12
CKR_USER_NOT_LOGGED_IN = 0x101
CKR_BUFFER_TOO_SMALL = 0x150

CK_BYTE = _ffi.typeof('CK_BYTE')
CK_BBOOL = _ffi.typeof('CK_BBOOL')
CK_ULONG = _ffi.typeof('CK_ULONG')
CK_BYTE_PTR = _ffi.typeof('CK_BYTE_PTR')
CK_FALSE = 0
CK_TRUE = 1

CK_OBJECT_HANDLE_PTR = _ffi.typeof('CK_OBJECT_HANDLE_PTR')

CK_ATTRIBUTE = _ffi.typeof('CK_ATTRIBUTE')

CK_MECHANISM = _ffi.typeof('CK_MECHANISM')

CK_FUNCTION_LIST_PTR = _ffi.typeof('CK_FUNCTION_LIST_PTR')

CK_SLOT_ID = _ffi.typeof('CK_SLOT_ID')

CK_TOKEN_INFO = _ffi.typeof('CK_TOKEN_INFO')

NULL_PTR = NULL


# p11-kit/uri.h

P11_KIT_URI_OK = 0

P11_KIT_URI_FOR_OBJECT = 2

p11_kit_uri_get_attributes = _libp11_kit.p11_kit_uri_get_attributes

p11_kit_uri_any_unrecognized = _libp11_kit.p11_kit_uri_any_unrecognized

p11_kit_uri_new = _libp11_kit.p11_kit_uri_new

p11_kit_uri_parse = _libp11_kit.p11_kit_uri_parse

p11_kit_uri_free = _libp11_kit.p11_kit_uri_free


# library.c

def loadLibrary(module):
    """Load the PKCS#11 library"""
    # Load PKCS #11 library
    if module:
        # pylint: disable=no-member
        pDynLib = _ffi.dlopen(module, _ffi.RTLD_NOW | _ffi.RTLD_LOCAL)
    else:
        raise Exception()

    # Retrieve the entry point for C_GetFunctionList
    pGetFunctionList = pDynLib.C_GetFunctionList
    if pGetFunctionList == NULL:
        raise Exception()

    # Store the handle so we can dlclose it later

    return pGetFunctionList, pDynLib


# p11helper.c

# compat TODO
CKM_AES_KEY_WRAP = 0x2109
CKM_AES_KEY_WRAP_PAD = 0x210a

# TODO
CKA_COPYABLE = 0x0017

CKG_MGF1_SHA1 = 0x00000001

CKZ_DATA_SPECIFIED = 0x00000001

CK_RSA_PKCS_OAEP_PARAMS = _ffi.typeof('CK_RSA_PKCS_OAEP_PARAMS')


true_ptr = new_ptr(CK_BBOOL, CK_TRUE)
false_ptr = new_ptr(CK_BBOOL, CK_FALSE)

MAX_TEMPLATE_LEN = 32

#
# Constants
#
CONST_RSA_PKCS_OAEP_PARAMS_ptr = new_ptr(CK_RSA_PKCS_OAEP_PARAMS, dict(
    hash_alg=CKM_SHA_1,
    mgf=CKG_MGF1_SHA1,
    source=CKZ_DATA_SPECIFIED,
    source_data=NULL,
    source_data_len=0,
))


#
# ipap11helper Exceptions
#
class P11HelperException(Exception):
    """parent class for all exceptions"""

P11HelperException.__name__ = 'Exception'


class Error(P11HelperException):
    """general error"""


class NotFound(P11HelperException):
    """key not found"""


class DuplicationError(P11HelperException):
    """key already exists"""


########################################################################
# Support functions
#

def pyobj_to_bool(pyobj):
    if pyobj:
        return true_ptr
    return false_ptr


def convert_py2bool(mapping):
    return tuple(pyobj_to_bool(py_obj) for py_obj in mapping)


def string_to_pybytes_or_none(str, len):
    if str == NULL:
        return None
    return _ffi.buffer(str, len)[:]


def unicode_to_char_array(unicode):
    """
    Convert a unicode string to the utf8 encoded char array
    :param unicode: input python unicode object
    """
    try:
        utf8_str = unicode.encode('utf-8')
    except Exception:
        raise Error("Unable to encode UTF-8")
    try:
        result = new_array(unsigned_char, utf8_str)
    except Exception:
        raise Error("Unable to get bytes from string")
    l = len(utf8_str)
    return result, l


def char_array_to_unicode(array, l):
    """
    Convert utf-8 encoded char array to unicode object
    """
    return _ffi.buffer(array, l)[:].decode('utf-8')


def int_to_bytes(value):
    try:
        return binascii.unhexlify('{0:x}'.format(value))
    except (TypeError, binascii.Error):
        return binascii.unhexlify('0{0:x}'.format(value))


def bytes_to_int(value):
    return int(binascii.hexlify(value), 16)


def check_return_value(rv, message):
    """
    Tests result value of pkc11 operations
    """
    if rv != CKR_OK:
        try:
            errmsg = "Error at %s: 0x%x\n" % (message, rv)
        except Exception:
            raise Error("An error occured during error message generation. "
                        "Please report this problem. Developers will use "
                        "a crystal ball to find out the root cause.")
        else:
            raise Error(errmsg)


def _fill_template_from_parts(attr, template_len, id, id_len, label, label_len,
                              class_, cka_wrap, cka_unwrap):
    """
    Fill template structure with pointers to attributes passed as independent
    variables.
    Variables with NULL values will be omitted from template.

    @warning input variables should not be modified when template is in use
    """
    cnt = 0
    if label != NULL:
        attr[0].type = CKA_LABEL
        attr[0].pValue = label
        attr[0].ulValueLen = label_len
        attr += 1
        cnt += 1
        assert cnt < template_len[0]
    if id != NULL:
        attr[0].type = CKA_ID
        attr[0].pValue = id
        attr[0].ulValueLen = id_len
        attr += 1
        cnt += 1
        assert cnt < template_len[0]
    if cka_wrap != NULL:
        attr[0].type = CKA_WRAP
        attr[0].pValue = cka_wrap
        attr[0].ulValueLen = sizeof(CK_BBOOL)
        attr += 1
        cnt += 1
        assert cnt < template_len[0]
    if cka_unwrap != NULL:
        attr[0].type = CKA_UNWRAP
        attr[0].pValue = cka_unwrap
        attr[0].ulValueLen = sizeof(CK_BBOOL)
        attr += 1
        cnt += 1
        assert cnt < template_len[0]

    if class_ != NULL:
        attr[0].type = CKA_CLASS
        attr[0].pValue = class_
        attr[0].ulValueLen = sizeof(CK_OBJECT_CLASS)
        attr += 1
        cnt += 1
        assert cnt < template_len[0]
    template_len[0] = cnt


def _parse_uri(uri_str):
    """
    Parse string to P11-kit representation of PKCS#11 URI.
    """
    uri = p11_kit_uri_new()
    if not uri:
        raise Error("Cannot initialize URI parser")

    try:
        result = p11_kit_uri_parse(uri_str, P11_KIT_URI_FOR_OBJECT, uri)
        if result != P11_KIT_URI_OK:
            raise Error("Cannot parse URI")

        if p11_kit_uri_any_unrecognized(uri):
            raise Error("PKCS#11 URI contains unsupported attributes")
    except Error:
        p11_kit_uri_free(uri)
        raise

    return uri


def _set_wrapping_mech_parameters(mech_type, mech):
    """
    Function set default param values for wrapping mechanism
    :param mech_type: mechanism type
    :param mech: filled structure with params based on mech type

    Warning: do not dealloc param values, it is static variables
    """
    if mech_type in (CKM_RSA_PKCS, CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD):
        mech.pParameter = NULL
        mech.ulParameterLen = 0
    elif mech_type == CKM_RSA_PKCS_OAEP:
        # Use the same configuration as openSSL
        # https://www.openssl.org/docs/crypto/RSA_public_encrypt.html
        mech.pParameter = CONST_RSA_PKCS_OAEP_PARAMS_ptr
        mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS)
    else:
        raise Error("Unsupported wrapping mechanism")
    mech.mechanism = mech_type


########################################################################
# P11_Helper object
#
class P11_Helper:
    @property
    def p11(self):
        return self.p11_ptr[0]

    @property
    def session(self):
        return self.session_ptr[0]

    def _find_key(self, template, template_len):
        """
        Find keys matching specified template.
        Function returns list of key handles via objects parameter.

        :param template: PKCS#11 template for attribute matching
        """
        result_objects = []
        result_object_ptr = new_ptr(CK_OBJECT_HANDLE)
        objectCount_ptr = new_ptr(CK_ULONG)

        rv = self.p11.C_FindObjectsInit(self.session, template, template_len)
        check_return_value(rv, "Find key init")

        rv = self.p11.C_FindObjects(self.session, result_object_ptr, 1,
                                    objectCount_ptr)
        check_return_value(rv, "Find key")

        while objectCount_ptr[0] > 0:
            result_objects.append(result_object_ptr[0])

            rv = self.p11.C_FindObjects(self.session, result_object_ptr, 1,
                                        objectCount_ptr)
            check_return_value(rv, "Check for duplicated key")

        rv = self.p11.C_FindObjectsFinal(self.session)
        check_return_value(rv, "Find objects final")

        return result_objects

    def _id_exists(self, id, id_len, class_):
        """
        Test if object with specified label, id and class exists

        :param id: key ID, (if value is NULL, will not be used to find key)
        :param id_len: key ID length
        :param class_ key: class

        :return: True if object was found, False if object doesnt exists
        """
        object_count_ptr = new_ptr(CK_ULONG)
        result_object_ptr = new_ptr(CK_OBJECT_HANDLE)
        class_ptr = new_ptr(CK_OBJECT_CLASS, class_)
        class_sec_ptr = new_ptr(CK_OBJECT_CLASS, CKO_SECRET_KEY)

        template_pub_priv = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id, id_len),
            (CKA_CLASS, class_ptr, sizeof(CK_OBJECT_CLASS)),
        ))

        template_sec = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id, id_len),
            (CKA_CLASS, class_sec_ptr, sizeof(CK_OBJECT_CLASS)),
        ))

        template_id = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id, id_len),
        ))

        #
        # Only one secret key with same ID is allowed
        #
        if class_ == CKO_SECRET_KEY:
            rv = self.p11.C_FindObjectsInit(self.session, template_id, 1)
            check_return_value(rv, "id, label exists init")

            rv = self.p11.C_FindObjects(self.session, result_object_ptr, 1,
                                        object_count_ptr)
            check_return_value(rv, "id, label exists")

            rv = self.p11.C_FindObjectsFinal(self.session)
            check_return_value(rv, "id, label exists final")

            if object_count_ptr[0] > 0:
                return True
            return False

        #
        # Public and private keys can share one ID, but
        #

        # test if secret key with same ID exists
        rv = self.p11.C_FindObjectsInit(self.session, template_sec, 2)
        check_return_value(rv, "id, label exists init")

        rv = self.p11.C_FindObjects(self.session, result_object_ptr, 1,
                                    object_count_ptr)
        check_return_value(rv, "id, label exists")

        rv = self.p11.C_FindObjectsFinal(self.session)
        check_return_value(rv, "id, label exists final")

        if object_count_ptr[0] > 0:
            # object found
            return True

        # test if pub/private key with same id exists
        object_count_ptr[0] = 0

        rv = self.p11.C_FindObjectsInit(self.session, template_pub_priv, 2)
        check_return_value(rv, "id, label exists init")

        rv = self.p11.C_FindObjects(self.session, result_object_ptr, 1,
                                    object_count_ptr)
        check_return_value(rv, "id, label exists")

        rv = self.p11.C_FindObjectsFinal(self.session)
        check_return_value(rv, "id, label exists final")

        if object_count_ptr[0] > 0:
            # Object found
            return True

        # Object not found
        return False

    def __init__(self, token_label, user_pin, library_path):
        self.p11_ptr = new_ptr(CK_FUNCTION_LIST_PTR)
        self.session_ptr = new_ptr(CK_SESSION_HANDLE)

        self.session_ptr[0] = 0
        self.p11_ptr[0] = NULL
        self.module_handle = None

        # Parse method args
        if isinstance(user_pin, unicode):
            user_pin = user_pin.encode()
        self.token_label = token_label

        try:
            pGetFunctionList, module_handle = loadLibrary(library_path)
        except Exception:
            raise Error("Could not load the library.")

        self.module_handle = module_handle

        #
        # Load the function list
        #
        pGetFunctionList(self.p11_ptr)

        #
        # Initialize
        #
        rv = self.p11.C_Initialize(NULL)
        check_return_value(rv, "initialize")

        #
        # Get Slot
        #
        slot = self.get_slot()
        if slot is None:
            raise Error("No slot for label {} found".format(self.token_label))

        #
        # Start session
        #
        rv = self.p11.C_OpenSession(slot,
                                    CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                    NULL, self.session_ptr)
        check_return_value(rv, "open session")

        #
        # Login
        #
        rv = self.p11.C_Login(self.session, CKU_USER, user_pin, len(user_pin))
        check_return_value(rv, "log in")

    def get_slot(self):
        """Get slot where then token is located
        :return: slot number or None when slot not found
        """
        object_count_ptr = new_ptr(CK_ULONG)

        # get slots ID
        slots = None
        for _i in range(0, 10):
            # try max N times, then die to avoid infinite iteration
            rv = self.p11.C_GetSlotList(CK_TRUE, NULL, object_count_ptr)
            check_return_value(rv, "get slots IDs - prepare")

            result_ids_ptr = new_array(CK_SLOT_ID, object_count_ptr[0])

            rv = self.p11.C_GetSlotList(
                CK_TRUE, result_ids_ptr, object_count_ptr)
            if rv == CKR_BUFFER_TOO_SMALL:
                continue
            check_return_value(rv, "get slots IDs")
            slots = result_ids_ptr
            break  # we have slots !!!

        if slots is None:
            raise Error("Failed to get slots")

        for slot in slots:
            token_info_ptr = new_ptr(CK_TOKEN_INFO)
            rv = self.p11.C_GetTokenInfo(slot, token_info_ptr)
            check_return_value(rv, 'get token info')

            # softhsm always returns label 32 bytes long with padding made of
            # white spaces (#32), so we have to rstrip() padding and compare
            # Label was created by softhsm-util so it is not our fault that
            # there are #32 as padding (cffi initializes structures with
            # zeroes)
            # In case that this is not valid anymore, keep in mind backward
            # compatibility

            if self.token_label == char_array_to_unicode(
                    token_info_ptr[0].label, 32).rstrip():
                return slot
        return None

    def finalize(self):
        """
        Finalize operations with pkcs11 library
        """
        if self.p11 == NULL:
            return

        #
        # Logout
        #
        rv = self.p11.C_Logout(self.session)
        check_return_value(rv, "log out")

        #
        # End session
        #
        rv = self.p11.C_CloseSession(self.session)
        check_return_value(rv, "close session")

        #
        # Finalize
        #
        self.p11.C_Finalize(NULL)

        self.p11_ptr[0] = NULL
        self.session_ptr[0] = 0
        self.module_handle = None

    #################################################################
    # Methods working with keys
    #

    def generate_master_key(self, label, id, key_length=16, cka_copyable=True,
                            cka_decrypt=False, cka_derive=False,
                            cka_encrypt=False, cka_extractable=True,
                            cka_modifiable=True, cka_private=True,
                            cka_sensitive=True, cka_sign=False,
                            cka_unwrap=True, cka_verify=False, cka_wrap=True,
                            cka_wrap_with_trusted=False):
        """
        Generate master key

        :return: master key handle
        """
        if isinstance(id, unicode):
            id = id.encode()

        attrs = (
            cka_copyable,
            cka_decrypt,
            cka_derive,
            cka_encrypt,
            cka_extractable,
            cka_modifiable,
            cka_private,
            cka_sensitive,
            cka_sign,
            cka_unwrap,
            cka_verify,
            cka_wrap,
            cka_wrap_with_trusted,
        )

        key_length_ptr = new_ptr(CK_ULONG, key_length)
        master_key_ptr = new_ptr(CK_OBJECT_HANDLE)

        label_unicode = label
        id_length = len(id)
        id_ = new_array(CK_BYTE, id)
        # TODO check long overflow

        label, label_length = unicode_to_char_array(label_unicode)

        # TODO param?
        mechanism_ptr = new_ptr(CK_MECHANISM, (
            CKM_AES_KEY_GEN, NULL_PTR, 0
        ))

        if key_length not in (16, 24, 32):
            raise Error("generate_master_key: key length allowed values are: "
                        "16, 24 and 32")

        if self._id_exists(id_, id_length, CKO_SECRET_KEY):
            raise DuplicationError("Master key with same ID already exists")

        # Process keyword boolean arguments
        (_cka_copyable_ptr, cka_decrypt_ptr, cka_derive_ptr, cka_encrypt_ptr,
         cka_extractable_ptr, cka_modifiable_ptr, cka_private_ptr,
         cka_sensitive_ptr, cka_sign_ptr, cka_unwrap_ptr, cka_verify_ptr,
         cka_wrap_ptr, cka_wrap_with_trusted_ptr,) = convert_py2bool(attrs)

        symKeyTemplate = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id_, id_length),
            (CKA_LABEL, label, label_length),
            (CKA_TOKEN, true_ptr, sizeof(CK_BBOOL)),
            (CKA_VALUE_LEN, key_length_ptr, sizeof(CK_ULONG)),
            # TODO Softhsm doesn't support it
            # (CKA_COPYABLE, cka_copyable_ptr, sizeof(CK_BBOOL)),
            (CKA_DECRYPT, cka_decrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_DERIVE, cka_derive_ptr, sizeof(CK_BBOOL)),
            (CKA_ENCRYPT, cka_encrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_EXTRACTABLE, cka_extractable_ptr, sizeof(CK_BBOOL)),
            (CKA_MODIFIABLE, cka_modifiable_ptr, sizeof(CK_BBOOL)),
            (CKA_PRIVATE, cka_private_ptr, sizeof(CK_BBOOL)),
            (CKA_SENSITIVE, cka_sensitive_ptr, sizeof(CK_BBOOL)),
            (CKA_SIGN, cka_sign_ptr, sizeof(CK_BBOOL)),
            (CKA_UNWRAP, cka_unwrap_ptr, sizeof(CK_BBOOL)),
            (CKA_VERIFY, cka_verify_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP, cka_wrap_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP_WITH_TRUSTED, cka_wrap_with_trusted_ptr,
             sizeof(CK_BBOOL)),
        ))

        rv = self.p11.C_GenerateKey(self.session, mechanism_ptr,
                                    symKeyTemplate,
                                    (sizeof(symKeyTemplate) //
                                     sizeof(CK_ATTRIBUTE)), master_key_ptr)
        check_return_value(rv, "generate master key")

        return master_key_ptr[0]

    def generate_replica_key_pair(self, label, id, modulus_bits=2048,
                                  pub_cka_copyable=True, pub_cka_derive=False,
                                  pub_cka_encrypt=False,
                                  pub_cka_modifiable=True,
                                  pub_cka_private=True, pub_cka_trusted=False,
                                  pub_cka_verify=False,
                                  pub_cka_verify_recover=False,
                                  pub_cka_wrap=True,
                                  priv_cka_always_authenticate=False,
                                  priv_cka_copyable=True,
                                  priv_cka_decrypt=False,
                                  priv_cka_derive=False,
                                  priv_cka_extractable=False,
                                  priv_cka_modifiable=True,
                                  priv_cka_private=True,
                                  priv_cka_sensitive=True,
                                  priv_cka_sign=False,
                                  priv_cka_sign_recover=False,
                                  priv_cka_unwrap=True,
                                  priv_cka_wrap_with_trusted=False):
        """
        Generate replica keys

        :returns: tuple (public_key_handle, private_key_handle)
        """
        if isinstance(id, unicode):
            id = id.encode()

        attrs_pub = (
            pub_cka_copyable,
            pub_cka_derive,
            pub_cka_encrypt,
            pub_cka_modifiable,
            pub_cka_private,
            pub_cka_trusted,
            pub_cka_verify,
            pub_cka_verify_recover,
            pub_cka_wrap,
        )

        attrs_priv = (
            priv_cka_always_authenticate,
            priv_cka_copyable,
            priv_cka_decrypt,
            priv_cka_derive,
            priv_cka_extractable,
            priv_cka_modifiable,
            priv_cka_private,
            priv_cka_sensitive,
            priv_cka_sign,
            priv_cka_sign_recover,
            priv_cka_unwrap,
            priv_cka_wrap_with_trusted,
        )

        label_unicode = label
        id_ = new_array(CK_BYTE, id)
        id_length = len(id)

        label, label_length = unicode_to_char_array(label_unicode)

        public_key_ptr = new_ptr(CK_OBJECT_HANDLE)
        private_key_ptr = new_ptr(CK_OBJECT_HANDLE)
        mechanism_ptr = new_ptr(CK_MECHANISM,
                                (CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0))

        if self._id_exists(id_, id_length, CKO_PRIVATE_KEY):
            raise DuplicationError("Private key with same ID already exists")

        if self._id_exists(id_, id_length, CKO_PUBLIC_KEY):
            raise DuplicationError("Public key with same ID already exists")

        modulus_bits_ptr = new_ptr(CK_ULONG, modulus_bits)

        # Process keyword boolean arguments
        (_pub_cka_copyable_ptr, pub_cka_derive_ptr, pub_cka_encrypt_ptr,
         pub_cka_modifiable_ptr, pub_cka_private_ptr, pub_cka_trusted_ptr,
         pub_cka_verify_ptr, pub_cka_verify_recover_ptr, pub_cka_wrap_ptr,
         ) = convert_py2bool(attrs_pub)
        (priv_cka_always_authenticate_ptr, _priv_cka_copyable_ptr,
         priv_cka_decrypt_ptr, priv_cka_derive_ptr, priv_cka_extractable_ptr,
         priv_cka_modifiable_ptr, priv_cka_private_ptr, priv_cka_sensitive_ptr,
         priv_cka_sign_ptr, _priv_cka_sign_recover_ptr, priv_cka_unwrap_ptr,
         priv_cka_wrap_with_trusted_ptr,) = convert_py2bool(attrs_priv)

        # 65537 (RFC 6376 section 3.3.1)
        public_exponent = new_array(CK_BYTE, (1, 0, 1))
        publicKeyTemplate = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id_, id_length),
            (CKA_LABEL, label, label_length),
            (CKA_TOKEN, true_ptr, sizeof(CK_BBOOL)),
            (CKA_MODULUS_BITS, modulus_bits_ptr, sizeof(CK_ULONG)),
            (CKA_PUBLIC_EXPONENT, public_exponent, 3),
            # TODO Softhsm doesn't support it
            # (CKA_COPYABLE, pub_cka_copyable_p, sizeof(CK_BBOOL)),
            (CKA_DERIVE, pub_cka_derive_ptr, sizeof(CK_BBOOL)),
            (CKA_ENCRYPT, pub_cka_encrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_MODIFIABLE, pub_cka_modifiable_ptr, sizeof(CK_BBOOL)),
            (CKA_PRIVATE, pub_cka_private_ptr, sizeof(CK_BBOOL)),
            (CKA_TRUSTED, pub_cka_trusted_ptr, sizeof(CK_BBOOL)),
            (CKA_VERIFY, pub_cka_verify_ptr, sizeof(CK_BBOOL)),
            (CKA_VERIFY_RECOVER, pub_cka_verify_recover_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP, pub_cka_wrap_ptr, sizeof(CK_BBOOL)),
        ))

        privateKeyTemplate = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id_, id_length),
            (CKA_LABEL, label, label_length),
            (CKA_TOKEN, true_ptr, sizeof(CK_BBOOL)),
            (CKA_ALWAYS_AUTHENTICATE, priv_cka_always_authenticate_ptr,
             sizeof(CK_BBOOL)),
            # TODO Softhsm doesn't support it
            # (CKA_COPYABLE, priv_cka_copyable_ptr, sizeof(CK_BBOOL)),
            (CKA_DECRYPT, priv_cka_decrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_DERIVE,  priv_cka_derive_ptr, sizeof(CK_BBOOL)),
            (CKA_EXTRACTABLE, priv_cka_extractable_ptr, sizeof(CK_BBOOL)),
            (CKA_MODIFIABLE, priv_cka_modifiable_ptr, sizeof(CK_BBOOL)),
            (CKA_PRIVATE, priv_cka_private_ptr, sizeof(CK_BBOOL)),
            (CKA_SENSITIVE, priv_cka_sensitive_ptr, sizeof(CK_BBOOL)),
            (CKA_SIGN, priv_cka_sign_ptr, sizeof(CK_BBOOL)),
            (CKA_SIGN_RECOVER, priv_cka_sign_ptr, sizeof(CK_BBOOL)),
            (CKA_UNWRAP, priv_cka_unwrap_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP_WITH_TRUSTED, priv_cka_wrap_with_trusted_ptr,
             sizeof(CK_BBOOL)),
        ))

        rv = self.p11.C_GenerateKeyPair(self.session, mechanism_ptr,
                                        publicKeyTemplate,
                                        (sizeof(publicKeyTemplate) //
                                         sizeof(CK_ATTRIBUTE)),
                                        privateKeyTemplate,
                                        (sizeof(privateKeyTemplate) //
                                         sizeof(CK_ATTRIBUTE)),
                                        public_key_ptr,
                                        private_key_ptr)
        check_return_value(rv, "generate key pair")

        return public_key_ptr[0], private_key_ptr[0]

    def find_keys(self, objclass=CKO_VENDOR_DEFINED, label=None, id=None,
                  cka_wrap=None, cka_unwrap=None, uri=None):
        """
        Find key
        """
        if isinstance(id, unicode):
            id = id.encode()
        if isinstance(uri, unicode):
            uri = uri.encode()

        class_ = objclass
        class_ptr = new_ptr(CK_OBJECT_CLASS, class_)
        ckawrap = NULL
        ckaunwrap = NULL
        if id is not None:
            id_ = new_array(CK_BYTE, id)
            id_length = len(id)
        else:
            id_ = NULL
            id_length = 0
        label_unicode, label = label, NULL
        cka_wrap_bool = cka_wrap
        cka_unwrap_bool = cka_unwrap
        label_length = 0
        uri_str = uri
        uri = NULL
        template = new_array(CK_ATTRIBUTE, MAX_TEMPLATE_LEN)
        template_len_ptr = new_ptr(CK_ULONG, MAX_TEMPLATE_LEN)

        # TODO check long overflow

        if label_unicode is not None:
            label, label_length = unicode_to_char_array(label_unicode)

        if cka_wrap_bool is not None:
            if cka_wrap_bool:
                ckawrap = true_ptr
            else:
                ckawrap = false_ptr

        if cka_unwrap_bool is not None:
            if cka_unwrap_bool:
                ckaunwrap = true_ptr
            else:
                ckaunwrap = false_ptr

        if class_ == CKO_VENDOR_DEFINED:
            class_ptr = NULL

        try:
            if uri_str is None:
                _fill_template_from_parts(template, template_len_ptr, id_,
                                          id_length, label, label_length,
                                          class_ptr, ckawrap, ckaunwrap)
            else:
                uri = _parse_uri(uri_str)
                template = (p11_kit_uri_get_attributes(uri, template_len_ptr))
                # Do not deallocate URI while you are using the template.
                # Template contains pointers to values inside URI!

            result_list = self._find_key(template, template_len_ptr[0])

            return result_list
        finally:
            if uri != NULL:
                p11_kit_uri_free(uri)

    def delete_key(self, key_handle):
        """
        delete key
        """
        # TODO check long overflow
        rv = self.p11.C_DestroyObject(self.session, key_handle)
        check_return_value(rv, "object deletion")

    def _export_RSA_public_key(self, object):
        """
        export RSA public key
        """
        class_ptr = new_ptr(CK_OBJECT_CLASS, CKO_PUBLIC_KEY)
        key_type_ptr = new_ptr(CK_KEY_TYPE, CKK_RSA)

        obj_template = new_array(CK_ATTRIBUTE, (
            (CKA_MODULUS, NULL_PTR, 0),
            (CKA_PUBLIC_EXPONENT, NULL_PTR, 0),
            (CKA_CLASS, class_ptr, sizeof(CK_OBJECT_CLASS)),
            (CKA_KEY_TYPE, key_type_ptr, sizeof(CK_KEY_TYPE)),
        ))

        rv = self.p11.C_GetAttributeValue(self.session, object, obj_template,
                                          (sizeof(obj_template) //
                                           sizeof(CK_ATTRIBUTE)))
        check_return_value(rv, "get RSA public key values - prepare")

        # Set proper size for attributes
        modulus = new_array(CK_BYTE,
                            obj_template[0].ulValueLen * sizeof(CK_BYTE))
        obj_template[0].pValue = modulus
        exponent = new_array(CK_BYTE,
                             obj_template[1].ulValueLen * sizeof(CK_BYTE))
        obj_template[1].pValue = exponent

        rv = self.p11.C_GetAttributeValue(self.session, object, obj_template,
                                          (sizeof(obj_template) //
                                           sizeof(CK_ATTRIBUTE)))
        check_return_value(rv, "get RSA public key values")

        # Check if the key is RSA public key
        if class_ptr[0] != CKO_PUBLIC_KEY:
            raise Error("export_RSA_public_key: required public key class")

        if key_type_ptr[0] != CKK_RSA:
            raise Error("export_RSA_public_key: required RSA key type")

        try:
            n = bytes_to_int(string_to_pybytes_or_none(
                modulus, obj_template[0].ulValueLen))
        except Exception:
            raise Error("export_RSA_public_key: internal error: unable to "
                        "convert modulus")

        try:
            e = bytes_to_int(string_to_pybytes_or_none(
                exponent, obj_template[1].ulValueLen))
        except Exception:
            raise Error("export_RSA_public_key: internal error: unable to "
                        "convert exponent")

        # set modulus and exponent
        rsa_ = rsa.RSAPublicNumbers(e, n)

        try:
            pkey = rsa_.public_key(default_backend())
        except Exception:
            raise Error("export_RSA_public_key: internal error: "
                        "EVP_PKEY_set1_RSA failed")

        try:
            ret = pkey.public_bytes(
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                encoding=serialization.Encoding.DER,
            )
        except Exception:
            ret = None

        return ret

    def export_public_key(self, key_handle):
        """
        Export public key

        Export public key in SubjectPublicKeyInfo (RFC5280) DER encoded format
        """
        object = key_handle
        class_ptr = new_ptr(CK_OBJECT_CLASS, CKO_PUBLIC_KEY)
        key_type_ptr = new_ptr(CK_KEY_TYPE, CKK_RSA)
        # TODO check long overflow

        obj_template = new_array(CK_ATTRIBUTE, (
            (CKA_CLASS, class_ptr, sizeof(CK_OBJECT_CLASS)),
            (CKA_KEY_TYPE, key_type_ptr, sizeof(CK_KEY_TYPE)),
        ))

        rv = self.p11.C_GetAttributeValue(self.session, object, obj_template,
                                          (sizeof(obj_template) //
                                           sizeof(CK_ATTRIBUTE)))
        check_return_value(rv, "export_public_key: get RSA public key values")

        if class_ptr[0] != CKO_PUBLIC_KEY:
            raise Error("export_public_key: required public key class")

        if key_type_ptr[0] == CKK_RSA:
            return self._export_RSA_public_key(object)
        else:
            raise Error("export_public_key: unsupported key type")

    def _import_RSA_public_key(self, label, label_length, id, id_length, pkey,
                               cka_copyable, cka_derive, cka_encrypt,
                               cka_modifiable, cka_private, cka_trusted,
                               cka_verify, cka_verify_recover, cka_wrap):
        """
        Import RSA public key
        """
        class_ptr = new_ptr(CK_OBJECT_CLASS, CKO_PUBLIC_KEY)
        keyType_ptr = new_ptr(CK_KEY_TYPE, CKK_RSA)
        cka_token = true_ptr

        if not isinstance(pkey, rsa.RSAPublicKey):
            raise Error("Required RSA public key")

        rsa_ = pkey.public_numbers()

        # convert BIGNUM to binary array
        modulus = new_array(CK_BYTE, int_to_bytes(rsa_.n))
        modulus_len = sizeof(modulus) - 1
        if modulus_len == 0:
            raise Error("import_RSA_public_key: BN_bn2bin modulus error")

        exponent = new_array(CK_BYTE, int_to_bytes(rsa_.e))
        exponent_len = sizeof(exponent) - 1
        if exponent_len == 0:
            raise Error("import_RSA_public_key: BN_bn2bin exponent error")

        template = new_array(CK_ATTRIBUTE, (
            (CKA_ID, id, id_length),
            (CKA_CLASS, class_ptr, sizeof(CK_OBJECT_CLASS)),
            (CKA_KEY_TYPE, keyType_ptr, sizeof(CK_KEY_TYPE)),
            (CKA_TOKEN, cka_token, sizeof(CK_BBOOL)),
            (CKA_LABEL, label, label_length),
            (CKA_MODULUS, modulus, modulus_len),
            (CKA_PUBLIC_EXPONENT, exponent, exponent_len),
            # TODO Softhsm doesn't support it
            # (CKA_COPYABLE, cka_copyable, sizeof(CK_BBOOL)),
            (CKA_DERIVE, cka_derive, sizeof(CK_BBOOL)),
            (CKA_ENCRYPT, cka_encrypt, sizeof(CK_BBOOL)),
            (CKA_MODIFIABLE, cka_modifiable, sizeof(CK_BBOOL)),
            (CKA_PRIVATE, cka_private, sizeof(CK_BBOOL)),
            (CKA_TRUSTED, cka_trusted, sizeof(CK_BBOOL)),
            (CKA_VERIFY, cka_verify, sizeof(CK_BBOOL)),
            (CKA_VERIFY_RECOVER, cka_verify_recover, sizeof(CK_BBOOL)),
            (CKA_WRAP, cka_wrap, sizeof(CK_BBOOL)),
        ))
        object_ptr = new_ptr(CK_OBJECT_HANDLE)

        rv = self.p11.C_CreateObject(self.session, template,
                                     (sizeof(template) //
                                      sizeof(CK_ATTRIBUTE)), object_ptr)
        check_return_value(rv, "create public key object")

        return object_ptr[0]

    def import_public_key(self, label, id, data, cka_copyable=True,
                          cka_derive=False, cka_encrypt=False,
                          cka_modifiable=True, cka_private=True,
                          cka_trusted=False, cka_verify=True,
                          cka_verify_recover=True, cka_wrap=False):
        """
        Import RSA public key
        """
        if isinstance(id, unicode):
            id = id.encode()
        if isinstance(data, unicode):
            data = data.encode()

        label_unicode = label
        id_ = new_array(CK_BYTE, id)
        id_length = len(id)

        attrs_pub = (
            cka_copyable,
            cka_derive,
            cka_encrypt,
            cka_modifiable,
            cka_private,
            cka_trusted,
            cka_verify,
            cka_verify_recover,
            cka_wrap,
        )

        label, label_length = unicode_to_char_array(label_unicode)

        if self._id_exists(id_, id_length, CKO_PUBLIC_KEY):
            raise DuplicationError("Public key with same ID already exists")

        # Process keyword boolean arguments
        (cka_copyable_ptr, cka_derive_ptr, cka_encrypt_ptr, cka_modifiable_ptr,
         cka_private_ptr, cka_trusted_ptr, cka_verify_ptr,
         cka_verify_recover_ptr, cka_wrap_ptr,) = convert_py2bool(attrs_pub)

        # decode from ASN1 DER
        try:
            pkey = serialization.load_der_public_key(data, default_backend())
        except Exception:
            raise Error("import_public_key: d2i_PUBKEY error")
        if isinstance(pkey, rsa.RSAPublicKey):
            ret = self._import_RSA_public_key(label, label_length, id_,
                                              id_length, pkey,
                                              cka_copyable_ptr,
                                              cka_derive_ptr,
                                              cka_encrypt_ptr,
                                              cka_modifiable_ptr,
                                              cka_private_ptr,
                                              cka_trusted_ptr,
                                              cka_verify_ptr,
                                              cka_verify_recover_ptr,
                                              cka_wrap_ptr)
        elif isinstance(pkey, dsa.DSAPublicKey):
            raise Error("DSA is not supported")
        elif isinstance(pkey, ec.EllipticCurvePublicKey):
            raise Error("EC is not supported")
        else:
            raise Error("Unsupported key type")

        return ret

    def export_wrapped_key(self, key, wrapping_key, wrapping_mech):
        """
        Export wrapped key
        """
        object_key = key
        object_wrapping_key = wrapping_key
        wrapped_key_len_ptr = new_ptr(CK_ULONG, 0)
        wrapping_mech_ptr = new_ptr(CK_MECHANISM, (wrapping_mech, NULL, 0))
        # currently we don't support parameter in mechanism

        # TODO check long overflow
        # TODO export method

        # fill mech parameters
        _set_wrapping_mech_parameters(wrapping_mech_ptr.mechanism,
                                      wrapping_mech_ptr)

        rv = self.p11.C_WrapKey(self.session, wrapping_mech_ptr,
                                object_wrapping_key, object_key, NULL,
                                wrapped_key_len_ptr)
        check_return_value(rv, "key wrapping: get buffer length")

        wrapped_key = new_array(CK_BYTE, wrapped_key_len_ptr[0])

        rv = self.p11.C_WrapKey(self.session, wrapping_mech_ptr,
                                object_wrapping_key, object_key, wrapped_key,
                                wrapped_key_len_ptr)
        check_return_value(rv, "key wrapping: wrapping")

        result = string_to_pybytes_or_none(wrapped_key, wrapped_key_len_ptr[0])

        return result

    def import_wrapped_secret_key(self, label, id, data, unwrapping_key,
                                  wrapping_mech, key_type, cka_copyable=True,
                                  cka_decrypt=False, cka_derive=False,
                                  cka_encrypt=False, cka_extractable=True,
                                  cka_modifiable=True, cka_private=True,
                                  cka_sensitive=True, cka_sign=False,
                                  cka_unwrap=True, cka_verify=False,
                                  cka_wrap=True, cka_wrap_with_trusted=False):
        """
        Import wrapped secret key
        """
        if isinstance(id, unicode):
            id = id.encode()
        if isinstance(data, unicode):
            data = data.encode()

        wrapped_key = new_array(CK_BYTE, data)
        wrapped_key_len = len(data)
        unwrapping_key_object = unwrapping_key
        unwrapped_key_object_ptr = new_ptr(CK_OBJECT_HANDLE, 0)
        label_unicode = label
        id_ = new_array(CK_BYTE, id)
        id_length = len(id)
        wrapping_mech_ptr = new_ptr(CK_MECHANISM, (wrapping_mech, NULL, 0))
        key_class_ptr = new_ptr(CK_OBJECT_CLASS, CKO_SECRET_KEY)
        key_type_ptr = new_ptr(CK_KEY_TYPE, key_type)

        attrs = (
            cka_copyable,
            cka_decrypt,
            cka_derive,
            cka_encrypt,
            cka_extractable,
            cka_modifiable,
            cka_private,
            cka_sensitive,
            cka_sign,
            cka_unwrap,
            cka_verify,
            cka_wrap,
            cka_wrap_with_trusted,
        )

        _set_wrapping_mech_parameters(wrapping_mech_ptr.mechanism,
                                      wrapping_mech_ptr)

        label, label_length = unicode_to_char_array(label_unicode)

        if self._id_exists(id_, id_length, key_class_ptr[0]):
            raise DuplicationError("Secret key with same ID already exists")

        # Process keyword boolean arguments
        (_cka_copyable_ptr, cka_decrypt_ptr, cka_derive_ptr, cka_encrypt_ptr,
         cka_extractable_ptr, cka_modifiable_ptr, cka_private_ptr,
         cka_sensitive_ptr, cka_sign_ptr, cka_unwrap_ptr, cka_verify_ptr,
         cka_wrap_ptr, cka_wrap_with_trusted_ptr,) = convert_py2bool(attrs)

        template = new_array(CK_ATTRIBUTE, (
            (CKA_CLASS, key_class_ptr, sizeof(CK_OBJECT_CLASS)),
            (CKA_KEY_TYPE, key_type_ptr, sizeof(CK_KEY_TYPE)),
            (CKA_ID, id_, id_length),
            (CKA_LABEL, label, label_length),
            (CKA_TOKEN, true_ptr, sizeof(CK_BBOOL)),
            # TODO Softhsm doesn't support it
            # (CKA_COPYABLE, cka_copyable_ptr, sizeof(CK_BBOOL)),
            (CKA_DECRYPT, cka_decrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_DERIVE, cka_derive_ptr, sizeof(CK_BBOOL)),
            (CKA_ENCRYPT, cka_encrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_EXTRACTABLE, cka_extractable_ptr, sizeof(CK_BBOOL)),
            (CKA_MODIFIABLE, cka_modifiable_ptr, sizeof(CK_BBOOL)),
            (CKA_PRIVATE, cka_private_ptr, sizeof(CK_BBOOL)),
            (CKA_SENSITIVE, cka_sensitive_ptr, sizeof(CK_BBOOL)),
            (CKA_SIGN, cka_sign_ptr, sizeof(CK_BBOOL)),
            (CKA_UNWRAP, cka_unwrap_ptr, sizeof(CK_BBOOL)),
            (CKA_VERIFY, cka_verify_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP, cka_wrap_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP_WITH_TRUSTED, cka_wrap_with_trusted_ptr,
             sizeof(CK_BBOOL)),
        ))

        rv = self.p11.C_UnwrapKey(self.session, wrapping_mech_ptr,
                                  unwrapping_key_object, wrapped_key,
                                  wrapped_key_len, template,
                                  sizeof(template) // sizeof(CK_ATTRIBUTE),
                                  unwrapped_key_object_ptr)
        check_return_value(rv, "import_wrapped_key: key unwrapping")

        return unwrapped_key_object_ptr[0]

    def import_wrapped_private_key(self, label, id, data, unwrapping_key,
                                   wrapping_mech, key_type,
                                   cka_always_authenticate=False,
                                   cka_copyable=True, cka_decrypt=False,
                                   cka_derive=False, cka_extractable=True,
                                   cka_modifiable=True, cka_private=True,
                                   cka_sensitive=True, cka_sign=True,
                                   cka_sign_recover=True, cka_unwrap=False,
                                   cka_wrap_with_trusted=False):
        """
        Import wrapped private key
        """
        if isinstance(id, unicode):
            id = id.encode()
        if isinstance(data, unicode):
            data = data.encode()

        wrapped_key = new_array(CK_BYTE, data)
        wrapped_key_len = len(data)
        unwrapping_key_object = unwrapping_key
        unwrapped_key_object_ptr = new_ptr(CK_OBJECT_HANDLE, 0)
        label_unicode = label
        id_ = new_array(CK_BYTE, id)
        id_length = len(id)
        wrapping_mech_ptr = new_ptr(CK_MECHANISM, (wrapping_mech, NULL, 0))
        key_class_ptr = new_ptr(CK_OBJECT_CLASS, CKO_PRIVATE_KEY)
        key_type_ptr = new_ptr(CK_KEY_TYPE, key_type)

        attrs_priv = (
            cka_always_authenticate,
            cka_copyable,
            cka_decrypt,
            cka_derive,
            cka_extractable,
            cka_modifiable,
            cka_private,
            cka_sensitive,
            cka_sign,
            cka_sign_recover,
            cka_unwrap,
            cka_wrap_with_trusted,
        )

        label, label_length = unicode_to_char_array(label_unicode)

        if self._id_exists(id_, id_length, CKO_SECRET_KEY):
            raise DuplicationError("Secret key with same ID already exists")

        # Process keyword boolean arguments
        (cka_always_authenticate_ptr, _cka_copyable_ptr, cka_decrypt_ptr,
         cka_derive_ptr, cka_extractable_ptr, cka_modifiable_ptr,
         cka_private_ptr, cka_sensitive_ptr, cka_sign_ptr,
         _cka_sign_recover_ptr, cka_unwrap_ptr, cka_wrap_with_trusted_ptr,
         ) = convert_py2bool(attrs_priv)

        template = new_array(CK_ATTRIBUTE, (
            (CKA_CLASS, key_class_ptr, sizeof(CK_OBJECT_CLASS)),
            (CKA_KEY_TYPE, key_type_ptr, sizeof(CK_KEY_TYPE)),
            (CKA_ID, id_, id_length),
            (CKA_LABEL, label, label_length),
            (CKA_TOKEN, true_ptr, sizeof(CK_BBOOL)),
            (CKA_ALWAYS_AUTHENTICATE, cka_always_authenticate_ptr,
             sizeof(CK_BBOOL)),
            # TODO Softhsm doesn't support it
            # (CKA_COPYABLE, cka_copyable_ptr, sizeof(CK_BBOOL)),
            (CKA_DECRYPT, cka_decrypt_ptr, sizeof(CK_BBOOL)),
            (CKA_DERIVE, cka_derive_ptr, sizeof(CK_BBOOL)),
            (CKA_EXTRACTABLE, cka_extractable_ptr, sizeof(CK_BBOOL)),
            (CKA_MODIFIABLE,  cka_modifiable_ptr, sizeof(CK_BBOOL)),
            (CKA_PRIVATE, cka_private_ptr, sizeof(CK_BBOOL)),
            (CKA_SENSITIVE, cka_sensitive_ptr, sizeof(CK_BBOOL)),
            (CKA_SIGN, cka_sign_ptr, sizeof(CK_BBOOL)),
            (CKA_SIGN_RECOVER, cka_sign_ptr, sizeof(CK_BBOOL)),
            (CKA_UNWRAP, cka_unwrap_ptr, sizeof(CK_BBOOL)),
            (CKA_WRAP_WITH_TRUSTED, cka_wrap_with_trusted_ptr,
             sizeof(CK_BBOOL)),
        ))

        rv = self.p11.C_UnwrapKey(self.session, wrapping_mech_ptr,
                                  unwrapping_key_object, wrapped_key,
                                  wrapped_key_len, template,
                                  sizeof(template) // sizeof(CK_ATTRIBUTE),
                                  unwrapped_key_object_ptr)
        check_return_value(rv, "import_wrapped_key: key unwrapping")

        return unwrapped_key_object_ptr[0]

    def set_attribute(self, key_object, attr, value):
        """
        Set object attributes
        """
        object = key_object
        attribute_ptr = new_ptr(CK_ATTRIBUTE)

        attribute_ptr.type = attr
        if attr in (CKA_ALWAYS_AUTHENTICATE,
                    CKA_ALWAYS_SENSITIVE,
                    CKA_COPYABLE,
                    CKA_ENCRYPT,
                    CKA_EXTRACTABLE,
                    CKA_DECRYPT,
                    CKA_DERIVE,
                    CKA_LOCAL,
                    CKA_MODIFIABLE,
                    CKA_NEVER_EXTRACTABLE,
                    CKA_PRIVATE,
                    CKA_SENSITIVE,
                    CKA_SIGN,
                    CKA_SIGN_RECOVER,
                    CKA_TOKEN,
                    CKA_TRUSTED,
                    CKA_UNWRAP,
                    CKA_VERIFY,
                    CKA_VERIFY_RECOVER,
                    CKA_WRAP,
                    CKA_WRAP_WITH_TRUSTED):
            attribute_ptr.pValue = true_ptr if value else false_ptr
            attribute_ptr.ulValueLen = sizeof(CK_BBOOL)
        elif attr == CKA_ID:
            if not isinstance(value, bytes):
                raise Error("Bytestring value expected")
            attribute_ptr.pValue = new_array(CK_BYTE, value)
            attribute_ptr.ulValueLen = len(value)
        elif attr == CKA_LABEL:
            if not isinstance(value, unicode):
                raise Error("Unicode value expected")
            label, label_length = unicode_to_char_array(value)
            attribute_ptr.pValue = label
            attribute_ptr.ulValueLen = label_length
        elif attr == CKA_KEY_TYPE:
            if not isinstance(value, int):
                raise Error("Integer value expected")
            attribute_ptr.pValue = new_ptr(unsigned_long, value)
            attribute_ptr.ulValueLen = sizeof(unsigned_long)
        else:
            raise Error("Unknown attribute")

        template = new_array(CK_ATTRIBUTE, (attribute_ptr[0],))

        rv = self.p11.C_SetAttributeValue(self.session, object, template,
                                          (sizeof(template) //
                                           sizeof(CK_ATTRIBUTE)))
        check_return_value(rv, "set_attribute")

    def get_attribute(self, key_object, attr):
        object = key_object
        attribute_ptr = new_ptr(CK_ATTRIBUTE)

        attribute_ptr.type = attr
        attribute_ptr.pValue = NULL_PTR
        attribute_ptr.ulValueLen = 0
        template = new_array(CK_ATTRIBUTE, (attribute_ptr[0],))

        rv = self.p11.C_GetAttributeValue(self.session, object, template,
                                          (sizeof(template) //
                                           sizeof(CK_ATTRIBUTE)))
        if rv == CKR_ATTRIBUTE_TYPE_INVALID or template[0].ulValueLen == -1:
            raise NotFound("attribute does not exist")
        check_return_value(rv, "get_attribute init")
        value = new_array(unsigned_char, template[0].ulValueLen)
        template[0].pValue = value

        rv = self.p11.C_GetAttributeValue(self.session, object, template,
                                          (sizeof(template) //
                                           sizeof(CK_ATTRIBUTE)))
        check_return_value(rv, "get_attribute")

        if attr in (CKA_ALWAYS_AUTHENTICATE,
                    CKA_ALWAYS_SENSITIVE,
                    CKA_COPYABLE,
                    CKA_ENCRYPT,
                    CKA_EXTRACTABLE,
                    CKA_DECRYPT,
                    CKA_DERIVE,
                    CKA_LOCAL,
                    CKA_MODIFIABLE,
                    CKA_NEVER_EXTRACTABLE,
                    CKA_PRIVATE,
                    CKA_SENSITIVE,
                    CKA_SIGN,
                    CKA_SIGN_RECOVER,
                    CKA_TOKEN,
                    CKA_TRUSTED,
                    CKA_UNWRAP,
                    CKA_VERIFY,
                    CKA_VERIFY_RECOVER,
                    CKA_WRAP,
                    CKA_WRAP_WITH_TRUSTED):
            ret = bool(_ffi.cast(_ffi.getctype(CK_BBOOL, '*'), value)[0])
        elif attr == CKA_LABEL:
            ret = char_array_to_unicode(value, template[0].ulValueLen)
        elif attr in (CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_ID):
            ret = string_to_pybytes_or_none(value, template[0].ulValueLen)
        elif attr == CKA_KEY_TYPE:
            ret = _ffi.cast(_ffi.getctype(unsigned_long, '*'), value)[0]
        else:
            raise Error("Unknown attribute")

        return ret


# Key Classes
KEY_CLASS_PUBLIC_KEY = CKO_PUBLIC_KEY
KEY_CLASS_PRIVATE_KEY = CKO_PRIVATE_KEY
KEY_CLASS_SECRET_KEY = CKO_SECRET_KEY

# Key types
KEY_TYPE_RSA = CKK_RSA
KEY_TYPE_AES = CKK_AES

# Wrapping mech type
MECH_RSA_PKCS = CKM_RSA_PKCS
MECH_RSA_PKCS_OAEP = CKM_RSA_PKCS_OAEP
MECH_AES_KEY_WRAP = CKM_AES_KEY_WRAP
MECH_AES_KEY_WRAP_PAD = CKM_AES_KEY_WRAP_PAD


def gen_key_id(key_id_len=16):
    """
    Generate random softhsm KEY_ID
    :param key_id_len: this should be 16
    :return: random softhsm KEY_ID in bytes representation
    """
    return struct.pack(
        "B" * key_id_len,  # key_id must be bytes
        *(random.randint(0, 255) for _ in range(key_id_len))
    )


def generate_master_key(p11, keylabel=u"dnssec-master", key_length=16,
                        disable_old_keys=True):
    assert isinstance(p11, P11_Helper)

    key_id = None
    while True:
        # check if key with this ID exist in LDAP or softHSM
        # id is 16 Bytes long
        key_id = gen_key_id()
        keys = p11.find_keys(KEY_CLASS_SECRET_KEY,
                             label=keylabel,
                             id=key_id)
        if not keys:
            break  # we found unique id

    p11.generate_master_key(keylabel,
                            key_id,
                            key_length=key_length,
                            cka_wrap=True,
                            cka_unwrap=True)

    if disable_old_keys:
        # set CKA_WRAP=False for old master keys
        master_keys = p11.find_keys(KEY_CLASS_SECRET_KEY,
                                    label=keylabel,
                                    cka_wrap=True)

        for handle in master_keys:
            # don't disable wrapping for new key
            # compare IDs not handle
            if key_id != p11.get_attribute(handle, CKA_ID):
                p11.set_attribute(handle, CKA_WRAP, False)
