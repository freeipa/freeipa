/*
 * Copyright (C) 2014  FreeIPA Contributors see COPYING for license
 *
 * This file includes an "OpenSSL license exception", see the
 * COPYING.openssl file for details.
 *
 * This code is based on PKCS#11 code snippets from NLnetLabs:
 * http://www.nlnetlabs.nl/publications/hsm/examples/pkcs11/
 * Original license follows:
 */
/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <Python.h>
#include "structmember.h"

#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include <p11-kit/pkcs11.h>
#include <p11-kit/uri.h>

#include "library.h"

// compat TODO
#define CKM_AES_KEY_WRAP           (0x2109)
#define CKM_AES_KEY_WRAP_PAD       (0x210a)

// TODO
#define CKA_COPYABLE           (0x0017)

#define CKG_MGF1_SHA1         (0x00000001)

#define CKZ_DATA_SPECIFIED    (0x00000001)

struct ck_rsa_pkcs_oaep_params {
    CK_MECHANISM_TYPE hash_alg;
    unsigned long mgf;
    unsigned long source;
    void *source_data;
    unsigned long source_data_len;
};

typedef struct ck_rsa_pkcs_oaep_params CK_RSA_PKCS_OAEP_PARAMS;
typedef struct ck_rsa_pkcs_oaep_params *CK_RSA_PKCS_OAEP_PARAMS_PTR;


CK_BBOOL true = CK_TRUE;
CK_BBOOL false = CK_FALSE;

#define MAX_TEMPLATE_LEN 32

/**
 * P11_Helper type
 */
typedef struct {
    PyObject_HEAD CK_SLOT_ID slot;
    CK_FUNCTION_LIST_PTR p11;
    CK_SESSION_HANDLE session;
    void *module_handle;
} P11_Helper;

typedef enum {
    sec_en_cka_copyable = 0,
    sec_en_cka_decrypt = 1,
    sec_en_cka_derive = 2,
    sec_en_cka_encrypt = 3,
    sec_en_cka_extractable = 4,
    sec_en_cka_modifiable = 5,
    sec_en_cka_private = 6,
    sec_en_cka_sensitive = 7,
    sec_en_cka_sign = 8,
    sec_en_cka_unwrap = 9,
    sec_en_cka_verify = 10,
    sec_en_cka_wrap = 11,
    sec_en_cka_wrap_with_trusted = 12
} secrect_key_enum;

typedef enum {
    pub_en_cka_copyable = 0,
    pub_en_cka_derive = 1,
    pub_en_cka_encrypt = 2,
    pub_en_cka_modifiable = 3,
    pub_en_cka_private = 4,
    pub_en_cka_trusted = 5,
    pub_en_cka_verify = 6,
    pub_en_cka_verify_recover = 7,
    pub_en_cka_wrap = 8
} public_key_enum;

typedef enum {
    priv_en_cka_always_authenticate = 0,
    priv_en_cka_copyable = 1,
    priv_en_cka_decrypt = 2,
    priv_en_cka_derive = 3,
    priv_en_cka_extractable = 4,
    priv_en_cka_modifiable = 5,
    priv_en_cka_private = 6,
    priv_en_cka_sensitive = 7,
    priv_en_cka_sign = 8,
    priv_en_cka_sign_recover = 9,
    priv_en_cka_unwrap = 10,
    priv_en_cka_wrap_with_trusted = 11
} private_key_enum;

typedef struct {
    PyObject *py_obj;
    CK_BBOOL *bool;
} PyObj2Bool_mapping_t;

/**
 * Constants
 */
static const CK_RSA_PKCS_OAEP_PARAMS CONST_RSA_PKCS_OAEP_PARAMS = {
    .hash_alg = CKM_SHA_1,
    .mgf = CKG_MGF1_SHA1,
    .source = CKZ_DATA_SPECIFIED,
    .source_data = NULL,
    .source_data_len = 0
};

/**
 * ipap11helper Exceptions
 */
static PyObject *ipap11helperException;     // parent class for all exceptions

static PyObject *ipap11helperError;         // general error
static PyObject *ipap11helperNotFound;      // key not found
static PyObject *ipap11helperDuplicationError;  // key already exists

/***********************************************************************
 * Support functions
 */

#define GOTO_FAIL     \
    do {              \
        error = 1;    \
        goto final;   \
    } while(0);

CK_BBOOL *pyobj_to_bool(PyObject *pyobj) {
    if (PyObject_IsTrue(pyobj))
        return &true;
    return &false;

}

void convert_py2bool(PyObj2Bool_mapping_t *mapping, int length) {
    int i;
    for (i = 0; i < length; ++i) {
        PyObject *py_obj = mapping[i].py_obj;
        if (py_obj != NULL) {
            mapping[i].bool = pyobj_to_bool(py_obj);
        }
    }
}

/**
 * Convert a unicode string to the utf8 encoded char array
 * :param unicode: input python unicode object
 * :param l length: of returned string
 * Returns NULL if an error occurs, else pointer to string
 */
unsigned char *unicode_to_char_array(PyObject *unicode, Py_ssize_t *l) {
    unsigned char *result = NULL;
    PyObject *utf8_str = PyUnicode_AsUTF8String(unicode);
    if (utf8_str == NULL) {
        PyErr_SetString(ipap11helperError, "Unable to encode UTF-8");
        return NULL;
    }
    unsigned char *bytes = (unsigned char *) PyString_AS_STRING(utf8_str);
    if (bytes == NULL) {
        PyErr_SetString(ipap11helperError, "Unable to get bytes from string");
        *l = 0;
    } else {
        *l = PyString_Size(utf8_str);

        /* Copy string first, then DECREF
         * https://docs.python.org/2/c-api/string.html#c.PyString_AS_STRING
         */
        result = (unsigned char *) PyMem_Malloc((size_t) * l);
        if (result == NULL) {
            Py_DECREF(utf8_str);
            PyErr_NoMemory();
            return NULL;
        } else {
            memcpy(result, bytes, *l);
        }

    }
    Py_DECREF(utf8_str);
    return result;
}

/**
 * Convert utf-8 encoded char array to unicode object
 */
PyObject *char_array_to_unicode(const char *array, unsigned long l) {
    return PyUnicode_DecodeUTF8(array, l, "strict");
}

/**
 * Tests result value of pkc11 operations
 * :return: 1 if everything is ok, 0 if an error occurs and set the error message
 */
int check_return_value(CK_RV rv, const char *message) {
    char *errmsg = NULL;
    if (rv != CKR_OK) {
        if (asprintf
            (&errmsg, "Error at %s: 0x%x\n", message, (unsigned int) rv)
            == -1) {
            PyErr_SetString(ipap11helperError,
                            "An error occured during error message generation. "
                            "Please report this problem. Developers will use "
                            "a crystal ball to find out the root cause.");
            return 0;
        }
        if (errmsg != NULL) {
            PyErr_SetString(ipap11helperError, errmsg);
            free(errmsg);
        }
        return 0;
    }
    return 1;
}

/**
 * Fill template structure with pointers to attributes passed as independent
 * variables.
 * Variables with NULL values will be omitted from template.
 *
 * @warning input variables should not be modified when template is in use
 */
int _fill_template_from_parts(CK_ATTRIBUTE_PTR attr, CK_ULONG_PTR template_len,
                              CK_BYTE_PTR id, CK_ULONG id_len,
                              CK_BYTE_PTR label, CK_ULONG label_len,
                              CK_OBJECT_CLASS *class, CK_BBOOL *cka_wrap,
                              CK_BBOOL *cka_unwrap) {
    int cnt = 0;
    if (label != NULL) {
        attr->type = CKA_LABEL;
        attr->pValue = (void *) label;
        attr->ulValueLen = label_len;
        ++attr;
        ++cnt;
        assert(cnt < *template_len);
    }
    if (id != NULL) {
        attr->type = CKA_ID;
        attr->pValue = (void *) id;
        attr->ulValueLen = id_len;
        ++attr;
        ++cnt;
        assert(cnt < *template_len);
    }
    if (cka_wrap != NULL) {
        attr->type = CKA_WRAP;
        attr->pValue = (void *) cka_wrap;
        attr->ulValueLen = sizeof(CK_BBOOL);
        ++attr;
        ++cnt;
        assert(cnt < *template_len);
    }
    if (cka_unwrap != NULL) {
        attr->type = CKA_UNWRAP;
        attr->pValue = (void *) cka_unwrap;
        attr->ulValueLen = sizeof(CK_BBOOL);
        ++attr;
        ++cnt;
        assert(cnt < *template_len);
    }

    if (class != NULL) {
        attr->type = CKA_CLASS;
        attr->pValue = (void *) class;
        attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
        ++attr;
        ++cnt;
        assert(cnt < *template_len);
    }
    *template_len = cnt;
    return 1;
}

/**
 * Parse string to P11-kit representation of PKCS#11 URI.
 *
 * @pre *urip is NULL
 * @post
 *
 * @retval 0 in case of error
 * @retval 1 when urip is filled with pointer to new URI structure
 */
int _parse_uri(const char *uri_str, P11KitUri **urip) {
    P11KitUriResult result;
    P11KitUri *uri = NULL;

    assert(urip != NULL && *urip == NULL);

    uri = p11_kit_uri_new();
    if (!uri) {
        PyErr_SetString(ipap11helperError, "Cannot initialize URI parser");
        return 0;
    }

    result = p11_kit_uri_parse(uri_str, P11_KIT_URI_FOR_OBJECT, uri);
    if (result != P11_KIT_URI_OK) {
        PyErr_SetString(ipap11helperError, "Cannot parse URI");
        goto cleanup;
    }

    if (p11_kit_uri_any_unrecognized(uri)) {
        PyErr_SetString(ipap11helperError, "PKCS#11 URI contains "
                        "unsupported attributes");
        goto cleanup;
    }

    *urip = uri;
    return 1;

cleanup:
    p11_kit_uri_free(uri);
    return 0;
}

/*
 * Find keys matching specified template.
 * Function returns list of key handles via objects parameter.
 *
 * :param template: PKCS#11 template for attribute matching
 * :param objects: found objects, NULL if no objects fit criteria
 * :param objects_count: number of objects in objects array
 * :return: 1 if success, otherwise return 0 and set the exception
 */
int _find_key(P11_Helper *self, CK_ATTRIBUTE_PTR template,
              CK_ULONG template_len, CK_OBJECT_HANDLE **objects,
              unsigned int *objects_count) {
    CK_OBJECT_HANDLE result_object;
    CK_ULONG objectCount;
    CK_OBJECT_HANDLE *result_objects = NULL;
    CK_OBJECT_HANDLE *tmp_objects_ptr = NULL;
    unsigned int count = 0;
    unsigned int allocated = 0;
    CK_RV rv;

    rv = self->p11->C_FindObjectsInit(self->session, template, template_len);
    if (!check_return_value(rv, "Find key init"))
        return 0;

    rv = self->p11->C_FindObjects(self->session, &result_object, 1,
                                  &objectCount);
    if (!check_return_value(rv, "Find key"))
        return 0;

    while (objectCount > 0) {
        if (allocated <= count) {
            allocated += 32;
            tmp_objects_ptr = (CK_OBJECT_HANDLE*) realloc(result_objects,
                    allocated * sizeof(CK_OBJECT_HANDLE));
            if (tmp_objects_ptr == NULL) {
                *objects_count = 0;
                PyErr_SetString(ipap11helperError, "_find_key realloc failed");
                free(result_objects);
                return 0;
            } else {
                result_objects = tmp_objects_ptr;
            }
        }
        result_objects[count] = result_object;
        count++;
        rv = self->p11->C_FindObjects(self->session, &result_object, 1,
                                      &objectCount);
        if (!check_return_value(rv, "Check for duplicated key")) {
            free(result_objects);
            return 0;
        }
    }

    rv = self->p11->C_FindObjectsFinal(self->session);
    if (!check_return_value(rv, "Find objects final")) {
        free(result_objects);
        return 0;
    }

    *objects = result_objects;
    *objects_count = count;
    return 1;
}

/*
 * Test if object with specified label, id and class exists
 *
 * :param id: key ID, (if value is NULL, will not be used to find key)
 * :param id_len: key ID length
 * :param label key: label (if value is NULL, will not be used to find key)
 * :param label_len: key label length
 * :param class key: class

 * :return: 1 if object was found, 0 if object doesnt exists, -1 if error
 * and set the exception
 *
 */
int _id_exists(P11_Helper *self, CK_BYTE_PTR id, CK_ULONG id_len,
               CK_OBJECT_CLASS class) {

    CK_RV rv;
    CK_ULONG object_count = 0;
    CK_OBJECT_HANDLE result_object = 0;
    CK_OBJECT_CLASS class_sec = CKO_SECRET_KEY;

    CK_ATTRIBUTE template_pub_priv[] = {
        { CKA_ID, id, id_len },
        { CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS) }
    };

    CK_ATTRIBUTE template_sec[] = {
        { CKA_ID, id, id_len },
        { CKA_CLASS, &class_sec, sizeof(CK_OBJECT_CLASS) }
    };

    CK_ATTRIBUTE template_id[] = {
        { CKA_ID, id, id_len }
    };

    /*
     * Only one secret key with same ID is allowed
     */
    if (class == CKO_SECRET_KEY) {
        rv = self->p11->C_FindObjectsInit(self->session, template_id, 1);
        if (!check_return_value(rv, "id, label exists init"))
            return -1;

        rv = self->p11->C_FindObjects(self->session, &result_object, 1,
                                      &object_count);
        if (!check_return_value(rv, "id, label exists"))
            return -1;

        rv = self->p11->C_FindObjectsFinal(self->session);
        if (!check_return_value(rv, "id, label exists final"))
            return -1;

        if (object_count > 0) {
            /* object found */
            return 1;
        }
        return 0;
    }

    /*
     *  Public and private keys can share one ID, but
     */

    /* test if secret key with same ID exists */
    rv = self->p11->C_FindObjectsInit(self->session, template_sec, 2);
    if (!check_return_value(rv, "id, label exists init"))
        return -1;

    rv = self->p11->C_FindObjects(self->session, &result_object, 1,
                                  &object_count);
    if (!check_return_value(rv, "id, label exists"))
        return -1;

    rv = self->p11->C_FindObjectsFinal(self->session);
    if (!check_return_value(rv, "id, label exists final"))
        return -1;

    if (object_count > 0) {
        /* object found */
        return 1;
    }

    /* test if pub/private key with same id exists */
    object_count = 0;

    rv = self->p11->C_FindObjectsInit(self->session, template_pub_priv, 2);
    if (!check_return_value(rv, "id, label exists init"))
        return -1;

    rv = self->p11->C_FindObjects(self->session, &result_object, 1,
                                  &object_count);
    if (!check_return_value(rv, "id, label exists"))
        return -1;

    rv = self->p11->C_FindObjectsFinal(self->session);
    if (!check_return_value(rv, "id, label exists final"))
        return -1;

    if (object_count > 0) {
        return 1; /* Object found*/
    }

    return 0; /* Object not found*/
}

/*
 * Function set default param values for wrapping mechanism
 * :param mech_type: mechanism type
 * :param mech: filled structure with params based on mech type
 *
 * :return: 1 if sucessfull, 0 if error (fill proper exception)
 *
 * Warning: do not dealloc param values, it is static variables
 */
int _set_wrapping_mech_parameters(CK_MECHANISM_TYPE mech_type,
                                  CK_MECHANISM *mech) {
    switch (mech_type) {
        case CKM_RSA_PKCS:
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
            mech->pParameter = NULL;
            mech->ulParameterLen = 0;
        break;

        case CKM_RSA_PKCS_OAEP:
            /* Use the same configuration as openSSL
             * https://www.openssl.org/docs/crypto/RSA_public_encrypt.html
             */
            mech->pParameter = (void *) &CONST_RSA_PKCS_OAEP_PARAMS;
            mech->ulParameterLen = sizeof(CONST_RSA_PKCS_OAEP_PARAMS);
        break;

        default:
            PyErr_SetString(ipap11helperError,
                            "Unsupported wrapping mechanism");
            return 0;
    }
    mech->mechanism = mech_type;
    return 1;
}


/***********************************************************************
 * P11_Helper object
 */

static void P11_Helper_dealloc(P11_Helper *self) {
    self->ob_type->tp_free((PyObject *) self);
}

static PyObject *P11_Helper_new(PyTypeObject *type, PyObject *args,
                                PyObject *kwds) {
    P11_Helper *self;

    self = (P11_Helper *) type->tp_alloc(type, 0);
    if (self != NULL) {

        self->slot = 0;
        self->session = 0;
        self->p11 = NULL;
        self->module_handle = NULL;
    }

    return (PyObject *) self;
}

static int P11_Helper_init(P11_Helper *self, PyObject *args, PyObject *kwds) {
    const char *user_pin = NULL;
    const char *library_path = NULL;
    CK_RV rv;
    void *module_handle = NULL;

    /* Parse method args */
    if (!PyArg_ParseTuple(args, "iss", &self->slot, &user_pin, &library_path))
        return -1;

    CK_C_GetFunctionList pGetFunctionList = loadLibrary(library_path,
                                                        &module_handle);
    if (!pGetFunctionList) {
        PyErr_SetString(ipap11helperError, "Could not load the library.");
        return -1;
    }

    self->module_handle = module_handle;

    /*
     * Load the function list
     */
    (*pGetFunctionList)(&self->p11);

    /*
     * Initialize
     */
    rv = self->p11->C_Initialize(NULL);
    if (!check_return_value(rv, "initialize"))
        return -1;

    /*
     *Start session
     */
    rv = self->p11->C_OpenSession(self->slot,
                                  CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL,
                                  NULL, &self->session);
    if (!check_return_value(rv, "open session"))
        return -1;

    /*
     * Login
     */
    rv = self->p11->C_Login(self->session, CKU_USER, (CK_BYTE *) user_pin,
                            strlen((char *) user_pin));
    if (!check_return_value(rv, "log in"))
        return -1;

    return 0;
}

static PyMemberDef P11_Helper_members[] = {
    { NULL }  /* Sentinel */
};

/*
 * Finalize operations with pkcs11 library
 */
static PyObject *P11_Helper_finalize(P11_Helper *self) {
    CK_RV rv;

    if (self->p11 == NULL)
        Py_RETURN_NONE;

    /*
     * Logout
     */
    rv = self->p11->C_Logout(self->session);
    if (rv != CKR_USER_NOT_LOGGED_IN) {
        if (!check_return_value(rv, "log out"))
            return NULL;
    }

    /*
     * End session
     */
    rv = self->p11->C_CloseSession(self->session);
    if (!check_return_value(rv, "close session"))
        return NULL;

    /*
     * Finalize
     */
    self->p11->C_Finalize(NULL);

    unloadLibrary(self->module_handle);

    self->p11 = NULL;
    self->session = 0;
    self->slot = 0;
    self->module_handle = NULL;

    Py_RETURN_NONE;
}

/********************************************************************
 * Methods working with keys
 */

/**
 * Generate master key
 *
 *:return: master key handle
 */
static PyObject *P11_Helper_generate_master_key(P11_Helper *self,
                                                PyObject *args,
                                                PyObject *kwds) {
    PyObj2Bool_mapping_t attrs[] = {
        { NULL, &true },   // sec_en_cka_copyable
        { NULL, &false },  // sec_en_cka_decrypt
        { NULL, &false },  // sec_en_cka_derive
        { NULL, &false },  // sec_en_cka_encrypt
        { NULL, &true },   // sec_en_cka_extractable
        { NULL, &true },   // sec_en_cka_modifiable
        { NULL, &true },   // sec_en_cka_private
        { NULL, &true },   // sec_en_cka_sensitive
        { NULL, &false },  // sec_en_cka_sign
        { NULL, &true },   // sec_en_cka_unwrap
        { NULL, &false },  // sec_en_cka_verify
        { NULL, &true },   // sec_en_cka_wrap
        { NULL, &false }   // sec_en_cka_wrap_with_trusted
    };

    CK_ULONG key_length = 16;
    CK_RV rv;
    CK_OBJECT_HANDLE master_key;
    CK_BYTE *id = NULL;
    int id_length = 0;

    PyObject *label_unicode = NULL;
    Py_ssize_t label_length = 0;
    CK_BYTE *label = NULL;
    int r;
    int error = 0;
    static char *kwlist[] = { "subject", "id", "key_length", "cka_copyable",
        "cka_decrypt", "cka_derive", "cka_encrypt", "cka_extractable",
        "cka_modifiable", "cka_private", "cka_sensitive", "cka_sign",
        "cka_unwrap", "cka_verify", "cka_wrap", "cka_wrap_with_trusted",
        NULL
    };
    //TODO check long overflow
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#|kOOOOOOOOOOOOO", kwlist,
                                     &label_unicode, &id, &id_length,
                                     &key_length,
                                     &attrs[sec_en_cka_copyable].py_obj,
                                     &attrs[sec_en_cka_decrypt].py_obj,
                                     &attrs[sec_en_cka_derive].py_obj,
                                     &attrs[sec_en_cka_encrypt].py_obj,
                                     &attrs[sec_en_cka_extractable].py_obj,
                                     &attrs[sec_en_cka_modifiable].py_obj,
                                     &attrs[sec_en_cka_private].py_obj,
                                     &attrs[sec_en_cka_sensitive].py_obj,
                                     &attrs[sec_en_cka_sign].py_obj,
                                     &attrs[sec_en_cka_unwrap].py_obj,
                                     &attrs[sec_en_cka_verify].py_obj,
                                     &attrs[sec_en_cka_wrap].py_obj,
                                     &attrs
                                     [sec_en_cka_wrap_with_trusted].py_obj)) {
        return NULL;
    }

    label = (unsigned char *) unicode_to_char_array(label_unicode,
                                                    &label_length);
    if (label == NULL)
        GOTO_FAIL;

    CK_MECHANISM mechanism = {  //TODO param?
        CKM_AES_KEY_GEN, NULL_PTR, 0
    };

    if ((key_length != 16) && (key_length != 24) && (key_length != 32)) {
        PyErr_SetString(ipap11helperError,
                        "generate_master_key: key length allowed values are: 16, 24 and 32");
        GOTO_FAIL;
    }

    r = _id_exists(self, id, id_length, CKO_SECRET_KEY);
    if (r == 1) {
        PyErr_SetString(ipap11helperDuplicationError,
                        "Master key with same ID already exists");
        GOTO_FAIL;
    } else if (r == -1) {
        GOTO_FAIL;
    }

    /* Process keyword boolean arguments */
    convert_py2bool(attrs, sizeof(attrs) / sizeof(PyObj2Bool_mapping_t));

    CK_ATTRIBUTE symKeyTemplate[] = {
        { CKA_ID, id, id_length },
        { CKA_LABEL, label, label_length },
        { CKA_TOKEN, &true, sizeof(CK_BBOOL) },
        { CKA_VALUE_LEN, &key_length, sizeof(key_length) },
        //{ CKA_COPYABLE, attrs[sec_en_cka_copyable].bool, sizeof(CK_BBOOL) }, //TODO Softhsm doesn't support it
        { CKA_DECRYPT, attrs[sec_en_cka_decrypt].bool, sizeof(CK_BBOOL) },
        { CKA_DERIVE, attrs[sec_en_cka_derive].bool, sizeof(CK_BBOOL) },
        { CKA_ENCRYPT, attrs[sec_en_cka_encrypt].bool, sizeof(CK_BBOOL) },
        { CKA_EXTRACTABLE, attrs[sec_en_cka_extractable].bool, sizeof(CK_BBOOL) },
        { CKA_MODIFIABLE, attrs[sec_en_cka_modifiable].bool, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, attrs[sec_en_cka_private].bool, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, attrs[sec_en_cka_sensitive].bool, sizeof(CK_BBOOL) },
        { CKA_SIGN, attrs[sec_en_cka_sign].bool, sizeof(CK_BBOOL) },
        { CKA_UNWRAP, attrs[sec_en_cka_unwrap].bool, sizeof(CK_BBOOL) },
        { CKA_VERIFY, attrs[sec_en_cka_verify].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP, attrs[sec_en_cka_wrap].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP_WITH_TRUSTED, attrs[sec_en_cka_wrap_with_trusted].bool, sizeof(CK_BBOOL) }
    };

    rv = self->p11->C_GenerateKey(self->session, &mechanism, symKeyTemplate,
                                  sizeof(symKeyTemplate) /
                                  sizeof(CK_ATTRIBUTE), &master_key);
    if (!check_return_value(rv, "generate master key")) {
        GOTO_FAIL;
    }
final:
    if (label != NULL)
        PyMem_Free(label);

    if (error)
        return NULL;
    return Py_BuildValue("k", master_key);
}

/**
 * Generate replica keys
 *
 * :returns: tuple (public_key_handle, private_key_handle)
 */
static PyObject *P11_Helper_generate_replica_key_pair(P11_Helper *self,
                                                      PyObject *args,
                                                      PyObject *kwds) {
    CK_RV rv;
    int r;
    CK_ULONG modulus_bits = 2048;
    CK_BYTE *id = NULL;
    int id_length = 0;
    PyObject *label_unicode = NULL;
    Py_ssize_t label_length = 0;
    CK_BYTE *label = NULL;
    int error = 0;

    PyObj2Bool_mapping_t attrs_pub[] = {
        { NULL, &true },   // pub_en_cka_copyable
        { NULL, &false },  // pub_en_cka_derive
        { NULL, &false },  // pub_en_cka_encrypt
        { NULL, &true },   // pub_en_cka_modifiable
        { NULL, &true },   // pub_en_cka_private
        { NULL, &false },  // pub_en_cka_trusted
        { NULL, &false },  // pub_en_cka_verify
        { NULL, &false },  // pub_en_cka_verify_recover
        { NULL, &true },   // pub_en_cka_wrap
    };

    PyObj2Bool_mapping_t attrs_priv[] = {
        { NULL, &false },  // priv_en_cka_always_authenticate
        { NULL, &true },   // priv_en_cka_copyable
        { NULL, &false },  // priv_en_cka_decrypt
        { NULL, &false },  // priv_en_cka_derive
        { NULL, &false },  // priv_en_cka_extractable
        { NULL, &true },   // priv_en_cka_modifiable
        { NULL, &true },   // priv_en_cka_private
        { NULL, &true },   // priv_en_cka_sensitive
        { NULL, &false },  // priv_en_cka_sign
        { NULL, &false },  // priv_en_cka_sign_recover
        { NULL, &true },   // priv_en_cka_unwrap
        { NULL, &false }   // priv_en_cka_wrap_with_trusted
    };

    static char *kwlist[] = { "label", "id", "modulus_bits",
        /* public key kw */
        "pub_cka_copyable", "pub_cka_derive", "pub_cka_encrypt",
        "pub_cka_modifiable", "pub_cka_private", "pub_cka_trusted",
        "pub_cka_verify", "pub_cka_verify_recover", "pub_cka_wrap",
        /* private key kw */
        "priv_cka_always_authenticate", "priv_cka_copyable",
        "priv_cka_decrypt", "priv_cka_derive", "priv_cka_extractable",
        "priv_cka_modifiable", "priv_cka_private", "priv_cka_sensitive",
        "priv_cka_sign", "priv_cka_sign_recover", "priv_cka_unwrap",
        "priv_cka_wrap_with_trusted", NULL
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#|kOOOOOOOOOOOOOOOOOOOOO",
                                     kwlist, &label_unicode, &id, &id_length,
                                     &modulus_bits,
                                     /* public key kw */
                                     &attrs_pub[pub_en_cka_copyable].py_obj,
                                     &attrs_pub[pub_en_cka_derive].py_obj,
                                     &attrs_pub[pub_en_cka_encrypt].py_obj,
                                     &attrs_pub[pub_en_cka_modifiable].py_obj,
                                     &attrs_pub[pub_en_cka_private].py_obj,
                                     &attrs_pub[pub_en_cka_trusted].py_obj,
                                     &attrs_pub[pub_en_cka_verify].py_obj,
                                     &attrs_pub[pub_en_cka_verify_recover].py_obj,
                                     &attrs_pub[pub_en_cka_wrap].py_obj,
                                     /* private key kw */
                                     &attrs_priv[priv_en_cka_always_authenticate].py_obj,
                                     &attrs_priv[priv_en_cka_copyable].py_obj,
                                     &attrs_priv[priv_en_cka_decrypt].py_obj,
                                     &attrs_priv[priv_en_cka_derive].py_obj,
                                     &attrs_priv[priv_en_cka_extractable].py_obj,
                                     &attrs_priv[priv_en_cka_modifiable].py_obj,
                                     &attrs_priv[priv_en_cka_private].py_obj,
                                     &attrs_priv[priv_en_cka_sensitive].py_obj,
                                     &attrs_priv[priv_en_cka_sign].py_obj,
                                     &attrs_priv[priv_en_cka_sign_recover].py_obj,
                                     &attrs_priv[priv_en_cka_unwrap].py_obj,
                                     &attrs_priv[priv_en_cka_wrap_with_trusted].py_obj)) {
        return NULL;
    }

    label = unicode_to_char_array(label_unicode, &label_length);
    if (label == NULL)
        GOTO_FAIL;

    CK_OBJECT_HANDLE public_key, private_key;
    CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };

    r = _id_exists(self, id, id_length, CKO_PRIVATE_KEY);
    if (r == 1) {
        PyErr_SetString(ipap11helperDuplicationError,
                        "Private key with same ID already exists");
        GOTO_FAIL;
    } else if (r == -1)
        GOTO_FAIL;

    r = _id_exists(self, id, id_length, CKO_PUBLIC_KEY);
    if (r == 1) {
        PyErr_SetString(ipap11helperDuplicationError,
                        "Public key with same ID already exists");
        GOTO_FAIL;
    } else if (r == -1)
        GOTO_FAIL;

    /* Process keyword boolean arguments */
    convert_py2bool(attrs_pub,
                    sizeof(attrs_pub) / sizeof(PyObj2Bool_mapping_t));
    convert_py2bool(attrs_priv,
                    sizeof(attrs_priv) / sizeof(PyObj2Bool_mapping_t));

    CK_BYTE public_exponent[] = { 1, 0, 1 };  /* 65537 (RFC 6376 section 3.3.1) */
    CK_ATTRIBUTE publicKeyTemplate[] = {
        { CKA_ID, id, id_length },
        { CKA_LABEL, label, label_length },
        { CKA_TOKEN, &true, sizeof(true) },
        { CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits) },
        { CKA_PUBLIC_EXPONENT, public_exponent, 3 },
        //{ CKA_COPYABLE, attrs_pub[pub_en_cka_copyable].bool, sizeof(CK_BBOOL) }, //TODO Softhsm doesn't support it
        { CKA_DERIVE, attrs_pub[pub_en_cka_derive].bool, sizeof(CK_BBOOL) },
        { CKA_ENCRYPT, attrs_pub[pub_en_cka_encrypt].bool, sizeof(CK_BBOOL) },
        { CKA_MODIFIABLE, attrs_pub[pub_en_cka_modifiable].bool, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, attrs_pub[pub_en_cka_private].bool, sizeof(CK_BBOOL) },
        { CKA_TRUSTED, attrs_pub[pub_en_cka_trusted].bool, sizeof(CK_BBOOL) },
        { CKA_VERIFY, attrs_pub[pub_en_cka_verify].bool, sizeof(CK_BBOOL) },
        { CKA_VERIFY_RECOVER, attrs_pub[pub_en_cka_verify_recover].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP, attrs_pub[pub_en_cka_wrap].bool, sizeof(CK_BBOOL) }, };

    CK_ATTRIBUTE privateKeyTemplate[] = {
        { CKA_ID, id, id_length },
        { CKA_LABEL, label, label_length },
        { CKA_TOKEN, &true, sizeof(true) },
        { CKA_ALWAYS_AUTHENTICATE, attrs_priv[priv_en_cka_always_authenticate].bool, sizeof(CK_BBOOL) },
        //{ CKA_COPYABLE, attrs_priv[priv_en_cka_copyable].bool, sizeof(CK_BBOOL) }, //TODO Softhsm doesn't support it
        { CKA_DECRYPT, attrs_priv[priv_en_cka_decrypt].bool, sizeof(CK_BBOOL) },
        { CKA_DERIVE,  attrs_priv[priv_en_cka_derive].bool, sizeof(CK_BBOOL) },
        { CKA_EXTRACTABLE, attrs_priv[priv_en_cka_extractable].bool, sizeof(CK_BBOOL) },
        { CKA_MODIFIABLE, attrs_priv[priv_en_cka_modifiable].bool, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, attrs_priv[priv_en_cka_private].bool, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, attrs_priv[priv_en_cka_sensitive].bool, sizeof(CK_BBOOL) },
        { CKA_SIGN, attrs_priv[priv_en_cka_sign].bool, sizeof(CK_BBOOL) },
        { CKA_SIGN_RECOVER, attrs_priv[priv_en_cka_sign].bool, sizeof(CK_BBOOL) },
        { CKA_UNWRAP, attrs_priv[priv_en_cka_unwrap].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP_WITH_TRUSTED, attrs_priv[priv_en_cka_wrap_with_trusted].bool, sizeof(CK_BBOOL) }
    };

    rv = self->p11->C_GenerateKeyPair(self->session, &mechanism,
                                      publicKeyTemplate,
                                      sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                      privateKeyTemplate,
                                      sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                      &public_key,
                                      &private_key);
    if (!check_return_value(rv, "generate key pair"))
        GOTO_FAIL;

final:
    if (label != NULL)
        PyMem_Free(label);

    if (error)
        return NULL;
    return Py_BuildValue("(kk)", public_key, private_key);
}

/**
 * Find key
 */
static PyObject *P11_Helper_find_keys(P11_Helper *self, PyObject *args,
                                      PyObject *kwds) {
    CK_OBJECT_CLASS class = CKO_VENDOR_DEFINED;
    CK_OBJECT_CLASS *class_ptr = &class;
    CK_BYTE *id = NULL;
    CK_BBOOL *ckawrap = NULL;
    CK_BBOOL *ckaunwrap = NULL;
    int id_length = 0;
    PyObject *label_unicode = NULL;
    PyObject *cka_wrap_bool = NULL;
    PyObject *cka_unwrap_bool = NULL;
    Py_ssize_t label_length = 0;
    CK_OBJECT_HANDLE *objects = NULL;
    unsigned int objects_len = 0;
    PyObject *result_list = NULL;
    const char *uri_str = NULL;
    P11KitUri *uri = NULL;
    CK_BYTE *label = NULL;
    CK_ATTRIBUTE template_static[MAX_TEMPLATE_LEN];
    CK_ATTRIBUTE_PTR template = template_static;
    CK_ULONG template_len = MAX_TEMPLATE_LEN;
    int error = 0;

    static char *kwlist[] = { "objclass", "label", "id", "cka_wrap",
        "cka_unwrap", "uri", NULL
    };
    //TODO check long overflow
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|iUz#OOs", kwlist, &class,
                                     &label_unicode, &id, &id_length,
                                     &cka_wrap_bool, &cka_unwrap_bool,
                                     &uri_str)) {
        GOTO_FAIL;
    }

    if (label_unicode != NULL) {
        label = (unsigned char *) unicode_to_char_array(label_unicode, &label_length);  //TODO verify signed/unsigned
        if (label == NULL)
            GOTO_FAIL;
    }

    if (cka_wrap_bool != NULL) {
        if (PyObject_IsTrue(cka_wrap_bool)) {
            ckawrap = &true;
        } else {
            ckawrap = &false;
        }
    }

    if (cka_unwrap_bool != NULL) {
        if (PyObject_IsTrue(cka_unwrap_bool)) {
            ckaunwrap = &true;
        } else {
            ckaunwrap = &false;
        }
    }

    if (class == CKO_VENDOR_DEFINED)
        class_ptr = NULL;

    if (uri_str == NULL)
        _fill_template_from_parts(template, &template_len, id, id_length,
                                  label, label_length, class_ptr, ckawrap,
                                  ckaunwrap);
    else {
        if (!_parse_uri(uri_str, &uri)) {
            GOTO_FAIL;
        }
        template = p11_kit_uri_get_attributes(uri, &template_len);
        /* Do not deallocate URI while you are using the template.
         * Template contains pointers to values inside URI! */
    }

    if (!_find_key(self, template, template_len, &objects, &objects_len)) {
        GOTO_FAIL;
    }

    result_list = PyList_New(objects_len);
    if (result_list == NULL) {
        PyErr_SetString(ipap11helperError,
                        "Unable to create list with results");
        GOTO_FAIL;
    }

    for (int i = 0; i < objects_len; ++i) {
        if (PyList_SetItem(result_list, i, Py_BuildValue("k", objects[i]))
            == -1) {
            PyErr_SetString(ipap11helperError,
                            "Unable to add to value to result list");
            Py_DECREF(result_list);
            GOTO_FAIL;
        }
    }
final:
    if (label != NULL)
        PyMem_Free(label);
    if (objects != NULL)
        free(objects);
    if (uri != NULL)
        p11_kit_uri_free(uri);

    if (error)
        return NULL;
    return result_list;
}

/**
 * delete key
 */
static PyObject *P11_Helper_delete_key(P11_Helper *self, PyObject *args,
                                       PyObject *kwds) {
    CK_RV rv;
    CK_OBJECT_HANDLE key_handle = 0;
    static char *kwlist[] = { "key_handle", NULL };
    //TODO check long overflow
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|", kwlist, &key_handle)) {
        return NULL;
    }
    rv = self->p11->C_DestroyObject(self->session, key_handle);
    if (!check_return_value(rv, "object deletion")) {
        return NULL;
    }

    Py_RETURN_NONE;
}

/**
 * export RSA public key
 */
static PyObject *P11_Helper_export_RSA_public_key(P11_Helper *self,
                                                  CK_OBJECT_HANDLE object) {
    CK_RV rv;
    PyObject *ret = NULL;

    int pp_len;
    unsigned char *pp = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *e = NULL;
    BIGNUM *n = NULL;
    RSA *rsa = NULL;
    CK_BYTE_PTR modulus = NULL;
    CK_BYTE_PTR exponent = NULL;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    int error = 0;

    CK_ATTRIBUTE obj_template[] = {
        { CKA_MODULUS, NULL_PTR, 0 },
        { CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) }
    };

    rv = self->p11->C_GetAttributeValue(self->session, object, obj_template,
                                        sizeof(obj_template) / sizeof(CK_ATTRIBUTE));
    if (!check_return_value(rv, "get RSA public key values - prepare"))
        GOTO_FAIL;

    /* Set proper size for attributes */
    modulus =
        (CK_BYTE_PTR) PyMem_Malloc(obj_template[0].ulValueLen *
                                   sizeof(CK_BYTE));
    if (modulus == NULL) {
        PyErr_NoMemory();
        GOTO_FAIL;
    }
    obj_template[0].pValue = modulus;
    exponent =
        (CK_BYTE_PTR) PyMem_Malloc(obj_template[1].ulValueLen *
                                   sizeof(CK_BYTE));
    if (exponent == NULL) {
        PyErr_NoMemory();
        GOTO_FAIL;
    }
    obj_template[1].pValue = exponent;

    rv = self->p11->C_GetAttributeValue(self->session, object, obj_template,
                                        sizeof(obj_template) / sizeof(CK_ATTRIBUTE));
    if (!check_return_value(rv, "get RSA public key values")) {
        GOTO_FAIL;
    }

    /* Check if the key is RSA public key */
    if (class != CKO_PUBLIC_KEY) {
        PyErr_SetString(ipap11helperError,
                        "export_RSA_public_key: required public key class");
        GOTO_FAIL;
    }

    if (key_type != CKK_RSA) {
        PyErr_SetString(ipap11helperError,
                        "export_RSA_public_key: required RSA key type");
        GOTO_FAIL;
    }

    rsa = RSA_new();
    pkey = EVP_PKEY_new();
    n = BN_bin2bn((const unsigned char *) modulus,
                  obj_template[0].ulValueLen * sizeof(CK_BYTE), NULL);
    if (n == NULL) {
        PyErr_SetString(ipap11helperError,
                        "export_RSA_public_key: internal error: unable to convert modulus");
        GOTO_FAIL;
    }

    e = BN_bin2bn((const unsigned char *) exponent,
                  obj_template[1].ulValueLen * sizeof(CK_BYTE), NULL);
    if (e == NULL) {
        PyErr_SetString(ipap11helperError,
                        "export_RSA_public_key: internal error: unable to convert exponent");
        GOTO_FAIL;
    }

    /* set modulus and exponent */
    rsa->n = n;
    rsa->e = e;

    if (EVP_PKEY_set1_RSA(pkey, rsa) == 0) {
        PyErr_SetString(ipap11helperError,
                        "export_RSA_public_key: internal error: EVP_PKEY_set1_RSA failed");
        GOTO_FAIL;
    }

    pp_len = i2d_PUBKEY(pkey, &pp);
    ret = Py_BuildValue("s#", pp, pp_len);

final:
    if (rsa != NULL) {
        RSA_free(rsa);  // this frees also 'n' and 'e'
    } else {
        if (n != NULL)
            BN_free(n);
        if (e != NULL)
            BN_free(e);
    }

    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pp != NULL)
        free(pp);
    if (modulus != NULL)
        PyMem_Free(modulus);
    if (exponent != NULL)
        PyMem_Free(exponent);

    if (error)
        return NULL;
    return ret;
}

/**
 * Export public key
 *
 * Export public key in SubjectPublicKeyInfo (RFC5280) DER encoded format
 */
static PyObject *P11_Helper_export_public_key(P11_Helper *self,
                                              PyObject *args, PyObject *kwds) {
    CK_RV rv;
    CK_OBJECT_HANDLE object = 0;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    static char *kwlist[] = { "key_handle", NULL };
    //TODO check long overflow
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "k|", kwlist, &object)) {
        return NULL;
    }

    CK_ATTRIBUTE obj_template[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) }
    };

    rv = self->p11->C_GetAttributeValue(self->session, object, obj_template,
                                        sizeof(obj_template) / sizeof(CK_ATTRIBUTE));
    if (!check_return_value
        (rv, "export_public_key: get RSA public key values"))
        return NULL;

    if (class != CKO_PUBLIC_KEY) {
        PyErr_SetString(ipap11helperError,
                        "export_public_key: required public key class");
        return NULL;
    }

    switch (key_type) {
        case CKK_RSA:
            return P11_Helper_export_RSA_public_key(self, object);
            break;
        default:
            PyErr_SetString(ipap11helperError,
                            "export_public_key: unsupported key type");
    }

    return NULL;
}

/**
 * Import RSA public key
 *
 */
static PyObject *P11_Helper_import_RSA_public_key(P11_Helper *self,
                                                  CK_UTF8CHAR * label,
                                                  Py_ssize_t label_length,
                                                  CK_BYTE * id,
                                                  Py_ssize_t id_length,
                                                  EVP_PKEY * pkey,
                                                  CK_BBOOL *cka_copyable,
                                                  CK_BBOOL *cka_derive,
                                                  CK_BBOOL *cka_encrypt,
                                                  CK_BBOOL *cka_modifiable,
                                                  CK_BBOOL *cka_private,
                                                  CK_BBOOL *cka_trusted,
                                                  CK_BBOOL *cka_verify,
                                                  CK_BBOOL *cka_verify_recover,
                                                  CK_BBOOL *cka_wrap) {
    CK_RV rv;
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL *cka_token = &true;
    RSA *rsa = NULL;
    CK_BYTE_PTR modulus = NULL;
    int modulus_len = 0;
    CK_BYTE_PTR exponent = NULL;
    int exponent_len = 0;
    int error = 0;

    if (pkey->type != EVP_PKEY_RSA) {
        PyErr_SetString(ipap11helperError, "Required RSA public key");
        GOTO_FAIL;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    if (rsa == NULL) {
        PyErr_SetString(ipap11helperError,
                        "import_RSA_public_key: EVP_PKEY_get1_RSA error");
        GOTO_FAIL;
    }

    /* convert BIGNUM to binary array */
    modulus = (CK_BYTE_PTR) PyMem_Malloc(BN_num_bytes(rsa->n));
    if (modulus == NULL) {
        PyErr_NoMemory();
        GOTO_FAIL;
    }
    modulus_len = BN_bn2bin(rsa->n, (unsigned char *) modulus);
    if (modulus_len == 0) {
        PyErr_SetString(ipap11helperError,
                        "import_RSA_public_key: BN_bn2bin modulus error");
        GOTO_FAIL;
    }

    exponent = (CK_BYTE_PTR) PyMem_Malloc(BN_num_bytes(rsa->e));
    if (exponent == NULL) {
        PyErr_NoMemory();
        GOTO_FAIL;
    }
    exponent_len = BN_bn2bin(rsa->e, (unsigned char *) exponent);
    if (exponent_len == 0) {
        PyErr_SetString(ipap11helperError,
                        "import_RSA_public_key: BN_bn2bin exponent error");
        GOTO_FAIL;
    }

    CK_ATTRIBUTE template[] = {
        { CKA_ID, id, id_length },
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_KEY_TYPE, &keyType, sizeof(keyType) },
        { CKA_TOKEN, cka_token, sizeof(CK_BBOOL) },
        { CKA_LABEL, label, label_length },
        { CKA_MODULUS, modulus, modulus_len },
        { CKA_PUBLIC_EXPONENT, exponent, exponent_len },
        //{ CKA_COPYABLE, cka_copyable, sizeof(CK_BBOOL) }, //TODO Softhsm doesn't support it
        { CKA_DERIVE, cka_derive, sizeof(CK_BBOOL) },
        { CKA_ENCRYPT, cka_encrypt, sizeof(CK_BBOOL) },
        { CKA_MODIFIABLE, cka_modifiable, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, cka_private, sizeof(CK_BBOOL) },
        { CKA_TRUSTED, cka_trusted, sizeof(CK_BBOOL) },
        { CKA_VERIFY, cka_verify, sizeof(CK_BBOOL) },
        { CKA_VERIFY_RECOVER, cka_verify_recover, sizeof(CK_BBOOL) },
        { CKA_WRAP, cka_wrap, sizeof(CK_BBOOL) }
    };
    CK_OBJECT_HANDLE object;

    rv = self->p11->C_CreateObject(self->session, template,
                                   sizeof(template) / sizeof(CK_ATTRIBUTE),
                                   &object);
    if (!check_return_value(rv, "create public key object"))
        GOTO_FAIL;

final:
    if (rsa != NULL)
        RSA_free(rsa);
    if (modulus != NULL)
        PyMem_Free(modulus);
    if (exponent != NULL)
        PyMem_Free(exponent);

    if (error)
        return NULL;
    return Py_BuildValue("k", object);
}

/**
 * Import RSA public key
 *
 */
static PyObject *P11_Helper_import_public_key(P11_Helper *self,
                                              PyObject *args, PyObject *kwds) {
    int r;
    PyObject *ret = NULL;
    PyObject *label_unicode = NULL;
    CK_BYTE *id = NULL;
    CK_BYTE *data = NULL;
    CK_UTF8CHAR *label = NULL;
    Py_ssize_t id_length = 0;
    Py_ssize_t data_length = 0;
    Py_ssize_t label_length = 0;
    EVP_PKEY *pkey = NULL;
    int error = 0;

    PyObj2Bool_mapping_t attrs_pub[] = {
        { NULL, &true },   // pub_en_cka_copyable
        { NULL, &false },  // pub_en_cka_derive
        { NULL, &false },  // pub_en_cka_encrypt
        { NULL, &true },   // pub_en_cka_modifiable
        { NULL, &true },   // pub_en_cka_private
        { NULL, &false },  // pub_en_cka_trusted
        { NULL, &true },   // pub_en_cka_verify
        { NULL, &true },   // pub_en_cka_verify_recover
        { NULL, &false },  // pub_en_cka_wrap
    };

    static char *kwlist[] = { "label", "id", "data",
        /* public key attributes */
        "cka_copyable", "cka_derive", "cka_encrypt", "cka_modifiable",
        "cka_private", "cka_trusted", "cka_verify", "cka_verify_recover",
        "cka_wrap", NULL
    };
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#s#|OOOOOOOOO", kwlist,
                                     &label_unicode, &id, &id_length, &data,
                                     &data_length,
                                     /* public key attributes */
                                     &attrs_pub[pub_en_cka_copyable].py_obj,
                                     &attrs_pub[pub_en_cka_derive].py_obj,
                                     &attrs_pub[pub_en_cka_encrypt].py_obj,
                                     &attrs_pub[pub_en_cka_modifiable].py_obj,
                                     &attrs_pub[pub_en_cka_private].py_obj,
                                     &attrs_pub[pub_en_cka_trusted].py_obj,
                                     &attrs_pub[pub_en_cka_verify].py_obj,
                                     &attrs_pub[pub_en_cka_verify_recover].py_obj,
                                     &attrs_pub[pub_en_cka_wrap].py_obj)) {
        return NULL;
    }

    label = (unsigned char *) unicode_to_char_array(label_unicode,
                                                    &label_length);
    if (label == NULL)
        GOTO_FAIL;

    r = _id_exists(self, id, id_length, CKO_PUBLIC_KEY);
    if (r == 1) {
        PyErr_SetString(ipap11helperDuplicationError,
                        "Public key with same ID already exists");
        GOTO_FAIL;
    } else if (r == -1) {
        GOTO_FAIL;
    }

    /* Process keyword boolean arguments */
    convert_py2bool(attrs_pub,
                    sizeof(attrs_pub) / sizeof(PyObj2Bool_mapping_t));

    /* decode from ASN1 DER */
    pkey = d2i_PUBKEY(NULL, (const unsigned char **) &data, data_length);
    if (pkey == NULL) {
        PyErr_SetString(ipap11helperError,
                        "import_public_key: d2i_PUBKEY error");
        GOTO_FAIL;
    }
    switch (pkey->type) {
        case EVP_PKEY_RSA:
            ret = P11_Helper_import_RSA_public_key(self, label, label_length,
                                                   id, id_length, pkey,
                                                   attrs_pub[pub_en_cka_copyable].bool,
                                                   attrs_pub[pub_en_cka_derive].bool,
                                                   attrs_pub[pub_en_cka_encrypt].bool,
                                                   attrs_pub[pub_en_cka_modifiable].bool,
                                                   attrs_pub[pub_en_cka_private].bool,
                                                   attrs_pub[pub_en_cka_trusted].bool,
                                                   attrs_pub[pub_en_cka_verify].bool,
                                                   attrs_pub[pub_en_cka_verify_recover].bool,
                                                   attrs_pub[pub_en_cka_wrap].bool);
            break;
        case EVP_PKEY_DSA:
            error = 1;
            PyErr_SetString(ipap11helperError, "DSA is not supported");
            break;
        case EVP_PKEY_EC:
            error = 1;
            PyErr_SetString(ipap11helperError, "EC is not supported");
            break;
        default:
            error = 1;
            PyErr_SetString(ipap11helperError, "Unsupported key type");
    }
final:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (label != NULL)
        PyMem_Free(label);

    if (error)
        return NULL;
    return ret;
}

/**
 * Export wrapped key
 *
 */
static PyObject *P11_Helper_export_wrapped_key(P11_Helper *self,
                                               PyObject *args,
                                               PyObject *kwds) {
    CK_RV rv;
    CK_OBJECT_HANDLE object_key = 0;
    CK_OBJECT_HANDLE object_wrapping_key = 0;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_key_len = 0;
    CK_MECHANISM wrapping_mech = { CKM_RSA_PKCS, NULL, 0 };
    /* currently we don't support parameter in mechanism */
    PyObject *result = NULL;
    int error = 0;

    static char *kwlist[] = { "key", "wrapping_key", "wrapping_mech", NULL };
    //TODO check long overflow
    //TODO export method
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "kkk|", kwlist, &object_key,
                                     &object_wrapping_key,
                                     &wrapping_mech.mechanism))
        GOTO_FAIL;

    // fill mech parameters
    if (!_set_wrapping_mech_parameters(wrapping_mech.mechanism, &wrapping_mech))
        GOTO_FAIL;

    rv = self->p11->C_WrapKey(self->session, &wrapping_mech,
                              object_wrapping_key, object_key, NULL,
                              &wrapped_key_len);
    if (!check_return_value(rv, "key wrapping: get buffer length"))
        GOTO_FAIL;

    wrapped_key = PyMem_Malloc(wrapped_key_len);
    if (wrapped_key == NULL) {
        PyErr_NoMemory();
        GOTO_FAIL;
    }

    rv = self->p11->C_WrapKey(self->session, &wrapping_mech,
                              object_wrapping_key, object_key, wrapped_key,
                              &wrapped_key_len);
    if (!check_return_value(rv, "key wrapping: wrapping"))
        GOTO_FAIL;

    result = Py_BuildValue("s#", wrapped_key, wrapped_key_len);

final:
    if (wrapped_key != NULL)
        PyMem_Free(wrapped_key);

    if (error)
        return NULL;
    return result;

}

/**
 * Import wrapped secret key
 *
 */
static PyObject *P11_Helper_import_wrapped_secret_key(P11_Helper *self,
                                                      PyObject *args,
                                                      PyObject *kwds) {
    CK_RV rv;
    int r;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_key_len = 0;
    CK_ULONG unwrapping_key_object = 0;
    CK_OBJECT_HANDLE unwrapped_key_object = 0;
    PyObject *label_unicode = NULL;
    CK_BYTE *id = NULL;
    CK_UTF8CHAR *label = NULL;
    Py_ssize_t id_length = 0;
    Py_ssize_t label_length = 0;
    CK_MECHANISM wrapping_mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    int error = 0;

    PyObj2Bool_mapping_t attrs[] = {
        { NULL, &true },   // sec_en_cka_copyable
        { NULL, &false },  // sec_en_cka_decrypt
        { NULL, &false },  // sec_en_cka_derive
        { NULL, &false },  // sec_en_cka_encrypt
        { NULL, &true },   // sec_en_cka_extractable
        { NULL, &true },   // sec_en_cka_modifiable
        { NULL, &true },   // sec_en_cka_private
        { NULL, &true },   // sec_en_cka_sensitive
        { NULL, &false },  // sec_en_cka_sign
        { NULL, &true },   // sec_en_cka_unwrap
        { NULL, &false },  // sec_en_cka_verify
        { NULL, &true },   // sec_en_cka_wrap
        { NULL, &false }   // sec_en_cka_wrap_with_trusted
    };

    static char *kwlist[] = { "label", "id", "data", "unwrapping_key",
        "wrapping_mech", "key_type",
        // secret key attrs
        "cka_copyable", "cka_decrypt", "cka_derive", "cka_encrypt",
        "cka_extractable", "cka_modifiable", "cka_private", "cka_sensitive",
        "cka_sign", "cka_unwrap", "cka_verify", "cka_wrap",
        "cka_wrap_with_trusted", NULL
    };
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#s#kkk|OOOOOOOOOOOOO",
                                     kwlist, &label_unicode, &id, &id_length,
                                     &wrapped_key, &wrapped_key_len,
                                     &unwrapping_key_object,
                                     &wrapping_mech.mechanism, &key_type,
                                     // secret key attrs
                                     &attrs[sec_en_cka_copyable].py_obj,
                                     &attrs[sec_en_cka_decrypt].py_obj,
                                     &attrs[sec_en_cka_derive].py_obj,
                                     &attrs[sec_en_cka_encrypt].py_obj,
                                     &attrs[sec_en_cka_extractable].py_obj,
                                     &attrs[sec_en_cka_modifiable].py_obj,
                                     &attrs[sec_en_cka_private].py_obj,
                                     &attrs[sec_en_cka_sensitive].py_obj,
                                     &attrs[sec_en_cka_sign].py_obj,
                                     &attrs[sec_en_cka_unwrap].py_obj,
                                     &attrs[sec_en_cka_verify].py_obj,
                                     &attrs[sec_en_cka_wrap].py_obj,
                                     &attrs[sec_en_cka_wrap_with_trusted].py_obj)) {
        return NULL;
    }

    if (!_set_wrapping_mech_parameters(wrapping_mech.mechanism, &wrapping_mech))
        return NULL;

    label = (unsigned char *) unicode_to_char_array(label_unicode,
                                                    &label_length);
    if (label == NULL)
        GOTO_FAIL;

    r = _id_exists(self, id, id_length, key_class);
    if (r == 1) {
        PyErr_SetString(ipap11helperDuplicationError,
                        "Secret key with same ID already exists");
        GOTO_FAIL;

    } else if (r == -1)
        GOTO_FAIL;


    /* Process keyword boolean arguments */
    convert_py2bool(attrs, sizeof(attrs) / sizeof(PyObj2Bool_mapping_t));

    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_ID, id, id_length },
        { CKA_LABEL, label, label_length },
        { CKA_TOKEN, &true, sizeof(CK_BBOOL) },
        //{ CKA_COPYABLE, attrs[sec_en_cka_copyable].bool, sizeof(CK_BBOOL) }, //TODO Softhsm doesn't support it
        { CKA_DECRYPT, attrs[sec_en_cka_decrypt].bool, sizeof(CK_BBOOL) },
        { CKA_DERIVE, attrs[sec_en_cka_derive].bool, sizeof(CK_BBOOL) },
        { CKA_ENCRYPT, attrs[sec_en_cka_encrypt].bool, sizeof(CK_BBOOL) },
        { CKA_EXTRACTABLE, attrs[sec_en_cka_extractable].bool, sizeof(CK_BBOOL) },
        { CKA_MODIFIABLE, attrs[sec_en_cka_modifiable].bool, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, attrs[sec_en_cka_private].bool, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, attrs[sec_en_cka_sensitive].bool, sizeof(CK_BBOOL) },
        { CKA_SIGN, attrs[sec_en_cka_sign].bool, sizeof(CK_BBOOL) },
        { CKA_UNWRAP, attrs[sec_en_cka_unwrap].bool, sizeof(CK_BBOOL) },
        { CKA_VERIFY, attrs[sec_en_cka_verify].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP, attrs[sec_en_cka_wrap].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP_WITH_TRUSTED, attrs[sec_en_cka_wrap_with_trusted].bool, sizeof(CK_BBOOL) }
    };

    rv = self->p11->C_UnwrapKey(self->session, &wrapping_mech,
                                unwrapping_key_object, wrapped_key,
                                wrapped_key_len, template,
                                sizeof(template) / sizeof(CK_ATTRIBUTE),
                                &unwrapped_key_object);
    if (!check_return_value(rv, "import_wrapped_key: key unwrapping"))
        GOTO_FAIL;

final:
    if (label != NULL)
        PyMem_Free(label);

    if (error)
        return NULL;

    return Py_BuildValue("k", unwrapped_key_object);
}

/**
 * Import wrapped private key
 *
 */
static PyObject *P11_Helper_import_wrapped_private_key(P11_Helper *self,
                                                       PyObject *args,
                                                       PyObject *kwds) {
    CK_RV rv;
    int r;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_key_len = 0;
    CK_ULONG unwrapping_key_object = 0;
    CK_OBJECT_HANDLE unwrapped_key_object = 0;
    PyObject *label_unicode = NULL;
    CK_BYTE *id = NULL;
    CK_UTF8CHAR *label = NULL;
    Py_ssize_t id_length = 0;
    Py_ssize_t label_length = 0;
    CK_MECHANISM wrapping_mech = { CKM_RSA_PKCS, NULL, 0 };
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_RSA;
    int error = 0;

    PyObj2Bool_mapping_t attrs_priv[] = {
        { NULL, &false },  // priv_en_cka_always_authenticate
        { NULL, &true },   // priv_en_cka_copyable
        { NULL, &false },  // priv_en_cka_decrypt
        { NULL, &false },  // priv_en_cka_derive
        { NULL, &true },   // priv_en_cka_extractable
        { NULL, &true },   // priv_en_cka_modifiable
        { NULL, &true },   // priv_en_cka_private
        { NULL, &true },   // priv_en_cka_sensitive
        { NULL, &true },   // priv_en_cka_sign
        { NULL, &true },   // priv_en_cka_sign_recover
        { NULL, &false },  // priv_en_cka_unwrap
        { NULL, &false }   // priv_en_cka_wrap_with_trusted
    };

    static char *kwlist[] = { "label", "id", "data", "unwrapping_key",
        "wrapping_mech", "key_type",
        // private key attrs
        "cka_always_authenticate", "cka_copyable", "cka_decrypt",
        "cka_derive", "cka_extractable", "cka_modifiable", "cka_private",
        "cka_sensitive", "cka_sign", "cka_sign_recover", "cka_unwrap",
        "cka_wrap_with_trusted", NULL
    };
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "Us#s#kkk|OOOOOOOOOOOO",
                                     kwlist, &label_unicode, &id, &id_length,
                                     &wrapped_key, &wrapped_key_len,
                                     &unwrapping_key_object,
                                     &wrapping_mech.mechanism, &key_type,
                                     // private key attrs
                                     &attrs_priv[priv_en_cka_always_authenticate].py_obj,
                                     &attrs_priv[priv_en_cka_copyable].py_obj,
                                     &attrs_priv[priv_en_cka_decrypt].py_obj,
                                     &attrs_priv[priv_en_cka_derive].py_obj,
                                     &attrs_priv[priv_en_cka_extractable].py_obj,
                                     &attrs_priv[priv_en_cka_modifiable].py_obj,
                                     &attrs_priv[priv_en_cka_private].py_obj,
                                     &attrs_priv[priv_en_cka_sensitive].py_obj,
                                     &attrs_priv[priv_en_cka_sign].py_obj,
                                     &attrs_priv[priv_en_cka_sign_recover].py_obj,
                                     &attrs_priv[priv_en_cka_unwrap].py_obj,
                                     &attrs_priv[priv_en_cka_wrap_with_trusted].py_obj)) {
        return NULL;
    }

    label = (unsigned char *) unicode_to_char_array(label_unicode,
                                                    &label_length);
    if (label == NULL)
        GOTO_FAIL;

    r = _id_exists(self, id, id_length, CKO_SECRET_KEY);
    if (r == 1) {
        PyErr_SetString(ipap11helperDuplicationError,
                        "Secret key with same ID already exists");
        GOTO_FAIL;
    } else if (r == -1) {
        GOTO_FAIL;
    }

    /* Process keyword boolean arguments */
    convert_py2bool(attrs_priv,
                    sizeof(attrs_priv) / sizeof(PyObj2Bool_mapping_t));

    CK_ATTRIBUTE template[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_KEY_TYPE, &key_type, sizeof(key_type) },
        { CKA_ID, id, id_length },
        { CKA_LABEL, label, label_length },
        { CKA_TOKEN, &true, sizeof(CK_BBOOL) },
        { CKA_ALWAYS_AUTHENTICATE, attrs_priv[priv_en_cka_always_authenticate].bool, sizeof(CK_BBOOL) },
        //{ CKA_COPYABLE, attrs_priv[priv_en_cka_copyable].bool, sizeof(CK_BBOOL) }, //TODO Softhsm doesn't support it
        { CKA_DECRYPT, attrs_priv[priv_en_cka_decrypt].bool, sizeof(CK_BBOOL) },
        { CKA_DERIVE, attrs_priv[priv_en_cka_derive].bool, sizeof(CK_BBOOL) },
        { CKA_EXTRACTABLE, attrs_priv[priv_en_cka_extractable].bool, sizeof(CK_BBOOL) },
        { CKA_MODIFIABLE,  attrs_priv[priv_en_cka_modifiable].bool, sizeof(CK_BBOOL) },
        { CKA_PRIVATE, attrs_priv[priv_en_cka_private].bool, sizeof(CK_BBOOL) },
        { CKA_SENSITIVE, attrs_priv[priv_en_cka_sensitive].bool, sizeof(CK_BBOOL) },
        { CKA_SIGN, attrs_priv[priv_en_cka_sign].bool, sizeof(CK_BBOOL) },
        { CKA_SIGN_RECOVER, attrs_priv[priv_en_cka_sign].bool, sizeof(CK_BBOOL) },
        { CKA_UNWRAP, attrs_priv[priv_en_cka_unwrap].bool, sizeof(CK_BBOOL) },
        { CKA_WRAP_WITH_TRUSTED, attrs_priv[priv_en_cka_wrap_with_trusted].bool, sizeof(CK_BBOOL) }
    };

    rv = self->p11->C_UnwrapKey(self->session, &wrapping_mech,
                                unwrapping_key_object, wrapped_key,
                                wrapped_key_len, template,
                                sizeof(template) / sizeof(CK_ATTRIBUTE),
                                &unwrapped_key_object);
    if (!check_return_value(rv, "import_wrapped_key: key unwrapping")) {
        GOTO_FAIL;
    }
final:
    if (label != NULL)
        PyMem_Free(label);

    if (error)
        return NULL;
    return PyLong_FromUnsignedLong(unwrapped_key_object);

}

/*
 * Set object attributes
 */
static PyObject *P11_Helper_set_attribute(P11_Helper *self, PyObject *args,
                                          PyObject *kwds) {
    PyObject *ret = Py_None;
    PyObject *value = NULL;
    CK_ULONG object = 0;
    unsigned long attr = 0;
    CK_ATTRIBUTE attribute;
    CK_RV rv;
    Py_ssize_t len = 0;
    CK_UTF8CHAR *label = NULL;
    int error = 0;

    static char *kwlist[] = { "key_object", "attr", "value", NULL };
    if (!PyArg_ParseTupleAndKeywords
        (args, kwds, "kkO|", kwlist, &object, &attr, &value)) {
        return NULL;
    }

    attribute.type = attr;
    switch (attr) {
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_COPYABLE:
        case CKA_ENCRYPT:
        case CKA_EXTRACTABLE:
        case CKA_DECRYPT:
        case CKA_DERIVE:
        case CKA_LOCAL:
        case CKA_MODIFIABLE:
        case CKA_NEVER_EXTRACTABLE:
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_SIGN:
        case CKA_SIGN_RECOVER:
        case CKA_TOKEN:
        case CKA_TRUSTED:
        case CKA_UNWRAP:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
        case CKA_WRAP:
        case CKA_WRAP_WITH_TRUSTED:
            attribute.pValue = PyObject_IsTrue(value) ? &true : &false;
            attribute.ulValueLen = sizeof(CK_BBOOL);
            break;
        case CKA_ID:
            if (!PyString_Check(value)) {
                PyErr_SetString(ipap11helperError, "String value expected");
                GOTO_FAIL;
            }
            if (PyString_AsStringAndSize(value, (char **) &attribute.pValue,
                                         &len) == -1) {
                GOTO_FAIL;
            }
            attribute.ulValueLen = len;
            break;
        case CKA_LABEL:
            if (!PyUnicode_Check(value)) {
                PyErr_SetString(ipap11helperError, "Unicode value expected");
                GOTO_FAIL;
            }
            label = unicode_to_char_array(value, &len);
            /* check for conversion error */
            if (label == NULL)
                GOTO_FAIL;
            attribute.pValue = label;
            attribute.ulValueLen = len;
            break;
        case CKA_KEY_TYPE:
            if (!PyInt_Check(value)) {
                PyErr_SetString(ipap11helperError, "Integer value expected");
                GOTO_FAIL;
            }
            unsigned long lv = PyInt_AsUnsignedLongMask(value);
            attribute.pValue = &lv;
            attribute.ulValueLen = sizeof(unsigned long);
            break;
        default:
            PyErr_SetString(ipap11helperError, "Unknown attribute");
            GOTO_FAIL;
    }

    CK_ATTRIBUTE template[] = { attribute };

    rv = self->p11->C_SetAttributeValue(self->session, object, template,
                                        sizeof(template) / sizeof(CK_ATTRIBUTE));
    if (!check_return_value(rv, "set_attribute"))
        GOTO_FAIL;

final:
    if (label != NULL)
        PyMem_Free(label);
    Py_XINCREF(ret);

    if (error)
        return NULL;
    return ret;
}

/*
 * Get object attributes
 */
static PyObject *P11_Helper_get_attribute(P11_Helper *self, PyObject *args,
                                          PyObject *kwds) {
    PyObject *ret = NULL;
    void *value = NULL;
    CK_ULONG object = 0;
    unsigned long attr = 0;
    CK_ATTRIBUTE attribute;
    CK_RV rv;
    int error = 0;

    static char *kwlist[] = { "key_object", "attr", NULL };
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "kk|", kwlist, &object,
                                     &attr)) {
        return NULL;
    }

    attribute.type = attr;
    attribute.pValue = NULL_PTR;
    attribute.ulValueLen = 0;
    CK_ATTRIBUTE template[] = { attribute };

    rv = self->p11->C_GetAttributeValue(self->session, object, template,
                                        sizeof(template) / sizeof(CK_ATTRIBUTE));
    // attribute doesn't exists
    if (rv == CKR_ATTRIBUTE_TYPE_INVALID
        || template[0].ulValueLen == (unsigned long) -1) {
        PyErr_SetString(ipap11helperNotFound, "attribute does not exist");
        GOTO_FAIL;
    }
    if (!check_return_value(rv, "get_attribute init")) {
        GOTO_FAIL;
    }
    value = PyMem_Malloc(template[0].ulValueLen);
    if (value == NULL) {
        PyErr_NoMemory();
        GOTO_FAIL;
    }
    template[0].pValue = value;

    rv = self->p11->C_GetAttributeValue(self->session, object, template,
                                        sizeof(template) / sizeof(CK_ATTRIBUTE));
    if (!check_return_value(rv, "get_attribute")) {
        GOTO_FAIL;
    }

    switch (attr) {
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_COPYABLE:
        case CKA_ENCRYPT:
        case CKA_EXTRACTABLE:
        case CKA_DECRYPT:
        case CKA_DERIVE:
        case CKA_LOCAL:
        case CKA_MODIFIABLE:
        case CKA_NEVER_EXTRACTABLE:
        case CKA_PRIVATE:
        case CKA_SENSITIVE:
        case CKA_SIGN:
        case CKA_SIGN_RECOVER:
        case CKA_TOKEN:
        case CKA_TRUSTED:
        case CKA_UNWRAP:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
        case CKA_WRAP:
        case CKA_WRAP_WITH_TRUSTED:
            /* booleans */
            ret = PyBool_FromLong(*(CK_BBOOL *) value);
            break;
        case CKA_LABEL:
            /* unicode string */
            ret = char_array_to_unicode(value, template[0].ulValueLen);
            break;
        case CKA_MODULUS:
        case CKA_PUBLIC_EXPONENT:
        case CKA_ID:
            /* byte arrays */
            ret = Py_BuildValue("s#", value, template[0].ulValueLen);
            break;
        case CKA_KEY_TYPE:
            /* unsigned long */
            ret = Py_BuildValue("k", *(unsigned long *) value);
            break;
        default:
            PyErr_SetString(ipap11helperError, "Unknown attribute");
            GOTO_FAIL;
    }

final:
    if (value != NULL)
        PyMem_Free(value);

    if (error)
        return NULL;
    return ret;
}

static PyMethodDef P11_Helper_methods[] = {
    {
        "finalize",
        (PyCFunction) P11_Helper_finalize,
        METH_NOARGS,
        "Finalize operations with pkcs11 library"
    },
    {
        "generate_master_key",
        (PyCFunction) P11_Helper_generate_master_key,
        METH_VARARGS | METH_KEYWORDS,
        "Generate master key"
    },
    {
        "generate_replica_key_pair",
        (PyCFunction) P11_Helper_generate_replica_key_pair,
        METH_VARARGS | METH_KEYWORDS,
        "Generate replica key pair"
    },
    {
        "find_keys",
        (PyCFunction) P11_Helper_find_keys,
        METH_VARARGS | METH_KEYWORDS,
        "Find keys"
    },
    {
        "delete_key",
        (PyCFunction) P11_Helper_delete_key,
        METH_VARARGS | METH_KEYWORDS,
        "Delete key"
    },
    {
        "export_public_key",
        (PyCFunction) P11_Helper_export_public_key,
        METH_VARARGS | METH_KEYWORDS,
        "Export public key"
    },
    {
        "import_public_key",
        (PyCFunction) P11_Helper_import_public_key,
        METH_VARARGS | METH_KEYWORDS,
        "Import public key"
    },
    {
        "export_wrapped_key",
        (PyCFunction) P11_Helper_export_wrapped_key,
        METH_VARARGS | METH_KEYWORDS,
        "Export wrapped private key"
    },
    {
        "import_wrapped_secret_key",
        (PyCFunction) P11_Helper_import_wrapped_secret_key,
        METH_VARARGS | METH_KEYWORDS,
        "Import wrapped secret key"
    },
    {
        "import_wrapped_private_key",
        (PyCFunction) P11_Helper_import_wrapped_private_key,
        METH_VARARGS | METH_KEYWORDS,
        "Import wrapped private key"
    },
    {
        "set_attribute",
        (PyCFunction) P11_Helper_set_attribute,
        METH_VARARGS | METH_KEYWORDS,
        "Set attribute"
    },
    {
        "get_attribute",
        (PyCFunction) P11_Helper_get_attribute,
        METH_VARARGS | METH_KEYWORDS,
        "Get attribute"
    },
    {
        /* Sentinel */
        NULL
    }
};

static PyTypeObject P11_HelperType = {
    PyObject_HEAD_INIT(NULL) 0, /* ob_size */
    "_ipap11helper.P11_Helper", /* tp_name */
    sizeof(P11_Helper),         /* tp_basicsize */
    0,                          /* tp_itemsize */
    (destructor) P11_Helper_dealloc,  /* tp_dealloc */
    0,                          /* tp_print */
    0,                          /* tp_getattr */
    0,                          /* tp_setattr */
    0,                          /* tp_compare */
    0,                          /* tp_repr */
    0,                          /* tp_as_number */
    0,                          /* tp_as_sequence */
    0,                          /* tp_as_mapping */
    0,                          /* tp_hash */
    0,                          /* tp_call */
    0,                          /* tp_str */
    0,                          /* tp_getattro */
    0,                          /* tp_setattro */
    0,                          /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,  /* tp_flags */
    "P11_Helper objects",       /* tp_doc */
    0,                          /* tp_traverse */
    0,                          /* tp_clear */
    0,                          /* tp_richcompare */
    0,                          /* tp_weaklistoffset */
    0,                          /* tp_iter */
    0,                          /* tp_iternext */
    P11_Helper_methods,         /* tp_methods */
    P11_Helper_members,         /* tp_members */
    0,                          /* tp_getset */
    0,                          /* tp_base */
    0,                          /* tp_dict */
    0,                          /* tp_descr_get */
    0,                          /* tp_descr_set */
    0,                          /* tp_dictoffset */
    (initproc) P11_Helper_init, /* tp_init */
    0,                          /* tp_alloc */
    P11_Helper_new,             /* tp_new */
};

static PyMethodDef module_methods[] = {
    { NULL }  /* Sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif
PyMODINIT_FUNC init_ipap11helper(void) {
    PyObject *m;

    if (PyType_Ready(&P11_HelperType) < 0)
        return;

    /*
     * Setting up P11_Helper module
     */
    m = Py_InitModule3("_ipap11helper", module_methods,
                       "Example module that creates an extension type.");

    if (m == NULL)
        return;

    /*
     * Setting up P11_Helper
     */
    Py_INCREF(&P11_HelperType);
    PyModule_AddObject(m, "P11_Helper", (PyObject *) &P11_HelperType);

    /*
     * Setting up P11_Helper Exceptions
     */
    ipap11helperException = PyErr_NewException("_ipap11helper.Exception", NULL,
                                               NULL);
    Py_INCREF(ipap11helperException);
    PyModule_AddObject(m, "Exception", ipap11helperException);

    ipap11helperError = PyErr_NewException("_ipap11helper.Error",
                                           ipap11helperException, NULL);
    Py_INCREF(ipap11helperError);
    PyModule_AddObject(m, "Error", ipap11helperError);

    ipap11helperNotFound = PyErr_NewException("_ipap11helper.NotFound",
                                              ipap11helperException, NULL);
    Py_INCREF(ipap11helperNotFound);
    PyModule_AddObject(m, "NotFound", ipap11helperNotFound);

    ipap11helperDuplicationError =
        PyErr_NewException("_ipap11helper.DuplicationError",
                           ipap11helperException, NULL);
    Py_INCREF(ipap11helperDuplicationError);
    PyModule_AddObject(m, "DuplicationError", ipap11helperDuplicationError);

    /**
     * Setting up module attributes
     */

    /* Key Classes */
    PyObject *P11_Helper_CLASS_PUBKEY_obj = PyInt_FromLong(CKO_PUBLIC_KEY);
    PyObject_SetAttrString(m, "KEY_CLASS_PUBLIC_KEY",
                           P11_Helper_CLASS_PUBKEY_obj);
    Py_XDECREF(P11_Helper_CLASS_PUBKEY_obj);

    PyObject *P11_Helper_CLASS_PRIVKEY_obj = PyInt_FromLong(CKO_PRIVATE_KEY);
    PyObject_SetAttrString(m, "KEY_CLASS_PRIVATE_KEY",
                           P11_Helper_CLASS_PRIVKEY_obj);
    Py_XDECREF(P11_Helper_CLASS_PRIVKEY_obj);

    PyObject *P11_Helper_CLASS_SECRETKEY_obj = PyInt_FromLong(CKO_SECRET_KEY);
    PyObject_SetAttrString(m, "KEY_CLASS_SECRET_KEY",
                           P11_Helper_CLASS_SECRETKEY_obj);
    Py_XDECREF(P11_Helper_CLASS_SECRETKEY_obj);

    /* Key types */
    PyObject *P11_Helper_KEY_TYPE_RSA_obj = PyInt_FromLong(CKK_RSA);
    PyObject_SetAttrString(m, "KEY_TYPE_RSA", P11_Helper_KEY_TYPE_RSA_obj);
    Py_XDECREF(P11_Helper_KEY_TYPE_RSA_obj);

    PyObject *P11_Helper_KEY_TYPE_AES_obj = PyInt_FromLong(CKK_AES);
    PyObject_SetAttrString(m, "KEY_TYPE_AES", P11_Helper_KEY_TYPE_AES_obj);
    Py_XDECREF(P11_Helper_KEY_TYPE_AES_obj);

    /* Wrapping mech type */
    PyObject *P11_Helper_MECH_RSA_PKCS_obj = PyInt_FromLong(CKM_RSA_PKCS);
    PyObject_SetAttrString(m, "MECH_RSA_PKCS", P11_Helper_MECH_RSA_PKCS_obj);
    Py_XDECREF(P11_Helper_MECH_RSA_PKCS_obj);

    PyObject *P11_Helper_MECH_RSA_PKCS_OAEP_obj =
        PyInt_FromLong(CKM_RSA_PKCS_OAEP);
    PyObject_SetAttrString(m, "MECH_RSA_PKCS_OAEP",
                           P11_Helper_MECH_RSA_PKCS_OAEP_obj);
    Py_XDECREF(P11_Helper_MECH_RSA_PKCS_OAEP_obj);

    PyObject *P11_Helper_MECH_AES_KEY_WRAP_obj =
        PyInt_FromLong(CKM_AES_KEY_WRAP);
    PyObject_SetAttrString(m, "MECH_AES_KEY_WRAP",
                           P11_Helper_MECH_AES_KEY_WRAP_obj);
    Py_XDECREF(P11_Helper_MECH_AES_KEY_WRAP_obj);

    PyObject *P11_Helper_MECH_AES_KEY_WRAP_PAD_obj =
        PyInt_FromLong(CKM_AES_KEY_WRAP_PAD);
    PyObject_SetAttrString(m, "MECH_AES_KEY_WRAP_PAD",
                           P11_Helper_MECH_AES_KEY_WRAP_PAD_obj);
    Py_XDECREF(P11_Helper_MECH_AES_KEY_WRAP_PAD_obj);

    /* Key attributes */
    PyObject *P11_Helper_ATTR_CKA_ALWAYS_AUTHENTICATE_obj =
        PyInt_FromLong(CKA_ALWAYS_AUTHENTICATE);
    PyObject_SetAttrString(m, "CKA_ALWAYS_AUTHENTICATE",
                           P11_Helper_ATTR_CKA_ALWAYS_AUTHENTICATE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_ALWAYS_AUTHENTICATE_obj);

    PyObject *P11_Helper_ATTR_CKA_ALWAYS_SENSITIVE_obj =
        PyInt_FromLong(CKA_ALWAYS_SENSITIVE);
    PyObject_SetAttrString(m, "CKA_ALWAYS_SENSITIVE",
                           P11_Helper_ATTR_CKA_ALWAYS_SENSITIVE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_ALWAYS_SENSITIVE_obj);

    PyObject *P11_Helper_ATTR_CKA_COPYABLE_obj = PyInt_FromLong(CKA_COPYABLE);
    PyObject_SetAttrString(m, "CKA_COPYABLE",
                           P11_Helper_ATTR_CKA_COPYABLE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_COPYABLE_obj);

    PyObject *P11_Helper_ATTR_CKA_DECRYPT_obj = PyInt_FromLong(CKA_DECRYPT);
    PyObject_SetAttrString(m, "CKA_DECRYPT", P11_Helper_ATTR_CKA_DECRYPT_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_DECRYPT_obj);

    PyObject *P11_Helper_ATTR_CKA_DERIVE_obj = PyInt_FromLong(CKA_DERIVE);
    PyObject_SetAttrString(m, "CKA_DERIVE", P11_Helper_ATTR_CKA_DERIVE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_DERIVE_obj);

    PyObject *P11_Helper_ATTR_CKA_ENCRYPT_obj = PyInt_FromLong(CKA_ENCRYPT);
    PyObject_SetAttrString(m, "CKA_ENCRYPT", P11_Helper_ATTR_CKA_ENCRYPT_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_ENCRYPT_obj);

    PyObject *P11_Helper_ATTR_CKA_EXTRACTABLE_obj =
        PyInt_FromLong(CKA_EXTRACTABLE);
    PyObject_SetAttrString(m, "CKA_EXTRACTABLE",
                           P11_Helper_ATTR_CKA_EXTRACTABLE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_EXTRACTABLE_obj);

    PyObject *P11_Helper_ATTR_CKA_ID_obj = PyInt_FromLong(CKA_ID);
    PyObject_SetAttrString(m, "CKA_ID", P11_Helper_ATTR_CKA_ID_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_ID_obj);

    PyObject *P11_Helper_ATTR_CKA_KEY_TYPE_obj = PyInt_FromLong(CKA_KEY_TYPE);
    PyObject_SetAttrString(m, "CKA_KEY_TYPE",
                           P11_Helper_ATTR_CKA_KEY_TYPE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_KEY_TYPE_obj);

    PyObject *P11_Helper_ATTR_CKA_LOCAL_obj = PyInt_FromLong(CKA_LOCAL);
    PyObject_SetAttrString(m, "CKA_LOCAL", P11_Helper_ATTR_CKA_LOCAL_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_LOCAL_obj);

    PyObject *P11_Helper_ATTR_CKA_MODIFIABLE_obj =
        PyInt_FromLong(CKA_MODIFIABLE);
    PyObject_SetAttrString(m, "CKA_MODIFIABLE",
                           P11_Helper_ATTR_CKA_MODIFIABLE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_MODIFIABLE_obj);

    PyObject *P11_Helper_ATTR_CKA_MODULUS_obj = PyInt_FromLong(CKA_MODULUS);
    PyObject_SetAttrString(m, "CKA_MODULUS", P11_Helper_ATTR_CKA_MODULUS_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_MODULUS_obj);

    PyObject *P11_Helper_ATTR_CKA_NEVER_EXTRACTABLE_obj =
        PyInt_FromLong(CKA_NEVER_EXTRACTABLE);
    PyObject_SetAttrString(m, "CKA_NEVER_EXTRACTABLE",
                           P11_Helper_ATTR_CKA_NEVER_EXTRACTABLE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_NEVER_EXTRACTABLE_obj);

    PyObject *P11_Helper_ATTR_CKA_PRIVATE_obj = PyInt_FromLong(CKA_PRIVATE);
    PyObject_SetAttrString(m, "CKA_PRIVATE", P11_Helper_ATTR_CKA_PRIVATE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_PRIVATE_obj);

    PyObject *P11_Helper_ATTR_CKA_PUBLIC_EXPONENT_obj
        = PyInt_FromLong(CKA_PUBLIC_EXPONENT);
    PyObject_SetAttrString(m, "CKA_PUBLIC_EXPONENT",
                           P11_Helper_ATTR_CKA_PUBLIC_EXPONENT_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_PUBLIC_EXPONENT_obj);

    PyObject *P11_Helper_ATTR_CKA_SENSITIVE_obj =
        PyInt_FromLong(CKA_SENSITIVE);
    PyObject_SetAttrString(m, "CKA_SENSITIVE",
                           P11_Helper_ATTR_CKA_SENSITIVE_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_SENSITIVE_obj);

    PyObject *P11_Helper_ATTR_CKA_SIGN_obj = PyInt_FromLong(CKA_SIGN);
    PyObject_SetAttrString(m, "CKA_SIGN", P11_Helper_ATTR_CKA_SIGN_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_SIGN_obj);

    PyObject *P11_Helper_ATTR_CKA_SIGN_RECOVER_obj =
        PyInt_FromLong(CKA_SIGN_RECOVER);
    PyObject_SetAttrString(m, "CKA_SIGN_RECOVER",
                           P11_Helper_ATTR_CKA_SIGN_RECOVER_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_SIGN_RECOVER_obj);

    PyObject *P11_Helper_ATTR_CKA_TRUSTED_obj = PyInt_FromLong(CKA_TRUSTED);
    PyObject_SetAttrString(m, "CKA_TRUSTED", P11_Helper_ATTR_CKA_TRUSTED_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_TRUSTED_obj);

    PyObject *P11_Helper_ATTR_CKA_VERIFY_obj = PyInt_FromLong(CKA_VERIFY);
    PyObject_SetAttrString(m, "CKA_VERIFY", P11_Helper_ATTR_CKA_VERIFY_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_VERIFY_obj);

    PyObject *P11_Helper_ATTR_CKA_VERIFY_RECOVER_obj =
        PyInt_FromLong(CKA_VERIFY_RECOVER);
    PyObject_SetAttrString(m, "CKA_VERIFY_RECOVER",
                           P11_Helper_ATTR_CKA_VERIFY_RECOVER_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_VERIFY_RECOVER_obj);

    PyObject *P11_Helper_ATTR_CKA_UNWRAP_obj = PyInt_FromLong(CKA_UNWRAP);
    PyObject_SetAttrString(m, "CKA_UNWRAP", P11_Helper_ATTR_CKA_UNWRAP_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_UNWRAP_obj);

    PyObject *P11_Helper_ATTR_CKA_WRAP_obj = PyInt_FromLong(CKA_WRAP);
    PyObject_SetAttrString(m, "CKA_WRAP", P11_Helper_ATTR_CKA_WRAP_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_WRAP_obj);

    PyObject *P11_Helper_ATTR_CKA_WRAP_WITH_TRUSTED_obj =
        PyInt_FromLong(CKA_WRAP_WITH_TRUSTED);
    PyObject_SetAttrString(m, "CKA_WRAP_WITH_TRUSTED",
                           P11_Helper_ATTR_CKA_WRAP_WITH_TRUSTED_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_WRAP_WITH_TRUSTED_obj);

    PyObject *P11_Helper_ATTR_CKA_TOKEN_obj = PyInt_FromLong(CKA_TOKEN);
    PyObject_SetAttrString(m, "CKA_TOKEN", P11_Helper_ATTR_CKA_TOKEN_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_TOKEN_obj);

    PyObject *P11_Helper_ATTR_CKA_LABEL_obj = PyInt_FromLong(CKA_LABEL);
    PyObject_SetAttrString(m, "CKA_LABEL", P11_Helper_ATTR_CKA_LABEL_obj);
    Py_XDECREF(P11_Helper_ATTR_CKA_LABEL_obj);

}
