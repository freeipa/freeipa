#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import ctypes


KRB5_CC_NOSUPP = -1765328137


try:
    LIBKRB5 = ctypes.CDLL('libkrb5.so.3')
except OSError as e:  # pragma: no cover
    raise ImportError(str(e))


class _krb5_context(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_context"""
    _fields_ = []


class _krb5_ccache(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_ccache"""
    _fields_ = []


class _krb5_data(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_data"""
    _fields_ = [
        ("magic", ctypes.c_int32),
        ("length", ctypes.c_uint),
        ("data", ctypes.c_char_p),
    ]


class krb5_principal_data(ctypes.Structure):  # noqa
    """krb5/krb5.h struct krb5_principal_data"""
    _fields_ = []


class KRB5Error(Exception):
    pass


def krb5_errcheck(result, func, arguments):
    """Error checker for krb5_error return value"""
    if result != 0:
        raise KRB5Error(result, func.__name__, arguments)


krb5_principal = ctypes.POINTER(krb5_principal_data)
krb5_context = ctypes.POINTER(_krb5_context)
krb5_ccache = ctypes.POINTER(_krb5_ccache)
krb5_data_p = ctypes.POINTER(_krb5_data)
krb5_error = ctypes.c_int32

krb5_init_context = LIBKRB5.krb5_init_context
krb5_init_context.argtypes = (ctypes.POINTER(krb5_context), )
krb5_init_context.restype = krb5_error
krb5_init_context.errcheck = krb5_errcheck

krb5_free_context = LIBKRB5.krb5_free_context
krb5_free_context.argtypes = (krb5_context, )
krb5_free_context.retval = None

krb5_free_principal = LIBKRB5.krb5_free_principal
krb5_free_principal.argtypes = (krb5_context, krb5_principal)
krb5_free_principal.retval = None

krb5_free_data_contents = LIBKRB5.krb5_free_data_contents
krb5_free_data_contents.argtypes = (krb5_context, krb5_data_p)
krb5_free_data_contents.retval = None

krb5_cc_default = LIBKRB5.krb5_cc_default
krb5_cc_default.argtypes = (krb5_context, ctypes.POINTER(krb5_ccache), )
krb5_cc_default.restype = krb5_error
krb5_cc_default.errcheck = krb5_errcheck

krb5_cc_close = LIBKRB5.krb5_cc_close
krb5_cc_close.argtypes = (krb5_context, krb5_ccache, )
krb5_cc_close.retval = krb5_error
krb5_cc_close.errcheck = krb5_errcheck

krb5_parse_name = LIBKRB5.krb5_parse_name
krb5_parse_name.argtypes = (krb5_context, ctypes.c_char_p,
                            ctypes.POINTER(krb5_principal), )
krb5_parse_name.retval = krb5_error
krb5_parse_name.errcheck = krb5_errcheck

krb5_cc_set_config = LIBKRB5.krb5_cc_set_config
krb5_cc_set_config.argtypes = (krb5_context, krb5_ccache, krb5_principal,
                               ctypes.c_char_p, krb5_data_p, )
krb5_cc_set_config.retval = krb5_error
krb5_cc_set_config.errcheck = krb5_errcheck

krb5_cc_get_config = LIBKRB5.krb5_cc_get_config
krb5_cc_get_config.argtypes = (krb5_context, krb5_ccache, krb5_principal,
                               ctypes.c_char_p, krb5_data_p, )
krb5_cc_get_config.retval = krb5_error
krb5_cc_get_config.errcheck = krb5_errcheck


def store_data(princ_name, key, value):
    """
    Stores the session cookie in a hidden ccache entry.
    """
    if not isinstance(princ_name, bytes):
        princ_name = princ_name.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('ascii')
    if not isinstance(value, bytes):
        value = value.encode('utf-8')

    context = krb5_context()
    principal = krb5_principal()
    ccache = krb5_ccache()

    try:
        krb5_init_context(ctypes.byref(context))

        krb5_parse_name(context, ctypes.c_char_p(princ_name),
                        ctypes.byref(principal))

        krb5_cc_default(context, ctypes.byref(ccache))

        buf = ctypes.create_string_buffer(value)
        data = _krb5_data()
        data.data = buf.value
        data.length = len(buf)
        krb5_cc_set_config(context, ccache, principal, key,
                           ctypes.byref(data))

    finally:
        if principal:
            krb5_free_principal(context, principal)
        if ccache:
            krb5_cc_close(context, ccache)
        if context:
            krb5_free_context(context)


def get_data(princ_name, key):
    """
    Gets the session cookie in a hidden ccache entry.
    """
    if not isinstance(princ_name, bytes):
        princ_name = princ_name.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('utf-8')

    context = krb5_context()
    principal = krb5_principal()
    ccache = krb5_ccache()
    data = _krb5_data()

    try:
        krb5_init_context(ctypes.byref(context))

        krb5_parse_name(context, ctypes.c_char_p(princ_name),
                        ctypes.byref(principal))

        krb5_cc_default(context, ctypes.byref(ccache))

        krb5_cc_get_config(context, ccache, principal, key,
                           ctypes.byref(data))

        return data.data.decode('utf-8')

    finally:
        if principal:
            krb5_free_principal(context, principal)
        if ccache:
            krb5_cc_close(context, ccache)
        if data:
            krb5_free_data_contents(context, data)
        if context:
            krb5_free_context(context)


def remove_data(princ_name, key):
    """
    Removes the hidden ccache entry with the session cookie.
    """
    if not isinstance(princ_name, bytes):
        princ_name = princ_name.encode('utf-8')
    if not isinstance(key, bytes):
        key = key.encode('utf-8')

    context = krb5_context()
    principal = krb5_principal()
    ccache = krb5_ccache()

    try:
        krb5_init_context(ctypes.byref(context))

        krb5_parse_name(context, ctypes.c_char_p(princ_name),
                        ctypes.byref(principal))

        krb5_cc_default(context, ctypes.byref(ccache))

        try:
            krb5_cc_set_config(context, ccache, principal, key, None)
        except KRB5Error as e:
            if e.args[0] == KRB5_CC_NOSUPP:
                # removal not supported with this CC type, just pass
                pass

    finally:
        if principal:
            krb5_free_principal(context, principal)
        if ccache:
          krb5_cc_close(context, ccache)
        if context:
            krb5_free_context(context)
