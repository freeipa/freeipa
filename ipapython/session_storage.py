#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

import ctypes
import sys


KRB5_CC_NOSUPP = -1765328137

if sys.platform == 'darwin':
    LIBKRB5_FILENAME = 'libkrb5.dylib'
else:
    LIBKRB5_FILENAME = 'libkrb5.so.3'

try:
    LIBKRB5 = ctypes.CDLL(LIBKRB5_FILENAME)
except OSError as e:  # pragma: no cover
    raise ImportError(str(e))

krb5_int32 = ctypes.c_int32
krb5_error_code = krb5_int32
krb5_magic = krb5_error_code
krb5_enctype = krb5_int32
krb5_octet = ctypes.c_uint8
krb5_timestamp = krb5_int32

class _krb5_context(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_context"""
    _fields_ = []


class _krb5_ccache(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_ccache"""
    _fields_ = []


class _krb5_data(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_data"""
    _fields_ = [
        ("magic", krb5_magic),
        ("length", ctypes.c_uint),
        ("data", ctypes.c_char_p),
    ]


class krb5_principal_data(ctypes.Structure):  # noqa
    """krb5/krb5.h struct krb5_principal_data"""
    _fields_ = []


class _krb5_keyblock(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_keyblock"""
    _fields_ = [
        ("magic", krb5_magic),
        ("enctype", krb5_enctype),
        ("length", ctypes.c_uint),
        ("contents", ctypes.POINTER(krb5_octet))
    ]


class _krb5_ticket_times(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_ticket_times"""
    _fields_ = [
        ("authtime", krb5_timestamp),
        ("starttime", krb5_timestamp),
        ("endtime", krb5_timestamp),
        ("renew_till", krb5_timestamp),
    ]


class _krb5_address(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_address"""
    _fields_ = []


class _krb5_authdata(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_authdata"""
    _fields_ = []


krb5_principal = ctypes.POINTER(krb5_principal_data)
krb5_keyblock = _krb5_keyblock
krb5_ticket_times = _krb5_ticket_times
krb5_boolean = ctypes.c_uint
krb5_flags = krb5_int32
krb5_data = _krb5_data
krb5_address_p = ctypes.POINTER(_krb5_address)
krb5_authdata_p = ctypes.POINTER(_krb5_authdata)


class _krb5_creds(ctypes.Structure):  # noqa
    """krb5/krb5.h struct _krb5_creds"""
    _fields_ = [
        ("magic", krb5_magic),
        ("client", krb5_principal),
        ("server", krb5_principal),
        ("keyblock", krb5_keyblock),
        ("times", krb5_ticket_times),
        ("is_skey", krb5_boolean),
        ("ticket_flags", krb5_flags),
        ("addresses", ctypes.POINTER(krb5_address_p)),
        ("ticket", krb5_data),
        ("second_ticket", krb5_data),
        ("authdata", ctypes.POINTER(krb5_authdata_p))
    ]


class KRB5Error(Exception):
    pass


def krb5_errcheck(result, func, arguments):
    """Error checker for krb5_error return value"""
    if result != 0:
        raise KRB5Error(result, func.__name__, arguments)


krb5_context = ctypes.POINTER(_krb5_context)
krb5_ccache = ctypes.POINTER(_krb5_ccache)
krb5_data_p = ctypes.POINTER(_krb5_data)
krb5_error = ctypes.c_int32
krb5_creds = _krb5_creds
krb5_pointer = ctypes.c_void_p
krb5_cc_cursor = krb5_pointer

krb5_init_context = LIBKRB5.krb5_init_context
krb5_init_context.argtypes = (ctypes.POINTER(krb5_context), )
krb5_init_context.restype = krb5_error
krb5_init_context.errcheck = krb5_errcheck

krb5_free_context = LIBKRB5.krb5_free_context
krb5_free_context.argtypes = (krb5_context, )
krb5_free_context.restype = None

krb5_free_principal = LIBKRB5.krb5_free_principal
krb5_free_principal.argtypes = (krb5_context, krb5_principal)
krb5_free_principal.restype = None

krb5_free_data_contents = LIBKRB5.krb5_free_data_contents
krb5_free_data_contents.argtypes = (krb5_context, krb5_data_p)
krb5_free_data_contents.restype = None

krb5_cc_default = LIBKRB5.krb5_cc_default
krb5_cc_default.argtypes = (krb5_context, ctypes.POINTER(krb5_ccache), )
krb5_cc_default.restype = krb5_error
krb5_cc_default.errcheck = krb5_errcheck

krb5_cc_close = LIBKRB5.krb5_cc_close
krb5_cc_close.argtypes = (krb5_context, krb5_ccache, )
krb5_cc_close.restype = krb5_error
krb5_cc_close.errcheck = krb5_errcheck

krb5_parse_name = LIBKRB5.krb5_parse_name
krb5_parse_name.argtypes = (krb5_context, ctypes.c_char_p,
                            ctypes.POINTER(krb5_principal), )
krb5_parse_name.restype = krb5_error
krb5_parse_name.errcheck = krb5_errcheck

krb5_cc_set_config = LIBKRB5.krb5_cc_set_config
krb5_cc_set_config.argtypes = (krb5_context, krb5_ccache, krb5_principal,
                               ctypes.c_char_p, krb5_data_p, )
krb5_cc_set_config.restype = krb5_error
krb5_cc_set_config.errcheck = krb5_errcheck

krb5_cc_get_principal = LIBKRB5.krb5_cc_get_principal
krb5_cc_get_principal.argtypes = (krb5_context, krb5_ccache,
                                  ctypes.POINTER(krb5_principal), )
krb5_cc_get_principal.restype = krb5_error
krb5_cc_get_principal.errcheck = krb5_errcheck

# krb5_build_principal is a variadic function but that can't be expressed
# in a ctypes argtypes definition, so I explicitly listed the number of
# arguments we actually use through the code for type checking purposes
krb5_build_principal = LIBKRB5.krb5_build_principal
krb5_build_principal.argtypes = (krb5_context, ctypes.POINTER(krb5_principal),
                                 ctypes.c_uint, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_char_p, )
krb5_build_principal.restype = krb5_error
krb5_build_principal.errcheck = krb5_errcheck

krb5_cc_start_seq_get = LIBKRB5.krb5_cc_start_seq_get
krb5_cc_start_seq_get.argtypes = (krb5_context, krb5_ccache,
                                  ctypes.POINTER(krb5_cc_cursor), )
krb5_cc_start_seq_get.restype = krb5_error
krb5_cc_start_seq_get.errcheck = krb5_errcheck

krb5_cc_next_cred = LIBKRB5.krb5_cc_next_cred
krb5_cc_next_cred.argtypes = (krb5_context, krb5_ccache,
                              ctypes.POINTER(krb5_cc_cursor),
                              ctypes.POINTER(krb5_creds), )
krb5_cc_next_cred.restype = krb5_error
krb5_cc_next_cred.errcheck = krb5_errcheck

krb5_cc_end_seq_get = LIBKRB5.krb5_cc_end_seq_get
krb5_cc_end_seq_get.argtypes = (krb5_context, krb5_ccache,
                                ctypes.POINTER(krb5_cc_cursor), )
krb5_cc_end_seq_get.restype = krb5_error
krb5_cc_end_seq_get.errcheck = krb5_errcheck

krb5_free_cred_contents = LIBKRB5.krb5_free_cred_contents
krb5_free_cred_contents.argtypes = (krb5_context, ctypes.POINTER(krb5_creds))
krb5_free_cred_contents.restype = krb5_error
krb5_free_cred_contents.errcheck = krb5_errcheck

krb5_principal_compare = LIBKRB5.krb5_principal_compare
krb5_principal_compare.argtypes = (krb5_context, krb5_principal,
                                   krb5_principal, )
krb5_principal_compare.restype = krb5_boolean

krb5_unparse_name = LIBKRB5.krb5_unparse_name
krb5_unparse_name.argtypes = (krb5_context, krb5_principal,
                              ctypes.POINTER(ctypes.c_char_p), )
krb5_unparse_name.restype = krb5_error
krb5_unparse_name.errcheck = krb5_errcheck

krb5_free_unparsed_name = LIBKRB5.krb5_free_unparsed_name
krb5_free_unparsed_name.argtypes = (krb5_context, ctypes.c_char_p, )
krb5_free_unparsed_name.restype = None

CONF_REALM = b"X-CACHECONF:"
CONF_NAME = b"krb5_ccache_conf_data"


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

    # FILE ccaches grow every time an entry is stored, so we need
    # to avoid storing the same entry multiple times.
    oldvalue = get_data(princ_name, key)
    if oldvalue == value:
        return

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
    srv_princ = krb5_principal()
    ccache = krb5_ccache()
    pname_princ = krb5_principal()
    pname = ctypes.c_char_p()

    try:
        krb5_init_context(ctypes.byref(context))

        krb5_cc_default(context, ctypes.byref(ccache))
        krb5_cc_get_principal(context, ccache, ctypes.byref(principal))

        # We need to parse and then unparse the name in case the pric_name
        # passed in comes w/o a realm attached
        krb5_parse_name(context, ctypes.c_char_p(princ_name),
                        ctypes.byref(pname_princ))
        krb5_unparse_name(context, pname_princ, ctypes.byref(pname))

        krb5_build_principal(context, ctypes.byref(srv_princ),
                             len(CONF_REALM), ctypes.c_char_p(CONF_REALM),
                             ctypes.c_char_p(CONF_NAME), ctypes.c_char_p(key),
                             pname, ctypes.c_char_p(None))

        # Unfortunately we can't just use krb5_cc_get_config()
        # because of bugs in some ccache handling code in krb5
        # libraries that would always return the first entry
        # stored and not the last one, which is the one we want.
        cursor = krb5_cc_cursor()
        creds = krb5_creds()
        got_creds = False
        krb5_cc_start_seq_get(context, ccache, ctypes.byref(cursor))
        try:
            while True:
                checkcreds = krb5_creds()
                # the next function will throw an error and break out of the
                # while loop when we try to access past the last cred
                krb5_cc_next_cred(context, ccache, ctypes.byref(cursor),
                                  ctypes.byref(checkcreds))
                if (krb5_principal_compare(context, principal,
                                          checkcreds.client) == 1 and
                    krb5_principal_compare(context, srv_princ,
                                           checkcreds.server) == 1):
                    if got_creds:
                        krb5_free_cred_contents(context, ctypes.byref(creds))
                    creds = checkcreds
                    got_creds = True
                    # We do not stop here, as we want the LAST entry
                    # in the ccache for those ccaches that cannot delete
                    # but only always append, like FILE
                else:
                    krb5_free_cred_contents(context,
                                            ctypes.byref(checkcreds))
        except KRB5Error:
            pass
        finally:
            krb5_cc_end_seq_get(context, ccache, ctypes.byref(cursor))

        if got_creds:
            data = creds.ticket.data
            krb5_free_cred_contents(context, ctypes.byref(creds))
            return data

    finally:
        if principal:
            krb5_free_principal(context, principal)
        if srv_princ:
            krb5_free_principal(context, srv_princ)
        if pname_princ:
            krb5_free_principal(context, pname_princ)
        if pname:
            krb5_free_unparsed_name(context, pname)
        if ccache:
            krb5_cc_close(context, ccache)
        if context:
            krb5_free_context(context)
    return None


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
