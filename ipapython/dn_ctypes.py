#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#
"""ctypes wrapper for libldap_str2dn
"""
from __future__ import absolute_import

import ctypes
import ctypes.util

import six

__all__ = ("str2dn", "dn2str", "DECODING_ERROR", "LDAPError")

# load reentrant ldap client library (libldap_r-*.so.2)
ldap_r_lib = ctypes.util.find_library("ldap_r-2")
if ldap_r_lib is None:
    raise ImportError("libldap_r shared library missing")
try:
    lib = ctypes.CDLL(ldap_r_lib)
except OSError as e:
    raise ImportError(str(e))

# constants
LDAP_AVA_FREE_ATTR = 0x0010
LDAP_AVA_FREE_VALUE = 0x0020
LDAP_DECODING_ERROR = -4

# mask for AVA flags
AVA_MASK = ~(LDAP_AVA_FREE_ATTR | LDAP_AVA_FREE_VALUE)


class berval(ctypes.Structure):
    __slots__ = ()
    _fields_ = [("bv_len", ctypes.c_ulong), ("bv_value", ctypes.c_char_p)]

    def __bytes__(self):
        buf = ctypes.create_string_buffer(self.bv_value, self.bv_len)
        return buf.raw

    def __str__(self):
        return self.__bytes__().decode("utf-8")

    if six.PY2:
        __unicode__ = __str__
        __str__ = __bytes__


class LDAPAVA(ctypes.Structure):
    __slots__ = ()
    _fields_ = [
        ("la_attr", berval),
        ("la_value", berval),
        ("la_flags", ctypes.c_uint16),
    ]


# typedef LDAPAVA** LDAPRDN;
LDAPRDN = ctypes.POINTER(ctypes.POINTER(LDAPAVA))
# typedef LDAPRDN* LDAPDN;
LDAPDN = ctypes.POINTER(LDAPRDN)


def errcheck(result, func, arguments):
    if result != 0:
        if result == LDAP_DECODING_ERROR:
            raise DECODING_ERROR
        else:
            msg = ldap_err2string(result)
            raise LDAPError(msg.decode("utf-8"))
    return result


ldap_str2dn = lib.ldap_str2dn
ldap_str2dn.argtypes = (
    ctypes.c_char_p,
    ctypes.POINTER(LDAPDN),
    ctypes.c_uint16,
)
ldap_str2dn.restype = ctypes.c_int16
ldap_str2dn.errcheck = errcheck

ldap_dnfree = lib.ldap_dnfree
ldap_dnfree.argtypes = (LDAPDN,)
ldap_dnfree.restype = None

ldap_err2string = lib.ldap_err2string
ldap_err2string.argtypes = (ctypes.c_int16,)
ldap_err2string.restype = ctypes.c_char_p


class LDAPError(Exception):
    pass


class DECODING_ERROR(LDAPError):
    pass


# RFC 4514, 2.4
_ESCAPE_CHARS = {'"', "+", ",", ";", "<", ">", "'", "\x00"}


def _escape_dn(dn):
    if not dn:
        return ""
    result = []
    # a space or number sign occurring at the beginning of the string
    if dn[0] in {"#", " "}:
        result.append("\\")
    for c in dn:
        if c in _ESCAPE_CHARS:
            result.append("\\")
        result.append(c)
    # a space character occurring at the end of the string
    if len(dn) > 1 and result[-1] == " ":
        # insert before last entry
        result.insert(-1, "\\")
    return "".join(result)


def dn2str(dn):
    return ",".join(
        "+".join(
            "=".join((attr, _escape_dn(value))) for attr, value, _flag in rdn
        )
        for rdn in dn
    )


def str2dn(dn, flags=0):
    if dn is None:
        return []
    if isinstance(dn, six.text_type):
        dn = dn.encode("utf-8")

    ldapdn = LDAPDN()
    try:
        ldap_str2dn(dn, ctypes.byref(ldapdn), flags)

        result = []
        if not ldapdn:
            # empty DN, str2dn("") == []
            return result

        for rdn in ldapdn:
            if not rdn:
                break
            avas = []
            for ava_p in rdn:
                if not ava_p:
                    break
                ava = ava_p[0]
                avas.append(
                    (
                        six.text_type(ava.la_attr),
                        six.text_type(ava.la_value),
                        ava.la_flags & AVA_MASK,
                    )
                )
            result.append(avas)

        return result
    finally:
        ldap_dnfree(ldapdn)
