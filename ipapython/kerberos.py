#
# Copyright (C) 2016-2024 FreeIPA Contributors see COPYING for license
#

"""
classes/utils for Kerberos operations using MIT Kerberos libraries
"""

import ctypes
import re
import six
import sys

from ipapython.ipautil import escape_seq, unescape_seq

if six.PY3:
    unicode = str

REALM_SPLIT_RE = re.compile(r'(?<!\\)@')
COMPONENT_SPLIT_RE = re.compile(r'(?<!\\)/')


def parse_princ_name_and_realm(principal, realm=None):
    """
    split principal to the <principal_name>, <realm> components

    :param principal: unicode representation of principal
    :param realm: if not None, replace the parsed realm with the specified one

    :returns: tuple containing the principal name and realm
        realm will be `None` if no realm was found in the input string
    """
    realm_and_name = REALM_SPLIT_RE.split(principal)
    if len(realm_and_name) > 2:
        raise ValueError(
            "Principal is not in <name>@<realm> format")

    principal_name = realm_and_name[0]

    try:
        parsed_realm = realm_and_name[1]
    except IndexError:
        parsed_realm = None if realm is None else realm

    return principal_name, parsed_realm


def split_principal_name(principal_name):
    """
    Split principal name (without realm) into the components

    NOTE: operates on the following RFC 1510 types:
        * NT-PRINCIPAL
        * NT-SRV-INST
        * NT-SRV-HST

    Enterprise principals (NT-ENTERPRISE, see RFC 6806) are also handled

    :param principal_name: unicode representation of principal name
    :returns: tuple of individual components (i.e. primary name for
    NT-PRINCIPAL and NT-ENTERPRISE, primary name and instance for others)
    """
    return tuple(COMPONENT_SPLIT_RE.split(principal_name))


@six.python_2_unicode_compatible
class Principal:
    """
    Container for the principal name and realm according to RFC 1510
    """
    def __init__(self, components, realm=None):
        if isinstance(components, bytes):
            raise TypeError(
                "Cannot create a principal object from bytes: {!r}".format(
                    components)
            )
        elif isinstance(components, str):
            # parse principal components from realm
            self.components, self.realm = self._parse_from_text(
                components, realm)

        elif isinstance(components, Principal):
            self.components = components.components
            self.realm = components.realm if realm is None else realm
        else:
            self.components = tuple(components)
            self.realm = realm

    def __eq__(self, other):
        if not isinstance(other, Principal):
            return False

        return (self.components == other.components and
                self.realm == other.realm)

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return unicode(self) < unicode(other)

    def __le__(self, other):
        return self.__lt__(other) or self.__eq__(other)

    def __gt__(self, other):
        return not self.__le__(other)

    def __ge__(self, other):
        return self.__gt__(other) or self.__eq__(other)

    def __hash__(self):
        return hash(self.components + (self.realm,))

    def _parse_from_text(self, principal, realm=None):
        r"""
        parse individual principal name components from the string
        representation of the principal. This is done in three steps:
            1.) split the string at the unescaped '@'
            2.) unescape any leftover '\@' sequences
            3.) split the primary at the unescaped '/'
            4.) unescape leftover '\/'
        :param principal: unicode representation of the principal name
        :param realm: if not None, this realm name will be used instead of the
            one parsed from `principal`

        :returns: tuple containing the principal name components and realm
        """
        principal_name, parsed_realm = parse_princ_name_and_realm(
            principal, realm=realm)

        (principal_name,) = unescape_seq(u'@', principal_name)

        if parsed_realm is not None:
            (parsed_realm,) = unescape_seq(u'@', parsed_realm)

        name_components = split_principal_name(principal_name)
        name_components = unescape_seq(u'/', *name_components)

        return name_components, parsed_realm

    @property
    def is_user(self):
        return len(self.components) == 1

    @property
    def is_enterprise(self):
        return self.is_user and u'@' in self.components[0]

    @property
    def is_service(self):
        return len(self.components) > 1

    @property
    def is_host(self):
        return (self.is_service and len(self.components) == 2 and
                self.components[0] == u'host')

    @property
    def username(self):
        if self.is_user:
            return self.components[0]
        else:
            raise ValueError(
                "User name is defined only for user and enterprise principals")

    @property
    def upn_suffix(self):
        if not self.is_enterprise:
            raise ValueError("Only enterprise principals have UPN suffix")

        return self.components[0].split(u'@')[1]

    @property
    def hostname(self):
        if not (self.is_host or self.is_service):
            raise ValueError(
                "hostname is defined for host and service principals")
        return self.components[-1]

    @property
    def service_name(self):
        if not self.is_service:
            raise ValueError(
                "Only service principals have meaningful service name")

        return u'/'.join(c for c in escape_seq('/', *self.components[:-1]))

    def __str__(self):
        """
        return the unicode representation of principal

        works in reverse of the `from_text` class method
        """
        name_components = escape_seq(u'/', *self.components)
        name_components = escape_seq(u'@', *name_components)

        principal_string = u'/'.join(name_components)

        if self.realm is not None:
            (realm,) = escape_seq(u'@', self.realm)
            principal_string = u'@'.join([principal_string, realm])

        return principal_string

    def __repr__(self):
        return "{0.__module__}.{0.__name__}('{1}')".format(
            self.__class__, self)


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
    """Error checker for krb5_error_code return value"""
    if result != 0:
        raise KRB5Error(result, func.__name__, arguments)


krb5_context = ctypes.POINTER(_krb5_context)
krb5_ccache = ctypes.POINTER(_krb5_ccache)
krb5_data_p = ctypes.POINTER(_krb5_data)
krb5_creds = _krb5_creds
krb5_pointer = ctypes.c_void_p
krb5_cc_cursor = krb5_pointer

krb5_init_context = LIBKRB5.krb5_init_context
krb5_init_context.argtypes = (ctypes.POINTER(krb5_context), )
krb5_init_context.restype = krb5_error_code
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
krb5_cc_default.restype = krb5_error_code
krb5_cc_default.errcheck = krb5_errcheck

krb5_cc_close = LIBKRB5.krb5_cc_close
krb5_cc_close.argtypes = (krb5_context, krb5_ccache, )
krb5_cc_close.restype = krb5_error_code
krb5_cc_close.errcheck = krb5_errcheck

krb5_parse_name = LIBKRB5.krb5_parse_name
krb5_parse_name.argtypes = (krb5_context, ctypes.c_char_p,
                            ctypes.POINTER(krb5_principal), )
krb5_parse_name.restype = krb5_error_code
krb5_parse_name.errcheck = krb5_errcheck

krb5_cc_set_config = LIBKRB5.krb5_cc_set_config
krb5_cc_set_config.argtypes = (krb5_context, krb5_ccache, krb5_principal,
                               ctypes.c_char_p, krb5_data_p, )
krb5_cc_set_config.restype = krb5_error_code
krb5_cc_set_config.errcheck = krb5_errcheck

krb5_cc_get_principal = LIBKRB5.krb5_cc_get_principal
krb5_cc_get_principal.argtypes = (krb5_context, krb5_ccache,
                                  ctypes.POINTER(krb5_principal), )
krb5_cc_get_principal.restype = krb5_error_code
krb5_cc_get_principal.errcheck = krb5_errcheck

# krb5_build_principal is a variadic function but that can't be expressed
# in a ctypes argtypes definition, so I explicitly listed the number of
# arguments we actually use through the code for type checking purposes
krb5_build_principal = LIBKRB5.krb5_build_principal
krb5_build_principal.argtypes = (krb5_context, ctypes.POINTER(krb5_principal),
                                 ctypes.c_uint, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_char_p,
                                 ctypes.c_char_p, ctypes.c_char_p, )
krb5_build_principal.restype = krb5_error_code
krb5_build_principal.errcheck = krb5_errcheck

krb5_cc_start_seq_get = LIBKRB5.krb5_cc_start_seq_get
krb5_cc_start_seq_get.argtypes = (krb5_context, krb5_ccache,
                                  ctypes.POINTER(krb5_cc_cursor), )
krb5_cc_start_seq_get.restype = krb5_error_code
krb5_cc_start_seq_get.errcheck = krb5_errcheck

krb5_cc_next_cred = LIBKRB5.krb5_cc_next_cred
krb5_cc_next_cred.argtypes = (krb5_context, krb5_ccache,
                              ctypes.POINTER(krb5_cc_cursor),
                              ctypes.POINTER(krb5_creds), )
krb5_cc_next_cred.restype = krb5_error_code
krb5_cc_next_cred.errcheck = krb5_errcheck

krb5_cc_end_seq_get = LIBKRB5.krb5_cc_end_seq_get
krb5_cc_end_seq_get.argtypes = (krb5_context, krb5_ccache,
                                ctypes.POINTER(krb5_cc_cursor), )
krb5_cc_end_seq_get.restype = krb5_error_code
krb5_cc_end_seq_get.errcheck = krb5_errcheck

krb5_free_cred_contents = LIBKRB5.krb5_free_cred_contents
krb5_free_cred_contents.argtypes = (krb5_context, ctypes.POINTER(krb5_creds))
krb5_free_cred_contents.restype = None

krb5_principal_compare = LIBKRB5.krb5_principal_compare
krb5_principal_compare.argtypes = (krb5_context, krb5_principal,
                                   krb5_principal, )
krb5_principal_compare.restype = krb5_boolean

krb5_unparse_name = LIBKRB5.krb5_unparse_name
krb5_unparse_name.argtypes = (krb5_context, krb5_principal,
                              ctypes.POINTER(ctypes.c_char_p), )
krb5_unparse_name.restype = krb5_error_code
krb5_unparse_name.errcheck = krb5_errcheck

krb5_free_unparsed_name = LIBKRB5.krb5_free_unparsed_name
krb5_free_unparsed_name.argtypes = (krb5_context, ctypes.c_char_p, )
krb5_free_unparsed_name.restype = None
