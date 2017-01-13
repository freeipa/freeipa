#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#

"""
classes/utils for Kerberos principal name validation/manipulation
"""
import re
import six

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
class Principal(object):
    """
    Container for the principal name and realm according to RFC 1510
    """
    def __init__(self, components, realm=None):
        if isinstance(components, six.binary_type):
            raise TypeError(
                "Cannot create a principal object from bytes: {!r}".format(
                    components)
            )
        elif isinstance(components, six.string_types):
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

    def __hash__(self):
        return hash(self.components + (self.realm,))

    def _parse_from_text(self, principal, realm=None):
        """
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
