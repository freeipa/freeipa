# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty inmsgion
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
All custom errors raised by `ipalib` package.

Also includes a few utility functions for raising exceptions.
"""

TYPE_FORMAT = '%s: need a %r; got %r'

def raise_TypeError(value, type_, name):
    """
    Raises a TypeError with a nicely formatted message and helpful attributes.

    The TypeError raised will have three custom attributes:

        ``value`` - The value (of incorrect type) passed as argument.

        ``type`` - The type expected for the argument.

        ``name`` - The name (identifier) of the argument in question.

    There is no edict that all TypeError should be raised with raise_TypeError,
    but when it fits, use it... it makes the unit tests faster to write and
    the debugging easier to read.

    Here is an example:

    >>> raise_TypeError(u'Hello, world!', str, 'message')
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "ipalib/errors.py", line 65, in raise_TypeError
        raise e
    TypeError: message: need a <type 'str'>; got u'Hello, world!'

    :param value: The value (of incorrect type) passed as argument.
    :param type_: The type expected for the argument.
    :param name: The name (identifier) of the argument in question.
    """

    assert type(type_) is type, TYPE_FORMAT % ('type_', type, type_)
    assert type(value) is not type_, 'value: %r is a %r' % (value, type_)
    assert type(name) is str, TYPE_FORMAT % ('name', str, name)
    e = TypeError(TYPE_FORMAT % (name, type_, value))
    setattr(e, 'value', value)
    setattr(e, 'type', type_)
    setattr(e, 'name', name)
    raise e


def check_type(value, type_, name, allow_none=False):
    assert type(name) is str, TYPE_FORMAT % ('name', str, name)
    assert type(type_) is type, TYPE_FORMAT % ('type_', type, type_)
    assert type(allow_none) is bool, TYPE_FORMAT % ('allow_none', bool, allow_none)
    if value is None and allow_none:
        return
    if type(value) is not type_:
        raise_TypeError(value, type_, name)
    return value


def check_isinstance(value, type_, name, allow_none=False):
    assert type(type_) is type, TYPE_FORMAT % ('type_', type, type_)
    assert type(name) is str, TYPE_FORMAT % ('name', str, name)
    assert type(allow_none) is bool, TYPE_FORMAT % ('allow_none', bool, allow_none)
    if value is None and allow_none:
        return
    if not isinstance(value, type_):
        raise_TypeError(value, type_, name)
    return value


class IPAError(Exception):
    """
    Base class for all custom IPA errors.

    Use this base class for your custom IPA errors unless there is a
    specific reason to subclass from AttributeError, KeyError, etc.
    """

    format = None

    def __init__(self, *args):
        self.args = args

    def __str__(self):
        """
        Returns the string representation of this exception.
        """
        return self.format % self.args


class ArgumentError(IPAError):
    """
    Raised when a command is called with wrong number of arguments.
    """

    format = '%s %s'

    def __init__(self, command, error):
        self.command = command
        self.error = error
        IPAError.__init__(self, command.name, error)


class ValidationError(IPAError):
    """
    Base class for all types of validation errors.
    """

    format = 'invalid %r value %r: %s'

    def __init__(self, name, value, error, index=None):
        """
        :param name: The name of the value that failed validation.
        :param value: The value that failed validation.
        :param error: The error message describing the failure.
        :param index: If multivalue, index of value in multivalue tuple
        """
        assert type(name) is str
        assert index is None or (type(index) is int and index >= 0)
        self.name = name
        self.value = value
        self.error = error
        self.index = index
        IPAError.__init__(self, name, value, error)


class ConversionError(ValidationError):
    """
    Raised when a value cannot be converted to the correct type.
    """

    def __init__(self, name, value, type_, index=None):
        self.type = type_
        ValidationError.__init__(self, name, value, type_.conversion_error,
            index=index,
        )


class RuleError(ValidationError):
    """
    Raised when a value fails a validation rule.
    """
    def __init__(self, name, value, error, rule, index=None):
        assert callable(rule)
        self.rule = rule
        ValidationError.__init__(self, name, value, error, index=index)


class RequirementError(ValidationError):
    """
    Raised when a required option was not provided.
    """
    def __init__(self, name):
        ValidationError.__init__(self, name, None, 'Required')


class RegistrationError(IPAError):
    """
    Base class for errors that occur during plugin registration.
    """


class NameSpaceError(RegistrationError):
    msg = 'name %r does not re.match %r'


class SubclassError(RegistrationError):
    """
    Raised when registering a plugin that is not a subclass of one of the
    allowed bases.
    """
    msg = 'plugin %r not subclass of any base in %r'

    def __init__(self, cls, allowed):
        self.cls = cls
        self.allowed = allowed

    def __str__(self):
        return self.msg % (self.cls, self.allowed)


class DuplicateError(RegistrationError):
    """
    Raised when registering a plugin whose exact class has already been
    registered.
    """
    msg = '%r at %d was already registered'

    def __init__(self, cls):
        self.cls = cls

    def __str__(self):
        return self.msg % (self.cls, id(self.cls))


class OverrideError(RegistrationError):
    """
    Raised when override=False yet registering a plugin that overrides an
    existing plugin in the same namespace.
    """
    msg = 'unexpected override of %s.%s with %r (use override=True if intended)'

    def __init__(self, base, cls):
        self.base = base
        self.cls = cls

    def __str__(self):
        return self.msg % (self.base.__name__, self.cls.__name__, self.cls)


class MissingOverrideError(RegistrationError):
    """
    Raised when override=True yet no preexisting plugin with the same name
    and base has been registered.
    """
    msg = '%s.%s has not been registered, cannot override with %r'

    def __init__(self, base, cls):
        self.base = base
        self.cls = cls

    def __str__(self):
        return self.msg % (self.base.__name__, self.cls.__name__, self.cls)

class GenericError(IPAError):
    """Base class for our custom exceptions"""
    faultCode = 1000
    fromFault = False
    def __str__(self):
        try:
            return str(self.args[0]['args'][0])
        except:
            try:
                return str(self.args[0])
            except:
                return str(self.__dict__)

class DatabaseError(GenericError):
    """A database error has occurred"""
    faultCode = 1001

class MidairCollision(GenericError):
    """Change collided with another change"""
    faultCode = 1002

class NotFound(GenericError):
    """Entry not found"""
    faultCode = 1003

class DuplicateEntry(GenericError):
    """This entry already exists"""
    faultCode = 1004

class MissingDN(GenericError):
    """The distinguished name (DN) is missing"""
    faultCode = 1005

class EmptyModlist(GenericError):
    """No modifications to be performed"""
    faultCode = 1006

class InputError(GenericError):
    """Error on input"""
    faultCode = 1007

class SameGroupError(InputError):
    """You can't add a group to itself"""
    faultCode = 1008

class NotGroupMember(InputError):
    """This entry is not a member of the group"""
    faultCode = 1009

class AdminsImmutable(InputError):
    """The admins group cannot be renamed"""
    faultCode = 1010

class UsernameTooLong(InputError):
    """The requested username is too long"""
    faultCode = 1011

class PrincipalError(GenericError):
    """There is a problem with the kerberos principal"""
    faultCode = 1012

class MalformedServicePrincipal(PrincipalError):
    """The requested service principal is not of the form: service/fully-qualified host name"""
    faultCode = 1013

class RealmMismatch(PrincipalError):
    """The realm for the principal does not match the realm for this IPA server"""
    faultCode = 1014

class PrincipalRequired(PrincipalError):
    """You cannot remove IPA server service principals"""
    faultCode = 1015

class InactivationError(GenericError):
    """This entry cannot be inactivated"""
    faultCode = 1016

class AlreadyActiveError(InactivationError):
    """This entry is already locked"""
    faultCode = 1017

class AlreadyInactiveError(InactivationError):
    """This entry is already unlocked"""
    faultCode = 1018

class HasNSAccountLock(InactivationError):
    """This entry appears to have the nsAccountLock attribute in it so the Class of Service activation/inactivation will not work. You will need to remove the attribute nsAccountLock for this to work."""
    faultCode = 1019

class ConnectionError(GenericError):
    """Connection to database failed"""
    faultCode = 1020

class NoCCacheError(GenericError):
    """No Kerberos credentials cache is available. Connection cannot be made"""
    faultCode = 1021

class GSSAPIError(GenericError):
    """GSSAPI Authorization error"""
    faultCode = 1022

class ServerUnwilling(GenericError):
    """Account inactivated. Server is unwilling to perform"""
    faultCode = 1023

class ConfigurationError(GenericError):
    """A configuration error occurred"""
    faultCode = 1024

class DefaultGroup(ConfigurationError):
    """You cannot remove the default users group"""
    faultCode = 1025

class FunctionDeprecated(GenericError):
    """Raised by a deprecated function"""
    faultCode = 2000

def convertFault(fault):
    """Convert a fault to the corresponding Exception type, if possible"""
    code = getattr(fault,'faultCode',None)
    if code is None:
        return fault
    for v in globals().values():
        if type(v) == type(Exception) and issubclass(v,GenericError) and \
            code == getattr(v,'faultCode',None):
            ret = v(fault.faultString)
            ret.fromFault = True
            return ret
    #otherwise...
    return fault

def listFaults():
    """Return a list of faults

    Returns a list of dictionaries whose keys are:
        faultCode: the numeric code used in fault conversion
        name: the name of the exception
        desc: the description of the exception (docstring)
    """
    ret = []
    for n,v in globals().items():
        if type(v) == type(Exception) and issubclass(v,GenericError):
            code = getattr(v,'faultCode',None)
            if code is None:
                continue
            info = {}
            info['faultCode'] = code
            info['name'] = n
            info['desc'] = getattr(v,'__doc__',None)
            ret.append(info)
    ret.sort(lambda a,b: cmp(a['faultCode'],b['faultCode']))
    return ret
