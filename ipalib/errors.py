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
