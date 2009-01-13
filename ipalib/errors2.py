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
Custom exception classes (some which are RPC transparent).

`PrivateError` and its subclasses are custom IPA excetions that will *never* be
forwarded in a Remote Procedure Call (RPC) response.

On the other hand, `PublicError` and its subclasses can be forwarded in an RPC
response.  These public errors each carry a unique integer error code as well as
a gettext translated error message (translated at the time the exception is
raised).  The purpose of the public errors is to relay information about
*expected* user errors, service availability errors, and so on.  They should
*never* be used for *unexpected* programmatic or run-time errors.

For security reasons it is *extremely* important that arbitrary exceptions *not*
be forwarded in an RPC response.  Unexpected exceptions can easily contain
compromising information in their error messages.  Any time the server catches
any exception that isn't a `PublicError` subclass, it should raise an
`InternalError`, which itself always has the same, static error message (and
therefore cannot be populated with information about the true exception).

The public errors are arranging into five main blocks of error code ranges:

    =============  ========================================
     Error codes                 Exceptions
    =============  ========================================
    1000 - 1999    `AuthenticationError` and its subclasses
    2000 - 2999    `AuthorizationError` and its subclasses
    3000 - 3999    `InvocationError` and its subclasses
    4000 - 4999    `ExecutionError` and its subclasses
    5000 - 5999    `GenericError` and its subclasses
    =============  ========================================

Within these five blocks some sub-ranges are already allocated for certain types
of error messages, while others are reserved for future use.  Here are the
current block assignments:

    - **900-5999** `PublicError` and its subclasses

        - **901 - 907**  Assigned to special top-level public errors

        - **908 - 999**  *Reserved for future use*

        - **1000 - 1999**  `AuthenticationError` and its subclasses

            - **1001 - 1099**  Open for general authentication errors

            - **1100 - 1199**  `KerberosError` and its subclasses

            - **1200 - 1999**  *Reserved for future use*

        - **2000 - 2999**  `AuthorizationError` and its subclasses

            - **2001 - 2099**  Open for general authorization errors

            - **2100 - 2199**  `ACIError` and its subclasses

            - **2200 - 2999**  *Reserved for future use*

        - **3000 - 3999**  `InvocationError` and its subclasses

            - **3001 - 3099**  Open for general invocation errors

            - **3100 - 3199**  *Reserved for future use*

        - **4000 - 4999**  `ExecutionError` and its subclasses

            - **4001 - 4099**  Open for general execution errors

            - **4100 - 4199**  `LDAPError` and its subclasses

            - **4300 - 4999**  *Reserved for future use*

        - **5000 - 5999**  `GenericError` and its subclasses

            - **5001 - 5099**  Open for generic errors

            - **5100 - 5999**  *Reserved for future use*
"""

from inspect import isclass
from request import ugettext, ungettext
from constants import TYPE_ERROR


class PrivateError(StandardError):
    """
    Base class for exceptions that are *never* forwarded in an RPC response.
    """

    format = ''

    def __init__(self, **kw):
        self.message = self.format % kw
        for (key, value) in kw.iteritems():
            assert not hasattr(self, key), 'conflicting kwarg %s.%s = %r' % (
                self.__class__.__name__, key, value,
            )
            setattr(self, key, value)
        StandardError.__init__(self, self.message)


class SubprocessError(PrivateError):
    """
    Raised when ``subprocess.call()`` returns a non-zero exit status.

    This custom exception is needed because Python 2.4 doesn't have the
    ``subprocess.CalledProcessError`` exception (which was added in Python 2.5).

    For example:

    >>> raise SubprocessError(returncode=2, argv=('ls', '-lh', '/no-foo/'))
    Traceback (most recent call last):
      ...
    SubprocessError: return code 2 from ('ls', '-lh', '/no-foo/')

    The exit code of the sub-process is available via the ``returncode``
    instance attribute.  For example:

    >>> e = SubprocessError(returncode=1, argv=('/bin/false',))
    >>> e.returncode
    1
    >>> e.argv  # argv is also available
    ('/bin/false',)
    """

    format = 'return code %(returncode)d from %(argv)r'


class PluginSubclassError(PrivateError):
    """
    Raised when a plugin doesn't subclass from an allowed base.

    For example:

    >>> raise PluginSubclassError(plugin='bad', bases=('base1', 'base2'))
    Traceback (most recent call last):
      ...
    PluginSubclassError: 'bad' not subclass of any base in ('base1', 'base2')

    """

    format  = '%(plugin)r not subclass of any base in %(bases)r'


class PluginDuplicateError(PrivateError):
    """
    Raised when the same plugin class is registered more than once.

    For example:

    >>> raise PluginDuplicateError(plugin='my_plugin')
    Traceback (most recent call last):
      ...
    PluginDuplicateError: 'my_plugin' was already registered
    """

    format = '%(plugin)r was already registered'


class PluginOverrideError(PrivateError):
    """
    Raised when a plugin overrides another without using ``override=True``.

    For example:

    >>> raise PluginOverrideError(base='Command', name='env', plugin='my_env')
    Traceback (most recent call last):
      ...
    PluginOverrideError: unexpected override of Command.env with 'my_env'
    """

    format = 'unexpected override of %(base)s.%(name)s with %(plugin)r'


class PluginMissingOverrideError(PrivateError):
    """
    Raised when a plugin overrides another that has not been registered.

    For example:

    >>> raise PluginMissingOverrideError(base='Command', name='env', plugin='my_env')
    Traceback (most recent call last):
      ...
    PluginMissingOverrideError: Command.env not registered, cannot override with 'my_env'
    """

    format = '%(base)s.%(name)s not registered, cannot override with %(plugin)r'



##############################################################################
# Public errors:

__messages = []

def _(message):
    __messages.append(message)
    return message


class PublicError(StandardError):
    """
    **900** Base class for exceptions that can be forwarded in an RPC response.
    """

    errno = 900
    format = None

    def __init__(self, format=None, message=None, **kw):
        name = self.__class__.__name__
        if self.format is not None and format is not None:
            raise ValueError(
                'non-generic %r needs format=None; got format=%r' % (
                    name, format)
            )
        if message is None:
            if self.format is None:
                if format is None:
                    raise ValueError(
                        '%s.format is None yet format=None, message=None' % name
                    )
                self.format = format
            self.forwarded = False
            self.message = self.format % kw
            self.strerror = ugettext(self.format) % kw
        else:
            if type(message) is not unicode:
                raise TypeError(
                    TYPE_ERROR % ('message', unicode, message, type(message))
                )
            self.forwarded = True
            self.message = message
            self.strerror = message
        for (key, value) in kw.iteritems():
            assert not hasattr(self, key), 'conflicting kwarg %s.%s = %r' % (
                name, key, value,
            )
            setattr(self, key, value)
        StandardError.__init__(self, self.message)


class VersionError(PublicError):
    """
    **901** Raised when client and server versions are incompatible.

    For example:

    >>> raise VersionError(cver='2.0', sver='2.1', server='https://localhost')
    Traceback (most recent call last):
      ...
    VersionError: 2.0 client incompatible with 2.1 server at 'https://localhost'

    """

    errno = 901
    format = _('%(cver)s client incompatible with %(sver)s server at %(server)r')



class InternalError(PublicError):
    """
    **902** Raised to conceal a non-public exception.

    For example:

    >>> raise InternalError()
    Traceback (most recent call last):
      ...
    InternalError: an internal error has occured
    """

    errno = 902
    format = _('an internal error has occured')

    def __init__(self, message=None):
        """
        Security issue: ignore any information given to constructor.
        """
        PublicError.__init__(self)


class ServerInternalError(PublicError):
    """
    **903** Raised when client catches an `InternalError` from server.

    For example:

    >>> raise ServerInternalError(server='https://localhost')
    Traceback (most recent call last):
      ...
    ServerInternalError: an internal error has occured on server at 'https://localhost'
    """

    errno = 903
    format = _('an internal error has occured on server at %(server)r')


class CommandError(PublicError):
    """
    **904** Raised when an unknown command is called.

    For example:

    >>> raise CommandError(name='foobar')
    Traceback (most recent call last):
      ...
    CommandError: unknown command 'foobar'
    """

    errno = 904
    format = _('unknown command %(name)r')


class ServerCommandError(PublicError):
    """
    **905** Raised when client catches a `CommandError` from server.

    For example:

    >>> e = CommandError(name='foobar')
    >>> raise ServerCommandError(error=e.message, server='https://localhost')
    Traceback (most recent call last):
      ...
    ServerCommandError: error on server 'https://localhost': unknown command 'foobar'
    """

    errno = 905
    format = _('error on server %(server)r: %(error)s')


class NetworkError(PublicError):
    """
    **906** Raised when a network connection cannot be created.

    For example:

    >>> raise NetworkError(uri='ldap://localhost:389')
    Traceback (most recent call last):
      ...
    NetworkError: cannot connect to 'ldap://localhost:389'
    """

    errno = 906
    format = _('cannot connect to %(uri)r')


class ServerNetworkError(PublicError):
    """
    **907** Raised when client catches a `NetworkError` from server.

    For example:

    >>> e = NetworkError(uri='ldap://localhost:389')
    >>> raise ServerNetworkError(error=e.message, server='https://localhost')
    Traceback (most recent call last):
      ...
    ServerNetworkError: error on server 'https://localhost': cannot connect to 'ldap://localhost:389'
    """

    errno = 907
    format = _('error on server %(server)r: %(error)s')



##############################################################################
# 1000 - 1999: Authentication errors
class AuthenticationError(PublicError):
    """
    **1000** Base class for authentication errors (*1000 - 1999*).
    """

    errno = 1000


class KerberosError(AuthenticationError):
    """
    **1100** Base class for Kerberos authentication errors (*1100 - 1199*).
    """

    errno = 1100



##############################################################################
# 2000 - 2999: Authorization errors
class AuthorizationError(PublicError):
    """
    **2000** Base class for authorization errors (*2000 - 2999*).
    """

    errno = 2000


class ACIError(AuthorizationError):
    """
    **2100** Base class for ACI authorization errors (*2100 - 2199*).
    """

    errno = 2100



##############################################################################
# 3000 - 3999: Invocation errors

class InvocationError(PublicError):
    """
    **3000** Base class for command invocation errors (*3000 - 3999*).
    """

    errno = 3000


class EncodingError(InvocationError):
    """
    **3001** Raised when received text is incorrectly encoded.
    """

    errno = 3001


class BinaryEncodingError(InvocationError):
    """
    **3002** Raised when received binary data is incorrectly encoded.
    """

    errno = 3002


class ArgumentError(InvocationError):
    """
    **3003** Raised when a command is called with wrong number of arguments.
    """

    errno = 3003


class OptionError(InvocationError):
    """
    **3004** Raised when a command is called with unknown options.
    """

    errno = 3004


class RequirementError(InvocationError):
    """
    **3005** Raised when a required parameter is not provided.

    For example:

    >>> raise RequirementError(name='givenname')
    Traceback (most recent call last):
      ...
    RequirementError: 'givenname' is required
    """

    errno = 3005
    format = _('%(name)r is required')


class ConversionError(InvocationError):
    """
    **3006** Raised when parameter value can't be converted to correct type.

    For example:

    >>> raise ConversionError(name='age', error='must be an integer')
    Traceback (most recent call last):
      ...
    ConversionError: invalid 'age': must be an integer
    """

    errno = 3006
    format = _('invalid %(name)r: %(error)s')


class ValidationError(InvocationError):
    """
    **3007** Raised when a parameter value fails a validation rule.

    For example:

    >>> raise ValidationError(name='sn', error='can be at most 128 characters')
    Traceback (most recent call last):
      ...
    ValidationError: invalid 'sn': can be at most 128 characters
    """

    errno = 3007
    format = _('invalid %(name)r: %(error)s')



##############################################################################
# 4000 - 4999: Execution errors

class ExecutionError(PublicError):
    """
    **4000** Base class for execution errors (*4000 - 4999*).
    """

    errno = 4000


class LDAPError(ExecutionError):
    """
    **4100** Base class for LDAP execution errors (*4100 - 4199*).
    """

    errno = 4100



##############################################################################
# 5000 - 5999: Generic errors

class GenericError(PublicError):
    """
    **5000** Base class for errors that don't fit elsewhere (*5000 - 5999*).
    """

    errno = 5000



def __errors_iter():
    """
    Iterate through all the `PublicError` subclasses.
    """
    for (key, value) in globals().items():
        if key.startswith('_') or not isclass(value):
            continue
        if issubclass(value, PublicError):
            yield value

public_errors = tuple(
    sorted(__errors_iter(), key=lambda E: E.errno)
)

if __name__ == '__main__':
    for klass in public_errors:
        print '%d\t%s' % (klass.code, klass.__name__)
    print '(%d public errors)' % len(public_errors)
