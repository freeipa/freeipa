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
Custom exception classes.

Certain errors can be returned in RPC response to relay some error condition
to the caller.

    =============  ========================================
     Error codes                 Exceptions
    =============  ========================================
    900            `PublicError`
    901            `InternalError`
    902 - 999      *Reserved for future use*
    1000 - 1999    `AuthenticationError` and its subclasses
    2000 - 2999    `AuthorizationError` and its subclasses
    3000 - 3999    `InvocationError` and its subclasses
    4000 - 4999    `ExecutionError` and its subclasses
    5000 - 5999    `GenericError` and its subclasses
    =============  ========================================
"""

from inspect import isclass
from request import ugettext, ungettext


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
class PublicError(StandardError):
    """
    **900** Base class for exceptions that can be forwarded in an RPC response.
    """

    code = 900

    def __init__(self, message=None, **kw):
        self.kw = kw
        if message is None:
            message = self.get_format() % kw
        StandardError.__init__(self, message)

    def get_format(self, _):
        return _('')



class InternalError(PublicError):
    """
    **901** Used to conceal a non-public exception.
    """

    code = 901



##############################################################################
# 1000 - 1999: Authentication errors
class AuthenticationError(PublicError):
    """
    **1000** Base class for authentication errors (*1000 - 1999*).
    """

    code = 1000



##############################################################################
# 2000 - 2999: Authorization errors
class AuthorizationError(PublicError):
    """
    **2000** Base class for authorization errors (*2000 - 2999*).
    """

    code = 2000



##############################################################################
# 3000 - 3999: Invocation errors

class InvocationError(PublicError):
    """
    **3000** Base class for command invocation errors (*3000 - 3999*).
    """

    code = 3000


class CommandError(InvocationError):
    """
    **3001** Raised when an unknown command is called.
    """

    code = 3001

    def get_format(self, _):
        return _('Unknown command %(name)r')


class RemoteCommandError(InvocationError):
    """
    **3002** Raised when client receives a `CommandError` from server.
    """

    code = 3002


class ArgumentError(InvocationError):
    """
    **3003** Raised when a command is called with wrong number of arguments.
    """

    code = 3003


class OptionError(InvocationError):
    """
    **3004** Raised when a command is called with unknown options.
    """

    code = 3004


class RequirementError(InvocationError):
    """
    **3005** Raised when a required parameter is not provided.
    """

    code = 3005


class ConversionError(InvocationError):
    """
    **3006** Raised when a parameter value is the wrong type.
    """

    code = 3006


class ValidationError(InvocationError):
    """
    **3007** Raised when a parameter value fails a validation rule.
    """

    code = 3007



##############################################################################
# 4000 - 4999: Execution errors

class ExecutionError(PublicError):
    """
    **4000** Base class for execution/operation errors (*4000 - 4999*).
    """

    code = 4000



##############################################################################
# 5000 - 5999: Generic errors

class GenericError(PublicError):
    """
    **5000** Errors inappropriate for other categories (*5000 - 5999*).
    """

    code = 5000



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
    sorted(__errors_iter(), key=lambda E: E.code)
)

if __name__ == '__main__':
    for klass in public_errors:
        print '%d\t%s' % (klass.code, klass.__name__)
    print '(%d public errors)' % len(public_errors)
