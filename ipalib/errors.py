# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008-2016  Red Hat
# see file 'COPYING' for use and warranty inmsgion
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

            - **1200 - 1299**  `SessionError` and its subclasses

            - **1300 - 1999**  *Reserved for future use*

        - **2000 - 2999**  `AuthorizationError` and its subclasses

            - **2001 - 2099**  Open for general authorization errors

            - **2100 - 2199**  `ACIError` and its subclasses

            - **2200 - 2999**  *Reserved for future use*

        - **3000 - 3999**  `InvocationError` and its subclasses

            - **3001 - 3099**  Open for general invocation errors

            - **3100 - 3199**  *Reserved for future use*

        - **4000 - 4999**  `ExecutionError` and its subclasses

            - **4001 - 4099**  Open for general execution errors

            - **4100 - 4199**  `BuiltinError` and its subclasses

            - **4200 - 4299**  `LDAPError` and its subclasses

            - **4300 - 4399**  `CertificateError` and its subclasses

            - **4400 - 4499**  `DNSError` and (some of) its subclasses

            - **4500 - 4999**  *Reserved for future use*

        - **5000 - 5999**  `GenericError` and its subclasses

            - **5001 - 5099**  Open for generic errors

            - **5100 - 5999**  *Reserved for future use*
"""

import six

from ipalib.text import ngettext as ungettext
from ipalib import messages


class PrivateError(Exception):
    """
    Base class for exceptions that are *never* forwarded in an RPC response.
    """

    format = ''

    def __init__(self, **kw):
        self.msg = self.format % kw
        self.kw = kw
        for (key, value) in kw.items():
            assert not hasattr(self, key), 'conflicting kwarg %s.%s = %r' % (
                self.__class__.__name__, key, value,
            )
            setattr(self, key, value)
        Exception.__init__(self, self.msg)

    if six.PY3:
        @property
        def message(self):
            return str(self)


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

    format = '%(plugin)r not subclass of any base in %(bases)r'


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


class SkipPluginModule(PrivateError):
    """
    Raised to abort the loading of a plugin module.
    """

    format = '%(reason)s'


class PluginsPackageError(PrivateError):
    """
    Raised when ``package.plugins`` is a module instead of a sub-package.
    """

    format = '%(name)s must be sub-package, not module: %(file)r'


class PluginModuleError(PrivateError):
    """
    Raised when a module is not a valid plugin module.
    """

    format = '%(name)s is not a valid plugin module'


##############################################################################
# Public errors:

_texts = []

def _(message):
    _texts.append(message)
    return message


class PublicError(Exception):
    """
    **900** Base class for exceptions that can be forwarded in an RPC response.
    """
    def __init__(self, format=None, message=None, **kw):
        messages.process_message_arguments(self, format, message, **kw)
        super(PublicError, self).__init__(self.msg)

    errno = 900
    rval = 1
    format = None

    if six.PY3:
        @property
        def message(self):
            return str(self)


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
    format = _("%(cver)s client incompatible with %(sver)s server at '%(server)s'")


class UnknownError(PublicError):
    """
    **902** Raised when client does not know error it caught from server.

    For example:

    >>> raise UnknownError(code=57, server='localhost', error=u'a new error')
    ...
    Traceback (most recent call last):
      ...
    UnknownError: unknown error 57 from localhost: a new error

    """

    errno = 902
    format = _('unknown error %(code)d from %(server)s: %(error)s')


class InternalError(PublicError):
    """
    **903** Raised to conceal a non-public exception.

    For example:

    >>> raise InternalError()
    Traceback (most recent call last):
      ...
    InternalError: an internal error has occurred
    """

    errno = 903
    format = _('an internal error has occurred')

    def __init__(self, message=None):
        """
        Security issue: ignore any information given to constructor.
        """
        PublicError.__init__(self)


class ServerInternalError(PublicError):
    """
    **904** Raised when client catches an `InternalError` from server.

    For example:

    >>> raise ServerInternalError(server='https://localhost')
    Traceback (most recent call last):
      ...
    ServerInternalError: an internal error has occurred on server at 'https://localhost'
    """

    errno = 904
    format = _("an internal error has occurred on server at '%(server)s'")


class CommandError(PublicError):
    """
    **905** Raised when an unknown command is called.

    For example:

    >>> raise CommandError(name='foobar')
    Traceback (most recent call last):
      ...
    CommandError: unknown command 'foobar'
    """

    errno = 905
    format = _("unknown command '%(name)s'")


class ServerCommandError(PublicError):
    """
    **906** Raised when client catches a `CommandError` from server.

    For example:

    >>> e = CommandError(name='foobar')
    >>> raise ServerCommandError(error=str(e), server='https://localhost')
    Traceback (most recent call last):
      ...
    ServerCommandError: error on server 'https://localhost': unknown command 'foobar'
    """

    errno = 906
    format = _("error on server '%(server)s': %(error)s")


class NetworkError(PublicError):
    """
    **907** Raised when a network connection cannot be created.

    For example:

    >>> raise NetworkError(uri='ldap://localhost:389', error=_(u'Connection refused'))
    Traceback (most recent call last):
      ...
    NetworkError: cannot connect to 'ldap://localhost:389': Connection refused
    """

    errno = 907
    format = _("cannot connect to '%(uri)s': %(error)s")


class ServerNetworkError(PublicError):
    """
    **908** Raised when client catches a `NetworkError` from server.
    """

    errno = 908
    format = _("error on server '%(server)s': %(error)s")


class JSONError(PublicError):
    """
    **909** Raised when server received a malformed JSON-RPC request.
    """

    errno = 909
    format = _('Invalid JSON-RPC request: %(error)s')


class XMLRPCMarshallError(PublicError):
    """
    **910** Raised when the XML-RPC lib cannot marshall the request

    For example:

    >>> raise XMLRPCMarshallError(error=_('int exceeds XML-RPC limits'))
    Traceback (most recent call last):
      ...
    XMLRPCMarshallError: error marshalling data for XML-RPC transport: int exceeds XML-RPC limits
    """

    errno = 910
    format = _('error marshalling data for XML-RPC transport: %(error)s')


class RefererError(PublicError):
    """
    **911** Raised when the request does not contain an HTTP referer

    For example:

    >>> raise RefererError(referer='referer')
    Traceback (most recent call last):
      ...
    RefererError: Missing or invalid HTTP Referer, referer
    """

    errno = 911
    format = _('Missing or invalid HTTP Referer, %(referer)s')


class EnvironmentError(PublicError):
    """
    **912** Raised when a command is called with invalid environment settings
    """

    errno = 912


class SystemEncodingError(PublicError):
    """
    **913** Raised when system encoding is not UTF-8
    """

    errno = 913
    format = _(
        "System encoding must be UTF-8, '%(encoding)s' is not supported. "
        "Set LC_ALL=\"C.UTF-8\", or LC_ALL=\"\" and LC_CTYPE=\"C.UTF-8\"."
    )

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

    For example:

    >>> raise KerberosError(major=_('Unspecified GSS failure.  Minor code may provide more information'), minor=_('No credentials cache found'))
    Traceback (most recent call last):
      ...
    KerberosError: Kerberos error: Unspecified GSS failure.  Minor code may provide more information/No credentials cache found

    """

    errno = 1100
    format= _('Kerberos error: %(major)s/%(minor)s')


class CCacheError(KerberosError):
    """
    **1101** Raised when sever does not receive Kerberose credentials.

    For example:

    >>> raise CCacheError()
    Traceback (most recent call last):
      ...
    CCacheError: did not receive Kerberos credentials

    """

    errno = 1101
    format = _('did not receive Kerberos credentials')


class ServiceError(KerberosError):
    """
    **1102** Raised when service is not found in Kerberos DB.

    For example:

    >>> raise ServiceError(service='HTTP@localhost')
    Traceback (most recent call last):
      ...
    ServiceError: Service 'HTTP@localhost' not found in Kerberos database
    """

    errno = 1102
    format = _("Service '%(service)s' not found in Kerberos database")


class NoCCacheError(KerberosError):
    """
    **1103** Raised when a client attempts to use Kerberos without a ccache.

    For example:

    >>> raise NoCCacheError()
    Traceback (most recent call last):
      ...
    NoCCacheError: No credentials cache found
    """

    errno = 1103
    format = _('No credentials cache found')


class TicketExpired(KerberosError):
    """
    **1104** Raised when a client attempts to use an expired ticket

    For example:

    >>> raise TicketExpired()
    Traceback (most recent call last):
      ...
    TicketExpired: Ticket expired
    """

    errno = 1104
    format = _('Ticket expired')


class BadCCachePerms(KerberosError):
    """
    **1105** Raised when a client has bad permissions on their ccache

    For example:

    >>> raise BadCCachePerms()
    Traceback (most recent call last):
      ...
    BadCCachePerms: Credentials cache permissions incorrect
    """

    errno = 1105
    format = _('Credentials cache permissions incorrect')


class BadCCacheFormat(KerberosError):
    """
    **1106** Raised when a client has a misformated ccache

    For example:

    >>> raise BadCCacheFormat()
    Traceback (most recent call last):
      ...
    BadCCacheFormat: Bad format in credentials cache
    """

    errno = 1106
    format = _('Bad format in credentials cache')


class CannotResolveKDC(KerberosError):
    """
    **1107** Raised when the KDC can't be resolved

    For example:

    >>> raise CannotResolveKDC()
    Traceback (most recent call last):
      ...
    CannotResolveKDC: Cannot resolve KDC for requested realm
    """

    errno = 1107
    format = _('Cannot resolve KDC for requested realm')


class SessionError(AuthenticationError):
    """
    **1200** Base class for Session errors (*1200 - 1299*).

    For example:

    """

    errno = 1200
    format= _('Session error')


class InvalidSessionPassword(SessionError):
    """
    **1201** Raised when we cannot obtain a TGT for a principal.
    """
    errno = 1201
    format= _('Principal %(principal)s cannot be authenticated: %(message)s')

class PasswordExpired(InvalidSessionPassword):
    """
    **1202** Raised when we cannot obtain a TGT for a principal because the password is expired.
    """
    errno = 1202

class KrbPrincipalExpired(SessionError):
    """
    **1203** Raised when Kerberos Principal is expired.
    """
    errno = 1203

class UserLocked(SessionError):
    """
    **1204** Raised when a user account is locked.
    """
    errno = 1204

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
    format = _('Insufficient access: %(info)s')



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


class ZeroArgumentError(InvocationError):
    """
    **3003** Raised when a command is called with arguments but takes none.

    For example:

    >>> raise ZeroArgumentError(name='ping')
    Traceback (most recent call last):
      ...
    ZeroArgumentError: command 'ping' takes no arguments
    """

    errno = 3003
    format = _("command '%(name)s' takes no arguments")


class MaxArgumentError(InvocationError):
    """
    **3004** Raised when a command is called with too many arguments.

    For example:

    >>> raise MaxArgumentError(name='user_add', count=2)
    Traceback (most recent call last):
      ...
    MaxArgumentError: command 'user_add' takes at most 2 arguments
    """

    errno = 3004

    def __init__(self, message=None, **kw):
        if message is None:
            format = ungettext(
                "command '%(name)s' takes at most %(count)d argument",
                "command '%(name)s' takes at most %(count)d arguments",
                kw['count']
            )
        else:
            format = None
        InvocationError.__init__(self, format, message, **kw)


class OptionError(InvocationError):
    """
    **3005** Raised when a command is called with unknown options.
    """

    errno = 3005


class OverlapError(InvocationError):
    """
    **3006** Raised when arguments and options overlap.

    For example:

    >>> raise OverlapError(names=['givenname', 'login'])
    Traceback (most recent call last):
      ...
    OverlapError: overlapping arguments and options: ['givenname', 'login']
    """

    errno = 3006
    format = _("overlapping arguments and options: %(names)s")


class RequirementError(InvocationError):
    """
    **3007** Raised when a required parameter is not provided.

    For example:

    >>> raise RequirementError(name='givenname')
    Traceback (most recent call last):
      ...
    RequirementError: 'givenname' is required
    """

    errno = 3007
    format = _("'%(name)s' is required")


class ConversionError(InvocationError):
    """
    **3008** Raised when parameter value can't be converted to correct type.

    For example:

    >>> raise ConversionError(name='age', error=_(u'must be an integer'))
    Traceback (most recent call last):
      ...
    ConversionError: invalid 'age': must be an integer
    """

    errno = 3008
    format = _("invalid '%(name)s': %(error)s")


class ValidationError(InvocationError):
    """
    **3009** Raised when a parameter value fails a validation rule.

    For example:

    >>> raise ValidationError(name='sn', error=_(u'can be at most 128 characters'))
    Traceback (most recent call last):
      ...
    ValidationError: invalid 'sn': can be at most 128 characters
    """

    errno = 3009
    format = _("invalid '%(name)s': %(error)s")


class NoSuchNamespaceError(InvocationError):
    """
    **3010** Raised when an unknown namespace is requested.

    For example:

    >>> raise NoSuchNamespaceError(name='Plugins')
    Traceback (most recent call last):
      ...
    NoSuchNamespaceError: api has no such namespace: 'Plugins'
    """

    errno = 3010
    format = _("api has no such namespace: '%(name)s'")


class PasswordMismatch(InvocationError):
    """
    **3011** Raise when password and password confirmation don't match.
    """

    errno = 3011
    format = _('Passwords do not match')


class NotImplementedError(InvocationError):
    """
    **3012** Raise when a function hasn't been implemented.
    """

    errno = 3012
    format = _('Command not implemented')


class NotConfiguredError(InvocationError):
    """
    **3013** Raise when there is no configuration
    """

    errno = 3013
    format = _('Client is not configured. Run ipa-client-install.')


class PromptFailed(InvocationError):
    """
    **3014** Raise when an interactive prompt failed.
    """

    errno = 3014
    format = _('Could not get %(name)s interactively')


class DeprecationError(InvocationError):
    """
    **3015** Raise when a command has been deprecated

    For example:

    >>> raise DeprecationError(name='hbacrule_add_sourcehost')
    Traceback (most recent call last):
      ...
    DeprecationError: Command 'hbacrule_add_sourcehost' has been deprecated
    """
    errno = 3015
    format = _("Command '%(name)s' has been deprecated")

class NotAForestRootError(InvocationError):
    """
    **3016** Raised when an attempt to establish trust is done against non-root domain
             Forest root domain has the same name as the forest itself

    For example:

    >>> raise NotAForestRootError(forest='example.test', domain='jointops.test')
    Traceback (most recent call last):
      ...
    NotAForestRootError: Domain 'jointops.test' is not a root domain for forest 'example.test'
    """

    errno = 3016
    format = _("Domain '%(domain)s' is not a root domain for forest '%(forest)s'")

##############################################################################
# 4000 - 4999: Execution errors

class ExecutionError(PublicError):
    """
    **4000** Base class for execution errors (*4000 - 4999*).
    """

    errno = 4000

class NotFound(ExecutionError):
    """
    **4001** Raised when an entry is not found.

    For example:

    >>> raise NotFound(reason='no such user')
    Traceback (most recent call last):
      ...
    NotFound: no such user

    """

    errno = 4001
    rval = 2
    format = _('%(reason)s')

class DuplicateEntry(ExecutionError):
    """
    **4002** Raised when an entry already exists.

    For example:

    >>> raise DuplicateEntry
    Traceback (most recent call last):
      ...
    DuplicateEntry: This entry already exists

    """

    errno = 4002
    format = _('This entry already exists')

class HostService(ExecutionError):
    """
    **4003** Raised when a host service principal is requested

    For example:

    >>> raise HostService
    Traceback (most recent call last):
      ...
    HostService: You must enroll a host in order to create a host service

    """

    errno = 4003
    format = _('You must enroll a host in order to create a host service')

class MalformedServicePrincipal(ExecutionError):
    """
    **4004** Raised when a service principal is not of the form: service/fully-qualified host name

    For example:

    >>> raise MalformedServicePrincipal(reason=_('missing service'))
    Traceback (most recent call last):
      ...
    MalformedServicePrincipal: Service principal is not of the form: service/fully-qualified host name: missing service

    """

    errno = 4004
    format = _('Service principal is not of the form: service/fully-qualified host name: %(reason)s')

class RealmMismatch(ExecutionError):
    """
    **4005** Raised when the requested realm does not match the IPA realm

    For example:

    >>> raise RealmMismatch
    Traceback (most recent call last):
      ...
    RealmMismatch: The realm for the principal does not match the realm for this IPA server

    """

    errno = 4005
    format = _('The realm for the principal does not match the realm for this IPA server')

class RequiresRoot(ExecutionError):
    """
    **4006** Raised when a command requires the unix super-user to run

    For example:

    >>> raise RequiresRoot
    Traceback (most recent call last):
      ...
    RequiresRoot: This command requires root access

    """

    errno = 4006
    format = _('This command requires root access')

class AlreadyPosixGroup(ExecutionError):
    """
    **4007** Raised when a group is already a posix group

    For example:

    >>> raise AlreadyPosixGroup
    Traceback (most recent call last):
      ...
    AlreadyPosixGroup: This is already a posix group

    """

    errno = 4007
    format = _('This is already a posix group')

class MalformedUserPrincipal(ExecutionError):
    """
    **4008** Raised when a user principal is not of the form: user@REALM

    For example:

    >>> raise MalformedUserPrincipal(principal='jsmith@@EXAMPLE.COM')
    Traceback (most recent call last):
      ...
    MalformedUserPrincipal: Principal is not of the form user@REALM: 'jsmith@@EXAMPLE.COM'

    """

    errno = 4008
    format = _("Principal is not of the form user@REALM: '%(principal)s'")

class AlreadyActive(ExecutionError):
    """
    **4009** Raised when an entry is made active that is already active

    For example:

    >>> raise AlreadyActive()
    Traceback (most recent call last):
      ...
    AlreadyActive: This entry is already enabled

    """

    errno = 4009
    format = _('This entry is already enabled')

class AlreadyInactive(ExecutionError):
    """
    **4010** Raised when an entry is made inactive that is already inactive

    For example:

    >>> raise AlreadyInactive()
    Traceback (most recent call last):
      ...
    AlreadyInactive: This entry is already disabled

    """

    errno = 4010
    format = _('This entry is already disabled')

class HasNSAccountLock(ExecutionError):
    """
    **4011** Raised when an entry has the nsAccountLock attribute set

    For example:

    >>> raise HasNSAccountLock()
    Traceback (most recent call last):
      ...
    HasNSAccountLock: This entry cannot be enabled or disabled

    """

    errno = 4011
    format = _('This entry cannot be enabled or disabled')

class NotGroupMember(ExecutionError):
    """
    **4012** Raised when a non-member is attempted to be removed from a group

    For example:

    >>> raise NotGroupMember()
    Traceback (most recent call last):
      ...
    NotGroupMember: This entry is not a member

    """

    errno = 4012
    format = _('This entry is not a member')

class RecursiveGroup(ExecutionError):
    """
    **4013** Raised when a group is added as a member of itself

    For example:

    >>> raise RecursiveGroup()
    Traceback (most recent call last):
      ...
    RecursiveGroup: A group may not be a member of itself

    """

    errno = 4013
    format = _('A group may not be a member of itself')

class AlreadyGroupMember(ExecutionError):
    """
    **4014** Raised when a member is attempted to be re-added to a group

    For example:

    >>> raise AlreadyGroupMember()
    Traceback (most recent call last):
      ...
    AlreadyGroupMember: This entry is already a member

    """

    errno = 4014
    format = _('This entry is already a member')

class Base64DecodeError(ExecutionError):
    """
    **4015** Raised when a base64-encoded blob cannot decoded

    For example:

    >>> raise Base64DecodeError(reason=_('Incorrect padding'))
    Traceback (most recent call last):
      ...
    Base64DecodeError: Base64 decoding failed: Incorrect padding

    """

    errno = 4015
    format = _('Base64 decoding failed: %(reason)s')

class RemoteRetrieveError(ExecutionError):
    """
    **4016** Raised when retrieving data from a remote server fails

    For example:

    >>> raise RemoteRetrieveError(reason=_("Failed to get certificate chain."))
    Traceback (most recent call last):
      ...
    RemoteRetrieveError: Failed to get certificate chain.

    """

    errno = 4016
    format = _('%(reason)s')

class SameGroupError(ExecutionError):
    """
    **4017** Raised when adding a group as a member of itself

    For example:

    >>> raise SameGroupError()
    Traceback (most recent call last):
      ...
    SameGroupError: A group may not be added as a member of itself

    """

    errno = 4017
    format = _('A group may not be added as a member of itself')

class DefaultGroupError(ExecutionError):
    """
    **4018** Raised when removing the default user group

    For example:

    >>> raise DefaultGroupError()
    Traceback (most recent call last):
      ...
    DefaultGroupError: The default users group cannot be removed

    """

    errno = 4018
    format = _('The default users group cannot be removed')


class ManagedGroupError(ExecutionError):
    """
    **4020** Raised when a managed group is deleted

    For example:

    >>> raise ManagedGroupError()
    Traceback (most recent call last):
      ...
    ManagedGroupError: Deleting a managed group is not allowed. It must be detached first.
    """

    errno = 4020
    format = _('Deleting a managed group is not allowed. It must be detached first.')

class ManagedPolicyError(ExecutionError):
    """
    **4021** Raised when password policy is assigned to a managed group

    For example:

    >>> raise ManagedPolicyError()
    Traceback (most recent call last):
      ...
    ManagedPolicyError: A managed group cannot have a password policy.
    """

    errno = 4021
    format = _('A managed group cannot have a password policy.')


class FileError(ExecutionError):
    """
    **4022** Errors when dealing with files

    For example:

    >>> raise FileError(reason=_("cannot write file \'test\'"))
    Traceback (most recent call last):
      ...
    FileError: cannot write file 'test'
    """

    errno = 4022
    format = _('%(reason)s')


class NoCertificateError(ExecutionError):
    """
    **4023** Raised when trying to retrieve a certificate that doesn't exist.

    For example:

    >>> raise NoCertificateError(entry='ipa.example.com')
    Traceback (most recent call last):
      ...
    NoCertificateError: 'ipa.example.com' doesn't have a certificate.
    """

    errno = 4023
    format = _('\'%(entry)s\' doesn\'t have a certificate.')


class ManagedGroupExistsError(ExecutionError):
    """
    **4024** Raised when adding a user and its managed group exists

    For example:

    >>> raise ManagedGroupExistsError(group=u'engineering')
    Traceback (most recent call last):
      ...
    ManagedGroupExistsError: Unable to create private group. A group 'engineering' already exists.
    """

    errno = 4024
    format = _('Unable to create private group. A group \'%(group)s\' already exists.')


class ReverseMemberError(ExecutionError):
    """
    **4025** Raised when verifying that all reverse members have been added or removed.

    For example:

    >>> raise ReverseMemberError(verb=_('added'), exc=_("Group 'foo' not found."))
    Traceback (most recent call last):
      ...
    ReverseMemberError: A problem was encountered when verifying that all members were added: Group 'foo' not found.
    """

    errno = 4025
    format = _('A problem was encountered when verifying that all members were %(verb)s: %(exc)s')


class AttrValueNotFound(ExecutionError):
    """
    **4026** Raised when an Attribute/Value pair is not found.

    For example:

    >>> raise AttrValueNotFound(attr='ipasudoopt', value='authenticate')
    Traceback (most recent call last):
      ...
    AttrValueNotFound: ipasudoopt does not contain 'authenticate'

    """

    errno = 4026
    rval = 1
    format = _('%(attr)s does not contain \'%(value)s\'')


class SingleMatchExpected(ExecutionError):
    """
    **4027** Raised when a search should return a single match

    For example:

    >>> raise SingleMatchExpected(found=9)
    Traceback (most recent call last):
      ...
    SingleMatchExpected: The search criteria was not specific enough. Expected 1 and found 9.
    """

    errno = 4027
    rval = 1
    format = _('The search criteria was not specific enough. Expected 1 and found %(found)d.')


class AlreadyExternalGroup(ExecutionError):
    """
    **4028** Raised when a group is already an external member group

    For example:

    >>> raise AlreadyExternalGroup
    Traceback (most recent call last):
      ...
    AlreadyExternalGroup: This group already allows external members

    """

    errno = 4028
    format = _('This group already allows external members')

class ExternalGroupViolation(ExecutionError):
    """
    **4029** Raised when a group is already an external member group
             and an attempt is made to use it as posix group

    For example:

    >>> raise ExternalGroupViolation
    Traceback (most recent call last):
      ...
    ExternalGroupViolation: This group cannot be posix because it is external

    """

    errno = 4029
    format = _('This group cannot be posix because it is external')

class PosixGroupViolation(ExecutionError):
    """
    **4030** Raised when a group is already a posix group
             and cannot be converted to external

    For example:

    >>> raise PosixGroupViolation
    Traceback (most recent call last):
      ...
    PosixGroupViolation: This is already a posix group and cannot be converted to external one

    """

    errno = 4030
    format = _('This is already a posix group and cannot be converted to external one')

class EmptyResult(NotFound):
    """
    **4031** Raised when a LDAP search returned no results.

    For example:

    >>> raise EmptyResult(reason='no matching entry found')
    Traceback (most recent call last):
      ...
    EmptyResult: no matching entry found

    """

    errno = 4031

class InvalidDomainLevelError(ExecutionError):
    """
    **4032** Raised when a operation could not be completed due to a invalid
             domain level.

    For example:

    >>> raise InvalidDomainLevelError(reason='feature requires domain level 4')
    Traceback (most recent call last):
      ...
    InvalidDomainLevelError: feature requires domain level 4

    """

    errno = 4032
    format = _('%(reason)s')


class ServerRemovalError(ExecutionError):
    """
    **4033** Raised when a removal of IPA server from managed topology fails

    For example:

    >>> raise ServerRemovalError(reason='Removal disconnects topology')
    Traceback (most recent call last):
      ...
    ServerRemovalError: Server removal aborted: Removal disconnects topology

    """

    errno = 4033
    format = _('Server removal aborted: %(reason)s.')


class OperationNotSupportedForPrincipalType(ExecutionError):
    """
    **4034** Raised when an operation is not supported for a principal type
    """

    errno = 4034
    format = _(
        '%(operation)s is not supported for %(principal_type)s principals')


class HTTPRequestError(RemoteRetrieveError):
    """
    **4035** Raised when an HTTP request fails.  Includes the response
    status in the ``status`` attribute.
    """

    errno = 4035
    format = _('Request failed with status %(status)s: %(reason)s')


class RedundantMappingRule(SingleMatchExpected):
    """
    **4036** Raised when more than one rule in a CSR generation ruleset matches
    a particular helper.

    For example:

    >>> raise RedundantMappingRule(ruleset='syntaxSubject', helper='certutil')
    Traceback (most recent call last):
      ...
    RedundantMappingRule: Mapping ruleset "syntaxSubject" has more than one
    rule for the certutil helper.
    """

    errno = 4036
    format = _('Mapping ruleset "%(ruleset)s" has more than one rule for the'
               ' %(helper)s helper')


class CSRTemplateError(ExecutionError):
    """
    **4037** Raised when evaluation of a CSR generation template fails
    """

    errno = 4037
    format = _('%(reason)s')


class AlreadyContainsValueError(ExecutionError):
    """
    **4038** Raised when BaseLDAPAddAttribute operation fails because one
    or more new values are already present.
    """
    errno = 4038
    format = _("'%(attr)s' already contains one or more values")


class BuiltinError(ExecutionError):
    """
    **4100** Base class for builtin execution errors (*4100 - 4199*).
    """

    errno = 4100


class HelpError(BuiltinError):
    """
    **4101** Raised when requesting help for an unknown topic.

    For example:

    >>> raise HelpError(topic='newfeature')
    Traceback (most recent call last):
      ...
    HelpError: no command nor help topic 'newfeature'
    """

    errno = 4101
    format = _("no command nor help topic '%(topic)s'")


class LDAPError(ExecutionError):
    """
    **4200** Base class for LDAP execution errors (*4200 - 4299*).
    """

    errno = 4200


class MidairCollision(ExecutionError):
    """
    **4201** Raised when a change collides with another change

    For example:

    >>> raise MidairCollision()
    Traceback (most recent call last):
      ...
    MidairCollision: change collided with another change
    """

    errno = 4201
    format = _('change collided with another change')


class EmptyModlist(ExecutionError):
    """
    **4202** Raised when an LDAP update makes no changes

    For example:

    >>> raise EmptyModlist()
    Traceback (most recent call last):
      ...
    EmptyModlist: no modifications to be performed
    """

    errno = 4202
    format = _('no modifications to be performed')


class DatabaseError(ExecutionError):
    """
    **4203** Raised when an LDAP error is not otherwise handled

    For example:

    >>> raise DatabaseError(desc=_("Can't contact LDAP server"), info=_('Info goes here'))
    Traceback (most recent call last):
      ...
    DatabaseError: Can't contact LDAP server: Info goes here
    """

    errno = 4203
    format = _('%(desc)s: %(info)s')


class LimitsExceeded(ExecutionError):
    """
    **4204** Raised when search limits are exceeded.

    For example:

    >>> raise LimitsExceeded()
    Traceback (most recent call last):
      ...
    LimitsExceeded: limits exceeded for this query
    """

    errno = 4204
    format = _('limits exceeded for this query')

class ObjectclassViolation(ExecutionError):
    """
    **4205** Raised when an entry is missing a required attribute or objectclass

    For example:

    >>> raise ObjectclassViolation(info=_('attribute "krbPrincipalName" not allowed'))
    Traceback (most recent call last):
      ...
    ObjectclassViolation: attribute "krbPrincipalName" not allowed
    """

    errno = 4205
    format = _('%(info)s')

class NotAllowedOnRDN(ExecutionError):
    """
    **4206** Raised when an RDN value is modified.

    For example:

    >>> raise NotAllowedOnRDN()
    Traceback (most recent call last):
      ...
    NotAllowedOnRDN: modifying primary key is not allowed
    """

    errno = 4206
    format = _('modifying primary key is not allowed')


class OnlyOneValueAllowed(ExecutionError):
    """
    **4207** Raised when trying to set more than one value to single-value attributes

    For example:

    >> raise OnlyOneValueAllowed(attr='ipasearchtimelimit')
    Traceback (most recent call last):
      ...
    OnlyOneValueAllowed: ipasearchtimelimit: Only one value allowed.
    """

    errno = 4207
    format = _('%(attr)s: Only one value allowed.')


class InvalidSyntax(ExecutionError):
    """
    **4208** Raised when an value does not match the required syntax

    For example:

    >> raise InvalidSyntax(attr='ipahomesrootdir')
    Traceback (most recent call last):
      ...
    InvalidSyntax: ipahomesrootdir: Invalid syntax
    """

    errno = 4208
    format = _('%(attr)s: Invalid syntax.')


class BadSearchFilter(ExecutionError):
    """
    **4209** Raised when an invalid LDAP search filter is used

    For example:

    >>> raise BadSearchFilter(info=_('invalid syntax'))
    Traceback (most recent call last):
      ...
    BadSearchFilter: Bad search filter invalid syntax
    """

    errno = 4209
    format = _('Bad search filter %(info)s')


class NotAllowedOnNonLeaf(ExecutionError):
    """
    **4210** Raised when operation is not allowed on a non-leaf entry

    For example:

    >>> raise NotAllowedOnNonLeaf()
    Traceback (most recent call last):
      ...
    NotAllowedOnNonLeaf: Not allowed on non-leaf entry
    """

    errno = 4210
    format = _('Not allowed on non-leaf entry')


class DatabaseTimeout(DatabaseError):
    """
    **4211** Raised when an LDAP call times out

    For example:

    >>> raise DatabaseTimeout()
    Traceback (most recent call last):
      ...
    DatabaseTimeout: LDAP timeout
    """

    errno = 4211
    format = _('LDAP timeout')


class TaskTimeout(DatabaseError):
    """
    **4213** Raised when an LDAP task times out

    For example:

    >>> raise TaskTimeout(task='Automember', task_dn='')
    Traceback (most recent call last):
      ...
    TaskTimeout: Automember LDAP task timeout, Task DN: ''
    """

    errno = 4213
    format = _("%(task)s LDAP task timeout, Task DN: '%(task_dn)s'")


class TimeLimitExceeded(LimitsExceeded):
    """
    **4214** Raised when time limit for the operation is exceeded.
    """

    errno = 4214
    format = _('Configured time limit exceeded')


class SizeLimitExceeded(LimitsExceeded):
    """
    **4215** Raised when size limit for the operation is exceeded.
    """

    errno = 4215
    format = _('Configured size limit exceeded')


class AdminLimitExceeded(LimitsExceeded):
    """
    **4216** Raised when server limit imposed by administrative authority was
    exceeded
    """

    errno = 4216
    format = _('Configured administrative server limit exceeded')


class CertificateError(ExecutionError):
    """
    **4300** Base class for Certificate execution errors (*4300 - 4399*).
    """

    errno = 4300


class CertificateOperationError(CertificateError):
    """
    **4301** Raised when a certificate operation cannot be completed

    For example:

    >>> raise CertificateOperationError(error=_(u'bad serial number'))
    Traceback (most recent call last):
      ...
    CertificateOperationError: Certificate operation cannot be completed: bad serial number

    """

    errno = 4301
    format = _('Certificate operation cannot be completed: %(error)s')

class CertificateFormatError(CertificateError):
    """
    **4302** Raised when a certificate is badly formatted

    For example:

    >>> raise CertificateFormatError(error=_(u'improperly formated DER-encoded certificate'))
    Traceback (most recent call last):
      ...
    CertificateFormatError: Certificate format error: improperly formated DER-encoded certificate

    """

    errno = 4302
    format = _('Certificate format error: %(error)s')


class MutuallyExclusiveError(ExecutionError):
    """
    **4303** Raised when an operation would result in setting two attributes which are mutually exlusive.

    For example:

    >>> raise MutuallyExclusiveError(reason=_(u'hosts may not be added when hostcategory=all'))
    Traceback (most recent call last):
      ...
    MutuallyExclusiveError: hosts may not be added when hostcategory=all

    """

    errno = 4303
    format = _('%(reason)s')


class NonFatalError(ExecutionError):
    """
    **4304** Raised when part of an operation succeeds and the part that failed isn't critical.

    For example:

    >>> raise NonFatalError(reason=_(u'The host was added but the DNS update failed'))
    Traceback (most recent call last):
      ...
    NonFatalError: The host was added but the DNS update failed

    """

    errno = 4304
    format = _('%(reason)s')


class AlreadyRegisteredError(ExecutionError):
    """
    **4305** Raised when registering a user that is already registered.

    For example:

    >>> raise AlreadyRegisteredError()
    Traceback (most recent call last):
      ...
    AlreadyRegisteredError: Already registered

    """

    errno = 4305
    format = _('Already registered')


class NotRegisteredError(ExecutionError):
    """
    **4306** Raised when not registered and a registration is required

    For example:
    >>> raise NotRegisteredError()
    Traceback (most recent call last):
      ...
    NotRegisteredError: Not registered yet

    """

    errno = 4306
    format = _('Not registered yet')


class DependentEntry(ExecutionError):
    """
    **4307** Raised when an entry being deleted has dependencies

    For example:
    >>> raise DependentEntry(label=u'SELinux User Map', key=u'test', dependent=u'test1')
    Traceback (most recent call last):
      ...
    DependentEntry: test cannot be deleted because SELinux User Map test1 requires it

    """

    errno = 4307
    format = _('%(key)s cannot be deleted because %(label)s %(dependent)s requires it')


class LastMemberError(ExecutionError):
    """
    **4308** Raised when an entry being deleted or disabled is last member of a protected group

    For example:
    >>> raise LastMemberError(key=u'admin', label=u'group', container=u'admins')
    Traceback (most recent call last):
      ...
    LastMemberError: admin cannot be deleted or disabled because it is the last member of group admins

    """

    errno = 4308
    format = _('%(key)s cannot be deleted or disabled because it is the last member of %(label)s %(container)s')


class ProtectedEntryError(ExecutionError):
    """
    **4309** Raised when an entry being deleted or modified in a forbidden way is protected

    For example:
    >>> raise ProtectedEntryError(label=u'group', key=u'admins', reason=_(u'privileged group'))
    Traceback (most recent call last):
      ...
    ProtectedEntryError: group admins cannot be deleted/modified: privileged group

    """

    errno = 4309
    format = _('%(label)s %(key)s cannot be deleted/modified: %(reason)s')


class CertificateInvalidError(CertificateError):
    """
    **4310** Raised when a certificate is not valid

    For example:

    >>> raise CertificateInvalidError(name=_(u'CA'))
    Traceback (most recent call last):
      ...
    CertificateInvalidError: CA certificate is not valid

    """

    errno = 4310
    format = _('%(name)s certificate is not valid')


class SchemaUpToDate(ExecutionError):
    """
    **4311** Raised by server when client asks for metadata but
    already has current version. Exception's attribute 'fingerprint'
    identitfies schema version to use. Attribute 'ttl' specifies how
    long (in seconds) before client should check for schema update.

    For example:
    >>> raise SchemaUpToDate(fingerprint=u'deadbeef', ttl=3600)
    Traceback (most recent call last):
      ...
    SchemaUpToDate: Schema is up to date (FP 'deadbeef', TTL 3600 s)
    """

    errno = 4311
    format = _("Schema is up to date (FP '%(fingerprint)s', TTL %(ttl)s s)")


class DNSError(ExecutionError):
    """
    **4400** Base class for DNS execution errors (*4400 - 4499*).
    These are typically wrapper exceptions around dns.exception.DNSException.
    """

    errno = 4400


class DNSNotARecordError(DNSError):
    """
    **4019** Raised when a hostname is not a DNS A/AAAA record

    For example:

    >>> raise DNSNotARecordError(hostname='x')
    Traceback (most recent call last):
      ...
    DNSNotARecordError: Host 'x' does not have corresponding DNS A/AAAA record

    """

    errno = 4019  # this exception was defined before DNSError
    format = _(
        'Host \'%(hostname)s\' does not have corresponding DNS A/AAAA record')


class DNSDataMismatch(DNSError):
    """
    **4212** Raised when an DNS query didn't return expected answer
    in a configured time limit.

    For example:

    >>> raise DNSDataMismatch(expected="zone3.test. 86400 IN A 192.0.2.1", \
                              got="zone3.test. 86400 IN A 192.168.1.1")
    Traceback (most recent call last):
      ...
    DNSDataMismatch: DNS check failed: Expected {zone3.test. 86400 IN A 192.0.2.1} got {zone3.test. 86400 IN A 192.168.1.1}
    """

    errno = 4212  # this exception was defined before DNSError
    format = _('DNS check failed: Expected {%(expected)s} got {%(got)s}')


class DNSResolverError(DNSError):
    """
    **4401** Wrapper around dns.exception.DNSException.
    Raised when an error occured in dns.resolver.

    For example:
    >>> raise DNSResolverError(exception=ValueError("this is bad"))
    Traceback (most recent call last):
      ...
    DNSResolverError: this is bad
    """

    errno = 4401
    format = _('%(exception)s')

class TrustError(ExecutionError):
    """
    **4500** Base class for trust execution errors (*4500 - 4599*).
    These are typically instantiated when there is an error in establishing or
    modifying a trust to another forest.
    """

    errno = 4500

class TrustTopologyConflictError(TrustError):
    """
    **4501** Raised when an attempt to establish trust fails with a topology
             conflict against another forest the target forest trusts

    For example:

    >>> raise TrustTopologyConflictError(forest='example.test',
                                         conflict='my.ad.test',
                                         domains=['ad.test'])
    Traceback (most recent call last):
      ...
    TrustTopologyConflictError: Forest 'example.test' has existing trust to forest(s) ['ad.test'] which prevents a trust to 'my.ad.test'
    """

    errno = 4501
    format = _("Forest '%(forest)s' has existing trust to forest(s) "
               "%(domains)s which prevents a trust to '%(conflict)s'")


##############################################################################
# 5000 - 5999: Generic errors

class GenericError(PublicError):
    """
    **5000** Base class for errors that don't fit elsewhere (*5000 - 5999*).
    """

    errno = 5000



public_errors = tuple(sorted(
    messages.iter_messages(globals(), PublicError), key=lambda E: E.errno))

errors_by_code = dict((e.errno, e) for e in public_errors)

if __name__ == '__main__':
    messages.print_report('public errors', public_errors)
