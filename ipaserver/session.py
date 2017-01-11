# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2011  Red Hat
# see file 'COPYING' for use and warranty information
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

import memcache
import random
import os
import re
import time
import io

# pylint: disable=import-error
from six.moves.urllib.parse import urlparse
# pylint: enable=import-error

from ipalib import errors
from ipalib.text import _
from ipapython.ipa_log_manager import root_logger, log_mgr
from ipalib import api
from ipaplatform.paths import paths
from ipalib.krb_utils import (
    krb5_parse_ccache,
    krb5_unparse_ccache)
from ipapython.cookie import Cookie

__doc__ = '''
Session Support for IPA
John Dennis <jdennis@redhat.com>

Goals
=====

Provide per-user session data caching which persists between
requests. Desired features are:

* Integrates cleanly with minimum impact on existing infrastructure.

* Provides maximum security balanced against real-world performance
  demands.

* Sessions must be able to be revoked (flushed).

* Should be flexible and easy to use for developers.

* Should leverage existing technology and code to the maximum extent
  possible to avoid re-invention, excessive implementation time and to
  benefit from robustness in field proven components commonly shared
  in the open source community.

* Must support multiple independent processes which share session
  data.

* System must function correctly if session data is available or not.

* Must be high performance.

* Should not be tied to specific web servers or browsers. Should
  integrate with our chosen WSGI model.

Issues
======

Cookies
-------

Most session implementations are based on the use of cookies. Cookies
have some inherent problems.

* User has the option to disable cookies.

* User stored cookie data is not secure. Can be mitigated by setting
  flags indicating the cookie is only to be used with SSL secured HTTP
  connections to specific web resources and setting the cookie to
  expire at session termination. Most modern browsers enforce these.

Where to store session data?
----------------------------

Session data may be stored on either on the client or on the
server. Storing session data on the client addresses the problem of
session data availability when requests are serviced by independent web
servers because the session data travels with the request. However
there are data size limitations. Storing session data on the client
also exposes sensitive data but this can be mitigated by encrypting
the session data such that only the server can decrypt it.

The more conventional approach is to bind session data to a unique
name, the session ID. The session ID is transmitted to the client and
the session data is paired with the session ID on the server in a
associative data store. The session data is retrieved by the server
using the session ID when the receiving the request. This eliminates
exposing sensitive session data on the client along with limitations
on data size. It however introduces the issue of session data
availability when requests are serviced by more than one server
process.

Multi-process session data availability
---------------------------------------

Apache (and other web servers) fork child processes to handle requests
in parallel. Also web servers may be deployed in a farm where requests
are load balanced in round robin fashion across different nodes. In
both cases session data cannot be stored in the memory of a server
process because it is not available to other processes, either sibling
children of a master server process or server processes on distinct
nodes.

Typically this is addressed by storing session data in a SQL
database. When a request is received by a server process containing a
session ID in it's cookie data the session ID is used to perform a SQL
query and the resulting data is then attached to the request as it
proceeds through the request processing pipeline. This of course
introduces coherency issues.

For IPA the introduction of a SQL database dependency is undesired and
should be avoided.

Session data may also be shared by independent processes by storing
the session data in files.

An alternative solution which has gained considerable popularity
recently is the use of a fast memory based caching server. Data is
stored in a single process memory and may be queried and set via a
light weight protocol using standard socket mechanisms, memcached is
one example. A typical use is to optimize SQL queries by storing a SQL
result in shared memory cache avoiding the more expensive SQL
operation. But the memory cache has distinct advantages in non-SQL
situations as well.

Possible implementations for use by IPA
=======================================

Apache Sessions
---------------

Apache has 2.3 has implemented session support via these modules:

  mod_session
    Overarching session support based on cookies.

    See: http://httpd.apache.org/docs/2.3/mod/mod_session.html

  mod_session_cookie
    Stores session data in the client.

    See: http://httpd.apache.org/docs/2.3/mod/mod_session_cookie.html

  mod_session_crypto
    Encrypts session data for security. Encryption key is shared
    configuration parameter visible to all Apache processes and is
    stored in a configuration file.

    See: http://httpd.apache.org/docs/2.3/mod/mod_session_crypto.html

  mod_session_dbd
    Stores session data in a SQL database permitting multiple
    processes to access and share the same session data.

    See: http://httpd.apache.org/docs/2.3/mod/mod_session_dbd.html

Issues with Apache sessions
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Although Apache has implemented generic session support and Apache is
our web server of preference it nonetheless introduces issues for IPA.

  * Session support is only available in httpd >= 2.3 which at the
    time of this writing is currently only available as a Beta release
    from upstream. We currently only ship httpd 2.2, the same is true
    for other distributions.

  * We could package and ship the sessions modules as a temporary
    package in httpd 2.2 environments. But this has the following
    consequences:

      - The code has to be backported. the module API has changed
        slightly between httpd 2.2 and 2.3. The backporting is not
        terribly difficult and a proof of concept has been
        implemented.

      - We would then be on the hook to package and maintain a special
        case Apache package. This is maintenance burden as well as a
        distribution packaging burden. Both of which would be best
        avoided if possible.

  * The design of the Apache session modules is such that they can
    only be manipulated by other Apache modules. The ability of
    consumers of the session data to control the session data is
    simplistic, constrained and static during the period the request
    is processed. Request handlers which are not native Apache modules
    (e.g. IPA via WSGI) can only examine the session data
    via request headers and reset it in response headers.

  * Shared session data is available exclusively via SQL.

However using the 2.3 Apache session modules would give us robust
session support implemented in C based on standardized Apache
interfaces which are widely used.

Python Web Frameworks
---------------------

Virtually every Python web framework supports cookie based sessions,
e.g. Django, Twisted, Zope, Turbogears etc. Early on in IPA we decided
to avoid the use of these frameworks. Trying to pull in just one part
of these frameworks just to get session support would be problematic
because the code does not function outside it's framework.

IPA implemented sessions
------------------------

Originally it was believed the path of least effort was to utilize
existing session support, most likely what would be provided by
Apache. However there are enough basic modular components available in
native Python and other standard packages it should be possible to
provide session support meeting the aforementioned goals with a modest
implementation effort. Because we're leveraging existing components
the implementation difficulties are subsumed by other components which
have already been field proven and have community support. This is a
smart strategy.

Proposed Solution
=================

Our interface to the web server is via WSGI which invokes a callback
per request passing us an environmental context for the request. For
this discussion we'll name the WSGI callback "application()", a
conventional name in WSGI parlance.

Shared session data will be handled by memcached. We will create one
instance of memcached on each server node dedicated to IPA
exclusively. Communication with memcached will be via a UNIX socket
located in the file system under /var/run/ipa_memcached. It will be
protected by file permissions and optionally SELinux policy.

In application() we examine the request cookies and if there is an IPA
session cookie with a session ID we retrieve the session data from our
memcached instance.

The session data will be a Python dict. IPA components will read or
write their session information by using a pre-agreed upon name
(e.g. key) in the dict. This is a very flexible system and consistent
with how we pass data in most parts of IPA.

If the session data is not available an empty session data dict will
be created.

How does this session data travel with the request in the IPA
pipeline? In IPA we use the HTTP request/response to implement RPC. In
application() we convert the request into a procedure call passing it
arguments derived from the HTTP request. The passed parameters are
specific to the RPC method being invoked. The context the RPC call is
executing in is not passed as an RPC parameter.

How would the contextual information such as session data be bound to
the request and hence the RPC call?

In IPA when a RPC invocation is being prepared from a request we
recognize this will only ever be processed serially by one Python
thread. A thread local dict called "context" is allocated for each
thread. The context dict is cleared in between requests (e.g. RPC method
invocations). The per-thread context dict is populated during the
lifetime of the request and is used as a global data structure unique to
the request that various IPA component can read from and write to with
the assurance the data is unique to the current request and/or method
call.

The session data dict will be written into the context dict under the
session key before the RPC method begins execution. Thus session data
can be read and written by any IPA component by accessing
``context.session``.

When the RPC method finishes execution the session data bound to the
request/method is retrieved from the context and written back to the
memcached instance. The session ID is set in the response sent back to
the client in the ``Set-Cookie`` header along with the flags
controlling it's usage.

Issues and details
------------------

IPA code cannot depend on session data being present, however it
should always update session data with the hope it will be available
in the future. Session data may not be available because:

  * This is the first request from the user and no session data has
    been created yet.

  * The user may have cookies disabled.

  * The session data may have been flushed. memcached operates with
    a fixed memory allocation and will flush entries on a LRU basis,
    like with any cache there is no guarantee of persistence.

    Also we may have have deliberately expired or deleted session
    data, see below.

Cookie manipulation is done via the standard Python Cookie module.

Session cookies will be set to only persist as long as the browser has
the session open. They will be tagged so the browser only returns
the session ID on SSL secured HTTP requests. They will not be visible
to Javascript in the browser.

Session ID's will be created by using 48 bits of random data and
converted to 12 hexadecimal digits. Newly generated session ID's will
be checked for prior existence to handle the unlikely case the random
number repeats.

memcached will have significantly higher performance than a SQL or file
based storage solution. Communication is effectively though a pipe
(UNIX socket) using a very simple protocol and the data is held
entirely in process memory. memcached also scales easily, it is easy
to add more memcached processes and distribute the load across them.
At this point in time we don't anticipate the need for this.

A very nice feature of the Python memcached module is that when a data
item is written to the cache it is done with standard Python pickling
(pickling is a standard Python mechanism to marshal and unmarshal
Python objects). We adopt the convention the object written to cache
will be a dict to meet our internal data handling conventions. The
pickling code will recursively handle nested objects in the dict. Thus
we gain a lot of flexibility using standard Python data structures to
store and retrieve our session data without having to author and debug
code to marshal and unmarshal the data if some other storage mechanism
had been used. This is a significant implementation win. Of course
some common sense limitations need to observed when deciding on what
is written to the session cache keeping in mind the data is shared
between processes and it should not be excessively large (a
configurable option)

We can set an expiration on memcached entries. We may elect to do that
to force session data to be refreshed periodically. For example we may
wish the client to present fresh credentials on a periodic basis even
if the cached credentials are otherwise within their validity period.

We can explicitly delete session data if for some reason we believe it
is stale, invalid or compromised.

memcached also gives us certain facilities to prevent race conditions
between different processes utilizing the cache. For example you can
check of the entry has been modified since you last read it or use CAS
(Check And Set) semantics. What has to be protected in terms of cache
coherency will likely have to be determined as the session support is
utilized and different data items are added to the cache. This is very
much data and context specific. Fortunately memcached operations are
atomic.

Controlling the memcached process
---------------------------------

We need a mechanism to start the memcached process and secure it so
that only IPA components can access it.

Although memcached ships with both an initscript and systemd unit
files those are for generic instances. We want a memcached instance
dedicated exclusively to IPA usage. To accomplish this we would install
a systemd unit file or an SysV initscript to control the IPA specific
memcached service. ipactl would be extended to know about this
additional service. systemd's cgroup facility would give us additional
mechanisms to integrate the IPA memcached service within a larger IPA
process group.

Protecting the memcached data would be done via file permissions (and
optionally SELinux policy) on the UNIX domain socket. Although recent
implementations of memcached support authentication via SASL this
introduces a performance and complexity burden not warranted when
cached is dedicated to our exclusive use and access controlled by OS
mechanisms.

Conventionally daemons are protected by assigning a system uid and/or
gid to the daemon. A daemon launched by root will drop it's privileges
by assuming the effective uid:gid assigned to it. File system access
is controlled by the OS via the effective identity and SELinux policy
can be crafted based on the identity. Thus the memcached UNIX socket
would be protected by having it owned by a specific system user and/or
membership in a restricted system group (discounting for the moment
SELinux).

Unfortunately we currently do not have an IPA system uid whose
identity our processes operate under nor do we have an IPA system
group. IPA does manage a collection of related processes (daemons) and
historically each has been assigned their own uid. When these
unrelated processes communicate they mutually authenticate via other
mechanisms. We do not have much of a history of using shared file
system objects across identities. When file objects are created they
are typically assigned the identity of daemon needing to access the
object and are not accessed by other daemons, or they carry root
identity.

When our WSGI application runs in Apache it is run as a WSGI
daemon. This means when Apache starts up it forks off WSGI processes
for us and we are independent of other Apache processes. When WSGI is
run in this mode there is the ability to set the uid:gid of the WSGI
process hosting us, however we currently do not take advantage of this
option. WSGI can be run in other modes as well, only in daemon mode
can the uid:gid be independently set from the rest of Apache. All
processes started by Apache can be set to a common uid:gid specified
in the global Apache configuration, by default it's
apache:apache. Thus when our IPA code executes it is running as
apache:apache.

To protect our memcached UNIX socket we can do one of two things:

1. Assign it's uid:gid as apache:apache. This would limit access to
   our cache only to processes running under httpd. It's somewhat
   restricted but far from ideal. Any code running in the web server
   could potentially access our cache. It's difficult to control what the
   web server runs and admins may not understand the consequences of
   configuring httpd to serve other things besides IPA.

2. Create an IPA specific uid:gid, for example ipa:ipa. We then configure
   our WSGI application to run as the ipa:ipa user and group. We also
   configure our memcached instance to run as the ipa:ipa user and
   group. In this configuration we are now fully protected, only our WSGI
   code can read & write to our memcached UNIX socket.

However there may be unforeseen issues by converting our code to run as
something other than apache:apache. This would require some
investigation and testing.

IPA is dependent on other system daemons, specifically Directory
Server (ds) and Certificate Server (cs). Currently we configure ds to
run under the dirsrv:dirsrv user and group, an identity of our
creation. We allow cs to default to it's pkiuser:pkiuser user and
group. Should these other cooperating daemons also run under the
common ipa:ipa user and group identities? At first blush there would
seem to be an advantage to coalescing all process identities under a
common IPA user and group identity. However these other processes do
not depend on user and group permissions when working with external
agents, processes, etc. Rather they are designed to be stand-alone
network services which authenticate their clients via other
mechanisms. They do depend on user and group permission to manage
their own file system objects. If somehow the ipa user and/or group
were compromised or malicious code somehow executed under the ipa
identity there would be an advantage in having the cooperating
processes cordoned off under their own identities providing one extra
layer of protection. (Note, these cooperating daemons may not even be
co-located on the same node in which case the issue is moot)

The UNIX socket behavior (ldapi) with Directory Server is as follows:

  * The socket ownership is: root:root

  * The socket permissions are: 0666

  * When connecting via ldapi you must authenticate as you would
    normally with a TCP socket, except ...

  * If autobind is enabled and the uid:gid is available via
    SO_PEERCRED and the uid:gid can be found in the set of users known
    to the Directory Server then that connection will be bound as that
    user.

  * Otherwise an anonymous bind will occur.

memcached UNIX socket behavior is as follows:

  * memcached can be invoked with a user argument, no group may be
    specified. The effective uid is the uid of the user argument and
    the effective gid is the primary group of the user, let's call
    this euid:egid

  * The socket ownership is: euid:egid

  * The socket permissions are 0700 by default, but this can be
    modified by the -a mask command line arg which sets the umask
    (defaults to 0700).

Overview of authentication in IPA
=================================

This describes how we currently authenticate and how we plan to
improve authentication performance. First some definitions.

There are 4 major players:

  1. client
  2. mod_auth_gssapi (in Apache process)
  3. wsgi handler (in IPA wsgi python process)
  4. ds (directory server)

There are several resources:

  1. /ipa/ui (unprotected, web UI static resources)
  2. /ipa/xml (protected, xmlrpc RPC used by command line clients)
  3. /ipa/json (protected, json RPC used by javascript in web UI)
  4. ds (protected, wsgi acts as proxy, our LDAP server)

Current Model
-------------

This describes how things work in our current system for the web UI.

  1. Client requests /ipa/ui, this is unprotected, is static and
     contains no sensitive information. Apache replies with html and
     javascript. The javascript requests /ipa/json.

  2. Client sends post to /ipa/json.

  3. mod_auth_gssapi is configured to protect /ipa/json, replies 401
     authenticate negotiate.

  4. Client resends with credentials

  5. mod_auth_gssapi validates credentials

     a. if invalid replies 403 access denied (stops here)

     b. if valid creates temporary ccache, adds KRB5CCNAME to request
        headers

  6. Request passed to wsgi handler

     a. validates request, KRB5CCNAME must be present, referrer, etc.

     b. ccache saved and used to bind to ds

     c. routes to specified RPC handler.

  7. wsgi handler replies to client

Proposed new session based optimization
---------------------------------------

The round trip negotiate and credential validation in steps 3,4,5 is
expensive. This can be avoided if we can cache the client
credentials. With client sessions we can store the client credentials
in the session bound to the client.

A few notes about the session implementation.

  * based on session cookies, cookies must be enabled

  * session cookie is secure, only passed on secure connections, only
    passed to our URL resource, never visible to client javascript
    etc.

  * session cookie has a session id which is used by wsgi handler to
    retrieve client session data from shared multi-process cache.

Changes to Apache's resource protection
---------------------------------------

  * /ipa/json is no longer protected by mod_auth_gssapi. This is
    necessary to avoid the negotiate expense in steps 3,4,5
    above. Instead the /ipa/json resource will be protected in our wsgi
    handler via the session cookie.

  * A new protected URI is introduced, /ipa/login. This resource
    does no serve any data, it is used exclusively for authentication.

The new sequence is:

  1. Client requests /ipa/ui, this is unprotected. Apache replies with
     html and javascript. The javascript requests /ipa/json.

  2. Client sends post to /ipa/json, which is unprotected.

  3. wsgi handler obtains session data from session cookie.

     a. if ccache is present in session data and is valid

        - request is further validated

        - ccache is established for bind to ds

        - request is routed to RPC handler

        - wsgi handler eventually replies to client

     b. if ccache is not present or not valid processing continues ...

  4. wsgi handler replies with 401 Unauthorized

  5. client sends request to /ipa/login to obtain session credentials

  6. mod_auth_gssapi replies 401 negotiate on /ipa/login

  7. client sends credentials to /ipa/login

  8. mod_auth_gssapi validates credentials

     a. if valid

        - mod_auth_gssapi permits access to /ipa/login. wsgi handler is
          invoked and does the following:

          * establishes session for client

          * retrieves the ccache from KRB5CCNAME and stores it

     a. if invalid

        - mod_auth_gssapi sends 403 access denied (processing stops)

  9. client now posts the same data again to /ipa/json including
     session cookie. Processing repeats starting at step 2 and since
     the session data now contains a valid ccache step 3a executes, a
     successful reply is sent to client.

Command line client using xmlrpc
--------------------------------

The above describes the web UI utilizing the json RPC mechanism. The
IPA command line tools utilize a xmlrpc RPC mechanism on the same
HTTP server. Access to the xmlrpc is via the /ipa/xml URI. The json
and xmlrpc API's are the same, they differ only on how their procedure
calls are marshalled and unmarshalled.

Under the new scheme /ipa/xml will continue to be Kerberos protected
at all times. Apache's mod_auth_gssapi will continue to require the
client provides valid Kerberos credentials.

When the WSGI handler routes to /ipa/xml the Kerberos credentials will
be extracted from the KRB5CCNAME environment variable as provided by
mod_auth_gssapi. Everything else remains the same.

'''

#-------------------------------------------------------------------------------

default_max_session_duration = 60*60 # number of seconds

ISO8601_DATETIME_FMT = '%Y-%m-%dT%H:%M:%S' # FIXME, this should be defined elsewhere
def fmt_time(timestamp):
    return time.strftime(ISO8601_DATETIME_FMT, time.localtime(timestamp))

#-------------------------------------------------------------------------------

class AuthManager(object):
    '''
    This class is an abstract base class and is meant to be subclassed
    to provide actual functionality. The purpose is to encapsulate all
    the callbacks one might need to manage authenticaion. Different
    authentication mechanisms will instantiate a subclass of this and
    register it with the SessionAuthManger. When an authentication
    event occurs the matching method will be called for each
    registered class. This allows the SessionAuthManager to notify
    interested parties.
    '''

    def __init__(self, name):
        log_mgr.get_logger(self, True)
        self.name = name


    def logout(self, session_data):
        '''
        Called when a user requests to be logged out of their session.

        :parameters:
          session_data
            The current session data
        :returns:
          None
        '''
        self.debug('AuthManager.logout.%s:', self.name)

class SessionAuthManager(object):

    def __init__(self):
        log_mgr.get_logger(self, True)
        self.auth_managers = {}

    def register(self, name, auth_mgr):
        self.debug('SessionAuthManager.register: name=%s', name)

        existing_mgr = self.auth_managers.get(name)
        if existing_mgr is not None:
            raise KeyError('cannot register auth manager named "%s" one already exists, name="%s" object=%s',
                           name, existing_mgr.name, repr(existing_mgr))

        if not isinstance(auth_mgr, AuthManager):
            raise TypeError('auth_mgr must be an instance of AuthManager, not %s',
                            auth_mgr.__class__.__name__)

        self.auth_managers[name] = auth_mgr


    def unregister(self, name):
        self.debug('SessionAuthManager.unregister: name=%s', name)

        if name not in self.auth_managers:
            raise KeyError('cannot unregister auth manager named "%s", does not exist',
                           name)
        del self.auth_managers[name]


    def logout(self, session_data):
        self.debug('SessionAuthManager.logout:')

        for auth_mgr in self.auth_managers.values():
            try:
                auth_mgr.logout(session_data)
            except Exception as e:
                self.error('%s auth_mgr logout failed: %s', auth_mgr.name, e)

#-------------------------------------------------------------------------------

class SessionManager(object):

    '''
    This class is used to manage a set of sessions. Each client
    connecting to the server is assigned a session id wich is then
    used to store data bound to the client's session in between server
    requests.
    '''

    def __init__(self):
        '''
        :returns:
          `SessionManager` object
        '''

        log_mgr.get_logger(self, True)
        self.generated_session_ids = set()
        self.auth_mgr = SessionAuthManager()

    def generate_session_id(self, n_bits=128):
        '''
        Return a random string to be used as a session id.

        This implementation creates a string of hexadecimal digits.
        There is no guarantee of uniqueness, it is the caller's
        responsibility to validate the returned id is not currently in
        use.

        :parameters:
          n_bits
            number of bits of random data, will be rounded to next
            highest multiple of 4
        :returns:
          string of random hexadecimal digits
        '''
        # round up to multiple of 4
        n_bits = (n_bits + 3) & ~3
        session_id = '%0*x' % (n_bits >> 2, random.getrandbits(n_bits))
        return session_id

    def new_session_id(self, max_retries=5):
        '''
        Returns a new *unique* session id. See `generate_session_id()`
        for how the session id's are formulated.

        The scope of the uniqueness of the id is limited to id's
        generated by this instance of the `SessionManager`.

        :parameters:
          max_retries
            Maximum number of attempts to produce a unique id.
        :returns:
          Unique session id as a string.
        '''
        n_retries = 0
        while n_retries < max_retries:
            session_id = self.generate_session_id()
            if not session_id in self.generated_session_ids:
                break
            n_retries += 1
        if n_retries >= max_retries:
            self.error('could not allocate unique new session_id, %d retries exhausted', n_retries)
            raise errors.ExecutionError(message=_('could not allocate unique new session_id'))
        self.generated_session_ids.add(session_id)
        return session_id


class MemcacheSessionManager(SessionManager):
    '''

    This class is used to assign a session id to a HTTP server client
    and then store client specific data associated with the session in
    a memcached memory cache instance. Multiple processes may share
    the memory cache permitting session data to be shared between
    forked HTTP server children handling server requests.

    The session id is guaranteed to be unique.

    The session id is set into a session cookie returned to the client
    and is secure (see `generate_cookie()`). Future requests from the
    client will send the session id which is then used to retrieve the
    session data (see `load_session_data()`)
    '''

    memcached_socket_path = paths.VAR_RUN_IPA_MEMCACHED
    session_cookie_name = 'ipa_session'
    mc_server_stat_name_re = re.compile(r'(.+)\s+\((\d+)\)')

    def __init__(self):
        '''
        :returns:
          `MemcacheSessionManager` object.
        '''

        super(MemcacheSessionManager, self).__init__()
        self.servers = ['unix:%s' % self.memcached_socket_path]
        self.mc = memcache.Client(self.servers, debug=0)

        if not self.servers_running():
            self.warning("session memcached servers not running")

    def get_server_statistics(self):
        '''
        Return memcached server statistics.

        Return value is a dict whose keys are server names and whose
        value is a dict of key/value statistics as returned by the
        memcached server.

        :returns:
          dict of server names, each value is dict of key/value server
          statistics.

        '''
        result = {}
        stats = self.mc.get_stats()
        for server in stats:
            match = self.mc_server_stat_name_re.search(server[0].decode())
            if match:
                name = match.group(1)
                result[name] = server[1]
            else:
                self.warning('unparseable memcached server name "%s"', server[0])
        return result

    def servers_running(self):
        '''
        Check if all configured memcached servers are running and can
        be communicated with.

        :returns:
          True if at least one server is configured and all servers
          can respond, False otherwise.

        '''

        if len(self.servers) == 0:
            return False
        stats = self.get_server_statistics()
        return len(self.servers) == len(stats)

    def new_session_id(self, max_retries=5):
        '''
        Returns a new *unique* session id. See `generate_session_id()`
        for how the session id's are formulated.

        The scope of the uniqueness of the id is limited to id's
        generated by this instance of the `SessionManager` and session
        id's currently stored in the memcache instance.

        :parameters:
          max_retries
            Maximum number of attempts to produce a unique id.
        :returns:
          Unique session id as a string.
        '''
        n_retries = 0
        while n_retries < max_retries:
            session_id = super(MemcacheSessionManager, self).new_session_id(max_retries)
            session_data = self.get_session_data(session_id)
            if session_data is None:
                break
            n_retries += 1
        if n_retries >= max_retries:
            self.error('could not allocate unique new session_id, %d retries exhausted', n_retries)
            raise errors.ExecutionError(message=_('could not allocate unique new session_id'))
        return session_id

    def new_session_data(self, session_id):
        '''
        Return a new session data dict. The session data will be
        associated with it's session id. The dict will be
        pre-populated with:

        session_id
          The session ID used to identify this session data.
        session_start_timestamp
          Timestamp when this session was created.
        session_access_timestamp
          Timestamp when the session was last accessed.
        session_expiration_timestamp
          Timestamp when session expires. Defaults to zero which
          implies no expiration. See `set_session_expiration_time()`.

        :parameters:
          session_id
            The session id used to look up this session data.
        :returns:
          Session data dict populated with a session_id key.
        '''

        now = time.time()
        return {'session_id'                   : session_id,
                'session_start_timestamp'      : now,
                'session_access_timestamp'     : now,
                'session_expiration_timestamp' : 0,
               }

    def session_key(self, session_id):
        '''
        Given a session id return a memcache key used to look up the
        session data in the memcache.

        :parameters:
          session_id
            The session id from which the memcache key will be derived.
        :returns:
          A key (string) used to look up the session data in the memcache.
        '''
        return 'ipa.session.%s' % (session_id)

    def get_session_data(self, session_id):
        '''
        Given a session id retrieve the session data associated with it.
        If no session data exists for the session id return None.

        :parameters:
          session_id
            The session id whose session data is desired.
        :returns:
          Session data if found, None otherwise.
        '''
        session_key = self.session_key(session_id)
        session_data = self.mc.get(session_key)

        if session_data is not None:
            # update the access timestamp
            now = time.time()
            session_data['session_access_timestamp'] = now

        return session_data

    def get_session_id_from_http_cookie(self, cookie_header):
        '''
        Parse an HTTP cookie header and search for our session
        id. Return the session id if found, return None if not
        found.

        :parameters:
          cookie_header
            An HTTP cookie header. May be None, if None return None.
        :returns:
          Session id as string or None if not found.
        '''

        if cookie_header is None:
            return None

        session_id = None

        try:
            session_cookie = Cookie.get_named_cookie_from_string(cookie_header, self.session_cookie_name)
        except Exception:
            session_cookie = None
        if session_cookie:
            session_id = session_cookie.value

        if session_id is None:
            self.debug('no session cookie found')
        else:
            self.debug('found session cookie_id = %s', session_id)

        return session_id


    def load_session_data(self, cookie_header):
        '''
        Parse an HTTP cookie header looking for our session
        information.

        * If no session id is found then a new session id and new
          session data dict will be generated, stored in the memcache
          and returned. The new session data dict will contain the new
          session id.

        * If the session id is found in the cookie an attempt is made
          to retrieve the session data from the memcache using the
          session id.

          - If existing session data is found in the memcache it is
            returned.

          - If no session data is found in the memcache then a new
            session data dict will be generated, stored in the
            memcache and returned. The new session data dict will
            contain the session id found in the cookie header.

        :parameters:
          cookie_header
            An HTTP cookie header. May be None.
        :returns:
          Session data dict containing at a minimum the session id it
          is bound to.
        '''

        session_id = self.get_session_id_from_http_cookie(cookie_header)
        if session_id is None:
            session_id = self.new_session_id()
            self.debug('no session id in request, generating empty session data with id=%s', session_id)
            session_data = self.new_session_data(session_id)
            self.store_session_data(session_data)
            return session_data
        else:
            session_data = self.get_session_data(session_id)
            if session_data is None:
                self.debug('no session data in cache with id=%s, generating empty session data', session_id)
                session_data = self.new_session_data(session_id)
                self.store_session_data(session_data)
                return session_data
            else:
                self.debug('found session data in cache with id=%s', session_id)
                return session_data

    def store_session_data(self, session_data):
        '''
        Store the supplied session_data dict in the memcached instance.

        The session_expiration_timestamp is always passed to memcached
        when the session data is written back to the memcache. This is
        because otherwise the memcache expiration will default to zero
        if it's not specified which implies no expiration. Thus a
        failure to specify an exiration time when writing an item to
        memcached will cause a previously set expiration time for the
        item to be discarded and the item will no longer expire.

        :parameters:
          session_data
            Session data dict, must contain session_id key.

        :returns:
          session_id
        '''
        session_id = session_data['session_id']
        session_key = self.session_key(session_id)

        # update the access timestamp
        now = time.time()
        session_data['session_access_timestamp'] = now

        session_expiration_timestamp = session_data['session_expiration_timestamp']

        self.debug('store session: session_id=%s start_timestamp=%s access_timestamp=%s expiration_timestamp=%s',
                   session_id,
                   fmt_time(session_data['session_start_timestamp']),
                   fmt_time(session_data['session_access_timestamp']),
                   fmt_time(session_data['session_expiration_timestamp']))

        self.mc.set(session_key, session_data, time=session_expiration_timestamp)
        return session_id

    def generate_cookie(self, url_path, session_id, expiration=None, add_header=False):
        '''
        Return a session cookie containing the session id. The cookie
        will be contrainted to the url path, defined for use
        with HTTP only, and only returned on secure connections (SSL).

        :parameters:
          url_path
            The cookie will be returned in a request if it begins
            with this url path.
          session_id
            The session id identified by the session cookie
          add_header
            If true format cookie string with Set-Cookie: header

        :returns:
          cookie string
        '''

        if not expiration:      # Catch zero unix timestamps
            expiration = None

        cookie = Cookie(self.session_cookie_name, session_id,
                        domain=urlparse(api.env.xmlrpc_uri).netloc,
                        path=url_path, httponly=True, secure=True,
                        expires=expiration)
        if add_header:
            result = 'Set-Cookie: %s' % cookie
        else:
            result = str(cookie)

        return result

    def set_session_expiration_time(self, session_data,
                                    duration=default_max_session_duration,
                                    max_age=None, duration_type='inactivity_timeout'):
        '''
        memcached permits setting an expiration time on entries. The
        expiration time may either be Unix time (number of seconds since
        January 1, 1970, as a 32-bit value), or a number of seconds starting
        from current time. In the latter case, this number of seconds may
        not exceed 60*60*24*30 (number of seconds in 30 days); if the number
        sent by a client is larger than that, the server will consider it to
        be real Unix time value rather than an offset from current time.

        We never use the duration value (< 30 days), we always use a
        timestamp, this makes it easier to integrate with other time
        constraints.

        When a session is created it's start time is recorded in the
        session data as the session_start_timestamp value.

        There are two ways the expiration timestamp can be computed:

          from_start
            A session has a fixed duration beginning with the start of
            the session. The session expires when the duration
            interval has elapsed relative to the start of the session.
          inactivity_timeout
            A session times out after a period of inactivity. The
            expiration time is advanced by the value of the duration
            interval everytime the session is updated.

        After the expiration is computed it may be capped at a maximum
        value due to other constraints (e.g. authentication credential
        expiration). If the optional max_age parameter is specified
        then expiration is constrained to be not greater than the
        max_age.

        The final computed expiration is then written into the
        session_data as the session_expiration_timestamp value. The
        session_expiration_timestamp is always passed to memcached
        when the session data is written back to the memcache. This is
        because otherwise the memcache expiration will default to zero
        if it's not specified which implies no expiration. Thus a
        failure to specify an exiration time when writing an item to
        memcached will cause a previously set expiration time for the
        item to be discarded and the item will no longer expire.


        :parameters:
          session_data
            Session data dict, must contain session_id key.
          duration
            Number of seconds cache entry should live. This is a
            duration value, not a timestamp.  Zero implies no
            expiration.
          max_age
            Unix time value when cache entry must expire by.

        :returns:
          expiration timestamp, zero implies no expiration
        '''

        if duration == 0 and max_age is None:
            # No expiration
            expiration = 0
            session_data['session_expiration_timestamp'] = expiration
            return expiration

        if duration_type == 'inactivity_timeout':
            now = time.time()
            session_data['session_access_timestamp'] = now
            expiration = now + duration
        elif duration_type == 'from_start':
            session_start_timestamp = session_data['session_start_timestamp']
            expiration = session_start_timestamp + duration
        else:
            # Don't throw an exception, it's critical the session be
            # given some expiration, instead log the error and execute
            # a default action of expiring the session 5 minutes after
            # it was initiated (similar to from_start but with
            # hardcoded duration)
            default = 60*5
            self.warning('unknown session duration_type (%s), defaulting to %s seconds from session start',
                         duration_type, default)
            session_start_timestamp = session_data['session_start_timestamp']
            expiration = session_start_timestamp + default

        # Cap the expiration if max_age is specified
        if max_age is not None:
            expiration = min(expiration, max_age)

        session_data['session_expiration_timestamp'] = expiration

        self.debug('set_session_expiration_time: duration_type=%s duration=%s max_age=%s expiration=%s (%s)',
                   duration_type, duration, max_age, expiration, fmt_time(expiration))

        return expiration

    def delete_session_data(self, session_id):
        '''
        Given a session id removed the session data bound to the id from the memcache.

        :parameters:
          session_id
            The ID of the session which should be removed from the cache.
        :returns:
          None
        '''
        session_key = self.session_key(session_id)

        self.debug('delete session data from memcache, session_id=%s', session_id)
        self.mc.delete(session_key)


#-------------------------------------------------------------------------------
krbccache_dir =paths.IPA_MEMCACHED_DIR
krbccache_prefix = 'krbcc_'

def _get_krbccache_pathname():
    return os.path.join(krbccache_dir, '%s%s' % (krbccache_prefix, os.getpid()))

def get_ipa_ccache_name(scheme='FILE'):
    if scheme == 'FILE':
        name = os.path.join(krbccache_dir, '%s%s' % (krbccache_prefix, os.getpid()))
    else:
        raise ValueError('ccache scheme "%s" unsupported', scheme)

    ccache_name = krb5_unparse_ccache(scheme, name)
    return ccache_name


def load_ccache_data(ccache_name):
    scheme, name = krb5_parse_ccache(ccache_name)
    if scheme == 'FILE':
        root_logger.debug('reading ccache data from file "%s"', name)
        with io.open(name, "rb") as src:
            ccache_data = src.read()
        return ccache_data
    else:
        raise ValueError('ccache scheme "%s" unsupported (%s)', scheme, ccache_name)

def bind_ipa_ccache(ccache_data, scheme='FILE'):
    if scheme == 'FILE':
        name = _get_krbccache_pathname()
        root_logger.debug('storing ccache data into file "%s"', name)
        with io.open(name, 'wb') as dst:
            dst.write(ccache_data)
    else:
        raise ValueError('ccache scheme "%s" unsupported', scheme)

    ccache_name = krb5_unparse_ccache(scheme, name)
    os.environ['KRB5CCNAME'] = ccache_name
    return ccache_name

def release_ipa_ccache(ccache_name):
    '''
    Stop using the current request's ccache.
      * Remove KRB5CCNAME from the enviroment
      * Remove the ccache file from the file system

    Note, we do not demand any of these elements exist, but if they
    do we'll remove them.
    '''

    if 'KRB5CCNAME' in os.environ:
        if ccache_name != os.environ['KRB5CCNAME']:
            root_logger.error('release_ipa_ccache: ccache_name (%s) != KRB5CCNAME environment variable (%s)',
                              ccache_name, os.environ['KRB5CCNAME'])
        del os.environ['KRB5CCNAME']
    else:
        root_logger.debug('release_ipa_ccache: KRB5CCNAME environment variable not set')

    scheme, name = krb5_parse_ccache(ccache_name)
    if scheme == 'FILE':
        if os.path.exists(name):
            try:
                os.unlink(name)
            except Exception as e:
                root_logger.error('unable to delete session ccache file "%s", %s', name, e)
    else:
        raise ValueError('ccache scheme "%s" unsupported (%s)', scheme, ccache_name)

_session_mgr = None


def get_session_mgr():
    global _session_mgr
    if _session_mgr is None:
        _session_mgr = MemcacheSessionManager()
    return _session_mgr
