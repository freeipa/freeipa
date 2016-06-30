#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

# pylint: disable=unused-import
import six

from . import Command, Method, Object
from ipalib import api, parameters, output
from ipalib.parameters import DefaultFrom
from ipalib.plugable import Registry
from ipalib.text import _
from ipapython.dn import DN
from ipapython.dnsutil import DNSName

if six.PY3:
    unicode = str

__doc__ = _("""
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
  2. mod_auth_kerb (in Apache process)
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

  3. mod_auth_kerb is configured to protect /ipa/json, replies 401
     authenticate negotiate.

  4. Client resends with credentials

  5. mod_auth_kerb validates credentials

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

  * /ipa/json is no longer protected by mod_auth_kerb. This is
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

  6. mod_auth_kerb replies 401 negotiate on /ipa/login

  7. client sends credentials to /ipa/login

  8. mod_auth_kerb validates credentials

     a. if valid

        - mod_auth_kerb permits access to /ipa/login. wsgi handler is
          invoked and does the following:

          * establishes session for client

          * retrieves the ccache from KRB5CCNAME and stores it

     a. if invalid

        - mod_auth_kerb sends 403 access denied (processing stops)

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
at all times. Apache's mod_auth_kerb will continue to require the
client provides valid Kerberos credentials.

When the WSGI handler routes to /ipa/xml the Kerberos credentials will
be extracted from the KRB5CCNAME environment variable as provided by
mod_auth_kerb. Everything else remains the same.
""")

register = Registry()


@register()
class session_logout(Command):
    __doc__ = _("RPC command used to log the current user out of their session.")

    has_output = (
        output.Output(
            'result',
        ),
    )
