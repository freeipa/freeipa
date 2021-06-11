# Copyright (C) 2015  Custodia Project Contributors - see LICENSE file
from __future__ import absolute_import

import atexit
import errno
import os
import shutil
import socket
import ssl
import struct
import sys
import warnings

import six

from custodia import log
from custodia.compat import parse_qs, unquote, urlparse
from custodia.plugin import HTTPError

# pylint: disable=import-error,no-name-in-module
if six.PY2:
    from BaseHTTPServer import BaseHTTPRequestHandler
    from SocketServer import ForkingTCPServer, BaseServer
else:
    from http.server import BaseHTTPRequestHandler
    from socketserver import ForkingTCPServer, BaseServer
# pylint: enable=import-error,no-name-in-module

try:
    from systemd import daemon as sd  # pylint: disable=import-error
except ImportError:
    sd = None
    if 'NOTIFY_SOCKET' in os.environ:
        warnings.warn(
            "NOTIFY_SOCKET env var is set but python-systemd bindings are "
            "not available!",
            category=RuntimeWarning
        )
    if 'LISTEN_FDS' in os.environ:
        warnings.warn(
            "LISTEN_FDS env var is set, but python-systemd bindings are"
            "not available!",
            category=RuntimeWarning
        )


logger = log.getLogger(__name__)

SO_PEERCRED = getattr(socket, 'SO_PEERCRED', 17)
SO_PEERSEC = getattr(socket, 'SO_PEERSEC', 31)
SELINUX_CONTEXT_LEN = 256
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # For now limit body to 10MiB


class ForkingHTTPServer(ForkingTCPServer):
    """
    A forking HTTP Server.
    Each request runs into a forked server so that the whole environment
    is clean and isolated, and parallel requests cannot unintentionally
    influence one another.

    When a request is received it is parsed by the handler_class provided
    at server initialization.
    """
    server_string = "Custodia/0.1"
    allow_reuse_address = True
    socket_file = None

    def __init__(self, server_address, handler_class, config,
                 bind_and_activate=True):
        # pylint: disable=super-init-not-called, non-parent-init-called
        # Init just BaseServer, TCPServer creates a socket.
        BaseServer.__init__(self, server_address, handler_class)

        if isinstance(server_address, socket.socket):
            # It's a bound and activates socket from systemd.
            self.socket = server_address
            bind_and_activate = False
        else:
            self.socket = socket.socket(self.address_family,
                                        self.socket_type)

        # copied from TCPServer
        if bind_and_activate:
            try:
                self.server_bind()
                self.server_activate()
            except BaseException:
                self.server_close()
                raise

        if self.socket.family == socket.AF_UNIX:
            self.socket_file = self.socket.getsockname()

        if 'consumers' not in config:
            raise ValueError('Configuration does not provide any consumer')
        self.config = config
        if 'server_string' in self.config:
            self.server_string = self.config['server_string']
        self.auditlog = log.auditlog


class ForkingUnixHTTPServer(ForkingHTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        self.unlink()
        # Remove on exit
        atexit.register(self.unlink)
        basedir = os.path.dirname(self.server_address)
        if not os.path.isdir(basedir):
            os.makedirs(basedir, mode=0o755)
        ForkingHTTPServer.server_bind(self)
        os.chmod(self.server_address, 0o666)

    def unlink(self):
        try:
            os.unlink(self.server_address)
        except OSError:
            pass


class ForkingTLSServer(ForkingHTTPServer):
    def __init__(self, server_address, handler_class, config, context=None,
                 bind_and_activate=True):
        ForkingHTTPServer.__init__(self, server_address, handler_class, config,
                                   bind_and_activate=bind_and_activate)
        if context is None:
            try:
                self._context = self._mkcontext()
            except Exception as e:
                logger.error(
                    "Failed to create a SSLContext for TLS server: %s", e
                )
                raise
        else:
            self._context = context

    def _mkcontext(self):
        certfile = self.config.get('tls_certfile')
        keyfile = self.config.get('tls_keyfile')
        cafile = self.config.get('tls_cafile')
        capath = self.config.get('tls_capath')
        if self.config.get('tls_verify_client', False):
            verifymode = ssl.CERT_REQUIRED
        else:
            verifymode = ssl.CERT_NONE

        if not certfile:
            raise ValueError('tls_certfile is not set.')

        logger.info(
            "Creating SSLContext for TLS server (cafile: '%s', capath: '%s', "
            "verify client: %s).",
            cafile, capath, verifymode == ssl.CERT_REQUIRED
        )
        context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH,
            cafile=cafile,
            capath=capath)
        context.verify_mode = verifymode
        logger.info(
            "Loading cert chain '%s' (keyfile: '%s')", certfile, keyfile)
        context.load_cert_chain(certfile, keyfile)
        return context

    def get_request(self):
        conn, client_addr = self.socket.accept()
        sslconn = self._context.wrap_socket(conn, server_side=True)
        return sslconn, client_addr


class HTTPRequestHandler(BaseHTTPRequestHandler):

    """
    This request handler is a slight modification of BaseHTTPRequestHandler
    where the per-request handler is replaced.

    When a request comes in it is parsed and the 'request' dictionary is
    populated accordingly. Additionally a 'creds' structure is added to the
    request.

    The 'creds' structure contains the data retrieved via a call to
    getsockopt with the SO_PEERCRED option. This retrieves via kernel assist
    the uid,gid and pid of the process on the other side of the unix socket
    on which the request has been made. This can be used for authentication
    and/or authorization purposes.
    The 'creds' structure is further augmented with a 'context' option
    containing the Selinux Context string for the calling process, if
    available.

    after the request is parsed the server's pipeline() function is invoked
    in order to handle it. The pipeline() should return a response object,
    where te return 'code', the 'output' and 'headers' may be found.

    If no 'code' is present the request is assumed to be successful and a
    '200 OK' status code will be sent back to the client.

    The 'output' parameter can be a string or a file like object.

    The 'headers' objct must be a dictionary where keys are headers names.

    By default we assume HTTP1.0
    """

    protocol_version = "HTTP/1.0"

    def __init__(self, request, client_address, server):
        self.requestline = ''
        self.request_version = ''
        self.command = ''
        self.raw_requestline = None
        self.close_connection = 0
        self.path = None  # quoted, raw path
        self.path_chain = None  # tuple of unquoted segments
        self.query = None
        self.url = None
        self.body = None
        self.loginuid = None
        self._creds = False
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    def version_string(self):
        return self.server.server_string

    def _get_loginuid(self, pid):
        loginuid = None
        # NOTE: Using proc to find the login uid is not reliable
        # this is why login uid is fetched separately and not stored
        # into 'creds', to avoid giving the false impression it can be
        # used to perform access control decisions
        try:
            with open("/proc/%i/loginuid" % pid, "r") as f:
                loginuid = int(f.read())
        except IOError as e:
            if e.errno != errno.ENOENT:
                raise
        if loginuid == -1:
            loginuid = None
        return loginuid

    @property
    def peer_creds(self):
        if self._creds is not False:
            return self._creds
        # works only for unix sockets
        if self.request.family != socket.AF_UNIX:
            self._creds = None
            return self._creds
        # pid_t: signed int32, uid_t/gid_t: unsigned int32
        fmt = 'iII'
        creds = self.request.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                                        struct.calcsize(fmt))
        pid, uid, gid = struct.unpack(fmt, creds)
        try:
            creds = self.request.getsockopt(socket.SOL_SOCKET, SO_PEERSEC,
                                            SELINUX_CONTEXT_LEN)
            context = creds.rstrip(b'\x00').decode('utf-8')
        except Exception:  # pylint: disable=broad-except
            logger.debug("Couldn't retrieve SELinux Context", exc_info=True)
            context = None

        self._creds = {'pid': pid, 'uid': uid, 'gid': gid, 'context': context}
        return self._creds

    @property
    def peer_info(self):
        if self.peer_creds is not None:
            return self._creds['pid']
        elif self.request.family in {socket.AF_INET, socket.AF_INET6}:
            return self.request.getpeername()
        return None

    @property
    def peer_cert(self):
        if not hasattr(self.request, 'getpeercert'):
            return None
        return self.request.getpeercert()

    def parse_request(self):
        if not BaseHTTPRequestHandler.parse_request(self):
            return False

        # grab the loginuid from `/proc` as soon as possible
        creds = self.peer_creds
        if creds is not None:
            self.loginuid = self._get_loginuid(creds['pid'])

        # after basic parsing also use urlparse to retrieve individual
        # elements of a request.
        url = urlparse(self.path)

        # Yes, override path with the path part only
        self.path = url.path
        self.path_chain = self._parse_path(url)

        # Create dict out of query
        self.query = parse_qs(url.query)

        # keep the rest into the 'url' element in case someone needs it
        self.url = url

        return True

    def _parse_path(self, url):
        path_chain = []
        for segment in url.path.split('/'):
            # unquote URL path encoding
            segment = unquote(segment)
            path_chain.append(segment)
        return tuple(path_chain)

    def parse_body(self):
        length = int(self.headers.get('content-length', 0))
        if length > MAX_REQUEST_SIZE:
            raise HTTPError(413)
        if length == 0:
            self.body = None
        else:
            self.body = self.rfile.read(length)

    def handle_one_request(self):
        if self.request.family == socket.AF_UNIX:
            # Set a fake client address to make log functions happy
            self.client_address = ['127.0.0.1', 0]
        try:
            if not self.server.config:
                self.close_connection = 1
                return
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = 1
                return
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                self.wfile.flush()
                return
            if not self.parse_request():
                self.close_connection = 1
                return
            try:
                self.parse_body()
            except HTTPError as e:
                self.send_error(e.code, e.mesg)
                self.wfile.flush()
                return
            request = {'creds': self.peer_creds,
                       'client_cert': self.peer_cert,
                       'client_id': self.peer_info,
                       'command': self.command,
                       'path': self.path,
                       'path_chain': self.path_chain,
                       'query': self.query,
                       'url': self.url,
                       'version': self.request_version,
                       'headers': self.headers,
                       'body': self.body}
            logger.debug(
                "REQUEST: %s %s, query: %r, cred: %r, client_id: %s, "
                "headers: %r, body: %r",
                request['command'], request['path_chain'], request['query'],
                request['creds'], request['client_id'],
                dict(request['headers']), request['body']
            )
            try:
                response = self.pipeline(self.server.config, request)
                if response is None:
                    raise HTTPError(500)
            except HTTPError as e:
                self.send_error(e.code, e.mesg)
                self.wfile.flush()
                return
            except socket.timeout as e:
                self.log_error("Request timed out: %r", e)
                self.close_connection = 1
                return
            except Exception as e:  # pylint: disable=broad-except
                self.log_error("Handler failed: %r", e, exc_info=True)
                self.send_error(500)
                self.wfile.flush()
                return

            self.send_response(response.get('code', 200))
            for header, value in six.iteritems(response.get('headers', {})):
                self.send_header(header, value)
            self.end_headers()

            output = response.get('output', None)
            if hasattr(output, 'read'):
                shutil.copyfileobj(output, self.wfile)
                output.close()
            elif output is not None:
                self.wfile.write(output)
            else:
                self.close_connection = 1
            self.wfile.flush()
            return
        except socket.timeout as e:
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

    # pylint: disable=arguments-differ
    def log_error(self, fmtstr, *args, **kwargs):
        logger.error(fmtstr, *args, **kwargs)

    def pipeline(self, config, request):
        """
        The pipeline() function handles authentication and invocation of
        the correct consumer based on the server configuration, that is
        provided at initialization time.

        When authentication is performed all the authenticators are
        executed. If any returns False, authentication fails and a 403
        error is raised. If none of them positively succeeds and they all
        return None then also authentication fails and a 403 error is
        raised. Authentication plugins can add attributes to the request
        object for use of authorization or other plugins.

        When authorization is performed and positive result will cause the
        operation to be accepted and any negative result will cause it to
        fail. If no authorization plugin returns a positive result a 403
        error is returned.

        Once authentication and authorization are successful the pipeline
        will parse the path component and find the consumer plugin that
        handles the provided path walking up the path component by
        component until a consumer is found.

        Paths are walked up from the leaf to the root, so if two consumers
        hang on the same tree, the one closer to the leaf will be used. If
        there is a trailing path when the conumer is selected then it will
        be stored in the request dicstionary named 'trail'. The 'trail' is
        an ordered list of the path components below the consumer entry
        point.
        """
        path_chain = request['path_chain']
        if not path_chain or path_chain[0] != '':
            # no path or not an absolute path
            raise HTTPError(400)

        # auth framework here
        authers = config.get('authenticators')
        if authers is None:
            raise HTTPError(403)
        valid_once = False
        for auth in authers:
            valid = authers[auth].handle(request)
            if valid is False:
                raise HTTPError(403)
            elif valid is True:
                valid_once = True
        if valid_once is not True:
            self.server.auditlog.svc_access(self.__class__.__name__,
                                            log.AUDIT_SVC_AUTH_FAIL,
                                            request['client_id'], 'No auth')
            raise HTTPError(403)

        # auhz framework here
        authzers = config.get('authorizers')
        if authzers is None:
            raise HTTPError(403)
        authz_ok = None
        for authz in authzers:
            valid = authzers[authz].handle(request)
            if valid is True:
                authz_ok = True
            elif valid is False:
                authz_ok = False
                break
        if authz_ok is not True:
            self.server.auditlog.svc_access(self.__class__.__name__,
                                            log.AUDIT_SVC_AUTHZ_FAIL,
                                            request['client_id'],
                                            path_chain)
            raise HTTPError(403)

        # Select consumer
        trail = []
        while path_chain:
            if path_chain in config['consumers']:
                con = config['consumers'][path_chain]
                if len(trail) != 0:
                    request['trail'] = trail
                return con.handle(request)
            trail.insert(0, path_chain[-1])
            path_chain = path_chain[:-1]

        raise HTTPError(404)


class HTTPServer(object):
    handler = HTTPRequestHandler

    def __init__(self, srvurl, config):
        url = urlparse(srvurl)
        serverclass, address = self._get_serverclass(url)
        if sd is not None:
            address = self._get_systemd_socket(address)
        self.httpd = serverclass(address, self.handler, config)

    def _get_serverclass(self, url):
        if url.scheme == 'http+unix':
            # Unix socket
            address = unquote(url.netloc)
            if not address:
                raise ValueError('Empty address {}'.format(url))
            logger.info('Serving on Unix socket %s', address)
            serverclass = ForkingUnixHTTPServer
        elif url.scheme == 'http':
            host, port = url.netloc.split(":")
            address = (host, int(port))
            logger.info('Serving on %s (HTTP)', url.netloc)
            serverclass = ForkingHTTPServer
        elif url.scheme == 'https':
            host, port = url.netloc.split(":")
            address = (host, int(port))
            logger.info('Serving on %s (HTTPS)', url.netloc)
            serverclass = ForkingTLSServer
        else:
            raise ValueError('Unknown URL Scheme: %s' % url.scheme)
        return serverclass, address

    def _get_systemd_socket(self, address):
        fds = sd.listen_fds()
        if not fds:
            return address
        elif len(fds) > 1:
            raise ValueError('Too many listening sockets', fds)

        if isinstance(address, tuple):
            port = address[1]
            # systemd uses IPv6
            if not sd.is_socket_inet(fds[0], family=socket.AF_INET6,
                                     type=socket.SOCK_STREAM,
                                     listening=True, port=port):
                raise ValueError(
                    "FD {} is not TCP IPv6 socket on port {}".format(
                        fds[0], port
                    )
                )
            logger.info('Using systemd socket activation on port %i', port)
            sock = socket.fromfd(fds[0], socket.AF_INET6, socket.SOCK_STREAM)
        else:
            if not sd.is_socket_unix(fds[0], socket.SOCK_STREAM,
                                     listening=True, path=address):
                raise ValueError(
                    "FD {} is not Unix stream socket on path {}".format(
                        fds[0], address
                    )
                )
            logger.info('Using systemd socket activation on path %s', address)
            sock = socket.fromfd(fds[0], socket.AF_UNIX, socket.SOCK_STREAM)

        if sys.version_info[0] < 3:
            # Python 2.7's socket.fromfd() returns _socket.socket
            sock = socket.socket(_sock=sock)
        return sock

    def get_socket(self):
        return (self.httpd.socket, self.httpd.socket_file)

    def serve(self):
        if sd is not None and sd.booted():
            sd.notify("READY=1")
        return self.httpd.serve_forever()
