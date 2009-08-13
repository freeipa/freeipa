# This is a forward backport of the Python2.5 uuid module. It isn't available
# in Python 2.6

# The next several classes are used to define FakeSocket, a socket-like
# interface to an SSL connection.

# The primary complexity comes from faking a makefile() method.  The
# standard socket makefile() implementation calls dup() on the socket
# file descriptor.  As a consequence, clients can call close() on the
# parent socket and its makefile children in any order.  The underlying
# socket isn't closed until they are all closed.

# The implementation uses reference counting to keep the socket open
# until the last client calls close().  SharedSocket keeps track of
# the reference counting and SharedSocketClient provides an constructor
# and close() method that call incref() and decref() correctly.

import socket
import errno
from httplib import UnimplementedFileMode, HTTPException

error = HTTPException

class SharedSocket:
    def __init__(self, sock):
        self.sock = sock
        self._refcnt = 0

    def incref(self):
        self._refcnt += 1

    def decref(self):
        self._refcnt -= 1
        assert self._refcnt >= 0
        if self._refcnt == 0:
            self.sock.close()

    def __del__(self):
        self.sock.close()

class SharedSocketClient:

    def __init__(self, shared):
        self._closed = 0
        self._shared = shared
        self._shared.incref()
        self._sock = shared.sock

    def close(self):
        if not self._closed:
            self._shared.decref()
            self._closed = 1
            self._shared = None

class SSLFile(SharedSocketClient):
    """File-like object wrapping an SSL socket."""

    BUFSIZE = 8192

    def __init__(self, sock, ssl, bufsize=None):
        SharedSocketClient.__init__(self, sock)
        self._ssl = ssl
        self._buf = ''
        self._bufsize = bufsize or self.__class__.BUFSIZE

    def _read(self):
        buf = ''
        # put in a loop so that we retry on transient errors
        while True:
            try:
                buf = self._ssl.read(self._bufsize)
            except socket.sslerror, err:
                if (err[0] == socket.SSL_ERROR_WANT_READ
                    or err[0] == socket.SSL_ERROR_WANT_WRITE):
                    continue
                if (err[0] == socket.SSL_ERROR_ZERO_RETURN
                    or err[0] == socket.SSL_ERROR_EOF):
                    break
                raise
            except socket.error, err:
                if err[0] == errno.EINTR:
                    continue
                if err[0] == errno.EBADF:
                    # XXX socket was closed?
                    break
                raise
            else:
                break
        return buf

    def read(self, size=None):
        L = [self._buf]
        avail = len(self._buf)
        while size is None or avail < size:
            s = self._read()
            if s == '':
                break
            L.append(s)
            avail += len(s)
        alldata = "".join(L)
        if size is None:
            self._buf = ''
            return alldata
        else:
            self._buf = alldata[size:]
            return alldata[:size]

    def readline(self):
        L = [self._buf]
        self._buf = ''
        while 1:
            i = L[-1].find("\n")
            if i >= 0:
                break
            s = self._read()
            if s == '':
                break
            L.append(s)
        if i == -1:
            # loop exited because there is no more data
            return "".join(L)
        else:
            alldata = "".join(L)
            # XXX could do enough bookkeeping not to do a 2nd search
            i = alldata.find("\n") + 1
            line = alldata[:i]
            self._buf = alldata[i:]
            return line

    def readlines(self, sizehint=0):
        total = 0
        inlist = []
        while True:
            line = self.readline()
            if not line:
                break
            inlist.append(line)
            total += len(line)
            if sizehint and total >= sizehint:
                break
        return inlist

    def fileno(self):
        return self._sock.fileno()

    def __iter__(self):
        return self

    def next(self):
        line = self.readline()
        if not line:
            raise StopIteration
        return line

class FakeSocket(SharedSocketClient):

    class _closedsocket:
        def __getattr__(self, name):
            raise error(9, 'Bad file descriptor')

    def __init__(self, sock, ssl):
        sock = SharedSocket(sock)
        SharedSocketClient.__init__(self, sock)
        self._ssl = ssl

    def close(self):
        SharedSocketClient.close(self)
        self._sock = self.__class__._closedsocket()

    def makefile(self, mode, bufsize=None):
        if mode != 'r' and mode != 'rb':
            raise UnimplementedFileMode()
        return SSLFile(self._shared, self._ssl, bufsize)

    def send(self, stuff, flags = 0):
        return self._ssl.write(stuff)

    sendall = send

    def recv(self, len = 1024, flags = 0):
        return self._ssl.read(len)

    def __getattr__(self, attr):
        return getattr(self._sock, attr)

