# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty information
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
Base classes for all backed-end plugins.
"""

import threading
import plugable
from errors import PublicError, InternalError, CommandError
from request import context, Connection, destroy_context


class Backend(plugable.Plugin):
    """
    Base class for all backend plugins.
    """

    __proxy__ = False  # Backend plugins are not wrapped in a PluginProxy


class Connectible(Backend):
    """
    Base class for backend plugins that create connections.

    In addition to the nicety of providing a standard connection API, all
    backend plugins that create connections should use this base class so that
    `request.destroy_context()` can properly close all open connections.
    """

    def connect(self, *args, **kw):
        """
        Create thread-local connection.
        """
        if hasattr(context, self.name):
            raise StandardError(
                "connect: 'context.%s' already exists in thread %r" % (
                    self.name, threading.currentThread().getName()
                )
            )
        conn = self.create_connection(*args, **kw)
        setattr(context, self.name, Connection(conn, self.disconnect))
        assert self.conn is conn
        self.info('Created connection context.%s' % self.name)

    def create_connection(self, *args, **kw):
        raise NotImplementedError('%s.create_connection()' % self.name)

    def disconnect(self):
        if not hasattr(context, self.name):
            raise StandardError(
                "disconnect: 'context.%s' does not exist in thread %r" % (
                    self.name, threading.currentThread().getName()
                )
            )
        self.destroy_connection()
        self.info('Destroyed connection context.%s' % self.name)

    def destroy_connection(self):
        raise NotImplementedError('%s.destroy_connection()' % self.name)

    def isconnected(self):
        """
        Return ``True`` if thread-local connection on `request.context` exists.
        """
        return hasattr(context, self.name)

    def __get_conn(self):
        """
        Return thread-local connection.
        """
        if not hasattr(context, self.name):
            raise AttributeError('no context.%s in thread %r' % (
                self.name, threading.currentThread().getName())
            )
        return getattr(context, self.name).conn
    conn = property(__get_conn)


class Executioner(Backend):


    def create_context(self, ccache=None, client_ip=None):
        if self.env.in_server:
            self.Backend.ldap2.connect(ccache=ccache)
        else:
            self.Backend.xmlclient.connect()

    def execute(self, _name, *args, **options):
        error = None
        try:
            if _name not in self.Command:
                raise CommandError(name=_name)
            result = self.Command[_name](*args, **options)
        except PublicError, e:
            error = e
        except StandardError, e:
            self.exception(
                'non-public: %s: %s', e.__class__.__name__, str(e)
            )
            error = InternalError()
        destroy_context()
        if error is None:
            return result
        assert isinstance(error, PublicError)
        raise error
