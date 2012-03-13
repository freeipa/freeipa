# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

"""
Base classes for all backed-end plugins.
"""

import threading
import plugable
import os
from errors import PublicError, InternalError, CommandError
from request import context, Connection, destroy_context


class Backend(plugable.Plugin):
    """
    Base class for all backend plugins.
    """


class Connectible(Backend):
    """
    Base class for backend plugins that create connections.

    In addition to the nicety of providing a standard connection API, all
    backend plugins that create connections should use this base class so that
    `request.destroy_context()` can properly close all open connections.
    """

    def __init__(self, shared_instance=True):
        Backend.__init__(self)
        if shared_instance:
            self.id = self.name
        else:
            self.id = '%s_%s' % (self.name, str(id(self)))

    def connect(self, *args, **kw):
        """
        Create thread-local connection.
        """
        if hasattr(context, self.id):
            raise StandardError(
                "connect: 'context.%s' already exists in thread %r" % (
                    self.id, threading.currentThread().getName()
                )
            )
        conn = self.create_connection(*args, **kw)
        setattr(context, self.id, Connection(conn, self.disconnect))
        assert self.conn is conn
        self.debug('Created connection context.%s' % self.id)

    def create_connection(self, *args, **kw):
        raise NotImplementedError('%s.create_connection()' % self.id)

    def disconnect(self):
        if not hasattr(context, self.id):
            raise StandardError(
                "disconnect: 'context.%s' does not exist in thread %r" % (
                    self.id, threading.currentThread().getName()
                )
            )
        self.destroy_connection()
        delattr(context, self.id)
        self.debug('Destroyed connection context.%s' % self.id)

    def destroy_connection(self):
        raise NotImplementedError('%s.destroy_connection()' % self.id)

    def isconnected(self):
        """
        Return ``True`` if thread-local connection on `request.context` exists.
        """
        return hasattr(context, self.id)

    def __get_conn(self):
        """
        Return thread-local connection.
        """
        if not hasattr(context, self.id):
            raise AttributeError('no context.%s in thread %r' % (
                self.id, threading.currentThread().getName())
            )
        return getattr(context, self.id).conn
    conn = property(__get_conn)


class Executioner(Backend):

    def create_context(self, ccache=None, client_ip=None):
        """
        client_ip: The IP address of the remote client.
        """

        if ccache is not None:
            os.environ["KRB5CCNAME"] = ccache

        if self.env.in_server:
            self.Backend.ldap2.connect(ccache=ccache)
        else:
            self.Backend.xmlclient.connect(verbose=(self.env.verbose >= 2),
                fallback=self.env.fallback, delegate=self.env.delegate)
        if client_ip is not None:
            setattr(context, "client_ip", client_ip)

    def destroy_context(self):
        destroy_context()

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
        except Exception, e:
            self.exception(
                'unhandled exception: %s: %s', e.__class__.__name__, str(e)
            )
            error = InternalError()
        destroy_context()
        if error is None:
            return result
        assert isinstance(error, PublicError)
        raise error #pylint: disable=E0702
