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
from errors2 import PublicError, InternalError, CommandError
from request import context, Connection, destroy_context


class Backend(plugable.Plugin):
    """
    Base class for all backend plugins.
    """

    __proxy__ = False  # Backend plugins are not wrapped in a PluginProxy


class Connectible(Backend):
    # Override in subclass:
    connection_klass = None

    def connect(self, *args, **kw):
        """
        Create thread-local connection.
        """
        if hasattr(context, self.name):
            raise StandardError(
                "connection 'context.%s' already exists in thread %r" % (
                    self.name, threading.currentThread().getName()
                )
            )
        if not issubclass(self.connection_klass, Connection):
            raise ValueError(
                '%s.connection_klass must be a request.Connection subclass' % self.name
            )
        conn = self.connection_klass(*args, **kw)
        setattr(context, self.name, conn)
        assert self.conn is conn.conn

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

    def execute(self, name, *args, **options):
        error = None
        try:
            if name not in self.Command:
                raise CommandError(name=name)
            result = self.Command[name](*args, **options)
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



class Context(plugable.Plugin):
    """
    Base class for plugable context components.
    """

    __proxy__ = False # Backend plugins are not wrapped in a PluginProxy

    def get_value(self):
        raise NotImplementedError(
            '%s.get_value()' % self.__class__.__name__
        )
