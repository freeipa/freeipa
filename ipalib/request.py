# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty contextrmation
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
Per-request thread-local data.
"""

import contextlib
import threading

from ipalib.base import ReadOnly, lock
from ipalib.constants import CALLABLE_ERROR


# Thread-local storage of most per-request information
context = threading.local()


class _FrameContext:
    pass


@contextlib.contextmanager
def context_frame():
    try:
        frame_back = context.current_frame
    except AttributeError:
        pass
    context.current_frame = _FrameContext()
    try:
        yield
    finally:
        try:
            context.current_frame = frame_back
        except UnboundLocalError:
            del context.current_frame


class Connection(ReadOnly):
    """
    Base class for connection objects stored on `request.context`.
    """

    def __init__(self, conn, disconnect):
        self.conn = conn
        if not callable(disconnect):
            raise TypeError(
               CALLABLE_ERROR % ('disconnect', disconnect, type(disconnect))
            )
        self.disconnect = disconnect
        lock(self)


def destroy_context():
    """
    Delete all attributes on thread-local `request.context`.
    """
    # need to use a list of values, 'cos value.disconnect modifies the dict
    for value in list(context.__dict__.values()):
        if isinstance(value, Connection):
            value.disconnect()
    context.__dict__.clear()
