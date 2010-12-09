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

import threading
import locale
import gettext
from base import ReadOnly, lock
from constants import OVERRIDE_ERROR, CALLABLE_ERROR


# Thread-local storage of most per-request information
context = threading.local()


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
    # need to use .values(), 'cos value.disconnect modifies the dict
    for value in context.__dict__.values():
        if isinstance(value, Connection):
            value.disconnect()
    context.__dict__.clear()


def ugettext(message):
    if hasattr(context, 'ugettext'):
        return context.ugettext(message)
    return message.decode('UTF-8')


def ungettext(singular, plural, n):
    if hasattr(context, 'ungettext'):
        return context.ungettext(singular, plural, n)
    if n == 1:
        return singular.decode('UTF-8')
    return plural.decode('UTF-8')


def set_languages(*languages):
    if hasattr(context, 'languages'):
        raise StandardError(OVERRIDE_ERROR %
            ('context', 'languages', context.languages, languages)
        )
    if len(languages) == 0:
        languages = locale.getdefaultlocale()[:1]
    context.languages = languages
    assert type(context.languages) is tuple


def create_translation(domain, localedir, *languages):
    if hasattr(context, 'ugettext') or hasattr(context, 'ungettext'):
        raise StandardError(
            'create_translation() already called in thread %r' %
            threading.currentThread().getName()
        )
    set_languages(*languages)
    translation = gettext.translation(domain,
        localedir=localedir, languages=context.languages, fallback=True
    )
    context.ugettext = translation.ugettext
    context.ungettext = translation.ungettext
