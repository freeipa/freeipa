# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
# see file 'COPYING' for use and warranty contextrmation
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
Per-request thread-local data.
"""

import threading
import locale
import gettext
from constants import OVERRIDE_ERROR


# Thread-local storage of most per-request information
context = threading.local()


def set_languages(*languages):
    if hasattr(context, 'languages'):
        raise StandardError(
            OVERRIDE_ERROR % ('context.languages', context.languages, languages)
        )
    if len(languages) == 0:
        languages = locale.getdefaultlocale()[:1]
    context.languages = languages
    assert type(context.languages) is tuple


def create_translation(domain, localedir, *languages):
    if hasattr(context, 'gettext') or hasattr(context, 'ngettext'):
        raise StandardError(
            'create_translation() already called in thread %r' %
            threading.currentThread().getName()
        )
    set_languages(*languages)
    translation = gettext.translation(domain,
        localedir=localedir, languages=context.languages, fallback=True
    )
    context.gettext = translation.ugettext
    context.ngettext = translation.ungettext
