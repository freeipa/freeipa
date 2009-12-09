# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
Thread-local lazy gettext service.

TODO: This aren't hooked up into gettext yet, they currently just provide
placeholders for the rest of the code.
"""


class LazyText(object):
    def __init__(self, domain, localedir):
        self.domain = domain
        self.localedir = localedir


class Gettext(LazyText):
    def __init__(self, msg, domain, localedir):
        self.msg = msg
        super(Gettext, self).__init__(domain, localedir)

    def __unicode__(self):
        return self.msg.decode('utf-8')

    def __mod__(self, value):
        return self.__unicode__() % value


class NGettext(LazyText):
    def __init__(self, singular, plural, domain, localedir):
        self.singular = singular
        self.plural = plural
        super(NGettext, self).__init__(domain, localedir)

    def __mod__(self, kw):
        count = kw['count']
        return self(count) % kw

    def __call__(self, count):
        if count == 1:
            return self.singular.decode('utf-8')
        return self.plural.decode('utf-8')


class gettext_factory(object):
    def __init__(self, domain='ipa', localedir=None):
        self.domain = domain
        self.localedir = localedir

    def __call__(self, msg):
        return Gettext(msg, self.domain, self.localedir)


class ngettext_factory(gettext_factory):
    def __call__(self, singular, plural, count=0):
        return NGettext(singular, plural, self.domain, self.localedir)


# Process wide factories:
gettext = gettext_factory()
_ = gettext
ngettext = ngettext_factory()
