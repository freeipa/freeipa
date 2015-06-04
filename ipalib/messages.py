# Authors:
#   Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2012  Red Hat
# see file 'COPYING' for use and warranty inmsgion
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
Custom message (debug, info, wraning) classes passed through RPC.

These are added to the "messages" entry in a RPC response, and printed to the
user as log messages.

Each message class has a unique numeric "errno" attribute from the 10000-10999
range, so that it does not clash with PublicError numbers.

Messages also have the 'type' argument, set to one of 'debug', 'info',
'warning', 'error'. This determines the severity of themessage.
"""

from inspect import isclass

from ipalib.constants import TYPE_ERROR
from ipalib.text import _ as ugettext
from ipalib.text import Gettext, NGettext
from ipalib.capabilities import client_has_capability


def add_message(version, result, message):
    if client_has_capability(version, 'messages'):
        result.setdefault('messages', []).append(message.to_dict())


def process_message_arguments(obj, format=None, message=None, **kw):
    obj.kw = kw
    name = obj.__class__.__name__
    if obj.format is not None and format is not None:
        raise ValueError(
            'non-generic %r needs format=None; got format=%r' % (
                name, format)
        )
    if message is None:
        if obj.format is None:
            if format is None:
                raise ValueError(
                    '%s.format is None yet format=None, message=None' % name
                )
            obj.format = format
        obj.forwarded = False
        obj.msg = obj.format % kw
        if isinstance(obj.format, basestring):
            obj.strerror = ugettext(obj.format) % kw
        else:
            obj.strerror = obj.format % kw
        if 'instructions' in kw:
            def convert_instructions(value):
                if isinstance(value, list):
                    result = u'\n'.join(map(lambda line: unicode(line), value))
                    return result
                return value
            instructions = u'\n'.join((unicode(_('Additional instructions:')),
                                    convert_instructions(kw['instructions'])))
            obj.strerror = u'\n'.join((obj.strerror, instructions))
    else:
        if isinstance(message, (Gettext, NGettext)):
            message = unicode(message)
        elif type(message) is not unicode:
            raise TypeError(
                TYPE_ERROR % ('message', unicode, message, type(message))
            )
        obj.forwarded = True
        obj.msg = message
        obj.strerror = message
    for (key, value) in kw.iteritems():
        assert not hasattr(obj, key), 'conflicting kwarg %s.%s = %r' % (
            name, key, value,
        )
        setattr(obj, key, value)


_texts = []

def _(message):
    _texts.append(message)
    return message


class PublicMessage(UserWarning):
    """
    **10000** Base class for messages that can be forwarded in an RPC response.
    """
    def __init__(self, format=None, message=None, **kw):
        process_message_arguments(self, format, message, **kw)
        super(PublicMessage, self).__init__(self.msg)

    errno = 10000
    format = None

    def to_dict(self):
        """Export this message to a dict that can be sent through RPC"""
        return dict(
            type=unicode(self.type),
            name=unicode(type(self).__name__),
            message=self.strerror,
            code=self.errno,
        )


class VersionMissing(PublicMessage):
    """
    **13001** Used when client did not send the API version.

    For example:

    >>> VersionMissing(server_version='2.123').strerror
    u"API Version number was not sent, forward compatibility not guaranteed. Assuming server's API version, 2.123"

    """

    errno = 13001
    type = 'warning'
    format = _("API Version number was not sent, forward compatibility not "
        "guaranteed. Assuming server's API version, %(server_version)s")


class ForwardersWarning(PublicMessage):
    """
    **13002** Used when (master) zone contains forwarders
    """

    errno = 13002
    type = 'warning'
    format =  _(
        u"DNS forwarder semantics changed since IPA 4.0.\n"
        u"You may want to use forward zones (dnsforwardzone-*) instead.\n"
        u"For more details read the docs.")


class DNSSECWarning(PublicMessage):
    """
    **13003** Used when user change DNSSEC settings
    """

    errno = 13003
    type = "warning"
    format = _("DNSSEC support is experimental.\n%(additional_info)s")


class OptionDeprecatedWarning(PublicMessage):
    """
    **13004** Used when user uses a deprecated option
    """

    errno = 13004
    type = "warning"
    format = _(u"'%(option)s' option is deprecated. %(additional_info)s")


class OptionSemanticChangedWarning(PublicMessage):
    """
    **13005** Used when option which recently changes its semantic is used
    """

    errno = 13005
    type = "warning"
    format = _(u"Semantic of %(label)s was changed. %(current_behavior)s\n"
               u"%(hint)s")


class DNSServerValidationWarning(PublicMessage):
    """
    **13006**  Used when a DNS server is not to able to resolve query
    """

    errno = 13006
    type = "warning"
    format = _(u"DNS server %(server)s: %(error)s.")


class DNSServerDoesNotSupportDNSSECWarning(PublicMessage):
    """
    **13007** Used when a DNS server does not support DNSSEC validation
    """

    errno = 13007
    type = "warning"
    format = _(u"DNS server %(server)s does not support DNSSEC: %(error)s.\n"
               u"If DNSSEC validation is enabled on IPA server(s), "
               u"please disable it.")


class ForwardzoneIsNotEffectiveWarning(PublicMessage):
    """
    **13008** Forwardzone is not effective, forwarding will not work because
    there is authoritative parent zone, without proper NS delegation
    """

    errno = 13008
    type = "warning"
    format = _(u"forward zone \"%(fwzone)s\" is not effective because of "
               u"missing proper NS delegation in authoritative zone "
               u"\"%(authzone)s\". Please add NS record "
               u"\"%(ns_rec)s\" to parent zone \"%(authzone)s\".")


class DNSServerDoesNotSupportEDNS0Warning(PublicMessage):
    """
    **13009** Used when a DNS server does not support EDNS0, required for
    DNSSEC support
    """

    errno = 13009
    type = "warning"
    format = _(u"DNS server %(server)s does not support EDNS0 (RFC 6891): "
               u"%(error)s.\n"
               u"If DNSSEC validation is enabled on IPA server(s), "
               u"please disable it.")


class DNSSECValidationFailingWarning(PublicMessage):
    """
    **13010** Used when a DNSSEC validation failed on IPA DNS server
    """

    errno = 13010
    type = "warning"
    format = _(u"DNSSEC validation failed: %(error)s.\n"
               u"Please verify your DNSSEC configuration or disable DNSSEC "
               u"validation on all IPA servers.")


def iter_messages(variables, base):
    """Return a tuple with all subclasses
    """
    for (key, value) in variables.items():
        if key.startswith('_') or not isclass(value):
            continue
        if issubclass(value, base):
            yield value


public_messages = tuple(sorted(
    iter_messages(globals(), PublicMessage), key=lambda E: E.errno))

def print_report(label, classes):
    for cls in classes:
        print '%d\t%s' % (cls.errno, cls.__name__)
    print '(%d %s)' % (len(classes), label)

if __name__ == '__main__':
    print_report('public messages', public_messages)
