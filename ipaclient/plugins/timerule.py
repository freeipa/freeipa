#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import six

from ipaclient.frontend import MethodOverride
from ipalib import File
from ipalib import errors
from ipalib.plugable import Registry
from ipalib import _

if six.PY3:
    unicode = str

register = Registry()


def get_accesstime(options):
    if not('icalfile' in options or 'accesstime' in options):
        raise errors.RequirementError(name='accesstime')
    if 'icalfile' in options:
        if 'accesstime' in options:
            raise errors.OverlapError(names=['time', 'icalfile'])
        options['accesstime'] = unicode(
            options['icalfile'].encode('unicode-escape'))
        del(options['icalfile'])
    return options['accesstime']


@register(override=True, no_fail=True)
class timerule_add(MethodOverride):
    takes_options = (
        File('icalfile?',
             label=_("iCalendar file"),
             doc=_("File containing the iCalendar string"),
             ),
    )

    def forward(self, *args, **options):
        options['accesstime'] = get_accesstime(options)
        return super(timerule_add, self).forward(*args, **options)


@register(override=True, no_fail=True)
class timerule_mod(MethodOverride):
    takes_options = (
        File('icalfile?',
             label=_("iCalendar file"),
             doc=_("File containing the iCalendar string"),
             ),
    )

    def forward(self, *args, **options):
        try:
            options['accesstime'] = get_accesstime(options)
        except errors.RequirementError:
            pass
        return super(timerule_mod, self).forward(*args, **options)
