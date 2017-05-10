#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

from ipalib import Object
from ipalib import _
from ipalib.plugable import Registry

register = Registry()


@register()
class pkinit(Object):
    """
    PKINIT Options
    """
    object_name = _('pkinit')

    label = _('PKINIT')
