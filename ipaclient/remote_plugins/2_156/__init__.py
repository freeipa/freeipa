#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from ..compat import CompatCommand, CompatMethod, CompatObject

Object = CompatObject


class Command(CompatCommand):
    api_version = u'2.156'


class Method(Command, CompatMethod):
    pass
