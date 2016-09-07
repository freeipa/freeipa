#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import pipes

from jinja2.ext import Extension

from ipalib import errors
from ipalib.text import _


class IPAExtension(Extension):
    """Jinja2 extension providing useful features for cert mapping rules."""

    def __init__(self, environment):
        super(IPAExtension, self).__init__(environment)

        environment.filters.update(
            quote=self.quote,
            required=self.required,
        )

    def quote(self, data):
        return pipes.quote(data)

    def required(self, data, name):
        if not data:
            raise errors.CertificateMappingError(
                reason=_('Required mapping rule %(name)s is missing data') %
                {'name': name})
        return data
