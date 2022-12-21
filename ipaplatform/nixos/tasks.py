#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

'''
This module contains default nixos-specific implementations of system tasks.
'''

from __future__ import absolute_import

from ipapython import directivesetter
from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths


class NixosTaskNamespace(RedHatTaskNamespace):

    def configure_httpd_protocol(self):
        # On nixos 31 and earlier DEFAULT crypto-policy has TLS 1.0 and 1.1
        # enabled.
        directivesetter.set_directive(
            paths.HTTPD_SSL_CONF,
            'SSLProtocol',
            "all -SSLv3 -TLSv1 -TLSv1.1",
            False
        )


tasks = NixosTaskNamespace()
