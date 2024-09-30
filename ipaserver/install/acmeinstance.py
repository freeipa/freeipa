#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#

import logging

from ipaserver.install.dogtaginstance import DogtagInstance

logger = logging.getLogger(__name__)


class ACMEInstance(DogtagInstance):
    """
    ACME is deployed automatically with a CA subsystem but it is the
    responsibility of IPA to uninstall the service.

    This is mostly a placeholder for the uninstaller. We can
    eventually move the ACME installation routines into this class
    if we want but it might result in an extra PKI restart which
    would be slow.
    """
    def __init__(self, realm=None, host_name=None):
        super(ACMEInstance, self).__init__(
            realm=realm,
            subsystem="ACME",
            service_desc="ACME server",
            host_name=host_name
        )

    def uninstall(self):
        DogtagInstance.uninstall(self)
