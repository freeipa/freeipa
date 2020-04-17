#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipaserver.install.servntpconf import BaseNTPServer
from ipapython.ntpmethods import SERVICE_NAME


class ChronyServer(BaseNTPServer):
    def __init__(self):
        super(ChronyServer, self).__init__(
            service_name=SERVICE_NAME,
            ntp_confile=paths.CHRONY_CONF,
            opts=['allow all'],
        )


class NTPDServer(BaseNTPServer):
    def __init__(self):
        super(NTPDServer, self).__init__(
            service_name=SERVICE_NAME,
            ntp_confile=paths.NTPD_CONF,
            opts=['restrict -4 default nomodify',
                  'restrict -6 default nomodify'],
        )


class OpenNTPDServer(BaseNTPServer):
    def __init__(self):
        super(OpenNTPDServer, self).__init__(
            service_name=SERVICE_NAME,
            ntp_confile=paths.ONTPD_CONF,
            opts=['listen on *'],
        )
