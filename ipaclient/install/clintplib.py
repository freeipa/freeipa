#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from ipaplatform.paths import paths
from ipaclient.install.clintpconf import BaseNTPClient


class ChronyClient(BaseNTPClient):
    sync_attempt_count = 3

    def __init__(self):
        super(ChronyClient, self).__init__(
            ntp_confile=paths.CHRONY_CONF,
            post_args=[paths.CHRONYC, 'waitsync',
                       str(self.sync_attempt_count), '-d'],
        )


class NTPDClient(BaseNTPClient):
    def __init__(self):
        super(NTPDClient, self).__init__(
            ntp_confile=paths.NTPD_CONF,
        )


class OpenNTPDClient(BaseNTPClient):
    def __init__(self):
        super(OpenNTPDClient, self).__init__(
            ntp_confile=paths.ONTPD_CONF,
        )
