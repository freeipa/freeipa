#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from __future__ import absolute_import

from logging import getLogger

from ipaplatform.paths import paths
from ipalib.install import sysrestore
from ipaserver.install import service
from ipapython import ntpmethods

logger = getLogger(__name__)


class BaseNTPServer(service.Service):

    def __init__(self, service_name, ntp_confile=None, fstore=None,
                 ntp_servers=None, ntp_pool=None, sstore=None, opts=None):
        super(BaseNTPServer, self).__init__(
            service_name=service_name,
            fstore=fstore,
            service_desc="NTP daemon",
            sstore=sstore,
        )

        self.ntp_confile = ntp_confile
        self.ntp_servers = ntp_servers
        self.ntp_pool = ntp_pool
        self.opts = opts

        if not fstore:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    def __configure_ntp(self):

        logger.debug("Backing up %s", self.ntp_confile)
        ntpmethods.backup_config(self.ntp_confile, self.fstore)

        logger.debug("Configuring %s", ntpmethods.TIME_SERVER)

        enabled = ntpmethods.SERVICE_API.is_enabled()
        running = ntpmethods.SERVICE_API.is_running()

        if self.sstore:
            self.sstore.backup_state(
                ntpmethods.SERVICE_NAME, 'enabled', enabled
            )
            self.sstore.backup_state(
                ntpmethods.SERVICE_NAME, 'running', running
            )

        if not self.ntp_servers and not self.ntp_pool:
            self.ntp_pool = "pool.ntp.org"

        ntpmethods.set_config(self.ntp_confile, pool=self.ntp_pool,
                              servers=self.ntp_servers, opts=self.opts,
                              logger=logger)

        ntpmethods.SERVICE_API.stop()

    def sync_time(self):
        self.step("stopping %s" % self.service_name, self.stop)
        self.step("writing configuration", self.__configure_ntp)
        self.step("configuring %s to start on boot"
                  % self.service_name, self.enable)
        self.step("starting %s" % self.service_name, self.start)

        self.start_creation()

    def uninstall(self):
        ntpmethods.uninstall(
            self.sstore, self.fstore, self.ntp_confile, logger
        )
