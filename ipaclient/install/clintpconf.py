#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
from logging import getLogger

from ipaplatform.tasks import tasks
from ipapython import ipautil
from ipapython import ntpmethods

logger = getLogger(__name__)


class BaseNTPClient:
    def __init__(self, fstore=None, ntp_confile=None, statestore=None,
                 cli_domain=None, ntp_servers=None, ntp_pool=None,
                 pre_args=None, post_args=None):

        self.fstore = fstore
        self.ntp_confile = ntp_confile
        self.statestore = statestore
        self.cli_domain = cli_domain
        self.ntp_pool = ntp_pool
        self.ntp_servers = ntp_servers
        self.pre_args = pre_args
        self.post_args = post_args

    def __configure_ntp(self):

        logger.debug("Backing up %s", self.ntp_confile)
        ntpmethods.backup_config(self.ntp_confile, self.fstore)

        logger.debug("Backing up state %s", ntpmethods.TIME_SERVER)

        enabled = ntpmethods.SERVICE_API.is_enabled()
        running = ntpmethods.SERVICE_API.is_running()

        if self.statestore:
            self.statestore.backup_state(
                ntpmethods.SERVICE_NAME, 'enabled', enabled)
            self.statestore.backup_state(
                ntpmethods.SERVICE_NAME, 'running', running)

        logger.debug("Configuring %s", ntpmethods.TIME_SERVER)

        try:
            ntpmethods.SERVICE_API.stop()
        except OSError:
            logger.warning("%s service stop error", ntpmethods.TIME_SERVER)
            return False

        ntp_servers = self.ntp_servers
        if not ntp_servers and not self.ntp_pool:
            ntp_servers = ntpmethods.search_ntp_servers(self.cli_domain)
            if not ntp_servers:
                logger.warning("No SRV records of NTP servers found and "
                               "no NTP server or pool address was provided.")

                return False

        ntpmethods.set_config(self.ntp_confile, servers=ntp_servers,
                              pool=self.ntp_pool, logger=logger)

        tasks.restore_context(self.ntp_confile)

        return True

    def sync_time(self):

        if not self.__configure_ntp():
            logger.warning(
                "%s service not configured and IPA will be not synchronized",
                ntpmethods.TIME_SERVER
            )
            return False

        try:
            logger.info(
                "Attempting to sync time with %s", ntpmethods.TIME_SERVER
            )
            logger.info("It may take a few seconds")

            ntpmethods.force_service(self.statestore)

            if self.pre_args:
                ipautil.run(self.pre_args)

            ntpmethods.SERVICE_API.enable()
            ntpmethods.SERVICE_API.start()

            if self.post_args:
                ipautil.run(self.post_args)

            return True

        except ipautil.CalledProcessError as e:
            logger.debug('Process not completed. %s', e)

            return False

    def uninstall(self):
        ntpmethods.uninstall(self.statestore, self.fstore,
                             self.ntp_confile, logger)
