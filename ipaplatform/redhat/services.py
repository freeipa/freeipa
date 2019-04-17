# Author: Alexander Bokovoy <abokovoy@redhat.com>
#         Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2011-2014   Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Contains Red Hat OS family-specific service class implementations.
"""

from __future__ import absolute_import

import logging
import os
import time
import contextlib

from ipaplatform.base import services as base_services

from ipapython import ipautil, dogtag
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names

# For beginning just remap names to add .service
# As more services will migrate to systemd, unit names will deviate and
# mapping will be kept in this dictionary
redhat_system_units = dict((x, "%s.service" % x)
                           for x in base_services.wellknownservices)

redhat_system_units['rpcgssd'] = 'rpc-gssd.service'
redhat_system_units['rpcidmapd'] = 'nfs-idmapd.service'
redhat_system_units['domainname'] = 'nis-domainname.service'

# Rewrite dirsrv and pki-tomcatd services as they support instances via separate
# service generator. To make this working, one needs to have both foo@.servic
# and foo.target -- the latter is used when request should be coming for
# all instances (like stop). systemd, unfortunately, does not allow one
# to request action for all service instances at once if only foo@.service
# unit is available. To add more, if any of those services need to be
# started/stopped automagically, one needs to manually create symlinks in
# /etc/systemd/system/foo.target.wants/ (look into systemd.py's enable()
# code).

redhat_system_units['dirsrv'] = 'dirsrv@.service'
# Our PKI instance is pki-tomcatd@pki-tomcat.service
redhat_system_units['pki-tomcatd'] = 'pki-tomcatd@pki-tomcat.service'
redhat_system_units['pki_tomcatd'] = redhat_system_units['pki-tomcatd']
redhat_system_units['ipa-otpd'] = 'ipa-otpd.socket'
redhat_system_units['ipa-dnskeysyncd'] = 'ipa-dnskeysyncd.service'
redhat_system_units['named-regular'] = 'named.service'
redhat_system_units['named-pkcs11'] = 'named-pkcs11.service'
redhat_system_units['named'] = redhat_system_units['named-pkcs11']
redhat_system_units['ods-enforcerd'] = 'ods-enforcerd.service'
redhat_system_units['ods_enforcerd'] = redhat_system_units['ods-enforcerd']
redhat_system_units['ods-signerd'] = 'ods-signerd.service'
redhat_system_units['ods_signerd'] = redhat_system_units['ods-signerd']
redhat_system_units['gssproxy'] = 'gssproxy.service'


# Service classes that implement Red Hat OS family-specific behaviour

class RedHatService(base_services.SystemdService):
    system_units = redhat_system_units

    def __init__(self, service_name, api=None):
        systemd_name = service_name
        if service_name in self.system_units:
            systemd_name = self.system_units[service_name]
        else:
            if '.' not in service_name:
                # if service_name does not have a dot, it is not foo.service
                # and not a foo.target. Thus, not correct service name for
                # systemd, default to foo.service style then
                systemd_name = "%s.service" % (service_name)
        super(RedHatService, self).__init__(service_name, systemd_name, api)


class RedHatDirectoryService(RedHatService):

    def is_installed(self, instance_name):
        file_path = "{}/{}-{}".format(paths.ETC_DIRSRV, "slapd", instance_name)
        return os.path.exists(file_path)

    def restart(self, instance_name="", capture_output=True, wait=True,
                ldapi=False):
    # We need to explicitly enable instances to install proper symlinks as
    # dirsrv.target.wants/ dependencies. Standard systemd service class does it
    # on enable() method call. Unfortunately, ipa-server-install does not do
    # explicit dirsrv.enable() because the service startup is handled by ipactl.
    #
    # If we wouldn't do this, our instances will not be started as systemd would
    # not have any clue about instances (PKI-IPA and the domain we serve)
    # at all. Thus, hook into dirsrv.restart().

        if instance_name:
            elements = self.systemd_name.split("@")

            srv_etc = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.systemd_name)
            srv_tgt = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt,
                                   self.service_instance(instance_name))

            if not os.path.exists(srv_etc):
                self.enable(instance_name)
            elif not os.path.samefile(srv_etc, srv_lnk):
                os.unlink(srv_lnk)
                os.symlink(srv_etc, srv_lnk)

        with self.__wait(instance_name, wait, ldapi) as wait:
            super(RedHatDirectoryService, self).restart(
                instance_name, capture_output=capture_output, wait=wait)

    def start(self, instance_name="", capture_output=True, wait=True,
              ldapi=False):
        with self.__wait(instance_name, wait, ldapi) as wait:
            super(RedHatDirectoryService, self).start(
                instance_name, capture_output=capture_output, wait=wait)

    @contextlib.contextmanager
    def __wait(self, instance_name, wait, ldapi):
        if ldapi:
            instance_name = self.service_instance(instance_name)
            if instance_name.endswith('.service'):
                instance_name = instance_name[:-8]
            if instance_name.startswith('dirsrv'):
                # this is intentional, return the empty string if the instance
                # name is 'dirsrv'
                instance_name = instance_name[7:]
            if not instance_name:
                ldapi = False
        if ldapi:
            yield False
            socket_name = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % instance_name
            ipautil.wait_for_open_socket(socket_name,
                                         self.api.env.startup_timeout)
        else:
            yield wait


class RedHatIPAService(RedHatService):
    # Enforce restart of IPA services when we do enable it
    # This gets around the fact that after ipa-server-install systemd thinks
    # ipa.service is not yet started but all services were actually started
    # already.
    def enable(self, instance_name=""):
        super(RedHatIPAService, self).enable(instance_name)
        self.restart(instance_name)


class RedHatCAService(RedHatService):
    def wait_until_running(self):
        logger.debug('Waiting until the CA is running')
        timeout = float(self.api.env.startup_timeout)
        op_timeout = time.time() + timeout
        while time.time() < op_timeout:
            try:
                # check status of CA instance on this host, not remote ca_host
                status = dogtag.ca_status(self.api.env.host)
            except Exception as e:
                status = 'check interrupted due to error: %s' % e
            logger.debug('The CA status is: %s', status)
            if status == 'running':
                break
            logger.debug('Waiting for CA to start...')
            time.sleep(1)
        else:
            raise RuntimeError('CA did not start in %ss' % timeout)

    def is_running(self, instance_name="", wait=True):
        if instance_name:
            return super(RedHatCAService, self).is_running(instance_name)
        try:
            status = dogtag.ca_status()
            if status == 'running':
                return True
            elif status == 'starting' and wait:
                # Exception is raised if status is 'starting' even after wait
                self.wait_until_running()
                return True
        except Exception as e:
            logger.debug(
                'Failed to check CA status: %s', e
            )
        return False


# Function that constructs proper Red Hat OS family-specific server classes for
# services of specified name

def redhat_service_class_factory(name, api=None):
    if name == 'dirsrv':
        return RedHatDirectoryService(name, api)
    if name == 'ipa':
        return RedHatIPAService(name, api)
    if name in ('pki-tomcatd', 'pki_tomcatd'):
        return RedHatCAService(name, api)
    return RedHatService(name, api)


# Magicdict containing RedHatService instances.

class RedHatServices(base_services.KnownServices):
    def __init__(self):
        # pylint: disable=ipa-forbidden-import
        import ipalib  # FixMe: break import cycle
        # pylint: enable=ipa-forbidden-import
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = self.service_class_factory(s, ipalib.api)
        # Call base class constructor. This will lock services to read-only
        super(RedHatServices, self).__init__(services)

    def service_class_factory(self, name, api=None):
        return redhat_service_class_factory(name, api)

# Objects below are expected to be exported by platform module

timedate_services = base_services.timedate_services
service = redhat_service_class_factory
knownservices = RedHatServices()
