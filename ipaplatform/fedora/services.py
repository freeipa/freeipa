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
Contains Fedora-specific service class implementations.
"""

import os
import time

from ipaplatform.tasks import tasks
from ipaplatform.base import services as base_services

from ipapython import ipautil, dogtag
from ipapython.ipa_log_manager import root_logger
from ipalib import api

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names

# For beginning just remap names to add .service
# As more services will migrate to systemd, unit names will deviate and
# mapping will be kept in this dictionary
system_units = dict((x, "%s.service" % x)
                    for x in base_services.wellknownservices)

system_units['rpcgssd'] = 'nfs-secure.service'
system_units['rpcidmapd'] = 'nfs-idmap.service'

# Rewrite dirsrv and pki-tomcatd services as they support instances via separate
# service generator. To make this working, one needs to have both foo@.servic
# and foo.target -- the latter is used when request should be coming for
# all instances (like stop). systemd, unfortunately, does not allow one
# to request action for all service instances at once if only foo@.service
# unit is available. To add more, if any of those services need to be
# started/stopped automagically, one needs to manually create symlinks in
# /etc/systemd/system/foo.target.wants/ (look into systemd.py's enable()
# code).

system_units['dirsrv'] = 'dirsrv@.service'
# Our directory server instance for PKI is dirsrv@PKI-IPA.service
system_units['pkids'] = 'dirsrv@PKI-IPA.service'
# Old style PKI instance
system_units['pki-cad'] = 'pki-cad@pki-ca.service'
system_units['pki_cad'] = system_units['pki-cad']
# Our PKI instance is pki-tomcatd@pki-tomcat.service
system_units['pki-tomcatd'] = 'pki-tomcatd@pki-tomcat.service'
system_units['pki_tomcatd'] = system_units['pki-tomcatd']
system_units['ipa-otpd'] = 'ipa-otpd.socket'
# Service that sets domainname on Fedora is called fedora-domainname.service
system_units['domainname'] = 'fedora-domainname.service'


# Service classes that implement Fedora-specific behaviour

class FedoraService(base_services.SystemdService):
    def __init__(self, service_name):
        systemd_name = service_name
        if service_name in system_units:
            systemd_name = system_units[service_name]
        else:
            if '.' not in service_name:
                # if service_name does not have a dot, it is not foo.service
                # and not a foo.target. Thus, not correct service name for
                # systemd, default to foo.service style then
                systemd_name = "%s.service" % (service_name)
        super(FedoraService, self).__init__(service_name, systemd_name)


class FedoraDirectoryService(FedoraService):

    def tune_nofile_platform(self, num=8192, fstore=None):
        """
        Increase the number of files descriptors available to directory server
        from the default 1024 to 8192. This will allow to support a greater
        number of clients out of the box.

        This is a part of the implementation that is systemd-specific.

        Returns False if the setting of the nofile limit needs to be skipped.
        """

        dirsrv_systemd = "/etc/sysconfig/dirsrv.systemd"

        if os.path.exists(dirsrv_systemd):
            # We need to enable LimitNOFILE=8192 in the dirsrv@.service
            # Since 389-ds-base-1.2.10-0.8.a7 the configuration of the
            # service parameters is performed via
            # /etc/sysconfig/dirsrv.systemd file which is imported by systemd
            # into dirsrv@.service unit

            replacevars = {'LimitNOFILE': str(num)}
            ipautil.inifile_replace_variables(dirsrv_systemd,
                                              'service',
                                              replacevars=replacevars)
            tasks.restore_context(dirsrv_systemd)
            ipautil.run(["/bin/systemctl", "--system", "daemon-reload"],
                        raiseonerr=False)

        return True

    def restart(self, instance_name="", capture_output=True, wait=True):
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

            srv_etc = os.path.join(self.SYSTEMD_ETC_PATH,
                                   self.systemd_name)
            srv_tgt = os.path.join(self.SYSTEMD_ETC_PATH,
                                   self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt,
                                   self.service_instance(instance_name))

            if not os.path.exists(srv_etc):
                self.enable(instance_name)
            elif not os.path.samefile(srv_etc, srv_lnk):
                os.unlink(srv_lnk)
                os.symlink(srv_etc, srv_lnk)

        super(FedoraDirectoryService, self).restart(instance_name,
            capture_output=capture_output, wait=wait)


class FedoraIPAService(FedoraService):
    # Enforce restart of IPA services when we do enable it
    # This gets around the fact that after ipa-server-install systemd thinks
    # ipa.service is not yet started but all services were actually started
    # already.
    def enable(self, instance_name=""):
        super(FedoraIPAService, self).enable(instance_name)
        self.restart(instance_name)


class FedoraSSHService(FedoraService):
    def get_config_dir(self, instance_name=""):
        return '/etc/ssh'


class FedoraCAService(FedoraService):
    def wait_until_running(self):
        # We must not wait for the httpd proxy if httpd is not set up yet.
        # Unfortunately, knownservices.httpd.is_installed() can return
        # false positives, so check for existence of our configuration file.
        # TODO: Use a cleaner solution
        use_proxy = True
        if not (os.path.exists('/etc/httpd/conf.d/ipa.conf') and
                os.path.exists('/etc/httpd/conf.d/ipa-pki-proxy.conf')):
            root_logger.debug(
                'The httpd proxy is not installed, wait on local port')
            use_proxy = False
        root_logger.debug('Waiting until the CA is running')
        timeout = float(api.env.startup_timeout)
        op_timeout = time.time() + timeout
        while time.time() < op_timeout:
            try:
                status = dogtag.ca_status(use_proxy=use_proxy)
            except Exception:
                status = 'check interrupted'
            root_logger.debug('The CA status is: %s' % status)
            if status == 'running':
                break
            root_logger.debug('Waiting for CA to start...')
            time.sleep(1)
        else:
            raise RuntimeError('CA did not start in %ss' % timeout)

    def start(self, instance_name="", capture_output=True, wait=True):
        super(FedoraCAService, self).start(
            instance_name, capture_output=capture_output, wait=wait)
        if wait:
            self.wait_until_running()

    def restart(self, instance_name="", capture_output=True, wait=True):
        super(FedoraCAService, self).restart(
            instance_name, capture_output=capture_output, wait=wait)
        if wait:
            self.wait_until_running()


# Function that constructs proper Fedora-specific server classes for services
# of specified name

def fedora_service_class_factory(name):
    if name == 'dirsrv':
        return FedoraDirectoryService(name)
    if name == 'ipa':
        return FedoraIPAService(name)
    if name == 'sshd':
        return FedoraSSHService(name)
    if name in ('pki-cad', 'pki_cad', 'pki-tomcatd', 'pki_tomcatd'):
        return FedoraCAService(name)
    return FedoraService(name)


# Magicdict containing FedoraService instances.

class FedoraServices(base_services.KnownServices):
    def __init__(self):
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = fedora_service_class_factory(s)
        # Call base class constructor. This will lock services to read-only
        super(FedoraServices, self).__init__(services)


# Objects below are expected to be exported by platform module

from ipaplatform.base.services import timedate_services
service = fedora_service_class_factory
knownservices = FedoraServices()
