#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
Contains Debian-specific service class implementations.
"""

from __future__ import absolute_import

from ipaplatform.base import services as base_services
from ipaplatform.redhat import services as redhat_services
from ipapython import ipautil
from ipaplatform.paths import paths

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
debian_system_units = redhat_services.redhat_system_units.copy()

# For beginning just remap names to add .service
# As more services will migrate to systemd, unit names will deviate and
# mapping will be kept in this dictionary
debian_system_units['httpd'] = 'apache2.service'
debian_system_units['kadmin'] = 'krb5-admin-server.service'
debian_system_units['krb5kdc'] = 'krb5-kdc.service'
debian_system_units['named-regular'] = 'bind9.service'
debian_system_units['named-pkcs11'] = 'bind9-pkcs11.service'
debian_system_units['named'] = debian_system_units['named-pkcs11']
debian_system_units['pki-tomcatd'] = 'pki-tomcatd.service'
debian_system_units['pki_tomcatd'] = debian_system_units['pki-tomcatd']
debian_system_units['ods-enforcerd'] = 'opendnssec-enforcer.service'
debian_system_units['ods_enforcerd'] = debian_system_units['ods-enforcerd']
debian_system_units['ods-signerd'] = 'opendnssec-signer.service'
debian_system_units['ods_signerd'] = debian_system_units['ods-signerd']
debian_system_units['rpcgssd'] = 'rpc-gssd.service'
debian_system_units['rpcidmapd'] = 'nfs-idmapd.service'
debian_system_units['smb'] = 'smbd.service'

# Service classes that implement Debian family-specific behaviour

class DebianService(redhat_services.RedHatService):
    system_units = debian_system_units


class DebianSysvService(base_services.PlatformService):
    def __wait_for_open_ports(self, instance_name=""):
        """
        If this is a service we need to wait for do so.
        """
        ports = None
        if instance_name in base_services.wellknownports:
            ports = base_services.wellknownports[instance_name]
        else:
            if self.service_name in base_services.wellknownports:
                ports = base_services.wellknownports[self.service_name]
        if ports:
            ipautil.wait_for_open_ports('localhost', ports, self.api.env.startup_timeout)

    def stop(self, instance_name='', capture_output=True):
        ipautil.run([paths.SBIN_SERVICE, self.service_name, "stop",
                     instance_name], capture_output=capture_output)
        super(DebianSysvService, self).stop(instance_name)

    def start(self, instance_name='', capture_output=True, wait=True):
        ipautil.run([paths.SBIN_SERVICE, self.service_name, "start",
                     instance_name], capture_output=capture_output)
        if wait and self.is_running(instance_name):
            self.__wait_for_open_ports(instance_name)
        super(DebianSysvService, self).start(instance_name)

    def restart(self, instance_name='', capture_output=True, wait=True):
        ipautil.run([paths.SBIN_SERVICE, self.service_name, "restart",
                     instance_name], capture_output=capture_output)
        if wait and self.is_running(instance_name):
            self.__wait_for_open_ports(instance_name)

    def is_running(self, instance_name="", wait=True):
        ret = True
        try:
            result = ipautil.run([paths.SBIN_SERVICE,
                                  self.service_name, "status",
                                  instance_name],
                                  capture_output=True)
            sout = result.output
            if sout.find("NOT running") >= 0:
                ret = False
            if sout.find("stop") >= 0:
                ret = False
            if sout.find("inactive") >= 0:
                ret = False
        except ipautil.CalledProcessError:
                ret = False
        return ret

    def is_installed(self):
        installed = True
        try:
            ipautil.run([paths.SBIN_SERVICE, self.service_name, "status"])
        except ipautil.CalledProcessError as e:
            if e.returncode == 1:
                # service is not installed or there is other serious issue
                installed = False
        return installed

    @staticmethod
    def is_enabled(instance_name=""):
        # Services are always assumed to be enabled when installed
        return True

    @staticmethod
    def enable():
        return True

    @staticmethod
    def disable():
        return True

    @staticmethod
    def install():
        return True

    @staticmethod
    def remove():
        return True


# For services which have no Debian counterpart
class DebianNoService(base_services.PlatformService):
    @staticmethod
    def start():
        return True

    @staticmethod
    def stop():
        return True

    @staticmethod
    def restart():
        return True

    @staticmethod
    def disable():
        return True


# Function that constructs proper Debian-specific server classes for services
# of specified name

def debian_service_class_factory(name, api=None):
    if name == 'dirsrv':
        return redhat_services.RedHatDirectoryService(name, api)
    if name == 'domainname':
        return DebianNoService(name, api)
    if name == 'ipa':
        return redhat_services.RedHatIPAService(name, api)
    if name in ('pki-tomcatd', 'pki_tomcatd'):
        return redhat_services.RedHatCAService(name, api)
    if name == 'ntpd':
        return DebianSysvService("ntp", api)
    if name == 'globalcatalog':
        return redhat_services.RedHatGCService('globalcatalog', api)
    return DebianService(name, api)


# Magicdict containing DebianService instances.

class DebianServices(base_services.KnownServices):
    def __init__(self):
        # pylint: disable=ipa-forbidden-import
        import ipalib  # FixMe: break import cycle
        # pylint: enable=ipa-forbidden-import
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = self.service_class_factory(s, ipalib.api)
        # Call base class constructor. This will lock services to read-only
        super(DebianServices, self).__init__(services)

    @staticmethod
    def service_class_factory(name, api=None):
        return debian_service_class_factory(name, api)

# Objects below are expected to be exported by platform module

timedate_services = base_services.timedate_services
service = debian_service_class_factory
knownservices = DebianServices()
