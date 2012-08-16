# Author: Alexander Bokovoy <abokovoy@redhat.com>
#
# Copyright (C) 2011   Red Hat
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

from ipapython import ipautil
from ipapython.platform import base, redhat, systemd
import os

# All what we allow exporting directly from this module
# Everything else is made available through these symbols when they are
# directly imported into ipapython.services:
# authconfig -- class reference for platform-specific implementation of
#               authconfig(8)
# service    -- class reference for platform-specific implementation of a
#               PlatformService class
# knownservices -- factory instance to access named services IPA cares about,
#                  names are ipapython.services.wellknownservices
# backup_and_replace_hostname -- platform-specific way to set hostname and
#                                make it persistent over reboots
# restore_context -- platform-sepcific way to restore security context, if
#                    applicable
# check_selinux_status -- platform-specific way to see if SELinux is enabled
#                         and restorecon is installed.
__all__ = ['authconfig', 'service', 'knownservices', 'backup_and_replace_hostname', 'restore_context', 'check_selinux_status']

# For beginning just remap names to add .service
# As more services will migrate to systemd, unit names will deviate and
# mapping will be kept in this dictionary
system_units = dict(map(lambda x: (x, "%s.service" % (x)), base.wellknownservices))

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

class Fedora16Service(systemd.SystemdService):
    def __init__(self, service_name):
        if service_name in system_units:
            service_name = system_units[service_name]
        else:
            if len(service_name.split('.')) == 1:
                # if service_name does not have a dot, it is not foo.service
                # and not a foo.target. Thus, not correct service name for
                # systemd, default to foo.service style then
                service_name = "%s.service" % (service_name)
        super(Fedora16Service, self).__init__(service_name)

# Special handling of directory server service
#
# We need to explicitly enable instances to install proper symlinks as
# dirsrv.target.wants/ dependencies. Standard systemd service class does it
# on enable() method call. Unfortunately, ipa-server-install does not do
# explicit dirsrv.enable() because the service startup is handled by ipactl.
#
# If we wouldn't do this, our instances will not be started as systemd would
# not have any clue about instances (PKI-IPA and the domain we serve) at all.
# Thus, hook into dirsrv.restart().
class Fedora16DirectoryService(Fedora16Service):
    def enable(self, instance_name=""):
        super(Fedora16DirectoryService, self).enable(instance_name)
        dirsrv_systemd = "/etc/sysconfig/dirsrv.systemd"
        if os.path.exists(dirsrv_systemd):
            # We need to enable LimitNOFILE=8192 in the dirsrv@.service
            # Since 389-ds-base-1.2.10-0.8.a7 the configuration of the
            # service parameters is performed via
            # /etc/sysconfig/dirsrv.systemd file which is imported by systemd
            # into dirsrv@.service unit
            replacevars = {'LimitNOFILE':'8192'}
            ipautil.inifile_replace_variables(dirsrv_systemd, 'service', replacevars=replacevars)
            restore_context(dirsrv_systemd)
            ipautil.run(["/bin/systemctl", "--system", "daemon-reload"],raiseonerr=False)

    def restart(self, instance_name="", capture_output=True, wait=True):
        if len(instance_name) > 0:
            elements = self.service_name.split("@")
            srv_etc = os.path.join(self.SYSTEMD_ETC_PATH, self.service_name)
            srv_tgt = os.path.join(self.SYSTEMD_ETC_PATH, self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt, self.service_instance(instance_name))
            if not os.path.exists(srv_etc):
                self.enable(instance_name)
            elif not os.path.samefile(srv_etc, srv_lnk):
                os.unlink(srv_lnk)
                os.symlink(srv_etc, srv_lnk)
        super(Fedora16DirectoryService, self).restart(instance_name, capture_output=capture_output, wait=wait)

# Enforce restart of IPA services when we do enable it
# This gets around the fact that after ipa-server-install systemd thinks
# ipa.service is not yet started but all services were actually started
# already.
class Fedora16IPAService(Fedora16Service):
    def enable(self, instance_name=""):
        super(Fedora16IPAService, self).enable(instance_name)
        self.restart(instance_name)

class Fedora16SSHService(Fedora16Service):
    def get_config_dir(self, instance_name=""):
        return '/etc/ssh'

# Redirect directory server service through special sub-class due to its
# special handling of instances
def f16_service(name):
    if name == 'dirsrv':
        return Fedora16DirectoryService(name)
    if name == 'ipa':
        return Fedora16IPAService(name)
    if name == 'sshd':
        return Fedora16SSHService(name)
    return Fedora16Service(name)

class Fedora16Services(base.KnownServices):
    def __init__(self):
        services = dict()
        for s in base.wellknownservices:
            services[s] = f16_service(s)
        # Call base class constructor. This will lock services to read-only
        super(Fedora16Services, self).__init__(services)

def restore_context(filepath, restorecon='/usr/sbin/restorecon'):
    return redhat.restore_context(filepath, restorecon)

def check_selinux_status(restorecon='/usr/sbin/restorecon'):
    return redhat.check_selinux_status(restorecon)

authconfig = redhat.authconfig
service = f16_service
knownservices = Fedora16Services()
backup_and_replace_hostname = redhat.backup_and_replace_hostname
