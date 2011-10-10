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
# Everything else is made available through these symbols when they directly imported into ipapython.services:
# authconfig -- class reference for platform-specific implementation of authconfig(8)
# service    -- class reference for platform-specific implementation of a PlatformService class
# knownservices -- factory instance to access named services IPA cares about, names are ipapython.services.wellknownservices
# backup_and_replace_hostname -- platform-specific way to set hostname and make it persistent over reboots
# restore_context -- platform-sepcific way to restore security context, if applicable
__all__ = ['authconfig', 'service', 'knownservices', 'backup_and_replace_hostname', 'restore_context']

# For beginning just remap names to add .service
# As more services will migrate to systemd, unit names will deviate and
# mapping will be kept in this dictionary
system_units = dict(map(lambda x: (x, "%s.service" % (x)), base.wellknownservices))

# Rewrite dirsrv and pki-cad services as they support instances via separate service generator
# To make this working, one needs to have both foo@.service and foo.target -- the latter is used
# when request should be coming for all instances (like stop). systemd, unfortunately, does not allow
# to request action for all service instances at once if only foo@.service unit is available.
# To add more, if any of those services need to be started/stopped automagically, one needs to manually
# create symlinks in /etc/systemd/system/foo.target.wants/ (look into systemd.py's enable() code).
system_units['dirsrv'] = 'dirsrv@.service'
# Our directory server instance for PKI is dirsrv@PKI-IPA.service
system_units['pkids'] = 'dirsrv@PKI-IPA.service'
# Our PKI instance is pki-cad@pki-ca.service
system_units['pki-cad'] = 'pki-cad@pki-ca.service'

class Fedora16Service(systemd.SystemdService):
    def __init__(self, service_name):
        if service_name in system_units:
            service_name = system_units[service_name]
        else:
            if len(service_name.split('.')) == 1:
                # if service_name does not have a dot, it is not foo.service and not a foo.target
                # Thus, not correct service name for systemd, default to foo.service style then
                service_name = "%s.service" % (service_name)
        super(Fedora16Service, self).__init__(service_name)

# Special handling of directory server service
# LimitNOFILE needs to be increased or any value set in the directory for this value will fail
# Read /lib/systemd/system/dirsrv@.service for details.
# We do modification of LimitNOFILE on service.enable() but we also need to explicitly enable instances
# to install proper symlinks as dirsrv.target.wants/ dependencies. Unfortunately, ipa-server-install
# does not do explicit dirsrv.enable() because the service startup is handled by ipactl.
# If we wouldn't do this, our instances will not be started as systemd would not have any clue
# about instances (PKI-IPA and the domain we serve) at all. Thus, hook into dirsrv.restart().
class Fedora16DirectoryService(Fedora16Service):
    def enable(self, instance_name=""):
        super(Fedora16DirectoryService, self).enable(instance_name)
        srv_etc = os.path.join(self.SYSTEMD_ETC_PATH, self.service_name)
        if os.path.exists(srv_etc):
            # We need to enable LimitNOFILE=8192 in the dirsrv@.service
            # We rely on the fact that [Service] section is the last one
            # and if variable is not there, it will be added as the last line
            replacevars = {'LimitNOFILE':'8192'}
            ipautil.config_replace_variables(srv_etc, replacevars=replacevars)
            redhat.restore_context(srv_etc)
            ipautil.run(["/bin/systemctl", "--system", "daemon-reload"],raiseonerr=False)

    def restart(self, instance_name="", capture_output=True):
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
        super(Fedora16DirectoryService, self).restart(instance_name, capture_output=capture_output)

# Enforce restart of IPA services when we do enable it
# This gets around the fact that after ipa-server-install systemd thinks ipa.service is not yet started
# but all services were actually started already.
class Fedora16IPAService(Fedora16Service):
    def enable(self, instance_name=""):
        super(Fedora16IPAService, self).enable(instance_name)
        self.restart(instance_name)

# Redirect directory server service through special sub-class due to its special handling of instances
def f16_service(name):
    if name == 'dirsrv':
        return Fedora16DirectoryService(name)
    if name == 'ipa':
        return Fedora16IPAService(name)
    return Fedora16Service(name)

class Fedora16Services(base.KnownServices):
    def __init__(self):
        services = dict()
        for s in base.wellknownservices:
            services[s] = f16_service(s)
        # Call base class constructor. This will lock services to read-only
        super(Fedora16Services, self).__init__(services)

authconfig = redhat.authconfig
service = f16_service
knownservices = Fedora16Services()
restore_context = redhat.restore_context
backup_and_replace_hostname = redhat.backup_and_replace_hostname
