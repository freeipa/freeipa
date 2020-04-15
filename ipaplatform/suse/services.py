#
# Copyright (C) 2020 FreeIPA Contributors, see COPYING for license
#

import os
import logging
import time
import contextlib

from ipaplatform.base import services as base_services
from ipapython import ipautil, dogtag
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

suse_system_units = dict(
    (x, "%s.service" % x) for x in base_services.wellknownservices
)
suse_system_units["httpd"] = "apache2.service"

suse_system_units["dirsrv"] = "dirsrv@.service"
suse_system_units["pki-tomcatd"] = "pki-tomcatd@pki-tomcat.service"
suse_system_units["pki_tomcatd"] = suse_system_units["pki-tomcatd"]
suse_system_units["ipa-otpd"] = "ipa-otpd.socket"
suse_system_units["ipa-dnskeysyncd"] = "ipa-dnskeysyncd.service"
suse_system_units["named-regular"] = "named.service"
suse_system_units["named-pkcs11"] = "named.service"
suse_system_units["named"] = "named.service"
suse_system_units["ods-enforcerd"] = "ods-enforcerd.service"
suse_system_units["ods_enforcerd"] = suse_system_units["ods-enforcerd"]
suse_system_units["ods-signerd"] = "ods-signerd.service"
suse_system_units["ods_signerd"] = suse_system_units["ods-signerd"]


class SuseService(base_services.SystemdService):
    system_units = suse_system_units

    def __init__(self, service_name, api=None):
        systemd_name = service_name
        if service_name in self.system_units:
            systemd_name = self.system_units[service_name]
        else:
            if "." not in service_name:
                systemd_name = "%s.service" % (service_name)
        super().__init__(service_name, systemd_name, api)


class SuseDirectoryService(SuseService):
    def is_installed(self, instance_name):
        file_path = "{}/{}-{}".format(
            paths.ETC_DIRSRV, "slapd", instance_name
        )
        return os.path.exists(file_path)

    def restart(
        self, instance_name="", capture_output=True, wait=True, ldapi=False
    ):
        # We need to explicitly enable instances to install proper symlinks as
        # dirsrv.target.wants/ dependencies. Standard systemd service class
        # does it on enable() method call. Unfortunately, ipa-server-install
        # does not do explicit dirsrv.enable() because the service startup is
        # handled by ipactl.
        #
        # If we wouldn't do this, our instances will not be started as systemd
        # would not have any clue about instances (PKI-IPA and the domain we
        # serve) at all. Thus, hook into dirsrv.restart().

        if instance_name:
            elements = self.systemd_name.split("@")

            srv_etc = os.path.join(
                paths.ETC_SYSTEMD_SYSTEM_DIR, self.systemd_name
            )
            srv_tgt = os.path.join(
                paths.ETC_SYSTEMD_SYSTEM_DIR,
                self.SYSTEMD_SRV_TARGET % (elements[0]),
            )
            srv_lnk = os.path.join(
                srv_tgt, self.service_instance(instance_name)
            )

            if not os.path.exists(srv_etc):
                self.enable(instance_name)
            elif not os.path.samefile(srv_etc, srv_lnk):
                os.unlink(srv_lnk)
                os.symlink(srv_etc, srv_lnk)

        with self._wait(instance_name, wait, ldapi) as wait:
            super().restart(
                instance_name, capture_output=capture_output, wait=wait
            )

    def start(
        self, instance_name="", capture_output=True, wait=True, ldapi=False
    ):
        with self._wait(instance_name, wait, ldapi) as wait:
            super().start(
                instance_name, capture_output=capture_output, wait=wait
            )

    @contextlib.contextmanager
    def _wait(self, instance_name, wait, ldapi):
        if ldapi:
            instance_name = self.service_instance(instance_name)
            if instance_name.endswith(".service"):
                instance_name = instance_name[:-8]
            if instance_name.startswith("dirsrv"):
                # this is intentional, return the empty string if the instance
                # name is 'dirsrv'
                instance_name = instance_name[7:]
            if not instance_name:
                ldapi = False
        if ldapi:
            yield False
            socket_name = paths.SLAPD_INSTANCE_SOCKET_TEMPLATE % instance_name
            ipautil.wait_for_open_socket(
                socket_name, self.api.env.startup_timeout
            )
        else:
            yield wait


class SuseIPAService(SuseService):
    # Credits to upstream developer
    def enable(self, instance_name=""):
        super().enable(instance_name)
        self.restart(instance_name)


class SuseCAService(SuseService):
    # Credits to upstream developer
    def wait_until_running(self):
        logger.debug("Waiting until the CA is running")
        timeout = float(self.api.env.startup_timeout)
        op_timeout = time.time() + timeout
        while time.time() < op_timeout:
            try:
                # check status of CA instance on this host, not remote ca_host
                status = dogtag.ca_status(self.api.env.host)
            except Exception as e:
                status = "check interrupted due to error: %s" % e
            logger.debug("The CA status is: %s", status)
            if status == "running":
                break
            logger.debug("Waiting for CA to start...")
            time.sleep(1)
        else:
            raise RuntimeError("CA did not start in %ss" % timeout)

    def is_running(self, instance_name="", wait=True):
        if instance_name:
            return super().is_running(instance_name)
        try:
            status = dogtag.ca_status()
            if status == "running":
                return True
            elif status == "starting" and wait:
                # Exception is raised if status is 'starting' even after wait
                self.wait_until_running()
                return True
        except Exception as e:
            logger.debug("Failed to check CA status: %s", e)
        return False


def suse_service_class_factory(name, api):
    if name == "dirsrv":
        return SuseDirectoryService(name, api)
    if name == "ipa":
        return SuseIPAService(name, api)
    if name in ("pki-tomcatd", "pki_tomcatd"):
        return SuseCAService(name, api)
    return SuseService(name, api)


class SuseServices(base_services.KnownServices):
    def service_class_factory(self, name, api=None):
        return suse_service_class_factory(name, api)

    # Credits to upstream developer
    def __init__(self):
        # pylint: disable=ipa-forbidden-import
        import ipalib

        # pylint: enable=ipa-forbidden-import
        services = dict()
        for s in base_services.wellknownservices:
            services[s] = self.service_class_factory(s, ipalib.api)
        super().__init__(services)


timedate_services = ["ntpd"]
service = suse_service_class_factory
knownservices = SuseServices()
