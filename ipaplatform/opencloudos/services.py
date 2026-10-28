#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#


"""
Contains OpenCloudOS family-specific service class implementations.
"""

from __future__ import absolute_import

from ipaplatform.redhat import services as redhat_services

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
opencloudos_system_units = redhat_services.redhat_system_units.copy()
opencloudos_system_units["named"] = opencloudos_system_units["named-regular"]
opencloudos_system_units["named-conflict"] = \
    opencloudos_system_units["named-pkcs11"]


# Service classes that implement OpenCloudOS family-specific behaviour


class OpenCloudOSService(redhat_services.RedHatService):
    system_units = opencloudos_system_units


# Function that constructs proper OpenCloudOS family-specific server classes
# for services of specified name


def opencloudos_service_class_factory(name, api=None):
    if name in ["named", "named-conflict"]:
        return OpenCloudOSService(name, api)
    return redhat_services.redhat_service_class_factory(name, api)


# Magicdict containing OpenCloudOSService instances.


class OpenCloudOSServices(redhat_services.RedHatServices):
    def service_class_factory(self, name, api=None):
        return opencloudos_service_class_factory(name, api)


# Objects below are expected to be exported by platform module

timedate_services = redhat_services.timedate_services
service = opencloudos_service_class_factory
knownservices = OpenCloudOSServices()
