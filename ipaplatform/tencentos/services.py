#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#


"""
Contains TencentOS specific service class implementations.
"""

from __future__ import absolute_import

from ipaplatform.redhat import services as redhat_services

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
tencentos_system_units = redhat_services.redhat_system_units.copy()
tencentos_system_units["named"] = tencentos_system_units["named-regular"]
tencentos_system_units["named-conflict"] = \
    tencentos_system_units["named-pkcs11"]


# Service classes that implement TencentOS-specific behaviour


class TencentOSService(redhat_services.RedHatService):
    system_units = tencentos_system_units


# Function that constructs proper TencentOS-specific server classes for
# services of specified name


def tencentos_service_class_factory(name, api=None):
    if name in ["named", "named-conflict"]:
        return TencentOSService(name, api)
    return redhat_services.redhat_service_class_factory(name, api)


# Magicdict containing TencentOSService instances.


class TencentOSServices(redhat_services.RedHatServices):
    def service_class_factory(self, name, api=None):
        return tencentos_service_class_factory(name, api)


# Objects below are expected to be exported by platform module

timedate_services = redhat_services.timedate_services
service = tencentos_service_class_factory
knownservices = TencentOSServices()
