#
# Copyright (C) 2022  FreeIPA Contributors see COPYING for license
#

"""
Contains Nixos-specific service class implementations.
"""

from __future__ import absolute_import

from ipaplatform.redhat import services as redhat_services

# Mappings from service names as FreeIPA code references to these services
# to their actual systemd service names
nixos_system_units = redhat_services.redhat_system_units.copy()
nixos_system_units['named'] = nixos_system_units['named-regular']
nixos_system_units['named-conflict'] = nixos_system_units['named-pkcs11']


# Service classes that implement nixos-specific behaviour

class nixosService(redhat_services.RedHatService):
    system_units = nixos_system_units


# Function that constructs proper nixos-specific server classes for services
# of specified name

def nixos_service_class_factory(name, api=None):
    if name in ['named', 'named-conflict']:
        return nixosService(name, api)
    return redhat_services.redhat_service_class_factory(name, api)


# Magicdict containing nixosService instances.

class NixosServices(redhat_services.RedHatServices):
    def service_class_factory(self, name, api=None):
        return nixos_service_class_factory(name, api)


# Objects below are expected to be exported by platform module

timedate_services = redhat_services.timedate_services
service = nixos_service_class_factory
knownservices = NixosServices()
