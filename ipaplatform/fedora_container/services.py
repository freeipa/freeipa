#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Fedora container services
"""
from ipaplatform.fedora import services as fedora_services


fedora_container_system_units = fedora_services.fedora_system_units.copy()


class FedoraContainerService(fedora_services.FedoraService):
    system_units = fedora_container_system_units


def fedora_container_service_class_factory(name, api=None):
    return fedora_services.fedora_service_class_factory(name, api)


class FedoraContainerServices(fedora_services.FedoraServices):
    def service_class_factory(self, name, api=None):
        return fedora_container_service_class_factory(name, api)


timedate_services = fedora_services.timedate_services
service = fedora_container_service_class_factory
knownservices = FedoraContainerServices()
