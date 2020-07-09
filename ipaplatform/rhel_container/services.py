#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""RHEL container services
"""
from ipaplatform.rhel import services as rhel_services


rhel_container_system_units = rhel_services.rhel_system_units.copy()


class RHELContainerService(rhel_services.RHELService):
    system_units = rhel_container_system_units


def rhel_container_service_class_factory(name, api=None):
    return rhel_services.rhel_service_class_factory(name, api)


class RHELContainerServices(rhel_services.RHELServices):
    def service_class_factory(self, name, api=None):
        return rhel_container_service_class_factory(name, api)


timedate_services = rhel_services.timedate_services
service = rhel_container_service_class_factory
knownservices = RHELContainerServices()
