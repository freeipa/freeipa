#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#
"""Fedora AES HMAC-SHA1 master key services
"""
from ipaplatform.fedora import services as fedora_services


test_fedora_legacy_system_units = fedora_services.fedora_system_units.copy()


class TestFedoraLegacyService(fedora_services.FedoraService):
    system_units = test_fedora_legacy_system_units


def test_fedora_legacy_service_class_factory(name, api=None):
    return fedora_services.fedora_service_class_factory(name, api)


class TestFedoraLegacyServices(fedora_services.FedoraServices):
    def service_class_factory(self, name, api=None):
        return test_fedora_legacy_service_class_factory(name, api)


timedate_services = fedora_services.timedate_services
service = test_fedora_legacy_service_class_factory
knownservices = TestFedoraLegacyServices()
