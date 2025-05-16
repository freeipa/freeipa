#
# Copyright (C) 2025  FreeIPA Contributors see COPYING for license
#
"""Fedora AES HMAC-SHA1 master key services
"""
from ipaplatform.fedora import services as fedora_services


fedora_aes_sha1_system_units = fedora_services.fedora_system_units.copy()


class FedoraAesSha1Service(fedora_services.FedoraService):
    system_units = fedora_aes_sha1_system_units


def fedora_aes_sha1_service_class_factory(name, api=None):
    return fedora_services.fedora_service_class_factory(name, api)


class FedoraAesSha1Services(fedora_services.FedoraServices):
    def service_class_factory(self, name, api=None):
        return fedora_aes_sha1_service_class_factory(name, api)


timedate_services = fedora_services.timedate_services
service = fedora_aes_sha1_service_class_factory
knownservices = FedoraAesSha1Services()
