#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#
"""Fedora container paths
"""
import os

from ipaplatform.fedora.paths import FedoraPathNamespace


def data(path):
    return os.path.join("/data", path[1:])


class FedoraContainerPathNamespace(FedoraPathNamespace):
    KRB5_CONF = data(FedoraPathNamespace.KRB5_CONF)
    KRB5_KEYTAB = data(FedoraPathNamespace.KRB5_KEYTAB)
    NAMED_KEYTAB = data(FedoraPathNamespace.NAMED_KEYTAB)
    NAMED_CUSTOM_CONF = data(FedoraPathNamespace.NAMED_CUSTOM_CONF)
    NAMED_CUSTOM_OPTIONS_CONF = data(
        FedoraPathNamespace.NAMED_CUSTOM_OPTIONS_CONF
    )
    NSSWITCH_CONF = data(FedoraPathNamespace.NSSWITCH_CONF)
    PKI_CONFIGURATION = data(FedoraPathNamespace.PKI_CONFIGURATION)
    SAMBA_DIR = data(FedoraPathNamespace.SAMBA_DIR)
    HTTPD_IPA_WSGI_MODULES_CONF = None
    HTTPD_PASSWD_FILE_FMT = data(FedoraPathNamespace.HTTPD_PASSWD_FILE_FMT)


paths = FedoraContainerPathNamespace()
