#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
KRA installer module
"""

from __future__ import absolute_import

import os

from ipalib import api
from ipalib.install.kinit import kinit_keytab
from ipaplatform import services
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.install.core import group
from ipaserver.install import cainstance
from ipaserver.install import krainstance
from ipaserver.install import dsinstance
from ipaserver.install import service as _service

from . import dogtag


def install_check(api, replica_config, options):
    if replica_config is not None and not replica_config.setup_kra:
        return

    kra = krainstance.KRAInstance(api.env.realm)
    if kra.is_installed():
        raise RuntimeError("KRA is already installed.")

    if not options.setup_ca:
        if cainstance.is_ca_installed_locally():
            if api.env.dogtag_version >= 10:
                # correct dogtag version of CA installed
                pass
            else:
                raise RuntimeError(
                    "Dogtag must be version 10.2 or above to install KRA")
        else:
            raise RuntimeError(
                "Dogtag CA is not installed.  Please install the CA first")

    if replica_config is not None:
        if not api.Command.kra_is_enabled()['result']:
            raise RuntimeError(
                "KRA is not installed on the master system. Please use "
                "'ipa-kra-install' command to install the first instance.")


def install(api, replica_config, options, custodia):
    if replica_config is None:
        if not options.setup_kra:
            return
        realm_name = api.env.realm
        dm_password = options.dm_password
        host_name = api.env.host
        subject_base = dsinstance.DsInstance().find_subject_base()

        pkcs12_info = None
        master_host = None
        promote = False
    else:
        if not replica_config.setup_kra:
            return
        krafile = os.path.join(replica_config.dir, 'kracert.p12')
        with ipautil.private_ccache():
            ccache = os.environ['KRB5CCNAME']
            kinit_keytab(
                'host/{env.host}@{env.realm}'.format(env=api.env),
                paths.KRB5_KEYTAB,
                ccache)
            custodia.get_kra_keys(
                krafile,
                replica_config.dirman_password)

        realm_name = replica_config.realm_name
        dm_password = replica_config.dirman_password
        host_name = replica_config.host_name
        subject_base = replica_config.subject_base

        pkcs12_info = (krafile,)
        master_host = replica_config.kra_host_name
        promote = True

    kra = krainstance.KRAInstance(realm_name)
    kra.configure_instance(
        realm_name, host_name, dm_password, dm_password,
        subject_base=subject_base,
        pkcs12_info=pkcs12_info,
        master_host=master_host,
        promote=promote,
        pki_config_override=options.pki_config_override,
    )

    _service.print_msg("Restarting the directory server")
    ds = dsinstance.DsInstance()
    ds.restart()
    kra.enable_client_auth_to_db()

    # Restart apache for new proxy config file
    services.knownservices.httpd.restart(capture_output=True)
    # Restarted named-pkcs11 to restore bind-dyndb-ldap operation, see
    # https://pagure.io/freeipa/issue/5813
    named = services.knownservices.named  # alias for named-pkcs11
    if named.is_running():
        named.restart(capture_output=True)


def uninstall():
    kra = krainstance.KRAInstance(api.env.realm)
    kra.stop_tracking_certificates()
    if kra.is_installed():
        kra.uninstall()


@group
class KRAInstallInterface(dogtag.DogtagInstallInterface):
    """
    Interface of the KRA installer

    Knobs defined here will be available in:
    * ipa-server-install
    * ipa-replica-prepare
    * ipa-replica-install
    * ipa-kra-install
    """
    description = "KRA"
