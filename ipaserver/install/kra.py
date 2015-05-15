#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import os
from ConfigParser import RawConfigParser
from ipalib import api
from ipaplatform.paths import paths
from ipapython import dogtag
from ipaserver.install import cainstance
from ipaserver.install import krainstance
from ipaserver.install import dsinstance
from ipaserver.install import service
from ipaserver.install.installutils import read_replica_info_kra_enabled


def install_check(replica_config, options, enable_kra, dogtag_version):
    if enable_kra:
        raise RuntimeError("KRA is already installed.")

    if not options.setup_ca:
        if cainstance.is_ca_installed_locally():
            if dogtag_version >= 10:
                # correct dogtag version of CA installed
                pass
            else:
                raise RuntimeError(
                    "Dogtag must be version 10.2 or above to install KRA")
        else:
            raise RuntimeError(
                "Dogtag CA is not installed.  Please install the CA first")

    if replica_config is not None:
        if not read_replica_info_kra_enabled(replica_config.dir):
            raise RuntimeError(
                "Either KRA is not installed on the master system or "
                "your replica file is out of date"
            )


def install(replica_config, options, dm_password):
    subject = dsinstance.DsInstance().find_subject_base()
    if replica_config is None:
        kra = krainstance.KRAInstance(
            api.env.realm,
            dogtag_constants=dogtag.install_constants)

        kra.configure_instance(
            api.env.host, api.env.domain, dm_password,
            dm_password, subject_base=subject)
    else:
        kra = krainstance.install_replica_kra(replica_config)

    service.print_msg("Restarting the directory server")
    ds = dsinstance.DsInstance()
    ds.restart()

    kra.enable_client_auth_to_db(kra.dogtag_constants.KRA_CS_CFG_PATH)

    # Update config file
    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    parser.set('global', 'enable_kra', 'True')

    with open(paths.IPA_DEFAULT_CONF, 'w') as f:
        parser.write(f)


def uninstall():
    dogtag_constants = dogtag.configured_constants()

    kra_instance = krainstance.KRAInstance(
        api.env.realm, dogtag_constants=dogtag_constants)
    kra_instance.stop_tracking_certificates()
    if kra_instance.is_installed():
        kra_instance.uninstall()

    # Check if config file exists, then update it
    if os.path.exists(paths.IPA_DEFAULT_CONF):
        parser = RawConfigParser()
        parser.read(paths.IPA_DEFAULT_CONF)
        parser.set('global', 'enable_kra', 'False')

        with open(paths.IPA_DEFAULT_CONF, 'w') as f:
            parser.write(f)
