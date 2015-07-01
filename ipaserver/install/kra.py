#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from ipalib import api, errors
from ipapython import certdb
from ipapython import dogtag
from ipapython import ipautil
from ipapython.dn import DN
from ipaserver.install import cainstance
from ipaserver.install import krainstance
from ipaserver.install import dsinstance
from ipaserver.install import service


def install_check(api, replica_config, options):
    dogtag_constants = dogtag.configured_constants(api=api)
    kra = krainstance.KRAInstance(api.env.realm,
                                  dogtag_constants=dogtag_constants)
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
            raise RuntimeError("KRA is not installed on the master system")

        with certdb.NSSDatabase() as tmpdb:
            pw = ipautil.write_tmp_file(ipautil.ipa_generate_password())
            tmpdb.create_db(pw.name)
            tmpdb.import_pkcs12(replica_config.dir + "/cacert.p12", pw.name,
                                replica_config.dirman_password)
            kra_cert_nicknames = [
                "storageCert cert-pki-kra", "transportCert cert-pki-kra",
                "auditSigningCert cert-pki-kra"
            ]
            if not all(tmpdb.has_nickname(nickname)
                       for nickname in kra_cert_nicknames):
                raise RuntimeError("Missing KRA certificates, please create a "
                                   "new replica file.")


def install(api, replica_config, options):
    subject = dsinstance.DsInstance().find_subject_base()
    if replica_config is None:
        kra = krainstance.KRAInstance(
            api.env.realm,
            dogtag_constants=dogtag.install_constants)

        kra.configure_instance(
            api.env.realm, api.env.host, api.env.domain, options.dm_password,
            options.dm_password, subject_base=subject)
    else:
        kra = krainstance.install_replica_kra(replica_config)

    service.print_msg("Restarting the directory server")
    ds = dsinstance.DsInstance()
    ds.restart()

    kra.ldap_enable('KRA', api.env.host, options.dm_password, api.env.basedn)

    kra.enable_client_auth_to_db(kra.dogtag_constants.KRA_CS_CFG_PATH)


def uninstall(standalone):
    dogtag_constants = dogtag.configured_constants(api)
    kra = krainstance.KRAInstance(api.env.realm,
                                  dogtag_constants=dogtag_constants)

    if standalone:
        kra.ldap_connect()
        try:
            kra.admin_conn.delete_entry(DN(('cn', 'KRA'), ('cn', api.env.host),
                                           ('cn', 'masters'), ('cn', 'ipa'),
                                           ('cn', 'etc'), api.env.basedn))
        except errors.NotFound:
            pass

    kra.stop_tracking_certificates()
    if kra.is_installed():
        kra.uninstall()
