#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

import os.path

from ipaserver.install import cainstance, custodiainstance, dsinstance, bindinstance
from ipapython import ipautil, certdb
from ipapython.admintool import ScriptError
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.install import installutils, certs
from ipaserver.install.replication import replica_conn_check
from ipalib import api, certstore, x509
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger

external_cert_file = None
external_ca_file = None


def install_check(standalone, replica_config, options):
    global external_cert_file
    global external_ca_file

    realm_name = options.realm_name
    host_name = options.host_name
    subject_base = options.subject

    if replica_config is not None:
        if standalone and api.env.ra_plugin == 'selfsign':
            raise ScriptError('A selfsign CA can not be added')

        cafile = os.path.join(replica_config.dir, 'cacert.p12')
        if not options.promote and not ipautil.file_exists(cafile):
            raise ScriptError('CA cannot be installed in CA-less setup.')

        if standalone and not options.skip_conncheck:
            principal = options.principal
            replica_conn_check(
                replica_config.ca_host_name, host_name, realm_name, True,
                replica_config.ca_ds_port, options.admin_password,
                principal=principal, ca_cert_file=options.ca_cert_file)

        if options.skip_schema_check:
            root_logger.info("Skipping CA DS schema check")
        else:
            cainstance.replica_ca_install_check(replica_config, options.promote)

        return

    if standalone:
        if api.Command.ca_is_enabled()['result']:
            raise ScriptError(
                "One or more CA masters are already present in IPA realm "
                "'%s'.\nIf you wish to replicate CA to this host, please "
                "re-run 'ipa-ca-install'\nwith a replica file generated on "
                "an existing CA master as argument." % realm_name
            )

    if options.external_cert_files:
        if not cainstance.is_step_one_done():
            # This can happen if someone passes external_ca_file without
            # already having done the first stage of the CA install.
            raise ScriptError(
                  "CA is not installed yet. To install with an external CA "
                  "is a two-stage process.\nFirst run the installer with "
                  "--external-ca.")

        external_cert_file, external_ca_file = installutils.load_external_cert(
            options.external_cert_files, options.subject)
    elif options.external_ca:
        if cainstance.is_step_one_done():
            raise ScriptError(
                "CA is already installed.\nRun the installer with "
                "--external-cert-file.")
        if ipautil.file_exists(paths.ROOT_IPA_CSR):
            raise ScriptError(
                "CA CSR file %s already exists.\nIn order to continue "
                "remove the file and run the installer again." %
                paths.ROOT_IPA_CSR)

    if not options.external_cert_files:
        if not cainstance.check_port():
            print("IPA requires port 8443 for PKI but it is currently in use.")
            raise ScriptError("Aborting installation")

    if standalone:
        dirname = dsinstance.config_dirname(
            installutils.realm_to_serverid(realm_name))
        cadb = certs.CertDB(realm_name, subject_base=subject_base)
        dsdb = certs.CertDB(realm_name, nssdir=dirname, subject_base=subject_base)

        for db in (cadb, dsdb):
            for nickname, _trust_flags in db.list_certs():
                if nickname in (certdb.get_ca_nickname(realm_name),
                                'ipaCert'):
                    raise ScriptError(
                        "Certificate with nickname %s is present in %s, "
                        "cannot continue." % (nickname, db.secdir))

                cert = db.get_cert_from_db(nickname)
                if not cert:
                    continue
                subject = DN(x509.load_certificate(cert).subject)
                if subject in (DN('CN=Certificate Authority', subject_base),
                               DN('CN=IPA RA', subject_base)):
                    raise ScriptError(
                        "Certificate with subject %s is present in %s, "
                        "cannot continue." % (subject, db.secdir))


def install(standalone, replica_config, options):
    install_step_0(standalone, replica_config, options)
    install_step_1(standalone, replica_config, options)


def install_step_0(standalone, replica_config, options):
    realm_name = options.realm_name
    dm_password = options.dm_password
    host_name = options.host_name

    if replica_config is None:
        subject_base = options.subject

        ca_signing_algorithm = options.ca_signing_algorithm
        if options.external_ca:
            ca_type = options.external_ca_type
            csr_file = paths.ROOT_IPA_CSR
        else:
            ca_type = None
            csr_file = None
        if options.external_cert_files:
            cert_file = external_cert_file.name
            cert_chain_file = external_ca_file.name
        else:
            cert_file = None
            cert_chain_file = None

        pkcs12_info = None
        master_host = None
        master_replication_port = None
        ra_p12 = None
        promote = False
    else:
        cafile = os.path.join(replica_config.dir, 'cacert.p12')
        if options.promote:
            custodia = custodiainstance.CustodiaInstance(
                replica_config.host_name,
                replica_config.realm_name)
            custodia.get_ca_keys(
                replica_config.ca_host_name,
                cafile,
                replica_config.dirman_password)

        subject_base = replica_config.subject_base

        ca_signing_algorithm = None
        ca_type = None
        csr_file = None
        cert_file = None
        cert_chain_file = None

        pkcs12_info = (cafile,)
        master_host = replica_config.ca_host_name
        master_replication_port = replica_config.ca_ds_port
        ra_p12 = os.path.join(replica_config.dir, 'ra.p12')
        promote = options.promote

    ca = cainstance.CAInstance(realm_name, certs.NSS_DIR,
                               host_name=host_name)
    if standalone or replica_config is not None:
        ca.create_ra_agent_db = False
    ca.configure_instance(host_name, dm_password, dm_password,
                          subject_base=subject_base,
                          ca_signing_algorithm=ca_signing_algorithm,
                          ca_type=ca_type,
                          csr_file=csr_file,
                          cert_file=cert_file,
                          cert_chain_file=cert_chain_file,
                          pkcs12_info=pkcs12_info,
                          master_host=master_host,
                          master_replication_port=master_replication_port,
                          ra_p12=ra_p12,
                          promote=promote)


def install_step_1(standalone, replica_config, options):
    realm_name = options.realm_name
    dm_password = options.dm_password
    host_name = options.host_name
    subject_base = options.subject

    basedn = ipautil.realm_to_suffix(realm_name)

    ca = cainstance.CAInstance(realm_name, certs.NSS_DIR, host_name=host_name)

    ca.stop('pki-tomcat')

    # This is done within stopped_service context, which restarts CA
    ca.enable_client_auth_to_db(paths.CA_CS_CFG_PATH)

    # Lightweight CA key retrieval is configured in step 1 instead
    # of CAInstance.configure_instance (which is invoked from step
    # 0) because kadmin_addprinc fails until krb5.conf is installed
    # by krb.create_instance.
    #
    ca.setup_lightweight_ca_key_retrieval()

    serverid = installutils.realm_to_serverid(realm_name)

    if standalone and replica_config is None:
        dirname = dsinstance.config_dirname(serverid)

        # Store the new IPA CA cert chain in DS NSS database and LDAP
        cadb = certs.CertDB(realm_name, subject_base=subject_base)
        dsdb = certs.CertDB(realm_name, nssdir=dirname, subject_base=subject_base)
        trust_flags = dict(reversed(cadb.list_certs()))
        trust_chain = cadb.find_root_cert('ipaCert')[:-1]
        for nickname in trust_chain[:-1]:
            cert = cadb.get_cert_from_db(nickname, pem=False)
            dsdb.add_cert(cert, nickname, trust_flags[nickname])
            certstore.put_ca_cert_nss(api.Backend.ldap2, api.env.basedn,
                                      cert, nickname, trust_flags[nickname])

        nickname = trust_chain[-1]
        cert = cadb.get_cert_from_db(nickname, pem=False)
        dsdb.add_cert(cert, nickname, trust_flags[nickname])
        certstore.put_ca_cert_nss(api.Backend.ldap2, api.env.basedn,
                                  cert, nickname, trust_flags[nickname],
                                  config_ipa=True, config_compat=True)

        # Store DS CA cert in Dogtag NSS database
        dogtagdb = certs.CertDB(realm_name, nssdir=paths.PKI_TOMCAT_ALIAS_DIR)
        trust_flags = dict(reversed(dsdb.list_certs()))
        server_certs = dsdb.find_server_certs()
        trust_chain = dsdb.find_root_cert(server_certs[0][0])[:-1]
        nickname = trust_chain[-1]
        cert = dsdb.get_cert_from_db(nickname)
        dogtagdb.add_cert(cert, nickname, trust_flags[nickname])

    installutils.restart_dirsrv()

    ca.start('pki-tomcat')

    if standalone or replica_config is not None:
        # We need to restart apache as we drop a new config file in there
        services.knownservices.httpd.restart(capture_output=True)

    if standalone:
        # Install CA DNS records
        if bindinstance.dns_container_exists(host_name, basedn, dm_password):
            bind = bindinstance.BindInstance()
            bind.update_system_records()


def uninstall():
    ca_instance = cainstance.CAInstance(
        api.env.realm, certs.NSS_DIR)
    ca_instance.stop_tracking_certificates()
    if ca_instance.is_configured():
        ca_instance.uninstall()
