#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function

from ipaserver.install import cainstance, dsinstance, bindinstance
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

        if ((not options.promote
             and not ipautil.file_exists(replica_config.dir + "/cacert.p12"))):
            raise ScriptError('CA cannot be installed in CA-less setup.')

        if standalone and not options.skip_conncheck:
            principal = options.principal
            replica_conn_check(
                replica_config.master_host_name, host_name, realm_name, True,
                replica_config.ca_ds_port, options.admin_password,
                principal=principal, ca_cert_file=options.ca_cert_file)

        if options.skip_schema_check or options.promote:
            root_logger.info("Skipping CA DS schema check")
        else:
            cainstance.replica_ca_install_check(replica_config)

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
            for nickname, trust_flags in db.list_certs():
                if nickname in (certdb.get_ca_nickname(realm_name),
                                'ipaCert',
                                'Signing-Cert'):
                    raise ScriptError(
                        "Certificate with nickname %s is present in %s, "
                        "cannot continue." % (nickname, db.secdir))

                cert = db.get_cert_from_db(nickname)
                if not cert:
                    continue
                subject = DN(str(x509.get_subject(cert)))
                if subject in (DN('CN=Certificate Authority', subject_base),
                               DN('CN=IPA RA', subject_base),
                               DN('CN=Object Signing Cert', subject_base)):
                    raise ScriptError(
                        "Certificate with subject %s is present in %s, "
                        "cannot continue." % (subject, db.secdir))


def install(standalone, replica_config, options):
    install_step_0(standalone, replica_config, options)
    install_step_1(standalone, replica_config, options)


def install_step_0(standalone, replica_config, options):
    realm_name = options.realm_name
    domain_name = options.domain_name
    dm_password = options.dm_password
    host_name = options.host_name
    subject_base = options.subject

    if replica_config is not None:
        # Configure the CA if necessary
        if standalone:
            postinstall = True
        else:
            postinstall = False

        if standalone:
            api.Backend.ldap2.disconnect()

        cainstance.install_replica_ca(replica_config, postinstall,
                ra_p12=getattr(options, 'ra_p12', None))

        if standalone and not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect(bind_dn=DN(('cn', 'Directory Manager')),
                                      bind_pw=dm_password)

        return

    if options.external_cert_files:
        external = 2
    elif options.external_ca:
        external = 1
    else:
        external = 0

    ca = cainstance.CAInstance(realm_name, certs.NSS_DIR)
    if standalone:
        ca.create_ra_agent_db = False
    if external == 0:
        ca.configure_instance(host_name, dm_password,
                              dm_password, subject_base=subject_base,
                              ca_signing_algorithm=options.ca_signing_algorithm)
    elif external == 1:
        ca.configure_instance(host_name, dm_password,
                              dm_password, csr_file=paths.ROOT_IPA_CSR,
                              subject_base=subject_base,
                              ca_signing_algorithm=options.ca_signing_algorithm,
                              ca_type=options.external_ca_type)
    else:
        ca.configure_instance(host_name, dm_password, dm_password,
                              cert_file=external_cert_file.name,
                              cert_chain_file=external_ca_file.name,
                              subject_base=subject_base,
                              ca_signing_algorithm=options.ca_signing_algorithm)


def install_step_1(standalone, replica_config, options):
    realm_name = options.realm_name
    domain_name = options.domain_name
    dm_password = options.dm_password
    host_name = options.host_name
    subject_base = options.subject

    basedn = ipautil.realm_to_suffix(realm_name)

    ca = cainstance.CAInstance(realm_name, certs.NSS_DIR, host_name=host_name)

    if standalone:
        ca.stop('pki-tomcat')

    # We need to ldap_enable the CA now that DS is up and running
    if replica_config is None:
        config = ['caRenewalMaster']
    else:
        config = []
    ca.ldap_enable('CA', host_name, dm_password, basedn, config)

    # This is done within stopped_service context, which restarts CA
    ca.enable_client_auth_to_db(paths.CA_CS_CFG_PATH)

    # Lightweight CA key retrieval is configured in step 1 instead
    # of CAInstance.configure_instance (which is invoked from step
    # 0) because kadmin_addprinc fails until krb5.conf is installed
    # by krb.create_instance.
    #
    ca.setup_lightweight_ca_key_retrieval()

    if standalone and replica_config is None:
        serverid = installutils.realm_to_serverid(realm_name)
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


        api.Backend.ldap2.disconnect()

        # Restart DS
        services.knownservices.dirsrv.restart(serverid)

        api.Backend.ldap2.connect(bind_dn=DN(('cn', 'Directory Manager')),
                                  bind_pw=dm_password)

        # Store DS CA cert in Dogtag NSS database
        dogtagdb = certs.CertDB(realm_name, nssdir=paths.PKI_TOMCAT_ALIAS_DIR)
        trust_flags = dict(reversed(dsdb.list_certs()))
        server_certs = dsdb.find_server_certs()
        trust_chain = dsdb.find_root_cert(server_certs[0][0])[:-1]
        nickname = trust_chain[-1]
        cert = dsdb.get_cert_from_db(nickname)
        dogtagdb.add_cert(cert, nickname, trust_flags[nickname])

    if standalone:
        ca.start('pki-tomcat')

        # We need to restart apache as we drop a new config file in there
        services.knownservices.httpd.restart(capture_output=True)

        # Install CA DNS records
        if bindinstance.dns_container_exists(host_name, basedn, dm_password):
            bind = bindinstance.BindInstance(dm_password=dm_password)
            bind.update_system_records()


def uninstall():
    ca_instance = cainstance.CAInstance(
        api.env.realm, certs.NSS_DIR)
    ca_instance.stop_tracking_certificates()
    if ca_instance.is_configured():
        ca_instance.uninstall()
