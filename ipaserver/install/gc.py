#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import logging

from ipalib.errors import NetworkError
from ipaplatform.paths import paths
from ipaserver.install import ca, dsinstance, gcinstance
from ipaserver.install import installutils, service
from ipaserver.install.installutils import read_password

logger = logging.getLogger(__name__)


def install_check(api, installer):
    if gcinstance.is_gc_configured():
        raise RuntimeError(
            "Global Catalog is already configured on this system.")

    options = installer

    options.unattended = not installer.interactive
    gc_pkcs12_file = None
    gc_pkcs12_info = None

    # Checks for valid configuration
    # Check we are on a master
    installutils.check_server_configuration()

    # Ask for required options in non-interactive mode
    # Check we have a DM password
    if not options.gc_password and options.interactive:
        print("The Global Catalog is a directory server instance")
        print("with a specific Directory Manager administration user.")
        print("The password must be at least 8 characters long.")
        options.gc_password = read_password("Directory Manager", confirm=True,
                                            validate=True, retry=True)
    if not options.gc_password:
        raise RuntimeError("Directory Manager password required")

    # If a cert file is provided, PIN is required
    if options.gc_cert_files:
        if options.gc_pin is None and options.interactive:
            options.gc_pin = installutils.read_password(
                "Enter Global Catalog private key unlock",
                confirm=False, validate=False, retry=False)
        if options.gc_pin is None:
            raise RuntimeError("You must specify --gc-pin with --gc-cert-file")

        gc_pkcs12_file, gc_pin, _gc_ca_cert = installutils.load_pkcs12(
            cert_files=options.gc_cert_files,
            key_password=options.gc_pin,
            key_nickname=None,
            ca_cert_files=[paths.IPA_CA_CRT])
        gc_pkcs12_info = (gc_pkcs12_file.name, gc_pin)

    # Check if we have creds, otherwise acquire them
    # installutils.check_creds(options, api.env.realm)

    installer._gc_pkcs12_info = gc_pkcs12_info
    installer._gc_pkcs12_file = gc_pkcs12_file

    if not api.Backend.ldap2.isconnected():
        try:
            api.Backend.ldap2.connect()
        except NetworkError as e:
            logger.debug("Unable to connect to the local instance: %s", e)
            raise RuntimeError("IPA must be running, please run ipactl start")

    # Check that a trust is installed
    if not api.Command['adtrust_is_enabled']()['result']:
        raise RuntimeError("AD Trusts are not enabled on this server")


def install(api, fstore, installer):
    options = installer
    gc_pkcs12_info = installer._gc_pkcs12_info
    # gc_pkcs12_file = installer._gc_pkcs12_file

    if options.interactive:
        print("")
        print("The following operations may take some minutes to complete.")
        print("Please wait until the prompt is returned.")
        print("")

    domainlevel = api.Command['domainlevel_get']()['result']
    subject_base = dsinstance.DsInstance().find_subject_base()
    ca_subject = ca.lookup_ca_subject(api, subject_base)

    if installer.gc_cert_files:
        gc = gcinstance.GCInstance(fstore=fstore, domainlevel=domainlevel)
        installer._gc = gc
        gc.create_instance(api.env.realm, api.env.host, api.env.domain,
                           options.gc_password, gc_pkcs12_info,
                           subject_base=subject_base,
                           ca_subject=ca_subject)
    else:
        gc = gcinstance.GCInstance(fstore=fstore, domainlevel=domainlevel)
        installer._gc = gc
        gc.create_instance(api.env.realm, api.env.host, api.env.domain,
                           options.gc_password,
                           subject_base=subject_base,
                           ca_subject=ca_subject)
    # gc.change_admin_password(admin_password)

    service.sync_services_state(api.env.host)
    print("======================================="
          "=======================================")
    print("Setup complete")
    print("")


def uninstall_check():
    if not gcinstance.is_gc_configured():
        print("WARNING:\nGlobal Catalog is not configured on this system.")


def uninstall(fstore):
    gcinstance.GCInstance(fstore=fstore).uninstall()
