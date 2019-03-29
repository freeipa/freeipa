#
# Copyright (C) 2019  FreeIPA Contributors see COPYING for license
#

# ipa-cert-fix performs the following steps:
#
# 1. Confirm running as root (AdminTool.validate_options does this)
#
# 2. Confirm that DS is up.
#
# 3. Determine which of following certs (if any) need renewing
#     - IPA RA
#     - Apache HTTPS
#     - 389 LDAPS
#     - Kerberos KDC (PKINIT)
#
# 4. Execute `pki-server cert-fix` with relevant options,
#    including `--extra-cert SERIAL` for each cert from #3.
#
# 5. Print details of renewed certificates.
#
# 6. Install renewed certs from #3 in relevant places
#
# 7. ipactl restart

from __future__ import print_function, absolute_import

import datetime
from enum import Enum
import logging
import shutil

from ipalib import api
from ipalib import x509
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython.certdb import NSSDatabase, EMPTY_TRUST_FLAGS
from ipapython.dn import DN
from ipaserver.install import ca, cainstance, dsinstance, installutils
from ipaserver.install.installutils import is_ipa_configured
from ipapython import ipautil

msg = """
                          WARNING

ipa-cert-fix is intended for recovery when expired certificates
prevent the normal operation of FreeIPA.  It should ONLY be used
in such scenarios, and backup of the system, especially certificates
and keys, is STRONGLY RECOMMENDED.

"""

logger = logging.getLogger(__name__)


class IPACertType(Enum):
    IPARA = "IPA RA"
    HTTPS = "Apache HTTPS"
    LDAPS = "LDAP"
    KDC = "KDC"


class IPACertFix(AdminTool):
    command_name = "ipa-cert-fix"
    usage = "%prog"
    description = "Renew expired certificates."

    def validate_options(self):
        super(IPACertFix, self).validate_options(needs_root=True)

    def run(self):
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        if not cainstance.is_ca_installed_locally():
            print("CA is not installed on this server.")
            return 1

        try:
            ipautil.run(['pki-server', 'cert-fix', '--help'], raiseonerr=True)
        except ipautil.CalledProcessError:
            print(
                "The 'pki-server cert-fix' command is not available; "
                "cannot proceed."
            )
            return 1

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect()  # ensure DS is up

        subject_base = dsinstance.DsInstance().find_subject_base()
        if not subject_base:
            raise RuntimeError("Cannot determine certificate subject base.")

        ca_subject_dn = ca.lookup_ca_subject(api, subject_base)

        now = datetime.datetime.now() + datetime.timedelta(weeks=2)
        certs, extra_certs = expired_certs(now)

        if not certs and not extra_certs:
            print("Nothing to do.")
            return 0

        print(msg)

        print_intentions(certs, extra_certs)

        response = ipautil.user_input('Enter "yes" to proceed')
        if response.lower() != 'yes':
            print("Not proceeding.")
            return 0
        print("Proceeding.")

        run_cert_fix(certs, extra_certs)

        replicate_dogtag_certs(subject_base, ca_subject_dn, certs)
        install_ipa_certs(subject_base, ca_subject_dn, extra_certs)

        if any(x != 'sslserver' for x in certs) \
                or any(x[0] is IPACertType.IPARA for x in extra_certs):
            # we renewed a "shared" certificate, therefore we must
            # become the renewal master
            print("Becoming renewal master.")
            cainstance.CAInstance().set_renewal_master()

        ipautil.run(['ipactl', 'restart'], raiseonerr=True)


def expired_certs(now):
    return expired_dogtag_certs(now), expired_ipa_certs(now)


def expired_dogtag_certs(now):
    """
    Determine which Dogtag certs are expired, or close to expiry.

    Return a list of (cert_id, cert) pairs.

    """
    certs = []
    db = NSSDatabase(nssdir=paths.PKI_TOMCAT_ALIAS_DIR)

    for certid, nickname in [
        ('sslserver', 'Server-Cert cert-pki-ca'),
        ('subsystem', 'subsystemCert cert-pki-ca'),
        ('ca_ocsp_signing', 'ocspSigningCert cert-pki-ca'),
        ('ca_audit_signing', 'auditSigningCert cert-pki-ca'),
        ('kra_transport', 'transportCert cert-pki-kra'),
        ('kra_storage', 'storageCert cert-pki-kra'),
        ('kra_audit_signing', 'auditSigningCert cert-pki-kra'),
    ]:
        try:
            cert = db.get_cert(nickname)
        except RuntimeError:
            pass  # unfortunately certdb doesn't give us a better exception
        else:
            if cert.not_valid_after <= now:
                certs.append((certid, cert))

    return certs


def expired_ipa_certs(now):
    """
    Determine which IPA certs are expired, or close to expiry.

    Return a list of (IPACertType, cert) pairs.

    """
    certs = []

    # IPA RA
    cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
    if cert.not_valid_after <= now:
        certs.append((IPACertType.IPARA, cert))

    # Apache HTTPD
    db = NSSDatabase(nssdir=paths.HTTPD_ALIAS_DIR)
    cert = db.get_cert('Server-Cert')
    if cert.not_valid_after <= now:
        certs.append((IPACertType.HTTPS, cert))

    # LDAPS
    ds_dbdir = dsinstance.config_dirname(
        installutils.realm_to_serverid(api.env.realm))
    db = NSSDatabase(nssdir=ds_dbdir)
    cert = db.get_cert('Server-Cert')
    if cert.not_valid_after <= now:
        certs.append((IPACertType.LDAPS, cert))

    # KDC
    cert = x509.load_certificate_from_file(paths.KDC_CERT)
    if cert.not_valid_after <= now:
        certs.append((IPACertType.KDC, cert))

    return certs


def print_intentions(dogtag_certs, ipa_certs):
    print("The following certificates will be renewed: ")
    print()

    for certid, cert in dogtag_certs:
        print_cert_info("Dogtag", certid, cert)

    for certtype, cert in ipa_certs:
        print_cert_info("IPA", certtype.value, cert)


def print_cert_info(context, desc, cert):
    print("{} {} certificate:".format(context, desc))
    print("  Subject: {}".format(DN(cert.subject)))
    print("  Serial:  {}".format(cert.serial_number))
    print("  Expires: {}".format(cert.not_valid_after))
    print()


def run_cert_fix(certs, extra_certs):
    ldapi_path = (
        paths.SLAPD_INSTANCE_SOCKET_TEMPLATE
        % '-'.join(api.env.realm.split('.'))
    )
    cmd = [
        'pki-server',
        'cert-fix',
        '--ldapi-socket', ldapi_path,
        '--agent-uid', 'ipara',
    ]
    for certid, _cert in certs:
        cmd.extend(['--cert', certid])
    for _certtype, cert in extra_certs:
        cmd.extend(['--extra-cert', str(cert.serial_number)])
    ipautil.run(cmd, raiseonerr=True)


def replicate_dogtag_certs(subject_base, ca_subject_dn, certs):
    for certid, _oldcert in certs:
        cert_path = "/etc/pki/pki-tomcat/certs/{}.crt".format(certid)
        cert = x509.load_certificate_from_file(cert_path)
        print_cert_info("Renewed Dogtag", certid, cert)
        replicate_cert(subject_base, ca_subject_dn, cert)


def install_ipa_certs(subject_base, ca_subject_dn, certs):
    """Print details and install renewed IPA certificates."""
    for certtype, oldcert in certs:
        cert_path = "/etc/pki/pki-tomcat/certs/{}-renewed.crt" \
                .format(oldcert.serial_number)
        cert = x509.load_certificate_from_file(cert_path)
        print_cert_info("Renewed IPA", certtype.value, cert)

        if certtype is IPACertType.IPARA:
            shutil.copyfile(cert_path, paths.RA_AGENT_PEM)
            cainstance.update_people_entry(cert)
            replicate_cert(subject_base, ca_subject_dn, cert)
        elif certtype is IPACertType.HTTPS:
            db = NSSDatabase(nssdir=paths.HTTPD_ALIAS_DIR)
            db.delete_cert('Server-Cert')
            db.import_pem_cert('Server-Cert', EMPTY_TRUST_FLAGS, cert_path)
        elif certtype is IPACertType.LDAPS:
            ds_dbdir = dsinstance.config_dirname(
                installutils.realm_to_serverid(api.env.realm))
            db = NSSDatabase(nssdir=ds_dbdir)
            db.delete_cert('Server-Cert')
            db.import_pem_cert('Server-Cert', EMPTY_TRUST_FLAGS, cert_path)
        elif certtype is IPACertType.KDC:
            shutil.copyfile(cert_path, paths.KDC_CERT)


def replicate_cert(subject_base, ca_subject_dn, cert):
    nickname = cainstance.get_ca_renewal_nickname(
        subject_base, ca_subject_dn, DN(cert.subject))
    if nickname:
        cainstance.update_ca_renewal_entry(api.Backend.ldap2, nickname, cert)
