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

import base64
from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
import datetime
from enum import Enum
import logging
import shutil

from ipalib import api
from ipalib import x509
from ipalib.facts import is_ipa_configured
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython.certdb import NSSDatabase, EMPTY_TRUST_FLAGS
from ipapython.dn import DN
from ipapython.ipaldap import realm_to_serverid
from ipaserver.install import ca, cainstance, dsinstance
from ipaserver.install.certs import is_ipa_issued_cert
from ipapython import directivesetter
from ipapython import ipautil

msg = """
                          WARNING

ipa-cert-fix is intended for recovery when expired certificates
prevent the normal operation of IPA.  It should ONLY be used
in such scenarios, and backup of the system, especially certificates
and keys, is STRONGLY RECOMMENDED.

"""

logger = logging.getLogger(__name__)


cert_nicknames = {
    'sslserver': 'Server-Cert cert-pki-ca',
    'subsystem': 'subsystemCert cert-pki-ca',
    'ca_ocsp_signing': 'ocspSigningCert cert-pki-ca',
    'ca_audit_signing': 'auditSigningCert cert-pki-ca',
    'kra_transport': 'transportCert cert-pki-kra',
    'kra_storage': 'storageCert cert-pki-kra',
    'kra_audit_signing': 'auditSigningCert cert-pki-kra',
}

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

        if not dsinstance.is_ds_running(realm_to_serverid(api.env.realm)):
            print(
                "The LDAP server is not running; cannot proceed."
            )
            return 1

        api.Backend.ldap2.connect()  # ensure DS is up

        subject_base = dsinstance.DsInstance().find_subject_base()
        if not subject_base:
            raise RuntimeError("Cannot determine certificate subject base.")

        ca_subject_dn = ca.lookup_ca_subject(api, subject_base)

        now = datetime.datetime.now() + datetime.timedelta(weeks=2)
        certs, extra_certs, non_renewed = expired_certs(now)

        if not certs and not extra_certs:
            print("Nothing to do.")
            return 0

        print(msg)

        print_intentions(certs, extra_certs, non_renewed)

        response = ipautil.user_input('Enter "yes" to proceed')
        if response.lower() != 'yes':
            print("Not proceeding.")
            return 0
        print("Proceeding.")

        try:
            fix_certreq_directives(certs)
            run_cert_fix(certs, extra_certs)
        except ipautil.CalledProcessError:
            if any(
                x[0] is IPACertType.LDAPS
                for x in extra_certs + non_renewed
            ):
                # The DS cert was expired.  This will cause
                # 'pki-server cert-fix' to fail at the final
                # restart.  Therefore ignore the CalledProcessError
                # and proceed to installing the IPA-specific certs.
                pass
            else:
                raise  # otherwise re-raise

        replicate_dogtag_certs(subject_base, ca_subject_dn, certs)
        install_ipa_certs(subject_base, ca_subject_dn, extra_certs)

        if any(x[0] != 'sslserver' for x in certs) \
                or any(x[0] is IPACertType.IPARA for x in extra_certs):
            # we renewed a "shared" certificate, therefore we must
            # become the renewal master
            print("Becoming renewal master.")
            cainstance.CAInstance().set_renewal_master()

        print("Restarting IPA")
        ipautil.run(['ipactl', 'restart'], raiseonerr=True)

        return 0


def expired_certs(now):
    expired_ipa, non_renew_ipa = expired_ipa_certs(now)
    return expired_dogtag_certs(now), expired_ipa, non_renew_ipa


def expired_dogtag_certs(now):
    """
    Determine which Dogtag certs are expired, or close to expiry.

    Return a list of (cert_id, cert) pairs.

    """
    certs = []
    db = NSSDatabase(nssdir=paths.PKI_TOMCAT_ALIAS_DIR)

    for certid, nickname in cert_nicknames.items():
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
    non_renewed = []

    # IPA RA
    cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
    if cert.not_valid_after <= now:
        certs.append((IPACertType.IPARA, cert))

    # Apache HTTPD
    cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
    if cert.not_valid_after <= now:
        if not is_ipa_issued_cert(api, cert):
            non_renewed.append((IPACertType.HTTPS, cert))
        else:
            certs.append((IPACertType.HTTPS, cert))

    # LDAPS
    serverid = realm_to_serverid(api.env.realm)
    ds = dsinstance.DsInstance(realm_name=api.env.realm)
    ds_dbdir = dsinstance.config_dirname(serverid)
    ds_nickname = ds.get_server_cert_nickname(serverid)
    db = NSSDatabase(nssdir=ds_dbdir)
    cert = db.get_cert(ds_nickname)
    if cert.not_valid_after <= now:
        if not is_ipa_issued_cert(api, cert):
            non_renewed.append((IPACertType.LDAPS, cert))
        else:
            certs.append((IPACertType.LDAPS, cert))

    # KDC
    cert = x509.load_certificate_from_file(paths.KDC_CERT)
    if cert.not_valid_after <= now:
        if not is_ipa_issued_cert(api, cert):
            non_renewed.append((IPACertType.HTTPS, cert))
        else:
            certs.append((IPACertType.KDC, cert))

    return certs, non_renewed


def print_intentions(dogtag_certs, ipa_certs, non_renewed):
    print("The following certificates will be renewed:")
    print()

    for certid, cert in dogtag_certs:
        print_cert_info("Dogtag", certid, cert)

    for certtype, cert in ipa_certs:
        print_cert_info("IPA", certtype.value, cert)

    if non_renewed:
        print(
            "The following certificates will NOT be renewed because "
            "they were not issued by the IPA CA:"
        )
        print()

        for certtype, cert in non_renewed:
            print_cert_info("IPA", certtype.value, cert)


def print_cert_info(context, desc, cert):
    print("{} {} certificate:".format(context, desc))
    print("  Subject: {}".format(DN(cert.subject)))
    print("  Serial:  {}".format(cert.serial_number))
    print("  Expires: {}".format(cert.not_valid_after))
    print()


def get_csr_from_certmonger(nickname):
    """
    Get the csr for the provided nickname by asking certmonger.

    Returns the csr in ASCII format without the header/footer in a single line
    or None if not found.
    """
    criteria = {
        'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
        'cert-nickname': nickname,
    }

    id = certmonger.get_request_id(criteria)
    if id:
        csr = certmonger.get_request_value(id, "csr")
        if csr:
            try:
                # Make sure the value can be parsed as valid CSR
                csr_obj = crypto_x509.load_pem_x509_csr(
                    csr.encode('ascii'), default_backend())
                val = base64.b64encode(csr_obj.public_bytes(x509.Encoding.DER))
                return val.decode('ascii')
            except Exception as e:
                # Fallthrough and return None
                logger.debug("Unable to get CSR from certmonger: %s", e)
    return None


def fix_certreq_directives(certs):
    """
    For all the certs to be fixed, ensure that the corresponding CSR is found
    in PKI config file, or try to get the CSR from certmonger.
    """
    directives = {
        'auditSigningCert cert-pki-ca': ('ca.audit_signing.certreq',
                                         paths.CA_CS_CFG_PATH),
        'ocspSigningCert cert-pki-ca': ('ca.ocsp_signing.certreq',
                                        paths.CA_CS_CFG_PATH),
        'subsystemCert cert-pki-ca': ('ca.subsystem.certreq',
                                      paths.CA_CS_CFG_PATH),
        'Server-Cert cert-pki-ca': ('ca.sslserver.certreq',
                                    paths.CA_CS_CFG_PATH),
        'auditSigningCert cert-pki-kra': ('kra.audit_signing.certreq',
                                          paths.KRA_CS_CFG_PATH),
        'storageCert cert-pki-kra': ('kra.storage.certreq',
                                     paths.KRA_CS_CFG_PATH),
        'transportCert cert-pki-kra': ('kra.transport.certreq',
                                       paths.KRA_CS_CFG_PATH),
    }

    # pki-server cert-fix needs to find the CSR in the subsystem config file
    # otherwise it will fail
    # For each cert to be fixed, check that the CSR is present or
    # get it from certmonger
    for (certid, _cert) in certs:
        # Check if the directive is set in the config file
        nickname = cert_nicknames[certid]
        (directive, cfg_path) = directives[nickname]
        if directivesetter.get_directive(cfg_path, directive, '=') is None:
            # The CSR is missing, try to get it from certmonger
            csr = get_csr_from_certmonger(nickname)
            if csr:
                # Update the directive
                directivesetter.set_directive(cfg_path, directive, csr,
                                              quotes=False, separator='=')


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
            shutil.copyfile(cert_path, paths.HTTPD_CERT_FILE)
        elif certtype is IPACertType.LDAPS:
            serverid = realm_to_serverid(api.env.realm)
            ds = dsinstance.DsInstance(realm_name=api.env.realm)
            ds_dbdir = dsinstance.config_dirname(serverid)
            db = NSSDatabase(nssdir=ds_dbdir)
            ds_nickname = ds.get_server_cert_nickname(serverid)
            db.delete_cert(ds_nickname)
            db.import_pem_cert(ds_nickname, EMPTY_TRUST_FLAGS, cert_path)
        elif certtype is IPACertType.KDC:
            shutil.copyfile(cert_path, paths.KDC_CERT)


def replicate_cert(subject_base, ca_subject_dn, cert):
    nickname = cainstance.get_ca_renewal_nickname(
        subject_base, ca_subject_dn, DN(cert.subject))
    if nickname:
        cainstance.update_ca_renewal_entry(api.Backend.ldap2, nickname, cert)
