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

import logging
import shutil

from ipalib import api
from ipalib import x509
from ipalib.facts import is_ipa_configured
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython.certdb import NSSDatabase, EMPTY_TRUST_FLAGS
from ipapython.dn import DN
from ipapython.ipaldap import realm_to_serverid
from ipaserver.install import ca, cainstance, dsinstance
# Re-export public names from the helper modules so that all symbols are
# importable from ``ipaserver.install.ipa_cert_fix``.
from ipaserver.install.ipa_cert_fix_services import (  # noqa: F401
    CertmongerClient,
    DeploymentDetector,
    expired_dogtag_certs,
    expired_ipa_certs,
    get_csr_from_certmonger,
    print_cert_info,
)
from ipaserver.install.ipa_cert_fix_types import (  # noqa: F401
    CERT_EXPIRY_LOOKAHEAD,
    CertFixContext,
    DOGTAG_CERTS,
    DeploymentType,
    FixScenario,
    IPACertType,
    RENEWAL_NOTE,
    RENEWED_CERT_PATH_TEMPLATE,
    WARNING_BANNER,
    _utcnow,
)
from ipapython import directivesetter
from ipapython import ipautil

logger = logging.getLogger(__name__)


class IPACertFix(AdminTool):
    command_name = "ipa-cert-fix"
    usage = "%prog"
    description = "Renew expired certificates."

    _cm = None  # CertmongerClient; set in run()
    _detector = None  # DeploymentDetector; set in _classify_and_dispatch

    def validate_options(self):
        super(IPACertFix, self).validate_options(needs_root=True)

    def run(self):
        """Top-level entry point for ipa-cert-fix.

        Detects the deployment type, classifies expired certificates,
        determines the appropriate fix scenario, and dispatches to the
        corresponding handler.

        :returns: exit code (0 success, 1 error, 2 not configured)
        """
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        if self._cm is None:
            self._cm = CertmongerClient()

        if not dsinstance.is_ds_running(realm_to_serverid(api.env.realm)):
            print("The LDAP server is not running; cannot proceed.\n"
                  "Try starting IPA first with: ipactl start -f")
            return 1

        api.Backend.ldap2.connect()

        try:
            return self._classify_and_dispatch()
        finally:
            if api.Backend.ldap2.isconnected():
                api.Backend.ldap2.disconnect()

    def _classify_and_dispatch(self):
        """Classify expired certificates and dispatch to a fix scenario.

        Detects deployment type, classifies expired certs, picks a scenario
        via :class:`DeploymentDetector`, builds a :class:`CertFixContext`,
        and dispatches to the appropriate handler.  Currently only the
        renewal-master scenario is implemented; other scenarios raise a
        clear "not implemented yet" error and will be filled in by
        subsequent commits.
        """
        serverid = realm_to_serverid(api.env.realm)
        ds = dsinstance.DsInstance(realm_name=api.env.realm)
        subject_base = ds.find_subject_base()
        if not subject_base:
            raise RuntimeError("Cannot determine certificate subject base.")
        ds_dbdir = dsinstance.config_dirname(serverid).rstrip('/')
        ds_nickname = ds.get_server_cert_nickname(serverid)

        # CA-specific setup (skip on CA-less deployments)
        ca_subject_dn = None
        has_ca = cainstance.is_ca_installed_locally()
        ca_inst = cainstance.CAInstance() if has_ca else None

        self._detector = DeploymentDetector(
            self._cm, ca_inst, self.options)

        deployment_type = self._detector.detect_deployment_type()
        logger.info("Deployment type: %s", deployment_type.value)
        if has_ca:
            ca_subject_dn = ca.lookup_ca_subject(api, subject_base)

        now = _utcnow() + CERT_EXPIRY_LOOKAHEAD
        dogtag_certs, ipa_certs, external_certs = \
            self._detector._classify_certs(now, ds_dbdir, ds_nickname)

        if not dogtag_certs and not ipa_certs and not external_certs:
            print("Nothing to do.")
            return 0

        if any(key == 'ca_issuing' for key, _ in dogtag_certs):
            logger.debug("CA signing cert is expired, exiting!")
            print(
                "The CA signing certificate is expired or will expire within "
                "the next two weeks.\n\nipa-cert-fix cannot proceed, please "
                "refer to the ipa-cacert-manage tool to renew the CA "
                "certificate before proceeding."
            )
            return 1

        try:
            scenario, master = self._detector.determine_scenario(
                deployment_type)
        except RuntimeError as e:
            print(str(e))
            return 1
        logger.info("Fix scenario: %s, master: %s", scenario.value, master)

        ctx = CertFixContext(
            deployment_type=deployment_type,
            scenario=scenario,
            subject_base=subject_base,
            ca_subject_dn=ca_subject_dn,
            dogtag_certs=dogtag_certs,
            ipa_certs=ipa_certs,
            external_certs=external_certs,
            master_server=master,
            serverid=serverid,
            ds_dbdir=ds_dbdir,
            ds_nickname=ds_nickname,
        )

        dispatch = {
            FixScenario.RENEWAL_MASTER: self.run_renewal_master_fix,
        }
        handler = dispatch.get(scenario)
        if handler is None:
            print(
                "Scenario %s is not yet implemented." % scenario.value)
            return 1

        try:
            return handler(ctx)
        except RuntimeError as e:
            print("ERROR: %s" % e)
            return 1

    def run_renewal_master_fix(self, ctx):
        """Fix certificates on the renewal master via ``pki-server cert-fix``.

        Regenerates expired Dogtag system certificates and installs renewed
        IPA service certificates.  If any "shared" certificate is renewed,
        promotes this server to the renewal master.
        """
        certs = ctx.dogtag_certs
        ipa_certs = ctx.ipa_certs
        external_certs = ctx.external_certs

        try:
            ipautil.run(['pki-server', 'cert-fix', '--help'], raiseonerr=True)
        except (ipautil.CalledProcessError, FileNotFoundError):
            print(
                "The 'pki-server cert-fix' command is not available; "
                "cannot proceed.")
            return 1

        print(WARNING_BANNER)

        print_intentions(certs, ipa_certs, external_certs)

        if not self._confirm_execution():
            return 0

        try:
            fix_certreq_directives(certs)
            run_cert_fix(certs, ipa_certs)
        except ipautil.CalledProcessError:
            if any(
                x[0] is IPACertType.LDAPS
                for x in ipa_certs + external_certs
            ):
                # The DS cert was expired.  This will cause 'pki-server
                # cert-fix' to fail at the final restart, and return nonzero.
                # So this exception *might* be OK to ignore.
                #
                # If 'pki-server cert-fix' has written new certificates
                # corresponding to all the ipa_certs, then ignore the
                # CalledProcessError and proceed to installing the
                # IPA-specific certs.  Otherwise re-raise.
                if check_renewed_ipa_certs(ipa_certs):
                    pass
                else:
                    raise
            else:
                raise

        replicate_dogtag_certs(ctx.subject_base, ctx.ca_subject_dn, certs)
        install_ipa_certs(ctx.subject_base, ctx.ca_subject_dn, ipa_certs)

        if any(x[0] != 'sslserver' for x in certs) \
                or any(x[0] is IPACertType.IPARA for x in ipa_certs):
            # we renewed a "shared" certificate, therefore we must
            # become the renewal master
            print("Becoming renewal master.")
            cainstance.CAInstance().set_renewal_master()

        print("Restarting IPA")
        ipautil.run(['ipactl', 'restart'], raiseonerr=True)

        print(RENEWAL_NOTE)
        return 0

    def _confirm_execution(self):
        """Interactively confirm before performing destructive actions."""
        response = ipautil.user_input('Enter "yes" to proceed')
        if response.lower() != 'yes':
            print("Not proceeding.")
            return False
        print("Proceeding.")
        return True


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


def fix_certreq_directives(certs):
    """
    For all the certs to be fixed, ensure that the corresponding CSR is found
    in PKI config file, or try to get the CSR from certmonger.
    """
    # pki-server cert-fix needs to find the CSR in the subsystem config file
    # otherwise it will fail.  Walk each cert to renew, check whether the CSR
    # directive is present, and fall back to certmonger.
    for (certid, _cert) in certs:
        ci = DOGTAG_CERTS[certid]
        if ci.certreq_directive is None or ci.cfg_path is None:
            continue
        if directivesetter.get_directive(
            ci.cfg_path, ci.certreq_directive, '='
        ) is None:
            # The CSR is missing, try to get it from certmonger
            csr = get_csr_from_certmonger(ci.nickname)
            if csr:
                directivesetter.set_directive(
                    ci.cfg_path, ci.certreq_directive, csr,
                    quotes=False, separator='=')


def run_cert_fix(certs, ipa_certs):
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
    for _certtype, cert in ipa_certs:
        cmd.extend(['--extra-cert', str(cert.serial_number)])
    ipautil.run(cmd, raiseonerr=True)


def replicate_dogtag_certs(subject_base, ca_subject_dn, certs):
    for certid, _oldcert in certs:
        cert_path = "/etc/pki/pki-tomcat/certs/{}.crt".format(certid)
        cert = x509.load_certificate_from_file(cert_path)
        print_cert_info("Renewed Dogtag", certid, cert)
        replicate_cert(subject_base, ca_subject_dn, cert)


def check_renewed_ipa_certs(certs):
    """
    Check whether all expected IPA-specific certs were renewed successfully by
    ``pki-server cert-fix``.

    Verifies that each renewed cert file:
    - exists and contains valid X.509 data
    - has a different serial number than the old cert
    - is not expired (using the 2-week lookahead threshold)

    Return ``True`` if everything looks good, otherwise ``False``.
    """
    threshold = _utcnow() + CERT_EXPIRY_LOOKAHEAD
    for _certtype, oldcert in certs:
        cert_path = RENEWED_CERT_PATH_TEMPLATE.format(oldcert.serial_number)
        try:
            newcert = x509.load_certificate_from_file(cert_path)
        except (IOError, ValueError):
            return False
        if newcert.serial_number == oldcert.serial_number:
            logger.warning(
                "Renewed cert at %s has same serial as old (%s)",
                cert_path, oldcert.serial_number)
            return False
        if newcert.not_valid_after_utc <= threshold:
            logger.warning(
                "Renewed cert at %s is expired or near expiry (notAfter=%s)",
                cert_path, newcert.not_valid_after_utc)
            return False

    return True


def install_ipa_certs(subject_base, ca_subject_dn, certs):
    """Print details and install renewed IPA certificates."""
    for certtype, oldcert in certs:
        cert_path = RENEWED_CERT_PATH_TEMPLATE.format(oldcert.serial_number)
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
