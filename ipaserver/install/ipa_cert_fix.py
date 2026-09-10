#
# Copyright (C) 2019, 2026  FreeIPA Contributors see COPYING for license
#

# ipa-cert-fix: Multi-scenario certificate recovery tool.
#
# Auto-detects the deployment type and chooses the least-invasive fix path:
#
#   DeploymentType        -> FixScenario
#   CA_SELF_SIGNED + RM   -> RENEWAL_MASTER
#   CA_SELF_SIGNED + !RM  -> CA_FULL_WITH_MASTER or CA_FULL_PROMOTE
#   CA_EXTERNALLY_SIGNED  -> (same as above)
#   CA_LESS               -> CA_LESS_WITH_MASTER or EXTERNAL_CERTS
#   CA_LESS_EXTERNAL      -> EXTERNAL_CERTS
#
# RENEWAL_MASTER: pki-server cert-fix, install certs, become RM, restart,
#   resubmit.
#
# CA_FULL_WITH_MASTER: ipa-certupdate, fetch RA/subsystem from master LDAP,
#   renew via certmonger pointed at master (-J), restart, resubmit.
#
# CA_FULL_PROMOTE: verify pki-server cert-fix available, promote to RM,
#   then run renewal master path.
#   Requires --renewal-master in unattended mode.
#
# CA_LESS_WITH_MASTER: ipa-certupdate, fetch RA from master,
#   renew HTTP/LDAP/KDC via certmonger, restart, resubmit.
#
# EXTERNAL_CERTS: offer per-cert transition to IPA CA (interactive) or
#   generate CSRs for external renewal.

from dataclasses import replace
import logging
import os
import shutil
import socket

from ipalib import api, errors
from ipalib import x509
from ipalib.facts import is_ipa_configured
from ipaplatform.paths import paths
from ipapython.admintool import AdminTool
from ipapython.certdb import NSSDatabase, EMPTY_TRUST_FLAGS
from ipapython.dn import DN
from ipapython import ipaldap
from ipapython.ipaldap import realm_to_serverid
from ipaserver.install import ca, cainstance, dsinstance
from ipaserver.masters import find_providing_servers
from ipapython import directivesetter
from ipapython import ipautil

# Re-export public names from helper modules so that all symbols are importable
# from ``ipaserver.install.ipa_cert_fix``.
# pylint: disable=unused-import
from ipaserver.install.ipa_cert_fix_types import (
    CertIdentity, DOGTAG_CERTS, _CS_CFG_CERT_DIRECTIVES,
    IPACertType, DeploymentType, FixScenario, CertFixContext,
    CERT_EXPIRY_LOOKAHEAD, CERTMONGER_WAIT_TIMEOUT,
    DBUS_RETRY_TIMEOUT, DBUS_RETRY_DELAY, HELPER_KILL_SETTLE,
    IPA_SERVICE_PROFILE, DOGTAG_CERT_PATH_TEMPLATE,
    RENEWED_CERT_PATH_TEMPLATE,
    WARNING_BANNER, RENEWAL_NOTE, PROMOTE_WARNING, _utcnow,)
from ipaserver.install.ipa_cert_fix_services import (
    CertmongerClient, ExternalCertHandler,
    CertRenewalFromMaster, DeploymentDetector,
    _get_pki_nssdb, _replace_cert_in_nssdb,
    _update_cs_cfg, _kill_stuck_helpers, print_cert_info,
    _check_tcp_reachable, _find_current_renewal_master,
    _ensure_ldap_connected, expired_dogtag_certs,
    _check_ipa_cert, expired_ipa_certs,
    get_csr_from_certmonger,)
# pylint: enable=unused-import

logger = logging.getLogger(__name__)


def _check_tls_handshake(server, timeout=10):
    """Verify TLS handshake to a server succeeds.

    Uses the system CA trust store (which includes ``/etc/ipa/ca.crt``) to
    verify that local trust chain is sufficient to connect to the master.

    :param server: FQDN to connect to
    :param timeout: connection timeout in seconds
    :raises Exception: if TLS handshake fails
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(paths.IPA_CA_CRT)
    with socket.create_connection(
        (server, 443), timeout=timeout
    ) as sock:
        with ctx.wrap_socket(sock, server_hostname=server):
            logger.debug("TLS handshake to %s:443 succeeded", server)


def _setup_kerberos():
    """Set up Kerberos credentials from the host keytab.

    The local ldap2 connection uses LDAPI (unix socket) and does not need
    Kerberos, but remote LDAP connections and ``ipa-certupdate`` require
    a ticket.

    Note: the Kerberos client uses the KDC(s) from ``/etc/krb5.conf`` or
    DNS SRV records.  If the local KDC is down (expired KDC cert), GSSAPI
    to the master may fail.  See Known Limitations in the design doc.

    :returns: tuple of previous ``(KRB5CCNAME, KRB5_CLIENT_KTNAME)``
        values for restoration
    """
    old_ccname = os.environ.get('KRB5CCNAME')
    old_ktname = os.environ.get('KRB5_CLIENT_KTNAME')
    os.environ['KRB5_CLIENT_KTNAME'] = '/etc/krb5.keytab'
    os.environ['KRB5CCNAME'] = "MEMORY:"
    logger.debug("Set KRB5_CLIENT_KTNAME=/etc/krb5.keytab, KRB5CCNAME=MEMORY:")
    return old_ccname, old_ktname


def _restore_kerberos(old_krb_env):
    """Restore Kerberos environment after remote operations.

    :param old_krb_env: tuple returned by :func:`_setup_kerberos`
    """
    old_ccname, old_ktname = old_krb_env
    if old_ccname is None:
        os.environ.pop('KRB5CCNAME', None)
    else:
        os.environ['KRB5CCNAME'] = old_ccname
    if old_ktname is None:
        os.environ.pop('KRB5_CLIENT_KTNAME', None)
    else:
        os.environ['KRB5_CLIENT_KTNAME'] = old_ktname


class IPACertFix(AdminTool):
    command_name = "ipa-cert-fix"
    usage = "%prog [options]"
    description = "Renew expired certificates."

    # Error handling convention:
    # - Scenario handlers (run_*) return exit codes (0/1).
    # - determine_scenario raises RuntimeError for invalid option combos;
    #   _classify_and_dispatch catches it for a clean exit.
    # - Internal helpers raise exceptions (caught by handlers).

    # Instance variables -- declared here so they exist regardless of which
    # code path runs. Set in _classify_and_dispatch().
    _ca_instance = None
    _cm = None  # CertmongerClient; set in run()
    _scenario_made_changes = False  # set by _confirm_execution
    _external_handler = None  # set in _classify_and_dispatch

    # =========================================================
    #  CLI & Entry Point
    # =========================================================

    @classmethod
    def add_options(cls, parser):
        super(IPACertFix, cls).add_options(parser)
        parser.add_option(
            "--force-server",
            dest="force_server",
            help="FQDN of the master server to fetch certificates from")
        parser.add_option(
            "--renewal-master",
            dest="renewal_master",
            action="store_true",
            default=False,
            help="Force this replica to become the renewal master. Use with "
                 "caution, and verify CRL generation and IPA config after the "
                 "topology is stable again!")
        parser.add_option(
            "--dry-run",
            dest="dry_run",
            action="store_true",
            default=False,
            help="Print intended actions without executing them")
        parser.add_option(
            "-U", "--unattended",
            dest="unattended",
            action="store_true",
            default=False,
            help="Unattended mode, never prompts the user")

    def validate_options(self):
        super(IPACertFix, self).validate_options(needs_root=True)

        if self.options.renewal_master and self.options.force_server:
            self.option_parser.error(
                "--renewal-master and --force-server are mutually exclusive")

    _detector = None  # DeploymentDetector; set in _classify_and_dispatch

    def run(self):
        """Top-level entry point for ipa-cert-fix.

        Detects the deployment type, classifies expired certificates,
        determines the appropriate fix scenario,
        and dispatches to the corresponding handler.

        :returns: exit code (0 success, 1 error, 2 not configured)
        """
        if not is_ipa_configured():
            print("IPA is not configured.")
            return 2

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        if self._cm is None:
            self._cm = CertmongerClient()

        if (self.options.force_server
                and self.options.force_server == api.env.host):
            print(
                "--force-server must point to a different server, "
                "not this one (%s)" % api.env.host)
            return 1

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
        """Inner dispatch logic for :meth:`run`.

        Separated so that ``run()`` can guarantee LDAP cleanup in
        a finally block.

        :returns: exit code
        """
        serverid = realm_to_serverid(api.env.realm)
        ds = dsinstance.DsInstance(realm_name=api.env.realm)
        subject_base = ds.find_subject_base()
        if not subject_base:
            raise RuntimeError("Cannot determine certificate subject base.")
        ds_dbdir = dsinstance.config_dirname(serverid).rstrip('/')
        ds_nickname = ds.get_server_cert_nickname(serverid)

        # CA-specific setup (skip on CA-less deployments)
        hsm_enabled = False
        hsm_token_name = None
        ca_subject_dn = None
        has_ca = cainstance.is_ca_installed_locally()
        self._ca_instance = cainstance.CAInstance() if has_ca else None

        # Create the detector before deployment detection
        self._detector = DeploymentDetector(
            self._cm, self._ca_instance, self.options)

        # Detect deployment type
        deployment_type = self._detector.detect_deployment_type()
        logger.info("Deployment type: %s", deployment_type.value)
        if has_ca:
            cai = self._ca_instance
            if hasattr(cai, 'hsm_enabled') and cai.hsm_enabled:
                hsm_enabled = True
                hsm_token_name = cai.token_name
                logger.info("HSM enabled, token: %s", hsm_token_name)
            ca_subject_dn = ca.lookup_ca_subject(api, subject_base)

        # Classify expired certificates
        now = _utcnow() + CERT_EXPIRY_LOOKAHEAD
        dogtag_certs, ipa_certs, external_certs = \
            self._detector._classify_certs(now, ds_dbdir, ds_nickname)

        logger.debug(
            "Expired certs: dogtag=%d, ipa=%d, external=%d",
            len(dogtag_certs), len(ipa_certs), len(external_certs),)
        for certid, cert in dogtag_certs:
            logger.debug(
                "  Dogtag: %s serial=%s expires=%s",
                certid, cert.serial_number, cert.not_valid_after_utc,)
        for certtype, cert in ipa_certs:
            logger.debug(
                "  IPA: %s serial=%s expires=%s",
                certtype.value, cert.serial_number, cert.not_valid_after_utc,
            )
        for certtype, cert in external_certs:
            logger.debug(
                "  External: %s serial=%s expires=%s",
                certtype.value, cert.serial_number, cert.not_valid_after_utc,
            )

        # On CA-full, detect RA/subsystem LDAP mismatches for certs we're NOT
        # going to fetch from master (those will be fixed by the fetch itself +
        # post-fix check).
        ldap_mismatches = []
        if has_ca:
            ra_will_be_fetched = any(
                ct is IPACertType.IPARA for ct, _ in ipa_certs)
            sub_will_be_fetched = any(
                cid == 'subsystem' for cid, _ in dogtag_certs)
            try:
                det = self._detector
                ldap_mismatches = det._detect_ra_subsystem_mismatches(
                    skip_ra=ra_will_be_fetched,
                    skip_subsystem=sub_will_be_fetched)
            except Exception as e:
                logger.warning("RA/subsystem consistency check failed: %s", e)

        # On CA-less replicas, the RA cert may be valid but stale (renewed on
        # the CA server, not yet updated here). A stale RA cert causes ipa
        # commands to fail with auth errors even though no cert is technically
        # expired.
        ra_stale = False
        if (not has_ca
                and deployment_type == DeploymentType.CA_LESS
                and not any(ct is IPACertType.IPARA
                            for ct, _ in ipa_certs)):
            ra_stale = self._check_ra_cert_staleness()

        if (not dogtag_certs and not ipa_certs
                and not external_certs and not ldap_mismatches
                and not ra_stale):
            print("Nothing to do.")
            return 0

        print(WARNING_BANNER)

        # Show unified list of intentions
        print_intentions(dogtag_certs, ipa_certs, external_certs)
        if ldap_mismatches:
            DeploymentDetector._print_ra_subsystem_mismatches(ldap_mismatches)

        # Only LDAP mismatches and/or stale RA, no expired certs
        if not dogtag_certs and not ipa_certs and not external_certs:
            if self.options.dry_run:
                if ldap_mismatches:
                    print("[DRY RUN] Would fix LDAP entries above.")
                if ra_stale:
                    print("[DRY RUN] Would fetch updated RA cert "
                          "from a CA server.")
                return 0
            if not self.options.unattended:
                response = ipautil.user_input('Enter "yes" to proceed')
                if response.lower() != 'yes':
                    print("Not proceeding.")
                    return 0
            if ldap_mismatches:
                DeploymentDetector._fix_ra_subsystem_mismatches(
                    ldap_mismatches)
            if ra_stale:
                self._fetch_ra_from_ca_server()
            return 0

        # Determine fix scenario (may prompt for server)
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
            hsm_enabled=hsm_enabled,
            hsm_token_name=hsm_token_name,)

        self._external_handler = ExternalCertHandler(
            self._cm, unattended=self.options.unattended)

        dispatch = {
            FixScenario.RENEWAL_MASTER:
                self.run_renewal_master_fix,
            FixScenario.CA_FULL_WITH_MASTER:
                lambda ctx: self._run_non_rm_replica_fix(ctx, is_ca_full=True),
            FixScenario.CA_FULL_PROMOTE:
                self.run_ca_full_promote,
            FixScenario.CA_LESS_WITH_MASTER:
                lambda ctx: self._run_non_rm_replica_fix(
                    ctx, is_ca_full=False),
            FixScenario.EXTERNAL_CERTS:
                self.run_external_certs,
        }

        handler = dispatch[scenario]
        try:
            result = handler(ctx)
        except RuntimeError as e:
            print("ERROR: %s" % e)
            return 1

        # Post-fix: detect and fix all RA/subsystem LDAP mismatches. This
        # catches both pre-existing mismatches (shown in intentions above) and
        # any new ones from fetched certs. Use a flag to know whether the
        # handler actually did work vs the user declining at the confirmation
        # prompt (both return 0).
        if has_ca and result == 0 and self._scenario_made_changes:
            det = self._detector
            post_mismatches = det._detect_ra_subsystem_mismatches()
            if post_mismatches:
                det._fix_ra_subsystem_mismatches(post_mismatches)

        return result

    # =========================================================
    #  Scenario Handlers
    # =========================================================

    def run_renewal_master_fix(self, ctx):
        """Fix certificates on the renewal master.

        Uses ``pki-server cert-fix`` to regenerate expired Dogtag certificates
        and installs renewed IPA service certificates. If shared certificates
        are renewed, sets this server as the renewal master.

        :param ctx: :class:`CertFixContext` with certificate details
        :returns: exit code (0 for success)
        """
        certs = ctx.dogtag_certs
        ipa_certs = ctx.ipa_certs

        # On externally-signed CA deployments, the CA signing cert is managed
        # by the external CA (renewed via ipa-cacert-manage).  Do not pass it
        # to pki-server cert-fix -- that would regenerate it as self-signed,
        # silently overwriting the external chain.
        if ctx.deployment_type == DeploymentType.CA_EXTERNALLY_SIGNED:
            if any(cid == 'ca_issuing' for cid, _ in certs):
                logger.info(
                    "Externally-signed CA: skipping ca_issuing cert "
                    "(managed by external CA)")
                certs = [(cid, c) for cid, c in certs if cid != 'ca_issuing']

        dry_extra = []
        if certs:
            dry_extra.append(
                "Dogtag certs for pki-server cert-fix: "
                + ", ".join(cid for cid, _ in certs))
        if ipa_certs:
            dry_extra.append(
                "IPA service certs (extra-cert): "
                + ", ".join(ct.value for ct, _ in ipa_certs))
        if ctx.external_certs:
            dry_extra.append(
                "External certs (handled separately): "
                + ", ".join(ct.value for ct, _ in ctx.external_certs))
        has_shared = (any(DOGTAG_CERTS[cid].is_shared for cid, _ in certs)
                      or any(ct is IPACertType.IPARA for ct, _ in ipa_certs))
        if has_shared:
            if self._detector.check_is_renewal_master():
                dry_extra.append("Would remain renewal master")
            else:
                dry_extra.append("Would become renewal master")
        dry_extra.append("Would restart IPA services")
        if not self._confirm_execution(
            "renewal master certificate fix",
            "proceed",
            dry_extra_lines=dry_extra,
        ):
            return 0

        # Pre-flight checks run after dry-run so that --dry-run always shows
        # the plan even when pki-server or the CA cert is unavailable.
        try:
            ipautil.run(['pki-server', 'cert-fix', '--help'], raiseonerr=True)
        except (ipautil.CalledProcessError, FileNotFoundError):
            print(
                "The 'pki-server cert-fix' command is not available; "
                "cannot proceed.")
            self._scenario_made_changes = False
            return 1

        if not self._detector._check_ca_signing_cert():
            self._scenario_made_changes = False
            return self._detector._handle_expired_ca_signing_cert(
                ctx.deployment_type)

        print("Proceeding with renewal master approach.")
        print("Running pki-server cert-fix (this may take several minutes)...")

        try:
            fix_certreq_directives(certs)
            run_cert_fix(certs, ipa_certs)
        except ipautil.CalledProcessError:
            if any(
                x[0] is IPACertType.LDAPS for x in ipa_certs
            ):
                # DS cert was expired. pki-server cert-fix may fail at final
                # restart. If renewed cert files exist on disk, we can proceed.
                if check_renewed_ipa_certs(ipa_certs):
                    pass
                else:
                    raise
            else:
                raise

        # If the CA signing cert was renewed, verify it is now valid. A
        # partially-failed pki-server cert-fix could leave us with a
        # still-expired CA cert, which would cause all subsequent cert issuance
        # to fail.
        if any(cid == 'ca_issuing' for cid, _ in certs):
            if not self._detector._check_ca_signing_cert():
                print(
                    "The CA signing certificate is still expired after "
                    "pki-server cert-fix.\n"
                    "Please renew it manually using ipa-cacert-manage.")
                return 1

        # pki-server cert-fix may have restarted DS (if the LDAP cert was
        # renewed), breaking our connection.
        _ensure_ldap_connected()

        replicate_dogtag_certs(ctx.subject_base, ctx.ca_subject_dn, certs)
        install_ipa_certs(ctx.subject_base, ctx.ca_subject_dn, ipa_certs)

        # Shared certs are Dogtag certs other than sslserver (which is
        # host-specific) and the RA cert. Renewing any shared cert requires
        # effectively becoming RM.
        has_shared_dogtag = any(
            DOGTAG_CERTS[cid].is_shared for cid, _ in certs)
        has_shared_ipa = any(ct is IPACertType.IPARA for ct, _ in ipa_certs)
        became_rm = False
        if has_shared_dogtag or has_shared_ipa:
            if self._detector.check_is_renewal_master():
                print("Remaining renewal master.")
            else:
                print("Becoming renewal master.")
                became_rm = True
                self._ca_instance.set_renewal_master()

        # External certs are handled inline (not via a separate scenario
        # dispatch) because the RM/replica path must complete first -- the IPA
        # CA helper and certmonger state need to be restored before
        # transitioning or generating CSRs. run_external_certs is only reached
        # for the EXTERNAL_CERTS scenario (fully external, no internal CA at
        # all).
        if ctx.external_certs:
            self._external_handler.handle(ctx)

        print("Restarting IPA")
        ipautil.run(['ipactl', 'restart', '--ignore-service-failures'])
        _ensure_ldap_connected()

        if self._cm.is_responsive():
            self.resubmit_expired_certs()
        else:
            print(
                "WARNING: certmonger is not responding. "
                "Certificate renewal completed successfully, but "
                "certmonger tracking requests were not resubmitted.\n"
                "Run 'getcert list' once certmonger recovers to "
                "verify tracking status.")

        print(RENEWAL_NOTE)
        if became_rm:
            print(
                "IMPORTANT: This server is now the renewal master.\n"
                "Enable CRL generation on this server:\n"
                "  ipa-crlgen-manage enable\n"
                "Disable CRL generation on all other CA servers:\n"
                "  ipa-crlgen-manage disable\n")
        return 0

    def _run_non_rm_replica_fix(self, ctx, is_ca_full):
        """Shared logic for CA-full and CA-less replica fix.

        Fetches the CA chain from the master, fetches RA (and subsystem certs
        for CA-full), renews expired certs via certmonger pointed at
        the master, restarts IPA, and resubmits remaining requests.

        :param ctx: :class:`CertFixContext` with master_server
        :param is_ca_full: ``True`` for CA-full replica, ``False`` for CA-less
        :returns: exit code (0 for success)
        """
        dogtag = ctx.dogtag_certs if is_ca_full else []
        ipa_certs = ctx.ipa_certs
        master_server = ctx.master_server
        label = ("CA-full replica" if is_ca_full else "CA-less replica")

        dry_extra = [
            "Would fetch certificates from %s"
            % master_server,
        ]
        if dogtag:
            dry_extra.append(
                "Dogtag certs to renew: "
                + ", ".join(cid for cid, _ in dogtag))
        if ipa_certs:
            dry_extra.append(
                "IPA service certs to renew: "
                + ", ".join(ct.value for ct, _ in ipa_certs))
        if ctx.external_certs:
            dry_extra.append(
                "External certs (handled separately): "
                + ", ".join(ct.value for ct, _ in ctx.external_certs))
        if is_ca_full:
            dry_extra.append("Would NOT become renewal master")
        if not self._confirm_execution(
            "%s certificate fix" % label,
            "proceed with %s fix using server %s" % (label, master_server),
            dry_extra_lines=dry_extra,
        ):
            return 0

        old_krb_env = _setup_kerberos()

        try:
            self.update_ca_cert_from_master(master_server)

            self._fetch_certs_from_master(
                master_server, ctx,
                fetch_subsystem=is_ca_full,)

            renewal = CertRenewalFromMaster(self._cm, master_server)
            renewed_ids = renewal.renew(dogtag, ipa_certs, ctx)

            # See comment in run_renewal_master_fix for why external certs are
            # handled inline.
            if ctx.external_certs:
                self._external_handler.handle(ctx)

            # Certmonger post-save commands may have already restarted
            # individual services.
            print("Restarting IPA")
            ipautil.run(['ipactl', 'restart', '--ignore-service-failures'])
            _ensure_ldap_connected()

            if self._cm.is_responsive():
                self.resubmit_expired_certs(renewed_ids)
            else:
                print(
                    "WARNING: certmonger is not responding. "
                    "Certificate renewal completed successfully, "
                    "but certmonger tracking requests were not resubmitted.\n"
                    "Run 'getcert list' once certmonger recovers "
                    "to verify tracking status.")
        finally:
            _restore_kerberos(old_krb_env)

        # Advisory: warn if any CA cert in the local chain is near expiry.
        # The replica path doesn't need it for signing, but services will break
        # again if it isn't renewed in time.
        self._detector._warn_ca_chain_near_expiry()

        print(RENEWAL_NOTE)
        return 0

    def run_ca_full_promote(self, ctx):
        """Promote this replica to renewal master and fix certs.

        Used when the current renewal master is unrecoverable. Sets this server
        as renewal master, then delegates to :meth:`run_renewal_master_fix`.

        :param ctx: :class:`CertFixContext`
        :returns: exit code
        """
        # Verify pki-server cert-fix is available BEFORE promoting -- promotion
        # is a topology-wide change that is hard to undo.
        try:
            ipautil.run(
                ['pki-server', 'cert-fix', '--help'],
                raiseonerr=True, capture_output=True)
        except (ipautil.CalledProcessError, FileNotFoundError):
            print(
                "No working master server was found and "
                "'pki-server cert-fix' is not available.\n"
                "Cannot proceed with promotion or renewal.\n"
                "Either point to a working master with\n"
                "--force-server=<FQDN>, or install/update "
                "pki-server on this host.")
            return 1

        if self.options.dry_run:
            print("[DRY RUN] Would promote this server to renewal master")
            # Delegate to RM handler's dry-run for cert detail
            return self.run_renewal_master_fix(
                replace(ctx,
                        scenario=FixScenario.RENEWAL_MASTER))

        # In unattended mode, refuse to silently promote. Promotion is the most
        # destructive path -- it must be explicitly requested via
        # --renewal-master (which routes to RENEWAL_MASTER, not here).
        if self.options.unattended:
            print(
                "No working CA server was found. In unattended mode,\n"
                "promotion to renewal master requires the explicit "
                "--renewal-master flag.\n"
                "Alternatively, use --force-server=<FQDN> to point to "
                "a working master.")
            return 1

        print(PROMOTE_WARNING)
        response = ipautil.user_input('Enter "yes" to promote and proceed')
        if response.lower() != 'yes':
            print("Not proceeding.")
            return 0

        # Record the current RM (if any) so we can attempt rollback if the cert
        # fix fails after promotion.
        old_rm = _find_current_renewal_master()

        self._promote_to_renewal_master()

        rm_ctx = replace(ctx, scenario=FixScenario.RENEWAL_MASTER)
        # User already confirmed promotion -- suppress the second confirmation
        # inside run_renewal_master_fix.
        saved_unattended = self.options.unattended
        self.options.unattended = True
        try:
            result = self.run_renewal_master_fix(rm_ctx)
            if result != 0:
                # RM-fix returned a guarded failure (pre-flight check, partial
                # cert-fix, post-fix CA still expired). The promotion is a
                # topology-wide change -- attempt to roll it back so we don't
                # leave the cluster with this host as RM holding expired certs.
                self._rollback_promotion(old_rm)
                return result
            print(
                "IMPORTANT: This server is now the renewal master.\n"
                "Enable CRL generation on this server:\n"
                "  ipa-crlgen-manage enable\n"
                "Disable CRL generation on all other CA servers:\n"
                "  ipa-crlgen-manage disable\n")
            return 0
        except Exception:
            self._rollback_promotion(old_rm)
            raise
        finally:
            self.options.unattended = saved_unattended

    def _rollback_promotion(self, old_rm):
        """Best-effort rollback of an RM promotion.

        Called when ``run_renewal_master_fix`` either raises or returns a
        non-zero exit code after this host was promoted.  Failure is logged
        and printed -- never re-raised -- because the caller is already on an
        error path.

        :param old_rm: previous renewal master FQDN (may be ``None``)
        """
        if not old_rm or old_rm == api.env.host:
            return
        logger.warning(
            "Certificate fix failed after promotion. "
            "Attempting to restore renewal master to %s", old_rm)
        try:
            self._ca_instance.set_renewal_master(old_rm)
            print("Restored renewal master to %s" % old_rm)
        except Exception as rollback_err:
            logger.error(
                "Failed to restore renewal master to %s: %s",
                old_rm, rollback_err,)
            print(
                "WARNING: Could not restore renewal master to %s.\n"
                "This server (%s) is now the renewal master with "
                "expired certs.\nManual intervention required."
                % (old_rm, api.env.host))

    # =========================================================
    #  External Cert Handling (delegates to ExternalCertHandler)
    # =========================================================

    def run_external_certs(self, ctx):
        """Handle expired externally-signed certificates.

        Delegates to :class:`ExternalCertHandler` for transition offers and
        CSR generation.

        :param ctx: :class:`CertFixContext` with external_certs
        :returns: exit code
        """
        if not ctx.external_certs:
            print("Nothing to do.")
            return 0

        if self.options.dry_run:
            print("[DRY RUN] Would handle external certificates:")
            for certtype, _cert in ctx.external_certs:
                print("[DRY RUN]   %s: CSR to %s/%s.csr"
                      % (certtype.value,
                         ExternalCertHandler.DEFAULT_CSR_DIR,
                         certtype.value.lower().replace(' ', '-')))
            if (ctx.deployment_type
                    != DeploymentType.CA_LESS_EXTERNAL):
                print("[DRY RUN]   Transition to IPA CA would be offered "
                      "(interactive only)")
            return 0

        # Cert details already printed by _classify_and_dispatch.
        if self._external_handler.handle(ctx):
            return 0
        return 1

    # =========================================================
    #  Master Cert Operations
    # =========================================================

    def _check_ra_cert_staleness(self):
        """Check if the local RA cert is stale on a CA-less replica.

        Compares the local RA cert serial against the CA server's
        LDAP entry.  Returns True if the serials differ (local cert
        is outdated), False if they match or the check fails.

        Only meaningful on CA-less replicas where the RA cert is
        not managed by local certmonger renewal.
        """
        try:
            local_ra = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
        except Exception:
            logger.debug("Cannot load local RA cert, skipping staleness check")
            return False

        ca_servers = []
        try:
            ca_servers = find_providing_servers(
                'CA', conn=api.Backend.ldap2, api=api)
        except Exception as e:
            logger.debug("Cannot discover CA servers: %s", e)
            return False

        if not ca_servers:
            return False

        server = ca_servers[0]
        old_krb = _setup_kerberos()
        try:
            conn = ipaldap.LDAPClient.from_hostname_secure(server)
            conn.gssapi_bind()
            ra_dn = DN(('uid', 'ipara'), ('ou', 'people'), ('o', 'ipaca'))
            entry = conn.get_entry(ra_dn, ['userCertificate'])
            remote_ra = _get_newest_cert(entry['userCertificate'])
            conn.unbind()
        except Exception as e:
            logger.debug("Cannot check RA cert on %s: %s", server, e)
            return False
        finally:
            _restore_kerberos(old_krb)

        if local_ra.serial_number != remote_ra.serial_number:
            logger.info(
                "Local RA cert (serial %s) differs from %s (serial %s)",
                local_ra.serial_number, server, remote_ra.serial_number)
            print(
                "The local RA certificate (serial %s) is outdated.\n"
                "The CA server %s has serial %s."
                % (local_ra.serial_number, server,
                   remote_ra.serial_number))
            return True

        logger.debug("Local RA cert matches CA server %s (serial %s)",
                     server, local_ra.serial_number)
        return False

    def _fetch_ra_from_ca_server(self):
        """Fetch the current RA cert from a CA server.

        Used when the local RA cert is valid but stale (different
        serial than the CA server's copy).
        """
        ca_servers = find_providing_servers(
            'CA', conn=api.Backend.ldap2, api=api)
        if not ca_servers:
            print("ERROR: No CA servers found.")
            return

        server = ca_servers[0]
        print("Fetching updated RA certificate from %s" % server)
        old_krb = _setup_kerberos()
        conn = None
        try:
            conn = ipaldap.LDAPClient.from_hostname_secure(server)
            conn.gssapi_bind()
            ra_dn = DN(('uid', 'ipara'), ('ou', 'people'), ('o', 'ipaca'))
            entry = conn.get_entry(ra_dn, ['userCertificate'])
            ra_cert = _get_newest_cert(entry['userCertificate'])

            print_cert_info("Fetched", "IPA RA", ra_cert)
            if ra_cert.not_valid_after_utc <= _utcnow():
                print("ERROR: RA cert fetched from %s is expired "
                      "(notAfter=%s). The CA server's RA cert "
                      "must be renewed first."
                      % (server, ra_cert.not_valid_after_utc))
                return
            x509.write_certificate(ra_cert, paths.RA_AGENT_PEM)
            cainstance.CAInstance._set_ra_cert_perms()
            print("RA certificate updated.")
        except Exception as e:
            print("ERROR: Failed to fetch RA cert from %s: %s"
                  % (server, e))
        finally:
            if conn is not None:
                conn.unbind()
            _restore_kerberos(old_krb)

    def _promote_to_renewal_master(self):
        """Promote the current replica to renewal master.

        Sets this server as the renewal master in LDAP.

        :raises RuntimeError: if promotion fails
        """
        _ensure_ldap_connected()
        print("Setting this server as the renewal master.")
        try:
            self._ca_instance.set_renewal_master(api.env.host)
        except Exception as e:
            raise RuntimeError("Failed to set renewal master: %s" % e)
        logger.info("Successfully set %s as renewal master", api.env.host)

    def _fetch_certs_from_master(
        self, master_server, ctx, fetch_subsystem=True,
    ):
        """Fetch RA and shared certs from master.

        Connects to the master's LDAP via GSSAPI and retrieves the RA cert.
        For CA-full replicas, also fetches the subsystem cert and any other
        shared/replicated dogtag certs (OCSP, audit, KRA) from
        ``cn=ca_renewal`` in LDAP, and installs them in the local PKI NSS
        database.

        :param master_server: FQDN of the master server
        :param ctx: :class:`CertFixContext`
        :param fetch_subsystem: if ``True``, also fetch shared dogtag
            certs (CA-full only)
        :raises RuntimeError: if a fetched cert is expired (master
            needs fixing first)
        """
        now = _utcnow()

        def _check_not_expired(cert, desc):
            if cert.not_valid_after_utc <= now:
                raise RuntimeError(
                    "Certificate '%s' fetched from %s is expired "
                    "(notAfter=%s). The master server's certificates "
                    "must be renewed first."
                    % (desc, master_server, cert.not_valid_after_utc))

        label = ("RA and shared certs" if fetch_subsystem else "RA")
        print("Fetching %s from %s" % (label, master_server))

        logger.debug("Connecting to master LDAP: %s (GSSAPI)", master_server)
        try:
            conn = ipaldap.LDAPClient.from_hostname_secure(master_server)
            conn.gssapi_bind()
        except Exception as e:
            err_str = str(e).lower()
            if ('certificate' in err_str
                    and ('expired' in err_str or 'verify' in err_str)):
                raise RuntimeError(
                    "Cannot connect to %s: TLS certificate error (%s).\n\n"
                    "Possible causes:\n"
                    "  - The server's certificates are expired."
                    "  Run ipa-cert-fix on %s first.\n"
                    "  - The CA certificate on %s was renewed "
                    "and this server's trust store is stale.\n"
                    "    Copy %s from %s to this server and retry."
                    % (master_server, e, master_server,
                       master_server, paths.IPA_CA_CRT,
                       master_server))
            raise
        logger.debug("Successfully connected to master LDAP")

        try:
            # RA certificate -- only fetch if expired
            ra_expired = any(
                ct is IPACertType.IPARA for ct, _ in ctx.ipa_certs)
            if ra_expired:
                ra_dn = DN(('uid', 'ipara'), ('ou', 'people'), ('o', 'ipaca'))
                try:
                    old_ra = x509.load_certificate_from_file(
                        paths.RA_AGENT_PEM)
                    old_serial = old_ra.serial_number
                except Exception:
                    old_serial = None
                if fetch_subsystem:
                    ra_cert = _fetch_and_update_cert(
                        conn, ra_dn, "RA", "IPA RA")
                else:
                    # CA-less: no local o=ipaca -- just fetch
                    remote_entry = conn.get_entry(ra_dn, ['userCertificate'])
                    ra_cert = _get_newest_cert(remote_entry['userCertificate'])
                    print_cert_info("Fetched", "IPA RA", ra_cert)
                _check_not_expired(ra_cert, "IPA RA")
                logger.debug(
                    "Writing RA cert to %s (old serial: %s, new serial: %s)",
                    paths.RA_AGENT_PEM, old_serial,
                    ra_cert.serial_number)
                x509.write_certificate(ra_cert, paths.RA_AGENT_PEM)
                cainstance.CAInstance._set_ra_cert_perms()
            else:
                logger.debug("RA cert is valid, skipping fetch")

            # Subsystem certificate -- only fetch if expired
            if fetch_subsystem:
                db = _get_pki_nssdb()
                sub_expired = any(
                    cid == 'subsystem' for cid, _ in ctx.dogtag_certs)
                if sub_expired:
                    sub_dn = DN(('uid', 'pkidbuser'),
                                ('ou', 'people'),
                                ('o', 'ipaca'),)
                    sub_cert = _fetch_and_update_cert(
                        conn, sub_dn,
                        "Subsystem", "CA Subsystem")
                    _check_not_expired(sub_cert, "CA Subsystem")
                    nickname = DOGTAG_CERTS['subsystem'].nickname
                    logger.debug(
                        "Updating subsystem cert in NSS database "
                        "%s, nickname=%s, serial=%s",
                        paths.PKI_TOMCAT_ALIAS_DIR,
                        nickname,
                        sub_cert.serial_number,)
                    _replace_cert_in_nssdb(db, nickname, sub_cert)
                    _update_cs_cfg(nickname, sub_cert)
                else:
                    logger.debug("Subsystem cert is valid, skipping fetch")

                self._fetch_shared_dogtag_certs(
                    conn, db, ctx, master_server, now)
        finally:
            conn.unbind()

    # Subset fetched from cn=ca_renewal by _fetch_shared_dogtag_certs. Excludes
    # ca_issuing (ipa-certupdate) and subsystem (direct fetch).
    _SHARED_DOGTAG_CERTS = {
        ci.id: ci.nickname for ci in DOGTAG_CERTS.values()
        if ci.is_shared and ci.id not in ('ca_issuing', 'subsystem')
    }

    def _fetch_shared_dogtag_certs(self, conn, db, ctx, master_server, now):
        """Fetch shared dogtag certs from cn=ca_renewal on the master.

        Installs each cert into the local NSSDB, sets audit cert trust flags,
        and updates the CS.cfg blob.

        :param conn: LDAP connection to the master
        :param db: local PKI :class:`NSSDatabase`
        :param ctx: :class:`CertFixContext`
        :param master_server: master FQDN (for error messages)
        :param now: current UTC datetime (for expiry check)
        """
        # Only fetch certs that are actually expired. KRA certs are only in
        # expired_ids if KRA is installed locally (expired_dogtag_certs skips
        # missing nicknames).
        expired_ids = {cid for cid, _ in ctx.dogtag_certs}
        for certid, nickname in self._SHARED_DOGTAG_CERTS.items():
            if certid not in expired_ids:
                continue
            try:
                renewal_dn = DN(('cn', nickname),
                                ('cn', 'ca_renewal'),
                                ('cn', 'ipa'),
                                ('cn', 'etc'),
                                api.env.basedn)
                entry = conn.get_entry(renewal_dn, ['usercertificate'])
                new_cert = entry.single_value['usercertificate']
                print_cert_info("Fetched", nickname, new_cert)
                if new_cert.not_valid_after_utc <= now:
                    raise RuntimeError(
                        "Certificate '%s' fetched from %s is expired "
                        "(notAfter=%s). The master server's certificates "
                        "must be renewed first."
                        % (nickname, master_server,
                           new_cert.not_valid_after_utc))
                _replace_cert_in_nssdb(db, nickname, new_cert)
                # Audit signing certs need 'u,u,Pu' trust (same as
                # renew_ca_cert post-save command)
                if 'audit' in certid:
                    db.run_certutil(['-M', '-t', 'u,u,Pu', '-n', nickname])
                _update_cs_cfg(nickname, new_cert)
                logger.debug(
                    "Installed shared cert %s (serial %s) in NSSDB",
                    nickname, new_cert.serial_number)
            except RuntimeError:
                raise  # expiry check -- must propagate
            except Exception as e:
                logger.warning(
                    "Failed to fetch shared cert %s: %s", nickname, e)

    def update_ca_cert_from_master(self, master_server):
        """
        Update the CA certificate chain from the master server.

        If the local CA chain (``/etc/ipa/ca.crt``) is already present
        and valid (no expired certs in the trust path), skips the
        expensive ``ipa-certupdate`` call.  Otherwise runs
        ``ipa-certupdate --force-server <master_server>``.

        ipa-certupdate may exit non-zero if some service restarts fail
        (e.g. httpd, krb5kdc with expired certs), but the CA cert chain
        update itself happens before any restarts. We check whether the
        chain file was actually modified to determine success.
        """
        # Check if local CA chain is already valid and we can reach the master
        # over TLS. If both are fine, ipa-certupdate is unnecessary -- skip it
        # to avoid service restarts and certmonger D-Bus disruption.
        try:
            DeploymentDetector._verify_ca_chain_valid(master_server)
        except RuntimeError:
            logger.debug("Local CA chain is missing or invalid, "
                         "running ipa-certupdate")
        else:
            # Chain is valid -- can we TLS handshake to the master?
            try:
                _check_tls_handshake(master_server)
                print("Local CA chain is valid and TLS to %s works, "
                      "skipping ipa-certupdate." % master_server)
                return
            except Exception as e:
                # Local chain is valid but TLS to master fails. The master's CA
                # cert was likely renewed and our trust store is stale.
                # ipa-certupdate will also fail (it needs HTTPS to the master).
                # The only safe fix is to manually copy the updated ca.crt.
                raise RuntimeError(
                    "Cannot verify TLS to %s: %s\n\n"
                    "The local CA chain (%s) is valid but does not match the "
                    "master's current certificate. This typically means the "
                    "CA certificate on %s was renewed.\n\n"
                    "ipa-cert-fix cannot update the trust store automatically "
                    "because it cannot verify the master's identity without "
                    "the updated CA chain (MITM risk).\n\n"
                    "To fix this:\n"
                    "  1. On %s, copy %s to this server\n"
                    "  2. Place it at %s\n"
                    "  3. Re-run ipa-cert-fix\n\n"
                    "Verify the file authenticity before copying "
                    "(e.g. compare checksums out-of-band)."
                    % (master_server, e, paths.IPA_CA_CRT,
                       master_server, master_server,
                       paths.IPA_CA_CRT, paths.IPA_CA_CRT))

        print("Updating CA certificate chain from %s" % master_server)

        logger.debug("Running: ipa-certupdate --force-server %s",
                     master_server)
        result = ipautil.run(
            ['ipa-certupdate', '--force-server', master_server],
            raiseonerr=False)
        logger.debug("ipa-certupdate returncode=%s", result.returncode)

        if result.returncode != 0:
            logger.warning("ipa-certupdate exited with code %s",
                           result.returncode)

        # Regardless of ipa-certupdate exit code, check whether the CA chain is
        # present and valid.  ipa-certupdate may exit non-zero due to service
        # restart failures (expected with expired certs) or certmonger D-Bus
        # timeouts, but the CA chain itself may be fine.
        DeploymentDetector._verify_ca_chain_valid(master_server)

        if result.returncode != 0:
            print("WARNING: ipa-certupdate exited with an error, but "
                  "the CA chain is valid.\n"
                  "This is expected if some services failed to restart "
                  "due to expired certificates. Continuing.")

        # LDAP must still be running for subsequent steps
        if not dsinstance.is_ds_running(realm_to_serverid(api.env.realm)):
            raise RuntimeError(
                "LDAP server is no longer running after ipa-certupdate. "
                "Please check the directory server logs and restart it "
                "before retrying.")

        # ipa-certupdate may have restarted dirsrv, which breaks our LDAPI
        # connection.
        _ensure_ldap_connected()

    # =========================================================
    #  Infrastructure Helpers
    # =========================================================

    def _confirm_execution(self, dry_label, prompt, dry_extra_lines=None):
        """Handle dry-run or ask for user confirmation.

        The expired cert summary is already printed before scenario
        dispatch.  This method only handles the dry-run label/extras
        or the yes/no confirmation.

        :param dry_label: label for ``[DRY RUN]`` output
        :param prompt: text after ``Enter "yes" to``
        :param dry_extra_lines: extra ``[DRY RUN]`` lines
        :returns: ``True`` to proceed, ``False`` to bail
        """
        if self.options.dry_run:
            print("[DRY RUN] Would execute %s" % dry_label)
            for line in (dry_extra_lines or []):
                print("[DRY RUN] %s" % line)
            logger.info("Dry run completed, no changes made")
            return False

        # Print the plan in all modes so the user (or log) sees what will
        # happen before the tool proceeds.
        for line in (dry_extra_lines or []):
            print("  %s" % line)

        if not self.options.unattended:
            response = ipautil.user_input('Enter "yes" to %s' % prompt)
            if response.lower() != 'yes':
                print("Not proceeding.")
                logger.info("User declined, no changes made")
                return False

        self._scenario_made_changes = True
        return True

    def resubmit_expired_certs(self, renewed_ids=None):
        """Resubmit remaining expired certificate requests.

        After IPA restart, certmonger may already be processing some requests
        (triggered by the restart or by post-save commands from earlier
        renewals).  This method:

        - Skips requests already renewed by :class:`CertRenewalFromMaster`
        - Skips requests that certmonger is actively processing
          (``SUBMITTING``, ``CA_WORKING``, etc.)
        - Skips requests whose cert is already valid (renewed by certmonger
          autonomously)
        - Only resubmits requests stuck in error states
          (``CA_UNREACHABLE``, ``CA_REJECTED``, etc.)

        :param renewed_ids: set of request IDs already renewed
            from master (skipped to avoid double-submission)
        """
        if renewed_ids is None:
            renewed_ids = set()
        print("Checking remaining certificate requests...")

        request_ids = []

        # Dogtag NSS database (empty on CA-less)
        pki_ids = self._cm.get_requests_for_dir(paths.PKI_TOMCAT_ALIAS_DIR)
        logger.debug(
            "Tracking requests in %s: %s",
            paths.PKI_TOMCAT_ALIAS_DIR, pki_ids)
        request_ids.extend(pki_ids)

        # DS NSS database
        serverid = realm_to_serverid(api.env.realm)
        ds_dbdir = dsinstance.config_dirname(serverid).rstrip('/')
        ds_ids = self._cm.get_requests_for_dir(ds_dbdir)
        logger.debug("Tracking requests in %s: %s", ds_dbdir, ds_ids)
        request_ids.extend(ds_ids)

        # File-based certs (HTTPD, KDC, RA)
        for certfile in (paths.HTTPD_CERT_FILE,
                         paths.KDC_CERT,
                         paths.RA_AGENT_PEM):
            request_id = self._cm.get_request_id({'cert-file': certfile})
            if request_id is not None:
                logger.debug(
                    "Tracking request for %s: %s", certfile, request_id)
                request_ids.append(request_id)

        logger.debug("Total tracking requests to check: %s", request_ids)

        # States where certmonger is actively processing the request or the
        # cert is already good. Resubmitting in these states would interfere
        # with certmonger's own renewal attempt.
        skip_states = {
            'MONITORING',
            'SUBMITTING', 'CA_WORKING',
            'READING_CERT', 'POST_SAVED_CERT', 'SAVING_CERT',
            'NEWLY_ADDED_NEED_KEYINFO_READ_PIN',
            'NEED_KEY_PAIR', 'GENERATING_KEY_PAIR',
            'NEED_CSR', 'GENERATING_CSR',
        }

        # Error states where a resubmit is warranted.
        error_states = {
            'CA_UNREACHABLE', 'CA_REJECTED',
            'CA_UNCONFIGURED', 'NEED_GUIDANCE',
            'NEED_CA',
        }

        resubmitted = 0
        for request_id in request_ids:
            if request_id in renewed_ids:
                logger.debug(
                    "Request %s already renewed from master, skipping",
                    request_id)
                continue

            try:
                status = self._cm.get_request_value(request_id, 'status')
            except Exception as e:
                logger.warning(
                    "Cannot read status for request %s: %s",
                    request_id, e)
                print("  Request %s: cannot read status, skipping"
                      % request_id)
                continue

            if status in skip_states:
                logger.debug(
                    "Request %s in state %s, skipping",
                    request_id, status)
                continue

            if status not in error_states:
                # Unknown state -- log it but don't blindly resubmit.
                logger.info(
                    "Request %s in unexpected state %s, not resubmitting",
                    request_id, status)
                continue

            # Check if the cert is already valid (e.g. we just installed it
            # via LDAP fetch but certmonger doesn't know yet).  Resubmitting
            # a valid cert causes certmonger to request a new one from CA,
            # which is wasteful and can get stuck in CA_WORKING state.
            if self._cm.is_cert_valid(request_id):
                logger.debug("Request %s cert is already valid, "
                             "skipping resubmit", request_id)
                print("  Request %s cert is already valid, skipping."
                      % request_id)
                continue

            print(
                "  Resubmitting request %s (status: %s)" % (request_id, status)
            )
            try:
                self._cm.resubmit_request(request_id)
            except Exception as e:
                logger.warning(
                    "Failed to resubmit request %s: %s", request_id, e)
                print("  WARNING: Failed to resubmit request %s "
                      "(certmonger may be busy)" % request_id)
                continue
            resubmitted += 1
            try:
                state = self._cm.wait_for_request(request_id, timeout=60)
            except RuntimeError:
                logger.debug("Timeout waiting for request %s", request_id)
                state = self._cm.get_request_value(request_id, 'status')

            if state == 'MONITORING':
                print("  Request %s completed." % request_id)
            elif state in ('CA_WORKING', 'SUBMITTING',
                           'POST_SAVED_CERT', 'READING_CERT'):
                print("  Request %s still being processed, "
                      "will complete in background." % request_id)
            else:
                logger.warning("Request %s is in state %s", request_id, state)
                print("  WARNING: Request %s is in state: %s"
                      % (request_id, state))

        if resubmitted == 0:
            print("  All requests are already being processed or completed.")


# =============================================================
#  Module-level cert operations (renewal master path)
# =============================================================


def _get_newest_cert(certs):
    """
    Given a list of certificates, return the one with the latest
    notAfter date.
    """
    if not certs:
        raise RuntimeError("No certificates found in LDAP entry")
    return max(certs, key=lambda c: c.not_valid_after_utc)


def _fetch_and_update_cert(remote_conn, dn, context, desc):
    """
    Fetch the newest certificate from a remote LDAP entry and update
    the corresponding local LDAP entry.

    Picks the cert with the latest notAfter from the remote entry's
    userCertificate attribute. Then updates the local entry: adds the cert
    if not already present, and updates the description with the current
    serial number.

    :param remote_conn: LDAP connection to the master server
    :param dn: DN of the entry (same on remote and local)
    :param context: label for log/print (e.g. "RA", "Subsystem")
    :param desc: certificate description for print_cert_info
    :returns: the newest certificate from the remote entry
    """
    logger.debug("Fetching %s cert from remote DN: %s", context, dn)
    remote_entry = remote_conn.get_entry(dn, ['userCertificate'])
    remote_certs = remote_entry['userCertificate']
    logger.debug(
        "Remote entry %s has %d userCertificate value(s)",
        dn, len(remote_certs))
    cert = _get_newest_cert(remote_certs)
    logger.debug(
        "Selected newest %s cert: serial=%s, subject=%s, "
        "notBefore=%s, notAfter=%s",
        context, cert.serial_number, DN(cert.subject),
        cert.not_valid_before_utc, cert.not_valid_after_utc)
    print_cert_info("Fetched", desc, cert)

    # Update local LDAP entry
    local_conn = api.Backend.ldap2
    local_entry = local_conn.get_entry(dn, ['userCertificate', 'description'])
    local_certs = local_entry.get('userCertificate', [])
    logger.debug(
        "Local entry %s has %d userCertificate value(s)",
        dn, len(local_certs))

    # Add the cert if not already present
    cert_der = cert.public_bytes(x509.Encoding.DER)
    already_present = any(
        c.public_bytes(x509.Encoding.DER) == cert_der
        for c in local_certs)
    if already_present:
        logger.debug(
            "Cert serial=%s already present in local entry, "
            "not adding duplicate", cert.serial_number)
    else:
        logger.debug(
            "Adding cert serial=%s to local entry", cert.serial_number)
        local_certs.append(cert)
        local_entry['userCertificate'] = local_certs

    # Update description with current serial: 2;SERIAL;issuer;subject
    new_desc = '2;%d;%s;%s' % (
        cert.serial_number, DN(cert.issuer), DN(cert.subject))
    try:
        old_desc = local_entry.single_value.get('description', '')
    except ValueError:
        old_desc = None
    logger.debug("Updating description: old='%s', new='%s'",
                 old_desc, new_desc)
    local_entry['description'] = new_desc

    try:
        local_conn.update_entry(local_entry)
        logger.debug("Local entry %s updated successfully", dn)
    except errors.EmptyModlist:
        logger.debug("Local entry %s already up to date", dn)

    return cert


def print_intentions(dogtag_certs, ipa_certs, external_certs=None):
    if dogtag_certs or ipa_certs:
        print("The following certificates will be renewed:")
        print()
        for certid, cert in dogtag_certs:
            print_cert_info("Dogtag", certid, cert)
        for certtype, cert in ipa_certs:
            print_cert_info("IPA", certtype.value, cert)
    if external_certs:
        print("The following externally-signed certificates require "
              "separate handling")
        print("(transition to IPA CA or CSR generation for external renewal):")
        print()
        for certtype, cert in external_certs:
            print_cert_info("External", certtype.value, cert)


def fix_certreq_directives(certs):
    """
    For all the certs to be fixed, ensure that the corresponding CSR is found
    in PKI config file, or try to get the CSR from certmonger.
    """
    # pki-server cert-fix needs to find the CSR in the subsystem config file
    # otherwise it will fail. For each cert to be fixed, check that the CSR is
    # present or get it from certmonger.
    for (certid, _cert) in certs:
        ci = DOGTAG_CERTS.get(certid)
        if ci is None or ci.certreq_directive is None:
            continue
        if directivesetter.get_directive(
                ci.cfg_path, ci.certreq_directive, '=') is None:
            csr = get_csr_from_certmonger(ci.nickname)
            if csr:
                directivesetter.set_directive(
                    ci.cfg_path, ci.certreq_directive, csr,
                    quotes=False, separator='=')


def run_cert_fix(certs, ipa_certs):
    ldapi_path = (
        paths.SLAPD_INSTANCE_SOCKET_TEMPLATE
        % realm_to_serverid(api.env.realm))
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
        cert_path = DOGTAG_CERT_PATH_TEMPLATE.format(certid)
        cert = x509.load_certificate_from_file(cert_path)
        print_cert_info("Renewed Dogtag", certid, cert)
        replicate_cert(subject_base, ca_subject_dn, cert)
        # Update ou=People,o=ipaca entry (userCertificate blob + description
        # with serial) and the lightweight authority entry (authoritySerial).
        # This mirrors what renew_ca_cert post-save does on the renewal master.
        try:
            cainstance.update_people_entry(cert)
        except Exception as e:
            logger.warning(
                "Failed to update people entry for %s: %s", certid, e)
        try:
            cainstance.update_authority_entry(cert)
        except Exception as e:
            logger.debug(
                "No authority entry for %s (expected for most certs): %s",
                certid, e)


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
