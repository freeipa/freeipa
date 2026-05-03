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

from dataclasses import replace
import logging
import os
import shutil
import socket

from ipalib import api
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
# Re-export public names from the helper modules so that all symbols are
# importable from ``ipaserver.install.ipa_cert_fix``.
from ipaserver.install.ipa_cert_fix_services import (  # noqa: F401
    CertRenewalFromMaster,
    CertmongerClient,
    DeploymentDetector,
    _ensure_ldap_connected,
    _find_current_renewal_master,
    _get_pki_nssdb,
    _replace_cert_in_nssdb,
    _update_cs_cfg,
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
    PROMOTE_WARNING,
    RENEWAL_NOTE,
    RENEWED_CERT_PATH_TEMPLATE,
    WARNING_BANNER,
    _utcnow,
)
from ipapython import directivesetter
from ipapython import ipautil

logger = logging.getLogger(__name__)


def _check_tls_handshake(server, timeout=10):
    """Verify TLS handshake to a server succeeds.

    Uses the system CA trust store (which includes ``/etc/ipa/ca.crt``) to
    verify that local trust chain is sufficient to connect to the master.
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
    """Restore Kerberos environment after remote operations."""
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

    _cm = None  # CertmongerClient; set in run()
    _ca_instance = None  # cainstance.CAInstance; set in _classify_and_dispatch
    _detector = None  # DeploymentDetector; set in _classify_and_dispatch

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
                 "caution, and verify CRL generation and IPA config after "
                 "the topology is stable again!")

    def validate_options(self):
        super(IPACertFix, self).validate_options(needs_root=True)

        if self.options.renewal_master and self.options.force_server:
            self.option_parser.error(
                "--renewal-master and --force-server are mutually exclusive")

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
        self._ca_instance = cainstance.CAInstance() if has_ca else None

        self._detector = DeploymentDetector(
            self._cm, self._ca_instance, self.options)

        deployment_type = self._detector.detect_deployment_type()
        logger.info("Deployment type: %s", deployment_type.value)
        if has_ca:
            ca_subject_dn = ca.lookup_ca_subject(api, subject_base)

        now = _utcnow() + CERT_EXPIRY_LOOKAHEAD
        dogtag_certs, ipa_certs, external_certs = \
            self._detector._classify_certs(now, ds_dbdir, ds_nickname)

        # On CA-less replicas, the RA cert may be valid but stale (renewed
        # on the CA server, not yet updated here).  A stale RA cert causes
        # ipa commands to fail with auth errors even though no cert is
        # technically expired.
        ra_stale = False
        if (not has_ca
                and deployment_type == DeploymentType.CA_LESS
                and not any(ct is IPACertType.IPARA
                            for ct, _ in ipa_certs)):
            ra_stale = self._check_ra_cert_staleness()

        if (not dogtag_certs and not ipa_certs
                and not external_certs and not ra_stale):
            print("Nothing to do.")
            return 0

        if ra_stale and not (dogtag_certs or ipa_certs or external_certs):
            if not self._confirm_execution():
                return 0
            self._fetch_ra_from_ca_server()
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
            FixScenario.CA_FULL_WITH_MASTER:
                lambda c: self._run_non_rm_replica_fix(c, is_ca_full=True),
            FixScenario.CA_FULL_PROMOTE: self.run_ca_full_promote,
            FixScenario.CA_LESS_WITH_MASTER:
                lambda c: self._run_non_rm_replica_fix(c, is_ca_full=False),
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

    def _run_non_rm_replica_fix(self, ctx, is_ca_full):
        """Shared logic for CA-full and CA-less replica fix.

        Fetches the CA chain from the master, fetches RA (and subsystem certs
        for CA-full), renews expired certs via certmonger pointed at the
        master, then restarts IPA.

        :param ctx: :class:`CertFixContext` with master_server
        :param is_ca_full: ``True`` for CA-full replica, ``False`` for CA-less
        :returns: exit code (0 for success)
        """
        dogtag = ctx.dogtag_certs if is_ca_full else []
        ipa_certs = ctx.ipa_certs
        master_server = ctx.master_server
        label = ("CA-full replica" if is_ca_full else "CA-less replica")

        print(WARNING_BANNER)
        print_intentions(dogtag, ipa_certs, ctx.external_certs)
        print("This will fetch certificates from %s." % master_server)
        if not self._confirm_execution():
            return 0

        print("Proceeding with %s fix using server %s."
              % (label, master_server))

        old_krb_env = _setup_kerberos()
        try:
            self.update_ca_cert_from_master(master_server)

            self._fetch_certs_from_master(
                master_server, ctx,
                fetch_subsystem=is_ca_full,)

            renewal = CertRenewalFromMaster(self._cm, master_server)
            renewal.renew(dogtag, ipa_certs, ctx)

            print("Restarting IPA")
            ipautil.run(['ipactl', 'restart', '--ignore-service-failures'])
            _ensure_ldap_connected()
        finally:
            _restore_kerberos(old_krb_env)

        print(RENEWAL_NOTE)
        return 0

    def run_ca_full_promote(self, ctx):
        """Promote this replica to renewal master and fix certs.

        Used when the current renewal master is unrecoverable.  Sets this
        server as the renewal master, then delegates to
        :meth:`run_renewal_master_fix`.  If the cert fix fails after
        promotion, attempts a best-effort rollback of the renewal master
        role.

        :param ctx: :class:`CertFixContext`
        :returns: exit code
        """
        # Verify pki-server cert-fix is available BEFORE promoting --
        # promotion is a topology-wide change that is hard to undo.
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

        # In unattended mode, refuse to silently promote.  Promotion is the
        # most destructive path -- it must be explicitly requested via
        # --renewal-master (which routes to RENEWAL_MASTER, not here).
        if getattr(self.options, 'unattended', False):
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

        # Record the current RM (if any) so we can attempt rollback if the
        # cert fix fails after promotion.
        old_rm = _find_current_renewal_master()

        self._promote_to_renewal_master()

        rm_ctx = replace(ctx, scenario=FixScenario.RENEWAL_MASTER)
        try:
            result = self.run_renewal_master_fix(rm_ctx)
            if result != 0:
                # RM-fix returned a guarded failure (pre-flight check, partial
                # cert-fix, post-fix CA still expired). The promotion is a
                # topology-wide change -- attempt to roll it back so we don't
                # leave the cluster with this host as RM holding expired
                # certs.
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

    def _rollback_promotion(self, old_rm):
        """Best-effort rollback of an RM promotion.

        Called when ``run_renewal_master_fix`` either raises or returns a
        non-zero exit code after this host was promoted.  Failure is logged
        and printed -- never re-raised -- because the caller is already on
        an error path.

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

    def _check_ra_cert_staleness(self):
        """Check if the local RA cert is stale on a CA-less replica.

        Compares the local RA cert serial against the CA server's LDAP
        entry.  Returns True if the serials differ (local cert is
        outdated), False if they match or the check fails.

        Only meaningful on CA-less replicas where the RA cert is not
        managed by local certmonger renewal.
        """
        try:
            local_ra = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
        except Exception:
            logger.debug("Cannot load local RA cert, skipping staleness check")
            return False

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

        Used when the local RA cert is valid but stale (different serial
        than the CA server's copy).
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
        :param fetch_subsystem: if ``True``, also fetch shared dogtag certs
            (CA-full only)
        :raises RuntimeError: if a fetched cert is expired (master needs
            fixing first)
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

            if fetch_subsystem:
                db = _get_pki_nssdb()
                sub_expired = any(
                    cid == 'subsystem' for cid, _ in ctx.dogtag_certs)
                if sub_expired:
                    sub_dn = DN(
                        ('uid', 'pkidbuser'),
                        ('ou', 'people'),
                        ('o', 'ipaca'),
                    )
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

    # Subset fetched from cn=ca_renewal by _fetch_shared_dogtag_certs.
    # Excludes ca_issuing (ipa-certupdate) and subsystem (direct fetch).
    _SHARED_DOGTAG_CERTS = {
        ci.id: ci.nickname for ci in DOGTAG_CERTS.values()
        if ci.is_shared and ci.id not in ('ca_issuing', 'subsystem')
    }

    def _fetch_shared_dogtag_certs(self, conn, db, ctx, master_server, now):
        """Fetch shared dogtag certs from cn=ca_renewal on the master.

        Installs each cert into the local NSSDB, sets audit cert trust
        flags, and updates the CS.cfg blob.
        """
        # Only fetch certs that are actually expired. KRA certs are only in
        # expired_ids if KRA is installed locally (expired_dogtag_certs skips
        # missing nicknames).
        expired_ids = {cid for cid, _ in ctx.dogtag_certs}
        for certid, nickname in self._SHARED_DOGTAG_CERTS.items():
            if certid not in expired_ids:
                continue
            try:
                renewal_dn = DN(
                    ('cn', nickname),
                    ('cn', 'ca_renewal'),
                    ('cn', 'ipa'),
                    ('cn', 'etc'),
                    api.env.basedn,
                )
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
        """Update the CA certificate chain from the master server.

        Runs ``ipa-certupdate --force-server <master_server>`` to refresh
        the local CA trust store from the master before any other remote
        operation.

        ipa-certupdate may exit non-zero if some service restarts fail
        (e.g. httpd, krb5kdc with expired certs), but the CA cert chain
        update itself happens before any restarts.
        """
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
            print(
                "WARNING: ipa-certupdate exited with an error.\n"
                "This is expected if some services failed to restart "
                "due to expired certificates. Continuing.")

        if not dsinstance.is_ds_running(realm_to_serverid(api.env.realm)):
            raise RuntimeError(
                "LDAP server is no longer running after ipa-certupdate. "
                "Please check the directory server logs and restart it "
                "before retrying.")

        # ipa-certupdate may have restarted dirsrv, which breaks our LDAPI
        # connection.
        _ensure_ldap_connected()

    def _confirm_execution(self):
        """Interactively confirm before performing destructive actions."""
        response = ipautil.user_input('Enter "yes" to proceed')
        if response.lower() != 'yes':
            print("Not proceeding.")
            return False
        print("Proceeding.")
        return True


def _get_newest_cert(certs):
    """Return the certificate with the latest notAfter from a list."""
    return max(certs, key=lambda c: c.not_valid_after_utc)


def _fetch_and_update_cert(remote_conn, dn, context, desc):
    """Fetch the newest cert at *dn* from a remote master and update LDAP.

    Reads ``userCertificate`` from the remote entry, picks the cert with the
    latest ``notAfter``, and writes it back into the local LDAP entry along
    with the matching ``description`` value (the format Dogtag expects).

    :param remote_conn: LDAP connection to the master
    :param dn: target DN (RA or subsystem)
    :param context: short label used in print/log
    :param desc: descriptive label for ``print_cert_info``
    :returns: the cert chosen as newest
    """
    remote_entry = remote_conn.get_entry(dn, ['userCertificate'])
    new_cert = _get_newest_cert(remote_entry['userCertificate'])
    print_cert_info("Fetched", desc, new_cert)

    expected_desc = '2;%d;%s;%s' % (
        new_cert.serial_number,
        DN(new_cert.issuer), DN(new_cert.subject))

    conn = api.Backend.ldap2
    try:
        local_entry = conn.get_entry(dn, ['userCertificate', 'description'])
    except Exception as e:
        logger.warning("Cannot read local LDAP entry %s: %s", dn, e)
        return new_cert

    new_der = new_cert.public_bytes(x509.Encoding.DER)
    have_cert = any(
        c.public_bytes(x509.Encoding.DER) == new_der
        for c in local_entry.get('userCertificate', []))
    changed = False
    if not have_cert:
        local_entry.setdefault('userCertificate', []).append(new_cert)
        changed = True

    try:
        current_desc = local_entry.single_value.get('description', '')
    except ValueError:
        current_desc = None
    if current_desc != expected_desc:
        local_entry['description'] = expected_desc
        changed = True

    if changed:
        try:
            conn.update_entry(local_entry)
            logger.debug("Updated local %s LDAP entry %s", context, dn)
        except Exception as e:
            logger.warning("Failed to update local LDAP entry %s: %s", dn, e)

    return new_cert


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
