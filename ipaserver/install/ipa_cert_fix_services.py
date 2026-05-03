#
# Copyright (C) 2026  FreeIPA Contributors see COPYING for license
#

"""
Service classes and utility functions for ipa-cert-fix.

Currently provides :class:`CertmongerClient` (the certmonger D-Bus adapter)
and a couple of small helpers shared by the main module.  This module will
grow as additional scenarios (CA-full replica recovery, external cert
handling, deployment detection) are added in subsequent commits.
"""

import base64
from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
import logging
import socket
import time

from ipalib import api, errors
from ipalib import x509
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython.certdb import NSSDatabase
from ipapython.dn import DN
from ipapython.ipaldap import realm_to_serverid
from ipapython import ipautil
from ipaserver.install import cainstance, dsinstance
from ipaserver.install.certs import is_ipa_issued_cert
from ipaserver.masters import find_providing_servers

from ipaserver.install.ipa_cert_fix_types import (
    CERT_EXPIRY_LOOKAHEAD,
    DBUS_RETRY_DELAY,
    DBUS_RETRY_TIMEOUT,
    DOGTAG_CERTS,
    DeploymentType,
    FixScenario,
    IPACertType,
    _utcnow,
)

logger = logging.getLogger(__name__)


def _get_pki_nssdb():
    """Lazy accessor for the PKI Tomcat NSS database."""
    return NSSDatabase(nssdir=paths.PKI_TOMCAT_ALIAS_DIR)


def print_cert_info(context, desc, cert):
    print("{} {} certificate:".format(context, desc))
    print("  Subject: {}".format(DN(cert.subject)))
    print("  Serial:  {}".format(cert.serial_number))
    print("  Expires: {}".format(cert.not_valid_after_utc))
    print()


def get_csr_from_certmonger(nickname):
    """
    Get the csr for the provided nickname by asking certmonger.

    :returns: base64-encoded DER as a single ASCII line (no PEM headers,
        no internal newlines), suitable for writing into pkispawn-style
        config directives.  Callers that want PEM must wrap it themselves.
        ``None`` if no tracking request is found or the value cannot be
        parsed as a CSR.
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


class CertmongerClient:
    """Adapter for certmonger operations.

    Provides a mockable boundary for unit tests and centralizes D-Bus retry
    logic for operations that may fail transiently when certmonger is busy
    or restarting.
    """

    def __init__(self, dbus_timeout=DBUS_RETRY_TIMEOUT):
        self._timeout = dbus_timeout

    def get_request_id(self, criteria):
        return certmonger.get_request_id(criteria)

    def get_request_value(self, request_id, key):
        return certmonger.get_request_value(request_id, key)

    def resubmit_request(self, request_id, ca=None, profile=None):
        certmonger.resubmit_request(request_id, ca=ca, profile=profile)

    def wait_for_request(self, request_id, timeout):
        return certmonger.wait_for_request(request_id, timeout=timeout)

    def modify_ca_helper(self, ca_name, helper):
        certmonger.modify_ca_helper(ca_name, helper)

    def get_ca_helper(self, ca_name):
        """Read the current CA helper via D-Bus with retry.

        Certmonger's D-Bus may be unresponsive after restarts.
        Retries until timeout.

        :param ca_name: CA nickname (e.g. ``'IPA'``)
        :returns: current external-helper string
        """
        import dbus
        deadline = time.monotonic() + self._timeout
        delay = DBUS_RETRY_DELAY
        while True:
            try:
                bus = dbus.SystemBus()
                obj = bus.get_object(
                    'org.fedorahosted.certmonger',
                    '/org/fedorahosted/certmonger',)
                iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
                ca_path = iface.find_ca_by_nickname(ca_name)
                if not ca_path:
                    raise RuntimeError(
                        "%s CA is not configured in certmonger"
                        % ca_name)
                ca_obj = bus.get_object('org.fedorahosted.certmonger', ca_path)
                ca_props = dbus.Interface(
                    ca_obj,
                    'org.freedesktop.DBus.Properties',)
                return str(ca_props.Get(
                    'org.fedorahosted.certmonger.ca',
                    'external-helper',
                ))
            except dbus.exceptions.DBusException as e:
                if time.monotonic() >= deadline:
                    raise
                logger.debug(
                    "certmonger D-Bus not ready (%s), retrying in %ds",
                    e, delay, )
                time.sleep(delay)

    def set_ca_override(self, ca_name, master_server):
        """Override a CA helper to point at a specific server.

        Reads the current helper, strips any prior ``-J`` override,
        and appends ``-J https://<master>/ipa/json``.

        :param ca_name: CA nickname (e.g. ``'IPA'``)
        :param master_server: FQDN of the master
        :returns: the base helper string (for restore)
        """
        old_helper = self.get_ca_helper(ca_name)
        base = old_helper.split(' -J ', maxsplit=1)[0].strip()
        url = 'https://%s/ipa/json' % master_server
        self.modify_ca_helper(ca_name, '%s -J %s' % (base, url))
        return base

    def restore_ca_override(self, ca_name, base_helper):
        """Restore a CA helper to its base value."""
        self.modify_ca_helper(ca_name, base_helper)

    def add_principal(self, request_id, principal):
        certmonger.add_principal(request_id, principal)

    def add_subject(self, request_id, subject):
        certmonger.add_subject(request_id, subject)

    def add_request_value(self, request_id, key, value):
        certmonger.add_request_value(request_id, key, value)

    def start_tracking(self, **params):
        return certmonger.start_tracking(**params)

    def stop_tracking(self, request_id):
        certmonger.stop_tracking(request_id=request_id)

    def modify(self, request_id, ca=None, profile=None):
        certmonger.modify(request_id, ca=ca, profile=profile)

    def get_requests_for_dir(self, directory):
        return certmonger.get_requests_for_dir(directory)

    def is_responsive(self, timeout=None):
        """Check if certmonger responds on D-Bus.

        Uses ``getcert list-cas`` as a lightweight probe.
        Polls until responsive or timeout.

        :param timeout: max seconds to wait (default: ``self._timeout``)
        :returns: ``True`` if responsive, ``False`` on timeout
        """
        if timeout is None:
            timeout = self._timeout
        deadline = time.monotonic() + timeout
        delay = DBUS_RETRY_DELAY
        while True:
            try:
                ipautil.run(
                    ['getcert', 'list-cas'],
                    capture_output=True)
                return True
            except Exception as e:
                if time.monotonic() >= deadline:
                    logger.error(
                        "certmonger not responsive after %ds: %s", timeout, e)
                    return False
                logger.debug(
                    "certmonger not ready yet (%s), retrying in %ds", e, delay)
                time.sleep(delay)

    def is_cert_valid(self, request_id):
        """Check if the cert tracked by a request is valid.

        Reads the cert file or NSS database referenced by the certmonger
        tracking request and checks expiry against the standard 2-week
        lookahead.

        :param request_id: certmonger request ID
        :returns: ``True`` if valid, ``False`` if expired/unreadable
        """
        threshold = (_utcnow() + CERT_EXPIRY_LOOKAHEAD)
        cert_file = self.get_request_value(request_id, 'cert-file')
        if cert_file:
            try:
                cert = x509.load_certificate_from_file(cert_file)
                return cert.not_valid_after_utc > threshold
            except Exception:
                return False
        cert_db = self.get_request_value(request_id, 'cert-database')
        cert_nick = self.get_request_value(request_id, 'cert-nickname')
        if cert_db and cert_nick:
            try:
                db = NSSDatabase(nssdir=cert_db)
                cert = db.get_cert(cert_nick)
                return cert.not_valid_after_utc > threshold
            except Exception:
                return False
        return False


def _ensure_ldap_connected():
    """Ensure the ldap2 backend is connected.

    After operations that restart Directory Server (``ipa-certupdate``,
    ``ipactl restart``, ``pki-server cert-fix``), the LDAPI socket is
    recycled and our existing connection becomes a broken pipe.
    ``isconnected()`` is unreliable in this case -- it may still
    return ``True`` on the stale socket.

    This function unconditionally disconnects and reconnects to guarantee
    a live connection.
    """
    try:
        if api.Backend.ldap2.isconnected():
            api.Backend.ldap2.disconnect()
    except Exception as e:
        logger.debug("ldap2 disconnect error (ignored): %s", e)
    api.Backend.ldap2.connect()
    logger.debug("ldap2 reconnected")


def _check_tcp_reachable(server):
    """Verify a server is TCP-reachable before using it.

    Performs DNS resolution and a TCP connect to port 443.  This is
    intentionally TCP-only (no TLS): the local CA trust store may be stale at
    this point.  TLS verification happens later in ``_check_tls_handshake``
    after ``ipa-certupdate`` updates the trust store.

    :param server: FQDN to check
    :raises RuntimeError: if the server is unreachable
    """
    logger.debug("Checking reachability of %s", server)
    try:
        addrs = socket.getaddrinfo(
            server, 443, socket.AF_UNSPEC,
            socket.SOCK_STREAM,)
    except socket.gaierror as e:
        raise RuntimeError("Cannot resolve %s: %s" % (server, e))

    for family, socktype, proto, _cn, addr in addrs:
        s = socket.socket(family, socktype, proto)
        try:
            s.settimeout(10)
            s.connect(addr)
            logger.debug("TCP connect to %s:%d succeeded", server, 443)
            return
        except OSError:
            continue
        finally:
            s.close()

    raise RuntimeError(
        "Cannot connect to %s on port 443. Verify the server is running "
        "and network connectivity is available." % server)


def _find_current_renewal_master():
    """Find the current renewal master FQDN.

    :returns: FQDN string, or ``None`` if not found
    """
    try:
        base_dn = DN(api.env.container_masters, api.env.basedn)
        ldap_filter = ('(&(cn=CA)(ipaConfigString=caRenewalMaster))')
        entries = api.Backend.ldap2.get_entries(
            base_dn=base_dn,
            filter=ldap_filter,
            attrs_list=[],)
        if entries:
            fqdn = entries[0].dn[1].value
            logger.debug("Current renewal master: %s", fqdn)
            return fqdn
    except Exception as e:
        logger.debug("Cannot determine current renewal master: %s", e)
    return None


def expired_dogtag_certs(now):
    """Determine which Dogtag certs are expired or close to expiry.

    Return a list of (cert_id, cert) pairs.
    """
    certs = []
    db = _get_pki_nssdb()

    for certid, ci in DOGTAG_CERTS.items():
        try:
            cert = db.get_cert(ci.nickname)
        except RuntimeError:
            logger.debug("Dogtag cert %s (%s): not found in NSSDB",
                         certid, ci.nickname)
        else:
            if cert.not_valid_after_utc <= now:
                logger.debug("Dogtag cert %s: EXPIRED (expires %s)",
                             certid, cert.not_valid_after_utc)
                certs.append((certid, cert))
            else:
                logger.debug("Dogtag cert %s: valid (expires %s)",
                             certid, cert.not_valid_after_utc)

    return certs


def _check_ipa_cert(certtype, cert, now, certs, non_renewed):
    """Classify an expired IPA cert as IPA-issued or external.

    :param certtype: :class:`IPACertType`
    :param cert: loaded certificate
    :param now: expiry threshold
    :param certs: list to append IPA-issued certs to
    :param non_renewed: list to append external certs to
    """
    if cert.not_valid_after_utc <= now:
        if not is_ipa_issued_cert(api, cert):
            logger.debug("IPA cert %s: EXPIRED, external (expires %s)",
                         certtype.value, cert.not_valid_after_utc)
            non_renewed.append((certtype, cert))
        else:
            logger.debug("IPA cert %s: EXPIRED (expires %s)",
                         certtype.value, cert.not_valid_after_utc)
            certs.append((certtype, cert))
    else:
        logger.debug("IPA cert %s: valid (expires %s)",
                     certtype.value, cert.not_valid_after_utc)


def expired_ipa_certs(now, ds_dbdir=None, ds_nickname=None):
    """Determine which IPA certs are expired or close to expiry.

    :param now: datetime threshold
    :param ds_dbdir: DS NSS database directory (optional, avoids creating a
        DsInstance if provided)
    :param ds_nickname: DS server cert nickname (optional)
    :returns: tuple of ``(certs, non_renewed)``
    """
    certs = []
    non_renewed = []

    # IPA RA (always IPA-issued, no external check)
    try:
        cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
        if cert.not_valid_after_utc <= now:
            logger.debug("IPA cert RA: EXPIRED (expires %s)",
                         cert.not_valid_after_utc)
            certs.append((IPACertType.IPARA, cert))
        else:
            logger.debug("IPA cert RA: valid (expires %s)",
                         cert.not_valid_after_utc)
    except FileNotFoundError:
        logger.debug("IPA cert RA: not present at %s "
                     "(expected on CA-less-external deployments)",
                     paths.RA_AGENT_PEM)
    except Exception as e:
        logger.debug("Cannot load RA cert from %s: %s",
                     paths.RA_AGENT_PEM, e)

    # Apache HTTPD
    try:
        cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
        _check_ipa_cert(IPACertType.HTTPS, cert, now, certs, non_renewed)
    except Exception as e:
        logger.debug("Cannot load HTTP cert from %s: %s",
                     paths.HTTPD_CERT_FILE, e)

    # LDAPS
    try:
        if ds_dbdir is None or ds_nickname is None:
            serverid = realm_to_serverid(api.env.realm)
            ds = dsinstance.DsInstance(realm_name=api.env.realm)
            ds_dbdir = dsinstance.config_dirname(serverid)
            ds_nickname = ds.get_server_cert_nickname(serverid)
        db = NSSDatabase(nssdir=ds_dbdir)
        cert = db.get_cert(ds_nickname)
        _check_ipa_cert(IPACertType.LDAPS, cert, now, certs, non_renewed)
    except Exception as e:
        logger.debug("Cannot load LDAP cert: %s", e)

    # KDC (can be self-signed if PKINIT is disabled)
    try:
        cert = x509.load_certificate_from_file(paths.KDC_CERT)
        _check_ipa_cert(IPACertType.KDC, cert, now, certs, non_renewed)
    except Exception as e:
        logger.debug("Cannot load KDC cert from %s: %s", paths.KDC_CERT, e)

    return certs, non_renewed


class DeploymentDetector:
    """Detection, classification, and scenario routing.

    Determines the deployment type, classifies expired certificates, and
    routes to the appropriate fix scenario.  CA chain validation and
    RA/subsystem LDAP consistency checks are added in a later commit.
    """

    def __init__(self, cm_client, ca_instance, options):
        self._cm = cm_client
        self._ca_instance = ca_instance
        self.options = options

    def detect_deployment_type(self):
        """Detect the deployment type of this replica.

        Checks whether a CA is installed locally and whether the CA signing
        certificate is self-signed or externally signed.

        :returns: :class:`DeploymentType` enum value
        """
        has_ca = cainstance.is_ca_installed_locally()

        if not has_ca:
            ca_servers = []
            ldap_failed = False
            try:
                _ensure_ldap_connected()
                ca_servers = find_providing_servers(
                    'CA', conn=api.Backend.ldap2,
                    api=api,)
            except Exception as e:
                logger.warning("Failed to discover CA servers: %s", e)
                ldap_failed = True

            if not ca_servers:
                if ldap_failed:
                    # LDAP query failed -- don't assume fully external. Warn
                    # and default to CA_LESS so the user is prompted for a
                    # server FQDN.
                    print(
                        "WARNING: Could not query topology for CA servers "
                        "(LDAP error).\n"
                        "Assuming CA servers exist. Use --force-server "
                        "to specify one explicitly.")
                    return DeploymentType.CA_LESS

                logger.info(
                    "No CA servers in topology, deployment is fully external."
                )
                return DeploymentType.CA_LESS_EXTERNAL
            logger.info(
                "CA-less replica, CA servers in topology: %s",
                ca_servers)
            return DeploymentType.CA_LESS

        # CA is installed locally -- check if self-signed
        db = _get_pki_nssdb()
        try:
            ca_cert = db.get_cert(DOGTAG_CERTS['ca_issuing'].nickname)
        except RuntimeError:
            logger.error(
                "Cannot read caSigningCert from %s",
                paths.PKI_TOMCAT_ALIAS_DIR)
            raise RuntimeError(
                "Cannot read caSigningCert from NSS database "
                "at %s" % paths.PKI_TOMCAT_ALIAS_DIR)

        is_self_signed = (DN(ca_cert.issuer) == DN(ca_cert.subject))
        logger.debug(
            "caSigningCert: issuer=%s, subject=%s, self_signed=%s",
            DN(ca_cert.issuer), DN(ca_cert.subject), is_self_signed)

        if is_self_signed:
            return DeploymentType.CA_SELF_SIGNED
        return DeploymentType.CA_EXTERNALLY_SIGNED

    @staticmethod
    def _classify_certs(now, ds_dbdir=None, ds_nickname=None):
        """Classify expired certificates into categories.

        Wraps :func:`expired_dogtag_certs` and :func:`expired_ipa_certs`,
        then re-classifies certs that are not IPA-issued as external.

        For CA-less deployments, Dogtag certs are skipped (the NSS database
        does not exist).

        :param now: datetime threshold for expiry check
        :param ds_dbdir: DS NSS database directory
        :param ds_nickname: DS server cert nickname
        :returns: tuple of ``(dogtag_certs, ipa_certs, external_certs)``
        """
        has_ca = cainstance.is_ca_installed_locally()
        if has_ca:
            dogtag = expired_dogtag_certs(now)
        else:
            dogtag = []

        ipa, non_renewed = expired_ipa_certs(now, ds_dbdir, ds_nickname)

        # non_renewed from expired_ipa_certs() contains certs where
        # is_ipa_issued_cert() returned False, i.e. they are externally signed.
        external = non_renewed

        return dogtag, ipa, external

    def determine_scenario(self, deployment_type):
        """Determine the fix scenario and master server.

        Uses the deployment type, renewal master status, and CLI options to
        choose the correct fix path.  May prompt the user interactively for
        a master server FQDN.

        :param deployment_type: :class:`DeploymentType` value
        :returns: tuple of ``(FixScenario, master_server_or_None)``
        """
        opt_renewal_master = getattr(self.options, 'renewal_master', False)
        opt_force_server = getattr(self.options, 'force_server', None)

        # CA-less paths
        if deployment_type in (
            DeploymentType.CA_LESS,
            DeploymentType.CA_LESS_EXTERNAL,
        ):
            if opt_renewal_master:
                raise RuntimeError(
                    "--renewal-master cannot be used on a CA-less replica "
                    "(no local CA to become renewal master of).")
            if deployment_type == DeploymentType.CA_LESS_EXTERNAL:
                return FixScenario.EXTERNAL_CERTS, None
            master = self.get_master_server()
            if master is None:
                raise RuntimeError(
                    "No server was selected. Re-run with "
                    "--force-server=<FQDN> to renew certificates "
                    "from a working CA server.")
            return FixScenario.CA_LESS_WITH_MASTER, master

        # CA-full paths
        is_rm = self.check_is_renewal_master()
        if opt_renewal_master or is_rm:
            if opt_force_server and is_rm:
                print(
                    "WARNING: --force-server ignored -- this server is the "
                    "renewal master and will use the renewal master fix path.")
            return FixScenario.RENEWAL_MASTER, None

        master = self.get_master_server()
        if master is not None:
            return FixScenario.CA_FULL_WITH_MASTER, master

        # No master available -- promotion is the only option. Prerequisites
        # are validated in run_ca_full_promote() before any destructive action
        # (promotion is a topology-wide change).
        return FixScenario.CA_FULL_PROMOTE, None

    def check_is_renewal_master(self):
        """Check if the current server is the renewal master.

        Uses LDAP via LDAPI (unix socket) which works even when TLS
        certificates are expired.

        :returns: ``True`` if this server is the renewal master,
            ``False`` otherwise
        :raises RuntimeError: if no CA instance is available (CA-less)
        """
        if self._ca_instance is None:
            raise RuntimeError(
                "check_is_renewal_master called without a CA instance "
                "(CA-less deployment?)")
        try:
            result = self._ca_instance.is_renewal_master()
            logger.debug("Renewal master check result: %s", result)
            return result
        except (errors.NetworkError, errors.DatabaseError) as e:
            logger.warning("Failed to determine renewal master status: %s", e)
            return False
        except Exception as e:
            logger.warning("Unexpected error checking renewal master: %s", e)
            return False

    def get_master_server(self):
        """Determine the master server FQDN.

        Resolution order:

        1. ``--force-server`` CLI option
        2. Interactive prompt (default from LDAP if any)
        3. ``None`` if no server selected (caller decides whether to fall
           back to promote or external path)

        :returns: FQDN string, or ``None``
        """
        opt_force_server = getattr(self.options, 'force_server', None)
        opt_unattended = getattr(self.options, 'unattended', False)

        if opt_force_server:
            server = opt_force_server
            _check_tcp_reachable(server)
            logger.info("Using server from --force-server: %s", server)
            return server

        # Find the current renewal master to use as default
        default_server = None
        ca_servers = []
        renewal_master = _find_current_renewal_master()
        if renewal_master and renewal_master != api.env.host:
            default_server = renewal_master
        elif renewal_master:
            logger.debug("Renewal master is this server, not using as default")

        # Find other CA servers in the topology (excluding ourselves)
        if not default_server:
            try:
                ca_servers = find_providing_servers(
                    'CA', conn=api.Backend.ldap2, api=api)
                ca_servers = [s for s in ca_servers if s != api.env.host]
                logger.debug("CA servers in topology: %s", ca_servers)
            except Exception as e:
                logger.warning("Failed to discover CA servers: %s", e)
                ca_servers = []

            if ca_servers:
                print("The following CA servers were found in the topology:")
                for s in ca_servers:
                    print("  %s" % s)
                print()

        if not default_server and ca_servers:
            default_server = ca_servers[0]

        # In unattended mode, use the default server if found, otherwise fall
        # back to the destructive path.
        if opt_unattended:
            if default_server:
                logger.info("Unattended mode: using server %s", default_server)
                return default_server
            logger.warning("Unattended mode: no working server found")
            return None

        while True:
            if default_server:
                prompt = ("Enter FQDN of a working CA server with valid "
                          "certificates\n(press Enter to use %s, or type "
                          "a different FQDN)" % default_server)
            else:
                prompt = ("Enter FQDN of a working CA server with valid "
                          "certificates\n(leave empty to skip; re-run with "
                          "--renewal-master to promote this server)")
            server = ipautil.user_input(prompt, default=default_server)

            if server:
                if server == api.env.host:
                    print(
                        "Cannot use the current server (%s) as the source."
                        % server)
                    print("Please enter a different server.")
                    continue
                try:
                    _check_tcp_reachable(server)
                except RuntimeError as e:
                    print("  %s" % e)
                    print("Please enter a different server.")
                    continue
                logger.debug("User selected master server: %s", server)
                return server

            # User chose empty -- fall back
            break

        # No server selected -- caller decides whether to fall back to the
        # promote/external path.
        logger.info("No master server selected")
        return None
