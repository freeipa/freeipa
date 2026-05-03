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
from contextlib import contextmanager
from cryptography import x509 as crypto_x509
from cryptography.hazmat.backends import default_backend
import logging
import os
import re
import socket
import time

from ipalib import api, errors
from ipalib.constants import IPA_CA_RECORD
from ipalib import x509
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython.certdb import NSSDatabase, EMPTY_TRUST_FLAGS
from ipapython.dn import DN
from ipapython.dogtag import KDC_PROFILE
from ipapython.ipaldap import realm_to_serverid
from ipapython import directivesetter
from ipapython import ipautil
from ipaserver.install import cainstance, dsinstance
from ipaserver.install.certs import is_ipa_issued_cert
from ipaserver.masters import find_providing_servers

from ipaserver.install.ipa_cert_fix_types import (
    CERT_EXPIRY_LOOKAHEAD,
    CERTMONGER_WAIT_TIMEOUT,
    DBUS_RETRY_DELAY,
    DBUS_RETRY_TIMEOUT,
    DOGTAG_CERTS,
    DeploymentType,
    FixScenario,
    HELPER_KILL_SETTLE,
    IPACertType,
    IPA_SERVICE_PROFILE,
    _CS_CFG_CERT_DIRECTIVES,
    _utcnow,
)

logger = logging.getLogger(__name__)


def _get_pki_nssdb():
    """Lazy accessor for the PKI Tomcat NSS database."""
    return NSSDatabase(nssdir=paths.PKI_TOMCAT_ALIAS_DIR)


def _replace_cert_in_nssdb(db, nickname, cert, trust_flags=EMPTY_TRUST_FLAGS):
    """Replace a certificate in an NSS database.

    Deletes the old cert (ignoring "not found") and adds the new
    one.  This is the standard pattern for updating a cert in
    NSSDB without losing the private key.

    :param db: :class:`NSSDatabase` instance
    :param nickname: certificate nickname
    :param cert: new certificate to install
    :param trust_flags: trust flags for the new cert
    """
    try:
        db.delete_cert(nickname)
    except ipautil.CalledProcessError:
        logger.debug(
            "Cert '%s' not found in NSS database, nothing to delete", nickname)
    db.add_cert(cert, nickname, trust_flags)


def _update_cs_cfg(nickname, cert):
    """Update the certificate blob in the Dogtag CS.cfg file.

    When a certificate is installed directly into the NSSDB (bypassing
    certmonger's post-save commands), the base64 cert blob in CS.cfg
    must be updated manually.  Otherwise Dogtag will have a stale
    certificate in its configuration.

    Also updates ``ca.connector.KRA.transportCert`` in the CA config
    when the KRA transport cert is renewed (used by CA to encrypt
    key archival requests to KRA).

    :param nickname: NSSDB certificate nickname
    :param cert: the new certificate (IPACertificate)
    """
    if nickname not in _CS_CFG_CERT_DIRECTIVES:
        return

    directive, cfg_path = _CS_CFG_CERT_DIRECTIVES[nickname]
    if not os.path.exists(cfg_path):
        logger.debug("CS.cfg not found at %s, skipping update", cfg_path)
        return

    cert_b64 = base64.b64encode(cert.public_bytes(x509.Encoding.DER))\
        .decode('ascii')
    logger.debug("Updating CS.cfg directive %s in %s", directive, cfg_path)
    directivesetter.set_directive(
        cfg_path, directive, cert_b64,
        quotes=False, separator='=')

    # KRA transport cert is also referenced in the CA config as
    # ca.connector.KRA.transportCert
    if nickname == 'transportCert cert-pki-kra':
        if os.path.exists(paths.CA_CS_CFG_PATH):
            logger.debug(
                "Updating ca.connector.KRA.transportCert in %s",
                paths.CA_CS_CFG_PATH)
            directivesetter.set_directive(
                paths.CA_CS_CFG_PATH,
                'ca.connector.KRA.transportCert', cert_b64,
                quotes=False, separator='=')


def _kill_stuck_helpers():
    """Kill running ipa-submit and ipa-server-guard processes.

    Certmonger processes D-Bus requests serially.  If ``ipa-submit`` is
    running (trying to contact httpd with expired certs), any D-Bus write
    (like ``modify_ca_helper``) blocks until the helper times out --
    which can take minutes.

    Killing the helpers makes certmonger's D-Bus responsive immediately.
    Certmonger will re-queue the requests and attempt them again later.
    """
    for proc_name in ('ipa-submit', 'ipa-server-guard'):
        try:
            result = ipautil.run(
                ['pkill', '-f', proc_name],
                raiseonerr=False, capture_output=True)
            if result.returncode == 0:
                logger.debug("Killed %s processes", proc_name)
        except Exception as e:
            logger.debug("pkill %s failed: %s", proc_name, e)
    time.sleep(HELPER_KILL_SETTLE)


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


class ExternalCertHandler:
    """Handle expired externally-signed service certificates.

    Offers per-cert transition to the internal IPA CA (interactive) or
    generates CSRs for manual renewal with the external CA.

    Extracted from IPACertFix so the logic can be tested and reused
    independently of the AdminTool lifecycle.
    """

    DEFAULT_CSR_DIR = '/run/ipa/cert-fix'

    def __init__(self, cm_client, unattended=False, csr_dir=None):
        self._cm = cm_client
        self._unattended = unattended
        self._csr_dir = csr_dir or self.DEFAULT_CSR_DIR

    def handle(self, ctx):
        """Dispatch external cert handling.

        If an internal CA exists in the topology, offers per-cert transition
        to the IPA CA via :meth:`offer_transition`.  For remaining certs (or
        if no CA exists), generates CSRs and prints manual installation
        instructions via :meth:`generate_csrs`.

        On ``CA_LESS_EXTERNAL`` deployments (no internal CA anywhere),
        transitions are not possible -- only CSR generation is performed.

        :param ctx: :class:`CertFixContext`
        :returns: ``True`` if any certs were handled (transitioned or CSRs
            generated), ``False`` if all failed
        """
        if not ctx.external_certs:
            return True

        remaining = list(ctx.external_certs)
        handled = False

        if ctx.deployment_type != DeploymentType.CA_LESS_EXTERNAL:
            try:
                ca_servers = find_providing_servers(
                    'CA', conn=api.Backend.ldap2, api=api)
            except Exception as e:
                logger.warning("Failed to discover CA servers: %s", e)
                ca_servers = []

            # find_providing_servers returns all CA replicas including this
            # host; filter so the helper override never points at self.
            other_cas = [s for s in ca_servers if s != api.env.host]
            master = ctx.master_server or (
                other_cas[0] if other_cas else None)

            if master is not None:
                transitioned = (
                    self.offer_transition(ctx.external_certs, master, ctx))
                if transitioned:
                    handled = True
                remaining = [
                    (t, c) for t, c in ctx.external_certs
                    if t not in transitioned
                ]

        if remaining:
            if self.generate_csrs(remaining, ctx):
                handled = True

        return handled

    def offer_transition(self, external_certs, master, ctx):
        """Offer to transition external certs to the internal CA.

        Externally-signed certificates typically have no certmonger tracking
        request (tracking is stopped when a cert is installed externally).
        To transition, we stop any existing tracking, create a new tracking
        request with the correct IPA parameters, optionally override the IPA
        CA helper to point at *master*, and wait for renewal.

        In unattended mode, no transitions are offered.
        """
        if self._unattended:
            logger.info(
                "Unattended mode: skipping external cert transition offers")
            return set()

        transitioned = set()

        for certtype, cert in external_certs:
            print(
                "Certificate %s is signed by an external CA (issuer: %s)."
                % (certtype.value, DN(cert.issuer)))
            response = ipautil.user_input(
                "Transition to internal IPA CA?",
                default=False,)
            if not response:
                continue

            try:
                self._transition_cert(certtype, cert, master, ctx)
                transitioned.add(certtype)
            except Exception as e:
                logger.error("Failed to transition %s: %s", certtype.value, e)
                print("ERROR: Failed to transition %s: %s"
                      % (certtype.value, e))

        return transitioned

    def _transition_cert(self, certtype, cert, master, ctx):
        """Transition a single cert to the internal IPA CA."""
        params = self._tracking_params(certtype, ctx)
        if params is None:
            raise RuntimeError(
                "No tracking parameters for %s" % certtype.value)

        criteria = self._cert_criteria(certtype, ctx)
        if criteria:
            old_id = self._cm.get_request_id(criteria)
            if old_id is not None:
                logger.debug(
                    "Stopping existing tracking %s for %s",
                    old_id, certtype.value,)
                self._cm.stop_tracking(request_id=old_id)

        print("  Creating IPA tracking request for %s..." % certtype.value)
        logger.debug("Tracking params for %s: %s", certtype.value, params)

        if master:
            if not self._cm.is_responsive():
                raise RuntimeError(
                    "certmonger did not become responsive; "
                    "cannot create tracking request for %s"
                    % certtype.value)
            with self._override_ca_helper(master):
                request_id = self._create_tracking(certtype, params)
                state = self._cm.wait_for_request(
                    request_id,
                    timeout=CERTMONGER_WAIT_TIMEOUT)
        else:
            request_id = self._create_tracking(certtype, params)
            state = self._cm.wait_for_request(
                request_id,
                timeout=CERTMONGER_WAIT_TIMEOUT)

        if state == 'MONITORING':
            print("  %s transitioned successfully." % certtype.value)
        else:
            ca_error = self._cm.get_request_value(request_id, 'ca-error')
            raise RuntimeError(
                "%s transition failed: state=%s, error=%s"
                % (certtype.value, state, ca_error))

    def _create_tracking(self, certtype, params):
        """Create a certmonger tracking request."""
        request_id = self._cm.start_tracking(
            certpath=params['certpath'],
            ca=params['ca'],
            storage=params['storage'],
            profile=params['profile'],
            post_command=params.get('post_command'),
            pinfile=params.get('pinfile'),
            nickname=params.get('nickname'),
            dns=params.get('dns'),
            perms=params.get('perms'),
            token_name=params.get('token'),)
        logger.debug(
            "Created tracking request %s for %s",
            request_id, certtype.value,)
        if params.get('principal'):
            self._cm.add_principal(request_id, params['principal'])
        if params.get('subject'):
            self._cm.add_subject(request_id, params['subject'])
        return request_id

    @staticmethod
    def _tracking_params(certtype, ctx):
        """Return certmonger tracking parameters for a cert.

        These mirror the parameters used during IPA server installation.
        """
        subject = str(DN(('CN', api.env.host), ctx.subject_base))

        if certtype is IPACertType.HTTPS:
            passwd_file = (
                paths.HTTPD_PASSWD_FILE_FMT.format(host=api.env.host))
            return {
                'certpath': (paths.HTTPD_CERT_FILE, paths.HTTPD_KEY_FILE),
                'ca': 'IPA',
                'storage': 'FILE',
                'profile': IPA_SERVICE_PROFILE,
                'post_command': 'restart_httpd',
                'pinfile': passwd_file,
                'dns': [
                    api.env.host,
                    '%s.%s' % (IPA_CA_RECORD,
                               api.env.domain),
                ],
                'principal': 'HTTP/%s@%s' % (api.env.host, api.env.realm),
                'subject': subject,
            }

        if certtype is IPACertType.LDAPS:
            return {
                'certpath': ctx.ds_dbdir,
                'ca': 'IPA',
                'storage': 'NSSDB',
                'profile': IPA_SERVICE_PROFILE,
                'post_command': ('restart_dirsrv %s'
                                 % ctx.serverid),
                'pinfile': os.path.join(ctx.ds_dbdir, 'pwdfile.txt'),
                'nickname': ctx.ds_nickname,
                'principal': 'ldap/%s@%s' % (api.env.host, api.env.realm),
                'subject': subject,
            }

        if certtype is IPACertType.KDC:
            return {
                'certpath': (paths.KDC_CERT, paths.KDC_KEY),
                'ca': 'IPA',
                'storage': 'FILE',
                'profile': KDC_PROFILE,
                'post_command': 'renew_kdc_cert',
                'dns': [api.env.host],
                'perms': (0o644, 0o600),
                'principal': 'krbtgt/%s@%s' % (api.env.realm, api.env.realm),
                'subject': subject,
            }

        # IPARA is handled separately (fetched from master LDAP, not via
        # certmonger tracking).
        return None

    def generate_csrs(self, external_certs, ctx):
        """Generate CSR files for externally-signed certificates.

        For each expired external cert, tries three sources for a CSR:

        1. Extract existing CSR from certmonger tracking
        2. Generate a new CSR from the existing private key and the expired
           cert's subject/SANs
        3. Fall back to manual instructions
        """
        csr_dir = self._csr_dir
        os.makedirs(csr_dir, mode=0o700, exist_ok=True)

        csr_paths = {}

        for certtype, cert in external_certs:
            csr_path = os.path.join(
                csr_dir, '%s.csr'
                % certtype.value.lower().replace(' ', '-'))

            csr_pem = self._get_csr_from_tracking(certtype, ctx)

            if csr_pem is None:
                csr_pem = self._generate_csr_from_key(certtype, cert, ctx)

            if csr_pem is None:
                logger.warning("Cannot generate CSR for %s", certtype.value)
                continue

            try:
                fd = os.open(
                    csr_path,
                    os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                    0o600)
                with os.fdopen(fd, 'w') as f:
                    f.write(csr_pem)
                csr_paths[certtype] = csr_path
                logger.debug(
                    "Wrote CSR for %s to %s",
                    certtype.value, csr_path,)
            except IOError as e:
                logger.error(
                    "Failed to write CSR for %s: %s",
                    certtype.value, e,)

        install_cmds = {
            IPACertType.HTTPS: (
                "ipa-server-certinstall --http /path/to/renewed.crt"),
            IPACertType.LDAPS: (
                "ipa-server-certinstall --dirsrv /path/to/renewed.crt"),
            IPACertType.KDC: (
                "ipa-server-certinstall --kdc /path/to/renewed.crt"),
        }

        if csr_paths:
            print()
            print("CSR files have been generated for external renewal:")
            print()
            for certtype, path in csr_paths.items():
                print("  %s:" % certtype.value)
                print("    CSR: %s" % path)
                cmd = install_cmds.get(certtype)
                if cmd:
                    print("    Install: %s" % cmd)
            print()
            print(
                "Submit these CSRs to your external CA, "
                "then install the renewed certificates "
                "using the commands above.")
            print()
            return True
        else:
            print(
                "Could not generate CSRs for the "
                "externally-signed certificates.")
            print(
                "Generate CSRs manually from your existing "
                "keys and submit them to your external CA, "
                "then install using ipa-server-certinstall.")
            print()
            return False

    def _get_csr_from_tracking(self, certtype, ctx):
        """Try to extract a CSR from certmonger tracking."""
        criteria = self._cert_criteria(certtype, ctx)
        if criteria is None:
            return None
        request_id = self._cm.get_request_id(criteria)
        if request_id is None:
            logger.debug("No certmonger tracking for %s", certtype.value)
            return None
        csr = self._cm.get_request_value(request_id, 'csr')
        if not csr:
            logger.debug("No CSR in tracking for %s", certtype.value)
            return None
        logger.debug("Extracted CSR from certmonger for %s", certtype.value)
        return csr

    def _generate_csr_from_key(self, certtype, cert, ctx):
        """Generate a CSR from the existing private key.

        Uses the subject and SANs from the expired certificate to build a
        new CSR signed with the existing private key.
        """
        from cryptography.exceptions import (UnsupportedAlgorithm)
        from cryptography.hazmat.primitives import (hashes, serialization)

        params = self._tracking_params(certtype, ctx)
        if params is None:
            return None

        if params['storage'] == 'NSSDB':
            return self._generate_csr_nssdb(certtype, cert, params)

        certpath = params['certpath']
        _cert_file, key_file = certpath

        try:
            with open(key_file, 'rb') as f:
                key_pem = f.read()
        except IOError as e:
            logger.warning(
                "Cannot read key for %s from %s: %s",
                certtype.value, key_file, e,)
            return None

        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            pinfile = params.get('pinfile')
            if pinfile:
                try:
                    with open(pinfile, 'rb') as f:
                        pin = f.read().strip()
                    key = serialization.load_pem_private_key(
                        key_pem, password=pin,)
                except Exception as e:
                    logger.warning(
                        "Cannot decrypt key for %s: %s",
                        certtype.value, e,)
                    return None
            else:
                logger.warning(
                    "Key for %s is encrypted, no pin file available",
                    certtype.value,)
                return None

        builder = crypto_x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(cert.subject)

        try:
            san = cert.extensions.get_extension_for_class(
                crypto_x509.SubjectAlternativeName)
            builder = builder.add_extension(san.value, critical=san.critical)
        except crypto_x509.ExtensionNotFound:
            pass

        csr = builder.sign(key, hashes.SHA256())
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('ascii')

        logger.info(
            "Generated CSR for %s from key %s",
            certtype.value, key_file,)
        return csr_pem

    @staticmethod
    def _generate_csr_nssdb(certtype, cert, params):
        """Generate a CSR from an NSSDB private key."""
        dbdir = params['certpath']
        nickname = params.get('nickname')
        pinfile = params.get('pinfile')
        token = params.get('token')
        subject = str(DN(cert.subject))

        key_id = None
        if nickname:
            key_id = ExternalCertHandler._get_nssdb_key_id(
                dbdir, nickname, pinfile, token)

        cmd = ['certutil', '-R', '-d', dbdir, '-s', subject, '-a']
        if token:
            cmd.extend(['-h', token])
        if key_id:
            cmd.extend(['-k', key_id])
        else:
            logger.warning(
                "Cannot find key ID for %s in %s, cannot generate CSR",
                nickname, dbdir,)
            return None
        if pinfile:
            cmd.extend(['-f', pinfile])

        try:
            san = cert.extensions.get_extension_for_class(
                crypto_x509.SubjectAlternativeName)
            dns_names = san.value.get_values_for_type(crypto_x509.DNSName)
            if dns_names:
                cmd.extend(['-8', ','.join(dns_names)])
        except crypto_x509.ExtensionNotFound:
            pass

        try:
            result = ipautil.run(cmd, capture_output=True)
            csr_pem = result.output
            begin = csr_pem.find('-----BEGIN CERTIFICATE REQUEST')
            if begin >= 0:
                csr_pem = csr_pem[begin:]
            logger.info(
                "Generated CSR for %s via certutil (key=%s in %s)",
                certtype.value, nickname or 'new', dbdir,)
            return csr_pem
        except Exception as e:
            logger.warning(
                "certutil CSR generation failed for %s: %s",
                certtype.value, e)
            return None

    @staticmethod
    def _get_nssdb_key_id(dbdir, nickname, pinfile=None, token=None):
        """Extract the hex key ID for a cert from NSSDB."""
        cmd = ['certutil', '-K', '-d', dbdir]
        if token:
            cmd.extend(['-h', token])
        if pinfile:
            cmd.extend(['-f', pinfile])

        try:
            result = ipautil.run(cmd, capture_output=True)
        except Exception as e:
            logger.debug("certutil -K failed for %s: %s", nickname, e)
            return None

        # Output format: < 0> rsa <hex-key-id> <token>:<nickname>
        hex_re = re.compile(r'^[0-9a-fA-F]{16,}$')

        for line in result.output.splitlines():
            line = line.strip()
            if not line.startswith('<'):
                continue
            if nickname not in line:
                continue
            parts = line.split()
            for part in parts:
                if hex_re.match(part):
                    logger.debug("Found key ID %s for %s", part, nickname)
                    return part

        logger.debug("No key ID found for %s in %s", nickname, dbdir)
        return None

    @staticmethod
    def _cert_criteria(certtype, ctx):
        """Return certmonger search criteria for a cert type."""
        if certtype is IPACertType.HTTPS:
            return {'cert-file': paths.HTTPD_CERT_FILE}
        elif certtype is IPACertType.KDC:
            return {'cert-file': paths.KDC_CERT}
        elif certtype is IPACertType.LDAPS:
            return {
                'cert-database': ctx.ds_dbdir,
                'cert-nickname': ctx.ds_nickname,
            }
        elif certtype is IPACertType.IPARA:
            return {'cert-file': paths.RA_AGENT_PEM}
        return None

    @contextmanager
    def _override_ca_helper(self, master):
        """Temporarily override IPA CA helper to point at master."""
        base = self._cm.set_ca_override('IPA', master)
        try:
            yield
        finally:
            self._cm.restore_ca_override('IPA', base)


class CertRenewalFromMaster:
    """Renew expired certificates via certmonger pointed at a master.

    Manages the IPA CA helper override, per-request CA/profile switching, and
    cleanup.  Used by the CA-full and CA-less replica recovery scenarios.
    """

    def __init__(self, cm_client, master_server):
        self._cm = cm_client
        self._master = master_server
        self._original_principals = {}
        self._original_profiles = {}

    def _set_helper(self):
        """Point the IPA CA helper at the master server.

        :returns: the base helper string (without ``-J``)
        """
        logger.debug("Setting IPA CA helper to master: %s", self._master)
        base = self._cm.set_ca_override('IPA', self._master)
        logger.debug("IPA CA helper base: '%s'", base)
        return base

    def _restore_helper(self, old_helper, timeout=DBUS_RETRY_TIMEOUT):
        """Restore the IPA CA helper to its original value.

        Retries for *timeout* seconds if certmonger's D-Bus is temporarily
        unreachable (e.g., being restarted by a post-save command).

        :param old_helper: value returned by :meth:`_set_helper`
        :param timeout: max seconds to retry
        """
        logger.debug("Restoring IPA CA helper to: %s", old_helper)
        deadline = time.monotonic() + timeout
        delay = DBUS_RETRY_DELAY
        while True:
            try:
                self._cm.restore_ca_override('IPA', old_helper)
                return
            except Exception as e:
                if time.monotonic() >= deadline:
                    logger.error(
                        "Failed to restore IPA CA helper after %ds: %s",
                        timeout, e,)
                    print(
                        "\nCRITICAL: Failed to restore the IPA CA certmonger "
                        "helper.\n"
                        "All future certificate renewals on this host may "
                        "fail or contact the wrong server.\nRun manually:\n\n"
                        "  getcert modify-ca -c IPA -e '%s'\n" % old_helper)
                    return
                logger.debug(
                    "certmonger not ready for restore (%s), retrying in %ds",
                    e, delay,)
                time.sleep(delay)

    def _resubmit(
        self, desc, old_cert, request_id, original_ca, load_renewed,
    ):
        """Resubmit a single cert's tracking request via master.

        Handles the Dogtag-vs-IPA distinction: Dogtag certs need their CA
        switched to IPA, a host principal added, and the profile overridden
        to ``caIPAserviceCert``.

        Mutates ``self._original_principals`` and ``self._original_profiles``
        for later cleanup by :meth:`_restore`.
        """
        desc_str = getattr(desc, 'display_name',
                           getattr(desc, 'value', str(desc)))
        print("\n  Renewing %s (request %s)..." % (desc_str, request_id))

        _kill_stuck_helpers()

        if self._cm.is_cert_valid(request_id):
            print("  %s already has a valid cert, skipping." % desc_str)
            return

        print_cert_info("  Old", desc_str, old_cert)

        is_dogtag = getattr(desc, 'is_dogtag', False)
        override_profile = None

        if is_dogtag:
            host_principal = 'host/%s@%s' % (api.env.host, api.env.realm)
            orig = self._cm.get_request_value(request_id, 'template-principal')
            self._original_principals[request_id] = orig
            logger.debug(
                "Setting template-principal on request %s to %s "
                "(original: %s)", request_id, host_principal, orig)
            self._cm.add_principal(request_id, host_principal)

            original_profile = self._cm.get_request_value(
                request_id, 'template-profile')
            if original_profile and original_profile != IPA_SERVICE_PROFILE:
                override_profile = IPA_SERVICE_PROFILE
                self._original_profiles[request_id] = (original_profile)
                logger.debug(
                    "Overriding profile on request %s: %s -> %s",
                    request_id, original_profile, override_profile)

        try:
            current_ca = self._cm.get_request_value(request_id, 'ca-name')
            logger.debug("Request %s current CA: %s", request_id, current_ca)
            cas_output = ipautil.run(
                ['getcert', 'list-cas', '-c', 'IPA'],
                capture_output=True, raiseonerr=False)
            logger.debug("IPA CA helper config:\n%s", cas_output.output)
        except Exception as diag_err:
            logger.debug("Pre-resubmit diagnostics failed: %s", diag_err)

        logger.debug(
            "Resubmitting request %s via %s CA (original CA: %s, "
            "is_dogtag: %s, profile_override: %s)",
            request_id,
            'IPA' if is_dogtag else '%s (unchanged)' % original_ca,
            original_ca, is_dogtag, override_profile)
        self._cm.resubmit_request(
            request_id,
            ca='IPA' if is_dogtag else None,
            profile=override_profile,)

        try:
            state = self._cm.wait_for_request(
                request_id, timeout=CERTMONGER_WAIT_TIMEOUT)
        except RuntimeError:
            logger.error("Timeout waiting for request %s", request_id)
            raise RuntimeError(
                "Certmonger request %s for %s timed out"
                % (request_id, desc_str))

        if state != 'MONITORING':
            ca_error = self._cm.get_request_value(request_id, 'ca-error')
            raise RuntimeError(
                "Certmonger request %s for %s failed: state=%s, ca-error=%s"
                % (request_id, desc_str, state, ca_error))

        if not self._cm.is_responsive():
            raise RuntimeError(
                "certmonger did not become responsive after renewing %s"
                % desc_str)

        try:
            new_cert = load_renewed()
            logger.debug(
                "Renewed %s: serial=%s, issued=%s, expires=%s",
                desc_str, new_cert.serial_number,
                new_cert.not_valid_before_utc,
                new_cert.not_valid_after_utc)
            if new_cert.serial_number == old_cert.serial_number:
                print("  WARNING: %s serial unchanged after renewal (%s) -- "
                      "cert may not have been updated"
                      % (desc_str, new_cert.serial_number))
            else:
                print("  %s renewed successfully." % desc_str)
            print_cert_info("  New", desc_str, new_cert)
        except Exception as e:
            logger.warning("Could not read renewed cert for %s: %s",
                           desc_str, e)
            print("  %s submitted for renewal." % desc_str)

    def _restore(self, request_id, original_ca):
        """Restore a single certmonger request after renewal.

        Restores the original CA name, profile, and removes any temporary
        principal that was added for Dogtag cert renewal through the IPA CA.
        """
        try:
            current_ca = self._cm.get_request_value(request_id, 'ca-name')
            restore_profile = self._original_profiles.get(request_id)
            if current_ca != original_ca or restore_profile:
                logger.debug(
                    "Restoring request %s: CA %s -> %s, profile -> %s",
                    request_id, current_ca, original_ca, restore_profile)
                self._cm.modify(
                    request_id, ca=original_ca, profile=restore_profile,)
        except Exception as e:
            logger.warning(
                "Failed to restore CA/profile for request %s: %s",
                request_id, e)

        if request_id in self._original_principals:
            orig = self._original_principals[request_id]
            if orig:
                try:
                    logger.debug(
                        "Restoring template-principal on request %s to %s",
                        request_id, orig)
                    self._cm.add_request_value(
                        request_id, 'template-principal', orig)
                except Exception as e:
                    logger.warning(
                        "Failed to restore principal on request %s: %s",
                        request_id, e)
            else:
                logger.debug(
                    "Request %s had no original principals, "
                    "skipping principal removal (harmless)",
                    request_id)

    def renew(self, certs, ipa_certs, ctx):
        """Renew expired certificates from a master via certmonger.

        Builds tracking criteria for each expired cert, temporarily overrides
        the IPA CA helper to point at the master, resubmits each request, and
        restores all certmonger state afterward.

        :param certs: list of ``(certid, cert)`` for Dogtag certs
        :param ipa_certs: list of ``(IPACertType, cert)`` for IPA service
            certs
        :param ctx: :class:`CertFixContext`
        :returns: set of renewed request IDs
        """
        tracking = self._build_tracking_list(certs, ipa_certs, ctx)

        if not tracking:
            print("No certificates to renew from master.")
            return set()

        requests = self._resolve_tracking_requests(tracking)

        if not requests:
            print("No certmonger tracking requests found.")
            return set()

        _kill_stuck_helpers()

        old_helper = self._set_helper()

        failed = []
        renewed_ids = set()
        try:
            print("Renewing certificates from %s" % self._master)
            for (desc, old_cert, request_id,
                 original_ca, load_renewed) in requests:
                _kill_stuck_helpers()
                try:
                    self._resubmit(
                        desc, old_cert, request_id,
                        original_ca, load_renewed,)
                    renewed_ids.add(request_id)
                except Exception as e:
                    desc_str = getattr(desc, 'display_name',
                                       getattr(desc, 'value', str(desc)))
                    logger.error("Failed to renew %s: %s", desc_str, e)
                    print("  ERROR: %s failed: %s" % (desc_str, e))
                    failed.append(desc_str)
        finally:
            for (_desc, _cert, request_id,
                 original_ca, _load) in requests:
                try:
                    self._restore(request_id, original_ca)
                except Exception as e:
                    logger.error(
                        "Failed to restore request %s: %s", request_id, e,)
            self._restore_helper(old_helper)

        if failed:
            print(
                "\nWARNING: %d certificate(s) failed to renew: %s\n"
                "These may need manual intervention."
                % (len(failed), ', '.join(failed)))

        return renewed_ids

    @staticmethod
    def _make_cert_loader(storage, path, nickname=None):
        """Create a callable that loads a renewed certificate.

        :param storage: ``'NSSDB'`` or ``'FILE'``
        :param path: NSS database dir or PEM file path
        :param nickname: cert nickname (NSSDB only)
        :returns: zero-arg callable returning the cert
        """
        if storage == 'NSSDB':
            db = NSSDatabase(nssdir=path)

            def _load(nn=nickname, _db=db):
                return _db.get_cert(nn)
            return _load

        def _load(_p=path):
            return x509.load_certificate_from_file(_p)
        return _load

    def _build_tracking_list(self, certs, ipa_certs, ctx):
        """Build certmonger tracking criteria for expired certs.

        Skips RA and subsystem certs (handled separately via
        ``_fetch_certs_from_master``).
        """
        tracking = []

        # Shared/replicated certs are fetched from master's LDAP
        # (cn=ca_renewal), not renewed via certmonger. Only sslserver is
        # server-specific and needs certmonger resubmit.
        for certid, cert in certs:
            if DOGTAG_CERTS[certid].is_shared:
                logger.debug("Skipping shared cert %s (fetched from LDAP)",
                             certid)
                continue
            ci = DOGTAG_CERTS[certid]
            logger.debug(
                "Adding dogtag cert to tracking: %s "
                "(nickname=%s, serial=%s, expires=%s)",
                certid, ci.nickname,
                cert.serial_number, cert.not_valid_after_utc,)
            tracking.append((
                ci, cert,
                {
                    'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                    'cert-nickname': ci.nickname,
                },
                self._make_cert_loader(
                    'NSSDB',
                    paths.PKI_TOMCAT_ALIAS_DIR,
                    ci.nickname,),
            ))

        cert_map = {
            IPACertType.HTTPS: (
                {'cert-file': paths.HTTPD_CERT_FILE},
                self._make_cert_loader('FILE', paths.HTTPD_CERT_FILE),),
            IPACertType.LDAPS: (
                {
                    'cert-database': ctx.ds_dbdir,
                    'cert-nickname': ctx.ds_nickname,
                },
                self._make_cert_loader('NSSDB', ctx.ds_dbdir, ctx.ds_nickname),
            ),
            IPACertType.KDC: (
                {'cert-file': paths.KDC_CERT},
                self._make_cert_loader('FILE', paths.KDC_CERT),),
        }

        for certtype, cert in ipa_certs:
            if certtype is IPACertType.IPARA:
                logger.debug("Skipping RA cert (already fetched)")
                continue
            entry = cert_map.get(certtype)
            if entry is None:
                continue
            criteria, loader = entry
            logger.debug(
                "Adding IPA cert to tracking: %s (serial=%s, expires=%s)",
                certtype.value, cert.serial_number, cert.not_valid_after_utc,
            )
            tracking.append((certtype, cert, criteria, loader))

        return tracking

    def _resolve_tracking_requests(self, tracking):
        """Look up certmonger request IDs for tracked certs."""
        requests = []
        for desc, old_cert, criteria, load_renewed in tracking:
            request_id = self._cm.get_request_id(criteria)
            if request_id is None:
                logger.warning(
                    "No certmonger tracking request found for %s "
                    "(criteria: %s)", desc, criteria)
                continue
            original_ca = self._cm.get_request_value(request_id, 'ca-name')
            requests.append(
                (desc, old_cert, request_id, original_ca, load_renewed))
            logger.debug(
                "Found tracking request %s for %s (CA: %s)",
                request_id, desc, original_ca)
        return requests


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
