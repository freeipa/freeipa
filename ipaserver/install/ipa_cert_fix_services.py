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
import time

from ipalib import x509
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython.certdb import NSSDatabase
from ipapython.dn import DN
from ipapython import ipautil

from ipaserver.install.ipa_cert_fix_types import (
    CERT_EXPIRY_LOOKAHEAD,
    DBUS_RETRY_DELAY,
    DBUS_RETRY_TIMEOUT,
    _utcnow,
)

logger = logging.getLogger(__name__)


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
