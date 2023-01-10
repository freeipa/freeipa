# Authors:
#   Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2014  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
LDAP shared certificate store.
"""
import enum
import logging
import os
import typing

from pyasn1.error import PyAsn1Error

from ipapython.dn import DN
from ipapython.certdb import get_ca_nickname, TrustFlags, NSSDatabase
from ipapython import ipautil
from ipalib import api, errors, x509
from ipalib.constants import IPA_CA_CN
from ipaplatform.base.services import PlatformService
from ipaplatform.paths import paths
from ipaplatform.services import knownservices
from ipaplatform.tasks import tasks

logger = logging.getLogger(__name__)

# get_ca_certs() used to return a tuple with four elements.
# The CA cert info object is a named tuple with same four elements and
# additional fields.


class CACertInfo(typing.NamedTuple):
    """CA certificate information object
    """
    cert: x509.IPACertificate
    nickname: str
    trusted: typing.Optional[bool] = None
    ext_key_usage: typing.Optional[list] = None

    @property
    def trustflags(self) -> TrustFlags:
        """Get NSS trust flags
        """
        return key_policy_to_trust_flags(
            trusted=self.trusted,
            ca=True,
            ext_key_usage=self.ext_key_usage
        )


class StoreType(enum.Enum):
    PEM_BUNDLE = "PEM bundle"
    NSSDB = "NSS DB"
    SYSTEM_STORE = "system store"


class StoreInstallation(enum.Enum):
    CLIENT = "client"
    SERVER = "server"


class CACertStore(typing.NamedTuple):
    """CA certificate store information
    """
    # path to cert store or callable for dynamic paths
    path: typing.Union[str, typing.Callable[[], str]]
    # service name or "ipa" for generic cert store
    service: str
    # store type (PEM, NSS DB, system store)
    store_type: StoreType
    # installation target (client or server)
    installation: StoreInstallation
    # affected services that should be restarted after update
    restart_services: typing.FrozenSet[PlatformService] = frozenset()
    # optional callback function
    pre_callback: typing.Optional[
        typing.Callable[["CACertStore", str], None]
    ] = None

    def update(self, certs: typing.List[CACertInfo]) -> None:
        """Update certificate store
        """
        if callable(self.path):
            path = self.path()
        else:
            path = self.path

        if self.pre_callback is not None:
            self.pre_callback(self, path)  # pylint: disable=not-callable

        logger.debug(
            "Writing %i certificates to %s at '%s'.",
            len(certs), self.store_type, path
        )

        if self.store_type is StoreType.PEM_BUNDLE:
            return self._update_pem_bundle(path, certs)
        elif self.store_type is StoreType.NSSDB:
            return self._update_nssdb(path, certs)
        elif self.store_type is StoreType.SYSTEM_STORE:
            return self._update_system_store(path, certs)
        else:
            raise ValueError(self.store_type)

    def _update_pem_bundle(
        self, path: str, certs: typing.List[CACertInfo]
    ) -> None:
        """Write trusted CA certs to PEM bundle
        """
        return write_trusted_ca_certs(path, certs, mode=0o644)

    def _update_nssdb(
        self, path: str, certs: typing.List[CACertInfo]
    ) -> None:
        """Drop all CA certs from db then add certs from list provided

        This may result in some churn as existing certs are dropped
        and re-added but this also provides the ability to change
        the trust flags.
        """
        db = NSSDatabase(path)
        for name, flags in db.list_certs():
            if flags.ca:
                db.delete_cert(name)
        for ci in certs:
            try:
                db.add_cert(ci.cert, ci.nickname, ci.trustflags)
            except ipautil.CalledProcessError as e:
                logger.error(
                    "failed to update %s in %s: %s", ci.nickname, path, e
                )

    def _update_system_store(
        self, path: str, certs: typing.List[CACertInfo]
    ) -> None:
        tasks.remove_ca_certs_from_systemwide_ca_store()
        tasks.insert_ca_certs_into_systemwide_ca_store(certs)


def update_cert_stores(
    certs: typing.List[CACertInfo],
    installation: StoreInstallation,
    service: typing.Optional[str] = None
) -> typing.List[CACertStore]:
    """Update certificate stores

    Update all certificate stores (PEM bundle, NSSDB, system trust store) for
    client or server. Stores can be further limited by service name.
    """
    stores = [
        store for store in CA_CERT_STORES if store.installation == installation
    ]
    if service is not None:
        stores = [store for store in stores if store.service == service]
    if not stores:
        raise ValueError(
            f"Empty cert store list ({installation}, service={service})"
        )
    for store in stores:
        store.update(certs)
    return stores


def _ipa_nssdb_dir() -> str:
    # ipaclient.install.client initializes the API with a temporary nss_dir.
    if (
        api.env.context == "cli_installer"
        or not os.path.isdir(api.env.nss_dir)
    ):
        return paths.IPA_NSSDB_DIR
    else:
        return api.env.nss_dir


def _remove_old_certs(store: CACertStore, path: str) -> None:
    """Remove old IPA certs from /etc/ipa/nssdb
    """
    assert store.store_type is StoreType.NSSDB
    ipa_db = NSSDatabase(path)
    for nickname in ('IPA CA', 'External CA cert'):
        while ipa_db.has_nickname(nickname):
            try:
                ipa_db.delete_cert(nickname)
            except ipautil.CalledProcessError as e:
                logger.error(
                    "Failed to remove %s from %s: %s",
                    nickname, ipa_db.secdir, e)
                break


CA_CERT_STORES = [
    # CA certs are written to p11-kit file first, then the system trust
    # store is updated from the p11-kit file.
    # paths.SYSTEMWIDE_IPA_CA_CRT is no longer used
    CACertStore(
        paths.IPA_P11_KIT,
        "ipa",
        StoreType.SYSTEM_STORE,
        installation=StoreInstallation.CLIENT,
    ),
    # Currently also used by HTTPd to provide trusted CAs for client cert
    # authentication purposes.
    CACertStore(
        paths.IPA_CA_CRT,
        "ipa",
        StoreType.PEM_BUNDLE,
        installation=StoreInstallation.CLIENT,
        restart_services=frozenset({knownservices.httpd}),
    ),
    # IPA NSSDB
    CACertStore(
        # api.env.nss_dir or paths.IPA_NSSDB_DIR
        _ipa_nssdb_dir,
        "ipa",
        StoreType.NSSDB,
        installation=StoreInstallation.CLIENT,
        pre_callback=_remove_old_certs
    ),
    # /etc/krb5.conf pkinit_anchors
    CACertStore(
        paths.KDC_CA_BUNDLE_PEM,
        "krb5kdc",
        StoreType.PEM_BUNDLE,
        installation=StoreInstallation.CLIENT,
        restart_services=frozenset({knownservices.krb5kdc}),
    ),
    # /etc/krb5.conf pkinit_pool
    CACertStore(
        paths.CA_BUNDLE_PEM,
        "krb5kdc",
        StoreType.PEM_BUNDLE,
        installation=StoreInstallation.CLIENT,
        restart_services=frozenset({knownservices.krb5kdc}),
    ),
    # 389-DS' NSSDB
    CACertStore(
        # 389-DS path is instance-specific
        lambda: paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % (
            '-'.join(api.env.realm.split('.'))
        ),
        "dirsrv",
        StoreType.NSSDB,
        installation=StoreInstallation.SERVER,
        restart_services=frozenset({knownservices.dirsrv}),
    ),
    # download link /ipa/config.ca.crt
    CACertStore(
        paths.CA_CRT,
        "httpd",
        StoreType.PEM_BUNDLE,
        installation=StoreInstallation.SERVER,
    ),
    # server-side PKINIT plugin
    CACertStore(
        paths.CACERT_PEM,
        "krb5kdc",
        StoreType.PEM_BUNDLE,
        installation=StoreInstallation.SERVER,
        restart_services=frozenset({knownservices.krb5kdc}),
    ),
]


def _parse_cert(cert):
    try:
        subject = DN(cert.subject)
        issuer = DN(cert.issuer)
        serial_number = cert.serial_number
        public_key_info = cert.public_key_info_bytes
    except (ValueError, PyAsn1Error) as e:
        raise ValueError("failed to decode certificate: %s" % e)

    subject = str(subject).replace('\\;', '\\3b')
    issuer = str(issuer).replace('\\;', '\\3b')
    issuer_serial = '%s;%s' % (issuer, serial_number)

    return subject, issuer_serial, public_key_info


def init_ca_entry(entry, cert, nickname, trusted, ext_key_usage):
    """
    Initialize certificate store entry for a CA certificate.
    """
    subject, issuer_serial, public_key = _parse_cert(cert)

    if ext_key_usage is not None:
        try:
            cert_eku = cert.extended_key_usage
        except ValueError as e:
            raise ValueError("failed to decode certificate: %s" % e)
        if cert_eku is not None:
            cert_eku -= {x509.EKU_SERVER_AUTH, x509.EKU_CLIENT_AUTH,
                         x509.EKU_EMAIL_PROTECTION, x509.EKU_CODE_SIGNING,
                         x509.EKU_ANY, x509.EKU_PLACEHOLDER}
            ext_key_usage = ext_key_usage | cert_eku

    entry['objectClass'] = ['ipaCertificate', 'pkiCA', 'ipaKeyPolicy']
    entry['cn'] = [nickname]

    entry['ipaCertSubject'] = [subject]
    entry['ipaCertIssuerSerial'] = [issuer_serial]
    entry['ipaPublicKey'] = [public_key]
    entry['cACertificate;binary'] = [cert]

    if trusted is not None:
        entry['ipaKeyTrust'] = ['trusted' if trusted else 'distrusted']
    if ext_key_usage is not None:
        ext_key_usage = list(ext_key_usage)
        if not ext_key_usage:
            ext_key_usage.append(x509.EKU_PLACEHOLDER)
        entry['ipaKeyExtUsage'] = ext_key_usage


def update_compat_ca(ldap, base_dn, cert):
    """
    Update the CA certificate in cn=CAcert,cn=ipa,cn=etc,SUFFIX.
    """
    dn = DN(('cn', 'CAcert'), ('cn', 'ipa'), ('cn', 'etc'), base_dn)
    try:
        entry = ldap.get_entry(dn, attrs_list=['cACertificate;binary'])
        entry.single_value['cACertificate;binary'] = cert
        ldap.update_entry(entry)
    except errors.NotFound:
        entry = ldap.make_entry(dn)
        entry['objectClass'] = ['nsContainer', 'pkiCA']
        entry.single_value['cn'] = 'CAcert'
        entry.single_value['cACertificate;binary'] = cert
        ldap.add_entry(entry)
    except errors.EmptyModlist:
        pass


def clean_old_config(ldap, base_dn, dn, config_ipa, config_compat):
    """
    Remove ipaCA and compatCA flags from their previous carriers.
    """
    if not config_ipa and not config_compat:
        return

    try:
        result, _truncated = ldap.find_entries(
            base_dn=DN(('cn', 'certificates'), ('cn', 'ipa'), ('cn', 'etc'),
                       base_dn),
            filter='(|(ipaConfigString=ipaCA)(ipaConfigString=compatCA))',
            attrs_list=['ipaConfigString'])
    except errors.NotFound:
        return

    for entry in result:
        if entry.dn == dn:
            continue
        for config in list(entry['ipaConfigString']):
            if config.lower() == 'ipaca' and config_ipa:
                entry['ipaConfigString'].remove(config)
            elif config.lower() == 'compatca' and config_compat:
                entry['ipaConfigString'].remove(config)
        try:
            ldap.update_entry(entry)
        except errors.EmptyModlist:
            pass


def add_ca_cert(ldap, base_dn, cert, nickname, trusted=None,
                ext_key_usage=None, config_ipa=False, config_compat=False):
    """
    Add new entry for a CA certificate to the certificate store.
    """
    container_dn = DN(('cn', 'certificates'), ('cn', 'ipa'), ('cn', 'etc'),
                      base_dn)
    dn = DN(('cn', nickname), container_dn)
    entry = ldap.make_entry(dn)

    init_ca_entry(entry, cert, nickname, trusted, ext_key_usage)

    if config_ipa:
        entry.setdefault('ipaConfigString', []).append('ipaCA')
    if config_compat:
        entry.setdefault('ipaConfigString', []).append('compatCA')

    if config_compat:
        update_compat_ca(ldap, base_dn, cert)

    ldap.add_entry(entry)
    clean_old_config(ldap, base_dn, dn, config_ipa, config_compat)


def update_ca_cert(ldap, base_dn, cert, trusted=None, ext_key_usage=None,
                   config_ipa=False, config_compat=False):
    """
    Update existing entry for a CA certificate in the certificate store.
    """
    subject, issuer_serial, public_key = _parse_cert(cert)

    filter = ldap.make_filter({'ipaCertSubject': subject})
    result, _truncated = ldap.find_entries(
        base_dn=DN(('cn', 'certificates'), ('cn', 'ipa'), ('cn', 'etc'),
                   base_dn),
        filter=filter,
        attrs_list=['cn', 'ipaCertSubject', 'ipaCertIssuerSerial',
                    'ipaPublicKey', 'ipaKeyTrust', 'ipaKeyExtUsage',
                    'ipaConfigString', 'cACertificate;binary'])
    entry = result[0]
    dn = entry.dn

    for old_cert in entry['cACertificate;binary']:
        # Check if we are adding a new cert
        if old_cert == cert:
            break
    else:
        # We are adding a new cert, validate it
        if entry.single_value['ipaCertSubject'].lower() != subject.lower():
            raise ValueError("subject name mismatch")
        if entry.single_value['ipaPublicKey'] != public_key:
            raise ValueError("subject public key info mismatch")
        entry['ipaCertIssuerSerial'].append(issuer_serial)
        entry['cACertificate;binary'].append(cert)

    # Update key trust
    if trusted is not None:
        old_trust = entry.single_value.get('ipaKeyTrust')
        new_trust = 'trusted' if trusted else 'distrusted'
        if old_trust is not None and old_trust.lower() != new_trust:
            raise ValueError("inconsistent trust")
        entry.single_value['ipaKeyTrust'] = new_trust

    # Update extended key usage
    if trusted is not False:
        if ext_key_usage is not None:
            old_eku = set(entry.get('ipaKeyExtUsage', []))
            old_eku.discard(x509.EKU_PLACEHOLDER)
            new_eku = old_eku | ext_key_usage
            if not new_eku:
                new_eku.add(x509.EKU_PLACEHOLDER)
            entry['ipaKeyExtUsage'] = list(new_eku)
    else:
        entry.pop('ipaKeyExtUsage', None)

    # Update configuration flags
    is_ipa = False
    is_compat = False
    for config in entry.get('ipaConfigString', []):
        if config.lower() == 'ipaca':
            is_ipa = True
        elif config.lower() == 'compatca':
            is_compat = True
    if config_ipa and not is_ipa:
        entry.setdefault('ipaConfigString', []).append('ipaCA')
    if config_compat and not is_compat:
        entry.setdefault('ipaConfigString', []).append('compatCA')

    if is_compat or config_compat:
        update_compat_ca(ldap, base_dn, cert)

    ldap.update_entry(entry)
    clean_old_config(ldap, base_dn, dn, config_ipa, config_compat)


def put_ca_cert(ldap, base_dn, cert, nickname, trusted=None,
                ext_key_usage=None, config_ipa=False, config_compat=False):
    """
    Add or update entry for a CA certificate in the certificate store.

    :param cert: IPACertificate
    """
    try:
        update_ca_cert(ldap, base_dn, cert, trusted, ext_key_usage,
                       config_ipa=config_ipa, config_compat=config_compat)
    except errors.NotFound:
        add_ca_cert(ldap, base_dn, cert, nickname, trusted, ext_key_usage,
                    config_ipa=config_ipa, config_compat=config_compat)
    except errors.EmptyModlist:
        pass


def make_compat_ca_certs(certs, realm, ipa_ca_subject):
    """
    Make CA certificates and associated key policy from DER certificates.
    """
    result = []

    for cert in certs:
        subject, _issuer_serial, _public_key_info = _parse_cert(cert)
        subject = DN(subject)

        if ipa_ca_subject is not None and subject == DN(ipa_ca_subject):
            nickname = get_ca_nickname(realm)
            ext_key_usage = {x509.EKU_SERVER_AUTH,
                             x509.EKU_CLIENT_AUTH,
                             x509.EKU_EMAIL_PROTECTION,
                             x509.EKU_CODE_SIGNING}
        else:
            nickname = str(subject)
            ext_key_usage = {x509.EKU_SERVER_AUTH}

        result.append(CACertInfo(cert, nickname, True, ext_key_usage))

    return result


def get_ca_certs(ldap, base_dn, compat_realm, compat_ipa_ca,
                 filter_subject=None) -> typing.List[CACertInfo]:
    """
    Get CA certificates and associated key policy from the certificate store.
    """
    if filter_subject is not None:
        if not isinstance(filter_subject, list):
            filter_subject = [filter_subject]
        filter_subject = [str(subj).replace('\\;', '\\3b')
                          for subj in filter_subject]

    certs = []
    config_dn = DN(('cn', 'ipa'), ('cn', 'etc'), base_dn)
    container_dn = DN(('cn', 'certificates'), config_dn)
    try:
        # Search the certificate store for CA certificate entries
        filters = ['(objectClass=ipaCertificate)', '(objectClass=pkiCA)']
        if filter_subject:
            filter = ldap.make_filter({'ipaCertSubject': filter_subject})
            filters.append(filter)
        result, _truncated = ldap.find_entries(
            base_dn=container_dn,
            filter=ldap.combine_filters(filters, ldap.MATCH_ALL),
            attrs_list=['cn', 'ipaCertSubject', 'ipaCertIssuerSerial',
                        'ipaPublicKey', 'ipaKeyTrust', 'ipaKeyExtUsage',
                        'cACertificate;binary'])

        for entry in result:
            nickname = entry.single_value['cn']
            trusted = entry.single_value.get('ipaKeyTrust', 'unknown').lower()
            if trusted == 'trusted':
                trusted = True
            elif trusted == 'distrusted':
                trusted = False
            else:
                trusted = None
            ext_key_usage = entry.get('ipaKeyExtUsage')
            if ext_key_usage is not None:
                ext_key_usage = set(str(p) for p in ext_key_usage)
                ext_key_usage.discard(x509.EKU_PLACEHOLDER)

            for cert in entry.get('cACertificate;binary', []):
                try:
                    _parse_cert(cert)
                except ValueError:
                    certs = []
                    break
                certs.append(
                    CACertInfo(cert, nickname, trusted, ext_key_usage)
                )
    except errors.NotFound:
        try:
            ldap.get_entry(container_dn, [''])
        except errors.NotFound:
            # Fallback to cn=CAcert,cn=ipa,cn=etc,SUFFIX
            dn = DN(('cn', 'CAcert'), config_dn)
            entry = ldap.get_entry(dn, ['cACertificate;binary'])

            cert = entry.single_value['cACertificate;binary']
            try:
                subject, _issuer_serial, _public_key_info = _parse_cert(cert)
            except ValueError:
                pass
            else:
                if filter_subject is not None and subject not in filter_subject:
                    raise errors.NotFound(reason="no matching entry found")

                if compat_ipa_ca:
                    ca_subject = subject
                else:
                    ca_subject = None
                certs = make_compat_ca_certs([cert], compat_realm, ca_subject)

    if certs:
        return certs
    else:
        raise errors.NotFound(reason="no such entry")


def trust_flags_to_key_policy(trust_flags):
    """
    Convert certutil trust flags to certificate store key policy.
    """
    return trust_flags[1:]


def key_policy_to_trust_flags(trusted, ca, ext_key_usage):
    """
    Convert certificate store key policy to certutil trust flags.
    """
    return TrustFlags(False, trusted, ca, ext_key_usage)


def put_ca_cert_nss(ldap, base_dn, cert, nickname, trust_flags,
                    config_ipa=False, config_compat=False):
    """
    Add or update entry for a CA certificate in the certificate store.

    :param cert: IPACertificate
    """
    trusted, ca, ext_key_usage = trust_flags_to_key_policy(trust_flags)
    if ca is False:
        raise ValueError("must be CA certificate")

    put_ca_cert(ldap, base_dn, cert, nickname, trusted, ext_key_usage,
                config_ipa, config_compat)


def get_ca_certs_nss(ldap, base_dn, compat_realm, compat_ipa_ca,
                     filter_subject=None):
    """
    Get CA certificates and associated trust flags from the certificate store.
    """
    nss_certs = []

    certs = get_ca_certs(ldap, base_dn, compat_realm, compat_ipa_ca,
                         filter_subject=filter_subject)
    for certinfo in certs:
        nss_certs.append(
            (certinfo.cert, certinfo.nickname, certinfo.trustflags)
        )

    return nss_certs


def get_ca_subject(ldap, container_ca, base_dn):
    """
    Look for the IPA CA certificate subject.
    """
    dn = DN(('cn', IPA_CA_CN), container_ca, base_dn)
    try:
        cacert_subject = ldap.get_entry(dn)['ipacasubjectdn'][0]
    except errors.NotFound:
        # if the entry doesn't exist, we are dealing with a pre-v4.4
        # installation, where the default CA subject was always based
        # on the subject_base.
        attrs = ldap.get_ipa_config()
        subject_base = attrs.get('ipacertificatesubjectbase')[0]
        cacert_subject = DN(('CN', 'Certificate Authority'), subject_base)

    return cacert_subject


def write_trusted_ca_certs(
    filename: str,
    certs: typing.List[CACertInfo],
    mode: int = 0o644
):
    """Write trusted CA certificates to a file"""
    certs = [ci.cert for ci in certs if ci.trusted is not False]
    x509.write_certificate_list(certs, filename, mode=mode)
