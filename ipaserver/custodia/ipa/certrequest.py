# Copyright (C) 2017  Custodia Project Contributors - see LICENSE file
"""FreeIPA cert request store
"""
from __future__ import absolute_import

import abc
import base64
import datetime
import textwrap

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import oid

from ipalib.errors import AuthorizationError, NotFound
from ipalib.krb_utils import krb5_format_service_principal_name


import six

from custodia.plugin import CSStore, PluginOption, REQUIRED
from custodia.plugin import CSStoreDenied, CSStoreError

from .interface import IPAInterface


TLS_SERVERAUTH = oid.ObjectIdentifier('2.5.29.37.1')


@six.add_metaclass(abc.ABCMeta)
class _CSRGenerator(object):
    """Build and sign certificate signing request
    """
    TEMPLATE = textwrap.dedent("""\
        Issuer: {issuer}
        Subject: {subject}
        Serial Number: {cert.serial_number}
        Validity:
            Not Before: {cert.not_valid_before}
            Not After: {cert.not_valid_after}
        {pem}\
    """)

    def __init__(self, plugin, backend=None):
        if backend is None:
            self.backend = default_backend()
        else:
            self.backend = backend
        self.plugin = plugin
        self._privkey = self._gen_private()

    def _gen_private(self):
        """Generate private key
        """
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.plugin.key_size,
            backend=self.backend
        )

    @abc.abstractmethod
    def build_csr(self, **kwargs):
        """Generate a certificate signing request builder
        """

    def _sign_csr(self, builder):
        return builder.sign(self._privkey, hashes.SHA256(), self.backend)

    @abc.abstractmethod
    def _cert_request(self, csr_pem, **kwargs):
        """Request certificate from IPA
        """

    def request_cert(self, builder, **kwargs):
        """Send CSR and request certificate
        """
        signed = self._sign_csr(builder)
        csr_pem = signed.public_bytes(serialization.Encoding.PEM)
        if not isinstance(csr_pem, six.text_type):
            csr_pem = csr_pem.decode('ascii')

        response = self._cert_request(csr_pem, **kwargs)

        if self.plugin.chain:
            certs = tuple(
                x509.load_der_x509_certificate(cert, self.backend)
                for cert in response[u'result'][u'certificate_chain']
            )
        else:
            # certificate is just base64 without BEGIN/END certificate
            cert = base64.b64decode(response[u'result'][u'certificate'])
            certs = (x509.load_der_x509_certificate(cert, self.backend), )

        pem = [self._dump_privkey(self._privkey)]
        pem.extend(self._dump_cert(cert) for cert in certs)
        return response, '\n'.join(pem)

    def _dump_cert(self, cert):
        pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        if six.PY3:
            pem = pem.decode('ascii')
        return self.TEMPLATE.format(
            issuer=self._dump_x509name(cert.issuer),
            subject=self._dump_x509name(cert.subject),
            cert=cert,
            pem=pem
        )

    def _dump_x509name(self, name):
        # no quoting, just for debugging
        out = []
        # pylint: disable=protected-access
        for nameattr in list(name):
            out.append("{}={}".format(nameattr.oid._name, nameattr.value))
        # pylint: enable=protected-access
        return ', '.join(out)

    def _dump_privkey(self, privkey):
        privkey = privkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        if six.PY3:
            privkey = privkey.decode('ascii')
        return privkey


class _ServerCSRGenerator(_CSRGenerator):
    # pylint: disable=arguments-differ
    def build_csr(self, hostname, **kwargs):
        realm = self.plugin.ipa.env.realm
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(oid.NameOID.COMMON_NAME, hostname),
                x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, realm),
            ])
        )
        build = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        build = builder.add_extension(
            x509.ExtendedKeyUsage([TLS_SERVERAUTH]), critical=True
        )
        builder = build.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False
        )
        return builder

    # pylint: disable=arguments-differ
    def _cert_request(self, pem_req, principal, **kwargs):
        # FreeIPA 4.4 has no chain option, only pass kwarg when enabled
        if self.plugin.chain:
            kwargs['chain'] = True
        with self.plugin.ipa as ipa:
            return ipa.Command.cert_request(
                pem_req,
                profile_id=self.plugin.cert_profile,
                add=self.plugin.add_principal,
                principal=principal,
                **kwargs
            )


class IPACertRequest(CSStore):
    """IPA cert request store

    The IPACertRequest store plugin generates or revokes certificates on the
    fly. It uses a backing store to cache certs and private keys.

    The request ```GET /secrets/certs/HTTP/client1.ipa.example``` generates a
    private key and CSR for the service ```HTTP/client1.ipa.example``` with
    DNS subject alternative name ```client1.ipa.example```.

    A DELETE request removes the cert/key pair from the backing store and
    revokes the cert at the same time.
    """
    backing_store = PluginOption(str, REQUIRED, None)

    key_size = PluginOption(int, 2048, 'RSA key size')
    cert_profile = PluginOption(str, 'caIPAserviceCert', 'IPA cert profile')
    add_principal = PluginOption(bool, True, 'Add missing principal')
    chain = PluginOption(bool, True, 'Return full cert chain')
    allowed_services = PluginOption('str_set', {'HTTP'}, 'Service prefixes')
    revocation_reason = PluginOption(
        int, 4, 'Cert revocation reason (4: superseded)')

    def __init__(self, config, section=None):
        super(IPACertRequest, self).__init__(config, section)
        self.store_name = self.backing_store
        self.store = None
        self.ipa = None
        if not isinstance(self.cert_profile, six.text_type):
            self.cert_profile = self.cert_profile.decode('utf-8')

    def finalize_init(self, config, cfgparser, context=None):
        super(IPACertRequest, self).finalize_init(config, cfgparser, context)
        if self.ipa is not None:
            return
        self.ipa = IPAInterface.from_config(config)
        self.ipa.finalize_init(config, cfgparser, context=self)

    def _parse_key(self, key):
        if not isinstance(key, six.text_type):
            key = key.decode('utf-8')
        parts = key.split(u'/')
        # XXX why is 'keys' added in in Secrets._db_key()?
        if len(parts) != 3 or parts[0] != 'keys':
            raise CSStoreDenied("Invalid cert request key '{}'".format(key))
        service, hostname = parts[1:3]
        # pylint: disable=unsupported-membership-test
        if service not in self.allowed_services:
            raise CSStoreDenied("Invalid service '{}'".format(key))
        principal = krb5_format_service_principal_name(
            service, hostname, self.ipa.env.realm
        )
        # use cert prefix in storage key
        key = u"cert/{}/{}".format(service, hostname)
        return key, hostname, principal

    def get(self, key):
        # check key first
        key, hostname, principal = self._parse_key(key)
        value = self.store.get(key)
        if value is not None:
            # TODO: validate certificate
            self.logger.info("Found cached certificate for %s", principal)
            return value
        # found no cached key/cert pair, generate one
        try:
            data = self._request_cert(hostname, principal)
        except AuthorizationError:
            msg = "Unauthorized request for '{}' ({})".format(
                hostname, principal
            )
            self.logger.exception(msg)
            raise CSStoreDenied(msg)
        except NotFound:
            msg = "Host '{}' or principal '{}' not found".format(
                hostname, principal
            )
            self.logger.exception(msg)
            raise CSStoreDenied(msg)
        except Exception:
            msg = "Failed to request cert '{}' ({})".format(
                hostname, principal
            )
            self.logger.exception(msg)
            raise CSStoreError(msg)
        self.store.set(key, data, replace=True)
        return data

    def set(self, key, value, replace=False):
        key, hostname, principal = self._parse_key(key)
        del hostname, principal
        return self.store.set(key, value, replace)

    def span(self, key):
        key, hostname, principal = self._parse_key(key)
        del hostname, principal
        return self.store.span(key)

    def list(self, keyfilter=''):
        return self.store.list(keyfilter)

    def cut(self, key):
        key, hostname, principal = self._parse_key(key)
        certs = self._revoke_certs(hostname, principal)
        return self.store.cut(key) or certs

    def _request_cert(self, hostname, principal):
        self.logger.info("Requesting certificate for %s", hostname)
        csrgen = _ServerCSRGenerator(plugin=self)
        builder = csrgen.build_csr(hostname=hostname)
        response, pem = csrgen.request_cert(builder, principal=principal)
        self.logger.info(
            "Got certificate for '%s', request id %s, serial number %s",
            response[u'result'][u'subject'],
            response[u'result'][u'request_id'],
            response[u'result'][u'serial_number'],
        )
        return pem

    def _revoke_certs(self, hostname, principal):
        with self.ipa as ipa:
            response = ipa.Command.cert_find(
                service=principal,
                validnotafter_from=datetime.datetime.utcnow(),
            )
            # XXX cert_find has no filter for valid cert
            certs = list(
                cert for cert in response['result']
                if not cert[u'revoked']
            )
            for cert in certs:
                self.logger.info(
                    'Revoking cert %i (subject: %s, issuer: %s)',
                    cert[u'serial_number'], cert[u'subject'],
                    cert[u'issuer']
                )
                ipa.Command.cert_revoke(
                    cert[u'serial_number'],
                    revocation_reason=self.revocation_reason,
                )
            return certs


def test():
    from custodia.compat import configparser
    from custodia.log import setup_logging
    from .interface import IPA_SECTIONNAME
    from .vault import IPAVault

    parser = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation()
    )
    parser.read_string(u"""
    [auth:ipa]
    handler = IPAInterface
    [store:ipa_vault]
    handler = IPAVault
    [store:ipa_certreq]
    handler = IPAVault
    backing_store = ipa_vault
    """)

    setup_logging(debug=True, auditfile=None)
    config = {
        'authenticators': {
            'ipa': IPAInterface(parser, IPA_SECTIONNAME)
        }
    }
    vault = IPAVault(parser, 'store:ipa_vault')
    vault.finalize_init(config, parser, None)
    s = IPACertRequest(parser, 'store:ipa_certreq')
    s.store = vault
    s.finalize_init(config, parser, None)
    print(s.get('keys/HTTP/client1.ipa.example'))
    print(s.get('keys/HTTP/client1.ipa.example'))
    print(s.cut('keys/HTTP/client1.ipa.example'))


if __name__ == '__main__':
    test()
