#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_csr(cn, is_hostname=True):
    """
    Generate certificate signing request

    :param cn: common name (str|unicode)
    :param is_hostname: is the common name a hostname (default: True)
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    if isinstance(cn, bytes):
        cn = cn.decode()
    csr = x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    )
    if is_hostname:
        csr = csr.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False
        )

    csr = csr.sign(key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def generate_certificate(hostname):
    """
    Generate self-signed certificate for some DNS name.
    The certificate is valid for 100 days from moment of generation.

    :param hostname: DNS name (str|unicode)
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    if isinstance(hostname, bytes):
        hostname = hostname.decode()
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, hostname)]
    )

    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject).issuer_name(issuer).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=100)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(hostname)]),
        critical=False
    ).sign(key, hashes.SHA256(), default_backend())
    return cert.public_bytes(serialization.Encoding.PEM).decode()
