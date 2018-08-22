#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_csr(hostname):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    csr = x509.CertificateSigningRequestBuilder()
    csr = csr.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'{}'.format(hostname))
    ]))
    csr = csr.sign(key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM)
