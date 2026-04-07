#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

import os
from datetime import datetime, timedelta, timezone
UTC = timezone.utc
import synta
import synta.ext
import synta.oids


def generate_csr(cn, is_hostname=True):
    """
    Generate certificate signing request

    :param cn: common name (str|unicode)
    :param is_hostname: is the common name a hostname (default: True)
    """
    key = synta.PrivateKey.generate_rsa(2048)
    if isinstance(cn, bytes):
        cn = cn.decode()
    name_der = synta.NameBuilder().common_name(cn).build()
    builder = synta.CsrBuilder().subject_name(name_der).public_key(key.public_key)
    if is_hostname:
        san_der = synta.ext.SAN().dns_name(cn).build()
        builder = builder.add_extension(synta.oids.SUBJECT_ALT_NAME,
                                        False, san_der)
    csr = builder.sign(key, "sha256")
    return csr.to_pem().decode()


def generate_certificate(hostname):
    """
    Generate self-signed certificate for some DNS name.
    The certificate is valid for 100 days from moment of generation.

    :param hostname: DNS name (str|unicode)
    """
    key = synta.PrivateKey.generate_rsa(2048)
    if isinstance(hostname, bytes):
        hostname = hostname.decode()
    name_der = synta.NameBuilder().common_name(hostname).build()
    pub = key.public_key
    now = datetime.now(tz=UTC)
    san_der = synta.ext.SAN().dns_name(hostname).build()
    cert = (
        synta.CertificateBuilder()
        .subject_name(name_der)
        .issuer_name(name_der)
        .public_key(pub)
        .serial_number(int.from_bytes(os.urandom(20), 'big'))
        .not_valid_before_utc(now)
        .not_valid_after_utc(now + timedelta(days=100))
        .add_extension(synta.oids.SUBJECT_ALT_NAME, False, san_der)
        .sign(key, "sha256")
    )
    return cert.to_pem().decode()
