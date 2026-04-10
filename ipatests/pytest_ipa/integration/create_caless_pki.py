# Copyright (c) 2015-2017, Jan Cholasta <jcholast@redhat.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


import base64
import collections
import datetime
import itertools
import os
import os.path

import synta
import synta.ext
import synta.krb5
import synta.oids

DAY = datetime.timedelta(days=1)
YEAR = 365 * DAY

_SHA256_WITH_RSA_ALG = synta.AlgorithmIdentifier.from_oid(
    synta.oids.SHA256_WITH_RSA
).to_der()

# Tracks revoked certificates per CA nick:
# nick → [(serial_bytes, revocation_datetime)]
_revoked_certs = {}

# we get the variables from ca_less test
domain = None
realm = None
server1 = None
server2 = None
client = None
password = None
cert_dir = None

CertInfo = collections.namedtuple('CertInfo', 'nick key cert counter')


def profile_ca(builder, ca_nick, ca, spki_der):
    now = datetime.datetime.now(tz=datetime.timezone.utc)

    builder = builder.not_valid_before_utc(now)
    builder = builder.not_valid_after_utc(now + 10 * YEAR)

    crl_uri = u'file://{}.crl'.format(os.path.join(cert_dir, ca_nick))

    ku = (synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_NON_REPUDIATION
          | synta.ext.KU_KEY_CERT_SIGN | synta.ext.KU_CRL_SIGN)
    builder = builder.add_extension(
        str(synta.oids.KEY_USAGE), True, synta.ext.key_usage(ku)
    )
    builder = builder.add_extension(
        str(synta.oids.BASIC_CONSTRAINTS), True,
        synta.ext.basic_constraints(ca=True)
    )
    builder = builder.add_extension(
        str(synta.oids.CRL_DISTRIBUTION_POINTS), False,
        synta.ext.CDP().full_name_uri(crl_uri).build()
    )
    builder = builder.add_extension(
        str(synta.oids.SUBJECT_KEY_IDENTIFIER), False,
        synta.ext.subject_key_identifier(spki_der)
    )
    if not ca:
        builder = builder.add_extension(
            str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False,
            synta.ext.authority_key_identifier(spki_der)
        )
    else:
        builder = builder.add_extension(
            str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False,
            synta.ext.authority_key_identifier(
                ca.cert.subject_public_key_info_der)
        )
    return builder


def profile_server(builder, ca_nick, ca, spki_der,
                   warp=datetime.timedelta(days=0), dns_name=None,
                   badusage=False, wildcard=False):
    now = datetime.datetime.now(tz=datetime.timezone.utc) + warp

    builder = builder.not_valid_before_utc(now)
    builder = builder.not_valid_after_utc(now + YEAR)

    crl_uri = u'file://{}.crl'.format(os.path.join(cert_dir, ca_nick))

    builder = builder.add_extension(
        str(synta.oids.CRL_DISTRIBUTION_POINTS), False,
        synta.ext.CDP().full_name_uri(crl_uri).build()
    )

    if dns_name is not None:
        builder = builder.add_extension(
            str(synta.oids.SUBJECT_ALT_NAME), False,
            synta.ext.SAN().dns_name(dns_name).build()
        )

    if ca:
        builder = builder.add_extension(
            str(synta.oids.AUTHORITY_KEY_IDENTIFIER), False,
            synta.ext.authority_key_identifier(
                ca.cert.subject_public_key_info_der)
        )

    if badusage:
        ku = synta.ext.KU_DATA_ENCIPHERMENT | synta.ext.KU_KEY_AGREEMENT
        builder = builder.add_extension(
            str(synta.oids.KEY_USAGE), False, synta.ext.key_usage(ku)
        )
    else:
        ku = (synta.ext.KU_DIGITAL_SIGNATURE | synta.ext.KU_KEY_ENCIPHERMENT
              | synta.ext.KU_DATA_ENCIPHERMENT)
        builder = builder.add_extension(
            str(synta.oids.KEY_USAGE), False, synta.ext.key_usage(ku)
        )

    builder = builder.add_extension(
        str(synta.oids.EXTENDED_KEY_USAGE), False,
        synta.ext.ExtendedKeyUsageBuilder().server_auth().build()
    )

    if wildcard:
        san_builder = synta.ext.SAN().dns_name(u'*.' + domain)
        server_split = server1.split('.', 1)
        if len(server_split) == 2 and domain != server_split[1]:
            san_builder = san_builder.dns_name(u'*.' + server_split[1])
        builder = builder.add_extension(
            str(synta.oids.SUBJECT_ALT_NAME), False, san_builder.build()
        )

    return builder


def profile_kdc(builder, ca_nick, ca, spki_der,
                warp=datetime.timedelta(days=0), dns_name=None,
                badusage=False):
    now = datetime.datetime.now(tz=datetime.timezone.utc) + warp

    builder = builder.not_valid_before_utc(now)
    builder = builder.not_valid_after_utc(now + YEAR)

    crl_uri = u'file://{}.crl'.format(os.path.join(cert_dir, ca_nick))

    kdc_oid_comps = list(synta.oids.PKINIT_KP_KDC.components())
    builder = builder.add_extension(
        str(synta.oids.EXTENDED_KEY_USAGE), False,
        synta.ext.ExtendedKeyUsageBuilder().add_oid(kdc_oid_comps).build()
    )

    principal = synta.krb5.Krb5PrincipalName(
        realm, synta.krb5.NT_SRV_INST, ['krbtgt', realm]
    )
    san_builder = synta.ext.SAN().other_name(principal.to_othername_der())
    if dns_name is not None:
        san_builder = san_builder.dns_name(dns_name)
    builder = builder.add_extension(
        str(synta.oids.SUBJECT_ALT_NAME), False, san_builder.build()
    )

    builder = builder.add_extension(
        str(synta.oids.CRL_DISTRIBUTION_POINTS), False,
        synta.ext.CDP().full_name_uri(crl_uri).build()
    )

    if badusage:
        ku = synta.ext.KU_DATA_ENCIPHERMENT | synta.ext.KU_KEY_AGREEMENT
        builder = builder.add_extension(
            str(synta.oids.KEY_USAGE), False, synta.ext.key_usage(ku)
        )

    return builder


def gen_cert(profile, nick_base, subject_der, ca=None, **kwargs):
    key = synta.PrivateKey.generate_rsa(2048)
    public_key = key.public_key
    spki_der = public_key.to_der()

    counter = itertools.count(1)

    if ca is not None:
        ca_nick, ca_key, ca_cert, ca_counter = ca
        nick = os.path.join(ca_nick, nick_base)
        issuer_der = ca_cert.subject_raw_der
    else:
        nick = ca_nick = nick_base
        ca_key = key
        ca_counter = counter
        issuer_der = subject_der

    serial = next(ca_counter)

    builder = (
        synta.CertificateBuilder()
        .serial_number(serial)
        .issuer_name(issuer_der)
        .subject_name(subject_der)
        .public_key(public_key)
    )
    builder = profile(builder, ca_nick, ca, spki_der, **kwargs)
    cert = builder.sign(ca_key, "sha256")

    key_pem = key.to_pem(password=password.encode())
    cert_pem = synta.Certificate.to_pem(cert)
    try:
        os.makedirs(os.path.dirname(os.path.join(cert_dir, nick)))
    except OSError:
        pass
    with open(os.path.join(cert_dir, nick + '.key'), 'wb') as f:
        f.write(key_pem)
    with open(os.path.join(cert_dir, nick + '.crt'), 'wb') as f:
        f.write(cert_pem)

    return CertInfo(nick, key, cert, counter)


def revoke_cert(ca, serial):
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    serial_bytes = serial.to_bytes((serial.bit_length() + 7) // 8 or 1, 'big')
    _revoked_certs.setdefault(ca.nick, []).append((serial_bytes, now))

    crl_builder = (
        synta.CertificateListBuilder()
        .issuer(ca.cert.subject_raw_der)
        .signature_algorithm(_SHA256_WITH_RSA_ALG)
        .this_update_utc(now)
        .next_update_utc(now + DAY)
    )
    for s_bytes, revoke_dt in _revoked_certs[ca.nick]:
        crl_builder = crl_builder.revoke_utc(s_bytes, revoke_dt, None)

    tbs_der = crl_builder.build()
    sig = ca.key.sign(tbs_der, "sha256")
    crl_der = synta.CertificateListBuilder.assemble(
        tbs_der, _SHA256_WITH_RSA_ALG, sig)

    b64 = base64.encodebytes(crl_der).decode('ascii')
    crl_pem = '-----BEGIN X509 CRL-----\n' + b64 + '-----END X509 CRL-----\n'
    crl_filename = os.path.join(cert_dir, ca.nick + '.crl')
    with open(crl_filename, 'wb') as f:
        f.write(crl_pem.encode())


def gen_server_certs(nick_base, hostname, org, ca=None):
    gen_cert(profile_server, nick_base,
             synta.NameBuilder()
             .organization(org).common_name(hostname).build(),
             ca, dns_name=hostname
             )
    gen_cert(profile_server, nick_base + u'-badname',
             synta.NameBuilder()
             .organization(org).common_name(u'not-' + hostname).build(),
             ca, dns_name=u'not-' + hostname
             )
    gen_cert(profile_server, nick_base + u'-altname',
             synta.NameBuilder()
             .organization(org).common_name(u'alt-' + hostname).build(),
             ca, dns_name=hostname
             )
    gen_cert(profile_server, nick_base + u'-expired',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'Expired')
             .common_name(hostname)
             .build(),
             ca, dns_name=hostname, warp=-2 * YEAR
             )
    gen_cert(
        profile_server, nick_base + u'-not-yet-valid',
        synta.NameBuilder()
        .organization(org)
        .organizational_unit(u'Future')
        .common_name(hostname)
        .build(),
        ca, dns_name=hostname, warp=1 * DAY,
    )
    gen_cert(profile_server, nick_base + u'-badusage',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'Bad Usage')
             .common_name(hostname)
             .build(),
             ca, dns_name=hostname, badusage=True
             )
    revoked = gen_cert(profile_server, nick_base + u'-revoked',
                       synta.NameBuilder()
                       .organization(org)
                       .organizational_unit(u'Revoked')
                       .common_name(hostname)
                       .build(),
                       ca, dns_name=hostname
                       )
    revoke_cert(ca, revoked.cert.serial_number)


def gen_kdc_certs(nick_base, hostname, org, ca=None):
    gen_cert(profile_kdc, nick_base + u'-kdc',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'KDC')
             .common_name(hostname)
             .build(),
             ca
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-badname',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'KDC')
             .common_name(u'not-' + hostname)
             .build(),
             ca
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-altname',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'KDC')
             .common_name(u'alt-' + hostname)
             .build(),
             ca, dns_name=hostname
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-expired',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'Expired KDC')
             .common_name(hostname)
             .build(),
             ca, warp=-2 * YEAR
             )
    gen_cert(profile_kdc, nick_base + u'-kdc-badusage',
             synta.NameBuilder()
             .organization(org)
             .organizational_unit(u'Bad Usage KDC')
             .common_name(hostname)
             .build(),
             ca, badusage=True
             )
    revoked = gen_cert(profile_kdc, nick_base + u'-kdc-revoked',
                       synta.NameBuilder()
                       .organization(org)
                       .organizational_unit(u'Revoked KDC')
                       .common_name(hostname)
                       .build(),
                       ca
                       )
    revoke_cert(ca, revoked.cert.serial_number)


def gen_subtree(nick_base, org, ca=None):
    subca = gen_cert(profile_ca, nick_base,
                     synta.NameBuilder()
                     .organization(org).common_name(u'CA').build(),
                     ca
                     )
    gen_cert(profile_server, u'wildcard',
             synta.NameBuilder()
             .organization(org).common_name(u'*.' + domain).build(),
             subca, wildcard=True
             )
    gen_server_certs(u'server', server1, org, subca)
    gen_server_certs(u'replica', server2, org, subca)
    gen_server_certs(u'client', client, org, subca)
    gen_cert(profile_kdc, u'kdcwildcard',
             synta.NameBuilder()
             .organization(org).common_name(u'*.' + domain).build(),
             subca
             )
    gen_kdc_certs(u'server', server1, org, subca)
    gen_kdc_certs(u'replica', server2, org, subca)
    gen_kdc_certs(u'client', client, org, subca)
    return subca


def create_pki():

    gen_cert(profile_server, u'server-selfsign',
             synta.NameBuilder()
             .organization(u'Self-signed')
             .common_name(server1)
             .build()
             )
    gen_cert(profile_server, u'replica-selfsign',
             synta.NameBuilder()
             .organization(u'Self-signed')
             .common_name(server2)
             .build()
             )
    gen_cert(profile_server, u'noca',
             synta.NameBuilder()
             .organization(u'No-CA')
             .common_name(server1)
             .build()
             )
    gen_cert(profile_kdc, u'server-kdc-selfsign',
             synta.NameBuilder()
             .organization(u'Self-signed')
             .organizational_unit(u'KDC')
             .common_name(server1)
             .build()
             )
    gen_cert(profile_kdc, u'replica-kdc-selfsign',
             synta.NameBuilder()
             .organization(u'Self-signed')
             .organizational_unit(u'KDC')
             .common_name(server2)
             .build()
             )
    ca1 = gen_subtree(u'ca1', u'Example Organization Espa\xf1a')
    gen_subtree(u'subca', u'Subsidiary Example Organization', ca1)
    gen_subtree(u'ca2', u'Other Example Organization')
    ca3 = gen_subtree(u'ca3', u'Unknown Organization')
    os.unlink(os.path.join(cert_dir, ca3.nick + '.key'))
    os.unlink(os.path.join(cert_dir, ca3.nick + '.crt'))
