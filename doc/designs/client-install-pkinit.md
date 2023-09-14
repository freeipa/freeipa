# IPA client enrollment with PKINIT

This design document proposes PKINIT as an additional authentication
mechanism for `ipa-client-install`, ticket
[https://pagure.io/freeipa/issue/9271](https://pagure.io/freeipa/issue/9271).

## Overview

PKINIT is an authentication mechanism for Kerberos that uses X.509
certificates and private keys to authenticate Kerberos KDC server to client
and optionally clients to the server. Mutual authentication is almost the
same as mTLS with TLS server and client certificates in HTTPS.

PKINIT can be used instead of user/password or OTP to authorize client
enrollment. This enables admins to re-use existing host certificates to
automate client installations.


## Assumptions

- The client machine has access to a X.509 certificate / key pair that
  uniquely identifies an account with necessary permissions to enroll the
  host. The certificate does not have to contain special extensions for
  PKINIT. It only requires an attribute that can be uniquely mapped to an
  account, e.g. subject alternative name (SAN) dNSName maps to FQDN of
  an existing host entry or RFC 822 name maps to an user account with
  enrollment privileges.
- A certmap rule exists matches the certificate, and maps the unique
  identifier to a single account like an existing host entry or user with
  enrollment privileges.
- The certificate is signed by a CA chain which is known to and trusted
  by the Kerberos KDC server. This can be accomplished by installing the
  root CA and intermediate CAs as additional CA certificates to IPA
  with `ipa-cacert-manage install` on one IPA server, then running
  `ipa-certupdate` on every IPA servers.
- The CA chain of the certificate and the CA chain of the Kerberos KDC
  server certificate are available on the host. On an IPA server, the file
  `/var/lib/ipa-client/pki/kdc-ca-bundle.pem` typically contains all
  necessary CAs.

How the certificates and CAs are generated and distributed and how host
entries are created is out of scope for this document. The certificates
and key can be provided as files or by a PKCS#11 provider like OpenSC
from a smart card or p11-kit proxy from a remote PKCS#11 source.


### Host self-enrollment

Host self-enrollment allows a host to enroll itself using a host-specific
certificate. The approach use the fact that a host account has the necessary
permissions to self-manage its host entry. A host entry must be pre-created
by a privileged account and a certmap rule must map a unique identifier to
a host entry.

For example a certmap rule like

```console
$ ipa certmaprule-add pkinit-host \
    --matchrule '<ISSUER>CN=Certificate Authority,O=IPA.EXAMPLE' \
    --maprule='(fqdn={subject_dns_name})'
```

allows an host with hostname `host.ipa.example` and a certificate with
properties like

```console
Issuer: O = HMSIDM.TEST, CN = Certificate Authority
Subject: O = HMSIDM.TEST, CN = host.ipa.example
X509v3 extensions:
    X509v3 Subject Alternative Name:
        DNS:host.ipa.example
```

to enroll itself with a command like

```console
$ ipa-client-install \
    --pkinit-identity=FILE:/path/to/cert.pem,/path/to/key.pem \
    --pkinit-anchor=FILE:/path/to/kdc-ca-bundle.pem \
    ...
```

A privileged account only has to pre-created its host entry with

```console
$ ipa host-add host.ipa.example
```

first.


### Privileged user account

A user account with e.g. `Host Administrators` privilege can be used to
create and enroll new hosts.

Example certmap rule:
```console
$ ipa certmaprule-add pkinit-user \
    --matchrule '<ISSUER>CN=Certificate Authority,O=IPA.EXAMPLE' \
    --maprule='(&(mail={subject_rfc822_name})(objectclass=inetorgperson))'
```

In this case you have to pass the principal name of the user account to
`ipa-client-install`:

```console
$ ipa-client-install \
    --pkinit-identity=FILE:/path/to/cert.pem,/path/to/key.pem \
    --pkinit-anchor=FILE:/path/to/kdc-ca-bundle.pem \
    -p enrollmentuser
    ...
```


## New options for ipa-client-install

The `ipa-client-install` command is extended with two new options:

`--pkinit-identity=IDENTITY` specifies the PKINIT identity information. The
option is mutually exclusive with `--keytab` and `--password` option.
See [man krb5.conf(5)](https://web.mit.edu/kerberos/krb5-1.19/doc/admin/conf_files/krb5_conf.html#pkinit-options)
for more information. Possible values are

- `FILE:/path/to/cert.pem,/path/to/key.pem` or `FILE:/path/to/combined.pem`
  for certificate and private key in PEM format.
- `PKCS12:/path/to/file.p12` for PKCS#12 file with a certificate and private
  key.
- `PKCS11:...` to use a PKCS#11 provider
- `DIR:/path/to/directory` with `*.crt` and `*.key` files.

`--pkinit-anchor=FILEDIR` to load trust anchors (root and intermediate CA
certs) for KDC server and host identity. *FILE* is either an absolute path to
a PEM bundle (for example `FILE:/etc/pki/tls/cert.pem`) or to an OpenSSL hash
directory (for example `DIR:/etc/ssl/certs/`). The option can be used multiple
times to load trust anchors from several locations.

By default `ipa-client-install` attempts to authenticate with the host
principal `host/hostname@REALM`. Use `-p` option to authenticate as a
different account.

Example:

```console
$ ipa-client-install \
    --pkinit-identity=FILE:/path/to/cert.pem,/path/to/key.pem \
    --pkinit-anchor=FILE:/path/to/kdc-ca-bundle.pem \
    ...
```


## Testing

The `ipa certmap-match` command does not support hosts, yet. To test a
rule and certificate, you can run kinit:

```console
$ kinit \
    -X X509_user_identity=FILE:/path/to/cert.pem,/path/to/key.pem \
    -X X509_anchors=FILE:/path/to/kdc-ca-bundle.pem \
    host/host.ipa.example
```

Set the environment variable `KRB5_CONFIG=/dev/stderr` for additional debug
information. On IPA servers the log file `/var/log/krb5kdc.log` contains
information about cert authentication and filters:

```console
Initializing IPA certauth plugin.
Doing certauth authorize for [host/host.ipa.example@IPA.EXAMPLE]
Got cert filter [(fqdn=host.ipa.example)]
PKINIT: freshness token received from host/host.ipa.example@IPA.EXAMPLE
```

The KDC caches certmap rules for 5 minutes. To test a new or modified certmap
rule immediately, the KDC must be restarted with the command
`systemctl restart krb5kdc.service`.


## cert map rules

See [SSSD: Certificate mapping and matching rules](https://sssd.io/design-pages/matching_and_mapping_certificates.html)
and [man sss-certmap(5)](https://www.mankier.com/5/sss-certmap).

### certmap matching rule

certmap *matching rules* use RFC 4514 string representation of subject and
issuer distinguished names (DN) in LDAP order with NSS-style attribute type
names. RFC 4514 is the successor to RFC 2253. LDAP order is reverse to X.509
order of relative distinguised names, so common name (CN) typically comes
before organization and country.

- Matching rules are regular expressions. Characters `^.[$()|*+?{\\` must be
  quoted, e.g. `.` becomes `\.`.
- Characters `=#+,;<=>\` have special meaning in in RDN attribute values
  and may be escaped. A `,` becomes `\,`, which is then quoted again as
  `\\,`.
- Some fields use different attribute type names than OpenSSL, e.g.
  `emailAddress` attributes is just `E`.

To match a cert with issuer DN 
`O = "ACME, Inc.", CN = host.acme.example, emailAddress = info@acme.example`,
use the matching rule
`<I>^E=info@acme.example,CN=host.acme.example,O=ACME\\, Inc\.$`.

### certmap mapping rules

certmap mapping rules are used to associate a certificate with an account.
Mapping rules are LDAP queries with templating, e.g.
`(fqdn={subject_dns_name})` uses the dNSName value from the certificate
subject alternative name extension.

- Combine the filter with `(!(krbprincipalkey=*))` to prevent further PKINIT
  authenticate after the host has been enrolled:
  `(&(fqdn={subject_dns_name})(!(krbprincipalkey=*)))`
- Use `(!(memberof=cn=ipaservers,cn=hostgroups,cn=accounts,.*))` to prevent
  PKINIT as an IPA server host or
  `(memberof=pkinit-hosts,cn=hostgroups,cn=accounts,.*)` to limit PKINIT to
  hosts in a custom `pkinit-hosts` host group.
