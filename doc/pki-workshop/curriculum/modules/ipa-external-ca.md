---
back-href: ipa-profiles.html
back-text: FreeIPA certificate profiles and user certificates
up-href: "../index.html#toc"
up-text: Up to index
next-href: ipa-acme.html
next-text: The FreeIPA ACME server
---

# Externally signing the FreeIPA CA

By default, FreeIPA installations use a **self-signed CA**.  Many
organisations, especially large ones, require their FreeIPA CA to be
subordinated to some other CA operated by the organisation.  In
other words, the CA has to be *externally signed*.

Because external signing does not change the Subject DN or the
signing key, a CA can change its chaining during its lifetime.  It
can go from self-signed to externally-signed, or vice versa.

In this module, you will change the FreeIPA CA in your workshop
environment to be externally signed.  This procedure has multiple
steps:

1. Generate a CSR.
2. Submit the CSR for signing by the external CA.
3. Install the new CSR.

::: note

This module must be performed on `ipa.$DOMAIN`, except where noted
below.

:::


## Initiating renewal

The `ipa-cacert-manage(1)` command renews the FreeIPA CA
certificate.  To switch a self-signed installation to
externally-signed, use the `--external-ca` option:

```command {.ipa}
sudo ipa-cacert-manage renew --external-ca
```
```output
Exporting CA certificate signing request, please wait

The next step is to get /var/lib/ipa/ca.csr signed by your CA and
re-run ipa-cacert-manage as:

ipa-cacert-manage renew
  --external-cert-file=/path/to/signed_certificate
  --external-cert-file=/path/to/external_ca_certificate

The ipa-cacert-manage command was successful
```

As suggested, a CSR is ready and waiting at `/var/lib/ipa/ca.csr`.


## Signing the CSR

In real world scenarios, how to submit the CSR for signing depends
on all sorts of things: the CA implementation, organisational
policy, the phase of the moon.

Fortunately this is not a real world scenario, so I have provided a
fake "external CA".  With it you can simulate the experience with
much less bureaucracy.


The "external" CA key and certificate, and an OpenSSL config file,
are in the `/root/ca` directory.  Execute the following command to
sign the CSR:

```command {.ipa}
sudo openssl x509 \
    -req -in /var/lib/ipa/ca.csr \
    -CAkey /root/ca/ca.key \
    -CA /root/ca/ca.crt \
    -extfile /root/ca/ca.cnf -extensions exts \
    -days 740 \
    -out ipa-new.crt
```
```output
Certificate request self-signature ok
subject=O=E1.__BASE_REALM__, CN=Certificate Authority
```


## Completing the renewal

Run `ipa-cacert-manage renew` again, and point it to the issued
certificate, as well as the external issuer certificate:

```command {.ipa}
sudo ipa-cacert-manage renew \
    --external-cert-file ipa-new.crt \
    --external-cert-file /root/ca/ca.crt
```
```output
Importing the renewed CA certificate, please wait
CA certificate successfully renewed
The ipa-cacert-manage command was successful
```

::: note

When there are additional certificates in the chain, repeat the
`--external-cert-file` option for all certificates.  Alternatively,
you can provide a PKCS #7 file with the complete chain.

:::


We are not quite done.  Certificate stores on servers and clients
still contain the original, self-signed certificate.  Run
`ipa-certupdate` **on all server replicas** (none in our case) **and
all client machines** to import the new CA certificate.

```command {.ipa}
sudo ipa-certupdate
```
```output
Systemwide CA database updated.
Systemwide CA database updated.
The ipa-certupdate command was successful
```

Use `ipa ca-show` to confirm that the FreeIPA CA certificate is
signed by the external CA:

```command {.ipa}
echo Secret.123 | kinit admin
```

```command {.ipa}
ipa ca-show ipa --raw |grep dn
```
```output
  ipacasubjectdn: CN=Certificate Authority,O=E1.__BASE_REALM__
  ipacaissuerdn: O=__BASE_REALM__,CN=PKI Workshop CA
```

::: note

You have completed the exercises for this module.  The sections that
follow are informational.

:::


## Renewing an externally signed CA

Certmonger cannot automatically renew an externally-signed CA.
Administrators must anticipate and manually initiate renewal.  The
procedure is the same as switching from self-signed to
externally-signed.


## Installing FreeIPA with an externally signed CA

Installing FreeIPA with an externally signed CA is a two stage
process, similar to renewal.  The `ipa-server-install(1)` command
accepts the same `--external-ca` and `--external-cert-file`
arguments as `ipa-cacert-manage(1)`.
