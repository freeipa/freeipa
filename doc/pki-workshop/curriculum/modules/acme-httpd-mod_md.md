---
up-href: "../index.html#toc"
up-text: Up to index
next-href: certificate-transparency.html
next-text: Using certificate transparency logs
---

# ACME - Apache and mod_md

In this module you'll use the `mod_md` module of **Apache httpd** to
automatically acquire TLS server certificates from a
publicly-trusted CA.

::: note

All steps in this module are to be performed on `web.$DOMAIN`.
SSH into this machine now:

```
ssh -i path/to/key.pem fedora@web.e$N.__BASE_DOMAIN__
```

:::


## Start the server

```command {.web}
sudo systemctl enable --now httpd
```
```output
Created symlink '/etc/systemd/system/multi-user.target.wants/httpd.service' → '/usr/lib/systemd/system/httpd.service'.
```

If you point a web browser at `https://$DOMAIN`, or try to retrieve
the cert via `curl(1)`, the TLS connection fails.  This is because
httpd automatically generated a self-signed CA and used it to sign
the certificate for the web domain.  The browser or HTTP client does
not trust the unknown CA.

The `openssl s_client` command is useful for diagnosing TLS
connection issues:

```command {.web}
openssl s_client \
    -connect $(hostname):443 \
    -verify_return_error
```
```output
Connecting to fe80::85d:bbff:feda:7911%ens5
CONNECTED(00000003)
depth=1 C=US, O=Unspecified, OU=ca-2871753292585466680, CN=web, emailAddress=root@web.e2.__BASE_DOMAIN__
verify error:num=19:self-signed certificate in certificate chain
C0D265F5407F0000:error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:ssl/statem/statem_clnt.c:2123:
---
Certificate chain
 0 s:C=US, O=Unspecified, CN=web, emailAddress=root@web.e2.__BASE_DOMAIN__
   i:C=US, O=Unspecified, OU=ca-2871753292585466680, CN=web, emailAddress=root@web.e2.__BASE_DOMAIN__
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Jan  8 01:31:02 2026 GMT; NotAfter: Jan  8 01:31:02 2027 GMT
 1 s:C=US, O=Unspecified, OU=ca-2871753292585466680, CN=web, emailAddress=root@web.e2.__BASE_DOMAIN__
   i:C=US, O=Unspecified, OU=ca-2871753292585466680, CN=web, emailAddress=root@web.e2.__BASE_DOMAIN__
   a:PKEY: RSA, 2048 (bit); sigalg: sha256WithRSAEncryption
   v:NotBefore: Jan  8 01:31:02 2026 GMT; NotAfter: Jan  8 01:31:02 2027 GMT
---
no peer certificate available
---
No client certificate CA names sent
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 3333 bytes and written 1575 bytes
Verification error: self-signed certificate in certificate chain
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Protocol: TLSv1.3
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 19 (self-signed certificate in certificate chain)
---
```

In the transcript above you can see a summary of the certificate
chain, the negotiated cipher suite, and an error message explaining
that the server's certificate is untrusted.


## Configuring `mod_md`

`mod_md` is a module for Apache httpd that uses the ACME protocol to
automatically acquire and renew certificates for ***M****anaged*
***D****omains*.  By default it obtains certificates from ***Let's
Encrypt***, a publicly-trusted CA.

The `mod_md` package is already installed on this machine.

::: note

`mod_md` wants to talk to an ACME server, but default SELinux policy
prevents httpd from making outbound network connections.  Run the
following command to allow these connections:

```command {.web}
sudo setsebool httpd_can_network_connect 1
```

:::

Now create the file `/etc/httpd/conf.d/md.conf`:

```command {.web}
sudo tee /etc/httpd/conf.d/md.conf >/dev/null <<EOF
LogLevel warn md:notice
MDCertificateAgreement accepted
MDContactEmail yeahnah@mailinator.com
MDomain $(hostname)
EOF
```

Restart the server:

```command {.web}
sudo systemctl restart httpd
```

Check the httpd error log for ACME-related messages.

```command {.web}
sudo tail -f /var/log/httpd/error_log
```

The message that indicates success will look like:

```output
[Thu Jan 08 06:44:32.452115 2026] [md:notice] [pid 4358:tid 4361]
AH10059: The Managed Domain web.e2.__BASE_DOMAIN__ has been setup
and changes will be activated on next (graceful) server restart.
```

Now perform a graceful restart to pick up the new certificate:

```command {.web}
sudo systemctl reload httpd
```

Now you will be able to reload the site (a basic test page) in your
browser or retrieve it via `curl`:

```command {.web}
curl https://$(hostname) --silent | head -n 6
```
```output
<!doctype html>
<html>
  <head>
    <meta charset='utf-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <title>Test Page for the HTTP Server on Fedora</title>
```

Success!

::: note

You have completed the exercises for this module.  The sections that
follow are informational.

:::


## Renewal

By default, `mod_md` initiates certificate renewal when 33% of the
certificate lifetime remains.  However, graceful restart is still
required to pick up new certificates.

Therefore, you should set up a cron job to restart the server on a
regular schedule.  Daily is reasonable—but the next section
describes a scenario where more frequent restarts are appropriate.


## OCSP stapling and revocation

`mod_md` can also perform *OCSP stapling*—retrieving OCSP responses
from the CA and including them in the handshake.  This gives
performance and privacy benefits for TLS clients.

To turn on OCSP stapling, add the following directive to the config:

```
MDStapling on
```

When this feature is turned on, `mod_md` also inspects the OCSP
responses to confirm that the certificate has not been revoked.  But
if it *has* been revoked for some reason, `mod_md` will immediately
initiate renewal.

Again, graceful restart is needed to pick up the new certificate.
So if you are using this feature, consider a shorter restart
interval to minimise the time the server is presenting an expired
certificate (e.g. hourly).

`mod_md` additionally supports the *ACME Renewal Information (ARI)*
extension (RFC 9773), and this behaviour is enabled by default.  If
the ACME server supports it, `mod_md` will query the renewal
resource each `MDCheckInterval` (default = 12 hours) and renew if
the server indicates it.
