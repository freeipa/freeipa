---
back-href: acme-httpd-mod_md.md
back-text: ACME - Apache and mod_md
up-href: "../index.html#toc"
up-text: Up to index
---

# Using Certificate Transparency logs

Publicly trusted CAs are required to log all the certificates they
issue to *Certificate Transparency (CT)* logs.  The Certificate
Transparency system ensures that:

- CA compromise or misbehaviour can more easily be detected.
- For domain owners, unexpected issuance—a sign of compromise or
  abuse—can be quickly detected.

Relying parties (web browsers in particular) reject certificates
that do not contain or are not accompanied by *Signed Certificate
Timestamps (SCTs)*.  SCTs are verifiable evidence of inclusion in
trusted CT logs.  This is what ensures compliance.

As a domain owner, you can use CT logs to improve the security and
reliability of your infrastructure.

CT *monitors* are services that monitor CT logs, and aggregate,
index or process the data.  There is a [broad ecosystem](
https://certificate.transparency.dev/monitors/) of services
available.  Many of these require registration or a subscription—but
not all.  Monitoring and alerting features make CT log monitoring a
useful tool for information security teams.

In this module you'll perform some basic searches of CT logs.


## Searching CT logs

**[crt.sh]** is a free CT log search tool.  The Let's Encrypt
certificate you requested is probably already indexed, so [**visit
the site**][crt.sh] and search for your `$DOMAIN` name.

[crt.sh]: https://crt.sh/

There could be multiple hits for the certificate you issued (check
the **Logged At** timestamps).  View the certificate details (links
in the **crt.sh ID** column).  You will see a pretty-print of the
certificate.

One of the entries is a *precertificate*.  The precertificate
contains a special X.509 extension:

```
  CT Precertificate Poison: critical
      NULL
```

This is not the final certificate.  In fact, most software systems
deliberately do not implement this extension and will choke on it.

Rather, a precertificate is the CA's committment to sign a
certificate that is *almost* the same as the logged precertificate.
The only allowable difference is that the final certificate includes
SCTs generated upon logging the precertificate.  You can see the
SCTs in the pretty-print of the other log entry.  For example:

```
  CT Precertificate SCTs:
      Signed Certificate Timestamp:
          Version   : v1 (0x0)
          Log Name  : Cloudflare Nimbus 2026
          Log ID    : CB:38:F7:15:89:7C:84:A1:44:5F:5B:C1:DD:FB:C9:6E:
                      F2:9A:59:CD:47:0A:69:05:85:B0:CB:14:C3:14:58:E7
          Timestamp : Jan 19 14:36:25.241 2026 GMT
          Extensions: none
          Signature : ecdsa-with-SHA256
                      30:44:02:20:30:EA:BC:CE:C1:9B:04:CC:64:DD:BF:76:
                      9E:1A:9B:06:6B:F1:1F:14:7D:72:35:95:82:CD:50:CE:
                      0F:86:63:3C:02:20:28:B4:FD:DB:A0:B1:27:33:E7:B9:
                      8A:2B:E6:F9:10:AA:13:6A:AC:38:CF:3A:EC:E5:D1:CD:
                      D9:B2:60:44:01:6B
      Signed Certificate Timestamp:
          Version   : v1 (0x0)
          Log Name  : DigiCert Sphinx 2026h1
          Log ID    : 49:9C:9B:69:DE:1D:7C:EC:FC:36:DE:CD:87:64:A6:B8:
                      5B:AF:0A:87:80:19:D1:55:52:FB:E9:EB:29:DD:F8:C3
          Timestamp : Jan 19 14:36:25.232 2026 GMT
          Extensions: none
          Signature : ecdsa-with-SHA256
                      30:44:02:20:04:D7:37:B1:C1:3D:5C:19:13:59:E7:78:
                      D4:3C:F9:17:47:BB:50:61:18:DE:48:0A:CF:7D:A3:3D:
                      C9:90:C6:C2:02:20:4D:2F:C1:C3:EF:21:27:0E:2C:B5:
                      2F:79:CF:E0:1E:07:4B:0F:5B:8D:21:E4:20:F4:75:DF:
                      50:99:D9:BB:43:11
```
