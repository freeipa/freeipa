---
back-href: ipa-external-ca.html
back-text: Externally signing the FreeIPA CA
up-href: "../index.html#toc"
up-text: Up to index
---

# The FreeIPA ACME server

ACME is not only for the public internet.  The protocol can be used
in enterprise environments for its automation benefits, which can
reduce downtime and configuration errors that lead to security
issues.

The FreeIPA CA includes an ACME subsystem.  In this module, you will
enable it and use an ACME client to request a certificate.


## Enable the ACME service

::: note

Perform the steps in this section on **`ipa.$DOMAIN`**.

:::

On each FreeIPA ACME server in your deployment (in our case, that's
just `ipa.$DOMAIN`, execute `ipa-acme-manage enable` as `root`.


```command {.ipa}
sudo ipa-acme-manage enable
```
```output
The ipa-acme-manage command was successful
```


If you issue a lot of short-lived certificates, for performance
reasons you should enable ***pruning*** to purge expired
certificates from the CA's database.

```command {.ipa}
sudo ipa-acme-manage pruning --enable
```
```output
Status: enabled
Certificate Retention Time: 30
Certificate Retention Unit: day
Certificate Search Size Limit: 1000
Certificate Search Time Limit: 0
Request Retention Time: day
Request Retention Unit: 30
Request Search Size Limit: 1000
Request Search Time Limit: 0
cron Schedule:
The CA service must be restarted for changes to take effect
The ipa-acme-manage command was successful
```

As noted in the output, you need to restart the CA service.  You
*could* run `sudo ipactl restart` to restart the *entire* FreeIPA
system.  But to restart just the CA, do this:

```command {.ipa}
sudo systemctl restart pki-tomcatd@pki-tomcat
```


## Request a certificate for `client`

::: note

**Jump over to `client.$DOMAIN` for this section!**

:::

We'll use the [Certbot](https://certbot.eff.org/) ACME client, which
is developed by the EFF.  Install the package:

```command {.client}
sudo dnf install -y certbot
```

::: note

Certbot is an *astoundingly* versatile program.  This module uses it
in a basic way.  Its purpose is to teach you about the FreeIPA ACME
service, not Certbot wizardry.

:::

By default Certbot wants to read and write system directories.  Make
a user-local directory to store the data instead, so that we can run
Certbot as an unprivileged process.

```command {.client}
mkdir ~/certbot
```

Create a config file that will tell Certbot to use the local
directory:

```command {.client}
sudo tee ~/certbot/cli.ini >/dev/null <<EOF
config-dir = $HOME/certbot/config
work-dir = $HOME/certbot/work
logs-dir = $HOME/certbot/logs
server = https://ipa-ca.$DOMAIN/acme/directory
EOF
```

The `server` directive tells Certbot to use the specified CA instead
of Let's Encrypt.  It points to the FreeIPA ACME service URI.

::: note

`ipa-ca.$DOMAIN` is a DNS alias that points to the FreeIPA CA
server(s).

:::

Now register an account with FreeIPA's ACME service.  Note that
these accounts are unrelated to the FreeIPA domain accounts.

```command {.client}
certbot --config ~/certbot/cli.ini register \
  --email nope@example.com --agree-tos --no-eff-email
```
```output
Saving debug log to /home/fedora/certbot/logs/letsencrypt.log
Account registered.
```

`--email`
: provide your contact email (it's part of the protocol, but
  the FreeIPA ACME server doesn't do anything with it)

`--agree-tos`
: agree to the terms of service of the ACME server

`--no-eff-email`
: suppress the "share email with EFF" prompt
  (which is only relevant when using Let's Encrypt anyway).


Certbot has a built in HTTP server it can use to satisfy the ACME
`http-01` domain validation challenge.  To use this feature as an
unprivileged user, we will tweak a `sysctl` to tell the kernel not
to restrict use of port 80 and up.

```command {.client}
sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80
```

Let port 80 through the firewall:

```command {.client}
sudo firewall-cmd --permanent --add-service=http \
  && sudo firewall-cmd --reload
```

Now tell `certbot` to request a certificate for the host's domain
name, using the `--standalone` HTTP server.

```command {.client}
certbot --config ~/certbot/cli.ini certonly \
  --standalone \
  --key-type rsa \
  --domain $(hostname)
```
```output
Saving debug log to /home/fedora/certbot/logs/letsencrypt.log
Requesting a certificate for client.e1.__BASE_DOMAIN__

Successfully received certificate.
Certificate is saved at: /home/fedora/certbot/config/live/client.e1.__BASE_DOMAIN__/fullchain.pem
Key is saved at:         /home/fedora/certbot/config/live/client.e1.__BASE_DOMAIN__/privkey.pem
This certificate expires on 2026-04-20.
These files will be updated when the certificate renews.
Certbot has set up a scheduled task to automatically renew this certificate in the background.

- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
If you like Certbot, please consider supporting our work by:
 * Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
 * Donating to EFF:                    https://eff.org/donate-le
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
```

Inspect the certificate issuer:

```command {.client}
openssl x509 -issuer -noout \
  -in ~/certbot/config/live/$(hostname)/fullchain.pem
```
```output
issuer=O=E1.__BASE_REALM__, CN=Certificate Authority
```

Indeed we see that the FreeIPA CA issued this certificate!
