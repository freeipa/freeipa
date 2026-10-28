# In-tree development debugging and testing

lite-server and lite-client enable fast development, debugging, and
performance analysis of server or client code from an in-tree source
directory. The lite-server runs a local web server that uses a remote
LDAP and KRB5 server.

## Prerequisites

### Remote IPA server

Lite-server and lite-client require a running IPA server. The server
should have a similar LDAP schema and IPA version as the in-tree
sources. Some features may not work if the differences are too great.

The lite-server only needs a working LDAP server and KRB5 server. For
KdcProxy or CA-related features the Apache HTTPd and pki-tomcatd service
must be running, too.

If the lite-client is configured for remote-server instead of
lite-server, then the lite-client uses the HTTP API of the remote
server.

### Local setup

1. Configure and build FreeIPA according to ``BUILD.txt``, TL;DR

```
$ sudo dnf builddep -b --spec freeipa.spec.in --best --allowerasing --setopt=install_weak_deps=False
$ ./autogen.sh
$ make
```

2. Install additional dependencies for the lite-server

```
sudo dnf install -y python3-werkzeug python3-watchdog
```

3. The FQDN of the remote IPA server must be resolvable. In case the
server does not have a valid DNS entry, it is possible to add the
hostname and IP address to ``/etc/hosts``.

4. Create configuration files in ``~/.ipa``. The lite-server requires
an IPA configuration, CA certificate file, KRB5 configuration,
Kerberos TGT and a file based credential cache. The script
``contrib/lite-setup.py`` can create a all necessary files for you
and sets up ``default.conf``, ``krb5.conf``, ``ca.crt``, and
even ``ldap.conf``:

```
$ contrib/lite-setup.py master.ipa.example
```

5. Setup environment variables: the lite-setup script also creates a
shell source file that activates a virtualenv like environment. The
source files sets several environment variables for PATH, KRB5, LDAP,
IPA, and Python. The env allows you to run the lite server, ``ipa``
client commands, or OpenLDAP commands:

```
$ source ~/.ipa/activate.sh
```

4. Acquire a TGT

```
(ipaenv) $ kinit username
```

5. Run the lite-server

```
(ipaenv) $ make lite-server
```

6. Run ``ipa`` client commands in another shell session. The lite-setup
scripts provides a wrapper that uses the development sources, too.

```
$ source ~/.ipa/activate.sh
(ipaenv) $ which ipa
~/.ipa/ipa
(ipaenv) $ ipa ping
```

7. Deactivate the environment

```
(ipaenv) $ deactivate_ipaenv
```

## Limitations

The lite-server does not have access to the ra-agent certificate.
Therefore most CA and KRA (vault) operations are not supported.

## Tricks and tips

The lite-server has a functional Web UI at
http://localhost:8888/ipa/xml. The session is already authenticated
with the current TGT.

The lite-setup script has additional options

* ``--kdcproxy`` configures ``krb5.conf`` for Kerberos over HTTPS
* ``--debug`` enables IPA and KRB5 debugging
* ``--remote-server`` lets you run local client commands without a
  local lite-server.

The ``make lite-server`` command supports arguments like
``PYTHON=/path/to/custom/interpreter`` or
``LITESERVER_ARGS='--enable-profiler=-'``.

By default the dev server supports HTTP only. To switch to HTTPS, you
can put a PEM file at ~/.ipa/lite.pem. The PEM file must contain a
server certificate, its unencrypted private key and intermediate chain
certs (if applicable).
