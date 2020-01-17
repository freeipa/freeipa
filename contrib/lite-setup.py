#!/usr/bin/env python3
#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#
"""Configure lite-server environment.

See README.md for more details.
"""
import argparse
import os
import socket
from urllib.request import urlopen

DEFAULT_CONF = """\
[global]
host = {args.hostname}
server = {args.servername}
basedn = {args.basedn}
realm = {args.realm}
domain = {args.domain}
xmlrpc_uri = {args.xmlrpc_uri}
ldap_uri = ldap://{args.servername}
debug = {args.debug}
enable_ra = False
ra_plugin = dogtag
dogtag_version = 10
"""

KRB5_CONF = """\
[libdefaults]
 default_realm = {args.realm}
 dns_lookup_realm = false
 dns_lookup_kdc = false
 rdns = false
 ticket_lifetime = 24h
 forwardable = true
 udp_preference_limit = 0
 default_ccache_name = FILE:{args.ccache}

[realms]
 {args.realm} = {{
  kdc = {args.kdc}
  master_kdc = {args.kdc}
  admin_server = {args.kadmin}
  default_domain = ipa.example
  pkinit_anchors = FILE:{args.ca_crt}
  pkinit_pool = FILE:{args.ca_crt}
  http_anchors = FILE:{args.ca_crt}
}}

[domain_realm]
 .ipa.example = {args.realm}
 ipa.example = {args.realm}
 {args.servername} = {args.realm}
"""

LDAP_CONF = """\
URI ldaps://{args.servername}
BASE {args.basedn}
TLS_CACERT {args.ca_crt}
SASL_MECH GSSAPI
SASL_NOCANON on
"""

IPA_BIN = """\
#!/bin/sh
exec python3 -m ipaclient $*
"""

ACTIVATE = """\
deactivate_ipaenv () {{
    export PS1="${{_OLD_IPAENV_PS1}}"
    export PATH="${{_OLD_IPAENV_PATH}}"
    unset _OLD_IPAENV_PS1
    unset _OLD_IPAENV_PATH
    unset KRB5_CONFIG
    unset KRB5CCNAME
    unset LDAPCONF
    unset IPA_CONFDIR
    unset PYTHONPATH
    unset -f deactivate_ipaenv
}}

export _OLD_IPAENV_PS1="${{PS1:-}}"
export _OLD_IPAENV_PATH="${{PATH:-}}"
export PS1="(ipaenv) ${{PS1:-}}"
export PATH="{args.dot_ipa}:${{PATH:-}}"
export KRB5_CONFIG="{args.krb5_conf}"
export KRB5CCNAME="{args.ccache}"
{args.tracecomment}export KRB5_TRACE=/dev/stderr
export LDAPCONF="{args.ldap_conf}"
export IPA_CONFDIR="{args.dot_ipa}"
export PYTHONPATH="{args.basedir}"
"""

MSG = """\
Configured for server '{args.servername}' and realm '{args.realm}'.

To activate the IPA test env:

    source {args.activate}
    kinit
    make lite-server

To deactivate the IPA test env and to unset the env vars:

    deactivate_ipaenv

The source file configures the env vars:

    export KRB5_CONFIG="{args.krb5_conf}"
    export KRB5CCNAME="{args.ccache}"
    export LDAPCONF="{args.ldap_conf}"
    export IPA_CONFDIR="{args.dot_ipa}"
    export PYTHONPATH="{args.basedir}"
"""

parser = argparse.ArgumentParser()
parser.add_argument("servername", help="IPA server name")
parser.add_argument("domain", default=None, nargs="?")
parser.add_argument(
    "--kdcproxy", action="store_true", help="Use KRB5 over HTTPS (KDC-Proxy)"
)
parser.add_argument(
    "--debug",
    action="store_true",
    help="Enable debug mode for lite-server and KRB5",
)
parser.add_argument(
    "--remote-server",
    action="store_true",
    help="Configure client to use a remote server instead of lite-server",
)


def main():
    args = parser.parse_args()
    if args.domain is None:
        args.domain = args.servername.lower().split(".", 1)[1]
    else:
        args.domain = args.domain.lower().rstrip(".")
    args.realm = args.domain.upper()
    args.hostname = socket.gethostname()
    args.basedn = ",".join(f"dc={part}" for part in args.domain.split("."))
    args.tracecomment = "" if args.debug else "#"

    if args.kdcproxy:
        args.kdc = f"https://{args.servername}/KdcProxy"
        args.kadmin = f"https://{args.servername}/KdcProxy"
    else:
        args.kdc = f"{args.servername}:88"
        args.kadmin = f"{args.servername}:749"

    if args.remote_server:
        args.xmlrpc_uri = f"https://{args.servername}/ipa/xml"
    else:
        args.xmlrpc_uri = f"http://localhost:8888/ipa/xml"

    args.basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    args.dot_ipa = os.path.expanduser("~/.ipa")
    args.default_conf = os.path.join(args.dot_ipa, "default.conf")
    args.ca_crt = os.path.join(args.dot_ipa, "ca.crt")
    args.krb5_conf = os.path.join(args.dot_ipa, "krb5.conf")
    args.ldap_conf = os.path.join(args.dot_ipa, "ldap.conf")
    args.ccache = os.path.join(args.dot_ipa, "ccache")
    args.ipa_bin = os.path.join(args.dot_ipa, "ipa")
    args.activate = os.path.join(args.dot_ipa, "activate.sh")

    if not os.path.isdir(args.dot_ipa):
        os.makedirs(args.dot_ipa, mode=0o750)

    with urlopen(f"http://{args.servername}/ipa/config/ca.crt") as req:
        ca_data = req.read()
    with open(args.ca_crt, "wb") as f:
        f.write(ca_data)
    with open(args.default_conf, "w") as f:
        f.write(DEFAULT_CONF.format(args=args))
    with open(args.krb5_conf, "w") as f:
        f.write(KRB5_CONF.format(args=args))
    with open(args.ldap_conf, "w") as f:
        f.write(LDAP_CONF.format(args=args))
    with open(args.ipa_bin, "w") as f:
        f.write(IPA_BIN.format(args=args))
        os.fchmod(f.fileno(), 0o755)
    with open(args.activate, "w") as f:
        f.write(ACTIVATE.format(args=args))

    print(MSG.format(args=args))


if __name__ == "__main__":
    main()
