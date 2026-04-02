"""
__main__.py — CLI entry point for the SSH S4U2Self/S4U2Proxy X.509 example.

Demonstrates the full client-side pipeline:
  keytab → attestation signing key → X.509 cert → S4U2Self creds
  → S4U2Proxy service ticket for HTTP/ipa-server (optional)

Requirements:
  pip install cryptography gssapi python-krb5

Usage:
  python -m s4u-x509 \\
      --user alice --realm EXAMPLE.COM --hostname server.example.com \\
      [--keytab /etc/krb5.keytab] \\
      [--host-pubkey /etc/ssh/ssh_host_ed25519_key.pub] \\
      [--auth-method publickey] \\
      [--user-pubkey /home/alice/.ssh/id_ed25519.pub] \\
      [--session-id <hex>] \\
      [--client-address 192.0.2.1:22] \\
      [--output-cert cert.der] \\
      [--ipa-server ipa.example.com]

  Or run directly:
  python __main__.py --user alice ...
"""

import argparse
import os
import sys

# Allow running as a standalone script from the directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import gssapi
except ImportError:
    print("Error: python-gssapi is required.  pip install gssapi",
          file=sys.stderr)
    sys.exit(1)

from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from ipapython.ssh import SSHPublicKey

from keytab import get_host_keytab_key
from cert import build_attestation_cert
from gss import acquire_s4u_creds, request_s4u_proxy


_HOST_KEY_CANDIDATES = [
    '/etc/ssh/ssh_host_ed25519_key.pub',
    '/etc/ssh/ssh_host_ecdsa_key.pub',
    '/etc/ssh/ssh_host_rsa_key.pub',
]


def _find_host_pubkey() -> str | None:
    for path in _HOST_KEY_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        prog='python -m s4u-x509',
        description='SSH S4U2Self X.509 attestation example client',
    )
    ap.add_argument('--user', required=True,
                    help='SSH username to impersonate')
    ap.add_argument('--realm', required=True,
                    help='Kerberos realm (e.g. EXAMPLE.COM)')
    ap.add_argument('--hostname', required=True,
                    help='SSH server hostname (e.g. server.example.com)')
    ap.add_argument('--keytab', default=None,
                    help='Path to host keytab (default: /etc/krb5.keytab)')
    ap.add_argument('--host-pubkey', default=None,
                    help='SSH host public key file '
                         '(default: first of /etc/ssh/ssh_host_*_key.pub)')
    ap.add_argument('--auth-method', default='password',
                    choices=['publickey', 'password', 'keyboard-interactive'],
                    help='SSH authentication method (default: password)')
    ap.add_argument('--session-id', default=None,
                    help='Session ID as hex bytes (default: 32 random bytes)')
    ap.add_argument('--client-address', default=None,
                    help='Client address string, e.g. "192.0.2.1:22"')
    ap.add_argument('--output-cert', default=None,
                    help='Write the DER-encoded certificate to this file')
    ap.add_argument('--user-pubkey', default=None,
                    help='User SSH public key file for publickey auth '
                         '(e.g. /home/alice/.ssh/id_ed25519.pub); '
                         'implies --auth-method publickey if not overridden')
    ap.add_argument('--ipa-server', default=None,
                    help='IPA server hostname for S4U2Proxy demonstration '
                         '(e.g. ipa.example.com); '
                         'requests HTTP/<hostname>@<realm>')
    args = ap.parse_args()

    # --- Session ID -------------------------------------------------------
    if args.session_id:
        try:
            session_id = bytes.fromhex(args.session_id)
        except ValueError as e:
            ap.error(f"--session-id: {e}")
    else:
        session_id = os.urandom(32)
        print(f"session-id (random): {session_id.hex()}")

    # --- Host public key --------------------------------------------------
    pubkey_path = args.host_pubkey or _find_host_pubkey()
    if pubkey_path is None:
        ap.error(
            "No host public key found in /etc/ssh/; "
            "pass --host-pubkey explicitly"
        )
    try:
        with open(pubkey_path, 'rb') as f:
            host_pubkey = load_ssh_public_key(f.read())
        print(f"Host public key:  {pubkey_path}")
    except FileNotFoundError:
        ap.error(f"host public key not found: {pubkey_path}")
    except ValueError as e:
        ap.error(f"cannot parse host public key {pubkey_path}: {e}")

    # --- Keytab entry -----------------------------------------------------
    try:
        keytab_entry = get_host_keytab_key(
            hostname=args.hostname,
            realm=args.realm,
            keytab_path=args.keytab,
        )
    except LookupError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Keytab error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Keytab principal: {keytab_entry.principal}")
    print(f"  enctype={keytab_entry.enctype}  kvno={keytab_entry.kvno}")

    # --- User public key (publickey auth) ---------------------------------
    user_pubkey = None
    key_fingerprint = None
    if args.user_pubkey:
        try:
            with open(args.user_pubkey, 'rb') as f:
                raw = f.read()
            ssh_key = SSHPublicKey(raw)
            key_fingerprint = ssh_key.fingerprint_hex_sha256()
            user_pubkey = load_ssh_public_key(raw)
            print(f"User public key:  {args.user_pubkey}")
            print(f"  fingerprint={key_fingerprint}")
            if args.auth_method != 'publickey':
                print(f"  note: --auth-method is '{args.auth_method}'; "
                      "KDB plugin will not verify the key "
                      "against ipasshpubkey")
        except FileNotFoundError:
            ap.error(f"user public key not found: {args.user_pubkey}")
        except ValueError as e:
            ap.error(f"cannot parse user public key {args.user_pubkey}: {e}")

    # --- Build attestation certificate ------------------------------------
    try:
        cert_der = build_attestation_cert(
            user=args.user,
            realm=args.realm,
            auth_method=args.auth_method,
            session_id=session_id,
            host_pubkey=host_pubkey,
            keytab_entry=keytab_entry,
            subject_pubkey=user_pubkey,
            key_fingerprint=key_fingerprint,
            client_address=args.client_address,
        )
    except Exception as e:
        print(f"Certificate build error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Attestation cert: {len(cert_der)} bytes  "
          f"method={args.auth_method}")

    if args.output_cert:
        with open(args.output_cert, 'wb') as f:
            f.write(cert_der)
        print(f"Written to:       {args.output_cert}")

    # --- GSSAPI S4U2Self --------------------------------------------------
    try:
        s4u_creds = acquire_s4u_creds(
            cert_der=cert_der,
            host_principal=keytab_entry.principal,
            keytab_path=args.keytab,
        )
    except gssapi.exceptions.GSSError as e:
        print(f"GSSAPI error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"S4U2Self error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"S4U2Self creds:   acquired for '{args.user}'")
    try:
        print(f"  lifetime={s4u_creds.lifetime}s")
    except Exception:
        pass

    # --- GSSAPI S4U2Proxy (constrained delegation) ------------------------
    if args.ipa_server:
        proxy_target = f"HTTP/{args.ipa_server}@{args.realm}"
        print(f"S4U2Proxy target: {proxy_target}")
        try:
            token = request_s4u_proxy(s4u_creds, proxy_target)
            print(f"S4U2Proxy token:  {len(token)} bytes  (AP-REQ assembled)")
        except gssapi.exceptions.GSSError as e:
            print(f"S4U2Proxy GSSAPI error: {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"S4U2Proxy error: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
