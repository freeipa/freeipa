#
# Copyright (C) 2019  IPA Project Contributors, see COPYING for license
#
"""Export / import PEM cert and key file as PKCS#12 data
"""
import base64
import json
import os

from ipaplatform.paths import paths
from ipapython import ipautil
from . import common


def export_key(args, tmpdir):
    """Export cert and private from PEM files as PKCS#12 file.

    The PKCS#12 file is encrypted with a password.
    """
    pk12file = os.path.join(tmpdir, 'export.p12')

    password = ipautil.ipa_generate_password()
    pk12pwfile = os.path.join(tmpdir, 'passwd')
    with open(pk12pwfile, 'w') as f:
        f.write(password)

    # OpenSSL does not support pkcs12 export of a cert without key
    ipautil.run([
        paths.OPENSSL, 'pkcs12', '-export',
        '-in', args.certfile,
        '-out', pk12file,
        '-inkey', args.keyfile,
        '-password', 'file:{pk12pwfile}'.format(pk12pwfile=pk12pwfile),
    ])

    with open(pk12file, 'rb') as f:
        p12data = f.read()

    data = {
        'export password': password,
        'pkcs12 data': p12data,
    }
    common.json_dump(data, args.exportfile)


def import_key(args, tmpdir):
    """Export key and certificate from a PKCS#12 file to key and cert files.
    """
    data = json.load(args.importfile)
    password = data['export password']
    p12data = base64.b64decode(data['pkcs12 data'])

    pk12pwfile = os.path.join(tmpdir, 'passwd')
    with open(pk12pwfile, 'w') as f:
        f.write(password)

    pk12file = os.path.join(tmpdir, 'import.p12')
    with open(pk12file, 'wb') as f:
        f.write(p12data)

    # get the certificate from the file
    cmd = [
        paths.OPENSSL, 'pkcs12',
        '-in', pk12file,
        '-clcerts', '-nokeys',
        '-out', args.certfile,
        '-password', 'file:{pk12pwfile}'.format(pk12pwfile=pk12pwfile),
    ]
    ipautil.run(cmd, umask=0o027)

    # get the private key from the file
    cmd = [
        paths.OPENSSL, 'pkcs12',
        '-in', pk12file,
        '-nocerts', '-nodes',
        '-out', args.keyfile,
        '-password', 'file:{pk12pwfile}'.format(pk12pwfile=pk12pwfile),
    ]
    ipautil.run(cmd, umask=0o027)


def default_parser():
    parser = common.mkparser(
        description='ipa-custodia PEM file handler'
    )
    parser.add_argument(
        '--certfile',
        help='path to PEM encoded cert file',
        required=True
    )
    parser.add_argument(
        'keyfile',
        help='path to PEM encoded key file',
        required=True
    )
    return parser


def ra_agent_parser():
    parser = common.mkparser(
        description='ipa-custodia RA agent cert handler'
    )
    parser.set_defaults(
        certfile=paths.RA_AGENT_PEM,
        keyfile=paths.RA_AGENT_KEY
    )
    return parser


def main(parser=None):
    if parser is None:
        parser = default_parser()

    common.main(parser, export_key, import_key)


if __name__ == '__main__':
    main()
