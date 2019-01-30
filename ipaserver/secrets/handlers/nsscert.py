#
# Copyright (C) 2019  IPA Project Contributors, see COPYING for license
#
"""Export / import cert and key from NSS DB as PKCS#12 data
"""
import base64
import json
import os

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.certdb import NSSDatabase
from . import common


def export_key(args, tmpdir):
    """Export key and certificate from the NSS DB to a PKCS#12 file.

    The PKCS#12 file is encrypted with a password.
    """
    pk12file = os.path.join(tmpdir, 'export.p12')

    password = ipautil.ipa_generate_password()
    pk12pk12pwfile = os.path.join(tmpdir, 'passwd')
    with open(pk12pk12pwfile, 'w') as f:
        f.write(password)

    nssdb = NSSDatabase(args.nssdb_path)
    nssdb.run_pk12util([
        "-o", pk12file,
        "-n", args.nickname,
        "-k", args.nssdb_pwdfile,
        "-w", pk12pk12pwfile,
    ])

    with open(pk12file, 'rb') as f:
        p12data = f.read()

    data = {
        'export password': password,
        'pkcs12 data': p12data,
    }
    common.json_dump(data, args.exportfile)


def import_key(args, tmpdir):
    """Import key and certificate from a PKCS#12 file to a NSS DB.
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

    nssdb = NSSDatabase(args.nssdb_path)
    nssdb.run_pk12util([
        "-i", pk12file,
        "-n", args.nickname,
        "-k", args.nssdb_pwdfile,
        "-w", pk12pwfile,
    ])


def default_parser():
    """Generic interface
    """
    parser = common.mkparser(
        description='ipa-custodia NSS cert handler'
    )
    parser.add_argument(
        '--nssdb',
        dest='nssdb_path',
        help='path to NSS DB',
        required=True
    )
    parser.add_argument(
        '--pwdfile',
        dest='nssdb_pwdfile',
        help='path to password file for NSS DB',
        required=True
    )
    parser.add_argument(
        '--nickname',
        help='nick name of certificate',
        required=True
    )
    return parser


def pki_tomcat_parser():
    """Hard-code Dogtag's NSSDB and its password file
    """
    parser = common.mkparser(
        description='ipa-custodia pki-tomcat NSS cert handler'
    )
    parser.add_argument(
        '--nickname',
        help='nick name of certificate',
        required=True
    )
    parser.set_defaults(
        nssdb_path=paths.PKI_TOMCAT_ALIAS_DIR,
        nssdb_pwdfile=paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
    )
    return parser


def main(parser=None):
    if parser is None:
        parser = default_parser()

    common.main(parser, export_key, import_key)


if __name__ == '__main__':
    main()
