#
# Copyright (C) 2019  IPA Project Contributors, see COPYING for license
#
"""Export and wrap key from NSS DB
"""
import os

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.certdb import NSSDatabase
from . import common


def export_key(args, tmpdir):
    """Export key and certificate from the NSS DB

    The private key is encrypted using key wrapping.
    """
    wrapped_key_file = os.path.join(tmpdir, 'wrapped_key')
    certificate_file = os.path.join(tmpdir, 'certificate')

    ipautil.run([
        paths.PKI,
        '-d', args.nssdb_path,
        '-C', args.nssdb_pwdfile,
        'ca-authority-key-export',
        '--wrap-nickname', args.wrap_nickname,
        '--target-nickname', args.nickname,
        '--algorithm', args.algorithm,
        '-o', wrapped_key_file
    ])

    nssdb = NSSDatabase(args.nssdb_path)
    nssdb.run_certutil([
        '-L',
        '-n', args.nickname,
        '-a',
        '-o', certificate_file,
    ])
    with open(wrapped_key_file, 'rb') as f:
        wrapped_key = f.read()
    with open(certificate_file, 'r') as f:
        certificate = f.read()

    data = {
        'wrapped_key': wrapped_key,
        'certificate': certificate
    }
    common.json_dump(data, args.exportfile)


def default_parser():
    """Generic interface
    """
    parser = common.mkparser(
        supports_import=False,
        description='ipa-custodia NSS wrapped cert handler',
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
        '--wrap-nickname',
        dest='wrap_nickname',
        help='nick name of wrapping key',
        required=True
    )
    parser.add_argument(
        '--nickname',
        dest='nickname',
        help='nick name of target key',
        required=True
    )
    return parser


def pki_tomcat_parser():
    """Hard-code Dogtag's NSS DB, its password file, and CA key for wrapping
    """
    parser = common.mkparser(
        supports_import=False,
        description='ipa-custodia pki-tomcat NSS wrapped cert handler',
    )
    parser.add_argument(
        '--nickname',
        dest='nickname',
        help='nick name of target key',
        required=True
    )

    # Caller must specify a cipher.  This gets passed on to
    # the 'pki ca-authority-key-export' command (part of
    # Dogtag) via its own --algorithm option.
    parser.add_argument(
        '--algorithm',
        dest='algorithm',
        help='OID of symmetric wrap algorithm',
        required=True
    )

    parser.set_defaults(
        nssdb_path=paths.PKI_TOMCAT_ALIAS_DIR,
        nssdb_pwdfile=paths.PKI_TOMCAT_ALIAS_PWDFILE_TXT,
        wrap_nickname='caSigningCert cert-pki-ca',
    )
    return parser


def main(parser=None):
    if parser is None:
        parser = default_parser()

    common.main(parser, export_key, None)


if __name__ == '__main__':
    main()
