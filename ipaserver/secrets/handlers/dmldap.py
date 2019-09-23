#
# Copyright (C) 2019  IPA Project Contributors, see COPYING for license
#
"""Export / import Directory Manager password hash
"""
import json
import os

from ipalib import api
from ipalib import errors
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, realm_to_ldapi_uri
from . import common

CN_CONFIG = DN(('cn', 'config'))
ROOTPW = 'nsslapd-rootpw'


def export_key(args, tmpdir, conn):
    entry = conn.get_entry(CN_CONFIG, [ROOTPW])
    data = {
        'dmhash': entry.single_value[ROOTPW],
    }
    common.json_dump(data, args.exportfile)


def import_key(args, tmpdir, conn):
    data = json.load(args.importfile)
    dmhash = data['dmhash'].encode('ascii')
    entry = conn.get_entry(CN_CONFIG, [ROOTPW])
    entry.single_value[ROOTPW] = dmhash
    try:
        conn.update_entry(entry)
    except errors.EmptyModlist:
        pass


def main():
    parser = common.mkparser(
        description='ipa-custodia LDAP DM hash handler'
    )

    if os.getegid() != 0:
        parser.error("Must be run as root user.\n")

    # create LDAP connection using LDAPI and EXTERNAL bind as root
    if not api.isdone('bootstrap'):
        api.bootstrap(confdir=paths.ETC_IPA, log=None)
    realm = api.env.realm
    ldap_uri = realm_to_ldapi_uri(realm)
    conn = LDAPClient(ldap_uri=ldap_uri, no_schema=True)
    try:
        conn.external_bind()
    except Exception as e:
        parser.error("Failed to connect to {}: {}\n".format(ldap_uri, e))

    with conn:
        common.main(parser, export_key, import_key, conn=conn)


if __name__ == '__main__':
    main()
