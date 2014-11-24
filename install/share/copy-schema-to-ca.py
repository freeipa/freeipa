#! /usr/bin/python2

"""Copy the IPA schema to the CA directory server instance

You need to run this script to prepare a 2.2 or 3.0 IPA master for
installation of a 3.1 replica.

Once a 3.1 replica is in the domain, every older CA master will emit schema
replication errors until this script is run on it.

"""

import os
import sys
import pwd
import shutil

from ipapython import ipautil, dogtag
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipaserver.install.dsinstance import DS_USER, schema_dirname
from ipaserver.install.cainstance import PKI_USER
from ipalib import api

try:
    from ipaplatform import services
except ImportError:
    from ipapython import services  # pylint: disable=no-name-in-module

SERVERID = "PKI-IPA"
SCHEMA_FILENAMES = (
    "60kerberos.ldif",
    "60samba.ldif",
    "60ipaconfig.ldif",
    "60basev2.ldif",
    "60basev3.ldif",
    "60ipadns.ldif",
    "61kerberos-ipav3.ldif",
    "65ipacertstore.ldif",
    "65ipasudo.ldif",
    "70ipaotp.ldif",
    "05rfc2247.ldif",
)


def add_ca_schema():
    """Copy IPA schema files into the CA DS instance
    """
    pki_pent = pwd.getpwnam(PKI_USER)
    ds_pent = pwd.getpwnam(DS_USER)
    for schema_fname in SCHEMA_FILENAMES:
        source_fname = os.path.join(ipautil.SHARE_DIR, schema_fname)
        target_fname = os.path.join(schema_dirname(SERVERID), schema_fname)
        if not os.path.exists(source_fname):
            root_logger.debug('File does not exist: %s', source_fname)
            continue
        if os.path.exists(target_fname):
            root_logger.info(
                'Target exists, not overwriting: %s', target_fname)
            continue
        try:
            shutil.copyfile(source_fname, target_fname)
        except IOError, e:
            root_logger.warning('Could not install %s: %s', target_fname, e)
        else:
            root_logger.info('Installed %s', target_fname)
        os.chmod(target_fname, 0440)    # read access for dirsrv user/group
        os.chown(target_fname, pki_pent.pw_uid, ds_pent.pw_gid)


def restart_pki_ds():
    """Restart the CA DS instance to pick up schema changes
    """
    root_logger.info('Restarting CA DS')
    services.service('dirsrv').restart(SERVERID)


def main():
    if os.getegid() != 0:
        sys.exit("Must be root to run this script")
    standard_logging_setup(verbose=True)

    # In 3.0, restarting needs access to api.env
    (options, argv) = api.bootstrap_with_global_options(context='server')

    add_ca_schema()
    restart_pki_ds()

    root_logger.info('Schema updated successfully')


main()
