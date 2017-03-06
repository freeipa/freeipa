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

from hashlib import sha256

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipaserver.install.dsinstance import schema_dirname
from ipalib import api

try:
    # BE CAREFUL when using the constants module - you need to define all
    # the constants separately because of old IPA installations
    from ipaplatform.constants import constants
    PKI_USER = constants.PKI_USER
    DS_USER = constants.DS_USER
except ImportError:
    # oh dear, this is an old IPA (3.0+)
    from ipaserver.install.dsinstance import DS_USER   #pylint: disable=E0611
    from ipaserver.install.cainstance import PKI_USER  #pylint: disable=E0611

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


def _file_digest(filename):
    with open(filename, 'rb') as f:
        return sha256(f.read()).hexdigest()


def add_ca_schema():
    """Copy IPA schema files into the CA DS instance
    """
    pki_pent = pwd.getpwnam(PKI_USER)
    ds_pent = pwd.getpwnam(DS_USER)
    for schema_fname in SCHEMA_FILENAMES:
        source_fname = os.path.join(paths.USR_SHARE_IPA_DIR, schema_fname)
        target_fname = os.path.join(schema_dirname(SERVERID), schema_fname)
        if not os.path.exists(source_fname):
            root_logger.debug('File does not exist: %s', source_fname)
            continue
        if os.path.exists(target_fname):
            target_digest = _file_digest(target_fname)
            source_digest = _file_digest(source_fname)
            if target_digest != source_digest:
                target_size = os.stat(target_fname).st_size
                source_size = os.stat(source_fname).st_size
                root_logger.info('Target file %s exists but the content is '
                                 'different', target_fname)
                root_logger.info('\tTarget file: sha256: %s, size: %s B',
                                 target_digest, target_size)
                root_logger.info('\tSource file: sha256: %s, size: %s B',
                                 source_digest, source_size)
                if not ipautil.user_input("Do you want replace %s file?" %
                                          target_fname, True):
                    continue

            else:
                root_logger.info(
                    'Target exists, not overwriting: %s', target_fname)
                continue
        try:
            shutil.copyfile(source_fname, target_fname)
        except IOError as e:
            root_logger.warning('Could not install %s: %s', target_fname, e)
        else:
            root_logger.info('Installed %s', target_fname)
        os.chmod(target_fname, 0o440)    # read access for dirsrv user/group
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
    api.bootstrap_with_global_options(context='server', confdir=paths.ETC_IPA)

    add_ca_schema()
    restart_pki_ds()

    root_logger.info('Schema updated successfully')


if __name__ == '__main__':
    main()
