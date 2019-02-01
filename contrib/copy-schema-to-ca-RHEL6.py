#! /usr/bin/python2

"""Copy the IPA schema to the CA directory server instance

You need to run this script to prepare a 2.2 or 3.0 IPA master for
installation of a 3.1 replica.

Once a 3.1 replica is in the domain, every older CA master will emit schema
replication errors until this script is run on it.

"""

# DO NOT TOUCH THIS CODE, IT MUST BE COMPATIBLE WITH RHEL6
# disable pylint because current codebase didn't match RHEL6 code
# pylint: disable=all

import os
import sys
import pwd
import shutil

from hashlib import sha1

from ipapython import ipautil
from ipapython.ipa_log_manager import root_logger, standard_logging_setup
from ipaserver.install.dsinstance import schema_dirname
from ipalib import api

# oh dear, this is an old IPA (3.0+)
from ipaserver.install.dsinstance import DS_USER
from ipaserver.install.cainstance import PKI_USER
from ipapython import services

# for mod_nss
from ipaserver.install.httpinstance import NSS_CONF
from ipaserver.install.httpinstance import HTTPInstance
from ipaserver.install import installutils
from ipapython import sysrestore

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


def _sha1_file(filename):
    with open(filename, 'rb') as f:
        return sha1(f.read()).hexdigest()


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
            target_sha1 = _sha1_file(target_fname)
            source_sha1 = _sha1_file(source_fname)
            if target_sha1 != source_sha1:
                target_size = os.stat(target_fname).st_size
                source_size = os.stat(source_fname).st_size
                root_logger.info('Target file %s exists but the content is '
                                 'different', target_fname)
                root_logger.info('\tTarget file: sha1: %s, size: %s B',
                                 target_sha1, target_size)
                root_logger.info('\tSource file: sha1: %s, size: %s B',
                                 source_sha1, source_size)
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


# The ipa-3-0 set_directive() has very loose comparision of directive
# which would cause multiple NSSCipherSuite to be added so provide
# a custom function for it.
def set_directive(filename, directive, value, quotes=True, separator=' '):
    """Set a name/value pair directive in a configuration file.

       A value of None means to drop the directive.

       This has only been tested with nss.conf
    """
    valueset = False
    st = os.stat(filename)
    fd = open(filename)
    newfile = []
    for line in fd:
        if line.lstrip().startswith(directive):
            valueset = True
            if value is not None:
                if quotes:
                    newfile.append('%s%s"%s"\n' %
                                   (directive, separator, value))
                else:
                    newfile.append('%s%s%s\n' % (directive, separator, value))
        else:
            newfile.append(line)
    fd.close()
    if not valueset:
        if value is not None:
            if quotes:
                newfile.append('%s%s"%s"\n' % (directive, separator, value))
            else:
                newfile.append('%s%s%s\n' % (directive, separator, value))

    fd = open(filename, "w")
    fd.write("".join(newfile))
    fd.close()
    os.chown(filename, st.st_uid, st.st_gid)  # reset perms


def update_mod_nss_cipher_suite():
    add_ciphers = ['ecdhe_rsa_aes_128_sha', 'ecdhe_rsa_aes_256_sha']
    ciphers = installutils.get_directive(NSS_CONF, 'NSSCipherSuite')

    # Run through once to see if any of the new ciphers are there but
    # disabled. If they are then enable them.
    lciphers = ciphers.split(',')
    new_ciphers = []
    for cipher in lciphers:
        for add in add_ciphers:
            if cipher.endswith(add):
                if cipher.startswith('-'):
                    cipher = '+%s' % add
        new_ciphers.append(cipher)

    # Run through again and add remaining ciphers as enabled.
    for add in add_ciphers:
        if add not in ciphers:
            new_ciphers.append('+%s' % add)

    ciphers = ','.join(new_ciphers)
    set_directive(NSS_CONF, 'NSSCipherSuite', ciphers, False)
    root_logger.info('Updated Apache cipher list')


def restart_http():
    root_logger.info('Restarting HTTP')
    fstore = sysrestore.FileStore('/var/lib/ipa/sysrestore')
    http = HTTPInstance(fstore)
    http.restart()


def main():
    if os.getegid() != 0:
        sys.exit("Must be root to run this script")
    standard_logging_setup(verbose=True)

    # In 3.0, restarting needs access to api.env
    api.bootstrap_with_global_options(context='server')

    add_ca_schema()
    restart_pki_ds()
    update_mod_nss_cipher_suite()
    restart_http()

    root_logger.info('Schema updated successfully')


if __name__ == '__main__':
    main()
