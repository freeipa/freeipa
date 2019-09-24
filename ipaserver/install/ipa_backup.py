# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import absolute_import, print_function

import logging
import optparse  # pylint: disable=deprecated-module
import os
import shutil
import sys
import tempfile
import time
import pwd

import six

from ipaplatform.paths import paths
from ipaplatform import services
from ipalib import api, errors
from ipapython import version
from ipapython.ipautil import run, write_tmp_file
from ipapython import admintool, certdb
from ipapython.dn import DN
from ipaserver.install.replication import wait_for_task
from ipaserver.install import installutils
from ipapython import ipaldap
from ipaplatform.constants import constants
from ipaplatform.tasks import tasks

# pylint: disable=import-error
if six.PY3:
    # The SafeConfigParser class has been renamed to ConfigParser in Py3
    from configparser import ConfigParser as SafeConfigParser
else:
    from ConfigParser import SafeConfigParser
# pylint: enable=import-error
ISO8601_DATETIME_FMT = '%Y-%m-%dT%H:%M:%S'

logger = logging.getLogger(__name__)

"""
A test GnuPG key can be generated like this:

# cat >keygen <<EOF
%echo Generating a standard key
Key-Type: RSA
Key-Length: 2048
Name-Real: IPA Backup
Name-Comment: IPA Backup
Name-Email: root@example.com
Expire-Date: 0
Passphrase: SecretPassPhrase42
%commit
%echo done
EOF
# export GNUPGHOME=/root/backup
# mkdir -p $GNUPGHOME
# gpg2 --batch --gen-key keygen
# gpg2 --list-secret-keys
"""


def encrypt_file(filename, remove_original=True):
    source = filename
    dest = filename + '.gpg'

    args = [
        paths.GPG2,
        '--batch',
        '--default-recipient-self',
        '--output', dest,
        '--encrypt', source,
    ]

    result = run(args, raiseonerr=False)
    if result.returncode != 0:
        raise admintool.ScriptError('gpg failed: %s' % result.error_log)

    if remove_original:
        os.unlink(source)

    return dest


class Backup(admintool.AdminTool):
    command_name = 'ipa-backup'
    log_file_name = paths.IPABACKUP_LOG

    usage = "%prog [options]"

    description = "Back up IPA files and databases."

    dirs = (paths.IPA_HTML_DIR,
            paths.ROOT_PKI,
            paths.PKI_TOMCAT,
            paths.SYSCONFIG_PKI,
            paths.VAR_LIB_PKI_DIR,
            paths.SYSRESTORE,
            paths.IPA_CLIENT_SYSRESTORE,
            paths.IPA_DNSSEC_DIR,
            paths.SSSD_PUBCONF_KRB5_INCLUDE_D_DIR,
            paths.AUTHCONFIG_LAST,
            paths.VAR_LIB_CERTMONGER_DIR,
            paths.VAR_LIB_IPA,
            paths.VAR_RUN_DIRSRV_DIR,
            paths.DIRSRV_LOCK_DIR,
    )

    files = (
        paths.NAMED_CONF,
        paths.NAMED_CUSTOM_CONFIG,
        paths.NAMED_KEYTAB,
        paths.RESOLV_CONF,
        paths.SYSCONFIG_PKI_TOMCAT,
        paths.SYSCONFIG_DIRSRV,
        paths.SYSCONFIG_KRB5KDC_DIR,
        paths.SYSCONFIG_IPA_DNSKEYSYNCD,
        paths.SYSCONFIG_IPA_ODS_EXPORTER,
        paths.SYSCONFIG_NAMED,
        paths.SYSCONFIG_ODS,
        paths.ETC_SYSCONFIG_AUTHCONFIG,
        paths.IPA_NSSDB_PWDFILE_TXT,
        paths.IPA_P11_KIT,
        paths.SYSTEMWIDE_IPA_CA_CRT,
        paths.NSSWITCH_CONF,
        paths.KRB5_KEYTAB,
        paths.SSSD_CONF,
        paths.OPENLDAP_LDAP_CONF,
        paths.LIMITS_CONF,
        paths.HTTPD_PASSWORD_CONF,
        paths.HTTP_KEYTAB,
        paths.HTTPD_IPA_KDCPROXY_CONF,
        paths.HTTPD_IPA_PKI_PROXY_CONF,
        paths.HTTPD_IPA_REWRITE_CONF,
        paths.HTTPD_SSL_CONF,
        paths.HTTPD_SSL_SITE_CONF,
        paths.HTTPD_CERT_FILE,
        paths.HTTPD_KEY_FILE,
        paths.HTTPD_IPA_CONF,
        paths.SSHD_CONFIG,
        paths.SSH_CONFIG,
        paths.KRB5_CONF,
        paths.KDC_CA_BUNDLE_PEM,
        paths.CA_BUNDLE_PEM,
        paths.IPA_CA_CRT,
        paths.IPA_DEFAULT_CONF,
        paths.DS_KEYTAB,
        paths.CHRONY_CONF,
        paths.SMB_CONF,
        paths.SAMBA_KEYTAB,
        paths.DOGTAG_ADMIN_P12,
        paths.RA_AGENT_PEM,
        paths.RA_AGENT_KEY,
        paths.CACERT_P12,
        paths.KRACERT_P12,
        paths.KRB5KDC_KDC_CONF,
        paths.KDC_CERT,
        paths.KDC_KEY,
        paths.CACERT_PEM,
        paths.SYSTEMD_IPA_SERVICE,
        paths.SYSTEMD_SYSTEM_HTTPD_IPA_CONF,
        paths.SYSTEMD_SSSD_SERVICE,
        paths.SYSTEMD_CERTMONGER_SERVICE,
        paths.SYSTEMD_PKI_TOMCAT_SERVICE,
        paths.SVC_LIST_FILE,
        paths.OPENDNSSEC_CONF_FILE,
        paths.OPENDNSSEC_KASP_FILE,
        paths.OPENDNSSEC_ZONELIST_FILE,
        paths.OPENDNSSEC_KASP_DB,
        paths.DNSSEC_SOFTHSM2_CONF,
        paths.DNSSEC_SOFTHSM_PIN_SO,
        paths.IPA_ODS_EXPORTER_KEYTAB,
        paths.IPA_DNSKEYSYNCD_KEYTAB,
        paths.IPA_CUSTODIA_KEYS,
        paths.IPA_CUSTODIA_CONF,
        paths.GSSPROXY_CONF,
        paths.HOSTS,
        paths.SYSTEMD_PKI_TOMCAT_IPA_CONF,
    ) + tuple(
        os.path.join(paths.IPA_NSSDB_DIR, file)
        for file in (certdb.NSS_DBM_FILES + certdb.NSS_SQL_FILES)
    ) + tasks.get_pkcs11_modules()

    logs=(
      paths.VAR_LOG_PKI_DIR,
      paths.VAR_LOG_HTTPD_DIR,
      paths.IPASERVER_INSTALL_LOG,
      paths.KADMIND_LOG,
      paths.MESSAGES,
      paths.IPACLIENT_INSTALL_LOG,
      paths.LOG_SECURE,
      paths.IPASERVER_UNINSTALL_LOG,
      paths.IPACLIENT_UNINSTALL_LOG,
      paths.NAMED_RUN,
    )

    required_dirs=(
      paths.TOMCAT_TOPLEVEL_DIR,
      paths.TOMCAT_CA_DIR,
      paths.TOMCAT_SIGNEDAUDIT_DIR,
      paths.TOMCAT_CA_ARCHIVE_DIR,
      paths.TOMCAT_KRA_DIR,
      paths.TOMCAT_KRA_SIGNEDAUDIT_DIR,
      paths.TOMCAT_KRA_ARCHIVE_DIR,
    )

    def __init__(self, options, args):
        super(Backup, self).__init__(options, args)
        self._conn = None
        self.files = list(self.files)
        self.dirs = list(self.dirs)
        self.logs = list(self.logs)

    @classmethod
    def add_options(cls, parser):
        super(Backup, cls).add_options(parser, debug_option=True)

        parser.add_option(
            "--gpg-keyring", dest="gpg_keyring",
            help=optparse.SUPPRESS_HELP)
        parser.add_option(
            "--gpg", dest="gpg", action="store_true",
            default=False, help="Encrypt the backup")
        parser.add_option(
            "--data", dest="data_only", action="store_true",
            default=False, help="Backup only the data")
        parser.add_option(
            "--logs", dest="logs", action="store_true",
            default=False, help="Include log files in backup")
        parser.add_option(
            "--online", dest="online", action="store_true",
            default=False,
            help="Perform the LDAP backups online, for data only.")


    def setup_logging(self, log_file_mode='a'):
        super(Backup, self).setup_logging(log_file_mode='a')


    def validate_options(self):
        options = self.options
        super(Backup, self).validate_options(needs_root=True)
        installutils.check_server_configuration()

        if options.gpg_keyring is not None:
            print(
                "--gpg-keyring is no longer supported, use GNUPGHOME "
                "environment variable to use a custom GnuPG2 directory.",
                file=sys.stderr
            )
            options.gpg = True

        if options.online and not options.data_only:
            self.option_parser.error("You cannot specify --online "
                "without --data")

        if options.gpg:
            tmpfd = write_tmp_file('encryptme')
            newfile = encrypt_file(tmpfd.name, False)
            os.unlink(newfile)

        if options.data_only and options.logs:
            self.option_parser.error("You cannot specify --data "
                "with --logs")


    def run(self):
        options = self.options
        super(Backup, self).run()

        api.bootstrap(in_server=True, context='backup', confdir=paths.ETC_IPA)
        api.finalize()

        logger.info("Preparing backup on %s", api.env.host)

        pent = pwd.getpwnam(constants.DS_USER)

        self.top_dir = tempfile.mkdtemp("ipa")
        os.chown(self.top_dir, pent.pw_uid, pent.pw_gid)
        os.chmod(self.top_dir, 0o750)
        self.dir = os.path.join(self.top_dir, "ipa")
        os.mkdir(self.dir, 0o750)
        os.chown(self.dir, pent.pw_uid, pent.pw_gid)
        self.tarfile = None

        self.header = os.path.join(self.top_dir, 'header')

        cwd = os.getcwd()
        try:
            dirsrv = services.knownservices.dirsrv

            self.add_instance_specific_data()

            # We need the dirsrv running to get the list of services
            dirsrv.start(capture_output=False)

            self.get_connection()

            self.create_header(options.data_only)
            if options.data_only:
                if not options.online:
                    logger.info('Stopping Directory Server')
                    dirsrv.stop(capture_output=False)
            else:
                logger.info('Stopping IPA services')
                run([paths.IPACTL, 'stop'])

            instance = ipaldap.realm_to_serverid(api.env.realm)
            if os.path.exists(paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE %
                              instance):
                if os.path.exists(paths.SLAPD_INSTANCE_DB_DIR_TEMPLATE %
                                  (instance, 'ipaca')):
                    self.db2ldif(instance, 'ipaca', online=options.online)
                self.db2ldif(instance, 'userRoot', online=options.online)
                self.db2bak(instance, online=options.online)
            if not options.data_only:
                # create backup of auth configuration
                auth_backup_path = os.path.join(paths.VAR_LIB_IPA, 'auth_backup')
                tasks.backup_auth_configuration(auth_backup_path)
                self.file_backup(options)

            if options.data_only:
                if not options.online:
                    logger.info('Starting Directory Server')
                    dirsrv.start(capture_output=False)
            else:
                logger.info('Starting IPA service')
                run([paths.IPACTL, 'start'])

            # Compress after services are restarted to minimize
            # the unavailability window
            if not options.data_only:
                self.compress_file_backup()

            self.finalize_backup(options.data_only, options.gpg,
                                 options.gpg_keyring)

        finally:
            try:
                os.chdir(cwd)
            except Exception as e:
                logger.error('Cannot change directory to %s: %s', cwd, e)
            shutil.rmtree(self.top_dir)


    def add_instance_specific_data(self):
        '''
        Add instance-specific files and directories.

        NOTE: this adds some things that may not get backed up.
        '''
        serverid = ipaldap.realm_to_serverid(api.env.realm)

        for dir in [paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid,
                    paths.VAR_LIB_DIRSRV_INSTANCE_SCRIPTS_TEMPLATE % serverid,
                    paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE % serverid]:
            if os.path.exists(dir):
                self.dirs.append(dir)

        for file in (
            paths.SYSCONFIG_DIRSRV_INSTANCE % serverid,
            paths.ETC_TMPFILESD_DIRSRV % serverid,
            paths.SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE % serverid,
        ):
            if os.path.exists(file):
                self.files.append(file)

        self.files.append(
            paths.HTTPD_PASSWD_FILE_FMT.format(host=api.env.host)
        )

        self.logs.append(paths.VAR_LOG_DIRSRV_INSTANCE_TEMPLATE % serverid)


    def get_connection(self):
        '''
        Create an ldapi connection and bind to it using autobind as root.
        '''
        if self._conn is not None:
            return self._conn

        self._conn = ipaldap.LDAPClient.from_realm(api.env.realm)

        try:
            self._conn.external_bind()
        except Exception as e:
            logger.error("Unable to bind to LDAP server %s: %s",
                         self._conn.ldap_uri, e)

        return self._conn


    def db2ldif(self, instance, backend, online=True):
        '''
        Create a LDIF backup of the data in this instance.

        If executed online create a task and wait for it to complete.

        For SELinux reasons this writes out to the 389-ds backup location
        and we move it.
        '''
        logger.info('Backing up %s in %s to LDIF', backend, instance)

        cn = time.strftime('export_%Y_%m_%d_%H_%M_%S')
        dn = DN(('cn', cn), ('cn', 'export'), ('cn', 'tasks'), ('cn', 'config'))

        ldifname = '%s-%s.ldif' % (instance, backend)
        ldiffile = os.path.join(
            paths.SLAPD_INSTANCE_LDIF_DIR_TEMPLATE % instance,
            ldifname)

        if online:
            conn = self.get_connection()
            ent = conn.make_entry(
                dn,
                {
                    'objectClass': ['top', 'extensibleObject'],
                    'cn': [cn],
                    'nsInstance': [backend],
                    'nsFilename': [ldiffile],
                    'nsUseOneFile': ['true'],
                    'nsExportReplica': ['true'],
                }
            )

            try:
                conn.add_entry(ent)
            except Exception as e:
                raise admintool.ScriptError(
                    'Unable to add LDIF task: %s' % e
                )

            logger.info("Waiting for LDIF to finish")
            if (wait_for_task(conn, dn) != 0):
                raise admintool.ScriptError(
                    'BAK online task failed. Check file systems\' free space.'
                )

        else:
            args = [paths.DSCTL,
                    instance,
                    'db2ldif',
                    '--replication',
                    backend,
                    ldiffile]
            result = run(args, raiseonerr=False)
            if result.returncode != 0:
                raise admintool.ScriptError(
                    'db2ldif failed: %s '
                    'Check if destination directory %s has enough space.'
                    % (result.error_log, os.path.dirname(ldiffile))
                )

        # Move the LDIF backup to our location
        try:
            shutil.move(ldiffile, os.path.join(self.dir, ldifname))
        except (IOError, OSError) as e:
            raise admintool.ScriptError(
                'Unable to move LDIF: %s '
                'Check if destination directory %s has enough space.'
                % (e, os.path.dirname(ldiffile))
            )
        except Exception as e:
            raise admintool.ScriptError(
                'Unexpected error: %s' % e
            )


    def db2bak(self, instance, online=True):
        '''
        Create a BAK backup of the data and changelog in this instance.

        If executed online create a task and wait for it to complete.
        '''
        logger.info('Backing up %s', instance)
        cn = time.strftime('backup_%Y_%m_%d_%H_%M_%S')
        dn = DN(('cn', cn), ('cn', 'backup'), ('cn', 'tasks'), ('cn', 'config'))

        bakdir = os.path.join(paths.SLAPD_INSTANCE_BACKUP_DIR_TEMPLATE % (instance, instance))

        if online:
            conn = self.get_connection()
            ent = conn.make_entry(
                dn,
                {
                    'objectClass': ['top', 'extensibleObject'],
                    'cn': [cn],
                    'nsInstance': ['userRoot'],
                    'nsArchiveDir': [bakdir],
                    'nsDatabaseType': ['ldbm database'],
                }
            )

            try:
                conn.add_entry(ent)
            except Exception as e:
                raise admintool.ScriptError(
                    'Unable to to add backup task: %s' % e
                )

            logger.info("Waiting for BAK to finish")
            if (wait_for_task(conn, dn) != 0):
                raise admintool.ScriptError(
                    'BAK online task failed. Check file systems\' free space.'
                )

        else:
            args = [paths.DSCTL,
                    instance,
                    'db2bak',
                    bakdir]
            result = run(args, raiseonerr=False)
            if result.returncode != 0:
                raise admintool.ScriptError(
                    'db2bak failed: %s '
                    'Check if destination directory %s has enough space.'
                    % (result.error_log, bakdir)
                )
        try:
            shutil.move(bakdir, self.dir)
        except (IOError, OSError) as e:
            raise admintool.ScriptError(
                'Unable to move BAK: %s '
                'Check if destination directory %s has enough space.'
                % (e, bakdir)
            )
        except Exception as e:
            raise admintool.ScriptError(
                'Unexpected error: %s' % e
            )


    def file_backup(self, options):

        def verify_directories(dirs):
            return [s for s in dirs if os.path.exists(s)]

        self.tarfile = os.path.join(self.dir, 'files.tar')

        logger.info("Backing up files")
        args = ['tar',
                '--exclude=%s' % paths.IPA_BACKUP_DIR,
                '--xattrs',
                '--selinux',
                '-cf',
                self.tarfile
               ]

        args.extend(verify_directories(self.dirs))
        args.extend(verify_directories(self.files))

        if options.logs:
            args.extend(verify_directories(self.logs))

        result = run(args, raiseonerr=False)
        if result.returncode != 0:
            raise admintool.ScriptError('tar returned non-zero code %d: %s' %
                                        (result.returncode, result.error_log))

        # Backup the necessary directory structure. This is a separate
        # call since we are using the '--no-recursion' flag to store
        # the directory structure only, no files.
        missing_directories = verify_directories(self.required_dirs)

        if missing_directories:
            args = ['tar',
                    '--exclude=%s' % paths.IPA_BACKUP_DIR,
                    '--xattrs',
                    '--selinux',
                    '--no-recursion',
                    '-rf',  # -r appends to an existing archive
                    self.tarfile,
                   ]
            args.extend(missing_directories)

            result = run(args, raiseonerr=False)
            if result.returncode != 0:
                raise admintool.ScriptError(
                    'tar returned non-zero code %d '
                    'when adding directory structure: %s' %
                    (result.returncode, result.error_log))

    def compress_file_backup(self):

        # Compress the archive. This is done separately, since 'tar' cannot
        # append to a compressed archive.
        if self.tarfile:
            result = run([paths.GZIP, self.tarfile], raiseonerr=False)
            if result.returncode != 0:
                raise admintool.ScriptError(
                    'gzip returned non-zero code %d '
                    'when compressing the backup: %s' %
                    (result.returncode, result.error_log))

            # Rename the archive back to files.tar to preserve compatibility
            os.rename(os.path.join(self.dir, 'files.tar.gz'), self.tarfile)


    def create_header(self, data_only):
        '''
        Create the backup file header that contains the meta data about
        this particular backup.
        '''
        config = SafeConfigParser()
        config.add_section("ipa")
        if data_only:
            config.set('ipa', 'type', 'DATA')
        else:
            config.set('ipa', 'type', 'FULL')
        config.set(
            'ipa', 'time', time.strftime(ISO8601_DATETIME_FMT, time.gmtime())
        )
        config.set('ipa', 'host', api.env.host)
        config.set('ipa', 'ipa_version', str(version.VERSION))
        config.set('ipa', 'version', '1')

        dn = DN(('cn', api.env.host), api.env.container_masters,
                api.env.basedn)
        services_cns = []
        try:
            conn = self.get_connection()
            services = conn.get_entries(dn, conn.SCOPE_ONELEVEL)
        except errors.NetworkError:
            logger.critical(
              "Unable to obtain list of master services, continuing anyway")
        except Exception as e:
            logger.error("Failed to read services from '%s': %s",
                         conn.ldap_uri, e)
        else:
            services_cns = [s.single_value['cn'] for s in services]

        config.set('ipa', 'services', ','.join(services_cns))
        with open(self.header, 'w') as fd:
            config.write(fd)


    def finalize_backup(self, data_only=False, encrypt=False, keyring=None):
        '''
        Create the final location of the backup files and move the files
        we've backed up there, optionally encrypting them.

        This is done in a couple of steps. We have a directory that
        contains the tarball of the files, a directory that contains
        the db2bak output and an LDIF.

        These, along with the header, are moved into a new subdirectory
        in paths.IPA_BACKUP_DIR (/var/lib/ipa/backup).
        '''

        if data_only:
            backup_dir = os.path.join(
                paths.IPA_BACKUP_DIR,
                time.strftime('ipa-data-%Y-%m-%d-%H-%M-%S')
            )
            filename = os.path.join(backup_dir, "ipa-data.tar")
        else:
            backup_dir = os.path.join(
                paths.IPA_BACKUP_DIR,
                time.strftime('ipa-full-%Y-%m-%d-%H-%M-%S')
            )
            filename = os.path.join(backup_dir, "ipa-full.tar")

        try:
            os.mkdir(backup_dir, 0o700)
        except (OSError, IOError) as e:
            raise admintool.ScriptError(
                'Could not create backup directory: %s' % e
            )
        except Exception as e:
            raise admintool.ScriptError(
                'Unexpected error: %s' % e
            )

        os.chdir(self.dir)
        args = [
            'tar', '--xattrs', '--selinux', '-czf', filename, '.'
        ]
        result = run(args, raiseonerr=False)
        if result.returncode != 0:
            raise admintool.ScriptError(
                'tar returned non-zero code %s: %s' %
                (result.returncode, result.error_log)
            )
        if encrypt:
            logger.info('Encrypting %s', filename)
            filename = encrypt_file(filename)
        try:
            shutil.move(self.header, backup_dir)
        except (IOError, OSError) as e:
            raise admintool.ScriptError(
                'Could not create or move data to backup directory %s: %s' %
                (backup_dir, e)
            )
        except Exception as e:
            raise admintool.ScriptError(
                'Unexpected error: %s' % e
            )

        logger.info('Backed up to %s', backup_dir)
