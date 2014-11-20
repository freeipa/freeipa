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

import os
import sys
import shutil
import tempfile
import time
import pwd
from ConfigParser import SafeConfigParser

from ipalib import api, errors
from ipapython import version, ipautil, certdb
from ipapython.ipautil import run, user_input
from ipapython import admintool
from ipapython.dn import DN
from ipaserver.install.dsinstance import (realm_to_serverid,
                                          create_ds_user, DS_USER)
from ipaserver.install.cainstance import PKI_USER, create_ca_user
from ipaserver.install.replication import (wait_for_task, ReplicationManager,
                                           get_cs_replication_manager)
from ipaserver.install import installutils
from ipaserver.install import httpinstance
from ipapython import ipaldap
import ipapython.errors
from ipaplatform.tasks import tasks
from ipaserver.install.ipa_backup import BACKUP_DIR
from ipaplatform import services
from ipaplatform.paths import paths

try:
    from ipaserver.install import adtrustinstance
except ImportError:
    adtrustinstance = None


def recursive_chown(path, uid, gid):
    '''
    Change ownership of all files and directories in a path.
    '''
    for root, dirs, files in os.walk(path):
        for dir in dirs:
            os.chown(os.path.join(root, dir), uid, gid)
            os.chmod(os.path.join(root, dir), 0750)
        for file in files:
            os.chown(os.path.join(root, file), uid, gid)
            os.chmod(os.path.join(root, file), 0640)


def decrypt_file(tmpdir, filename, keyring):
    source = filename
    (dest, ext) = os.path.splitext(filename)

    if ext != '.gpg':
        raise admintool.ScriptError('Trying to decrypt a non-gpg file')

    dest = os.path.basename(dest)
    dest = os.path.join(tmpdir, dest)

    args = [paths.GPG,
            '--batch',
            '-o', dest]

    if keyring is not None:
        args.append('--no-default-keyring')
        args.append('--keyring')
        args.append(keyring + '.pub')
        args.append('--secret-keyring')
        args.append(keyring + '.sec')

    args.append('-d')
    args.append(source)

    (stdout, stderr, rc) = run(args, raiseonerr=False)
    if rc != 0:
        raise admintool.ScriptError('gpg failed: %s' % stderr)

    return dest


class Restore(admintool.AdminTool):
    command_name = 'ipa-restore'
    log_file_name = paths.IPARESTORE_LOG

    usage = "%prog [options] backup"

    description = "Restore IPA files and databases."

    def __init__(self, options, args):
        super(Restore, self).__init__(options, args)
        self._conn = None

    @classmethod
    def add_options(cls, parser):
        super(Restore, cls).add_options(parser, debug_option=True)

        parser.add_option("-p", "--password", dest="password",
            help="Directory Manager password")
        parser.add_option("--gpg-keyring", dest="gpg_keyring",
            help="The gpg key name to be used")
        parser.add_option("--data", dest="data_only", action="store_true",
            default=False, help="Restore only the data")
        parser.add_option("--online", dest="online", action="store_true",
            default=False, help="Perform the LDAP restores online, for data only.")
        parser.add_option("--instance", dest="instance",
            help="The 389-ds instance to restore (defaults to all found)")
        parser.add_option("--backend", dest="backend",
            help="The backend to restore within the instance or instances")
        parser.add_option('--no-logs', dest="no_logs", action="store_true",
            default=False, help="Do not restore log files from the backup")
        parser.add_option('-U', '--unattended', dest="unattended",
            action="store_true", default=False,
            help="Unattended restoration never prompts the user")


    def setup_logging(self, log_file_mode='a'):
        super(Restore, self).setup_logging(log_file_mode='a')


    def validate_options(self):
        options = self.options
        super(Restore, self).validate_options(needs_root=True)
        if options.data_only:
            installutils.check_server_configuration()

        if len(self.args) < 1:
            self.option_parser.error(
                "must provide the backup to restore")
        elif len(self.args) > 1:
            self.option_parser.error(
                "must provide exactly one name for the backup")

        dirname = self.args[0]
        if not os.path.isabs(dirname):
            self.backup_dir = os.path.join(BACKUP_DIR, dirname)
        else:
            self.backup_dir = dirname

        if options.gpg_keyring:
            if (not os.path.exists(options.gpg_keyring + '.pub') or
               not os.path.exists(options.gpg_keyring + '.sec')):
                raise admintool.ScriptError('No such key %s' %
                    options.gpg_keyring)


    def ask_for_options(self):
        options = self.options
        super(Restore, self).ask_for_options()

        # get the directory manager password
        self.dirman_password = options.password
        if not options.password:
            if not options.unattended:
                self.dirman_password = installutils.read_password(
                    "Directory Manager (existing master)",
                    confirm=False, validate=False)
            if self.dirman_password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")


    def run(self):
        options = self.options
        super(Restore, self).run()

        api.bootstrap(in_server=False, context='restore')
        api.finalize()

        self.log.info("Preparing restore from %s on %s",
            self.backup_dir, api.env.host)

        if not options.instance:
            instances = []
            for instance in [realm_to_serverid(api.env.realm), 'PKI-IPA']:
                if os.path.exists(paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE % instance):
                    instances.append(instance)
        else:
            instances = [options.instance]
        if options.data_only and not instances:
            raise admintool.ScriptError('No instances to restore to')

        create_ds_user()
        pent = pwd.getpwnam(DS_USER)

        # Temporary directory for decrypting files before restoring
        self.top_dir = tempfile.mkdtemp("ipa")
        os.chown(self.top_dir, pent.pw_uid, pent.pw_gid)
        os.chmod(self.top_dir, 0750)
        self.dir = os.path.join(self.top_dir, "ipa")
        os.mkdir(self.dir, 0750)

        os.chown(self.dir, pent.pw_uid, pent.pw_gid)

        self.header = os.path.join(self.backup_dir, 'header')

        cwd = os.getcwd()
        try:
            dirsrv = services.knownservices.dirsrv

            self.read_header()
            # These two checks would normally be in the validate method but
            # we need to know the type of backup we're dealing with.
            if (self.backup_type != 'FULL' and not options.data_only and
                not instances):
                raise admintool.ScriptError('Cannot restore a data backup into an empty system')
            if (self.backup_type == 'FULL' and not options.data_only and
                (options.instance or options.backend)):
                raise admintool.ScriptError('Restore must be in data-only mode when restoring a specific instance or backend.')
            if self.backup_host != api.env.host:
                self.log.warning('Host name %s does not match backup name %s' %
                    (api.env.host, self.backup_host))
                if (not options.unattended and
                    not user_input("Continue to restore?", False)):
                    raise admintool.ScriptError("Aborted")
            if self.backup_ipa_version != str(version.VERSION):
                self.log.warning(
                    "Restoring data from a different release of IPA.\n"
                    "Data is version %s.\n"
                    "Server is running %s." %
                    (self.backup_ipa_version, str(version.VERSION)))
                if (not options.unattended and
                    not user_input("Continue to restore?", False)):
                    raise admintool.ScriptError("Aborted")

            # Big fat warning
            if  (not options.unattended and
                not user_input("Restoring data will overwrite existing live data. Continue to restore?", False)):
                raise admintool.ScriptError("Aborted")

            self.log.info(
                "Each master will individually need to be re-initialized or")
            self.log.info(
                "re-created from this one. The replication agreements on")
            self.log.info(
                "masters running IPA 3.1 or earlier will need to be manually")
            self.log.info(
                "re-enabled. See the man page for details.")

            self.log.info("Disabling all replication.")
            self.disable_agreements()

            self.extract_backup(options.gpg_keyring)
            if options.data_only:
                if not options.online:
                    self.log.info('Stopping Directory Server')
                    dirsrv.stop(capture_output=False)
                else:
                    self.log.info('Starting Directory Server')
                    dirsrv.start(capture_output=False)
            else:
                self.log.info('Stopping IPA services')
                (stdout, stderr, rc) = run(['ipactl', 'stop'], raiseonerr=False)
                if rc not in [0, 6]:
                    self.log.warn('Stopping IPA failed: %s' % stderr)

                self.restore_selinux_booleans()


            # We do either a full file restore or we restore data.
            if self.backup_type == 'FULL' and not options.data_only:
                if 'CA' in self.backup_services:
                    create_ca_user()
                if options.online:
                    raise admintool.ScriptError('File restoration cannot be done online.')
                self.cert_restore_prepare()
                self.file_restore(options.no_logs)
                self.cert_restore()
                if 'CA' in self.backup_services:
                    self.__create_dogtag_log_dirs()

            # Always restore the data from ldif
            # If we are restoring PKI-IPA then we need to restore the
            # userRoot backend in it and the main IPA instance. If we
            # have a unified instance we need to restore both userRoot and
            # ipaca.
            for instance in instances:
                if os.path.exists(paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE % instance):
                    if options.backend is None:
                        self.ldif2db(instance, 'userRoot', online=options.online)
                        if os.path.exists(paths.IPACA_DIRSRV_INSTANCE_DB_TEMPLATE % instance):
                            self.ldif2db(instance, 'ipaca', online=options.online)
                    else:
                        self.ldif2db(instance, options.backend, online=options.online)
                else:
                    raise admintool.ScriptError('389-ds instance %s does not exist' % instance)

            if options.data_only:
                if not options.online:
                    self.log.info('Starting Directory Server')
                    dirsrv.start(capture_output=False)
            else:
                # explicitly enable then disable the pki tomcatd service to
                # re-register its instance. FIXME, this is really wierd.
                services.knownservices.pki_tomcatd.enable()
                services.knownservices.pki_tomcatd.disable()

                self.log.info('Starting IPA services')
                run(['ipactl', 'start'])
                self.log.info('Restarting SSSD')
                sssd = services.service('sssd')
                sssd.restart()
                http = httpinstance.HTTPInstance()
                http.remove_httpd_ccache()
        finally:
            try:
                os.chdir(cwd)
            except Exception, e:
                self.log.error('Cannot change directory to %s: %s' % (cwd, e))
            shutil.rmtree(self.top_dir)


    def get_connection(self):
        '''
        Create an ldapi connection and bind to it using autobind as root.
        '''
        if self._conn is not None:
            return self._conn

        self._conn = ipaldap.IPAdmin(host=api.env.host,
                                   ldapi=True,
                                   protocol='ldapi',
                                   realm=api.env.realm)

        try:
            pw_name = pwd.getpwuid(os.geteuid()).pw_name
            self._conn.do_external_bind(pw_name)
        except Exception, e:
            raise admintool.ScriptError('Unable to bind to LDAP server: %s'
                % e)
        return self._conn


    def disable_agreements(self):
        '''
        Find all replication agreements on all masters and disable them.

        Warn very loudly about any agreements/masters we cannot contact.
        '''
        try:
            conn = self.get_connection()
        except Exception, e :
            self.log.error('Unable to get connection, skipping disabling agreements: %s' % e)
            return
        masters = []
        dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
        try:
            entries = conn.get_entries(dn, conn.SCOPE_ONELEVEL)
        except Exception, e:
            raise admintool.ScriptError(
                "Failed to read master data: %s" % e)
        else:
            masters = [ent.single_value['cn'] for ent in entries]

        for master in masters:
            if master == api.env.host:
                continue

            try:
                repl = ReplicationManager(api.env.realm, master,
                                          self.dirman_password)
            except Exception, e:
                self.log.critical("Unable to disable agreement on %s: %s" % (master, e))

            master_dn = DN(('cn', master), ('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
            try:
                services = repl.conn.get_entries(master_dn,
                                                 repl.conn.SCOPE_ONELEVEL)
            except errors.NotFound:
                continue

            services_cns = [s.single_value['cn'] for s in services]

            host_entries = repl.find_ipa_replication_agreements()
            hosts = [rep.single_value.get('nsds5replicahost')
                     for rep in host_entries]

            for host in hosts:
                self.log.info('Disabling replication agreement on %s to %s' % (master, host))
                repl.disable_agreement(host)

            if 'CA' in services_cns:
                try:
                    repl = get_cs_replication_manager(api.env.realm, master,
                                                      self.dirman_password)
                except Exception, e:
                    self.log.critical("Unable to disable agreement on %s: %s" % (master, e))

                host_entries = repl.find_ipa_replication_agreements()
                hosts = [rep.single_value.get('nsds5replicahost')
                         for rep in host_entries]
                for host in hosts:
                    self.log.info('Disabling CA replication agreement on %s to %s' % (master, host))
                    repl.hostnames = [master, host]
                    repl.disable_agreement(host)


    def ldif2db(self, instance, backend, online=True):
        '''
        Restore a LDIF backup of the data in this instance.

        If executed online create a task and wait for it to complete.
        '''
        self.log.info('Restoring from %s in %s' % (backend, instance))

        now = time.localtime()
        cn = time.strftime('import_%Y_%m_%d_%H_%M_%S')
        dn = DN(('cn', cn), ('cn', 'import'), ('cn', 'tasks'), ('cn', 'config'))

        ldifname = '%s-%s.ldif' % (instance, backend)
        ldiffile = os.path.join(self.dir, ldifname)

        if online:
            conn = self.get_connection()
            ent = conn.make_entry(
                dn,
                {
                    'objectClass': ['top', 'extensibleObject'],
                    'cn': [cn],
                    'nsFilename': [ldiffile],
                    'nsUseOneFile': ['true'],
                }
            )
            ent['nsInstance'] = [backend]

            try:
                conn.add_entry(ent)
            except Exception, e:
                raise admintool.ScriptError(
                    'Unable to bind to LDAP server: %s' % e)

            self.log.info("Waiting for LDIF to finish")
            wait_for_task(conn, dn)
        else:
            args = ['%s/ldif2db' % self.__find_scripts_dir(instance),
                    '-i', ldiffile]
            if backend is not None:
                args.append('-n')
                args.append(backend)
            else:
                args.append('-n')
                args.append('userRoot')
            (stdout, stderr, rc) = run(args, raiseonerr=False)
            if rc != 0:
                self.log.critical("ldif2db failed: %s" % stderr)


    def bak2db(self, instance, backend, online=True):
        '''
        Restore a BAK backup of the data and changelog in this instance.

        If backend is None then all backends are restored.

        If executed online create a task and wait for it to complete.

        instance here is a loaded term. It can mean either a separate
        389-ds install instance or a separate 389-ds backend. We only need
        to treat PKI-IPA and ipaca specially.
        '''
        if backend is not None:
            self.log.info('Restoring %s in %s' % (backend, instance))
        else:
            self.log.info('Restoring %s' % instance)

        cn = time.strftime('restore_%Y_%m_%d_%H_%M_%S')

        dn = DN(('cn', cn), ('cn', 'restore'), ('cn', 'tasks'), ('cn', 'config'))

        if online:
            conn = self.get_connection()
            ent = conn.make_entry(
                dn,
                {
                    'objectClass': ['top', 'extensibleObject'],
                    'cn': [cn],
                    'nsArchiveDir': [os.path.join(self.dir, instance)],
                    'nsDatabaseType': ['ldbm database'],
                }
            )
            if backend is not None:
                ent['nsInstance'] = [backend]

            try:
                conn.add_entry(ent)
            except Exception, e:
                raise admintool.ScriptError('Unable to bind to LDAP server: %s'
                    % e)

            self.log.info("Waiting for restore to finish")
            wait_for_task(conn, dn)
        else:
            args = ['%s/bak2db' % self.__find_scripts_dir(instance),
                    os.path.join(self.dir, instance)]
            if backend is not None:
                args.append('-n')
                args.append(backend)
            (stdout, stderr, rc) = run(args, raiseonerr=False)
            if rc != 0:
                self.log.critical("bak2db failed: %s" % stderr)


    def file_restore(self, nologs=False):
        '''
        Restore all the files in the tarball.

        This MUST be done offline because we directly backup the 389-ds
        databases.
        '''
        self.log.info("Restoring files")
        cwd = os.getcwd()
        os.chdir('/')
        args = ['tar',
                '--xattrs',
                '--selinux',
                '-xzf',
                os.path.join(self.dir, 'files.tar')
               ]
        if nologs:
            args.append('--exclude')
            args.append('var/log')

        (stdout, stderr, rc) = run(args, raiseonerr=False)
        if rc != 0:
            self.log.critical('Restoring files failed: %s', stderr)

        os.chdir(cwd)


    def read_header(self):
        '''
        Read the backup file header that contains the meta data about
        this particular backup.
        '''
        fd = open(self.header)
        config = SafeConfigParser()
        config.readfp(fd)

        self.backup_type = config.get('ipa', 'type')
        self.backup_time = config.get('ipa', 'time')
        self.backup_host = config.get('ipa', 'host')
        self.backup_ipa_version = config.get('ipa', 'ipa_version')
        self.backup_version = config.get('ipa', 'version')
        self.backup_services = config.get('ipa', 'services').split(',')


    def extract_backup(self, keyring=None):
        '''
        Extract the contents of the tarball backup into a temporary location,
        decrypting if necessary.
        '''

        encrypt = False
        filename = None
        if self.backup_type == 'FULL':
            filename = os.path.join(self.backup_dir, 'ipa-full.tar')
        else:
            filename = os.path.join(self.backup_dir, 'ipa-data.tar')
        if not os.path.exists(filename):
            if not os.path.exists(filename + '.gpg'):
                raise admintool.ScriptError('Unable to find backup file in %s' % self.backup_dir)
            else:
                filename = filename + '.gpg'
                encrypt = True

        if encrypt:
            self.log.info('Decrypting %s' % filename)
            filename = decrypt_file(self.dir, filename, keyring)

        cwd = os.getcwd()
        os.chdir(self.dir)

        args = ['tar',
                '--xattrs',
                '--selinux',
                '-xzf',
                filename,
                '.'
               ]
        run(args)

        pent = pwd.getpwnam(DS_USER)
        os.chown(self.top_dir, pent.pw_uid, pent.pw_gid)
        recursive_chown(self.dir, pent.pw_uid, pent.pw_gid)

        if encrypt:
            # We can remove the decoded tarball
            os.unlink(filename)


    def __find_scripts_dir(self, instance):
        """
        IPA stores its 389-ds scripts in a different directory than dogtag
        does so we need to probe for it.
        """
        if instance != 'PKI-IPA':
            return os.path.join(paths.VAR_LIB_DIRSRV, 'scripts-%s' % instance)
        else:
            if sys.maxsize > 2**32L:
                libpath = 'lib64'
            else:
                libpath = 'lib'
            return os.path.join(paths.USR_DIR, libpath, 'dirsrv', 'slapd-PKI-IPA')

    def __create_dogtag_log_dirs(self):
        """
        If we are doing a full restore and the dogtag log directories do
        not exist then tomcat will fail to start.

        The directory is different depending on whether we have a d9-based
        or a d10-based installation. We can tell based on whether there is
        a PKI-IPA 389-ds instance.
        """
        if os.path.exists(paths.ETC_SLAPD_PKI_IPA_DIR): # dogtag 9
            topdir = paths.PKI_CA_LOG_DIR
            dirs = [topdir,
                    '/var/log/pki-ca/signedAudit,']
        else: # dogtag 10
            topdir = paths.TOMCAT_TOPLEVEL_DIR
            dirs = [topdir,
                    paths.TOMCAT_CA_DIR,
                    paths.TOMCAT_CA_ARCHIVE_DIR,
                    paths.TOMCAT_SIGNEDAUDIT_DIR,]

        if os.path.exists(topdir):
            return

        try:
            pent = pwd.getpwnam(PKI_USER)
        except KeyError:
            self.log.debug("No %s user exists, skipping CA directory creation" % PKI_USER)
            return
        self.log.debug('Creating log directories for dogtag')
        for dir in dirs:
            try:
                self.log.debug('Creating %s' % dir)
                os.mkdir(dir, 0770)
                os.chown(dir, pent.pw_uid, pent.pw_gid)
                tasks.restore_context(dir)
            except Exception, e:
                # This isn't so fatal as to side-track the restore
                self.log.error('Problem with %s: %s' % (dir, e))

    def restore_selinux_booleans(self):
        bools = dict(httpinstance.SELINUX_BOOLEAN_SETTINGS)
        if 'ADTRUST' in self.backup_services:
            if adtrustinstance:
                bools.update(adtrustinstance.SELINUX_BOOLEAN_SETTINGS)
            else:
                self.log.error(
                    'The AD trust package was not found, '
                    'not setting SELinux booleans.')
        try:
            tasks.set_selinux_booleans(bools)
        except ipapython.errors.SetseboolError as e:
            self.log.error('%s', e)

    def cert_restore_prepare(self):
        for basename in ('cert8.db', 'key3.db', 'secmod.db', 'pwdfile.txt'):
            filename = os.path.join(paths.IPA_NSSDB_DIR, basename)
            try:
                ipautil.backup_file(filename)
            except OSError as e:
                self.log.error("Failed to backup %s: %s" % (filename, e))

        tasks.remove_ca_certs_from_systemwide_ca_store()

    def cert_restore(self):
        if not os.path.exists(os.path.join(paths.IPA_NSSDB_DIR, 'cert8.db')):
            certdb.create_ipa_nssdb()
            ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
            sys_db = certdb.NSSDatabase(paths.NSS_DB_DIR)
            for nickname, trust_flags in (('IPA CA', 'CT,C,C'),
                                          ('External CA cert', 'C,,')):
                try:
                    cert = sys_db.get_cert(nickname)
                except RuntimeError:
                    pass
                else:
                    try:
                        ipa_db.add_cert(cert, nickname, trust_flags)
                    except ipautil.CalledProcessError as e:
                        self.log.error(
                            "Failed to add %s to %s: %s" %
                            (nickname, paths.IPA_NSSDB_DIR, e))

        tasks.reload_systemwide_ca_store()
