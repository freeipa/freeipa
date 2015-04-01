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
import ldif
import itertools

from ipalib import api, errors, constants
from ipapython import version, ipautil, certdb
from ipapython.ipautil import run, user_input
from ipapython import admintool
from ipapython.dn import DN
from ipaserver.install.dsinstance import create_ds_user, DS_USER
from ipaserver.install.cainstance import PKI_USER, create_ca_user
from ipaserver.install.replication import (wait_for_task, ReplicationManager,
                                           get_cs_replication_manager)
from ipaserver.install import installutils
from ipaserver.install import dsinstance, httpinstance, cainstance
from ipapython import ipaldap
import ipapython.errors
from ipaplatform.tasks import tasks
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


class RemoveRUVParser(ldif.LDIFParser):
    def __init__(self, input_file, writer, logger):
        ldif.LDIFParser.__init__(self, input_file)
        self.writer = writer
        self.log = logger

    def handle(self, dn, entry):
        objectclass = None
        nsuniqueid = None

        for name, value in entry.iteritems():
            name = name.lower()
            if name == 'objectclass':
                objectclass = [x.lower() for x in value]
            elif name == 'nsuniqueid':
                nsuniqueid = [x.lower() for x in value]

        if (objectclass and nsuniqueid and
            'nstombstone' in objectclass and
            'ffffffff-ffffffff-ffffffff-ffffffff' in nsuniqueid):
            self.log.debug("Removing RUV entry %s", dn)
            return

        self.writer.unparse(dn, entry)


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
        parser = self.option_parser
        options = self.options
        super(Restore, self).validate_options(needs_root=True)

        if len(self.args) < 1:
            parser.error("must provide the backup to restore")
        elif len(self.args) > 1:
            parser.error("must provide exactly one name for the backup")

        dirname = self.args[0]
        if not os.path.isabs(dirname):
            dirname = os.path.join(paths.IPA_BACKUP_DIR, dirname)
        if not os.path.isdir(dirname):
            parser.error("must provide path to backup directory")

        if options.gpg_keyring:
            if (not os.path.exists(options.gpg_keyring + '.pub') or
                    not os.path.exists(options.gpg_keyring + '.sec')):
                parser.error("no such key %s" % options.gpg_keyring)


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

        self.backup_dir = self.args[0]
        if not os.path.isabs(self.backup_dir):
            self.backup_dir = os.path.join(paths.IPA_BACKUP_DIR, self.backup_dir)

        self.log.info("Preparing restore from %s on %s",
                      self.backup_dir, constants.FQDN)

        self.header = os.path.join(self.backup_dir, 'header')

        try:
            self.read_header()
        except IOError as e:
            raise admintool.ScriptError("Cannot read backup metadata: %s" % e)

        if options.data_only:
            restore_type = 'DATA'
        else:
            restore_type = self.backup_type

        # These checks would normally be in the validate method but
        # we need to know the type of backup we're dealing with.
        if restore_type == 'FULL':
            if options.online:
                raise admintool.ScriptError(
                    "File restoration cannot be done online")
            if options.instance or options.backend:
                raise admintool.ScriptError(
                    "Restore must be in data-only mode when restoring a "
                    "specific instance or backend")
        else:
            installutils.check_server_configuration()

            self.init_api()

            if options.instance:
                instance_dir = (paths.VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE %
                                options.instance)
                if not os.path.exists(instance_dir):
                    raise admintool.ScriptError(
                        "Instance %s does not exist" % options.instance)

                self.instances = [options.instance]

            if options.backend:
                for instance in self.instances:
                    db_dir = (paths.SLAPD_INSTANCE_DB_DIR_TEMPLATE %
                              (instance, options.backend))
                    if os.path.exists(db_dir):
                        break
                else:
                    raise admintool.ScriptError(
                        "Backend %s does not exist" % options.backend)

                self.backends = [options.backend]

            for instance, backend in itertools.product(self.instances,
                                                       self.backends):
                db_dir = (paths.SLAPD_INSTANCE_DB_DIR_TEMPLATE %
                          (instance, backend))
                if os.path.exists(db_dir):
                    break
            else:
                raise admintool.ScriptError(
                    "Cannot restore a data backup into an empty system")

        self.log.info("Performing %s restore from %s backup" %
                      (restore_type, self.backup_type))

        if self.backup_host != constants.FQDN:
            raise admintool.ScriptError(
                "Host name %s does not match backup name %s" %
                (constants.FQDN, self.backup_host))

        if self.backup_ipa_version != str(version.VERSION):
            self.log.warning(
                "Restoring data from a different release of IPA.\n"
                "Data is version %s.\n"
                "Server is running %s." %
                (self.backup_ipa_version, str(version.VERSION)))
            if (not options.unattended and
                    not user_input("Continue to restore?", False)):
                raise admintool.ScriptError("Aborted")

        create_ds_user()
        pent = pwd.getpwnam(DS_USER)

        # Temporary directory for decrypting files before restoring
        self.top_dir = tempfile.mkdtemp("ipa")
        os.chown(self.top_dir, pent.pw_uid, pent.pw_gid)
        os.chmod(self.top_dir, 0750)
        self.dir = os.path.join(self.top_dir, "ipa")
        os.mkdir(self.dir, 0750)

        os.chown(self.dir, pent.pw_uid, pent.pw_gid)

        cwd = os.getcwd()
        try:
            dirsrv = services.knownservices.dirsrv

            self.extract_backup(options.gpg_keyring)

            if restore_type == 'FULL':
                self.restore_default_conf()
                self.init_api(confdir=self.dir + paths.ETC_IPA)

            databases = []
            for instance in self.instances:
                for backend in self.backends:
                    database = (instance, backend)
                    ldiffile = os.path.join(self.dir, '%s-%s.ldif' % database)
                    if os.path.exists(ldiffile):
                        databases.append(database)

            if options.instance:
                for instance, backend in databases:
                    if instance == options.instance:
                        break
                else:
                    raise admintool.ScriptError(
                        "Instance %s not found in backup" % options.instance)

            if options.backend:
                for instance, backend in databases:
                    if backend == options.backend:
                        break
                else:
                    raise admintool.ScriptError(
                        "Backend %s not found in backup" % options.backend)

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

            if restore_type != 'FULL':
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
            if restore_type == 'FULL':
                if 'CA' in self.backup_services:
                    create_ca_user()
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
            for instance, backend in databases:
                self.ldif2db(instance, backend, online=options.online)

            if restore_type != 'FULL':
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
                continue

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
                    continue

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

        ldifdir = paths.SLAPD_INSTANCE_LDIF_DIR_TEMPLATE % instance
        ldifname = '%s-%s.ldif' % (instance, backend)
        ldiffile = os.path.join(ldifdir, ldifname)
        srcldiffile = os.path.join(self.dir, ldifname)

        if not os.path.exists(ldifdir):
            pent = pwd.getpwnam(DS_USER)
            os.mkdir(ldifdir, 0770)
            os.chown(ldifdir, pent.pw_uid, pent.pw_gid)

        ipautil.backup_file(ldiffile)
        with open(ldiffile, 'wb') as out_file:
            ldif_writer = ldif.LDIFWriter(out_file)
            with open(srcldiffile, 'rb') as in_file:
                ldif_parser = RemoveRUVParser(in_file, ldif_writer, self.log)
                ldif_parser.parse()

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
                self.log.error("Unable to bind to LDAP server: %s" % e)
                return

            self.log.info("Waiting for LDIF to finish")
            wait_for_task(conn, dn)
        else:
            try:
                os.makedirs(paths.VAR_LOG_DIRSRV_INSTANCE_TEMPLATE % instance)
            except OSError as e:
                pass

            args = [paths.LDIF2DB,
                    '-Z', instance,
                    '-i', ldiffile,
                    '-n', backend]
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
            args = [paths.BAK2DB,
                    '-Z', instance,
                    os.path.join(self.dir, instance)]
            if backend is not None:
                args.append('-n')
                args.append(backend)
            (stdout, stderr, rc) = run(args, raiseonerr=False)
            if rc != 0:
                self.log.critical("bak2db failed: %s" % stderr)


    def restore_default_conf(self):
        '''
        Restore paths.IPA_DEFAULT_CONF to temporary directory.

        Primary purpose of this method is to get cofiguration for api
        finalization when restoring ipa after uninstall.
        '''
        cwd = os.getcwd()
        os.chdir(self.dir)
        args = ['tar',
                '--xattrs',
                '--selinux',
                '-xzf',
                os.path.join(self.dir, 'files.tar'),
                paths.IPA_DEFAULT_CONF[1:],
               ]

        (stdout, stderr, rc) = run(args, raiseonerr=False)
        if rc != 0:
            self.log.critical('Restoring %s failed: %s' %
                              (paths.IPA_DEFAULT_CONF, stderr))
        os.chdir(cwd)


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
        with open(self.header) as fd:
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
        or a d10-based installation.
        """
        dirs = []
        # dogtag 9
        if (os.path.exists(paths.VAR_LIB_PKI_CA_DIR) and
                not os.path.exists(paths.PKI_CA_LOG_DIR)):
            dirs += [paths.PKI_CA_LOG_DIR,
                     os.path.join(paths.PKI_CA_LOG_DIR, 'signedAudit')]
        # dogtag 10
        if (os.path.exists(paths.VAR_LIB_PKI_TOMCAT_DIR) and
                not os.path.exists(paths.TOMCAT_TOPLEVEL_DIR)):
            dirs += [paths.TOMCAT_TOPLEVEL_DIR,
                     paths.TOMCAT_CA_DIR,
                     paths.TOMCAT_CA_ARCHIVE_DIR,
                     paths.TOMCAT_SIGNEDAUDIT_DIR]

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
        cainstance.CAInstance().stop_tracking_certificates()
        httpinstance.HTTPInstance().stop_tracking_certificates()
        try:
            dsinstance.DsInstance().stop_tracking_certificates(
                installutils.realm_to_serverid(api.env.realm))
        except OSError:
            # When IPA is not installed, DS NSS DB does not exist
            pass

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

        services.knownservices.certmonger.restart()

    def init_api(self, **overrides):
        api.bootstrap(in_server=False, context='restore', **overrides)
        api.finalize()

        self.instances = [
            installutils.realm_to_serverid(api.env.realm), 'PKI-IPA'
        ]
        self.backends = ['userRoot', 'ipaca']
