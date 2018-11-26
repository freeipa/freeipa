# Authors: Simo Sorce <ssorce@redhat.com>
#          Alexander Bokovoy <abokovoy@redhat.com>
#          Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2007-2014  Red Hat
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

from __future__ import absolute_import
import logging
import six
import abc

from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.admintool import ScriptError
import os

FILES_TO_NOT_BACKUP = ['passwd', 'group', 'shadow', 'gshadow']

logger = logging.getLogger(__name__)


def get_auth_tool():
    return RedHatAuthSelect()


@six.add_metaclass(abc.ABCMeta)
class RedHatAuthToolBase:

    @abc.abstractmethod
    def configure(self, sssd, mkhomedir, statestore, sudo=True):
        pass

    @abc.abstractmethod
    def unconfigure(self, fstore, statestore,
                    was_sssd_installed,
                    was_sssd_configured):
        pass

    @abc.abstractmethod
    def backup(self, path):
        """
        Backup the system authentication resources configuration
        :param path: directory where the backup will be stored
        """

    @abc.abstractmethod
    def restore(self, path):
        """
        Restore the system authentication resources configuration from a backup
        :param path: directory where the backup is stored
        """

    @abc.abstractmethod
    def set_nisdomain(self, nisdomain):
        pass


class RedHatAuthSelect(RedHatAuthToolBase):

    def _get_authselect_current_output(self):
        try:
            current = ipautil.run(
                [paths.AUTHSELECT, "current", "--raw"])
        except ipautil.CalledProcessError:
            logger.debug("Current configuration not managed by authselect")
            return None

        return current.raw_output.decode()

    def _parse_authselect_output(self, output_text=None):
        """
        Parses the output_text to extract the profile and options.
        When no text is provided, runs the 'authselect profile' command to
        generate the text to be parsed.
        """
        if output_text is None:
            output_text = self._get_authselect_current_output()
            if output_text is None:
                return None

        output_text = output_text.strip()
        if not output_text:
            return None
        output_items = output_text.split(' ')
        profile = output_items[0]
        features = output_items[1:]
        return profile, features

    def configure(self, sssd, mkhomedir, statestore, sudo=True):
        # In the statestore, the following keys are used for the
        # 'authselect' module:
        # profile: name of the profile configured pre-installation
        # features_list: list of features configured pre-installation
        # mkhomedir: True if installation was called with --mkhomedir
        # profile and features_list are used when reverting to the
        # pre-install state
        cfg = self._parse_authselect_output()
        if cfg:
            statestore.backup_state('authselect', 'profile', cfg[0])
            statestore.backup_state(
                    'authselect', 'features_list', " ".join(cfg[1]))
        else:
            # cfg = None means that the current conf is not managed by
            # authselect but by authconfig.
            # As we are using authselect to configure the host,
            # it will not be possible to revert to a custom authconfig
            # configuration later (during uninstall)
            # Best thing to do will be to use sssd profile at this time
            logger.warning(
                "WARNING: The configuration pre-client installation is not "
                "managed by authselect and cannot be backed up. "
                "Uninstallation may not be able to revert to the original "
                "state.")

        cmd = [paths.AUTHSELECT, "select", "sssd"]
        if mkhomedir:
            cmd.append("with-mkhomedir")
            statestore.backup_state('authselect', 'mkhomedir', True)
        if sudo:
            cmd.append("with-sudo")
        cmd.append("--force")

        ipautil.run(cmd)

    def unconfigure(
        self, fstore, statestore, was_sssd_installed, was_sssd_configured
    ):
        if not statestore.has_state('authselect') and was_sssd_installed:
            logger.warning(
                "WARNING: Unable to revert to the pre-installation state "
                "('authconfig' tool has been deprecated in favor of "
                "'authselect'). The default sssd profile will be used "
                "instead.")
            # Build the equivalent command line that will be displayed
            # to the user
            # This is a copy-paste of unconfigure code, except that it
            # creates the command line but does not actually call it
            authconfig = RedHatAuthConfig()
            authconfig.prepare_unconfigure(
                fstore, statestore, was_sssd_installed, was_sssd_configured)
            args = authconfig.build_args()
            logger.warning(
                "The authconfig arguments would have been: authconfig %s",
                " ".join(args))

            profile = 'sssd'
            features = ''
        else:
            profile = \
                statestore.restore_state('authselect', 'profile') or 'sssd'
            features = \
                statestore.restore_state('authselect', 'features_list') or ''
            statestore.delete_state('authselect', 'mkhomedir')

        cmd = [paths.AUTHSELECT, "select", profile, features, "--force"]
        ipautil.run(cmd)

    def backup(self, path):
        current = self._get_authselect_current_output()
        if current is None:
            return

        if not os.path.exists(path):
            os.makedirs(path)

        with open(os.path.join(path, "authselect.backup"), 'w') as f:
            f.write(current)

    def restore(self, path):
        with open(os.path.join(path, "authselect.backup"), "r") as f:
            cfg = self._parse_authselect_output(f.read())

        if cfg:
            profile = cfg[0]

            cmd = [
                paths.AUTHSELECT, "select", profile,
                " ".join(cfg[1]), "--force"]
            ipautil.run(cmd)

    def set_nisdomain(self, nisdomain):
        try:
            with open(paths.SYSCONF_NETWORK, 'r') as f:
                content = [
                    line for line in f
                    if not line.strip().upper().startswith('NISDOMAIN')
                ]
        except IOError:
            content = []

        content.append("NISDOMAIN={}\n".format(nisdomain))

        with open(paths.SYSCONF_NETWORK, 'w') as f:
            f.writelines(content)


# RedHatAuthConfig concrete class definition to be removed later
# when agreed on exact path to migrate to authselect
class RedHatAuthConfig(RedHatAuthToolBase):
    """
    AuthConfig class implements system-independent interface to configure
    system authentication resources. In Red Hat systems this is done with
    authconfig(8) utility.

    AuthConfig class is nothing more than a tool to gather configuration
    options and execute their processing. These options then converted by
    an actual implementation to series of a system calls to appropriate
    utilities performing real configuration.

    If you need to re-use existing AuthConfig instance for multiple runs,
    make sure to call 'AuthConfig.reset()' between the runs.
    """

    def __init__(self):
        self.parameters = {}

    def enable(self, option):
        self.parameters[option] = True
        return self

    def disable(self, option):
        self.parameters[option] = False
        return self

    def add_option(self, option):
        self.parameters[option] = None
        return self

    def add_parameter(self, option, value):
        self.parameters[option] = [value]
        return self

    def reset(self):
        self.parameters = {}
        return self

    def build_args(self):
        args = []

        for (option, value) in self.parameters.items():
            if type(value) is bool:
                if value:
                    args.append("--enable%s" % (option))
                else:
                    args.append("--disable%s" % (option))
            elif type(value) in (tuple, list):
                args.append("--%s" % (option))
                args.append("%s" % (value[0]))
            elif value is None:
                args.append("--%s" % (option))
            else:
                args.append("--%s%s" % (option, value))

        return args

    def execute(self, update=True):
        if update:
            self.add_option("update")

        args = self.build_args()
        try:
            ipautil.run([paths.AUTHCONFIG] + args)
        except ipautil.CalledProcessError:
            raise ScriptError("Failed to execute authconfig command")

    def configure(self, sssd, mkhomedir, statestore, sudo=True):
        if sssd:
            statestore.backup_state('authconfig', 'sssd', True)
            statestore.backup_state('authconfig', 'sssdauth', True)
            self.enable("sssd")
            self.enable("sssdauth")
        else:
            statestore.backup_state('authconfig', 'ldap', True)
            self.enable("ldap")
            self.enable("forcelegacy")

            statestore.backup_state('authconfig', 'krb5', True)
            self.enable("krb5")
            self.add_option("nostart")

        if mkhomedir:
            statestore.backup_state('authconfig', 'mkhomedir', True)
            self.enable("mkhomedir")

        self.execute()
        self.reset()

    def prepare_unconfigure(self, fstore, statestore,
                            was_sssd_installed,
                            was_sssd_configured):
        if statestore.has_state('authconfig'):
            # disable only those configurations that we enabled during install
            for conf in ('ldap', 'krb5', 'sssd', 'sssdauth', 'mkhomedir'):
                cnf = statestore.restore_state('authconfig', conf)
                # Do not disable sssd, as this can cause issues with its later
                # uses. Remove it from statestore however, so that it becomes
                # empty at the end of uninstall process.
                if cnf and conf != 'sssd':
                    self.disable(conf)
        else:
            # There was no authconfig status store
            # It means the code was upgraded after original install
            # Fall back to old logic
            self.disable("ldap")
            self.disable("krb5")
            if not(was_sssd_installed and was_sssd_configured):
                # Only disable sssdauth. Disabling sssd would cause issues
                # with its later uses.
                self.disable("sssdauth")
            self.disable("mkhomedir")

    def unconfigure(self, fstore, statestore,
                    was_sssd_installed,
                    was_sssd_configured):
        self.prepare_unconfigure(
            fstore, statestore, was_sssd_installed, was_sssd_configured)
        self.execute()
        self.reset()

    def backup(self, path):
        try:
            ipautil.run([paths.AUTHCONFIG, "--savebackup", path])
        except ipautil.CalledProcessError:
            raise ScriptError("Failed to execute authconfig command")

        # do not backup these files since we don't want to mess with
        # users/groups during restore. Authconfig doesn't seem to mind about
        # having them deleted from backup dir
        files_to_remove = [os.path.join(path, f) for f in FILES_TO_NOT_BACKUP]
        for filename in files_to_remove:
            try:
                os.remove(filename)
            except OSError:
                pass

    def restore(self, path):
        try:
            ipautil.run([paths.AUTHCONFIG, "--restorebackup", path])
        except ipautil.CalledProcessError:
            raise ScriptError("Failed to execute authconfig command")

    def set_nisdomain(self, nisdomain):
        # Let authconfig setup the permanent configuration
        self.reset()
        self.add_parameter("nisdomain", nisdomain)
        self.execute()
