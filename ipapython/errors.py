# Authors: Petr Viktorin <pviktori@redhat.com>
#
# Copyright (C) 2014    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#


class SetseboolError(Exception):
    """Raised when setting a SELinux boolean fails

    :param failed: Dictionary mapping boolean names to intended values
                   to their intended values, for booleans that cound not be set
    :param command: Command the user can run to set the booleans

    The initializer arguments are copied to attributes of the same name.
    """
    def __init__(self, failed, command):
        message = "Could not set SELinux booleans: %s" % ' '.join(
            '%s=%s' % (name, value) for name, value in failed.items())
        super(SetseboolError, self).__init__(message)
        self.failed = failed
        self.command = command

    def format_service_warning(self, service_name):
        """Format warning for display when this is raised from service install
        """
        return '\n'.join([
            'WARNING: %(err)s',
            '',
            'The %(service)s may not function correctly until ',
            'the booleans are successfully changed with the command:',
            '    %(cmd)s',
            'Try updating the policycoreutils and selinux-policy packages.'
        ]) % {'err': self, 'service': service_name, 'cmd': self.command}
