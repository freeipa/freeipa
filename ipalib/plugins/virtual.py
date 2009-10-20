# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
Base classes for non-LDAP backend plugins.
"""
from ipalib import api
from ipalib import Command
from ipalib import errors

class VirtualCommand(Command):
    """
    A command that doesn't use the LDAP backend but wants to use the
    LDAP access control system to make authorization decisions.

    The class variable operation is the commonName attribute of the
    entry to be tested against.

    In advance, you need to create an entry of the form:
        cn=<operation>, api.env.container_virtual, api.env.basedn

    Ex.
        cn=request certificate, cn=virtual operations, dc=example, dc=com
    """
    operation = None

    def check_access(self, operation=None):
        """
        Perform an LDAP query to determine authorization.

        This should be executed before any actual work is done.
        """
        if self.operation is None and operation is None:
            raise errors.ACIError(info='operation not defined')

        if operation is None:
            operation = self.operation

        ldap = self.api.Backend.ldap2
        self.log.info("IPA: virtual verify %s" % operation)

        operationdn = "cn=%s,%s,%s" % (operation, self.api.env.container_virtual, self.api.env.basedn)

        try:
            if not ldap.can_write(operationdn, "objectclass"):
                raise errors.ACIError(info='not allowed to perform this command')
        except errors.NotFound:
            raise errors.ACIError(info='No such virtual command')

        return True
