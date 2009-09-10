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

    def execute(self, *args, **kw):
        """
        Perform the LDAP query to determine authorization.

        This should be executed via super() before any actual work is done.
        """
        if self.operation is None:
            raise errors.ACIError(info='operation not defined')

        ldap = self.api.Backend.ldap2
        self.log.info("IPA: virtual verify %s" % self.operation)

        operationdn = "cn=%s,%s,%s" % (self.operation, self.api.env.container_virtual, self.api.env.basedn)

        # By adding this unknown objectclass we do several things.
        # DS checks ACIs before the objectclass so we can test for ACI
        # errors to know if we have rights. If we do have rights then the
        # update will fail anyway with a Database error because of an
        # unknown objectclass, so we can catch that gracefully as well.
        try:
            updatekw = {'objectclass': ['somerandomunknownclass']}
            ldap.update(operationdn, **updatekw)
        except errors.ACIError, e:
            self.log.debug("%s" % str(e))
            raise errors.ACIError(info='not allowed to perform this command')
        except errors.ObjectclassViolation:
            return
        except Exception, e:
            # Something unexpected happened. Log it and deny access to be safe.
            self.log.info("Virtual verify failed: %s %s" % (type(e), str(e)))
            raise errors.ACIError(info='not allowed to perform this command')
