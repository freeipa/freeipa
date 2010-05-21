# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
HBAC Services
"""
import base64

from ipalib import api, errors
from ipalib import Str, Flag, Bytes
from ipalib.plugins.baseldap import *
from ipalib import x509
from pyasn1.error import PyAsn1Error
from ipalib import _, ngettext


class hbacsvc(LDAPObject):
    """
    HBAC Service object.
    """
    container_dn = api.env.container_hbacservice
    object_name = 'service'
    object_name_plural = 'services'
    object_class = [ 'ipaobject', 'ipahbacservice' ]
    default_attributes = ['cn', 'description']
    uuid_attribute = 'ipauniqueid'

    label = _('Services')

    takes_params = (
        Str('cn',
            cli_name='service',
            label=_('Service name'),
            doc=_('HBAC Service'),
            primary_key=True,
            normalizer=lambda value: value.lower(),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
            doc=_('Description of service'),
        ),
    )

api.register(hbacsvc)


class hbacsvc_add(LDAPCreate):
    """
    Add new HBAC service.
    """
    msg_summary = _('Added service "%(value)s"')

api.register(hbacsvc_add)


class hbacsvc_del(LDAPDelete):
    """
    Delete an existing HBAC service.
    """
    msg_summary = _('Deleted service "%(value)s"')

api.register(hbacsvc_del)


class hbacsvc_mod(LDAPUpdate):
    """
    Modify HBAC service.
    """

api.register(hbacsvc_mod)


class hbacsvc_find(LDAPSearch):
    """
    Search for HBAC services.
    """

api.register(hbacsvc_find)


class hbacsvc_show(LDAPRetrieve):
    """
    Display HBAC service.
    """

api.register(hbacsvc_show)
