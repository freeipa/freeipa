# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
"""
Self-Service Permissions

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

A Self-Service permission defines what an object can change in its own entry.


EXAMPLES:

 Add a self-service rule to allow users to manage their address:
   ipa selfservice-add --permissions=write --attrs=street,postalCode,l,c,st "User's manage their own address"

 When managing the list of attributes you need to include all attributes
 in the list, including existing ones. Add telephoneNumber to the list:
   ipa selfservice-mod --attrs=street,postalCode,l,c,st,telephoneNumber "User's manage their own address"

 Display our updated rule:
   ipa selfservice-show "User's manage their own address"

 Delete a rule:
   ipa selfservice-del "User's manage their own address"
"""

import copy
from ipalib import api, _, ngettext
from ipalib import Flag, Str, List
from ipalib.request import context
from ipalib import api, crud, errors
from ipalib import output
from ipalib import Object, Command

def is_selfservice(aciname):
    """
    Determine if the ACI is a Self-Service ACI and raise an exception if it
    isn't.

    Return the result if it is a self-service ACI.
    """
    result = api.Command['aci_show'](aciname)['result']
    if 'selfaci' not in result or result['selfaci'] == False:
        raise errors.NotFound(reason=_('Self-service permission \'%(permission)s\' not found') % dict(permission=aciname))
    return result

class selfservice(Object):
    """
    Selfservice object.
    """

    bindable = False
    object_name = 'selfservice',
    object_name_plural = 'selfservice',
    label = _('Self Service Permissions')

    takes_params = (
        Str('aciname',
            cli_name='name',
            label=_('Self-Service name'),
            doc=_('Self-Service name'),
            primary_key=True,
        ),
        List('permissions?',
            cli_name='permissions',
            label=_('Permissions'),
            doc=_('Comma-separated list of permissions to grant ' \
                '(read, write). Default is write.'),
        ),
        List('attrs',
            cli_name='attrs',
            label=_('Attributes'),
            doc=_('Comma-separated list of attributes'),
            normalizer=lambda value: value.lower(),
        ),
    )

    def __json__(self):
        json_friendly_attributes = (
            'label', 'takes_params', 'bindable', 'name',
            'object_name', 'object_name_plural',
        )
        json_dict = dict(
            (a, getattr(self, a)) for a in json_friendly_attributes
        )
        json_dict['primary_key'] = self.primary_key.name
        json_dict['methods'] = [m for m in self.methods]
        return json_dict

api.register(selfservice)


class selfservice_add(crud.Create):
    """
    Add a new selfservice permission.
    """

    msg_summary = _('Added selfservice "%(value)s"')

    def execute(self, aciname, **kw):
        if not 'permissions' in kw:
            kw['permissions'] = (u'write',)
        kw['selfaci'] = True
        result = api.Command['aci_add'](aciname, **kw)['result']

        return dict(
            result=result,
            value=aciname,
        )

api.register(selfservice_add)


class selfservice_del(crud.Delete):
    """
    Delete a selfservice.
    """

    has_output = output.standard_delete
    msg_summary = _('Deleted selfservice "%(value)s"')

    def execute(self, aciname, **kw):
        is_selfservice(aciname)
        result = api.Command['aci_del'](aciname, **kw)
        return dict(
            result=True,
            value=aciname,
        )

api.register(selfservice_del)


class selfservice_mod(crud.Update):
    """
    Modify a selfservice.
    """

    msg_summary = _('Modified selfservice "%(value)s"')

    def execute(self, aciname, **kw):
        is_selfservice(aciname)
        result = api.Command['aci_mod'](aciname, **kw)['result']
        return dict(
            result=result,
            value=aciname,
        )

api.register(selfservice_mod)


class selfservice_find(crud.Search):
    """
    Search for selfservices.
    """

    msg_summary = ngettext(
        '%(count)d selfservice matched', '%(count)d selfservices matched'
    )

    def execute(self, term, **kw):
        kw['selfaci'] = True
        result = api.Command['aci_find'](term, **kw)['result']

        return dict(
            result=result,
            count=len(result),
            truncated=False,
        )

api.register(selfservice_find)


class selfservice_show(crud.Retrieve):
    """
    Display information about a selfservice.
    """
    has_output_params = (
        Str('aci',
            label=_('ACI'),
        ),
    )

    def execute(self, aciname, **kw):
        result = is_selfservice(aciname)
        return dict(
            result=result,
            value=aciname,
        )

api.register(selfservice_show)
