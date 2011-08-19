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
Group to Group Delegation

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

Group to Group Delegations grants the members of one group to update a set
of attributes of members of another group.

EXAMPLES:

 Add a delegation rule to allow managers to edit employee's addresses:
   ipa delegation-add --attrs=street --membergroup=managers --group=employees "managers edit employees' street"

 When managing the list of attributes you need to include all attributes
 in the list, including existing ones. Add postalCode to the list:
   ipa delegation-mod --attrs=street,postalCode --membergroup=managers --group=employees "managers edit employees' street"

 Display our updated rule:
   ipa delegation-show "managers edit employees' street"

 Delete a rule:
   ipa delegation-del "managers edit employees' street"
"""

import copy
from ipalib import api, _, ngettext
from ipalib import Flag, Str, List
from ipalib.request import context
from ipalib import api, crud, errors
from ipalib import output
from ipalib import Object, Command

ACI_PREFIX=u"delegation"

def convert_delegation(ldap, aci):
    """
    memberOf is in filter but we want to pull out the group for easier
    displaying.
    """
    filter = aci['memberof']
    st = filter.find('memberOf=')
    if st == -1:
        raise errors.NotFound(reason=_('Delegation \'%(permission)s\' not found') % dict(permission=aci['aciname']))
    en = filter.find(')', st)
    membergroup = filter[st+9:en]
    try:
        (dn, entry_attrs) = ldap.get_entry(membergroup, ['cn'])
    except Exception, e:
        # Uh oh, the group we're granting access to has an error
        msg = _('Error retrieving member group %(group)s: %(error)s') % (membergroup, str(e))
        raise errors.NonFatalError(reason=msg)
    aci['memberof'] = entry_attrs['cn'][0]

    del aci['aciprefix']     # do not include prefix in result

    return aci

def is_delegation(ldap, aciname):
    """
    Determine if the ACI is a Delegation ACI and raise an exception if it
    isn't.

    Return the result if it is a delegation ACI, adding a new attribute
    membergroup.
    """
    result = api.Command['aci_show'](aciname, aciprefix=ACI_PREFIX)['result']
    if 'memberof' in result:
        result = convert_delegation(ldap, result)
    else:
        raise errors.NotFound(reason=_('Delegation \'%(permission)s\' not found') % dict(permission=aciname))
    return result


class delegation(Object):
    """
    Delegation object.
    """

    bindable = False
    object_name = _('delegation')
    object_name_plural = _('delegations')
    label = _('Delegations')
    label_singular = _('Delegation')

    takes_params = (
        Str('aciname',
            cli_name='name',
            label=_('Delegation name'),
            doc=_('Delegation name'),
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
        Str('memberof',
            cli_name='membergroup',
            label=_('Member user group'),
            doc=_('User group to apply delegation to'),
        ),
        Str('group',
            cli_name='group',
            label=_('User group'),
            doc=_('User group ACI grants access to'),
        ),
    )

    def __json__(self):
        json_friendly_attributes = (
            'label', 'label_singular', 'takes_params', 'bindable', 'name',
            'object_name', 'object_name_plural',
        )
        json_dict = dict(
            (a, getattr(self, a)) for a in json_friendly_attributes
        )
        json_dict['primary_key'] = self.primary_key.name

        json_dict['methods'] = [m for m in self.methods]
        return json_dict

api.register(delegation)


class delegation_add(crud.Create):
    """
    Add a new delegation.
    """

    msg_summary = _('Added delegation "%(value)s"')

    def execute(self, aciname, **kw):
        ldap = self.api.Backend.ldap2
        if not 'permissions' in kw:
            kw['permissions'] = (u'write',)
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_add'](aciname, **kw)['result']
        if 'memberof' in result:
            result = convert_delegation(ldap, result)

        return dict(
            result=result,
            value=aciname,
        )

api.register(delegation_add)


class delegation_del(crud.Delete):
    """
    Delete a delegation.
    """

    has_output = output.standard_boolean
    msg_summary = _('Deleted delegation "%(value)s"')

    def execute(self, aciname, **kw):
        ldap = self.api.Backend.ldap2
        is_delegation(ldap, aciname)
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_del'](aciname, **kw)
        return dict(
            result=True,
            value=aciname,
        )

api.register(delegation_del)


class delegation_mod(crud.Update):
    """
    Modify a delegation.
    """

    msg_summary = _('Modified delegation "%(value)s"')

    def execute(self, aciname, **kw):
        ldap = self.api.Backend.ldap2
        is_delegation(ldap, aciname)
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_mod'](aciname, **kw)['result']
        if 'memberof' in result:
            result = convert_delegation(ldap, result)
        return dict(
            result=result,
            value=aciname,
        )

api.register(delegation_mod)


class delegation_find(crud.Search):
    """
    Search for delegations.
    """

    msg_summary = ngettext(
        '%(count)d delegation matched', '%(count)d delegations matched', 0
    )

    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap2
        kw['aciprefix'] = ACI_PREFIX
        acis = api.Command['aci_find'](term, **kw)['result']
        results = []
        for aci in acis:
            try:
                if 'memberof' in aci:
                    aci = convert_delegation(ldap, aci)
                    results.append(aci)
            except errors.NotFound:
                pass

        return dict(
            result=results,
            count=len(results),
            truncated=False,
        )

api.register(delegation_find)


class delegation_show(crud.Retrieve):
    """
    Display information about a delegation.
    """
    has_output_params = (
        Str('aci',
            label=_('ACI'),
        ),
    )

    def execute(self, aciname, **kw):
        ldap = self.api.Backend.ldap2
        result = is_delegation(ldap, aciname)
        return dict(
            result=result,
            value=aciname,
        )

api.register(delegation_show)
