# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Martin Kosek <mkosek@redhat.com>
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

from ipalib import _, ngettext
from ipalib import Str
from ipalib import api, crud
from ipalib import output
from ipalib import Object
from ipalib.plugable import Registry
from .baseldap import gen_pkey_only_option, pkey_to_value

__doc__ = _("""
Group to Group Delegation

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

Group to Group Delegations grants the members of one group to update a set
of attributes of members of another group.

EXAMPLES:

 Add a delegation rule to allow managers to edit employee's addresses:
   ipa delegation-add --attrs=street --group=managers --membergroup=employees "managers edit employees' street"

 When managing the list of attributes you need to include all attributes
 in the list, including existing ones. Add postalCode to the list:
   ipa delegation-mod --attrs=street --attrs=postalCode --group=managers --membergroup=employees "managers edit employees' street"

 Display our updated rule:
   ipa delegation-show "managers edit employees' street"

 Delete a rule:
   ipa delegation-del "managers edit employees' street"
""")

register = Registry()

ACI_PREFIX=u"delegation"


@register()
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
        Str('permissions*',
            cli_name='permissions',
            label=_('Permissions'),
            doc=_('Permissions to grant (read, write). Default is write.'),
        ),
        Str('attrs+',
            cli_name='attrs',
            label=_('Attributes'),
            doc=_('Attributes to which the delegation applies'),
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
        Str('aci',
            label=_('ACI'),
            flags={'no_create', 'no_update', 'no_search'},
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

        json_dict['methods'] = list(self.methods)
        return json_dict

    def postprocess_result(self, result):
        try:
            # do not include prefix in result
            del result['aciprefix']
        except KeyError:
            pass



@register()
class delegation_add(crud.Create):
    __doc__ = _('Add a new delegation.')

    msg_summary = _('Added delegation "%(value)s"')

    def execute(self, aciname, **kw):
        if 'permissions' not in kw:
            kw['permissions'] = (u'write',)
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_add'](aciname, **kw)['result']
        self.obj.postprocess_result(result)

        return dict(
            result=result,
            value=pkey_to_value(aciname, kw),
        )



@register()
class delegation_del(crud.Delete):
    __doc__ = _('Delete a delegation.')

    has_output = output.standard_boolean
    msg_summary = _('Deleted delegation "%(value)s"')

    def execute(self, aciname, **kw):
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_del'](aciname, **kw)
        self.obj.postprocess_result(result)
        return dict(
            result=True,
            value=pkey_to_value(aciname, kw),
        )



@register()
class delegation_mod(crud.Update):
    __doc__ = _('Modify a delegation.')

    msg_summary = _('Modified delegation "%(value)s"')

    def execute(self, aciname, **kw):
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_mod'](aciname, **kw)['result']
        self.obj.postprocess_result(result)

        return dict(
            result=result,
            value=pkey_to_value(aciname, kw),
        )



@register()
class delegation_find(crud.Search):
    __doc__ = _('Search for delegations.')

    msg_summary = ngettext(
        '%(count)d delegation matched', '%(count)d delegations matched', 0
    )

    takes_options = (gen_pkey_only_option("name"),)

    def execute(self, term=None, **kw):
        kw['aciprefix'] = ACI_PREFIX
        results = api.Command['aci_find'](term, **kw)['result']

        for aci in results:
            self.obj.postprocess_result(aci)

        return dict(
            result=results,
            count=len(results),
            truncated=False,
        )



@register()
class delegation_show(crud.Retrieve):
    __doc__ = _('Display information about a delegation.')

    def execute(self, aciname, **kw):
        result = api.Command['aci_show'](aciname, aciprefix=ACI_PREFIX, **kw)['result']
        self.obj.postprocess_result(result)
        return dict(
            result=result,
            value=pkey_to_value(aciname, kw),
        )
