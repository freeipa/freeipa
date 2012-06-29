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

from ipalib import api, _, ngettext
from ipalib import Flag, Str
from ipalib.request import context
from ipalib import api, crud, errors
from ipalib import output
from ipalib import Object, Command
from ipalib.plugins.baseldap import gen_pkey_only_option

__doc__ = _("""
Self-service Permissions

A permission enables fine-grained delegation of permissions. Access Control
Rules, or instructions (ACIs), grant permission to permissions to perform
given tasks such as adding a user, modifying a group, etc.

A Self-service permission defines what an object can change in its own entry.


EXAMPLES:

 Add a self-service rule to allow users to manage their address:
   ipa selfservice-add --permissions=write --attrs=street,postalCode,l,c,st "Users manage their own address"

 When managing the list of attributes you need to include all attributes
 in the list, including existing ones. Add telephoneNumber to the list:
   ipa selfservice-mod --attrs=street,postalCode,l,c,st,telephoneNumber "Users manage their own address"

 Display our updated rule:
   ipa selfservice-show "Users manage their own address"

 Delete a rule:
   ipa selfservice-del "Users manage their own address"
""")

ACI_PREFIX=u"selfservice"

output_params = (
    Str('aci',
        label=_('ACI'),
    ),
)


class selfservice(Object):
    """
    Selfservice object.
    """

    bindable = False
    object_name = _('self service permission')
    object_name_plural = _('self service permissions')
    label = _('Self Service Permissions')
    label_singular = _('Self Service Permission')

    takes_params = (
        Str('aciname',
            cli_name='name',
            label=_('Self-service name'),
            doc=_('Self-service name'),
            primary_key=True,
            pattern='^[-_ a-zA-Z0-9]+$',
            pattern_errmsg="May only contain letters, numbers, -, _, and space",
        ),
        Str('permissions*',
            cli_name='permissions',
            label=_('Permissions'),
            doc=_('Comma-separated list of permissions to grant ' \
                '(read, write). Default is write.'),
            csv=True,
        ),
        Str('attrs+',
            cli_name='attrs',
            label=_('Attributes'),
            doc=_('Comma-separated list of attributes'),
            csv=True,
            normalizer=lambda value: value.lower(),
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

    def postprocess_result(self, result):
        try:
            # do not include prefix in result
            del result['aciprefix']
        except KeyError:
            pass

api.register(selfservice)


class selfservice_add(crud.Create):
    __doc__ = _('Add a new self-service permission.')

    msg_summary = _('Added selfservice "%(value)s"')
    has_output_params = output_params

    def execute(self, aciname, **kw):
        if not 'permissions' in kw:
            kw['permissions'] = (u'write',)
        kw['selfaci'] = True
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_add'](aciname, **kw)['result']
        self.obj.postprocess_result(result)

        return dict(
            result=result,
            value=aciname,
        )

api.register(selfservice_add)


class selfservice_del(crud.Delete):
    __doc__ = _('Delete a self-service permission.')

    has_output = output.standard_boolean
    msg_summary = _('Deleted selfservice "%(value)s"')

    def execute(self, aciname, **kw):
        result = api.Command['aci_del'](aciname, aciprefix=ACI_PREFIX)
        self.obj.postprocess_result(result)

        return dict(
            result=True,
            value=aciname,
        )

api.register(selfservice_del)


class selfservice_mod(crud.Update):
    __doc__ = _('Modify a self-service permission.')

    msg_summary = _('Modified selfservice "%(value)s"')
    has_output_params = output_params

    def execute(self, aciname, **kw):
        if 'attrs' in kw and kw['attrs'] is None:
            raise errors.RequirementError(name='attrs')

        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_mod'](aciname, **kw)['result']
        self.obj.postprocess_result(result)

        return dict(
            result=result,
            value=aciname,
        )

api.register(selfservice_mod)


class selfservice_find(crud.Search):
    __doc__ = _('Search for a self-service permission.')

    msg_summary = ngettext(
        '%(count)d selfservice matched', '%(count)d selfservices matched', 0
    )

    takes_options = (gen_pkey_only_option("name"),)
    has_output_params = output_params

    def execute(self, term, **kw):
        kw['selfaci'] = True
        kw['aciprefix'] = ACI_PREFIX
        result = api.Command['aci_find'](term, **kw)['result']

        for aci in result:
            self.obj.postprocess_result(aci)

        return dict(
            result=result,
            count=len(result),
            truncated=False,
        )

api.register(selfservice_find)


class selfservice_show(crud.Retrieve):
    __doc__ = _('Display information about a self-service permission.')

    has_output_params = output_params

    def execute(self, aciname, **kw):
        result = api.Command['aci_show'](aciname, aciprefix=ACI_PREFIX, **kw)['result']
        self.obj.postprocess_result(result)
        return dict(
            result=result,
            value=aciname,
        )

api.register(selfservice_show)
