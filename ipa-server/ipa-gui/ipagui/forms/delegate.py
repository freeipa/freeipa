# Copyright (C) 2007  Red Hat
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
#

import turbogears
from turbogears import validators, widgets
from ipagui.helpers import ipahelper

from ipagui.forms.user import UserFields

# TODO - get from config or somewhere
aci_attrs = [
  UserFields.givenname,
  UserFields.sn,
  UserFields.cn,
  UserFields.title,
  UserFields.displayname,
  UserFields.initials,
  UserFields.uid,
  UserFields.krbprincipalkey,
  UserFields.uidnumber,
  UserFields.gidnumber,
  UserFields.homedirectory,
  UserFields.loginshell,
  UserFields.gecos,
  UserFields.mail,
  UserFields.telephonenumber,
  UserFields.facsimiletelephonenumber,
  UserFields.mobile,
  UserFields.pager,
  UserFields.homephone,
  UserFields.street,
  UserFields.l,
  UserFields.st,
  UserFields.postalcode,
  UserFields.ou,
  UserFields.businesscategory,
  UserFields.description,
  UserFields.employeetype,
  UserFields.manager,
  UserFields.roomnumber,
  UserFields.secretary,
  UserFields.carlicense,
  UserFields.labeleduri,
]

aci_checkbox_attrs = [(field.name, field.label) for field in aci_attrs]

aci_name_to_label = dict(aci_checkbox_attrs)

class DelegateFields(object):
    name = widgets.TextField(name="name", label="Delegation Name")

    source_group_dn = widgets.HiddenField(name="source_group_dn")
    dest_group_dn = widgets.HiddenField(name="dest_group_dn")

    source_group_cn = widgets.HiddenField(name="source_group_cn",
        label="People in Group")
    dest_group_cn = widgets.HiddenField(name="dest_group_cn",
        label="For People in Group")

    orig_acistr = widgets.HiddenField(name="orig_acistr")

    attrs = widgets.CheckBoxList(name="attrs", label="Can Modify",
            options=aci_checkbox_attrs, validator=validators.NotEmpty)

class DelegateValidator(validators.Schema):
    name = validators.String(not_empty=True)
    source_group_dn = validators.String(not_empty=True,
        messages = { 'empty': _("Please choose a group"), })
    dest_group_dn = validators.String(not_empty=True,
        messages = { 'empty': _("Please choose a group"), })
    # There is no attrs validator here because then it shows as one
    # huge block of color in the form. The validation is done in
    # the subcontroller.

class DelegateForm(widgets.Form):
    params = ['delegate_fields', 'attr_list']

    hidden_fields = [
      DelegateFields.source_group_dn,
      DelegateFields.dest_group_dn,
      DelegateFields.source_group_cn,
      DelegateFields.dest_group_cn,
      DelegateFields.orig_acistr,
    ]

    validator = DelegateValidator()

    def __init__(self, *args, **kw):
        super(DelegateForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = ipahelper.load_template(
                "ipagui.templates.delegateform")
        self.delegate_fields = DelegateFields

    def update_params(self, params):
        super(DelegateForm,self).update_params(params)
