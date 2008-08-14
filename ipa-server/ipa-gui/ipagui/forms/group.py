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
from tg_expanding_form_widget.tg_expanding_form_widget import ExpandingForm
from ipagui.helpers import ipahelper,validators

class GroupFields(object):
    cn = widgets.TextField(name="cn", label="Name")
    gidnumber = widgets.TextField(name="gidnumber", label="GID")
    description = widgets.TextField(name="description", label="Description")

    editprotected_hidden = widgets.HiddenField(name="editprotected")

    nsAccountLock = widgets.SingleSelectField(name="nsAccountLock",
            label="Group Status",
            options = [("", "active"), ("true", "inactive")])

    group_orig = widgets.HiddenField(name="group_orig")
    member_data = widgets.HiddenField(name="member_data")
    dn_to_info_json = widgets.HiddenField(name="dn_to_info_json")

class GroupNewValidator(validators.Schema):
    cn = validators.GoodName(not_empty=True)
    description = validators.String(not_empty=False)


class GroupNewForm(widgets.Form):
    params = ['group_fields']

    hidden_fields = [
      GroupFields.dn_to_info_json
    ]

    validator = GroupNewValidator()

    def __init__(self, *args, **kw):
        super(GroupNewForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = ipahelper.load_template("ipagui.templates.groupnewform")
        self.group_fields = GroupFields

    def update_params(self, params):
        super(GroupNewForm,self).update_params(params)


class GroupEditValidator(validators.Schema):
    cn = validators.GoodName(not_empty=False)
    gidnumber = validators.Int(not_empty=False)
    description = validators.String(not_empty=False)

    pre_validators = [
      validators.RequireIfPresent(required='cn', present='editprotected'),
      validators.RequireIfPresent(required='gidnumber', present='editprotected'),
    ]

class GroupEditForm(widgets.Form):
    params = ['members', 'group_fields']

    hidden_fields = [
      GroupFields.editprotected_hidden,
      GroupFields.group_orig, GroupFields.member_data,
      GroupFields.dn_to_info_json
    ]

    validator = GroupEditValidator()

    def __init__(self, *args, **kw):
        super(GroupEditForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = ipahelper.load_template("ipagui.templates.groupeditform")
        self.group_fields = GroupFields
