import turbogears
from turbogears import validators, widgets

class GroupFields():
    cn = widgets.TextField(name="cn", label="Name")
    gidnumber = widgets.TextField(name="gidnumber", label="GID")
    description = widgets.TextField(name="description", label="Description")

    cn_hidden = widgets.HiddenField(name="cn")
    editprotected_hidden = widgets.HiddenField(name="editprotected")

    group_orig = widgets.HiddenField(name="group_orig")
    member_data = widgets.HiddenField(name="member_data")
    uid_to_cn_json = widgets.HiddenField(name="uid_to_cn_json")

class GroupNewValidator(validators.Schema):
    cn = validators.String(not_empty=True)
    description = validators.String(not_empty=False)


class GroupNewForm(widgets.Form):
    params = ['group']

    fields = [GroupFields.cn, GroupFields.description]

    validator = GroupNewValidator()

    def __init__(self, *args, **kw):
        super(GroupNewForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.groupnewform")
        self.group = GroupFields

    def update_params(self, params):
        super(GroupNewForm,self).update_params(params)


class GroupEditValidator(validators.Schema):
    gidnumber = validators.Int(not_empty=False)
    description = validators.String(not_empty=False)

    pre_validators = [
      validators.RequireIfPresent(required='gidnumber', present='editprotected'),
    ]

class GroupEditForm(widgets.Form):
    params = ['members', 'group']

    fields = [GroupFields.gidnumber, GroupFields.description,
              GroupFields.cn_hidden, GroupFields.editprotected_hidden,
              GroupFields.group_orig, GroupFields.member_data,
              GroupFields.uid_to_cn_json]

    validator = GroupEditValidator()

    def __init__(self, *args, **kw):
        super(GroupEditForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.groupeditform")
        self.group = GroupFields
