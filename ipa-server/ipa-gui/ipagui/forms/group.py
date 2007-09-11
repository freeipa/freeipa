import turbogears
from turbogears import validators, widgets

class GroupFields():
    cn = widgets.TextField(name="cn", label="Name")
    gidnumber = widgets.TextField(name="gidnumber", label="GID")
    description = widgets.TextField(name="description", label="Description")

    cn_hidden = widgets.HiddenField(name="cn")

    group_orig = widgets.HiddenField(name="group_orig")

class GroupNewValidator(validators.Schema):
    cn = validators.PlainText(not_empty=True)
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
    gidnumber = widgets.TextField(name="gidnumber", label="GID")
    description = widgets.TextField(name="description", label="Description")

class GroupEditForm(widgets.Form):
    params = ['group']

    fields = [GroupFields.gidnumber, GroupFields.description]

    validator = GroupEditValidator()

    def __init__(self, *args, **kw):
        super(GroupEditForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.groupeditform")
        self.group = GroupFields
