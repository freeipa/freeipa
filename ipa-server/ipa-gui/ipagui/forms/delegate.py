import turbogears
from turbogears import validators, widgets

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
  UserFields.userpassword,
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

class DelegateFields():
    name = widgets.TextField(name="name", label="ACI Name")

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
    attrs = validators.NotEmpty(
        messages = { 'empty': _("Please select at least one value"), })

class DelegateForm(widgets.Form):
    params = ['delegate', 'attr_list']

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
        (self.template_c, self.template) = widgets.meta.load_kid_template(
                "ipagui.templates.delegateform")
        self.delegate = DelegateFields

    def update_params(self, params):
        super(DelegateForm,self).update_params(params)
