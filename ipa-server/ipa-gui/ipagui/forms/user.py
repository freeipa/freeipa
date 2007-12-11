import turbogears
from turbogears import validators, widgets
from tg_expanding_form_widget.tg_expanding_form_widget import ExpandingForm

class UserFields(object):
    givenname = widgets.TextField(name="givenname", label="First Name")
    sn = widgets.TextField(name="sn", label="Last Name")
    cn = widgets.TextField(name="cn", label="Common Names")
    cns = ExpandingForm(name="cns", label="Common Names", fields=[cn])
    title = widgets.TextField(name="title", label="Title")
    displayname = widgets.TextField(name="displayname", label="Display Name")
    initials = widgets.TextField(name="initials", label="Initials")

    uid = widgets.TextField(name="uid", label="Login", attrs=dict(onchange="warnRDN(this.id)"))
    userpassword = widgets.PasswordField(name="userpassword", label="Password")
    userpassword_confirm = widgets.PasswordField(name="userpassword_confirm",
            label="Confirm Password")
    uidnumber = widgets.TextField(name="uidnumber", label="UID")
    gidnumber = widgets.TextField(name="gidnumber", label="GID")
    homedirectory = widgets.TextField(name="homedirectory", label="Home Directory")
    loginshell = widgets.TextField(name="loginshell", label="Login Shell")
    gecos = widgets.TextField(name="gecos", label="GECOS")

    mail = widgets.TextField(name="mail", label="E-mail Address")
    telephonenumber = widgets.TextField(name="telephonenumber", label="Work Number")
    telephonenumbers = ExpandingForm(name="telephonenumbers", label="Work Numbers", fields=[telephonenumber])
    facsimiletelephonenumber = widgets.TextField(name="facsimiletelephonenumber",
            label="Fax Number")
    facsimiletelephonenumbers = ExpandingForm(name="facsimiletelephonenumbers", label="Fax Numbers", fields=[facsimiletelephonenumber])
    mobile = widgets.TextField(name="mobile", label="Cell Number")
    mobiles = ExpandingForm(name="mobiles", label="Cell Numbers", fields=[mobile])
    pager = widgets.TextField(name="pager", label="Pager Number")
    pagers = ExpandingForm(name="pagers", label="Pager Numbers", fields=[pager])
    homephone = widgets.TextField(name="homephone", label="Home Number")
    homephones = ExpandingForm(name="homephones", label="Home Numbers", fields=[homephone])

    street = widgets.TextField(name="street", label="Street Address")
    l = widgets.TextField(name="l", label="City")
    st = widgets.TextField(name="st", label="State")
    postalcode = widgets.TextField(name="postalcode", label="ZIP")

    ou = widgets.TextField(name="ou", label="Org Unit")
    businesscategory = widgets.TextField(name="businesscategory", label="Tags")
    description = widgets.TextField(name="description", label="Description")
    employeetype = widgets.TextField(name="employeetype", label="Employee Type")
    manager = widgets.HiddenField(name="manager", label="Manager")
    manager_cn = widgets.HiddenField(name="manager_cn", label="Manager")
    roomnumber = widgets.TextField(name="roomnumber", label="Room Number")
    secretary = widgets.HiddenField(name="secretary", label="Secretary")
    secretary_cn = widgets.HiddenField(name="secretary_cn", label="Manager")

    carlicense = widgets.TextField(name="carlicense", label="Car License")
    labeleduri = widgets.TextField(name="labeleduri", label="Home Page")

    nsAccountLock = widgets.SingleSelectField(name="nsAccountLock",
            label="Account Status",
            options = [("", "active"), ("true", "inactive")])

    uid_hidden = widgets.HiddenField(name="uid_hidden")
    krbPasswordExpiration_hidden = widgets.HiddenField(name="krbPasswordExpiration")
    editprotected_hidden = widgets.HiddenField(name="editprotected")

    user_orig = widgets.HiddenField(name="user_orig")
    user_groups_data = widgets.HiddenField(name="user_groups_data")
    dn_to_info_json = widgets.HiddenField(name="dn_to_info_json")

    custom_fields = []

class UserNewValidator(validators.Schema):
    uid = validators.PlainText(not_empty=True)
    userpassword = validators.String(not_empty=False)
    userpassword_confirm = validators.String(not_empty=False)
    givenname = validators.String(not_empty=True)
    sn = validators.String(not_empty=True)
    cn = validators.ForEach(validators.String(not_empty=True))
    mail = validators.Email(not_empty=False)

    chained_validators = [
      validators.FieldsMatch('userpassword', 'userpassword_confirm')
    ]


class UserNewForm(widgets.Form):
    params = ['user_fields', 'custom_fields']

    hidden_fields = [
      UserFields.dn_to_info_json,
      UserFields.manager,
      UserFields.manager_cn,
      UserFields.secretary,
      UserFields.secretary_cn,
    ]

    custom_fields = []

    validator = UserNewValidator()

    def __init__(self, *args, **kw):
        super(UserNewForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.usernewform")
        self.user_fields = UserFields

    def update_params(self, params):
        super(UserNewForm,self).update_params(params)

class UserEditValidator(validators.Schema):
    userpassword = validators.String(not_empty=False)
    userpassword_confirm = validators.String(not_empty=False)
    givenname = validators.String(not_empty=True)
    sn = validators.String(not_empty=True)
    cn = validators.ForEach(validators.String(not_empty=True))
    mail = validators.Email(not_empty=False)
    uidnumber = validators.Int(not_empty=False)
    gidnumber = validators.Int(not_empty=False)

    pre_validators = [
      validators.RequireIfPresent(required='uid', present='editprotected'),
      validators.RequireIfPresent(required='uidnumber', present='editprotected'),
      validators.RequireIfPresent(required='gidnumber', present='editprotected'),
    ]

    chained_validators = [
      validators.FieldsMatch('userpassword', 'userpassword_confirm')
    ]

class UserEditForm(widgets.Form):
    params = ['user_fields', 'custom_fields']

    hidden_fields = [
      UserFields.uid_hidden, UserFields.user_orig,
      UserFields.krbPasswordExpiration_hidden,
      UserFields.editprotected_hidden,
      UserFields.user_groups_data,
      UserFields.dn_to_info_json,
      UserFields.manager,
      UserFields.manager_cn,
      UserFields.secretary,
      UserFields.secretary_cn,
    ]

    custom_fields = []

    validator = UserEditValidator()

    def __init__(self, *args, **kw):
        super(UserEditForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.usereditform")
        self.user_fields = UserFields


# TODO - add dynamic field retrieval:
#      myfields=[]
#      schema = ipa.rpcclient.get_add_schema ()
# 
#      # FIXME: What if schema is None or an error is thrown?
# 
#      for s in schema:
#          required=False
# 
#          if (s['type'] == "text"):
#              field = widgets.TextField(name=s['name'],label=s['label'])
#          elif (s['type'] == "password"):
#              field = widgets.PasswordField(name=s['name'],label=s['label'])
# 
#          if (s['required'] == "true"):
#              required=True
# 
#          if (s['validator'] == "text"):
#              field.validator=validators.PlainText(not_empty=required)
#          elif (s['validator'] == "email"):
#              field.validator=validators.Email(not_empty=required)
#          elif (s['validator'] == "string"):
#              field.validator=validators.String(not_empty=required)
# 
#          myfields.append(field)
