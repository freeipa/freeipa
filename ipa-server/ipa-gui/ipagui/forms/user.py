import turbogears
from turbogears import validators, widgets

class UserFields():
    uid = widgets.TextField(name="uid", label="Login")
    userpassword = widgets.PasswordField(name="userpassword", label="Password")
    userpassword_confirm = widgets.PasswordField(name="userpassword_confirm",
            label="Confirm Password")
    uidnumber = widgets.TextField(name="uidnumber", label="UID")
    gidnumber = widgets.TextField(name="gidnumber", label="GID")
    givenname = widgets.TextField(name="givenname", label="First name")
    sn = widgets.TextField(name="sn", label="Last name")
    mail = widgets.TextField(name="mail", label="E-mail address")
    telephonenumber = widgets.TextField(name="telephonenumber", label="Phone")
    # nsAccountLock = widgets.CheckBox(name="nsAccountLock", label="Account Deactivated")
    nsAccountLock = widgets.SingleSelectField(name="nsAccountLock",
            label="Account Status",
            options = [("", "active"), ("true", "inactive")])

    uid_hidden = widgets.HiddenField(name="uid")
    uidnumber_hidden = widgets.HiddenField(name="uidnumber")
    gidnumber_hidden = widgets.HiddenField(name="gidnumber")
    krbPasswordExpiration_hidden = widgets.HiddenField(name="krbPasswordExpiration")
    editprotected_hidden = widgets.HiddenField(name="editprotected")

    user_orig = widgets.HiddenField(name="user_orig")
    user_groups_data = widgets.HiddenField(name="user_groups_data")
    dn_to_info_json = widgets.HiddenField(name="dn_to_info_json")

class UserNewValidator(validators.Schema):
    uid = validators.PlainText(not_empty=True)
    userpassword = validators.String(not_empty=False)
    userpassword_confirm = validators.String(not_empty=False)
    givenname = validators.String(not_empty=True)
    sn = validators.String(not_empty=True)
    mail = validators.Email(not_empty=True)
    #  validators.PhoneNumber may be a bit too picky, requiring an area code
    # telephonenumber = validators.PlainText(not_empty=False)

    chained_validators = [
      validators.FieldsMatch('userpassword', 'userpassword_confirm')
    ]


class UserNewForm(widgets.Form):
    params = ['user']

    fields = [UserFields.uid, UserFields.givenname,
              UserFields.sn, UserFields.mail,
              UserFields.dn_to_info_json,
             ]

    validator = UserNewValidator()

    def __init__(self, *args, **kw):
        super(UserNewForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.usernewform")
        self.user = UserFields

    def update_params(self, params):
        super(UserNewForm,self).update_params(params)
        params['has_foo'] = self.has_foo

    def has_foo(self):
        return False

class UserEditValidator(validators.Schema):
    userpassword = validators.String(not_empty=False)
    userpassword_confirm = validators.String(not_empty=False)
    givenname = validators.String(not_empty=True)
    sn = validators.String(not_empty=True)
    mail = validators.Email(not_empty=True)
    uidnumber = validators.Int(not_empty=False)
    gidnumber = validators.Int(not_empty=False)
    #  validators.PhoneNumber may be a bit too picky, requiring an area code
    # telephonenumber = validators.PlainText(not_empty=False)

    pre_validators = [
      validators.RequireIfPresent(required='uidnumber', present='editprotected'),
      validators.RequireIfPresent(required='gidnumber', present='editprotected'),
    ]

    chained_validators = [
      validators.FieldsMatch('userpassword', 'userpassword_confirm')
    ]

class UserEditForm(widgets.Form):
    params = ['user']

    fields = [UserFields.givenname, UserFields.sn, UserFields.mail,
              UserFields.uid_hidden, UserFields.user_orig,
              UserFields.uidnumber, UserFields.gidnumber,
              UserFields.krbPasswordExpiration_hidden,
              UserFields.editprotected_hidden,
              UserFields.user_groups_data,
              UserFields.dn_to_info_json,
              ]

    validator = UserEditValidator()

    def __init__(self, *args, **kw):
        super(UserEditForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.usereditform")
        self.user = UserFields


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
