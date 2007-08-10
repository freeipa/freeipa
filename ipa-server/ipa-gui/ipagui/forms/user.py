import turbogears
from turbogears import validators, widgets

class UserFields():
    uid = widgets.TextField(name="uid", label="Login:")
    userPassword = widgets.TextField(name="userPassword", label="Password:")
    uidNumber = widgets.TextField(name="uidNumber", label="UID:")
    gidNumber = widgets.TextField(name="gidNumber", label="GID:")
    givenName = widgets.TextField(name="givenName", label="First name:")
    sn = widgets.TextField(name="sn", label="Last name:")
    mail = widgets.TextField(name="mail", label="E-mail address:")
    telephoneNumber = widgets.TextField(name="telephoneNumber", label="Phone:")

    uid.validator = validators.PlainText(not_empty=True)
    userPassword.validator = validators.String(not_empty=True)
    givenName.validator = validators.String(not_empty=True)
    sn.validator = validators.String(not_empty=True)
    mail.validator = validators.Email(not_empty=True)
    #  validators.PhoneNumber may be a bit too picky, requiring an area code
    telephoneNumber.validator = validators.PlainText(not_empty=True)

    uid_hidden = widgets.HiddenField(name="uid")
    uidNumber_hidden = widgets.HiddenField(name="uidNumber")
    gidNumber_hidden = widgets.HiddenField(name="gidNumber")
    givenName_orig = widgets.HiddenField(name="givenName_orig")
    sn_orig = widgets.HiddenField(name="sn_orig")
    mail_orig = widgets.HiddenField(name="mail_orig")
    telephoneNumber_orig = widgets.HiddenField(name="telephoneNumber_orig")


class UserNewForm(widgets.Form):
    params = ['user']

    fields = [UserFields.uid, UserFields.givenName,
              UserFields.uidNumber, UserFields.gidNumber,
              UserFields.sn, UserFields.mail]

    def __init__(self, *args, **kw):
        super(UserNewForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.usernewform")
        self.user = UserFields

    def update_params(self, params):
        super(UserNewForm,self).update_params(params)
        params['has_foo'] = self.has_foo

    def has_foo(self):
        return False


class UserEditForm(widgets.Form):
    params = ['user']

    fields = [UserFields.givenName, UserFields.sn, UserFields.mail,
              UserFields.givenName_orig, UserFields.sn_orig, UserFields.mail_orig,
              UserFields.uid_hidden,
              UserFields.uidNumber_hidden, UserFields.gidNumber_hidden]

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
