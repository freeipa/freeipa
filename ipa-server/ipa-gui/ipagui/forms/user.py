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


class UserFormWidget(widgets.Form):
    params = ['user']
#     fields = [UserFields.uid, UserFields.userPassword, UserFields.givenName,
#               UserFields.sn, UserFields.mail]
    fields = [UserFields.uid, UserFields.givenName,
              UserFields.uidNumber, UserFields.gidNumber,
               UserFields.sn, UserFields.mail]

    def __init__(self, *args, **kw):
        super(UserFormWidget,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.userform")
        self.user = UserFields

    def update_params(self, params):
        super(UserFormWidget,self).update_params(params)
        params['has_foo'] = self.has_foo

    def has_foo(self):
        return False

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
