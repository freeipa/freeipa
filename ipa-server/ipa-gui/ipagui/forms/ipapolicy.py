import turbogears
from turbogears import validators, widgets

class IPAPolicyFields(object):
    # From cn=ipaConfig
    ipausersearchfields =  widgets.TextField(name="ipausersearchfields", label="User Search Fields", attrs=dict(size=50))
    ipagroupsearchfields =  widgets.TextField(name="ipagroupsearchfields", label="Group Search Fields")
    ipasearchtimelimit = widgets.TextField(name="ipasearchtimelimit", label="Search Time Limit (sec.)", attrs=dict(size=6,maxlength=6))
    ipasearchrecordslimit = widgets.TextField(name="ipasearchrecordslimit", label="Search Records Limit", attrs=dict(size=6,maxlength=6))
    ipahomesrootdir = widgets.TextField(name="ipahomesrootdir", label="Root for Home Directories")
    ipadefaultloginshell = widgets.TextField(name="ipadefaultloginshell", label="Default shell")
    ipadefaultprimarygroup = widgets.TextField(name="ipadefaultprimarygroup", label="Default Users group")
    ipamaxusernamelength = widgets.TextField(name="ipamaxusernamelength", label="Max. Username Length", attrs=dict(size=3,maxlength=3))
    ipapwdexpadvnotify = widgets.TextField(name="ipapwdexpadvnotify", label="Password Expiration Notification (days)", attrs=dict(size=3,maxlength=3))

    ipapolicy_orig = widgets.HiddenField(name="ipapolicy_orig")

    # From cn=accounts
    krbmaxpwdlife = widgets.TextField(name="krbmaxpwdlife", label="Max. Password Lifetime (days)", attrs=dict(size=3,maxlength=3))
    krbminpwdlife = widgets.TextField(name="krbminpwdlife", label="Min. Password Lifetime (hours)", attrs=dict(size=3,maxlength=3))
    krbpwdmindiffchars = widgets.TextField(name="krbpwdmindiffchars", label="Min. number of character classes", attrs=dict(size=3,maxlength=3))
    krbpwdminlength = widgets.TextField(name="krbpwdminlength", label="Min. Length of password", attrs=dict(size=3,maxlength=3))
    krbpwdhistorylength = widgets.TextField(name="krbpwdhistorylength", label="Password History size", attrs=dict(size=3,maxlength=3))

    password_orig = widgets.HiddenField(name="password_orig")

class IPAPolicyValidator(validators.Schema):
    ipausersearchfields = validators.String(not_empty=True)
    ipagroupsearchfields = validators.String(not_empty=True)
    ipasearchtimelimit = validators.Number(not_empty=True)
    ipasearchrecordslimit = validators.Number(not_empty=True)
    ipamaxusernamelength = validators.Number(not_empty=True)
    ipapwdexpadvnotify = validators.Number(not_empty=True)
    ipahomesrootdir = validators.String(not_empty=True)
    ipadefaultloginshell = validators.String(not_empty=True)
    ipadefaultprimarygroup = validators.String(not_empty=True)
    krbmaxpwdlife = validators.Number(not_empty=True)
    krbminpwdlife = validators.Number(not_empty=True)
    krbpwdmindiffchars = validators.Number(not_empty=True)
    krbpwdminlength = validators.Number(not_empty=True)
    krbpwdhistorylength = validators.Number(not_empty=True)

class IPAPolicyForm(widgets.Form):
    params = ['ipapolicy_fields']

    hidden_fields = [
        IPAPolicyFields.ipapolicy_orig, IPAPolicyFields.password_orig
    ]

    validator = IPAPolicyValidator()

    def __init__(self, *args, **kw):
        super(IPAPolicyForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template(
                "ipagui.templates.ipapolicyeditform")
        self.ipapolicy_fields = IPAPolicyFields

    def update_params(self, params):
        super(IPAPolicyForm,self).update_params(params)
