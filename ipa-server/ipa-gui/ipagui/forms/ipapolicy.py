import turbogears
from turbogears import validators, widgets

class IPAPolicyFields():
    searchlimit = widgets.TextField(name="searchlimit", label="Search Time Limit", attrs=dict(size=6,maxlength=6))
    maxuidlength = widgets.TextField(name="maxuidlength", label="Max. UID Length", attrs=dict(size=3,maxlength=3))
    passwordnotif = widgets.TextField(name="passwordnotif", label="Password Expiration Notification (days)", attrs=dict(size=3,maxlength=3))

class IPAPolicyValidator(validators.Schema):
    searchlimit = validators.Number(not_empty=True)
    maxuidlength = validators.Number(not_empty=True)
    passwordnotif = validators.Number(not_empty=True)

class IPAPolicyForm(widgets.Form):
    params = ['ipapolicy_fields']

    hidden_fields = [
    ]

    validator = IPAPolicyValidator()

    def __init__(self, *args, **kw):
        super(IPAPolicyForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template(
                "ipagui.templates.ipapolicyeditform")
        self.ipapolicy_fields = IPAPolicyFields

    def update_params(self, params):
        super(IPAPolicyForm,self).update_params(params)
