import turbogears
from turbogears import validators, widgets
from tg_expanding_form_widget.tg_expanding_form_widget import ExpandingForm

class PrincipalFields(object):
    hostname = widgets.TextField(name="hostname", label="Host Name")
    service = widgets.SingleSelectField(name="service",
            label="Service Type",
            options = [
                       ("cifs", "cifs"),
                       ("dhcp", "dhcp"),
                       ("dns", "dns"),
                       ("host", "host"),
                       ("HTTP", "HTTP"),
                       ("ldap", "ldap"),
                       ("other", "other"),
                       ("rpc", "rpc"),
                       ("snmp", "snmp")
                      ],
            attrs=dict(onchange="toggleOther(this.id)"))
    other = widgets.TextField(name="other", label="Other Service", attrs=dict(size=10))

class PrincipalNewValidator(validators.Schema):
    hostname = validators.String(not_empty=True)
    service = validators.String(not_empty=True)
    other = validators.String(not_empty=False)

class PrincipalNewForm(widgets.Form):
    params = ['principal_fields']

    validator = PrincipalNewValidator()

    def __init__(self, *args, **kw):
        super(PrincipalNewForm,self).__init__(*args, **kw)
        (self.template_c, self.template) = widgets.meta.load_kid_template("ipagui.templates.principalnewform")
        self.principal_fields = PrincipalFields

    def update_params(self, params):
        super(PrincipalNewForm,self).update_params(params)
