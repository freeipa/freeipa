# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import turbogears
from turbogears import validators, widgets
from tg_expanding_form_widget.tg_expanding_form_widget import ExpandingForm
from ipagui.helpers import ipahelper

class PrincipalFields(object):
    hostname = widgets.TextField(name="hostname", label="Host Name")
    service = widgets.SingleSelectField(name="service",
            label="Service Type",
            options = [
                       ("cifs", "cifs"),
                       ("dns", "dns"),
                       ("host", "host"),
                       ("HTTP", "HTTP"),
                       ("ldap", "ldap"),
                       ("nfs", "nfs"),
                       ("other", "other")
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
        (self.template_c, self.template) = ipahelper.load_template("ipagui.templates.principalnewform")
        self.principal_fields = PrincipalFields

    def update_params(self, params):
        super(PrincipalNewForm,self).update_params(params)
