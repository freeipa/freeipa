import os
from pickle import dumps, loads
from base64 import b64encode, b64decode
import copy
import logging

import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity

from ipacontroller import IPAController
from ipa.entity import utf8_encode_values
from ipa import ipaerror
import ipagui.forms.principal

import ldap.dn

log = logging.getLogger(__name__)

principal_new_form = ipagui.forms.principal.PrincipalNewForm()
principal_fields = ['*']

class PrincipalController(IPAController):

    @expose()
    @identity.require(identity.in_group("admins"))
    def index(self, tg_errors=None):
        raise turbogears.redirect("/principal/list")

    @expose("ipagui.templates.principalnew")
    @identity.require(identity.in_group("admins"))
    def new(self, tg_errors=None):
        """Displays the new service principal form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        client = self.get_ipaclient()

        return dict(form=principal_new_form, principal={})

    @expose()
    @identity.require(identity.in_group("admins"))
    def create(self, **kw):
        """Creates a service principal group"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add principal cancelled")
            raise turbogears.redirect('/')

        tg_errors, kw = self.principalcreatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
            return dict(form=principal_new_form, principal=kw,
                    tg_template='ipagui.templates.principalnew')

        principal_name = ""
        hostname = kw.get('hostname')
        #
        # Create the principal itself
        #
        try:
            if kw.get('service') == "other":
                service = kw.get('other')
                if not service:
                    turbogears.flash("Service type must be provided")
                    return dict(form=principal_new_form, principal=kw,
                            tg_template='ipagui.templates.principalnew')
            else:
                service = kw.get('service')

            # The realm is added by add_service_principal
            principal_name = utf8_encode_values(service + "/" + kw.get('hostname'))

            rv = client.add_service_principal(principal_name)
        except ipaerror.exception_for(ipaerror.LDAP_DUPLICATE):
            turbogears.flash("Service principal '%s' already exists" %
                    principal_name)
            return dict(form=principal_new_form, principal=kw,
                    tg_template='ipagui.templates.principalnew')
        except ipaerror.IPAError, e:
            turbogears.flash("Service principal add failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=principal_new_form, principal=kw,
                    tg_template='ipagui.templates.principalnew')

        turbogears.flash("%s added!" % principal_name)
        raise turbogears.redirect('/principal/list', hostname=hostname)

    @expose("ipagui.templates.principallist")
    @identity.require(identity.not_anonymous())
    def list(self, **kw):
        """Searches for service principals and displays list of results"""
        client = self.get_ipaclient()

        principals = None
        counter = 0
        hostname = kw.get('hostname')
        if hostname != None and len(hostname) > 0:
            try:
                principals = client.find_service_principal(hostname.encode('utf-8'), principal_fields, 0, 2)
                counter = principals[0]
                principals = principals[1:]

                if counter == -1:
                    turbogears.flash("These results are truncated.<br />" +
                                    "Please refine your search and try again.")

                # For each entry break out service type and hostname
                for i in range(len(principals)):
                    (service,host) = principals[i].krbprincipalname.split('/')
                    h = host.split('@')
                    principals[i].setValue('service', service)
                    principals[i].setValue('hostname', h[0])

            except ipaerror.IPAError, e:
                turbogears.flash("principal list failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
                raise turbogears.redirect("/principal/list")

        return dict(principals=principals, hostname=hostname, fields=ipagui.forms.principal.PrincipalFields())

    @validate(form=principal_new_form)
    @identity.require(identity.not_anonymous())
    def principalcreatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw
