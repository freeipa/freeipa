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
import ipagui.forms.ipapolicy

import ldap.dn

log = logging.getLogger(__name__)

ipapolicy_edit_form = ipagui.forms.ipapolicy.IPAPolicyForm()

class IPAPolicyController(IPAController):

    @expose()
    def index(self):
        raise turbogears.redirect("/ipapolicy/show")

    @expose("ipagui.templates.ipapolicyshow")
    @identity.require(identity.not_anonymous())
    def show(self, tg_errors=None):
        """Displays the one policy page"""

        # TODO: Get this dict from LDAP
        ipapolicy = {}
        ipapolicy['searchlimit'] = 2
        ipapolicy['maxuidlength'] = 3
        ipapolicy['passwordnotif'] = 4
        return dict(ipapolicy=ipapolicy,fields=ipagui.forms.ipapolicy.IPAPolicyFields())

    @expose("ipagui.templates.ipapolicyedit")
    @identity.require(identity.not_anonymous())
    def edit(self, tg_errors=None):
        """Displays the edit IPA policy form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        try:
            # TODO: Get this dict from LDAP
            ipapolicy_dict = {}
            ipapolicy_dict['searchlimit'] = 2
            ipapolicy_dict['maxuidlength'] = 3
            ipapolicy_dict['passwordnotif'] = 4
            return dict(form=ipapolicy_edit_form, ipapolicy=ipapolicy_dict)
        except ipaerror.IPAError, e:
            turbogears.flash("IPA Policy edit failed: " + str(e) + "<br/>" + str(e.detail))
            raise turbogears.redirect('/group/show', uid=cn)


    @expose()
    @identity.require(identity.not_anonymous())
    def update(self, **kw):
        """Display delegate page"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit', '').startswith('Cancel'):
            turbogears.flash("Edit policy cancelled")
            raise turbogears.redirect('/ipapolicy/show')

        tg_errors, kw = self.ipapolicyupdatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
            return dict(form=ipapolicy_edit_form, ipapolicy=kw,
                    tg_template='ipagui.templates.ipapolicyedit')

        try:

            # TODO: Actually save the data

            turbogears.flash("IPA Policy updated")
            raise turbogears.redirect('/ipapolicy/show')
        except (SyntaxError, ipaerror.IPAError), e:
            turbogears.flash("Policy update failed: " + str(e))
            return dict(form=policy_form, policy=kw,
                        tg_template='ipagui.templates.policyindex')

    @validate(form=ipapolicy_edit_form)
    @identity.require(identity.not_anonymous())
    def ipapolicyupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw
