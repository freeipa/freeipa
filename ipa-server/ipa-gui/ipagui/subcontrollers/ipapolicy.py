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
import ipa.entity
import ipagui.forms.ipapolicy

import ldap.dn

log = logging.getLogger(__name__)

ipapolicy_edit_form = ipagui.forms.ipapolicy.IPAPolicyForm()

class IPAPolicyController(IPAController):

    @expose()
    @identity.require(identity.in_group("admins"))
    def index(self):
        raise turbogears.redirect("/ipapolicy/show")

    @expose("ipagui.templates.ipapolicyshow")
    @identity.require(identity.in_group("admins"))
    def show(self, tg_errors=None):
        """Displays the one policy page"""
        client = self.get_ipaclient()
        config = client.get_ipa_config()
        ipapolicy = config.toDict()

        ppolicy = client.get_password_policy()
        password = ppolicy.toDict()

        return dict(ipapolicy=ipapolicy,password=password,fields=ipagui.forms.ipapolicy.IPAPolicyFields())

    @expose("ipagui.templates.ipapolicyedit")
    @identity.require(identity.in_group("admins"))
    def edit(self, tg_errors=None):
        """Displays the edit IPA policy form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        try:
            client = self.get_ipaclient()
            config = client.get_ipa_config()
            ipapolicy_dict = config.toDict()

            ppolicy = client.get_password_policy()
            password_dict = ppolicy.toDict()

            # store a copy of the original policy for the update later
            ipapolicy_data = b64encode(dumps(ipapolicy_dict))
            ipapolicy_dict['ipapolicy_orig'] = ipapolicy_data

            # store a copy of the original policy for the update later
            password_data = b64encode(dumps(password_dict))
            password_dict['password_orig'] = password_data

            # Combine the 2 dicts to make the form easier
            ipapolicy_dict.update(password_dict)

            return dict(form=ipapolicy_edit_form, ipapolicy=ipapolicy_dict)
        except ipaerror.IPAError, e:
            turbogears.flash("IPA Policy edit failed: " + str(e) + "<br/>" + str(e.detail))
            raise turbogears.redirect('/ipapolicy/show')


    @expose()
    @identity.require(identity.in_group("admins"))
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

        policy_modified = False
        password_modified = False

        try:
            orig_ipapolicy_dict = loads(b64decode(kw.get('ipapolicy_orig')))
            orig_password_dict = loads(b64decode(kw.get('password_orig')))

            new_ipapolicy = ipa.entity.Entity(orig_ipapolicy_dict)
            new_password = ipa.entity.Entity(orig_password_dict)

            if str(new_ipapolicy.ipasearchtimelimit) != str(kw.get('ipasearchtimelimit')):
                policy_modified = True
                new_ipapolicy.setValue('ipasearchtimelimit', kw.get('ipasearchtimelimit'))
            if str(new_ipapolicy.ipasearchrecordslimit) != str(kw.get('ipasearchrecordslimit')):
                policy_modified = True
                new_ipapolicy.setValue('ipasearchrecordslimit', kw.get('ipasearchrecordslimit'))
            if new_ipapolicy.ipausersearchfields != kw.get('ipausersearchfields'):
                policy_modified = True
                new_ipapolicy.setValue('ipausersearchfields', kw.get('ipausersearchfields'))
            if new_ipapolicy.ipagroupsearchfields != kw.get('ipagroupsearchfields'):
                policy_modified = True
                new_ipapolicy.setValue('ipagroupsearchfields', kw.get('ipagroupsearchfields'))
            if str(new_ipapolicy.ipapwdexpadvnotify) != str(kw.get('ipapwdexpadvnotify')):
                policy_modified = True
                new_ipapolicy.setValue('ipapwdexpadvnotify', kw.get('ipapwdexpadvnotify'))
            if str(new_ipapolicy.ipamaxusernamelength) != str(kw.get('ipamaxusernamelength')):
                policy_modified = True
                new_ipapolicy.setValue('ipamaxusernamelength', kw.get('ipamaxusernamelength'))
            if new_ipapolicy.ipahomesrootdir != kw.get('ipahomesrootdir'):
                policy_modified = True
                new_ipapolicy.setValue('ipahomesrootdir', kw.get('ipahomesrootdir'))
            if new_ipapolicy.ipadefaultloginshell != kw.get('ipadefaultloginshell'):
                policy_modified = True
                new_ipapolicy.setValue('ipadefaultloginshell', kw.get('ipadefaultloginshell'))
            if new_ipapolicy.ipadefaultprimarygroup != kw.get('ipadefaultprimarygroup'):
                policy_modified = True
                new_ipapolicy.setValue('ipadefaultprimarygroup', kw.get('ipadefaultprimarygroup'))

            if policy_modified:
                rv = client.update_ipa_config(new_ipapolicy)

            # Now check the password policy for updates
            if str(new_password.krbmaxpwdlife) != str(kw.get('krbmaxpwdlife')):
                password_modified = True
                new_password.setValue('krbmaxpwdlife', str(kw.get('krbmaxpwdlife')))
            if str(new_password.krbminpwdlife) != str(kw.get('krbminpwdlife')):
                password_modified = True
                new_password.setValue('krbminpwdlife', str(kw.get('krbminpwdlife')))
            if str(new_password.krbpwdhistorylength) != str(kw.get('krbpwdhistorylength')):
                password_modified = True
                new_password.setValue('krbpwdhistorylength', str(kw.get('krbpwdhistorylength')))
            if str(new_password.krbpwdmindiffchars) != str(kw.get('krbpwdmindiffchars')):
                password_modified = True
                new_password.setValue('krbpwdmindiffchars', str(kw.get('krbpwdmindiffchars')))
            if str(new_password.krbpwdminlength) != str(kw.get('krbpwdminlength')):
                password_modified = True
                new_password.setValue('krbpwdminlength', str(kw.get('krbpwdminlength')))
            if password_modified:
                rv = client.update_password_policy(new_password)

            turbogears.flash("IPA Policy updated")
            raise turbogears.redirect('/ipapolicy/show')
        except ipaerror.IPAError, e:
            turbogears.flash("Policy update failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=ipapolicy_edit_form, ipapolicy=kw,
                        tg_template='ipagui.templates.ipapolicyedit')

    @validate(form=ipapolicy_edit_form)
    @identity.require(identity.not_anonymous())
    def ipapolicyupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw
