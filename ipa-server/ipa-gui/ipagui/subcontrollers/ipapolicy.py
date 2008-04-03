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
from ipagui.helpers import ipahelper

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

            # Load potential multi-valued fields
            if isinstance(ipapolicy_dict.get('ipauserobjectclasses',''), basestring):
                ipapolicy_dict['ipauserobjectclasses'] = [ipapolicy_dict.get('ipauserobjectclasses')]
            ipapolicy_dict['userobjectclasses'] = ipahelper.setup_mv_fields(ipapolicy_dict.get('ipauserobjectclasses'), 'ipauserobjectclasses')

            if isinstance(ipapolicy_dict.get('ipagroupobjectclasses',''), basestring):
                ipapolicy_dict['ipagroupobjectclasses'] = [ipapolicy_dict.get('ipagroupobjectclasses')]
            ipapolicy_dict['groupobjectclasses'] = ipahelper.setup_mv_fields(ipapolicy_dict.get('ipagroupobjectclasses'), 'ipagroupobjectclasses')

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

        # Fix incoming multi-valued fields we created for the form
        kw = ipahelper.fix_incoming_fields(kw, 'ipauserobjectclasses', 'userobjectclasses')
        kw = ipahelper.fix_incoming_fields(kw, 'ipagroupobjectclasses', 'groupobjectclasses')

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

            if str(new_ipapolicy.getValues('ipasearchtimelimit')) != str(kw.get('ipasearchtimelimit')):
                policy_modified = True
                new_ipapolicy.setValue('ipasearchtimelimit', kw.get('ipasearchtimelimit'))
            if str(new_ipapolicy.getValues('ipasearchrecordslimit')) != str(kw.get('ipasearchrecordslimit')):
                policy_modified = True
                new_ipapolicy.setValue('ipasearchrecordslimit', kw.get('ipasearchrecordslimit'))
            if new_ipapolicy.getValues('ipausersearchfields') != kw.get('ipausersearchfields'):
                policy_modified = True
                new_ipapolicy.setValue('ipausersearchfields', kw.get('ipausersearchfields'))
            if new_ipapolicy.getValues('ipagroupsearchfields') != kw.get('ipagroupsearchfields'):
                policy_modified = True
                new_ipapolicy.setValue('ipagroupsearchfields', kw.get('ipagroupsearchfields'))
            if str(new_ipapolicy.getValues('ipapwdexpadvnotify')) != str(kw.get('ipapwdexpadvnotify')):
                policy_modified = True
                new_ipapolicy.setValue('ipapwdexpadvnotify', kw.get('ipapwdexpadvnotify'))
            if str(new_ipapolicy.getValues('ipamaxusernamelength')) != str(kw.get('ipamaxusernamelength')):
                policy_modified = True
                new_ipapolicy.setValue('ipamaxusernamelength', kw.get('ipamaxusernamelength'))
            if new_ipapolicy.getValues('ipahomesrootdir') != kw.get('ipahomesrootdir'):
                policy_modified = True
                new_ipapolicy.setValue('ipahomesrootdir', kw.get('ipahomesrootdir'))
            if new_ipapolicy.getValues('ipadefaultloginshell') != kw.get('ipadefaultloginshell'):
                policy_modified = True
                new_ipapolicy.setValue('ipadefaultloginshell', kw.get('ipadefaultloginshell'))
            if new_ipapolicy.getValues('ipadefaultprimarygroup') != kw.get('ipadefaultprimarygroup'):
                policy_modified = True
                new_ipapolicy.setValue('ipadefaultprimarygroup', kw.get('ipadefaultprimarygroup'))
#            if new_ipapolicy.getValues('ipauserobjectclasses') != kw.get('ipauserobjectclasses'):
#                policy_modified = True
#                new_ipapolicy.setValue('ipauserobjectclasses', kw.get('ipauserobjectclasses'))
#            if new_ipapolicy.getValues('ipagroupobjectclasses') != kw.get('ipagroupobjectclasses'):
#                policy_modified = True
#                new_ipapolicy.setValue('ipagroupobjectclasses', kw.get('ipagroupobjectclasses'))
            if new_ipapolicy.getValues('ipadefaultemaildomain') != kw.get('ipadefaultemaildomain'):
                policy_modified = True
                new_ipapolicy.setValue('ipadefaultemaildomain', kw.get('ipadefaultemaildomain'))

            if policy_modified:
                rv = client.update_ipa_config(new_ipapolicy)

            # Now check the password policy for updates
            if str(new_password.getValues('krbmaxpwdlife')) != str(kw.get('krbmaxpwdlife')):
                password_modified = True
                new_password.setValue('krbmaxpwdlife', str(kw.get('krbmaxpwdlife')))
            if str(new_password.getValues('krbminpwdlife')) != str(kw.get('krbminpwdlife')):
                password_modified = True
                new_password.setValue('krbminpwdlife', str(kw.get('krbminpwdlife')))
            if str(new_password.getValues('krbpwdhistorylength')) != str(kw.get('krbpwdhistorylength')):
                password_modified = True
                new_password.setValue('krbpwdhistorylength', str(kw.get('krbpwdhistorylength')))
            if str(new_password.getValues('krbpwdmindiffchars')) != str(kw.get('krbpwdmindiffchars')):
                password_modified = True
                new_password.setValue('krbpwdmindiffchars', str(kw.get('krbpwdmindiffchars')))
            if str(new_password.getValues('krbpwdminlength')) != str(kw.get('krbpwdminlength')):
                password_modified = True
                new_password.setValue('krbpwdminlength', str(kw.get('krbpwdminlength')))
            if password_modified:
                rv = client.update_password_policy(new_password)

            turbogears.flash("IPA Policy updated")
            raise turbogears.redirect('/ipapolicy/show')
        except ipaerror.IPAError, e:
            turbogears.flash("Policy update failed: " + str(e) + "<br/>" + e.detail[0].get('desc','') + ". " + e.detail[0].get('info',''))
            return dict(form=ipapolicy_edit_form, ipapolicy=kw,
                        tg_template='ipagui.templates.ipapolicyedit')

    @validate(form=ipapolicy_edit_form)
    @identity.require(identity.not_anonymous())
    def ipapolicyupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw
