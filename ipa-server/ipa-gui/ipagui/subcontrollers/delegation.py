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
import ipagui.forms.delegate
import ipa.aci

import ldap.dn
import operator

log = logging.getLogger(__name__)

aci_fields = ['*', 'aci']

delegate_form = ipagui.forms.delegate.DelegateForm()

class DelegationController(IPAController):

    @expose()
    @identity.require(identity.not_anonymous())
    def index(self, tg_errors=None):
        raise turbogears.redirect("/delegate/list")

    @expose("ipagui.templates.delegatenew")
    @identity.require(identity.in_group("admins"))
    def new(self):
        """Display delegate page"""
        client = self.get_ipaclient()
        delegate = {}
        delegate['source_group_cn'] = "Please choose:"
        delegate['dest_group_cn'] = "Please choose:"

        return dict(form=delegate_form, delegate=delegate)

    @expose()
    @identity.require(identity.in_group("admins"))
    def create(self, **kw):
        """Creates a new delegation"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit', '').startswith('Cancel'):
            turbogears.flash("Add delegation cancelled")
            raise turbogears.redirect('/delegate/list')

        # Try to handle the case where the user entered just some data
        # into the source/dest group name but didn't do a Find. We'll do
        # our best to see if a group by that name exists and if so, use it.
        dest_group_dn = kw.get('dest_group_dn')
        dest_group_cn = kw.get('dest_group_cn')
        if not dest_group_dn and dest_group_cn:
            try:
                group = client.get_entry_by_cn(dest_group_cn, ['dn'])
                kw['dest_group_dn'] = group.dn
            except:
                kw['dest_group_cn'] = "Please choose:"
        source_group_dn = kw.get('source_group_dn')
        source_group_cn = kw.get('source_group_cn')
        if not source_group_dn and source_group_cn:
            try:
                group = client.get_entry_by_cn(source_group_cn, ['dn'])
                kw['source_group_dn'] = group.dn
            except:
                kw['source_group_cn'] = "Please choose:"
        tg_errors, kw = self.delegatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
            return dict(form=delegate_form, delegate=kw,
                    tg_template='ipagui.templates.delegatenew')

        try:
            aci_entry = client.get_aci_entry(aci_fields)

            new_aci = ipa.aci.ACI()
            new_aci.name = kw.get('name')
            new_aci.source_group = kw.get('source_group_dn')
            new_aci.dest_group = kw.get('dest_group_dn')
            new_aci.attrs = kw.get('attrs')
            if isinstance(new_aci.attrs, basestring):
                new_aci.attrs = [new_aci.attrs]

            # Look for an existing ACI of the same name
            aci_str_list = aci_entry.getValues('aci')
            if aci_str_list is None:
                aci_str_list = []
            if not(isinstance(aci_str_list,list) or isinstance(aci_str_list,tuple)):
                aci_str_list = [aci_str_list]

            for aci_str in aci_str_list:
                try:
                    old_aci = ipa.aci.ACI(aci_str)
                    if old_aci.name == new_aci.name:
                        turbogears.flash("Delgate add failed: a delegation of that name already exists")
                        return dict(form=delegate_form, delegate=kw,
                                tg_template='ipagui.templates.delegatenew')
                except SyntaxError:
                    # ignore aci_str's that ACI can't parse
                    pass


            # not pulling down existing aci attributes
            aci_entry = client.get_aci_entry(['dn'])
            aci_entry.setValue('aci', new_aci.export_to_string())

            client.update_entry(aci_entry)
        except ipaerror.IPAError, e:
            turbogears.flash("Delgate add failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=delegate_form, delegate=kw,
                    tg_template='ipagui.templates.delegatenew')

        turbogears.flash("delegate created")
        raise turbogears.redirect('/delegate/list')

    @expose("ipagui.templates.delegateedit")
    @identity.require(identity.in_group("admins"))
    def edit(self, acistr, tg_errors=None):
        """Display delegate page"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        client = self.get_ipaclient()

        try:
            aci_entry = client.get_aci_entry(aci_fields)
            aci = ipa.aci.ACI(acistr)
            group_dn_to_cn = ipa.aci.extract_group_cns([aci], client)

            delegate = aci.to_dict()
            delegate['source_group_dn'] = delegate['source_group']
            delegate['source_group_cn'] = group_dn_to_cn[delegate['source_group_dn']]
            delegate['dest_group_dn'] = delegate['dest_group']
            delegate['dest_group_cn'] = group_dn_to_cn[delegate['dest_group_dn']]

            return dict(form=delegate_form, delegate=delegate)
        except (SyntaxError, ipaerror.IPAError), e:
            turbogears.flash("Delegation edit failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect('/delegate/list')


    @expose()
    @identity.require(identity.in_group("admins"))
    def update(self, **kw):
        """Display delegate page"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit', '').startswith('Cancel'):
            turbogears.flash("Edit delegation cancelled")
            raise turbogears.redirect('/delegate/list')

        tg_errors, kw = self.delegatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
            return dict(form=delegate_form, delegate=kw,
                    tg_template='ipagui.templates.delegatenew')

        try:
            aci_entry = client.get_aci_entry(aci_fields)

            aci_str_list = aci_entry.getValues('aci')
            if aci_str_list is None:
                aci_str_list = []
            if not(isinstance(aci_str_list,list) or isinstance(aci_str_list,tuple)):
                aci_str_list = [aci_str_list]

            try :
                old_aci_index = aci_str_list.index(kw['orig_acistr'])
            except ValueError:
                turbogears.flash("Delegation update failed:<br />" +
                        "The delegation you were attempting to update has been " +
                        "concurrently modified.  Please cancel the edit " +
                        "and try editing the delegation again.")
                return dict(form=delegate_form, delegate=kw,
                            tg_template='ipagui.templates.delegateedit')

            new_aci = ipa.aci.ACI()
            new_aci.name = kw.get('name')
            new_aci.source_group = kw.get('source_group_dn')
            new_aci.dest_group = kw.get('dest_group_dn')
            new_aci.attrs = kw.get('attrs')
            if isinstance(new_aci.attrs, basestring):
                new_aci.attrs = [new_aci.attrs]
            new_aci_str = new_aci.export_to_string()

            new_aci_str_list = copy.copy(aci_str_list)
            new_aci_str_list[old_aci_index] = new_aci_str
            aci_entry.setValue('aci', new_aci_str_list)

            client.update_entry(aci_entry)

            turbogears.flash("delegate updated")
            raise turbogears.redirect('/delegate/list')
        except (SyntaxError, ipaerror.IPAError), e:
            turbogears.flash("Delegation update failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=delegate_form, delegate=kw,
                        tg_template='ipagui.templates.delegateedit')

    @expose("ipagui.templates.delegatelist")
    @identity.require(identity.not_anonymous())
    def list(self):
        """Display delegate page"""
        client = self.get_ipaclient()

        try:
            aci_entry = client.get_aci_entry(aci_fields)
        except ipaerror.IPAError, e:
            turbogears.flash("Delegation list failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect('/')

        aci_str_list = aci_entry.getValues('aci')
        if aci_str_list is None:
            aci_str_list = []
        if not(isinstance(aci_str_list,list) or isinstance(aci_str_list,tuple)):
            aci_str_list = [aci_str_list]

        aci_list = []
        for aci_str in aci_str_list:
            try:
                aci = ipa.aci.ACI(aci_str)
                aci_list.append(aci)
            except SyntaxError:
                # ignore aci_str's that ACI can't parse
                pass
        group_dn_to_cn = ipa.aci.extract_group_cns(aci_list, client)

        aci_list = sorted(aci_list, key=operator.itemgetter(0))
        # The list page needs to display field labels, not raw
        # LDAP attributes
        for aci in aci_list:
            aci.attrs = map(lambda name:
                      ipagui.forms.delegate.aci_name_to_label.get(name, name),
                      aci.attrs)

        return dict(aci_list=aci_list, group_dn_to_cn=group_dn_to_cn,
                    fields=ipagui.forms.delegate.DelegateFields())

    @expose()
    @identity.require(identity.in_group("admins"))
    def delete(self, acistr):
        """Display delegate page"""
        self.restrict_post()
        client = self.get_ipaclient()

        try:
            aci_entry = client.get_aci_entry(aci_fields)

            aci_str_list = aci_entry.getValues('aci')
            if aci_str_list is None:
                aci_str_list = []
            if not(isinstance(aci_str_list,list) or isinstance(aci_str_list,tuple)):
                aci_str_list = [aci_str_list]

            try :
                old_aci_index = aci_str_list.index(acistr)
            except ValueError:
                turbogears.flash("Delegation deletion failed:<br />" +
                        "The delegation you were attempting to delete has been " +
                        "concurrently modified.")
                raise turbogears.redirect('/delegate/list')

            new_aci_str_list = copy.copy(aci_str_list)
            del new_aci_str_list[old_aci_index]
            aci_entry.setValue('aci', new_aci_str_list)

            client.update_entry(aci_entry)

            turbogears.flash("delegate deleted")
            raise turbogears.redirect('/delegate/list')
        except (SyntaxError, ipaerror.IPAError), e:
            turbogears.flash("Delegation deletion failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect('/delegate/list')

    @expose("ipagui.templates.delegategroupsearch")
    @identity.require(identity.not_anonymous())
    def group_search(self, **kw):
        """Searches for groups and displays list of results in a table.
           This method is used for the ajax search on the delegation pages."""
        client = self.get_ipaclient()

        groups = []
        groups_counter = 0
        searchlimit = 100
        criteria = kw.get('criteria')
        if criteria != None and len(criteria) > 0:
            try:
                groups = client.find_groups(criteria.encode('utf-8'), None,
                        searchlimit)
                groups_counter = groups[0]
                groups = groups[1:]
            except ipaerror.IPAError, e:
                turbogears.flash("search failed: " + str(e))

        return dict(groups=groups, criteria=criteria,
                which_group=kw.get('which_group'),
                counter=groups_counter)

    @validate(form=delegate_form)
    @identity.require(identity.not_anonymous())
    def delegatevalidate(self, tg_errors=None, **kw):
        # We are faking this because otherwise it shows up as one huge
        # block of color in the UI when it has a not empty validator.
        if not kw.get('attrs'):
            if not tg_errors:
                tg_errors = {}
            tg_errors['attrs'] = _("Please select at least one value")
            cherrypy.request.validation_errors = tg_errors
        return tg_errors, kw
