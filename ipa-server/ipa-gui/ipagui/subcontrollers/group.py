from pickle import dumps, loads
from base64 import b64encode, b64decode
import logging

import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity

from ipacontroller import IPAController
import ipa.config
import ipa.group
from ipa.entity import utf8_encode_values
from ipa import ipaerror
import ipagui.forms.group

log = logging.getLogger(__name__)

group_new_form = ipagui.forms.group.GroupNewForm()
group_edit_form = ipagui.forms.group.GroupEditForm()

group_fields = ['*']

class GroupController(IPAController):


    #########
    # Group #
    #########

    @expose()
    @identity.require(identity.not_anonymous())
    def index(self, tg_errors=None):
        raise turbogears.redirect("/group/list")

    @expose("ipagui.templates.groupnew")
    @identity.require(identity.in_group("admins"))
    def new(self, tg_errors=None):
        """Displays the new group form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        client = self.get_ipaclient()

        return dict(form=group_new_form, group={})

    @expose()
    @identity.require(identity.in_group("admins"))
    def create(self, **kw):
        """Creates a new group"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add group cancelled")
            raise turbogears.redirect('/')

        tg_errors, kw = self.groupcreatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
            return dict(form=group_new_form, group=kw,
                    tg_template='ipagui.templates.groupnew')

        #
        # Create the group itself
        #
        try:
            new_group = ipa.group.Group()
            new_group.setValue('cn', kw.get('cn'))
            new_group.setValue('description', kw.get('description'))

            rv = client.add_group(new_group)
        except ipaerror.exception_for(ipaerror.LDAP_DUPLICATE):
            turbogears.flash("Group with name '%s' already exists" %
                    kw.get('cn'))
            return dict(form=group_new_form, group=kw,
                    tg_template='ipagui.templates.groupnew')
        except ipaerror.IPAError, e:
            turbogears.flash("Group add failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=group_new_form, group=kw,
                    tg_template='ipagui.templates.groupnew')

        #
        # NOTE: from here on, the group now exists.
        #       on any error, we redirect to the _edit_ group page.
        #       this code does data setup, similar to groupedit()
        #
        if isinstance(kw['cn'], list):
            cn0 = kw['cn'][0]
        else:
            cn0 = kw['cn']
        group = client.get_entry_by_cn(cn0, group_fields)
        group_dict = group.toDict()
        member_dicts = []

        # store a copy of the original group for the update later
        group_data = b64encode(dumps(group_dict))
        member_data = b64encode(dumps(member_dicts))
        group_dict['group_orig'] = group_data
        group_dict['member_data'] = member_data

        # preserve group add info in case of errors
        group_dict['dnadd'] = kw.get('dnadd')
        group_dict['dn_to_info_json'] = kw.get('dn_to_info_json')

        #
        # Add members
        #
        failed_adds = []
        try:
            dnadds = kw.get('dnadd')
            if dnadds != None:
                if not(isinstance(dnadds,list) or isinstance(dnadds,tuple)):
                    dnadds = [dnadds]
                failed_adds = client.add_members_to_group(
                        utf8_encode_values(dnadds), group.dn)
                kw['dnadd'] = failed_adds
        except ipaerror.IPAError, e:
            failed_adds = dnadds

        if len(failed_adds) > 0:
            message = "Group successfully created.<br />"
            message += "There was an error adding group members.<br />"
            message += "Failures have been preserved in the add/remove lists."
            turbogears.flash(message)
            return dict(form=group_edit_form, group=group_dict,
                        members=member_dicts,
                        tg_template='ipagui.templates.groupedit')

        turbogears.flash("%s added!" % kw.get('cn'))
        raise turbogears.redirect('/group/show', cn=kw.get('cn'))

    @expose("ipagui.templates.dynamiceditsearch")
    @identity.require(identity.not_anonymous())
    def edit_search(self, **kw):
        """Searches for users+groups and displays list of results in a table.
           This method is used for the ajax search on the group edit page."""
        client = self.get_ipaclient()

        users = []
        groups = []
        counter = 0
        searchlimit = 100
        criteria = kw.get('criteria')
        if criteria != None and len(criteria) > 0:
            try:
                users = client.find_users(criteria.encode('utf-8'), None, searchlimit)
                users_counter = users[0]
                users = users[1:]

                groups = client.find_groups(criteria.encode('utf-8'), None,
                        searchlimit)
                groups_counter = groups[0]
                groups = groups[1:]

                if users_counter < 0 or groups_counter < 0:
                    counter = -1
                else:
                    counter = users_counter + groups_counter
            except ipaerror.IPAError, e:
                turbogears.flash("search failed: " + str(e))

        return dict(users=users, groups=groups, criteria=criteria,
                counter=counter)


    @expose("ipagui.templates.groupedit")
    @identity.require(identity.in_group("admins"))
    def edit(self, cn, tg_errors=None):
        """Displays the edit group form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        client = self.get_ipaclient()

        try:
            group = client.get_entry_by_cn(cn, group_fields)

            group_dict = group.toDict()

            #
            # convert members to users, for easier manipulation on the page
            #

            members = client.group_members(group.dn, ['dn', 'givenname', 'sn', 'uid', 'cn'])
            members = members[1:]
            members.sort(self.sort_group_member)

            # Map users into an array of dicts, which can be serialized
            # (so we don't have to do this on each round trip)
            member_dicts = map(lambda member: member.toDict(), members)

            # store a copy of the original group for the update later
            group_data = b64encode(dumps(group_dict))
            member_data = b64encode(dumps(member_dicts))
            group_dict['group_orig'] = group_data
            group_dict['member_data'] = member_data

            return dict(form=group_edit_form, group=group_dict, members=member_dicts)
        except ipaerror.IPAError, e:
            turbogears.flash("Group edit failed: " + str(e))
            raise turbogears.redirect('/group/show', uid=cn)

    @expose()
    @identity.require(identity.in_group("admins"))
    def update(self, **kw):
        """Updates an existing group"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit') == 'Cancel Edit':
            orig_group_dict = loads(b64decode(kw.get('group_orig')))
            # if cancelling need to use the original group because the one
            # in kw may not exist yet.
            cn = orig_group_dict.get('cn')
            if (isinstance(cn,str)):
                cn = [cn]
            turbogears.flash("Edit group cancelled")
            raise turbogears.redirect('/group/show', cn=cn[0])

        # Decode the member data, in case we need to round trip
        member_dicts = loads(b64decode(kw.get('member_data')))

        tg_errors, kw = self.groupupdatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
            return dict(form=group_edit_form, group=kw, members=member_dicts,
                        tg_template='ipagui.templates.groupedit')

        group_modified = False

        #
        # Update group itself
        #
        try:
            orig_group_dict = loads(b64decode(kw.get('group_orig')))

            new_group = ipa.group.Group(orig_group_dict)
            if new_group.description != kw.get('description'):
                group_modified = True
                new_group.setValue('description', kw.get('description'))
            if kw.get('editprotected') == 'true':
                new_gid = str(kw.get('gidnumber'))
                if new_group.gidnumber != new_gid:
                    group_modified = True
                    new_group.setValue('gidnumber', new_gid)
            if new_group.cn != kw.get('cn'):
                group_modified = True
                new_group.setValue('cn', kw['cn'])

            if group_modified:
                rv = client.update_group(new_group)
                #
                # If the group update succeeds, but below operations fail, we
                # need to make sure a subsequent submit doesn't try to update
                # the group again.
                #
                kw['group_orig'] = b64encode(dumps(new_group.toDict()))
        except ipaerror.IPAError, e:
            turbogears.flash("Group update failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=group_edit_form, group=kw, members=member_dicts,
                        tg_template='ipagui.templates.groupedit')

        #
        # Add members
        #
        failed_adds = []
        try:
            dnadds = kw.get('dnadd')
            if dnadds != None:
                if not(isinstance(dnadds,list) or isinstance(dnadds,tuple)):
                    dnadds = [dnadds]
                failed_adds = client.add_members_to_group(
                        utf8_encode_values(dnadds), new_group.dn)
                kw['dnadd'] = failed_adds
                group_modified = True
        except ipaerror.IPAError, e:
            turbogears.flash("Group update failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=group_edit_form, group=kw, members=member_dicts,
                        tg_template='ipagui.templates.groupedit')

        #
        # Remove members
        #
        failed_dels = []
        try:
            dndels = kw.get('dndel')
            if dndels != None:
                if not(isinstance(dndels,list) or isinstance(dndels,tuple)):
                    dndels = [dndels]
                failed_dels = client.remove_members_from_group(
                        utf8_encode_values(dndels), new_group.dn)
                kw['dndel'] = failed_dels
                group_modified = True
        except ipaerror.IPAError, e:
            turbogears.flash("Group update failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            return dict(form=group_edit_form, group=kw, members=member_dicts,
                        tg_template='ipagui.templates.groupedit')

        #
        # TODO - check failed ops to see if it's because of another update.
        #        handle "someone else already did it" errors better - perhaps
        #        not even as an error
        # TODO - update the Group Members list.
        #        (note that we have to handle the above todo first, or else
        #         there will be an error message, but the add/del lists will
        #         be empty)
        #
        if (len(failed_adds) > 0) or (len(failed_dels) > 0):
            message = "There was an error updating group members.<br />"
            message += "Failures have been preserved in the add/remove lists."
            if group_modified:
                message = "Group Details successfully updated.<br />" + message
            turbogears.flash(message)
            return dict(form=group_edit_form, group=kw, members=member_dicts,
                        tg_template='ipagui.templates.groupedit')

        if isinstance(kw['cn'], list):
            cn0 = kw['cn'][0]
        else:
            cn0 = kw['cn']
        if group_modified == True:
            turbogears.flash("%s updated!" % cn0)
        else:
            turbogears.flash("No modifications requested.")
        raise turbogears.redirect('/group/show', cn=cn0)


    @expose("ipagui.templates.grouplist")
    @identity.require(identity.not_anonymous())
    def list(self, **kw):
        """Search for groups and display results"""
        client = self.get_ipaclient()

        groups = None
        # counter = 0
        criteria = kw.get('criteria')
        if criteria != None and len(criteria) > 0:
            try:
                groups = client.find_groups(criteria.encode('utf-8'), None, 0, 2)
                counter = groups[0]
                groups = groups[1:]
                if counter == -1:
                    turbogears.flash("These results are truncated.<br />" +
                                    "Please refine your search and try again.")
            except ipaerror.IPAError, e:
                turbogears.flash("Find groups failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
                raise turbogears.redirect("/group/list")

        return dict(groups=groups, criteria=criteria,
                    fields=ipagui.forms.group.GroupFields())

    @expose("ipagui.templates.groupshow")
    @identity.require(identity.not_anonymous())
    def show(self, cn):
        """Retrieve a single group for display"""
        client = self.get_ipaclient()

        try:
            group = client.get_entry_by_cn(cn, group_fields)
            group_dict = group.toDict()

            #
            # convert members to users, for display on the page
            #

            members = client.group_members(group.dn, ['dn', 'givenname', 'sn', 'uid', 'cn'])
            members = members[1:]
            members.sort(self.sort_group_member)
            member_dicts = map(lambda member: member.toDict(), members)

            return dict(group=group_dict, fields=ipagui.forms.group.GroupFields(),
                    members = member_dicts)
        except ipaerror.IPAError, e:
            turbogears.flash("Group show failed: " + str(e))
            raise turbogears.redirect("/")

    @expose()
    @identity.require(identity.not_anonymous())
    def delete(self, dn):
        """Delete group."""
        self.restrict_post()
        client = self.get_ipaclient()

        try:
            client.delete_group(dn)

            turbogears.flash("group deleted")
            raise turbogears.redirect('/group/list')
        except (SyntaxError, ipaerror.IPAError), e:
            turbogears.flash("Group deletion failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect('/group/list')

    @validate(form=group_new_form)
    @identity.require(identity.not_anonymous())
    def groupcreatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @validate(form=group_edit_form)
    @identity.require(identity.not_anonymous())
    def groupupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

