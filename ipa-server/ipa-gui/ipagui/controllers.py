import random
from pickle import dumps, loads
from base64 import b64encode, b64decode
import re

import os
import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
from turbogears import identity
# from model import *
# import logging
# log = logging.getLogger("ipagui.controllers")

import ipa.config
import ipa.ipaclient
import ipa.user
from ipa.entity import utf8_encode_values
import xmlrpclib
import forms.user
import forms.group
from helpers import userhelper
from ipa import ipaerror

ipa.config.init_config()
user_new_form = forms.user.UserNewForm()
user_edit_form = forms.user.UserEditForm()
group_new_form = forms.group.GroupNewForm()
group_edit_form = forms.group.GroupEditForm()

password_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

client = ipa.ipaclient.IPAClient(True)

user_fields = ['*', 'nsAccountLock']

group_fields = ['*']

def restrict_post():
    if cherrypy.request.method != "POST":
        turbogears.flash("This method only accepts posts")
        raise turbogears.redirect("/")

def utf8_encode(value):
    if value != None:
        value = value.encode('utf-8')
    return value

def sort_group_member(a, b):
    """Comparator function used for sorting group members."""
    if a.getValue('uid') and b.getValue('uid'):
        if a.getValue('givenname') == b.getValue('givenname'):
            if a.getValue('sn') == b.getValue('sn'):
                if a.getValue('uid') == b.getValue('uid'):
                    return 0
                elif a.getValue('uid') < b.getValue('uid'):
                    return -1
                else:
                    return 1
            elif a.getValue('sn') < b.getValue('sn'):
                return -1
            else:
                return 1
        elif a.getValue('givenname') < b.getValue('givenname'):
            return -1
        else:
            return 1
    elif a.getValue('uid'):
        return -1
    elif b.getValue('uid'):
        return 1
    else:
        if a.getValue('cn') == b.getValue('cn'):
            return 0
        elif a.getValue('cn') < b.getValue('cn'):
            return -1
        else:
            return 1

def sort_by_cn(a, b):
    """Comparator function used for sorting groups."""
    if a.getValue('cn') == b.getValue('cn'):
        return 0
    elif a.getValue('cn') < b.getValue('cn'):
        return -1
    else:
        return 1

class Root(controllers.RootController):

    @expose(template="ipagui.templates.welcome")
    @identity.require(identity.not_anonymous())
    def index(self):
        return dict()

    @expose()
    @identity.require(identity.not_anonymous())
    def topsearch(self, **kw):
        if kw.get('searchtype') == "Users":
            return self.userlist(uid=kw.get('searchvalue'))
        else:
            return self.grouplist(criteria=kw.get('searchvalue'))



    ########
    # User #
    ########

    @expose("ipagui.templates.usernew")
    @identity.require(identity.not_anonymous())
    def usernew(self, tg_errors=None):
        """Displays the new user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        return dict(form=user_new_form, user={})

    @expose()
    @identity.require(identity.not_anonymous())
    def usercreate(self, **kw):
        """Creates a new user"""
        restrict_post()
        client.set_krbccache(os.environ["KRB5CCNAME"])
        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add user cancelled")
            raise turbogears.redirect('/userlist')

        tg_errors, kw = self.usercreatevalidate(**kw)
        if tg_errors:
            return dict(form=user_new_form, user=kw,
                    tg_template='ipagui.templates.usernew')

        #
        # Create the user itself
        #
        try:
            new_user = ipa.user.User()
            new_user.setValue('title', kw.get('title'))
            new_user.setValue('givenname', kw.get('givenname'))
            new_user.setValue('sn', kw.get('sn'))
            new_user.setValue('cn', kw.get('cn'))
            new_user.setValue('displayname', kw.get('displayname'))
            new_user.setValue('initials', kw.get('initials'))

            new_user.setValue('uid', kw.get('uid'))
            new_user.setValue('loginshell', kw.get('loginshell'))
            new_user.setValue('gecos', kw.get('gecos'))

            new_user.setValue('mail', kw.get('mail'))
            new_user.setValue('telephonenumber', kw.get('telephonenumber'))
            new_user.setValue('facsimiletelephonenumber',
                    kw.get('facsimiletelephonenumber'))
            new_user.setValue('mobile', kw.get('mobile'))
            new_user.setValue('pager', kw.get('pager'))
            new_user.setValue('homephone', kw.get('homephone'))

            new_user.setValue('street', kw.get('street'))
            new_user.setValue('l', kw.get('l'))
            new_user.setValue('st', kw.get('st'))
            new_user.setValue('postalcode', kw.get('postalcode'))

            new_user.setValue('ou', kw.get('ou'))
            new_user.setValue('businesscategory', kw.get('businesscategory'))
            new_user.setValue('description', kw.get('description'))
            new_user.setValue('employeetype', kw.get('employeetype'))
            # new_user.setValue('manager', kw.get('manager'))
            new_user.setValue('roomnumber', kw.get('roomnumber'))
            # new_user.setValue('secretary', kw.get('secretary'))

            new_user.setValue('carlicense', kw.get('carlicense'))
            new_user.setValue('labeleduri', kw.get('labeleduri'))

            if kw.get('nsAccountLock'):
                new_user.setValue('nsAccountLock', 'true')

            rv = client.add_user(new_user)
        except ipaerror.exception_for(ipaerror.LDAP_DUPLICATE):
            turbogears.flash("Person with login '%s' already exists" %
                    kw.get('uid'))
            return dict(form=user_new_form, user=kw,
                    tg_template='ipagui.templates.usernew')
        except ipaerror.IPAError, e:
            turbogears.flash("User add failed: " + str(e))
            return dict(form=user_new_form, user=kw,
                    tg_template='ipagui.templates.usernew')

        #
        # NOTE: from here on, the user account now exists.
        #       on any error, we redirect to the _edit_ user page.
        #       this code does data setup, similar to useredit()
        #
        user = client.get_user_by_uid(kw['uid'], user_fields)
        user_dict = user.toDict()

        user_groups_dicts = []
        user_groups_data = b64encode(dumps(user_groups_dicts))

        # store a copy of the original user for the update later
        user_data = b64encode(dumps(user_dict))
        user_dict['user_orig'] = user_data
        user_dict['user_groups_data'] = user_groups_data

        # preserve group add info in case of errors
        user_dict['dnadd'] = kw.get('dnadd')
        user_dict['dn_to_info_json'] = kw.get('dn_to_info_json')

        #
        # Password change
        # TODO
        #

        #
        # Add groups
        #
        failed_adds = []
        try:
            dnadds = kw.get('dnadd')
            if dnadds != None:
                if not(isinstance(dnadds,list) or isinstance(dnadds,tuple)):
                    dnadds = [dnadds]
                failed_adds = client.add_groups_to_user(
                        utf8_encode_values(dnadds), user.dn)
                kw['dnadd'] = failed_adds
        except ipaerror.IPAError, e:
            failed_adds = dnadds

        if len(failed_adds) > 0:
            message = "Person successfully created.<br />"
            message += "There was an error adding groups.<br />"
            message += "Failures have been preserved in the add/remove lists."
            turbogears.flash(message)
            return dict(form=user_edit_form, user=user_dict,
                        user_groups=user_groups_dicts,
                        tg_template='ipagui.templates.useredit')

        turbogears.flash("%s added!" % kw['uid'])
        raise turbogears.redirect('/usershow', uid=kw['uid'])

    @expose("ipagui.templates.dynamiceditsearch")
    @identity.require(identity.not_anonymous())
    def useredit_search(self, **kw):
        """Searches for groups and displays list of results in a table.
           This method is used for the ajax search on the user edit page."""
        client.set_krbccache(os.environ["KRB5CCNAME"])
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

        return dict(users=None, groups=groups, criteria=criteria,
                counter=groups_counter)


    @expose("ipagui.templates.useredit")
    @identity.require(identity.not_anonymous())
    def useredit(self, uid, tg_errors=None):
        """Displays the edit user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        client.set_krbccache(os.environ["KRB5CCNAME"])
        try:
            user = client.get_user_by_uid(uid, user_fields)
            user_dict = user.toDict()
            # Edit shouldn't fill in the password field.
            if user_dict.has_key('userpassword'):
                del(user_dict['userpassword'])

            user_groups = client.get_groups_by_member(user.dn, ['dn', 'cn'])
            user_groups.sort(sort_by_cn)
            user_groups_dicts = map(lambda group: group.toDict(), user_groups)
            user_groups_data = b64encode(dumps(user_groups_dicts))

            # store a copy of the original user for the update later
            user_data = b64encode(dumps(user_dict))
            user_dict['user_orig'] = user_data
            user_dict['user_groups_data'] = user_groups_data

            return dict(form=user_edit_form, user=user_dict,
                    user_groups=user_groups_dicts)
        except ipaerror.IPAError, e:
            turbogears.flash("User edit failed: " + str(e))
            raise turbogears.redirect('/usershow', uid=kw.get('uid'))

    @expose()
    @identity.require(identity.not_anonymous())
    def userupdate(self, **kw):
        """Updates an existing user"""
        restrict_post()
        client.set_krbccache(os.environ["KRB5CCNAME"])
        if kw.get('submit') == 'Cancel Edit':
            turbogears.flash("Edit user cancelled")
            raise turbogears.redirect('/usershow', uid=kw.get('uid'))

        # Decode the group data, in case we need to round trip
        user_groups_dicts = loads(b64decode(kw.get('user_groups_data')))

        tg_errors, kw = self.userupdatevalidate(**kw)
        if tg_errors:
            return dict(form=user_edit_form, user=kw,
                        user_groups=user_groups_dicts,
                        tg_template='ipagui.templates.useredit')

        password_change = False
        user_modified = False

        #
        # Update the user itself
        #
        try:
            orig_user_dict = loads(b64decode(kw.get('user_orig')))

            new_user = ipa.user.User(orig_user_dict)
            new_user.setValue('title', kw.get('title'))
            new_user.setValue('givenname', kw.get('givenname'))
            new_user.setValue('sn', kw.get('sn'))
            new_user.setValue('cn', kw.get('cn'))
            new_user.setValue('displayname', kw.get('displayname'))
            new_user.setValue('initials', kw.get('initials'))

            new_user.setValue('loginshell', kw.get('loginshell'))
            new_user.setValue('gecos', kw.get('gecos'))

            new_user.setValue('mail', kw.get('mail'))
            new_user.setValue('telephonenumber', kw.get('telephonenumber'))
            new_user.setValue('facsimiletelephonenumber',
                    kw.get('facsimiletelephonenumber'))
            new_user.setValue('mobile', kw.get('mobile'))
            new_user.setValue('pager', kw.get('pager'))
            new_user.setValue('homephone', kw.get('homephone'))

            new_user.setValue('street', kw.get('street'))
            new_user.setValue('l', kw.get('l'))
            new_user.setValue('st', kw.get('st'))
            new_user.setValue('postalcode', kw.get('postalcode'))

            new_user.setValue('ou', kw.get('ou'))
            new_user.setValue('businesscategory', kw.get('businesscategory'))
            new_user.setValue('description', kw.get('description'))
            new_user.setValue('employeetype', kw.get('employeetype'))
            # new_user.setValue('manager', kw.get('manager'))
            new_user.setValue('roomnumber', kw.get('roomnumber'))
            # new_user.setValue('secretary', kw.get('secretary'))

            new_user.setValue('carlicense', kw.get('carlicense'))
            new_user.setValue('labeleduri', kw.get('labeleduri'))


            if kw.get('nsAccountLock'):
                new_user.setValue('nsAccountLock', 'true')
            else:
                new_user.setValue('nsAccountLock', None)
            if kw.get('editprotected') == 'true':
                if kw.get('userpassword'):
                    password_change = True
                new_user.setValue('uidnumber', str(kw.get('uidnumber')))
                new_user.setValue('gidnumber', str(kw.get('gidnumber')))
                new_user.setValue('homedirectory', str(kw.get('homedirectory')))

            rv = client.update_user(new_user)
            #
            # If the user update succeeds, but below operations fail, we
            # need to make sure a subsequent submit doesn't try to update
            # the user again.
            #
            user_modified = True
            kw['user_orig'] = b64encode(dumps(new_user.toDict()))
        except ipaerror.exception_for(ipaerror.LDAP_EMPTY_MODLIST), e:
            # could be a password change
            # could be groups change
            # too much work to figure out unless someone really screams
            pass
        except ipaerror.IPAError, e:
            turbogears.flash("User update failed: " + str(e))
            return dict(form=user_edit_form, user=kw,
                        user_groups=user_groups_dicts,
                        tg_template='ipagui.templates.useredit')

        #
        # Password change
        #
        try:
            if password_change:
                rv = client.modifyPassword(kw['krbprincipalname'], "", kw.get('userpassword'))
        except ipaerror.IPAError, e:
            turbogears.flash("User password change failed: " + str(e))
            return dict(form=user_edit_form, user=kw,
                        user_groups=user_groups_dicts,
                        tg_template='ipagui.templates.useredit')

        #
        # Add groups
        #
        failed_adds = []
        try:
            dnadds = kw.get('dnadd')
            if dnadds != None:
                if not(isinstance(dnadds,list) or isinstance(dnadds,tuple)):
                    dnadds = [dnadds]
                failed_adds = client.add_groups_to_user(
                        utf8_encode_values(dnadds), new_user.dn)
                kw['dnadd'] = failed_adds
        except ipaerror.IPAError, e:
            failed_adds = dnadds

        #
        # Remove groups
        #
        failed_dels = []
        try:
            dndels = kw.get('dndel')
            if dndels != None:
                if not(isinstance(dndels,list) or isinstance(dndels,tuple)):
                    dndels = [dndels]
                failed_dels = client.remove_groups_from_user(
                        utf8_encode_values(dndels), new_user.dn)
                kw['dndel'] = failed_dels
        except ipaerror.IPAError, e:
            failed_dels = dndels

        if (len(failed_adds) > 0) or (len(failed_dels) > 0):
            message = "There was an error updating groups.<br />"
            message += "Failures have been preserved in the add/remove lists."
            if user_modified:
                message = "User Details successfully updated.<br />" + message
            if password_change:
                message = "User password successfully updated.<br />" + message
            turbogears.flash(message)
            return dict(form=user_edit_form, user=kw,
                        user_groups=user_groups_dicts,
                        tg_template='ipagui.templates.useredit')

        turbogears.flash("%s updated!" % kw['uid'])
        raise turbogears.redirect('/usershow', uid=kw['uid'])


    @expose("ipagui.templates.userlist")
    @identity.require(identity.not_anonymous())
    def userlist(self, **kw):
        """Searches for users and displays list of results"""
        client.set_krbccache(os.environ["KRB5CCNAME"])
        users = None
        counter = 0
        uid = kw.get('uid')
        if uid != None and len(uid) > 0:
            try:
                users = client.find_users(uid.encode('utf-8'), None, 0, 2)
                counter = users[0]
                users = users[1:]
                if counter == -1:
                    turbogears.flash("These results are truncated.<br />" +
                                    "Please refine your search and try again.")
            except ipaerror.IPAError, e:
                turbogears.flash("User list failed: " + str(e))
                raise turbogears.redirect("/userlist")

        return dict(users=users, uid=uid, fields=forms.user.UserFields())


    @expose("ipagui.templates.usershow")
    @identity.require(identity.not_anonymous())
    def usershow(self, uid):
        """Retrieve a single user for display"""
        client.set_krbccache(os.environ["KRB5CCNAME"])
        try:
            user = client.get_user_by_uid(uid, user_fields)
            user_groups = client.get_groups_by_member(user.dn, ['cn'])
            user_groups.sort(sort_by_cn)
            user_reports = client.get_users_by_manager(user.dn,
                    ['givenname', 'sn', 'uid'])
            user_reports.sort(sort_group_member)

            user_manager = None
            try:
                if user.manager:
                    user_manager = client.get_user_by_dn(user.manager,
                        ['givenname', 'sn', 'uid'])
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                pass

            return dict(user=user.toDict(), fields=forms.user.UserFields(),
                        user_groups=user_groups, user_reports=user_reports,
                        user_manager=user_manager)
        except ipaerror.IPAError, e:
            turbogears.flash("User show failed: " + str(e))
            raise turbogears.redirect("/")

    @validate(form=user_new_form)
    @identity.require(identity.not_anonymous())
    def usercreatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @validate(form=user_edit_form)
    @identity.require(identity.not_anonymous())
    def userupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @expose()
    def userindex(self):
        raise turbogears.redirect("/userlist")

    # @expose()
    def generate_password(self):
        password = ""
        generator = random.SystemRandom()
        for char in range(8):
            index = generator.randint(0, len(password_chars) - 1)
            password += password_chars[index]

        return password

    @expose()
    @identity.require(identity.not_anonymous())
    def suggest_uid(self, givenname, sn):
        # filter illegal uid characters out
        givenname = re.sub(r'[^a-zA-Z_\-0-9]', "", givenname)
        sn = re.sub(r'[^a-zA-Z_\-0-9]', "", sn)

        if (len(givenname) == 0) or (len(sn) == 0):
            return ""

        client.set_krbccache(os.environ["KRB5CCNAME"])
        givenname = givenname.lower()
        sn = sn.lower()

        uid = givenname[0] + sn[:7]
        try:
            client.get_user_by_uid(uid)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return uid

        uid = givenname[:7] + sn[0]
        try:
            client.get_user_by_uid(uid)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return uid

        uid = (givenname + sn)[:8]
        try:
            client.get_user_by_uid(uid)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return uid

        uid = sn[:8]
        try:
            client.get_user_by_uid(uid)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return uid

        suffix = 2
        template = givenname[0] + sn[:7]
        while suffix < 20:
            uid = template[:8 - len(str(suffix))] + str(suffix)
            try:
                client.get_user_by_uid(uid)
            except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
                return uid
            suffix += 1

        return ""

    @expose()
    @identity.require(identity.not_anonymous())
    def suggest_email(self, givenname, sn):
        # remove illegal email characters
        givenname = re.sub(r'[^a-zA-Z0-9!#\$%\*/?\|\^\{\}`~&\'\+\-=_]', "", givenname)
        sn = re.sub(r'[^a-zA-Z0-9!#\$%\*/?\|\^\{\}`~&\'\+\-=_]', "", sn)

        if (len(givenname) == 0) or (len(sn) == 0):
            return ""

        client.set_krbccache(os.environ["KRB5CCNAME"])
        givenname = givenname.lower()
        sn = sn.lower()

        # TODO - get from config
        domain = "freeipa.org"

        return "%s.%s@%s" % (givenname, sn, domain)


        # TODO - mail is currently not indexed nor searchable.
        #        implement when it's done
        # email = givenname + "." + sn + domain
        # users = client.find_users(email, ['mail'])
        # if len(filter(lambda u: u['mail'] == email, users[1:])) == 0:
        #     return email

        # email = self.suggest_uid(givenname, sn) + domain
        # users = client.find_users(email, ['mail'])
        # if len(filter(lambda u: u['mail'] == email, users[1:])) == 0:
        #     return email

        # suffix = 2
        # template = givenname + "." + sn
        # while suffix < 20:
        #     email = template + str(suffix) + domain
        #     users = client.find_users(email, ['mail'])
        #     if len(filter(lambda u: u['mail'] == email, users[1:])) == 0:
        #         return email
        #     suffix += 1

        # return ""



    #########
    # Group #
    #########

    @expose("ipagui.templates.groupindex")
    @identity.require(identity.not_anonymous())
    def groupindex(self, tg_errors=None):
        client.set_krbccache(os.environ["KRB5CCNAME"])
        return dict()

    @expose("ipagui.templates.groupnew")
    @identity.require(identity.not_anonymous())
    def groupnew(self, tg_errors=None):
        """Displays the new group form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        client.set_krbccache(os.environ["KRB5CCNAME"])

        return dict(form=group_new_form, group={})

    @expose()
    @identity.require(identity.not_anonymous())
    def groupcreate(self, **kw):
        """Creates a new group"""
        restrict_post()
        client.set_krbccache(os.environ["KRB5CCNAME"])

        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add group cancelled")
            raise turbogears.redirect('/')

        tg_errors, kw = self.groupcreatevalidate(**kw)
        if tg_errors:
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
            turbogears.flash("Group add failed: " + str(e) + "<br/>" + str(e.detail))
            return dict(form=group_new_form, group=kw,
                    tg_template='ipagui.templates.groupnew')

        #
        # NOTE: from here on, the group now exists.
        #       on any error, we redirect to the _edit_ group page.
        #       this code does data setup, similar to groupedit()
        #
        group = client.get_group_by_cn(kw['cn'], group_fields)
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
        raise turbogears.redirect('/groupshow', cn=kw.get('cn'))

    @expose("ipagui.templates.dynamiceditsearch")
    @identity.require(identity.not_anonymous())
    def groupedit_search(self, **kw):
        """Searches for users+groups and displays list of results in a table.
           This method is used for the ajax search on the group edit page."""
        client.set_krbccache(os.environ["KRB5CCNAME"])
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
    @identity.require(identity.not_anonymous())
    def groupedit(self, cn, tg_errors=None):
        """Displays the edit group form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        client.set_krbccache(os.environ["KRB5CCNAME"])
        try:
            group = client.get_group_by_cn(cn, group_fields)

            group_dict = group.toDict()

            #
            # convert members to users, for easier manipulation on the page
            #
            member_dns = []
            if group_dict.has_key('uniquemember'):
                member_dns = group_dict.get('uniquemember')
                # remove from dict - it's not needed for update
                # and we are storing the members in a different form
                del group_dict['uniquemember']
            if not(isinstance(member_dns,list) or isinstance(member_dns,tuple)):
                member_dns = [member_dns]

            # TODO: convert this into an efficient (single) function call
            # Note: this isn't quite right, since it can be users and groups.
            members = map(
                    lambda dn: client.get_user_by_dn(dn, ['dn', 'givenname', 'sn',
                        'uid', 'cn']),
                    member_dns)
            members.sort(sort_group_member)

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
            raise turbogears.redirect('/groupshow', uid=cn)

    @expose()
    @identity.require(identity.not_anonymous())
    def groupupdate(self, **kw):
        """Updates an existing group"""
        restrict_post()
        client.set_krbccache(os.environ["KRB5CCNAME"])
        if kw.get('submit') == 'Cancel Edit':
            turbogears.flash("Edit group cancelled")
            raise turbogears.redirect('/groupshow', cn=kw.get('cn'))

        # Decode the member data, in case we need to round trip
        member_dicts = loads(b64decode(kw.get('member_data')))


        tg_errors, kw = self.groupupdatevalidate(**kw)
        if tg_errors:
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

            if group_modified:
                rv = client.update_group(new_group)
                #
                # If the group update succeeds, but below operations fail, we
                # need to make sure a subsequent submit doesn't try to update
                # the group again.
                #
                kw['group_orig'] = b64encode(dumps(new_group.toDict()))
        except ipaerror.IPAError, e:
            turbogears.flash("Group update failed: " + str(e))
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
        except ipaerror.IPAError, e:
            turbogears.flash("Group update failed: " + str(e))
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
        except ipaerror.IPAError, e:
            turbogears.flash("Group update failed: " + str(e))
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

        turbogears.flash("%s updated!" % kw['cn'])
        raise turbogears.redirect('/groupshow', cn=kw['cn'])


    @expose("ipagui.templates.grouplist")
    @identity.require(identity.not_anonymous())
    def grouplist(self, **kw):
        """Search for groups and display results"""
        client.set_krbccache(os.environ["KRB5CCNAME"])
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
                turbogears.flash("Find groups failed: " + str(e))
                raise turbogears.redirect("/grouplist")

        return dict(groups=groups, criteria=criteria, fields=forms.group.GroupFields())

    @expose("ipagui.templates.groupshow")
    @identity.require(identity.not_anonymous())
    def groupshow(self, cn):
        """Retrieve a single group for display"""
        client.set_krbccache(os.environ["KRB5CCNAME"])
        try:
            group = client.get_group_by_cn(cn, group_fields)
            group_dict = group.toDict()

            #
            # convert members to users, for display on the page
            #
            member_dns = []
            if group_dict.has_key('uniquemember'):
                member_dns = group_dict.get('uniquemember')
            if not(isinstance(member_dns,list) or isinstance(member_dns,tuple)):
                member_dns = [member_dns]

            # TODO: convert this into an efficient (single) function call
            # Note: this isn't quite right, since it can be users and groups.
            members = map(
                    lambda dn: client.get_user_by_dn(dn, ['dn', 'givenname', 'sn',
                        'uid', 'cn']),
                    member_dns)
            members.sort(sort_group_member)
            member_dicts = map(lambda member: member.toDict(), members)

            return dict(group=group_dict, fields=forms.group.GroupFields(),
                    members = member_dicts)
        except ipaerror.IPAError, e:
            turbogears.flash("Group show failed: " + str(e))
            raise turbogears.redirect("/")

    @validate(form=group_new_form)
    @identity.require(identity.not_anonymous())
    def groupcreatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @validate(form=group_edit_form)
    @identity.require(identity.not_anonymous())
    def groupupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @expose("ipagui.templates.loginfailed")
    def loginfailed(self, **kw):
        return dict()
