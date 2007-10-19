import re
import random
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
import ipa.user
from ipa.entity import utf8_encode_values
from ipa import ipaerror
import ipagui.forms.user
import ipa.config

log = logging.getLogger(__name__)

password_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

user_new_form = ipagui.forms.user.UserNewForm()
user_edit_form = ipagui.forms.user.UserEditForm()

user_fields = ['*', 'nsAccountLock']

email_domain = ipa.config.config.default_realm.lower()

class UserController(IPAController):

    @expose()
    def index(self):
        raise turbogears.redirect("/user/list")

    @expose("ipagui.templates.usernew")
    @identity.require(identity.not_anonymous())
    def new(self, tg_errors=None):
        """Displays the new user form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        return dict(form=user_new_form, user={})

    @expose()
    @identity.require(identity.not_anonymous())
    def create(self, **kw):
        """Creates a new user"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add user cancelled")
            raise turbogears.redirect('/user/list')

        tg_errors, kw = self.usercreatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
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
            new_user.setValue('manager', kw.get('manager'))
            new_user.setValue('roomnumber', kw.get('roomnumber'))
            new_user.setValue('secretary', kw.get('secretary'))

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
        raise turbogears.redirect('/user/show', uid=kw['uid'])

    @expose("ipagui.templates.dynamiceditsearch")
    @identity.require(identity.not_anonymous())
    def edit_search(self, **kw):
        """Searches for groups and displays list of results in a table.
           This method is used for the ajax search on the user edit page."""
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

        return dict(users=None, groups=groups, criteria=criteria,
                counter=groups_counter)


    @expose("ipagui.templates.useredit")
    @identity.require(identity.not_anonymous())
    def edit(self, uid, tg_errors=None):
        """Displays the edit user form"""
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        client = self.get_ipaclient()

        try:
            user = client.get_user_by_uid(uid, user_fields)
            user_dict = user.toDict()
            # Edit shouldn't fill in the password field.
            if user_dict.has_key('userpassword'):
                del(user_dict['userpassword'])

            user_groups = client.get_groups_by_member(user.dn, ['dn', 'cn'])
            user_groups.sort(self.sort_by_cn)
            user_groups_dicts = map(lambda group: group.toDict(), user_groups)
            user_groups_data = b64encode(dumps(user_groups_dicts))

            # store a copy of the original user for the update later
            user_data = b64encode(dumps(user_dict))
            user_dict['user_orig'] = user_data
            user_dict['user_groups_data'] = user_groups_data

            # grab manager and secretary names
            if user.manager:
                try:
                    user_manager = client.get_entry_by_dn(user.manager,
                        ['givenname', 'sn', 'uid'])
                    user_dict['manager_cn'] = "%s %s" % (
                            user_manager.getValue('givenname', ''),
                            user_manager.getValue('sn', ''))
                except (ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND),
                        ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR)):
                    pass
            if user.secretary:
                try:
                    user_secretary = client.get_entry_by_dn(user.secretary,
                        ['givenname', 'sn', 'uid'])
                    user_dict['secretary_cn'] = "%s %s" % (
                            user_secretary.getValue('givenname', ''),
                            user_secretary.getValue('sn', ''))
                except (ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND),
                        ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR)):
                    pass

            return dict(form=user_edit_form, user=user_dict,
                    user_groups=user_groups_dicts)
        except ipaerror.IPAError, e:
            turbogears.flash("User edit failed: " + str(e))
            raise turbogears.redirect('/user/show', uid=uid)

    @expose()
    @identity.require(identity.not_anonymous())
    def update(self, **kw):
        """Updates an existing user"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit') == 'Cancel Edit':
            turbogears.flash("Edit user cancelled")
            raise turbogears.redirect('/user/show', uid=kw.get('uid'))

        # Decode the group data, in case we need to round trip
        user_groups_dicts = loads(b64decode(kw.get('user_groups_data')))

        tg_errors, kw = self.userupdatevalidate(**kw)
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")
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
            new_user.setValue('manager', kw.get('manager'))
            new_user.setValue('roomnumber', kw.get('roomnumber'))
            new_user.setValue('secretary', kw.get('secretary'))

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
        raise turbogears.redirect('/user/show', uid=kw['uid'])


    @expose("ipagui.templates.userlist")
    @identity.require(identity.not_anonymous())
    def list(self, **kw):
        """Searches for users and displays list of results"""
        client = self.get_ipaclient()

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
                raise turbogears.redirect("/user/list")

        return dict(users=users, uid=uid, fields=ipagui.forms.user.UserFields())


    @expose("ipagui.templates.usershow")
    @identity.require(identity.not_anonymous())
    def show(self, uid):
        """Retrieve a single user for display"""
        client = self.get_ipaclient()

        try:
            user = client.get_user_by_uid(uid, user_fields)
            user_groups = client.get_groups_by_member(user.dn, ['cn'])
            user_groups.sort(self.sort_by_cn)
            user_reports = client.get_users_by_manager(user.dn,
                    ['givenname', 'sn', 'uid'])
            user_reports.sort(self.sort_group_member)

            user_manager = None
            user_secretary = None
            try:
                if user.manager:
                    user_manager = client.get_entry_by_dn(user.manager,
                        ['givenname', 'sn', 'uid'])
            except (ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND),
                    ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR)):
                pass

            try:
                if user.secretary:
                    user_secretary = client.get_entry_by_dn(user.secretary,
                        ['givenname', 'sn', 'uid'])
            except (ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND),
                    ipaerror.exception_for(ipaerror.LDAP_DATABASE_ERROR)):
                pass

            return dict(user=user.toDict(), fields=ipagui.forms.user.UserFields(),
                        user_groups=user_groups, user_reports=user_reports,
                        user_manager=user_manager, user_secretary=user_secretary)
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

        client = self.get_ipaclient()

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

        client = self.get_ipaclient()

        givenname = givenname.lower()
        sn = sn.lower()

        email = "%s.%s@%s" % (givenname, sn, email_domain)
        try:
            client.get_user_by_email(email)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return email

        email = "%s@%s" % (self.suggest_uid(givenname, sn), email_domain)
        try:
            client.get_user_by_email(email)
        except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
            return email

        return ""

    @expose("ipagui.templates.userselectsearch")
    @identity.require(identity.not_anonymous())
    def user_select_search(self, **kw):
        """Searches for users and displays list of results in a table.
           This method is used for the ajax search for managers
           and secrectary on the user pages."""
        client = self.get_ipaclient()

        users = []
        users_counter = 0
        searchlimit = 100
        criteria = kw.get('criteria')
        if criteria != None and len(criteria) > 0:
            try:
                users = client.find_users(criteria.encode('utf-8'), None,
                        searchlimit)
                users_counter = users[0]
                users = users[1:]
            except ipaerror.IPAError, e:
                turbogears.flash("search failed: " + str(e))

        return dict(users=users, criteria=criteria,
                which_select=kw.get('which_select'),
                counter=users_counter)
