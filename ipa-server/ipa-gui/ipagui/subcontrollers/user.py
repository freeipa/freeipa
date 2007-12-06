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
from ipagui.helpers import ipahelper

log = logging.getLogger(__name__)

password_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

user_new_form = ipagui.forms.user.UserNewForm()
user_edit_form = ipagui.forms.user.UserEditForm()

user_fields = ['*', 'nsAccountLock']

email_domain = ipa.config.config.default_realm.lower()

class UserController(IPAController):

    def __init__(self, *args, **kw):
        super(UserController,self).__init__(*args, **kw)
#        self.load_custom_fields()

    def load_custom_fields(self):

        client = self.get_ipaclient()
        schema = client.get_custom_fields()

        # FIXME: Don't load from LDAP every single time it is called

        # FIXME: Is removing the attributes on the fly thread-safe? Do we
        # need to lock here?
        for s in schema:
            required=False
            if (s['required'].lower() == "true"):
                required=True
            field = widgets.TextField(name=s['field'],label=s['label'])
            validator = validators.String(not_empty=required)

            # Don't allow dupes on the new form
            try:
                for i in range(len(user_new_form.custom_fields)):
                    if user_new_form.custom_fields[i].name == s['field']:
                        user_new_form.custom_fields.pop(i)
            except:
                pass

            # Don't allow dupes on the edit form
            try:
                for i in range(len(user_edit_form.custom_fields)):
                    if user_edit_form.custom_fields[i].name == s['field']:
                        user_edit_form.custom_fields.pop(i)
            except:
                pass

            # Don't allow dupes in the list of user fields
            try:
                for i in range(len(ipagui.forms.user.UserFields.custom_fields)):
                    if ipagui.forms.user.UserFields.custom_fields[i].name == s['field']:
                        ipagui.forms.user.UserFields.custom_fields.pop(i)
            except:
                pass

            ipagui.forms.user.UserFields.custom_fields.append(field)
            user_new_form.custom_fields.append(field)
            user_edit_form.custom_fields.append(field)

            user_new_form.validator.add_field(s['field'], validator)
            user_edit_form.validator.add_field(s['field'], validator)

    @expose()
    def index(self):
        raise turbogears.redirect("/user/list")

    @expose("ipagui.templates.usernew")
    @identity.require(identity.in_any_group("admins","editors"))
    def new(self, tg_errors=None):
        """Displays the new user form"""
        self.load_custom_fields()
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        return dict(form=user_new_form, user={})

    @expose()
    @identity.require(identity.in_any_group("admins","editors"))
    def create(self, **kw):
        """Creates a new user"""
        self.restrict_post()
        client = self.get_ipaclient()

        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add user cancelled")
            raise turbogears.redirect('/user/list')

        tg_errors, kw = self.usercreatevalidate(**kw)

        # Fix incoming multi-valued fields we created for the form
        kw = ipahelper.fix_incoming_fields(kw, 'cn', 'cns')
        kw = ipahelper.fix_incoming_fields(kw, 'telephonenumber', 'telephonenumbers')
        kw = ipahelper.fix_incoming_fields(kw, 'facsimiletelephonenumber', 'facsimiletelephonenumbers')
        kw = ipahelper.fix_incoming_fields(kw, 'mobile', 'mobiles')
        kw = ipahelper.fix_incoming_fields(kw, 'pager', 'pagers')
        kw = ipahelper.fix_incoming_fields(kw, 'homephone', 'homephones')

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
            if kw.get('manager'):
                new_user.setValue('manager', kw.get('manager'))
            new_user.setValue('roomnumber', kw.get('roomnumber'))
            if kw.get('secretary'):
                new_user.setValue('secretary', kw.get('secretary'))

            new_user.setValue('carlicense', kw.get('carlicense'))
            new_user.setValue('labeleduri', kw.get('labeleduri'))

            for custom_field in user_new_form.custom_fields:
                new_user.setValue(custom_field.name,
                                  kw.get(custom_field.name, ''))

            rv = client.add_user(new_user)

            if kw.get('nsAccountLock'):
                client.mark_user_inactive(kw.get('uid'))
        except ipaerror.exception_for(ipaerror.LDAP_DUPLICATE):
            turbogears.flash("User with login '%s' already exists" %
                    kw.get('uid'))
            return dict(form=user_new_form, user=kw,
                    tg_template='ipagui.templates.usernew')
        except ipaerror.IPAError, e:
            turbogears.flash("User add failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
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
        # Set the Password
        #
        if kw.get('userpassword'):
            try:
                client.modifyPassword(user_dict['krbprincipalname'], "", kw.get('userpassword'))
            except ipaerror.IPAError, e:
                message = "User successfully created.<br />"
                message += "There was an error setting the password.<br />"
                turbogears.flash(message)
                return dict(form=user_edit_form, user=user_dict,
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
                        utf8_encode_values(dnadds), user.dn)
                kw['dnadd'] = failed_adds
        except ipaerror.IPAError, e:
            failed_adds = dnadds

        if len(failed_adds) > 0:
            message = "User successfully created.<br />"
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
    def edit(self, uid=None, principal=None, tg_errors=None):
        """Displays the edit user form"""
        self.load_custom_fields()
        if tg_errors:
            turbogears.flash("There were validation errors.<br/>" +
                             "Please see the messages below for details.")

        client = self.get_ipaclient()

        try:
            if uid is not None:
                user = client.get_user_by_uid(uid, user_fields)
            elif principal is not None:
                principal = principal + "@" + ipa.config.config.default_realm
                user = client.get_user_by_principal(principal, user_fields)
            else:
                turbogears.flash("User edit failed: No uid or principal provided")
                raise turbogears.redirect('/')
            user_dict = user.toDict()

            # Load potential multi-valued fields
            if isinstance(user_dict['cn'], str):
                user_dict['cn'] = [user_dict['cn']]
            user_dict['cns'] = ipahelper.setup_mv_fields(user_dict['cn'], 'cn')

            if isinstance(user_dict.get('telephonenumber',''), str):
                user_dict['telephonenumber'] = [user_dict.get('telephonenumber')]
            user_dict['telephonenumbers'] = ipahelper.setup_mv_fields(user_dict.get('telephonenumber'), 'telephonenumber')

            if isinstance(user_dict.get('facsimiletelephonenumber',''), str):
                user_dict['facsimiletelephonenumber'] = [user_dict.get('facsimiletelephonenumber')]
            user_dict['facsimiletelephonenumbers'] = ipahelper.setup_mv_fields(user_dict.get('facsimiletelephonenumber'), 'facsimiletelephonenumber')

            if isinstance(user_dict.get('mobile',''), str):
                user_dict['mobile'] = [user_dict.get('mobile')]
            user_dict['mobiles'] = ipahelper.setup_mv_fields(user_dict.get('mobile'), 'mobile')

            if isinstance(user_dict.get('pager',''), str):
                user_dict['pager'] = [user_dict.get('pager')]
            user_dict['pagers'] = ipahelper.setup_mv_fields(user_dict.get('pager'), 'pager')

            if isinstance(user_dict.get('homephone',''), str):
                user_dict['homephone'] = [user_dict.get('homephone')]
            user_dict['homephones'] = ipahelper.setup_mv_fields(user_dict.get('homephone'), 'homephone')

            # Edit shouldn't fill in the password field.
            if user_dict.has_key('userpassword'):
                del(user_dict['userpassword'])

            user_dict['uid_hidden'] = user_dict.get('uid')

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
            if uid is None:
                uid = principal
            turbogears.flash("User edit failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect('/user/show', uid=uid)

    @expose()
    @identity.require(identity.not_anonymous())
    def update(self, **kw):
        """Updates an existing user"""
        self.restrict_post()
        client = self.get_ipaclient()

        if not kw.get('uid'):
            kw['uid'] = kw.get('uid_hidden')

        if kw.get('submit') == 'Cancel Edit':
            turbogears.flash("Edit user cancelled")
            raise turbogears.redirect('/user/show', uid=kw.get('uid'))

        # Fix incoming multi-valued fields we created for the form
        kw = ipahelper.fix_incoming_fields(kw, 'cn', 'cns')
        kw = ipahelper.fix_incoming_fields(kw, 'telephonenumber', 'telephonenumbers')
        kw = ipahelper.fix_incoming_fields(kw, 'facsimiletelephonenumber', 'facsimiletelephonenumbers')
        kw = ipahelper.fix_incoming_fields(kw, 'mobile', 'mobiles')
        kw = ipahelper.fix_incoming_fields(kw, 'pager', 'pagers')
        kw = ipahelper.fix_incoming_fields(kw, 'homephone', 'homephones')

        # admins and editors can update anybody. A user can only update
        # themselves. We need this check because it is very easy to guess
        # the edit URI.
        if ((not 'admins' in turbogears.identity.current.groups and
            not 'editors' in turbogears.identity.current.groups) and 
            (kw.get('uid') != turbogears.identity.current.display_name)):
            turbogears.flash("You do not have permission to update this user.")
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

        # We don't want to inadvertantly add this to a record
        try:
            del kw['uid_hidden']
        except KeyError:
            pass

        password_change = False
        user_modified = False

        #
        # Update the user itself
        #
        try:
            orig_user_dict = loads(b64decode(kw.get('user_orig')))

            # remove multi-valued fields we created for the form
            del(orig_user_dict['cns'])
            del(orig_user_dict['telephonenumbers'])
            del(orig_user_dict['facsimiletelephonenumbers'])
            del(orig_user_dict['mobiles'])
            del(orig_user_dict['pagers'])
            del(orig_user_dict['homephones'])

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

            if kw.get('editprotected') == 'true':
                if kw.get('userpassword'):
                    password_change = True
                new_user.setValue('uidnumber', str(kw.get('uidnumber')))
                new_user.setValue('gidnumber', str(kw.get('gidnumber')))
                new_user.setValue('homedirectory', str(kw.get('homedirectory')))
                new_user.setValue('uid', str(kw.get('uid')))

            for custom_field in user_edit_form.custom_fields:
                new_user.setValue(custom_field.name,
                                  kw.get(custom_field.name, ''))

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
            turbogears.flash("User update failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
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
            turbogears.flash("User password change failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
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

        if kw.get('nsAccountLock') == '':
            kw['nsAccountLock'] = "false"

        try:
            if kw.get('nsAccountLock') == "false" and new_user.getValues('nsaccountlock') == "true":
                client.mark_user_active(kw.get('uid'))
            elif kw.get('nsAccountLock') == "true" and new_user.nsaccountlock != "true":
                client.mark_user_inactive(kw.get('uid'))
        except ipaerror.IPAError, e:
            turbogears.flash("User status change failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
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
                users = client.find_users(uid.encode('utf-8'), user_fields, 0, 2)
                counter = users[0]
                users = users[1:]
                if counter == -1:
                    turbogears.flash("These results are truncated.<br />" +
                                    "Please refine your search and try again.")
            except ipaerror.IPAError, e:
                turbogears.flash("User list failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
                raise turbogears.redirect("/user/list")

        return dict(users=users, uid=uid, fields=ipagui.forms.user.UserFields())


    @expose("ipagui.templates.usershow")
    @identity.require(identity.not_anonymous())
    def show(self, uid):
        """Retrieve a single user for display"""
        client = self.get_ipaclient()
        self.load_custom_fields()

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
            turbogears.flash("User show failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect("/")

    @expose()
    @identity.require(identity.not_anonymous())
    def delete(self, uid):
        """Delete user."""
        self.restrict_post()
        client = self.get_ipaclient()

        try:
            client.delete_user(uid)

            turbogears.flash("user deleted")
            raise turbogears.redirect('/user/list')
        except (SyntaxError, ipaerror.IPAError), e:
            turbogears.flash("User deletion failed: " + str(e) + "<br/>" + e.detail[0]['desc'])
            raise turbogears.redirect('/user/list')

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
                turbogears.flash("search failed: " + str(e) + "<br/>" + e.detail[0]['desc'])

        return dict(users=users, criteria=criteria,
                which_select=kw.get('which_select'),
                counter=users_counter)
