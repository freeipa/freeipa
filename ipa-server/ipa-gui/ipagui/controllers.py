import random
from pickle import dumps, loads
from base64 import b64encode, b64decode

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

def restrict_post():
    if cherrypy.request.method != "POST":
        turbogears.flash("This method only accepts posts")
        raise turbogears.redirect("/")

def utf8_encode(value):
    if value != None:
        value = value.encode('utf-8')
    return value


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
            return self.index()



    ########
    # User #
    ########

    @expose("ipagui.templates.usernew")
    @identity.require(identity.not_anonymous())
    def usernew(self, tg_errors=None):
        """Displays the new user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        return dict(form=user_new_form)

    @expose()
    @identity.require(identity.not_anonymous())
    def usercreate(self, **kw):
        """Creates a new user"""
        restrict_post()
        client.set_principal(identity.current.user_name)
        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add user cancelled")
            raise turbogears.redirect('/userlist')

        tg_errors, kw = self.usercreatevalidate(**kw)
        if tg_errors:
            return dict(form=user_new_form, tg_template='ipagui.templates.usernew')

        try:
            new_user = ipa.user.User()
            new_user.setValue('uid', kw.get('uid'))
            new_user.setValue('givenname', kw.get('givenname'))
            new_user.setValue('sn', kw.get('sn'))
            new_user.setValue('mail', kw.get('mail'))
            new_user.setValue('telephonenumber', kw.get('telephonenumber'))
            if kw.get('nsAccountLock'):
                new_user.setValue('nsAccountLock', 'true')

            rv = client.add_user(new_user)
            turbogears.flash("%s added!" % kw['uid'])
            raise turbogears.redirect('/usershow', uid=kw['uid'])
        except ipaerror.exception_for(ipaerror.LDAP_DUPLICATE):
            turbogears.flash("Person with login '%s' already exists" %
                    kw.get('uid'))
            return dict(form=user_new_form, tg_template='ipagui.templates.usernew')
        except ipaerror.IPAError, e:
            turbogears.flash("User add failed: " + str(e))
            return dict(form=user_new_form, tg_template='ipagui.templates.usernew')


    @expose("ipagui.templates.useredit")
    @identity.require(identity.not_anonymous())
    def useredit(self, uid, tg_errors=None):
        """Displays the edit user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        client.set_principal(identity.current.user_name)
        user = client.get_user_by_uid(uid, user_fields)
        user_dict = user.toDict()
        # Edit shouldn't fill in the password field.
        if user_dict.has_key('userpassword'):
            del(user_dict['userpassword'])

        # store a copy of the original user for the update later
        user_data = b64encode(dumps(user_dict))
        user_dict['user_orig'] = user_data
        return dict(form=user_edit_form, user=user_dict)

    @expose()
    @identity.require(identity.not_anonymous())
    def userupdate(self, **kw):
        """Updates an existing user"""
        restrict_post()
        client.set_principal(identity.current.user_name)
        if kw.get('submit') == 'Cancel Edit':
            turbogears.flash("Edit user cancelled")
            raise turbogears.redirect('/usershow', uid=kw.get('uid'))

        tg_errors, kw = self.userupdatevalidate(**kw)
        if tg_errors:
            return dict(form=user_edit_form, user=kw,
                        tg_template='ipagui.templates.useredit')

        try:
            orig_user_dict = loads(b64decode(kw.get('user_orig')))

            new_user = ipa.user.User(orig_user_dict)
            new_user.setValue('givenname', kw.get('givenname'))
            new_user.setValue('sn', kw.get('sn'))
            new_user.setValue('mail', kw.get('mail'))
            new_user.setValue('telephonenumber', kw.get('telephonenumber'))
            if kw.get('nsAccountLock'):
                new_user.setValue('nsAccountLock', 'true')
            else:
                new_user.setValue('nsAccountLock', None)
            if kw.get('userpassword'):
                new_user.setValue('userpassword', kw.get('userpassword'))
            if kw.get('uidnumber'):
                new_user.setValue('uidnumber', kw.get('uidnumber'))
            if kw.get('gidnumber'):
                new_user.setValue('gidnumber', kw.get('gidnumber'))

            #
            # this is a hack until we decide on the policy for names/cn/sn/givenName
            #
            new_user.setValue('cn',
                           "%s %s" % (new_user.getValue('givenname'),
                                      new_user.getValue('sn')))

            rv = client.update_user(new_user)
            turbogears.flash("%s updated!" % kw['uid'])
            raise turbogears.redirect('/usershow', uid=kw['uid'])
        except ipaerror.IPAError, e:
            turbogears.flash("User update failed: " + str(e))
            return dict(form=user_edit_form, user=kw,
                        tg_template='ipagui.templates.useredit')


    @expose("ipagui.templates.userlist")
    @identity.require(identity.not_anonymous())
    def userlist(self, **kw):
        """Retrieve a list of all users and display them in one huge list"""
        client.set_principal(identity.current.user_name)
        users = None
        counter = 0
        uid = kw.get('uid')
        if uid != None and len(uid) > 0:
            try:
                users = client.find_users(uid.encode('utf-8'))
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
        client.set_principal(identity.current.user_name)
        try:
            user = client.get_user_by_uid(uid, user_fields)
            return dict(user=user.toDict(), fields=forms.user.UserFields())
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
        if (len(givenname) == 0) or (len(sn) == 0):
            return ""

        client.set_principal(identity.current.user_name)
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
        if (len(givenname) == 0) or (len(sn) == 0):
            return ""

        client.set_principal(identity.current.user_name)
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
        client.set_principal(identity.current.user_name)
        return dict()

    @expose("ipagui.templates.groupnew")
    @identity.require(identity.not_anonymous())
    def groupnew(self, tg_errors=None):
        """Displays the new group form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        client.set_principal(identity.current.user_name)

        return dict(form=group_new_form)

    @expose()
    @identity.require(identity.not_anonymous())
    def groupcreate(self, **kw):
        """Creates a new group"""
        restrict_post()
        client.set_principal(identity.current.user_name)

        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add group cancelled")
            raise turbogears.redirect('/')

        tg_errors, kw = self.groupcreatevalidate(**kw)
        if tg_errors:
            return dict(form=group_new_form, tg_template='ipagui.templates.groupnew')

        try:
            new_group = ipa.group.Group()
            new_group.setValue('cn', kw.get('cn'))
            new_group.setValue('description', kw.get('description'))

            rv = client.add_group(new_group)
            turbogears.flash("%s added!" % kw.get('cn'))
            # raise turbogears.redirect('/groupedit', cn=kw['cn'])
            raise turbogears.redirect('/')
        except ipaerror.exception_for(ipaerror.LDAP_DUPLICATE):
            turbogears.flash("Group with name '%s' already exists" %
                    kw.get('cn'))
            return dict(form=group_new_form, tg_template='ipagui.templates.groupnew')
        except ipaerror.IPAError, e:
            turbogears.flash("Group add failed: " + str(e) + "<br/>" + str(e.detail))
            return dict(form=group_new_form, tg_template='ipagui.templates.groupnew')

    @validate(form=group_new_form)
    @identity.require(identity.not_anonymous())
    def groupcreatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @validate(form=group_edit_form)
    @identity.require(identity.not_anonymous())
    def groupupdatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw
