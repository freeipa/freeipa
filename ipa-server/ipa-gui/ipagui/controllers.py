import random
from pickle import dumps, loads
from base64 import b64encode, b64decode

import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
# from model import *
# import logging
# log = logging.getLogger("ipagui.controllers")

import ipa.config
import ipa.ipaclient
import ipa.user
import xmlrpclib
import forms.user
from helpers import userhelper
from ipa import ipaerror

ipa.config.init_config()
user_new_form = forms.user.UserNewForm()
user_edit_form = forms.user.UserEditForm()

password_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

client = ipa.ipaclient.IPAClient(True)
client.set_principal("test@FREEIPA.ORG")

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
    def index(self):
        return dict()

    @expose()
    def topsearch(self, **kw):
        if kw.get('searchtype') == "Users":
            return self.userlist(uid=kw.get('searchvalue'))
        else:
            return self.index()



    ########
    # User #
    ########

    @expose("ipagui.templates.usernew")
    def usernew(self, tg_errors=None):
        """Displays the new user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        return dict(form=user_new_form)

    @expose()
    def usercreate(self, **kw):
        """Creates a new user"""
        restrict_post()
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
        except ipaerror.IPAError, e:
            turbogears.flash("User add failed: " + str(e))
            return dict(form=user_new_form, tg_template='ipagui.templates.usernew')


    @expose("ipagui.templates.useredit")
    def useredit(self, uid, tg_errors=None):
        """Displays the edit user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        user = client.get_user_by_uid(uid, user_fields)
        user_dict = user.toDict()
        # store a copy of the original user for the update later
        user_data = b64encode(dumps(user_dict))
        user_dict['user_orig'] = user_data
        return dict(form=user_edit_form, user=user_dict)

    @expose()
    def userupdate(self, **kw):
        """Updates an existing user"""
        restrict_post()
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
    def userlist(self, **kw):
        """Retrieve a list of all users and display them in one huge list"""
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
    def usershow(self, uid):
        """Retrieve a single user for display"""
        try:
            user = client.get_user_by_uid(uid, user_fields)
            return dict(user=user.toDict(), fields=forms.user.UserFields())
        except ipaerror.IPAError, e:
            turbogears.flash("User show failed: " + str(e))
            raise turbogears.redirect("/")

    @validate(form=user_new_form)
    def usercreatevalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @validate(form=user_edit_form)
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
    def suggest_uid(self, givenname, sn):
        if (len(givenname) == 0) or (len(sn) == 0):
            return ""

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
    def suggest_email(self, givenname, sn):
        if (len(givenname) == 0) or (len(sn) == 0):
            return ""

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
    def groupindex(self, tg_errors=None):
        return dict()


    ############
    # Resource #
    ############

    @expose("ipagui.templates.resindex")
    def resindex(self, tg_errors=None):
        return dict()
