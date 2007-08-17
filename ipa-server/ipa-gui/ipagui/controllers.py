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

ipa.config.init_config()
user_new_form = forms.user.UserNewForm()
user_edit_form = forms.user.UserEditForm()

password_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

client = ipa.ipaclient.IPAClient(True)
client.set_principal("test@FREEIPA.ORG")

def restrict_post():
    if cherrypy.request.method != "POST":
        turbogears.flash("This method only accepts posts")
        raise turbogears.redirect("/")

def to_ldap_hash(orig):
    """LDAP hashes expect all values to be a list.  This method converts single
       entries to a list."""
    new={}
    for (k,v) in orig.iteritems():
        if v == None:
            continue
        if not isinstance(v, list) and k != 'dn':
            v = [v]
        new[k] = v

    return new

def set_ldap_value(hash, key, value):
    """Converts unicode strings to normal strings
       (because LDAP is choking on unicode strings"""
    if value != None:
        value = value.encode('utf-8')
    hash[key] = value


class Root(controllers.RootController):

    @expose(template="ipagui.templates.welcome")
    def index(self):
        return dict()


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
            new_user = {}
            set_ldap_value(new_user, 'uid', kw.get('uid'))
            set_ldap_value(new_user, 'givenname', kw.get('givenname'))
            set_ldap_value(new_user, 'sn', kw.get('sn'))
            set_ldap_value(new_user, 'mail', kw.get('mail'))
            set_ldap_value(new_user, 'telephonenumber', kw.get('telephonenumber'))

            rv = client.add_user(new_user)
            turbogears.flash("%s added!" % kw['uid'])
            raise turbogears.redirect('/usershow', uid=kw['uid'])
        except xmlrpclib.Fault, f:
            turbogears.flash("User add failed: " + str(f.faultString))
            return dict(form=user_new_form, tg_template='ipagui.templates.usernew')


    @expose("ipagui.templates.useredit")
    def useredit(self, uid, tg_errors=None):
        """Displays the edit user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        user = client.get_user(uid)
        user_hash = user.toDict()
        # store a copy of the original user for the update later
        user_data = b64encode(dumps(user_hash))
        user_hash['user_orig'] = user_data
        return dict(form=user_edit_form, user=user_hash)

    @expose()
    def userupdate(self, **kw):
        """Updates an existing user"""
        restrict_post()
        if kw.get('submit') == 'Cancel':
            turbogears.flash("Edit user cancelled")
            raise turbogears.redirect('/usershow', uid=kw.get('uid'))

        tg_errors, kw = self.userupdatevalidate(**kw)
        if tg_errors:
            return dict(form=user_edit_form, user=kw,
                        tg_template='ipagui.templates.useredit')

        try:
            orig_user = loads(b64decode(kw.get('user_orig')))

            new_user = dict(orig_user)
            set_ldap_value(new_user, 'givenname', kw.get('givenname'))
            set_ldap_value(new_user, 'sn', kw.get('sn'))
            set_ldap_value(new_user, 'mail', kw.get('mail'))
            set_ldap_value(new_user, 'telephonenumber', kw.get('telephonenumber'))
            #
            # this is a hack until we decide on the policy for names/cn/sn/givenName
            #
            set_ldap_value(new_user, 'cn', 
                           "%s %s" % (kw.get('givenname'), kw.get('sn')))

            orig_user = to_ldap_hash(orig_user)
            new_user = to_ldap_hash(new_user)

            rv = client.update_user(orig_user, new_user)
            turbogears.flash("%s updated!" % kw['uid'])
            raise turbogears.redirect('/usershow', uid=kw['uid'])
        except xmlrpclib.Fault, f:
            turbogears.flash("User update failed: " + str(f.faultString))
            return dict(form=user_edit_form, user=kw,
                        tg_template='ipagui.templates.useredit')


    @expose("ipagui.templates.userlist")
    def userlist(self, **kw):
        """Retrieve a list of all users and display them in one huge list"""
        users = None
        uid = kw.get('uid')
        if uid != None and len(uid) > 0:
            users = client.find_users("*%s*" % uid)

        return dict(users=users, fields=forms.user.UserFields())


    @expose("ipagui.templates.usershow")
    def usershow(self, uid):
        """Retrieve a single user for display"""
        try:
            user = client.get_user(uid)
            return dict(user=user.toDict(), fields=forms.user.UserFields())
        except xmlrpclib.Fault, f:
            turbogears.flash("User show failed: " + str(f.faultString))
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

    @expose()
    def generate_password(self):
        password = ""
        generator = random.SystemRandom()
        for char in range(8):
            index = generator.randint(0, len(password_chars) - 1)
            password += password_chars[index]

        return password


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
