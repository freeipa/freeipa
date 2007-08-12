import cherrypy
import turbogears
from turbogears import controllers, expose, flash
from turbogears import validators, validate
from turbogears import widgets, paginate
from turbogears import error_handler
# from model import *
# import logging
# log = logging.getLogger("ipagui.controllers")
# import ipa.rpcclient
import ipa.config
import ipa.ipaclient
import ipa.user
import xmlrpclib
import forms.user

ipa.config.init_config()
user_form = forms.user.UserFormWidget()

client = ipa.ipaclient.IPAClient(True)
client.set_principal("test@FREEIPA.ORG")

def restrict_post():
    if cherrypy.request.method != "POST":
        turbogears.flash("This method only accepts posts")
        raise turbogears.redirect("/")

def user_to_hash(user):
    return {
        'uid'       : user.getValue('uid'),
        'givenName' : user.getValue('givenName'),
        'sn'        : user.getValue('sn'),
        'mail'      : user.getValue('mail'),
        'telephoneNumber': user.getValue('telephoneNumber'),
        'uidNumber': user.getValue('uidNumber'),
        'gidNumber': user.getValue('gidNumber'),
            }

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

        return dict(form=user_form)

    @expose()
    def usercreate(self, **kw):
        """Creates a new user"""
        restrict_post()
        if kw.get('submit') == 'Cancel':
            turbogears.flash("Add user cancelled")
            raise turbogears.redirect('/userlist')

        tg_errors, kw = self.uservalidate(**kw)
        if tg_errors:
            return dict(form=user_form, tg_template='ipagui.templates.usernew')

        try:
            # rv = ipa.rpcclient.add_user(kw)
            newuser = ipa.user.User(None)
            newuser.setValue('uid', kw['uid'])
            newuser.setValue('givenName', kw['givenName'])
            newuser.setValue('sn', kw['sn'])
            newuser.setValue('mail', kw['mail'])
            newuser.setValue('telephoneNumber', kw['telephoneNumber'])
            newuser2 = {
                'uid'       : kw['uid'],
                'givenName' : kw['givenName'],
                'sn'        : kw['sn'],
                'mail'      : kw['mail'],
                'telephoneNumber': kw['telephoneNumber']
                    }
            rv = client.add_user(newuser2)
            turbogears.flash("%s added!" % kw['uid'])
            raise turbogears.redirect('/usershow', uid=kw['uid'])
        except xmlrpclib.Fault, f:
            turbogears.flash("User add failed: " + str(f.faultString))
            return dict(form=user_form, tg_template='ipagui.templates.usernew')


    @expose("ipagui.templates.useredit")
    def useredit(self, uid, tg_errors=None):
        """Displays the edit user form"""
        if tg_errors:
            turbogears.flash("There was a problem with the form!")

        # user = ipa.rpcclient.get_user(uid)
        user = client.get_user(uid)
        return dict(form=user_form, user=user_to_hash(user))

    @expose()
    def userupdate(self, **kw):
        """Updates an existing user"""
        restrict_post()
        if kw.get('submit') == 'Cancel':
            turbogears.flash("Edit user cancelled")
            raise turbogears.redirect('/usershow', uid=kw.get('uid'))

        tg_errors, kw = self.uservalidate(**kw)
        if tg_errors:
            return dict(form=user_form, user={}, tg_template='ipagui.templates.useredit')

        try:
            # rv = ipa.rpcclient.add_user(kw)
            turbogears.flash("%s updated!" % kw['uid'])
            raise turbogears.redirect('/usershow', uid=kw['uid'])
        except xmlrpclib.Fault, f:
            turbogears.flash("User add failed: " + str(f.faultString))
            return dict(form=user_form, user={}, tg_template='ipagui.templates.useredit')


    @expose("ipagui.templates.userlist")
    @paginate('users', limit=3, allow_limit_override=True)
    def userlist(self):
        """Retrieve a list of all users and display them in one huge list"""
        # users = ipa.rpcclient.get_all_users()
        users = client.get_all_users()
        return dict(users=users)


    @expose("ipagui.templates.usershow")
    def usershow(self, uid):
        """Retrieve a single user for display"""
        try:
            # user = ipa.rpcclient.get_user(uid)
            user = client.get_user(uid)
            return dict(user=user_to_hash(user))
        except xmlrpclib.Fault, f:
            turbogears.flash("User show failed: " + str(f.faultString))
            raise turbogears.redirect("/")

    @validate(form=user_form)
    def uservalidate(self, tg_errors=None, **kw):
        return tg_errors, kw

    @expose()
    def userindex(self):
        raise turbogears.redirect("/userlist")


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
