# Authors:
#   Richard Kalinec <rkalinec@gmail.com>
#
# Copyright (C) 2020  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import logging

import six

from ipalib import api
from ipalib import Password, Str
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject, LDAPCreate, LDAPDelete, LDAPSearch, LDAPRetrieve)
from ipalib.request import context
from ipalib import _, ngettext
from ipalib.constants import (
    PATTERN_APPPW_UID, PATTERN_APPNAME)
from ipapython.dn import RDN, DN
from ipapython.ipautil import ipa_generate_password


if six.PY3:
    unicode = str

__doc__ = _("""
App password
""") + _("""
Manage app passwords for a user.
""") + _("""
A user can have multiple app passwords besides his primary password.
These cannot be used to manage the user's account in FreeIPA (i.e. log
in directly into FreeIPA), but to log into a specific application.  The
user can also use multiple app passwords for the same application for
use on various devices.  However, these restrictions cannot be enforced
by FreeIPA, only the use can effectively keep them by using a particular
app password for only one application (and only on one/some device(s),
if desired). App passwords can be added only by generating them, and
they cannot be changed afterwards, only deleted. The command to find app
passwords always lists all app passwords of the specified user (which,
in the case of non-admins, can be only the current user).
""") + _("""
EXAMPLES:

 Generate a new app password for user1 for use with GitHub:
   ipa appspecificpw-add user1 GitHub-home-PC github

 List all the user's app passwords:
   ipa appspecificpw-find user1

 Delete an app password:
   ipa appspecificpw-del user1 XXXXXXXXX-XXXXXXXXXX-XXXXXXXXXX
""")

logger = logging.getLogger(__name__)

register = Registry()

apppw_output_params = (
)


@register()
class apppw(LDAPObject):
    """
    Object representing an app password of a user.
    """

    container_dn = api.env.container_apppw
    label = _('App passwords')
    label_singular = _('App password')
    object_name = _('app password')
    object_name_plural = _('app passwords')
    object_class = ['account', 'simplesecurityobject']
    disallow_object_classes = ['krbticketpolicyaux']
    permission_filter_objectclasses = ['account']
    permission_filter_objectclasses_string = '(objectclass=account)'
    managed_permissions = {
        'System: Allow users to add or remove an app password for themselves': {
            'ipapermbindruletype': 'permission',
            'ipapermlocation': container_dn,
            'ipapermtarget': DN('uid=*', 'cn=($dn)', api.env.container_apppw,
                                api.env.basedn),
            'ipapermtargetfilter': [
                permission_filter_objectclasses_string,
            ],
            'ipapermright': {'add', 'delete'},
            'ipapermdefaultattr': {
                'uid', 'description', 'ou', 'userpassword',
            },
        },
        'System: Allow users to search for their app passwords': {
            'ipapermbindruletype': 'permission',
            'ipapermlocation': container_dn,
            'ipapermtarget': DN('uid=*', 'cn=($dn)', api.env.container_apppw,
                                api.env.basedn),
            'ipapermtargetfilter': [
                permission_filter_objectclasses_string,
            ],
            'ipapermright': {'search', 'read'},
            'ipapermdefaultattr': {
                'uid', 'description', 'ou',
            },
        },
    }

    default_attributes = [
        'uid', 'description', 'ou',
    ]
    search_attributes = {
        'uid', 'description', 'ou',
    }
    search_display_attributes = {
        'uid', 'description', 'ou',
    }
    allow_rename = True
    bindable = False
    password_attributes = [
        ('userpassword', 'has_password'),
    ]

    takes_params = (
        Str(
            'uid',
            pattern=PATTERN_APPPW_UID,
            pattern_errmsg='may only be numbers 0 - 99',
            maxlength=2,
            label=_('App password\'s uid (0 - 99)'),
            primary_key=True,
            flags=('no_update'),
        ),
        Str(
            'description',
            label=_('Description'),
            flags=('no_update'),
        ),
        Str(
            'ou',
            pattern=PATTERN_APPNAME,
            pattern_errmsg='may only include letters, numbers, _, - and $',
            cli_name='appname',
            label=_('Application name'),
            doc=_('Name of the application with which this app password should '
                  'be used'),
            flags=('no_update'),
        ),
        Password(
            'userpassword',
            cli_name='password',
            label=_('Password'),
            flags=('no_create', 'no_update', 'no_search'),
            # FIXME: This is temporary till bug is fixed causing updates to
            # bomb out via the webUI.
            exclude='webui',
        ),
        Str(
            'randompassword',
            label=_('Random password'),
            flags=('no_create', 'no_update', 'no_search', 'virtual_attribute'),
        ),
    )


@register()
class apppw_add(LDAPCreate):
    __doc__ = _('Add a new app password of a user.')

    msg_summary = _('Added app password "%(value)s" of a user "%(value)s"')

    has_output_params = LDAPCreate.has_output_params + apppw_output_params

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        dn = DN(dn[0],
                ('cn', RDN(self.api.Backend.ldap2.conn.whoami_s()[4]).value),
                self.api.env.container_apppw,
                self.api.env.basedn)
        entry_attrs['userpassword'] = ipa_generate_password(
            uppercase=5, lowercase=5, digits=5, special=5, min_len=20)
        # save the password so it can be displayed in post_callback
        setattr(context, 'randompassword', entry_attrs['userpassword'])

        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        entry_attrs['randompassword'] = unicode(getattr(context,
                                                        'randompassword'))

        assert isinstance(dn, DN)
        return dn


@register()
class apppw_del(LDAPDelete):
    __doc__ = _('Delete an app password of a user.')

    msg_summary = _('Deleted app password "%(value)s" of a user "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        dn = DN(dn[0],
                ('cn', RDN(self.api.Backend.ldap2.conn.whoami_s()[4]).value),
                self.api.env.container_apppw,
                self.api.env.basedn)

        assert isinstance(dn, DN)
        return dn


@register()
class apppw_find(LDAPSearch):
    __doc__ = _('List app passwords of a user.')

    msg_summary = ngettext(
        '%(count)d app password matched', '%(count)d app passwords matched', 0
    )

    has_output_params = LDAPSearch.has_output_params + apppw_output_params

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope,
                     *keys, **options):
        filter = self.obj.permission_filter_objectclasses_string
        base_dn = DN(('cn', self.api.Backend.ldap2.conn.whoami_s()[4]),
                     self.api.env.container_apppw,
                     self.api.env.basedn)
        scope = ldap.SCOPE_ONELEVEL

        assert isinstance(base_dn, DN)
        return (filter, base_dn, scope)


@register()
class apppw_show(LDAPRetrieve):
    __doc__ = _('Display information about a user.')

    has_output_params = LDAPRetrieve.has_output_params + apppw_output_params

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        dn = DN(dn[0],
                ('cn', RDN(self.api.Backend.ldap2.conn.whoami_s()[4]).value),
                self.api.env.container_apppw,
                self.api.env.basedn)

        assert isinstance(dn, DN)
        return dn
