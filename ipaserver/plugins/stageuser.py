# Authors:
#   Thierry Bordaz <tbordaz@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from __future__ import absolute_import

import logging
import posixpath
from copy import deepcopy

import six

from ipalib import api, errors
from ipalib import Bool
from ipalib.plugable import Registry
from .baseldap import (
    LDAPCreate,
    LDAPQuery,
    DN)
from . import baseldap
from .baseuser import (
    baseuser,
    baseuser_add,
    baseuser_del,
    baseuser_mod,
    baseuser_find,
    baseuser_show,
    NO_UPG_MAGIC,
    baseuser_output_params,
    baseuser_add_cert,
    baseuser_remove_cert,
    baseuser_add_principal,
    baseuser_remove_principal,
    baseuser_add_manager,
    baseuser_remove_manager,
    baseuser_add_certmapdata,
    baseuser_remove_certmapdata)
from ipalib.request import context
from ipalib.util import set_krbcanonicalname
from ipalib import _, ngettext
from ipalib import output
from ipaplatform.paths import paths
from ipaplatform.constants import constants as platformconstants
from ipapython.ipautil import ipa_generate_password, TMP_PWD_ENTROPY_BITS
from ipalib.capabilities import client_has_capability

if six.PY3:
    unicode = str

__doc__ = _("""
Stageusers

Manage stage user entries.

Stage user entries are directly under the container: "cn=stage users,
cn=accounts, cn=provisioning, SUFFIX".
Users can not authenticate with those entries (even if the entries
contain credentials). Those entries are only candidate to become Active entries.

Active user entries are Posix users directly under the container: "cn=accounts, SUFFIX".
Users can authenticate with Active entries, at the condition they have
credentials.

Deleted user entries are Posix users directly under the container: "cn=deleted users,
cn=accounts, cn=provisioning, SUFFIX".
Users can not authenticate with those entries, even if the entries contain credentials.

The stage user container contains entries:
    - created by 'stageuser-add' commands that are Posix users,
    - created by external provisioning system.

A valid stage user entry MUST have:
    - entry RDN is 'uid',
    - ipaUniqueID is 'autogenerate'.

IPA supports a wide range of username formats, but you need to be aware of any
restrictions that may apply to your particular environment. For example,
usernames that start with a digit or usernames that exceed a certain length
may cause problems for some UNIX systems.
Use 'ipa config-mod' to change the username format allowed by IPA tools.


EXAMPLES:

 Add a new stageuser:
   ipa stageuser-add --first=Tim --last=User --password tuser1

 Add a stageuser from the deleted users container:
   ipa stageuser-add  --first=Tim --last=User --from-delete tuser1

""")

logger = logging.getLogger(__name__)

register = Registry()


stageuser_output_params = baseuser_output_params


@register()
class stageuser(baseuser):
    """
    Stage User object
    A Stage user is not an Active user and can not be used to bind with.
    Stage container is: cn=staged users,cn=accounts,cn=provisioning,SUFFIX
    Stage entry conforms the schema
    Stage entry RDN attribute is 'uid'
    Stage entry are disabled (nsAccountLock: True) through cos
    """

    container_dn              = baseuser.stage_container_dn
    label                     = _('Stage Users')
    label_singular            = _('Stage User')
    object_name               = _('stage user')
    object_name_plural        = _('stage users')
    managed_permissions       = {
        #
        # Stage container
        #
        # Allowed to create stage user
        'System: Add Stage User': {
            'ipapermlocation': DN(baseuser.stage_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.stage_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=*)'},
            'ipapermright': {'add'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators', 'Stage User Provisioning'},
        },
        # Allow to read kerberos/password
        'System: Read Stage User password': {
           'ipapermlocation': DN(baseuser.stage_container_dn, api.env.basedn),
           'ipapermbindruletype': 'permission',
           'ipapermtarget': DN('uid=*', baseuser.stage_container_dn, api.env.basedn),
           'ipapermtargetfilter': {'(objectclass=*)'},
           'ipapermright': {'read', 'search', 'compare'},
           'ipapermdefaultattr': {
               'userPassword', 'krbPrincipalKey',
           },
           'default_privileges': {'Stage User Administrators'},
        },
        # Allow to update stage user
        'System: Modify Stage User': {
            'ipapermlocation': DN(baseuser.stage_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.stage_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=*)'},
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators'},
        },
        # Allow to delete stage user
        'System: Remove Stage User': {
            'ipapermlocation': DN(baseuser.stage_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.stage_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=*)'},
            'ipapermright': {'delete'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators'},
        },
        # Allow to read any attributes of stage users
        'System: Read Stage Users': {
            'ipapermlocation': DN(baseuser.stage_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.stage_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=*)'},
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators'},
        },
        #
        # Preserve container
        #
        # Allow to read Preserved User
        'System: Read Preserved Users': {
            'ipapermlocation': DN(baseuser.delete_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.delete_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=posixaccount)'},
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators'},
        },
        # Allow to update Preserved User
        'System: Modify Preserved Users': {
            'ipapermlocation': DN(baseuser.delete_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.delete_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=posixaccount)'},
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators'},
        },
        # Allow to reset Preserved User password
        'System: Reset Preserved User password': {
            'ipapermlocation': DN(baseuser.delete_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.delete_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=posixaccount)'},
            'ipapermright': {'read', 'search', 'write'},
            'ipapermdefaultattr': {
                'userPassword', 'krbPrincipalKey','krbPasswordExpiration','krbLastPwdChange'
            },
            'default_privileges': {'Stage User Administrators'},
        },
        # Allow to delete preserved user
        'System: Remove preserved User': {
            'ipapermlocation': DN(baseuser.delete_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.delete_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=*)'},
            'ipapermright': {'delete'},
            'ipapermdefaultattr': {'*'},
            'default_privileges': {'Stage User Administrators'},
        },
        #
        # Active container
        #
        # Stage user administrators need write right on RDN when
        # the active user is deleted (preserved)
        'System: Modify User RDN': {
            'ipapermlocation': DN(baseuser.active_container_dn, api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtarget': DN('uid=*', baseuser.active_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=posixaccount)'},
            'ipapermright': {'write'},
            'ipapermdefaultattr': {'uid'},
            'default_privileges': {'Stage User Administrators'},
        },
        #
        # Cross containers autorization
        #
        # Allow to move active user to preserve container (user-del --preserve)
        # Note: targetfilter is the target parent container
        'System: Preserve User': {
            'ipapermlocation': DN(api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtargetfrom': DN(baseuser.active_container_dn, api.env.basedn),
            'ipapermtargetto': DN(baseuser.delete_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=nsContainer)'},
            'ipapermright': {'moddn'},
            'default_privileges': {'Stage User Administrators'},
        },
        # Allow to move preserved user to active container (user-undel)
        # Note: targetfilter is the target parent container
        'System: Undelete User': {
            'ipapermlocation': DN(api.env.basedn),
            'ipapermbindruletype': 'permission',
            'ipapermtargetfrom': DN(baseuser.delete_container_dn, api.env.basedn),
            'ipapermtargetto': DN(baseuser.active_container_dn, api.env.basedn),
            'ipapermtargetfilter': {'(objectclass=nsContainer)'},
            'ipapermright': {'moddn'},
            'default_privileges': {'Stage User Administrators'},
        },
     }

@register()
class stageuser_add(baseuser_add):
    __doc__ = _('Add a new stage user.')

    msg_summary = _('Added stage user "%(value)s"')

    has_output_params = baseuser_add.has_output_params + stageuser_output_params

    takes_options = LDAPCreate.takes_options + (
        Bool(
            'from_delete?',
            deprecated=True,
            doc=_('Create Stage user in from a delete user'),
            cli_name='from_delete',
            flags={'no_option'},
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        # then givenname and sn are required attributes
        if 'givenname' not in entry_attrs:
            raise errors.RequirementError(name='givenname', error=_('givenname is required'))

        if 'sn' not in entry_attrs:
            raise errors.RequirementError(name='sn', error=_('sn is required'))

        # we don't want an user private group to be created for this user
        # add NO_UPG_MAGIC description attribute to let the DS plugin know
        entry_attrs.setdefault('description', [])
        entry_attrs['description'].append(NO_UPG_MAGIC)

        # uidNumber/gidNumber
        entry_attrs.setdefault('uidnumber', baseldap.DNA_MAGIC)
        entry_attrs.setdefault('gidnumber', baseldap.DNA_MAGIC)

        if not client_has_capability(
                options['version'], 'optional_uid_params'):
            # https://fedorahosted.org/freeipa/ticket/2886
            # Old clients say 999 (OLD_DNA_MAGIC) when they really mean
            # "assign a value dynamically".
            OLD_DNA_MAGIC = 999
            if entry_attrs.get('uidnumber') == OLD_DNA_MAGIC:
                entry_attrs['uidnumber'] = baseldap.DNA_MAGIC
            if entry_attrs.get('gidnumber') == OLD_DNA_MAGIC:
                entry_attrs['gidnumber'] = baseldap.DNA_MAGIC


        # Check the lenght of the RDN (uid) value
        config = ldap.get_ipa_config()
        if 'ipamaxusernamelength' in config:
            if len(keys[-1]) > int(config.get('ipamaxusernamelength')[0]):
                raise errors.ValidationError(
                    name=self.obj.primary_key.cli_name,
                    error=_('can be at most %(len)d characters') % dict(
                        len = int(config.get('ipamaxusernamelength')[0])
                    )
                )
        default_shell = config.get('ipadefaultloginshell',
                                   [platformconstants.DEFAULT_SHELL])[0]
        entry_attrs.setdefault('loginshell', default_shell)
        # hack so we can request separate first and last name in CLI
        full_name = '%s %s' % (entry_attrs['givenname'], entry_attrs['sn'])
        entry_attrs.setdefault('cn', full_name)

        # Homedirectory
        # (order is : option, placeholder (TBD), CLI default value (here in config))
        if 'homedirectory' not in entry_attrs:
            # get home's root directory from config
            homes_root = config.get('ipahomesrootdir', [paths.HOME_DIR])[0]
            # build user's home directory based on his uid
            entry_attrs['homedirectory'] = posixpath.join(homes_root, keys[-1])

        # Kerberos principal
        entry_attrs.setdefault('krbprincipalname', '%s@%s' % (entry_attrs['uid'], api.env.realm))


        # If requested, generate a userpassword
        if 'userpassword' not in entry_attrs and options.get('random'):
            entry_attrs['userpassword'] = ipa_generate_password(
                entropy_bits=TMP_PWD_ENTROPY_BITS)
            # save the password so it can be displayed in post_callback
            setattr(context, 'randompassword', entry_attrs['userpassword'])

        # Check the email or create it
        if 'mail' in entry_attrs:
            entry_attrs['mail'] = self.obj.normalize_and_validate_email(entry_attrs['mail'], config)
        else:
            # No e-mail passed in. If we have a default e-mail domain set
            # then we'll add it automatically.
            defaultdomain = config.get('ipadefaultemaildomain', [None])[0]
            if defaultdomain:
                entry_attrs['mail'] = self.obj.normalize_and_validate_email(keys[-1], config)

        # If the manager is defined, check it is a ACTIVE user to validate it
        if 'manager' in entry_attrs:
            entry_attrs['manager'] = self.obj.normalize_manager(entry_attrs['manager'], self.obj.active_container_dn)

        if ('objectclass' in entry_attrs
            and 'userclass' in entry_attrs
            and 'ipauser' not in entry_attrs['objectclass']):
            entry_attrs['objectclass'].append('ipauser')

        if 'ipatokenradiusconfiglink' in entry_attrs:
            cl = entry_attrs['ipatokenradiusconfiglink']
            if cl:
                if 'objectclass' not in entry_attrs:
                    _entry = ldap.get_entry(dn, ['objectclass'])
                    entry_attrs['objectclass'] = _entry['objectclass']

                if 'ipatokenradiusproxyuser' not in entry_attrs['objectclass']:
                    entry_attrs['objectclass'].append('ipatokenradiusproxyuser')

                answer = self.api.Object['radiusproxy'].get_dn_if_exists(cl)
                entry_attrs['ipatokenradiusconfiglink'] = answer

        self.pre_common_callback(ldap, dn, entry_attrs, attrs_list, *keys,
                                 **options)

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)

        # Fetch the entry again to update memberof, mep data, etc updated
        # at the end of the transaction.
        newentry = ldap.get_entry(dn, ['*'])
        entry_attrs.update(newentry)

        if options.get('random', False):
            try:
                entry_attrs['randompassword'] = unicode(getattr(context, 'randompassword'))
            except AttributeError:
                # if both randompassword and userpassword options were used
                pass

        self.post_common_callback(ldap, dn, entry_attrs, *keys, **options)
        return dn

@register()
class stageuser_del(baseuser_del):
    __doc__ = _('Delete a stage user.')

    msg_summary = _('Deleted stage user "%(value)s"')

@register()
class stageuser_mod(baseuser_mod):
    __doc__ = _('Modify a stage user.')

    msg_summary = _('Modified stage user "%(value)s"')

    has_output_params = baseuser_mod.has_output_params + stageuser_output_params

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        self.pre_common_callback(ldap, dn, entry_attrs, attrs_list, *keys,
                                 **options)
        # Make sure it is not possible to authenticate with a Stage user account
        if 'nsaccountlock' in entry_attrs:
            del entry_attrs['nsaccountlock']
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        self.post_common_callback(ldap, dn, entry_attrs, **options)
        if 'nsaccountlock' in entry_attrs:
            del entry_attrs['nsaccountlock']
        return dn

@register()
class stageuser_find(baseuser_find):
    __doc__ = _('Search for stage users.')

    member_attributes = ['memberof']
    has_output_params = baseuser_find.has_output_params + stageuser_output_params

    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *keys, **options):
        assert isinstance(base_dn, DN)
        self.pre_common_callback(ldap, filter, attrs_list, base_dn, scope,
                                 *keys, **options)

        container_filter = ldap.make_filter_from_attr(
            'objectclass', 'posixaccount')
        # provisioning system can create non posixaccount stage user
        # but then they have to create inetOrgPerson stage user
        stagefilter = filter.replace(container_filter,
                                     "(|%s(objectclass=inetOrgPerson))" % container_filter)
        logger.debug("stageuser_find: pre_callback new filter=%s ",
                     stagefilter)
        return (stagefilter, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        self.post_common_callback(ldap, entries, lockout=True, **options)
        return truncated

    msg_summary = ngettext(
        '%(count)d user matched', '%(count)d users matched', 0
    )

@register()
class stageuser_show(baseuser_show):
    __doc__ = _('Display information about a stage user.')

    has_output_params = baseuser_show.has_output_params + stageuser_output_params

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        self.pre_common_callback(ldap, dn, attrs_list, *keys, **options)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        entry_attrs['nsaccountlock'] = True
        self.post_common_callback(ldap, dn, entry_attrs, *keys, **options)
        return dn


@register()
class stageuser_activate(LDAPQuery):
    __doc__ = _('Activate a stage user.')

    msg_summary = _('Activate a stage user "%(value)s"')

    preserved_DN_syntax_attrs = ('manager', 'managedby', 'secretary')

    searched_operational_attributes = ['uidNumber', 'gidNumber', 'nsAccountLock', 'ipauniqueid']

    has_output = output.standard_entry
    has_output_params = LDAPQuery.has_output_params + stageuser_output_params

    def _check_validy(self, dn, entry):
        if dn[0].attr != 'uid':
            raise errors.ValidationError(
                        name=self.obj.primary_key.cli_name,
                        error=_('Entry RDN is not \'uid\''),
                        )
        for attr in ('cn', 'sn', 'uid'):
            if attr not in entry:
                raise errors.ValidationError(
                            name=self.obj.primary_key.cli_name,
                            error=_('Entry has no \'%(attribute)s\'') % dict(attribute=attr),
                            )

    def _build_new_entry(self, ldap, dn, entry_from, entry_to):
        config = ldap.get_ipa_config()

        if 'uidnumber' not in entry_from:
            entry_to['uidnumber'] = baseldap.DNA_MAGIC
        if 'gidnumber' not in entry_from:
            entry_to['gidnumber'] = baseldap.DNA_MAGIC
        if 'homedirectory' not in entry_from:
            # get home's root directory from config
            homes_root = config.get('ipahomesrootdir', [paths.HOME_DIR])[0]
            # build user's home directory based on his uid
            entry_to['homedirectory'] = posixpath.join(homes_root, dn[0].value)
        if 'ipamaxusernamelength' in config:
            if len(dn[0].value) > int(config.get('ipamaxusernamelength')[0]):
                raise errors.ValidationError(
                    name=self.obj.primary_key.cli_name,
                    error=_('can be at most %(len)d characters') % dict(
                        len = int(config.get('ipamaxusernamelength')[0])
                    )
                )
        if 'loginshell' not in entry_from:
            default_shell = config.get('ipadefaultloginshell',
                                       [platformconstants.DEFAULT_SHELL])[0]
            if default_shell:
                entry_to.setdefault('loginshell', default_shell)

        if 'givenname' not in entry_from:
            entry_to['givenname'] = entry_from['cn'][0].split()[0]

        if 'krbprincipalname' not in entry_from:
            entry_to['krbprincipalname'] = '%s@%s' % (entry_from['uid'][0], api.env.realm)

        set_krbcanonicalname(entry_to)

    def __dict_new_entry(self, *args, **options):
        ldap = self.obj.backend

        entry_attrs = self.args_options_2_entry(*args, **options)
        entry_attrs = ldap.make_entry(DN(), entry_attrs)

        self.process_attr_options(entry_attrs, None, args, options)

        entry_attrs['objectclass'] = deepcopy(self.obj.object_class)

        if self.obj.object_class_config:
            config = ldap.get_ipa_config()
            entry_attrs['objectclass'] = config.get(
                self.obj.object_class_config, entry_attrs['objectclass']
            )

        return(entry_attrs)

    def __merge_values(self, args, options, entry_from, entry_to, attr):
        '''
        This routine merges the values of attr taken from entry_from, into entry_to.
        If attr is a syntax DN attribute, it is replaced by an empty value. It is a preferable solution
        compare to skiping it because the final entry may no longer conform the schema.
        An exception of this is for a limited set of syntax DN attribute that we want to
        preserved (defined in preserved_DN_syntax_attrs)
        see http://www.freeipa.org/page/V3/User_Life-Cycle_Management#Adjustment_of_DN_syntax_attributes
        '''
        if not attr in entry_to:
            if isinstance(entry_from[attr], (list, tuple)):
                # attr is multi value attribute
                entry_to[attr] = []
            else:
                # attr single valued attribute
                entry_to[attr] = None

        # At this point entry_to contains for all resulting attributes
        # either a list (possibly empty) or a value (possibly None)

        for value in entry_from[attr]:
                # merge all the values from->to
                v = self.__value_2_add(args, options, attr, value)
                if (isinstance(v, str) and v in ('', None)) or \
                   (isinstance(v, unicode) and v in (u'', None)):
                    try:
                        v.decode('utf-8')
                        logger.debug("merge: %s:%r wiped", attr, v)
                    except Exception:
                        logger.debug("merge %s: [no_print %s]",
                                     attr, v.__class__.__name__)
                    if isinstance(entry_to[attr], (list, tuple)):
                        # multi value attribute
                        if v not in entry_to[attr]:
                            # it may has been added before in the loop
                            # so add it only if it not present
                            entry_to[attr].append(v)
                    else:
                        # single value attribute
                        # keep the value defined in staging
                        entry_to[attr] = v
                else:
                    try:
                        v.decode('utf-8')
                        logger.debug("Add: %s:%r", attr, v)
                    except Exception:
                        logger.debug("Add %s: [no_print %s]",
                                     attr, v.__class__.__name__)

                    if isinstance(entry_to[attr], (list, tuple)):
                        # multi value attribute
                        if attr.lower() == 'objectclass':
                            entry_to[attr] = [oc.lower() for oc in entry_to[attr]]
                            value = value.lower()
                            if value not in entry_to[attr]:
                                entry_to[attr].append(value)
                        else:
                            if value not in entry_to[attr]:
                                entry_to[attr].append(value)
                    else:
                        # single value attribute
                        if value:
                            entry_to[attr] = value

    def __value_2_add(self, args, options, attr, value):
        '''
        If the attribute is NOT syntax DN it returns its value.
        Else it checks if the value can be preserved.
        To be preserved:
            - attribute must be in preserved_DN_syntax_attrs
            - value must be an active user DN (in Active container)
            - the active user entry exists
        '''
        ldap = self.obj.backend

        if ldap.has_dn_syntax(attr):
            if attr.lower() in self.preserved_DN_syntax_attrs:
                # we are about to add a DN syntax value
                # Check this is a valid DN
                if not isinstance(value, DN):
                    return u''

                if not self.obj.active_user(value):
                    return u''

                # Check that this value is a Active user
                try:
                    self._exc_wrapper(args, options, ldap.get_entry)(
                        value, ['dn']
                    )
                    return value
                except errors.NotFound:
                    return u''
            else:
                return u''
        else:
            return value

    def execute(self, *args, **options):

        ldap = self.obj.backend

        staging_dn = self.obj.get_dn(*args, **options)
        assert isinstance(staging_dn, DN)

        # retrieve the current entry
        try:
            entry_attrs = self._exc_wrapper(args, options, ldap.get_entry)(
                staging_dn, ['*']
            )
        except errors.NotFound:
            raise self.obj.handle_not_found(*args)
        entry_attrs = dict((k.lower(), v) for (k, v) in entry_attrs.items())

        # Check it does not exist an active entry with the same RDN
        active_dn = DN(staging_dn[0], api.env.container_user, api.env.basedn)
        try:
            self._exc_wrapper(args, options, ldap.get_entry)(
                active_dn, ['dn']
            )
            raise errors.DuplicateEntry(
                message=_('active user with name "%(user)s" already exists') %
                dict(user=args[-1]))
        except errors.NotFound:
            pass

        # Check the original entry is valid
        self._check_validy(staging_dn, entry_attrs)

        # Time to build the new entry
        result_entry = {'dn' : active_dn}
        new_entry_attrs = self.__dict_new_entry()
        for (attr, values) in entry_attrs.items():
            self.__merge_values(args, options, entry_attrs, new_entry_attrs, attr)
            result_entry[attr] = values

        # Allow Managed entry plugin to do its work
        if 'description' in new_entry_attrs and NO_UPG_MAGIC in new_entry_attrs['description']:
            new_entry_attrs['description'].remove(NO_UPG_MAGIC)
            if result_entry['description'] == NO_UPG_MAGIC:
                del result_entry['description']

        for (k, v) in new_entry_attrs.items():
            logger.debug("new entry: k=%r and v=%r)", k, v)

        self._build_new_entry(ldap, staging_dn, entry_attrs, new_entry_attrs)

        # Add the Active entry
        entry = ldap.make_entry(active_dn, new_entry_attrs)
        self._exc_wrapper(args, options, ldap.add_entry)(entry)

        # Now delete the Staging entry
        try:
            self._exc_wrapper(args, options, ldap.delete_entry)(staging_dn)
        except:
            try:
                logger.error("Fail to delete the Staging user after "
                             "activating it %s ", staging_dn)
                self._exc_wrapper(args, options, ldap.delete_entry)(active_dn)
            except Exception:
                logger.error("Fail to cleanup activation. The user remains "
                             "active %s", active_dn)
            raise

        # add the user we just created into the default primary group
        config = ldap.get_ipa_config()
        def_primary_group = config.get('ipadefaultprimarygroup')
        group_dn = self.api.Object['group'].get_dn(def_primary_group)

        # if the user is already a member of default primary group,
        # do not raise error
        # this can happen if automember rule or default group is set
        try:
            ldap.add_entry_to_group(active_dn, group_dn)
        except errors.AlreadyGroupMember:
            pass

        # Now retrieve the activated entry
        result = self.api.Command.user_show(
            args[-1],
            all=options.get('all', False),
            raw=options.get('raw', False),
            version=options.get('version'),
        )
        result['summary'] = unicode(
            _('Stage user %s activated' % staging_dn[0].value))

        return result


@register()
class stageuser_add_manager(baseuser_add_manager):
    __doc__ = _("Add a manager to the stage user entry")


@register()
class stageuser_remove_manager(baseuser_remove_manager):
    __doc__ = _("Remove a manager to the stage user entry")


@register()
class stageuser_add_cert(baseuser_add_cert):
    __doc__ = _("Add one or more certificates to the stageuser entry")
    msg_summary = _('Added certificates to stageuser "%(value)s"')


@register()
class stageuser_remove_cert(baseuser_remove_cert):
    __doc__ = _("Remove one or more certificates to the stageuser entry")
    msg_summary = _('Removed certificates from stageuser "%(value)s"')


@register()
class stageuser_add_principal(baseuser_add_principal):
    __doc__ = _('Add new principal alias to the stageuser entry')
    msg_summary = _('Added new aliases to stageuser "%(value)s"')


@register()
class stageuser_remove_principal(baseuser_remove_principal):
    __doc__ = _('Remove principal alias from the stageuser entry')
    msg_summary = _('Removed aliases from stageuser "%(value)s"')


@register()
class stageuser_add_certmapdata(baseuser_add_certmapdata):
    __doc__ = _("Add one or more certificate mappings to the stage user"
                " entry.")


@register()
class stageuser_remove_certmapdata(baseuser_remove_certmapdata):
    __doc__ = _("Remove one or more certificate mappings from the stage user"
                " entry.")
