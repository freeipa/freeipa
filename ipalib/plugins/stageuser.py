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

from time import gmtime, strftime
import string
import posixpath
import os

from ipalib import api, errors
from ipalib import Flag, Int, Password, Str, Bool, StrEnum, DateTime
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import LDAPCreate, DN, entry_to_dict
from ipalib.plugins import baseldap
from ipalib.plugins.baseuser import baseuser, baseuser_add, baseuser_mod, baseuser_find, \
    NO_UPG_MAGIC, radius_dn2pk, \
    baseuser_pwdchars, fix_addressbook_permission_bindrule, normalize_principal, validate_principal, \
    baseuser_output_params, status_baseuser_output_params

from ipalib.request import context
from ipalib import _, ngettext
from ipalib import output
from ipaplatform.paths import paths
from ipapython.ipautil import ipa_generate_password
from ipapython.ipavalidate import Email
from ipalib.capabilities import client_has_capability
from ipalib.util import (normalize_sshpubkey, validate_sshpubkey,
    convert_sshpubkey_post)
if api.env.in_server and api.env.context in ['lite', 'server']:
    from ipaserver.plugins.ldap2 import ldap2

__doc__ = _("""
Stageusers

Manage stage user entries.

Stage user entries are directly under the container: "cn=stage users,
cn=accounts, cn=provisioning, SUFFIX".
User can not authenticate with those entries (even if the entries
contain credentials) and are candidate to become Active entries.

Active user entries are Posix users directly under the container: "cn=accounts, SUFFIX".
User can authenticate with Active entries, at the condition they have
credentials

Delete user enties are Posix users directly under the container: "cn=deleted users,
cn=accounts, cn=provisioning, SUFFIX".
User can not authenticate with those entries (even if the entries contain credentials)

The stage user container contains entries
    - created by 'stageuser-add' commands that are Posix users
    - created by external provisioning system

A valid stage user entry MUST:
    - entry RDN is 'uid'
    - ipaUniqueID is 'autogenerate'

IPA supports a wide range of username formats, but you need to be aware of any
restrictions that may apply to your particular environment. For example,
usernames that start with a digit or usernames that exceed a certain length
may cause problems for some UNIX systems.
Use 'ipa config-mod' to change the username format allowed by IPA tools.


EXAMPLES:

 Add a new stageuser:
   ipa stageuser-add --first=Tim --last=User --password tuser1

 Add a stageuser from the Delete container
   ipa stageuser-add  --first=Tim --last=User --from-delete tuser1

""")

register = Registry()


stageuser_output_params = baseuser_output_params

status_output_params = status_baseuser_output_params

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
    managed_permissions       = {}

@register()
class stageuser_add(baseuser_add):
    __doc__ = _('Add a new stage user.')

    msg_summary = _('Added stage user "%(value)s"')

    has_output_params = baseuser_add.has_output_params + stageuser_output_params

    takes_options = LDAPCreate.takes_options + (
        Flag('from_delete?',
            doc=_('Create Stage user in from a delete user'),
            cli_name='from_delete',
            default=False,
        ),
    )

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)

        if not options.get('from_delete'):
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
        default_shell = config.get('ipadefaultloginshell', [paths.SH])[0]
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
            entry_attrs['userpassword'] = ipa_generate_password(baseuser_pwdchars)
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

        return dn

    def execute(self, *keys, **options):
        '''
        A stage entry may be taken from the Delete container.
        In that case we rather do 'MODRDN' than 'ADD'.
        '''
        if options.get('from_delete'):
            ldap = self.obj.backend

            staging_dn = self.obj.get_dn(*keys, **options)
            delete_dn = DN(staging_dn[0], self.obj.delete_container_dn, api.env.basedn)

            # Check that this value is a Active user
            try:
                entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(delete_dn, ['dn'])
            except errors.NotFound:
                raise
            self._exc_wrapper(keys, options, ldap.move_entry_newsuperior)(delete_dn, str(DN(self.obj.stage_container_dn, api.env.basedn)))

            entry_attrs = entry_to_dict(entry_attrs, **options)
            entry_attrs['dn'] = delete_dn

            if self.obj.primary_key and keys[-1] is not None:
                return dict(result=entry_attrs, value=keys[-1])
            return dict(result=entry_attrs, value=u'')
        else:
            return super(stageuser_add, self).execute(*keys, **options)

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        config = ldap.get_ipa_config()

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

        self.obj.get_password_attributes(ldap, dn, entry_attrs)
        convert_sshpubkey_post(ldap, dn, entry_attrs)
        radius_dn2pk(self.api, entry_attrs)
        return dn
