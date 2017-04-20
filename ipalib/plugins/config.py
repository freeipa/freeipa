# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

from ipalib import api
from ipalib import Bool, Int, Str, IA5Str, StrEnum, DNParam
from ipalib.plugable import Registry
from ipalib.plugins.baseldap import *
from ipalib.plugins.selinuxusermap import validate_selinuxuser
from ipalib import _
from ipalib.errors import ValidationError

# 389-ds attributes that should be skipped in attribute checks
OPERATIONAL_ATTRIBUTES = ('nsaccountlock', 'member', 'memberof',
    'memberindirect', 'memberofindirect',)

__doc__ = _("""
Server configuration

Manage the default values that IPA uses and some of its tuning parameters.

NOTES:

The password notification value (--pwdexpnotify) is stored here so it will
be replicated. It is not currently used to notify users in advance of an
expiring password.

Some attributes are read-only, provided only for information purposes. These
include:

Certificate Subject base: the configured certificate subject base,
  e.g. O=EXAMPLE.COM.  This is configurable only at install time.
Password plug-in features: currently defines additional hashes that the
  password will generate (there may be other conditions).

When setting the order list for mapping SELinux users you may need to
quote the value so it isn't interpreted by the shell.

EXAMPLES:

 Show basic server configuration:
   ipa config-show

 Show all configuration options:
   ipa config-show --all

 Change maximum username length to 99 characters:
   ipa config-mod --maxusername=99

 Increase default time and size limits for maximum IPA server search:
   ipa config-mod --searchtimelimit=10 --searchrecordslimit=2000

 Set default user e-mail domain:
   ipa config-mod --emaildomain=example.com

 Enable migration mode to make "ipa migrate-ds" command operational:
   ipa config-mod --enable-migration=TRUE

 Define SELinux user map order:
   ipa config-mod --ipaselinuxusermaporder='guest_u:s0$xguest_u:s0$user_u:s0-s0:c0.c1023$staff_u:s0-s0:c0.c1023$unconfined_u:s0-s0:c0.c1023'
""")

register = Registry()

@register()
class config(LDAPObject):
    """
    IPA configuration object
    """
    object_name = _('configuration options')
    default_attributes = [
        'ipamaxusernamelength', 'ipahomesrootdir', 'ipadefaultloginshell',
        'ipadefaultprimarygroup', 'ipadefaultemaildomain', 'ipasearchtimelimit',
        'ipasearchrecordslimit', 'ipausersearchfields', 'ipagroupsearchfields',
        'ipamigrationenabled', 'ipacertificatesubjectbase',
        'ipapwdexpadvnotify', 'ipaselinuxusermaporder',
        'ipaselinuxusermapdefault', 'ipaconfigstring', 'ipakrbauthzdata',
        'ipauserauthtype'
    ]
    container_dn = DN(('cn', 'ipaconfig'), ('cn', 'etc'))
    permission_filter_objectclasses = ['ipaguiconfig']
    managed_permissions = {
        'System: Read Global Configuration': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'cn', 'objectclass',
                'ipacertificatesubjectbase', 'ipaconfigstring',
                'ipadefaultemaildomain', 'ipadefaultloginshell',
                'ipadefaultprimarygroup', 'ipagroupobjectclasses',
                'ipagroupsearchfields', 'ipahomesrootdir',
                'ipakrbauthzdata', 'ipamaxusernamelength',
                'ipamigrationenabled', 'ipapwdexpadvnotify',
                'ipaselinuxusermapdefault', 'ipaselinuxusermaporder',
                'ipasearchrecordslimit', 'ipasearchtimelimit',
                'ipauserauthtype', 'ipauserobjectclasses',
                'ipausersearchfields', 'ipacustomfields',
            },
        },
    }

    label = _('Configuration')
    label_singular = _('Configuration')

    takes_params = (
        Int('ipamaxusernamelength',
            cli_name='maxusername',
            label=_('Maximum username length'),
            minvalue=1,
        ),
        IA5Str('ipahomesrootdir',
            cli_name='homedirectory',
            label=_('Home directory base'),
            doc=_('Default location of home directories'),
        ),
        Str('ipadefaultloginshell',
            cli_name='defaultshell',
            label=_('Default shell'),
            doc=_('Default shell for new users'),
        ),
        Str('ipadefaultprimarygroup',
            cli_name='defaultgroup',
            label=_('Default users group'),
            doc=_('Default group for new users'),
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            label=_('Default e-mail domain'),
            doc=_('Default e-mail domain'),
        ),
        Int('ipasearchtimelimit',
            cli_name='searchtimelimit',
            label=_('Search time limit'),
            doc=_('Maximum amount of time (seconds) for a search (-1 or 0 is unlimited)'),
            minvalue=-1,
        ),
        Int('ipasearchrecordslimit',
            cli_name='searchrecordslimit',
            label=_('Search size limit'),
            doc=_('Maximum number of records to search (-1 or 0 is unlimited)'),
            minvalue=-1,
        ),
        IA5Str('ipausersearchfields',
            cli_name='usersearch',
            label=_('User search fields'),
            doc=_('A comma-separated list of fields to search in when searching for users'),
        ),
        IA5Str('ipagroupsearchfields',
            cli_name='groupsearch',
            #label='Group search fields',
            label=_('Group search fields'),
            doc=_('A comma-separated list of fields to search in when searching for groups'),
        ),
        Bool('ipamigrationenabled',
            cli_name='enable_migration',
            label=_('Enable migration mode'),
            doc=_('Enable migration mode'),
        ),
        DNParam('ipacertificatesubjectbase',
            cli_name='subject',
            label=_('Certificate Subject base'),
            doc=_('Base for certificate subjects (OU=Test,O=Example)'),
            flags=['no_update'],
        ),
        Str('ipagroupobjectclasses+',
            cli_name='groupobjectclasses',
            label=_('Default group objectclasses'),
            doc=_('Default group objectclasses (comma-separated list)'),
            csv=True,
        ),
        Str('ipauserobjectclasses+',
            cli_name='userobjectclasses',
            label=_('Default user objectclasses'),
            doc=_('Default user objectclasses (comma-separated list)'),
            csv=True,
        ),
        Int('ipapwdexpadvnotify',
            cli_name='pwdexpnotify',
            label=_('Password Expiration Notification (days)'),
            doc=_('Number of days\'s notice of impending password expiration'),
            minvalue=0,
        ),
        StrEnum('ipaconfigstring*',
            cli_name='ipaconfigstring',
            label=_('Password plugin features'),
            doc=_('Extra hashes to generate in password plug-in'),
            values=(u'AllowNThash',
                    u'KDC:Disable Last Success', u'KDC:Disable Lockout',
                    u'KDC:Disable Default Preauth for SPNs'),
            csv=True,
        ),
        Str('ipaselinuxusermaporder',
            label=_('SELinux user map order'),
            doc=_('Order in increasing priority of SELinux users, delimited by $'),
        ),
        Str('ipaselinuxusermapdefault?',
            label=_('Default SELinux user'),
            doc=_('Default SELinux user when no match is found in SELinux map rule'),
        ),
        StrEnum('ipakrbauthzdata*',
            cli_name='pac_type',
            label=_('Default PAC types'),
            doc=_('Default types of PAC supported for services'),
            values=(u'MS-PAC', u'PAD', u'nfs:NONE'),
            csv=True,
        ),
        StrEnum('ipauserauthtype*',
            cli_name='user_auth_type',
            label=_('Default user authentication types'),
            doc=_('Default types of supported user authentication'),
            values=(u'password', u'radius', u'otp', u'disabled'),
            csv=True,
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return DN(('cn', 'ipaconfig'), ('cn', 'etc'), api.env.basedn)



@register()
class config_mod(LDAPUpdate):
    __doc__ = _('Modify configuration options.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        if 'ipadefaultprimarygroup' in entry_attrs:
            group=entry_attrs['ipadefaultprimarygroup']
            try:
                api.Object['group'].get_dn_if_exists(group)
            except errors.NotFound:
                raise errors.NotFound(message=_("The group doesn't exist"))
        kw = {}
        if 'ipausersearchfields' in entry_attrs:
            kw['ipausersearchfields'] = 'ipauserobjectclasses'
        if 'ipagroupsearchfields' in entry_attrs:
            kw['ipagroupsearchfields']  = 'ipagroupobjectclasses'
        if kw:
            config = ldap.get_ipa_config(list(kw.values()))
            for (k, v) in kw.items():
                allowed_attrs = ldap.get_allowed_attributes(config[v])
                fields = entry_attrs[k].split(',')
                for a in fields:
                    a = a.strip()
                    a, tomato, olive = a.partition(';')
                    if a not in allowed_attrs:
                        raise errors.ValidationError(
                            name=k, error=_('attribute "%s" not allowed') % a
                        )

        # Set ipasearchrecordslimit to -1 if 0 is used
        if 'ipasearchrecordslimit' in entry_attrs:
            if entry_attrs['ipasearchrecordslimit'] is 0:
                 entry_attrs['ipasearchrecordslimit'] = -1

        # Set ipasearchtimelimit to -1 if 0 is used
        if 'ipasearchtimelimit' in entry_attrs:
            if entry_attrs['ipasearchtimelimit'] is 0:
                 entry_attrs['ipasearchtimelimit'] = -1

        for (attr, obj) in (('ipauserobjectclasses', 'user'),
                            ('ipagroupobjectclasses', 'group')):
            if attr in entry_attrs:
                if not entry_attrs[attr]:
                    raise errors.ValidationError(name=attr,
                        error=_('May not be empty'))
                objectclasses = list(set(entry_attrs[attr]).union(
                        self.api.Object[obj].possible_objectclasses))
                new_allowed_attrs = ldap.get_allowed_attributes(objectclasses,
                                        raise_on_unknown=True)
                checked_attrs = self.api.Object[obj].default_attributes
                if self.api.Object[obj].uuid_attribute:
                    checked_attrs = checked_attrs + [self.api.Object[obj].uuid_attribute]
                for obj_attr in checked_attrs:
                    obj_attr, tomato, olive = obj_attr.partition(';')
                    if obj_attr in OPERATIONAL_ATTRIBUTES:
                        continue
                    if obj_attr in self.api.Object[obj].params and \
                      'virtual_attribute' in \
                      self.api.Object[obj].params[obj_attr].flags:
                        # skip virtual attributes
                        continue
                    if obj_attr not in new_allowed_attrs:
                        raise errors.ValidationError(name=attr,
                                error=_('%(obj)s default attribute %(attr)s would not be allowed!') \
                                % dict(obj=obj, attr=obj_attr))

        if ('ipaselinuxusermapdefault' in entry_attrs or
          'ipaselinuxusermaporder' in entry_attrs):
            config = None
            failedattr = 'ipaselinuxusermaporder'

            if 'ipaselinuxusermapdefault' in entry_attrs:
                defaultuser = entry_attrs['ipaselinuxusermapdefault']
                failedattr = 'ipaselinuxusermapdefault'

                # validate the new default user first
                if defaultuser is not None:
                    error_message = validate_selinuxuser(_, defaultuser)

                    if error_message:
                        raise errors.ValidationError(name='ipaselinuxusermapdefault',
                                error=error_message)

            else:
                config = ldap.get_ipa_config()
                defaultuser = config.get('ipaselinuxusermapdefault', [None])[0]

            if 'ipaselinuxusermaporder' in entry_attrs:
                order = entry_attrs['ipaselinuxusermaporder']
                userlist = order.split('$')

                # validate the new user order first
                for user in userlist:
                    if not user:
                        raise errors.ValidationError(name='ipaselinuxusermaporder',
                                error=_('A list of SELinux users delimited by $ expected'))

                    error_message = validate_selinuxuser(_, user)
                    if error_message:
                        error_message = _("SELinux user '%(user)s' is not "
                                "valid: %(error)s") % dict(user=user,
                                                          error=error_message)
                        raise errors.ValidationError(name='ipaselinuxusermaporder',
                                error=error_message)
            else:
                if not config:
                    config = ldap.get_ipa_config()
                order = config['ipaselinuxusermaporder']
                userlist = order[0].split('$')
            if defaultuser and defaultuser not in userlist:
                raise errors.ValidationError(name=failedattr,
                    error=_('SELinux user map default user not in order list'))

        return dn



@register()
class config_show(LDAPRetrieve):
    __doc__ = _('Show the current configuration.')

