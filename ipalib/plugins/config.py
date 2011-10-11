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
from ipalib import Bool, Int, Str, IA5Str
from ipalib.plugins.baseldap import *
from ipalib import _
from ipalib.errors import ValidationError

# 389-ds attributes that should be skipped in attribute checks
OPERATIONAL_ATTRIBUTES = ('nsaccountlock', 'member', 'memberof',
    'memberindirect', 'memberofindirect',)

__doc__ = _("""
Manage the IPA configuration

Manage the default values that IPA uses and some of its tuning parameters.

 To show the current configuration:
   ipa config-show

 To modify the configuration:
   ipa config-mod --maxusername=99

The available options are:

User management options:

  --maxusername=INT     Max. username length when creating/modifying a user
  --homedirectory=STR   Default location of home directories (default /home)
  --defaultshell=STR    Default shell for new users (default /bin/sh)
  --defaultgroup=STR    Default group for new users (default ipausers). The
                        group must exist, or adding new users will fail.
  --emaildomain=STR     Default e-mail domain for new users

Search tuning options. These impact how much data is searched through and
how many records may be returned on a given search.

  --searchtimelimit=INT Max. amount of time (sec.) for a search (> 0, or -1 for
                        unlimited)
  --searchrecordslimit=INT Max. number of records to search (-1 is unlimited)

Server Configuration.

  --enable-migration=BOOL Enable migration mode
  --pwdexpnotify=INT      Password Expiration Notification (days)

The password notification value is stored here so it will be replicated.
It is not currently used to notify users in advance of an expiring
password.

Some attributes are read-only, provided only for information purposes. These
include:

Certificate Subject base: the configured certificate subject base,
  e.g. O=EXAMPLE.COM.  This is configurable only at install time.
Password plug-in features: currently defines additional hashes that the
  password will generate (there may be other conditions).
""")

def validate_searchtimelimit(ugettext, limit):
    if limit == 0:
        raise ValidationError(name='ipasearchtimelimit', error=_('searchtimelimit must be -1 or > 1.'))
    return None

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
        'ipapwdexpadvnotify',
    ]

    label = _('Configuration')
    label_singular = _('Configuration')

    takes_params = (
        Int('ipamaxusernamelength?',
            cli_name='maxusername',
            label=_('Max. username length'),
            minvalue=1,
        ),
        IA5Str('ipahomesrootdir?',
            cli_name='homedirectory',
            label=_('Home directory base'),
            doc=_('Default location of home directories.'),
        ),
        Str('ipadefaultloginshell?',
            cli_name='defaultshell',
            label=_('Default shell'),
            doc=_('Default shell for new users.'),
        ),
        Str('ipadefaultprimarygroup?',
            cli_name='defaultgroup',
            label=_('Default users group'),
            doc=_('Default group for new users.'),
        ),
        Str('ipadefaultemaildomain?',
            cli_name='emaildomain',
            label=_('Default e-mail domain for new users'),
            doc=_('Default e-mail domain new users.'),
        ),
        Int('ipasearchtimelimit?', validate_searchtimelimit,
            cli_name='searchtimelimit',
            label=_('Search time limit'),
            doc=_('Max. amount of time (sec.) for a search (> 0, or -1 for unlimited).'),
            minvalue=-1,
        ),
        Int('ipasearchrecordslimit?',
            cli_name='searchrecordslimit',
            label=_('Search size limit'),
            doc=_('Max. number of records to search (-1 is unlimited).'),
            minvalue=-1,
        ),
        IA5Str('ipausersearchfields?',
            cli_name='usersearch',
            label=_('User search fields'),
            doc=_('A comma-separated list of fields to search when searching for users.'),
        ),
        IA5Str('ipagroupsearchfields?',
            cli_name='groupsearch',
            label='Group search fields',
            doc=_('A comma-separated list of fields to search when searching for groups.'),
        ),
        Bool('ipamigrationenabled?',
            cli_name='enable_migration',
            label=_('Enable migration mode'),
            doc=_('Enable migration mode.'),
        ),
        Str('ipacertificatesubjectbase?',
            cli_name='subject',
            label=_('Certificate Subject base'),
            doc=_('Base for certificate subjects (OU=Test,O=Example).'),
            flags=['no_update'],
        ),
        List('ipagroupobjectclasses?',
            cli_name='groupobjectclasses',
            label=_('Default group objectclasses'),
            doc=_('Default group objectclasses (comma-separated list).'),
        ),
        List('ipauserobjectclasses?',
            cli_name='userobjectclasses',
            label=_('Default user objectclasses'),
            doc=_('Default user objectclasses (comma-separated list).'),
        ),
        Int('ipapwdexpadvnotify?',
            cli_name='pwdexpnotify',
            label=_('Password Expiration Notification (days)'),
            doc=_('Number of days\'s notice of impending password expiration.'),
            minvalue=0,
        ),
        Str('ipaconfigstring?',
            cli_name='ipaconfigstring',
            label=_('Password plugin features'),
            doc=_('Extra hashes to generate in password plug-in.'),
            flags=['no_update'],
        ),
    )

    def get_dn(self, *keys, **kwargs):
        return 'cn=ipaconfig,cn=etc'

api.register(config)


class config_mod(LDAPUpdate):
    __doc__ = _('Modify configuration options.')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        if 'ipamigrationenabled' in entry_attrs:
            if entry_attrs['ipamigrationenabled']:
                entry_attrs['ipamigrationenabled'] = 'TRUE'
            else:
                entry_attrs['ipamigrationenabled'] = 'FALSE'
        if 'ipadefaultprimarygroup' in entry_attrs:
            group=entry_attrs['ipadefaultprimarygroup']
            try:
                api.Command['group_show'](group)
            except errors.NotFound:
                raise errors.NotFound(message=unicode("The group doesn't exist"))
        kw = {}
        if 'ipausersearchfields' in entry_attrs:
            kw['ipausersearchfields'] = 'ipauserobjectclasses'
        if 'ipagroupsearchfields' in entry_attrs:
            kw['ipagroupsearchfields']  = 'ipagroupobjectclasses'
        if kw:
            config = ldap.get_ipa_config(kw.values())
            for (k, v) in kw.iteritems():
                allowed_attrs = ldap.get_allowed_attributes(config[1][v])
                fields = entry_attrs[k].split(',')
                for a in fields:
                    a = a.strip()
                    if a not in allowed_attrs:
                        raise errors.ValidationError(
                            name=k, error='attribute "%s" not allowed' % a
                        )

        for (attr, obj) in (('ipauserobjectclasses', 'user'),
                            ('ipagroupobjectclasses', 'group')):
            if attr in entry_attrs:
                objectclasses = list(set(entry_attrs[attr] \
                                         + self.api.Object[obj].possible_objectclasses))
                new_allowed_attrs = ldap.get_allowed_attributes(objectclasses,
                                        raise_on_unknown=True)
                checked_attrs = self.api.Object[obj].default_attributes
                if self.api.Object[obj].uuid_attribute:
                    checked_attrs = checked_attrs + [self.api.Object[obj].uuid_attribute]
                for obj_attr in checked_attrs:
                    if obj_attr in OPERATIONAL_ATTRIBUTES:
                        continue
                    if obj_attr not in new_allowed_attrs:
                        raise errors.ValidationError(name=attr,
                                error=_('%s default attribute %s would not be allowed!') \
                                % (obj, obj_attr))

        return dn

api.register(config_mod)


class config_show(LDAPRetrieve):
    __doc__ = _('Show the current configuration.')

api.register(config_show)
