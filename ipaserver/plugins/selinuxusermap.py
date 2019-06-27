# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2011  Red Hat
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

import re

from ipalib import api, errors
from ipalib import Str, StrEnum, Bool
from ipalib.plugable import Registry
from .baseldap import (
    pkey_to_value,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPQuery,
    LDAPAddMember,
    LDAPRemoveMember)
from ipalib import _, ngettext
from ipalib import output
from .hbacrule import is_all
from ipapython.dn import DN
from ipaplatform.constants import constants as platformconstants

__doc__ = _("""
SELinux User Mapping

Map IPA users to SELinux users by host.

Hosts, hostgroups, users and groups can be either defined within
the rule or it may point to an existing HBAC rule. When using
--hbacrule option to selinuxusermap-find an exact match is made on the
HBAC rule name, so only one or zero entries will be returned.

EXAMPLES:

 Create a rule, "test1", that sets all users to xguest_u:s0 on the host "server":
   ipa selinuxusermap-add --usercat=all --selinuxuser=xguest_u:s0 test1
   ipa selinuxusermap-add-host --hosts=server.example.com test1

 Create a rule, "test2", that sets all users to guest_u:s0 and uses an existing HBAC rule for users and hosts:
   ipa selinuxusermap-add --usercat=all --hbacrule=webserver --selinuxuser=guest_u:s0 test2

 Display the properties of a rule:
   ipa selinuxusermap-show test2

 Create a rule for a specific user. This sets the SELinux context for
 user john to unconfined_u:s0-s0:c0.c1023 on any machine:
   ipa selinuxusermap-add --hostcat=all --selinuxuser=unconfined_u:s0-s0:c0.c1023 john_unconfined
   ipa selinuxusermap-add-user --users=john john_unconfined

 Disable a rule:
   ipa selinuxusermap-disable test1

 Enable a rule:
   ipa selinuxusermap-enable test1

 Find a rule referencing a specific HBAC rule:
   ipa selinuxusermap-find --hbacrule=allow_some

 Remove a rule:
   ipa selinuxusermap-del john_unconfined

SEEALSO:

 The list controlling the order in which the SELinux user map is applied
 and the default SELinux user are available in the config-show command.
""")

register = Registry()

notboth_err = _('HBAC rule and local members cannot both be set')


def validate_selinuxuser(ugettext, user):
    """
    An SELinux user has 3 components: user:MLS:MCS. user and MLS are required.
    user traditionally ends with _u but this is not mandatory.
      The regex is {name}

    The MLS part can only be:
      Level: {mls}
      MaxLevel: {mls_max}

    Then MCS could be {mcs}
    MaxCat: {mcs_max}

    Returns a message on invalid, returns nothing on valid.
    """.format(
        name=platformconstants.SELINUX_USER_REGEX,
        mls=platformconstants.SELINUX_MLS_REGEX,
        mls_max=platformconstants.SELINUX_MLS_MAX,
        mcs=platformconstants.SELINUX_MCS_REGEX,
        mcs_max=platformconstants.SELINUX_MCS_MAX,
    )
    SELINUX_MCS_MAX = platformconstants.SELINUX_MCS_MAX
    SELINUX_MCS_REGEX = platformconstants.SELINUX_MCS_REGEX
    SELINUX_MLS_MAX = platformconstants.SELINUX_MLS_MAX
    SELINUX_MLS_REGEX = platformconstants.SELINUX_MLS_REGEX
    SELINUX_USER_REGEX = platformconstants.SELINUX_USER_REGEX

    regex_name = re.compile(SELINUX_USER_REGEX)
    regex_mls = re.compile(SELINUX_MLS_REGEX)
    regex_mcs = re.compile(SELINUX_MCS_REGEX)

    # If we add in ::: we don't have to check to see if some values are
    # empty
    (name, mls, mcs, _ignore) = (user + ':::').split(':', 3)

    if not regex_name.match(name):
        return _('Invalid SELinux user name, must match {}').format(
            SELINUX_USER_REGEX)

    def _validate_level(level, level_regex, upper_limit):
        if not level_regex.match(level):
            return False

        for m in re.finditer(r'\d+', level):
            if int(m.group()) > upper_limit:
                return False
        return True

    if not mls or not _validate_level(mls, regex_mls, SELINUX_MLS_MAX):
        return _(
            'Invalid MLS value, must match {mls}, where max level '
            '{mls_max}').format(mls=SELINUX_MLS_REGEX, mls_max=SELINUX_MLS_MAX)

    if mcs and not _validate_level(mcs, regex_mcs, SELINUX_MCS_MAX):
        return _(
            'Invalid MCS value, must match {mcs}, where max category '
            '{mcs_max}').format(mcs=SELINUX_MCS_REGEX, mcs_max=SELINUX_MCS_MAX)

    return None

def validate_selinuxuser_inlist(ldap, user):
    """
    Ensure the user is in the list of allowed SELinux users.

    Returns nothing if the user is found, raises an exception otherwise.
    """
    config = ldap.get_ipa_config()
    item = config.get('ipaselinuxusermaporder', [])
    if len(item) != 1:
        raise errors.NotFound(reason=_('SELinux user map list not '
                                       'found in configuration'))
    userlist = item[0].split('$')
    if user not in userlist:
        raise errors.NotFound(
            reason=_('SELinux user %(user)s not found in '
                     'ordering list (in config)') % dict(user=user))


@register()
class selinuxusermap(LDAPObject):
    """
    SELinux User Map object.
    """
    container_dn = api.env.container_selinux
    object_name = _('SELinux User Map rule')
    object_name_plural = _('SELinux User Map rules')
    object_class = ['ipaassociation', 'ipaselinuxusermap']
    permission_filter_objectclasses = ['ipaselinuxusermap']
    default_attributes = [
        'cn', 'ipaenabledflag',
        'description', 'usercategory', 'hostcategory',
        'ipaenabledflag', 'memberuser', 'memberhost',
        'seealso', 'ipaselinuxuser',
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
    }
    managed_permissions = {
        'System: Read SELinux User Maps': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'accesstime', 'cn', 'description', 'hostcategory',
                'ipaenabledflag', 'ipaselinuxuser', 'ipauniqueid',
                'memberhost', 'memberuser', 'seealso', 'usercategory',
                'objectclass', 'member',
            },
        },
        'System: Add SELinux User Maps': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=usermap,cn=selinux,$SUFFIX")(version 3.0;acl "permission:Add SELinux User Maps";allow (add) groupdn = "ldap:///cn=Add SELinux User Maps,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'SELinux User Map Administrators'},
        },
        'System: Modify SELinux User Maps': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'cn', 'ipaenabledflag', 'ipaselinuxuser', 'memberhost',
                'memberuser', 'seealso'
            },
            'replaces': [
                '(targetattr = "cn || memberuser || memberhost || seealso || ipaselinuxuser || ipaenabledflag")(target = "ldap:///ipauniqueid=*,cn=usermap,cn=selinux,$SUFFIX")(version 3.0;acl "permission:Modify SELinux User Maps";allow (write) groupdn = "ldap:///cn=Modify SELinux User Maps,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'SELinux User Map Administrators'},
        },
        'System: Remove SELinux User Maps': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=usermap,cn=selinux,$SUFFIX")(version 3.0;acl "permission:Remove SELinux User Maps";allow (delete) groupdn = "ldap:///cn=Remove SELinux User Maps,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'SELinux User Map Administrators'},
        },
    }

    # These maps will not show as members of other entries

    label = _('SELinux User Maps')
    label_singular = _('SELinux User Map')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Rule name'),
            primary_key=True,
        ),
        Str('ipaselinuxuser', validate_selinuxuser,
            cli_name='selinuxuser',
            label=_('SELinux User'),
        ),
        Str('seealso?',
            cli_name='hbacrule',
            label=_('HBAC Rule'),
            doc=_('HBAC Rule that defines the users, groups and hostgroups'),
        ),
        StrEnum('usercategory?',
            cli_name='usercat',
            label=_('User category'),
            doc=_('User category the rule applies to'),
            values=(u'all', ),
        ),
        StrEnum('hostcategory?',
            cli_name='hostcat',
            label=_('Host category'),
            doc=_('Host category the rule applies to'),
            values=(u'all', ),
        ),
        Str('description?',
            cli_name='desc',
            label=_('Description'),
        ),
        Bool('ipaenabledflag?',
             label=_('Enabled'),
             flags=['no_option'],
        ),
        Str('memberuser_user?',
            label=_('Users'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberuser_group?',
            label=_('User Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_host?',
            label=_('Hosts'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberhost_hostgroup?',
            label=_('Host Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    def _normalize_seealso(self, seealso):
        """
        Given a HBAC rule name verify its existence and return the dn.
        """
        if not seealso:
            return None

        try:
            dn = DN(seealso)
            return str(dn)
        except ValueError:
            try:
                entry_attrs = self.backend.find_entry_by_attr(
                    self.api.Object['hbacrule'].primary_key.name,
                    seealso,
                    self.api.Object['hbacrule'].object_class,
                    [''],
                    DN(self.api.Object['hbacrule'].container_dn, api.env.basedn))
                seealso = entry_attrs.dn
            except errors.NotFound:
                raise errors.NotFound(reason=_('HBAC rule %(rule)s not found') % dict(rule=seealso))

        return seealso

    def _convert_seealso(self, ldap, entry_attrs, **options):
        """
        Convert an HBAC rule dn into a name
        """
        if options.get('raw', False):
            return

        if 'seealso' in entry_attrs:
            hbac_attrs = ldap.get_entry(entry_attrs['seealso'][0], ['cn'])
            entry_attrs['seealso'] = hbac_attrs['cn'][0]



@register()
class selinuxusermap_add(LDAPCreate):
    __doc__ = _('Create a new SELinux User Map.')

    msg_summary = _('Added SELinux User Map "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # rules are enabled by default
        entry_attrs['ipaenabledflag'] = 'TRUE'
        validate_selinuxuser_inlist(ldap, entry_attrs['ipaselinuxuser'])

        # hbacrule is not allowed when usercat or hostcat is set
        is_to_be_set = lambda x: x in entry_attrs and entry_attrs[x] != None

        are_local_members_to_be_set = any(is_to_be_set(attr)
                                          for attr in ('usercategory',
                                                       'hostcategory'))

        is_hbacrule_to_be_set = is_to_be_set('seealso')

        if is_hbacrule_to_be_set and are_local_members_to_be_set:
            raise errors.MutuallyExclusiveError(reason=notboth_err)

        if is_hbacrule_to_be_set:
            entry_attrs['seealso'] = self.obj._normalize_seealso(entry_attrs['seealso'])

        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj._convert_seealso(ldap, entry_attrs, **options)

        return dn



@register()
class selinuxusermap_del(LDAPDelete):
    __doc__ = _('Delete a SELinux User Map.')

    msg_summary = _('Deleted SELinux User Map "%(value)s"')



@register()
class selinuxusermap_mod(LDAPUpdate):
    __doc__ = _('Modify a SELinux User Map.')

    msg_summary = _('Modified SELinux User Map "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            _entry_attrs = ldap.get_entry(dn, attrs_list)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        def is_to_be_deleted(x):
            return (
                (x in _entry_attrs and x in entry_attrs)
                and entry_attrs[x] is None
            )

        # makes sure the local members and hbacrule is not set at the same time
        # memberuser or memberhost could have been set using --setattr
        def is_to_be_set(x):
            return (
                (
                    (x in _entry_attrs and _entry_attrs[x] is not None) or
                    (x in entry_attrs and entry_attrs[x] is not None)
                )
                and not is_to_be_deleted(x)
            )

        are_local_members_to_be_set = any(is_to_be_set(attr)
                                          for attr in ('usercategory',
                                                       'hostcategory',
                                                       'memberuser',
                                                       'memberhost'))

        is_hbacrule_to_be_set = is_to_be_set('seealso')

        # this can disable all modifications if hbacrule and local members were
        # set at the same time bypassing this commad, e.g. using ldapmodify
        if are_local_members_to_be_set and is_hbacrule_to_be_set:
            raise errors.MutuallyExclusiveError(reason=notboth_err)

        if (is_all(entry_attrs, 'usercategory')
                and 'memberuser' in entry_attrs):
            raise errors.MutuallyExclusiveError(
                reason="user category cannot be set to 'all' while there "
                       "are allowed users"
            )
        if (is_all(entry_attrs, 'hostcategory')
                and 'memberhost' in entry_attrs):
            raise errors.MutuallyExclusiveError(
                reason="host category cannot be set to 'all' while there "
                       "are allowed hosts"
            )

        if 'ipaselinuxuser' in entry_attrs:
            validate_selinuxuser_inlist(ldap, entry_attrs['ipaselinuxuser'])

        if 'seealso' in entry_attrs:
            entry_attrs['seealso'] = self.obj._normalize_seealso(
                entry_attrs['seealso']
            )
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj._convert_seealso(ldap, entry_attrs, **options)
        return dn



@register()
class selinuxusermap_find(LDAPSearch):
    __doc__ = _('Search for SELinux User Maps.')

    msg_summary = ngettext(
        '%(count)d SELinux User Map matched', '%(count)d SELinux User Maps matched', 0
    )

    def execute(self, *args, **options):
        # If searching on hbacrule we need to find the uuid to search on
        if options.get('seealso'):
            hbacrule = options['seealso']

            try:
                hbac = api.Command['hbacrule_show'](hbacrule,
all=True)['result']
                dn = hbac['dn']
            except errors.NotFound:
                return dict(count=0, result=[], truncated=False)
            options['seealso'] = dn

        return super(selinuxusermap_find, self).execute(*args, **options)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        if options.get('pkey_only', False):
            return truncated
        for attrs in entries:
            self.obj._convert_seealso(ldap, attrs, **options)
        return truncated



@register()
class selinuxusermap_show(LDAPRetrieve):
    __doc__ = _('Display the properties of a SELinux User Map rule.')

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        self.obj._convert_seealso(ldap, entry_attrs, **options)
        return dn



@register()
class selinuxusermap_enable(LDAPQuery):
    __doc__ = _('Enable an SELinux User Map rule.')

    msg_summary = _('Enabled SELinux User Map "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['TRUE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            raise errors.AlreadyActive()

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )



@register()
class selinuxusermap_disable(LDAPQuery):
    __doc__ = _('Disable an SELinux User Map rule.')

    msg_summary = _('Disabled SELinux User Map "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            raise self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            raise errors.AlreadyInactive()

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )



@register()
class selinuxusermap_add_user(LDAPAddMember):
    __doc__ = _('Add users and groups to an SELinux User Map rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)
        if ('usercategory' in entry_attrs and
                entry_attrs['usercategory'][0].lower() == 'all'):
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when user category='all'"))
        if 'seealso' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=notboth_err)
        return dn



@register()
class selinuxusermap_remove_user(LDAPRemoveMember):
    __doc__ = _('Remove users and groups from an SELinux User Map rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')



@register()
class selinuxusermap_add_host(LDAPAddMember):
    __doc__ = _('Add target hosts and hostgroups to an SELinux User Map rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)
        if ('hostcategory' in entry_attrs and
                entry_attrs['hostcategory'][0].lower() == 'all'):
            raise errors.MutuallyExclusiveError(
                reason=_("hosts cannot be added when host category='all'"))
        if 'seealso' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=notboth_err)
        return dn



@register()
class selinuxusermap_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove target hosts and hostgroups from an SELinux User Map rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')
