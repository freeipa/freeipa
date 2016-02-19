# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

from ipalib import api, errors
from ipalib import Str, StrEnum, Bool
from ipalib.plugable import Registry
from .baseldap import (
    pkey_to_value,
    external_host_param,
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPRetrieve,
    LDAPUpdate,
    LDAPSearch,
    LDAPQuery,
    LDAPAddMember,
    LDAPRemoveMember)
from ipalib import _, ngettext
from ipalib import output
from ipapython.dn import DN

__doc__ = _("""
Host-based access control

Control who can access what services on what hosts. You
can use HBAC to control which users or groups can
access a service, or group of services, on a target host.

You can also specify a category of users and target hosts.
This is currently limited to "all", but might be expanded in the
future.

Target hosts in HBAC rules must be hosts managed by IPA.

The available services and groups of services are controlled by the
hbacsvc and hbacsvcgroup plug-ins respectively.

EXAMPLES:

 Create a rule, "test1", that grants all users access to the host "server" from
 anywhere:
   ipa hbacrule-add --usercat=all test1
   ipa hbacrule-add-host --hosts=server.example.com test1

 Display the properties of a named HBAC rule:
   ipa hbacrule-show test1

 Create a rule for a specific service. This lets the user john access
 the sshd service on any machine from any machine:
   ipa hbacrule-add --hostcat=all john_sshd
   ipa hbacrule-add-user --users=john john_sshd
   ipa hbacrule-add-service --hbacsvcs=sshd john_sshd

 Create a rule for a new service group. This lets the user john access
 the FTP service on any machine from any machine:
   ipa hbacsvcgroup-add ftpers
   ipa hbacsvc-add sftp
   ipa hbacsvcgroup-add-member --hbacsvcs=ftp --hbacsvcs=sftp ftpers
   ipa hbacrule-add --hostcat=all john_ftp
   ipa hbacrule-add-user --users=john john_ftp
   ipa hbacrule-add-service --hbacsvcgroups=ftpers john_ftp

 Disable a named HBAC rule:
   ipa hbacrule-disable test1

 Remove a named HBAC rule:
   ipa hbacrule-del allow_server
""")

register = Registry()

topic = 'hbac'

def validate_type(ugettext, type):
    if type.lower() == 'deny':
        raise errors.ValidationError(name='type', error=_('The deny type has been deprecated.'))

def is_all(options, attribute):
    """
    See if options[attribute] is lower-case 'all' in a safe way.
    """
    if attribute in options and options[attribute] is not None:
        if type(options[attribute]) in (list, tuple):
            value = options[attribute][0].lower()
        else:
            value = options[attribute].lower()
        if value == 'all':
            return True
    else:
        return False


def replace_attr_value(attr_vals, replace, replacement):
    lower_replace = replace.lower()
    ret = [val for val in attr_vals if val.lower() != lower_replace]
    ret.append(replacement)
    return ret


@register()
class hbacrule(LDAPObject):
    """
    HBAC object.
    """
    container_dn = api.env.container_hbac
    object_name = _('HBAC rule')
    object_name_plural = _('HBAC rules')
    object_class = ['ipaassociation']
    possible_objectclasses = ['ipahbacrule', 'ipahbacrulev2']
    permission_filter_objectclasses = ['ipahbacrule', 'ipahbacrulev2']
    default_attributes = [
        'cn', 'ipaenabledflag',
        'description', 'usercategory', 'hostcategory',
        'servicecategory', 'ipaenabledflag',
        'memberuser', 'sourcehost', 'memberhost', 'memberservice',
        'externalhost', 'ipamembertimerule'
    ]
    uuid_attribute = 'ipauniqueid'
    rdn_attribute = 'ipauniqueid'
    attribute_members = {
        'memberuser': ['user', 'group'],
        'memberhost': ['host', 'hostgroup'],
        'sourcehost': ['host', 'hostgroup'],
        'memberservice': ['hbacsvc', 'hbacsvcgroup'],
        'ipamembertimerule': ['timerule'],
    }
    managed_permissions = {
        'System: Read HBAC Rules': {
            'replaces_global_anonymous_aci': True,
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {
                'accessruletype', 'accesstime', 'cn', 'description',
                'externalhost', 'hostcategory', 'ipaenabledflag',
                'ipauniqueid', 'memberhost', 'memberservice', 'memberuser',
                'servicecategory', 'sourcehost', 'sourcehostcategory',
                'usercategory', 'objectclass', 'member', 'ipamembertimerule',
            },
        },
        'System: Add HBAC Rule': {
            'ipapermright': {'add'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Add HBAC rule";allow (add) groupdn = "ldap:///cn=Add HBAC rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Delete HBAC Rule': {
            'ipapermright': {'delete'},
            'replaces': [
                '(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Delete HBAC rule";allow (delete) groupdn = "ldap:///cn=Delete HBAC rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Manage HBAC Rule Membership': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'externalhost', 'memberhost', 'memberservice', 'memberuser',
                'ipamembertimerule'
            },
            'replaces': [
                '(targetattr = "memberuser || externalhost || memberservice || memberhost")(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Manage HBAC rule membership";allow (write) groupdn = "ldap:///cn=Manage HBAC rule membership,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
        'System: Modify HBAC Rule': {
            'ipapermright': {'write'},
            'ipapermdefaultattr': {
                'accessruletype', 'accesstime', 'cn', 'description',
                'hostcategory', 'ipaenabledflag', 'servicecategory',
                'sourcehost', 'sourcehostcategory', 'usercategory',
                'ipamembertimerule'
            },
            'replaces': [
                '(targetattr = "servicecategory || sourcehostcategory || cn || description || ipaenabledflag || accesstime || usercategory || hostcategory || accessruletype || sourcehost")(target = "ldap:///ipauniqueid=*,cn=hbac,$SUFFIX")(version 3.0;acl "permission:Modify HBAC rule";allow (write) groupdn = "ldap:///cn=Modify HBAC rule,cn=permissions,cn=pbac,$SUFFIX";)',
            ],
            'default_privileges': {'HBAC Administrator'},
        },
    }

    label = _('HBAC Rules')
    label_singular = _('HBAC Rule')

    takes_params = (
        Str('cn',
            cli_name='name',
            label=_('Rule name'),
            primary_key=True,
        ),
        StrEnum('accessruletype?', validate_type,
            cli_name='type',
            doc=_('Rule type (allow)'),
            label=_('Rule type'),
            values=(u'allow', u'deny'),
            default=u'allow',
            autofill=True,
            exclude=('webui', 'cli'),
            flags=['no_option', 'no_output'],
        ),
        # FIXME: {user,host,service}categories should expand in the future
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
        StrEnum('sourcehostcategory?',
            deprecated=True,
            cli_name='srchostcat',
            label=_('Source host category'),
            doc=_('Source host category the rule applies to'),
            values=(u'all', ),
            flags={'no_option'},
        ),
        StrEnum('servicecategory?',
            cli_name='servicecat',
            label=_('Service category'),
            doc=_('Service category the rule applies to'),
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
        Str('ipamembertimerule_timerule?',
            label=_('Time Rules'),
            flags=['no_create', 'no_update', 'no_search']
        ),
        Str('sourcehost_host?',
            deprecated=True,
            label=_('Source Hosts'),
            flags=['no_create', 'no_update', 'no_search', 'no_option'],
        ),
        Str('sourcehost_hostgroup?',
            deprecated=True,
            label=_('Source Host Groups'),
            flags=['no_create', 'no_update', 'no_search', 'no_option'],
        ),
        Str('memberservice_hbacsvc?',
            label=_('Services'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('memberservice_hbacsvcgroup?',
            label=_('Service Groups'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        external_host_param,
    )



@register()
class hbacrule_add(LDAPCreate):
    __doc__ = _('Create a new HBAC rule.')

    msg_summary = _('Added HBAC rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        # HBAC rules are enabled by default
        entry_attrs['ipaenabledflag'] = 'TRUE'
        # start as an old type HBAC
        entry_attrs['objectclass'].append('ipahbacrule')
        return dn



@register()
class hbacrule_del(LDAPDelete):
    __doc__ = _('Delete an HBAC rule.')

    msg_summary = _('Deleted HBAC rule "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        kw = dict(seealso=keys[0])
        _entries = api.Command.selinuxusermap_find(None, **kw)
        if _entries['count']:
            raise errors.DependentEntry(key=keys[0], label=self.api.Object['selinuxusermap'].label_singular, dependent=_entries['result'][0]['cn'][0])

        return dn



@register()
class hbacrule_mod(LDAPUpdate):
    __doc__ = _('Modify an HBAC rule.')

    msg_summary = _('Modified HBAC rule "%(value)s"')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, attrs_list)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)

        if is_all(options, 'usercategory') and 'memberuser' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("user category cannot be set to 'all' while there are allowed users"))
        if is_all(options, 'hostcategory') and 'memberhost' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("host category cannot be set to 'all' while there are allowed hosts"))
        if is_all(options, 'servicecategory') and 'memberservice' in entry_attrs:
            raise errors.MutuallyExclusiveError(reason=_("service category cannot be set to 'all' while there are allowed services"))
        return dn


@register()
class hbacrule_find(LDAPSearch):
    __doc__ = _('Search for HBAC rules.')

    msg_summary = ngettext(
        '%(count)d HBAC rule matched', '%(count)d HBAC rules matched', 0
    )

    def pre_callback(self, ldap, filter, attrs_list, base_dn,
                     scope, *args, **options):
        assert isinstance(base_dn, DN)
        filters = [
            ldap.make_filter({'objectclass': ['ipahbacrule', 'ipahbacrulev2']},
                             rules=ldap.MATCH_ANY)
        ]
        filters.append(filter)
        filter = ldap.combine_filters(filters, rules=ldap.MATCH_ALL)
        return (filter, base_dn, scope)


@register()
class hbacrule_show(LDAPRetrieve):
    __doc__ = _('Display the properties of an HBAC rule.')



@register()
class hbacrule_enable(LDAPQuery):
    __doc__ = _('Enable an HBAC rule.')

    msg_summary = _('Enabled HBAC rule "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['TRUE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )



@register()
class hbacrule_disable(LDAPQuery):
    __doc__ = _('Disable an HBAC rule.')

    msg_summary = _('Disabled HBAC rule "%(value)s"')
    has_output = output.standard_value

    def execute(self, cn, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(cn)
        try:
            entry_attrs = ldap.get_entry(dn, ['ipaenabledflag'])
        except errors.NotFound:
            self.obj.handle_not_found(cn)

        entry_attrs['ipaenabledflag'] = ['FALSE']

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return dict(
            result=True,
            value=pkey_to_value(cn, options),
        )


@register()
class hbacrule_add_timerule(LDAPAddMember):
    __doc__ = _('Add time rules to an HBAC rule.')

    member_attributes = ['ipamembertimerule']
    member_count_out = ('%i object added.', '%i objects added.')

    def execute(self, *args, **options):
        ldap = self.obj.backend
        dn = self.obj.get_dn(*args, **options)
        assert(isinstance(dn, DN))

        try:
            entry_attrs = ldap.get_entry(dn, ['objectclass', 'accessruletype'])
        except errors.NotFound:
            self.obj.handle_not_found(*args)
        objclass_updated = False
        # ipaHBACRuleV2 objectclass marks new version HBAC rules with new
        # capabilities such as time policies
        if ('ipahbacrulev2' not in
                (o.lower() for o in entry_attrs['objectclass'])):
            entry_attrs['objectclass'] = replace_attr_value(
                                            entry_attrs['objectclass'],
                                            'ipahbacrule',
                                            'ipahbacrulev2')
            type_backup = entry_attrs['accessruletype']
            entry_attrs['accessruletype'] = []
            ldap.update_entry(entry_attrs)
            objclass_updated = True

        try:
            result = super(hbacrule_add_timerule, self).execute(*args,
                                                                **options)
        except Exception as e:
            self.log.error("Failed to add a timerule: {err}".format(err=e))
            if objclass_updated:
                # there was an error adding time rule to an HBAC rule which was
                # of old version before, switch it back to ipaHBACRule class
                entry_attrs['objectclass'] = replace_attr_value(
                                                entry_attrs['objectclass'],
                                                'ipahbacrulev2',
                                                'ipahbacrule')
                entry_attrs['accessruletype'] = type_backup
                ldap.update_entry(entry_attrs)
            raise
        return result


@register()
class hbacrule_remove_timerule(LDAPRemoveMember):
    __doc__ = _('Remove users and groups from an HBAC rule.')

    member_attributes = ['ipamembertimerule']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def execute(self, *args, **options):
        result = super(hbacrule_remove_timerule, self).execute(*args,
                                                               **options)
        dn = result['result']['dn']
        assert(isinstance(dn, DN))
        timerules = result['result'].get('membertimerule_timerule', [])

        ldap = self.obj.backend
        entry_attrs = ldap.get_entry(dn, ['objectclass'])
        if (not timerules and 'ipahbacrulev2' in
           (o.lower() for o in entry_attrs['objectclass'])):
            # there are no more time rules left in the HBAC rule, switch
            # to old type rules
            entry_attrs['objectclass'] = replace_attr_value(
                                            entry_attrs['objectclass'],
                                            'ipahbacrulev2',
                                            'ipahbacrule')
            # accessRuleType is MUST attribute in ipaHBACRule
            entry_attrs['accessruletype'] = 'allow'
            ldap.update_entry(entry_attrs)
        return result


@register()
class hbacrule_add_user(LDAPAddMember):
    __doc__ = _('Add users and groups to an HBAC rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if 'usercategory' in entry_attrs and \
            entry_attrs['usercategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(
                reason=_("users cannot be added when user category='all'"))
        return dn



@register()
class hbacrule_remove_user(LDAPRemoveMember):
    __doc__ = _('Remove users and groups from an HBAC rule.')

    member_attributes = ['memberuser']
    member_count_out = ('%i object removed.', '%i objects removed.')



@register()
class hbacrule_add_host(LDAPAddMember):
    __doc__ = _('Add target hosts and hostgroups to an HBAC rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if 'hostcategory' in entry_attrs and \
            entry_attrs['hostcategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(
                reason=_("hosts cannot be added when host category='all'"))
        return dn



@register()
class hbacrule_remove_host(LDAPRemoveMember):
    __doc__ = _('Remove target hosts and hostgroups from an HBAC rule.')

    member_attributes = ['memberhost']
    member_count_out = ('%i object removed.', '%i objects removed.')



@register()
class hbacrule_add_sourcehost(LDAPAddMember):
    NO_CLI = True

    member_attributes = ['sourcehost']
    member_count_out = ('%i object added.', '%i objects added.')

    def validate(self, **kw):
        raise errors.DeprecationError(name='hbacrule_add_sourcehost')



@register()
class hbacrule_remove_sourcehost(LDAPRemoveMember):
    NO_CLI = True

    member_attributes = ['sourcehost']
    member_count_out = ('%i object removed.', '%i objects removed.')

    def validate(self, **kw):
        raise errors.DeprecationError(name='hbacrule_remove_sourcehost')



@register()
class hbacrule_add_service(LDAPAddMember):
    __doc__ = _('Add services to an HBAC rule.')

    member_attributes = ['memberservice']
    member_count_out = ('%i object added.', '%i objects added.')

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        try:
            entry_attrs = ldap.get_entry(dn, self.obj.default_attributes)
            dn = entry_attrs.dn
        except errors.NotFound:
            self.obj.handle_not_found(*keys)
        if 'servicecategory' in entry_attrs and \
            entry_attrs['servicecategory'][0].lower() == 'all':
            raise errors.MutuallyExclusiveError(reason=_(
                "services cannot be added when service category='all'"))
        return dn



@register()
class hbacrule_remove_service(LDAPRemoveMember):
    __doc__ = _('Remove service and service groups from an HBAC rule.')

    member_attributes = ['memberservice']
    member_count_out = ('%i object removed.', '%i objects removed.')
