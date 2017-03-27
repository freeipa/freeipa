#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import six

from ipalib import api
from ipalib import Str
from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPAddMember,
    LDAPRemoveMember,
    LDAPCreate,
    LDAPDelete,
    LDAPSearch,
    LDAPRetrieve)
from .service import normalize_principal
from ipalib import _, ngettext
from ipalib import errors
from ipapython.dn import DN

if six.PY3:
    unicode = str

__doc__ = _("""
Service Constrained Delegation

Manage rules to allow constrained delegation of credentials so
that a service can impersonate a user when communicating with another
service without requiring the user to actually forward their TGT.
This makes for a much better method of delegating credentials as it
prevents exposure of the short term secret of the user.

The naming convention is to append the word "target" or "targets" to
a matching rule name. This is not mandatory but helps conceptually
to associate rules and targets.

A rule consists of two things:
  - A list of targets the rule applies to
  - A list of memberPrincipals that are allowed to delegate for
    those targets

A target consists of a list of principals that can be delegated.

In English, a rule says that this principal can delegate as this
list of principals, as defined by these targets.

EXAMPLES:

 Add a new constrained delegation rule:
   ipa servicedelegationrule-add ftp-delegation

 Add a new constrained delegation target:
   ipa servicedelegationtarget-add ftp-delegation-target

 Add a principal to the rule:
   ipa servicedelegationrule-add-member --principals=ftp/ipa.example.com \
      ftp-delegation

 Add our target to the rule:
   ipa servicedelegationrule-add-target \
      --servicedelegationtargets=ftp-delegation-target ftp-delegation

 Add a principal to the target:
   ipa servicedelegationtarget-add-member --principals=ldap/ipa.example.com \
      ftp-delegation-target

 Display information about a named delegation rule and target:
   ipa servicedelegationrule_show ftp-delegation
   ipa servicedelegationtarget_show ftp-delegation-target

 Remove a constrained delegation:
   ipa servicedelegationrule-del ftp-delegation-target
   ipa servicedelegationtarget-del ftp-delegation

In this example the ftp service can get a TGT for the ldap service on
the bound user's behalf.

It is strongly discouraged to modify the delegations that ship with
IPA, ipa-http-delegation and its targets ipa-cifs-delegation-targets and
ipa-ldap-delegation-targets. Incorrect changes can remove the ability
to delegate, causing the framework to stop functioning.
""")

register = Registry()

PROTECTED_CONSTRAINT_RULES = (
    u'ipa-http-delegation',
)

PROTECTED_CONSTRAINT_TARGETS = (
    u'ipa-cifs-delegation-targets',
    u'ipa-ldap-delegation-targets',

)


class servicedelegation(LDAPObject):
    """
    Service Constrained Delegation base object.

    This jams a couple of concepts into a single plugin because the
    data is all stored in one place. There is a "rule" which has the
    objectclass ipakrb5delegationacl. This is the entry that controls
    the delegation. Other entries that lack this objectclass are
    targets and define what services can be impersonated.
    """
    container_dn = api.env.container_s4u2proxy
    object_class = ['groupofprincipals', 'top']

    managed_permissions = {
        'System: Read Service Delegations': {
            'ipapermbindruletype': 'permission',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermtargetfilter': {'(objectclass=groupofprincipals)'},
            'ipapermdefaultattr': {
                'cn', 'objectclass', 'memberprincipal',
                'ipaallowedtarget',
            },
            'default_privileges': {'Service Administrators'},
        },
        'System: Add Service Delegations': {
            'ipapermright': {'add'},
            'ipapermtargetfilter': {'(objectclass=groupofprincipals)'},
            'default_privileges': {'Service Administrators'},
        },
        'System: Remove Service Delegations': {
            'ipapermright': {'delete'},
            'ipapermtargetfilter': {'(objectclass=groupofprincipals)'},
            'default_privileges': {'Service Administrators'},
        },
        'System: Modify Service Delegation Membership': {
            'ipapermright': {'write'},
            'ipapermtargetfilter': {'(objectclass=groupofprincipals)'},
            'ipapermdefaultattr': {'memberprincipal', 'ipaallowedtarget'},
            'default_privileges': {'Service Administrators'},
        },
    }

    allow_rename = True

    takes_params = (
        Str(
            'cn',
            pattern='^[a-zA-Z0-9_.][a-zA-Z0-9_ .-]*[a-zA-Z0-9_.-]?$',
            pattern_errmsg='may only include letters, numbers, _, -, ., '
                           'and a space inside',
            maxlength=255,
            cli_name='delegation_name',
            label=_('Delegation name'),
            primary_key=True,
        ),
        Str(
            'ipaallowedtarget_servicedelegationtarget',
            label=_('Allowed Target'),
            flags={'virtual_attribute', 'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'ipaallowedtoimpersonate',
            label=_('Allowed to Impersonate'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'memberprincipal',
            label=_('Member principals'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
    )


class servicedelegation_add_member(LDAPAddMember):
    __doc__ = _('Add target to a named service delegation.')
    member_attrs = ['memberprincipal']
    member_attributes = []
    member_names = {}
    principal_attr = 'memberprincipal'
    principal_failedattr = 'failed_memberprincipal'

    def get_options(self):
        for option in super(servicedelegation_add_member, self).get_options():
            yield option
        for attr in self.member_attrs:
            name = self.member_names[attr]
            doc = self.member_param_doc % name
            yield Str('%s*' % name, cli_name='%ss' % name, doc=doc,
                      label=_('member %s') % name, alwaysask=True)

    def get_member_dns(self, **options):
        """
        There are no member_dns to return. memberPrincipal needs
        special handling since it is just a principal, not a
        full dn.
        """
        return dict(), dict()

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        """
        Add memberPrincipal values. This is done afterward because it isn't
        a DN and the LDAPAddMember method explicitly only handles DNs.

        A separate fake attribute name is used for failed members. This is
        a reverse of the way this is typically handled in the *Member
        routines, where a successful addition will be represented as
        member/memberof_<attribute>. In this case, because memberPrincipal
        isn't a DN, I'm doing the reverse, and creating a fake failed
        attribute instead.
        """
        ldap = self.obj.backend
        members = []
        failed[self.principal_failedattr] = {}
        failed[self.principal_failedattr][self.principal_attr] = []
        names = options.get(self.member_names[self.principal_attr], [])
        ldap_obj = self.api.Object['service']
        if names:
            for name in names:
                if not name:
                    continue
                name = normalize_principal(name)
                obj_dn = ldap_obj.get_dn(name)
                try:
                    ldap.get_entry(obj_dn, ['krbprincipalname'])
                except errors.NotFound as e:
                    failed[self.principal_failedattr][
                        self.principal_attr].append((name, unicode(e)))
                    continue
                try:
                    if name not in entry_attrs.get(self.principal_attr, []):
                        members.append(name)
                    else:
                        raise errors.AlreadyGroupMember()
                except errors.PublicError as e:
                    failed[self.principal_failedattr][
                        self.principal_attr].append((name, unicode(e)))
                else:
                    completed += 1

        if members:
            value = entry_attrs.setdefault(self.principal_attr, [])
            value.extend(members)

            try:
                ldap.update_entry(entry_attrs)
            except errors.EmptyModlist:
                pass

        return completed, dn


class servicedelegation_remove_member(LDAPRemoveMember):
    __doc__ = _('Remove member from a named service delegation.')

    member_attrs = ['memberprincipal']
    member_attributes = []
    member_names = {}
    principal_attr = 'memberprincipal'
    principal_failedattr = 'failed_memberprincipal'

    def get_options(self):
        for option in super(
                servicedelegation_remove_member, self).get_options():
            yield option
        for attr in self.member_attrs:
            name = self.member_names[attr]
            doc = self.member_param_doc % name
            yield Str('%s*' % name, cli_name='%ss' % name, doc=doc,
                      label=_('member %s') % name, alwaysask=True)

    def get_member_dns(self, **options):
        """
        Need to ignore memberPrincipal for now and handle the difference
        in objectclass between a rule and a target.
        """
        dns = {}
        failed = {}
        for attr in self.member_attrs:
            dns[attr] = {}
            if attr.lower() == 'memberprincipal':
                # This will be handled later. memberprincipal isn't a
                # DN so will blow up in assertions in baseldap.
                continue
            failed[attr] = {}
            for ldap_obj_name in self.obj.attribute_members[attr]:
                dns[attr][ldap_obj_name] = []
                failed[attr][ldap_obj_name] = []
                names = options.get(self.member_names[attr], [])
                if not names:
                    continue
                for name in names:
                    if not name:
                        continue
                    ldap_obj = self.api.Object[ldap_obj_name]
                    try:
                        dns[attr][ldap_obj_name].append(ldap_obj.get_dn(name))
                    except errors.PublicError as e:
                        failed[attr][ldap_obj_name].append((name, unicode(e)))
        return dns, failed

    def post_callback(self, ldap, completed, failed, dn, entry_attrs,
                      *keys, **options):
        """
        Remove memberPrincipal values. This is done afterward because it
        isn't a DN and the LDAPAddMember method explicitly only handles DNs.

        See servicedelegation_add_member() for an explanation of what
        failedattr is.
        """
        ldap = self.obj.backend
        failed[self.principal_failedattr] = {}
        failed[self.principal_failedattr][self.principal_attr] = []
        names = options.get(self.member_names[self.principal_attr], [])
        if names:
            for name in names:
                if not name:
                    continue
                name = normalize_principal(name)
                try:
                    if name in entry_attrs.get(self.principal_attr, []):
                        entry_attrs[self.principal_attr].remove(name)
                    else:
                        raise errors.NotGroupMember()
                except errors.PublicError as e:
                    failed[self.principal_failedattr][
                        self.principal_attr].append((name, unicode(e)))
                else:
                    completed += 1

        try:
            ldap.update_entry(entry_attrs)
        except errors.EmptyModlist:
            pass

        return completed, dn


@register()
class servicedelegationrule(servicedelegation):
    """
    A service delegation rule. This is the ACL that controls
    what can be delegated to whom.
    """
    object_name = _('service delegation rule')
    object_name_plural = _('service delegation rules')
    object_class = ['ipakrb5delegationacl', 'groupofprincipals', 'top']
    default_attributes = [
        'cn', 'memberprincipal', 'ipaallowedtarget',
        'ipaallowedtoimpersonate',
    ]
    attribute_members = {
        # memberprincipal is not listed because it isn't a DN
        'ipaallowedtarget': ['servicedelegationtarget'],
    }

    label = _('Service delegation rules')
    label_singular = _('Service delegation rule')


@register()
class servicedelegationrule_add(LDAPCreate):
    __doc__ = _('Create a new service delegation rule.')

    msg_summary = _('Added service delegation rule "%(value)s"')


@register()
class servicedelegationrule_del(LDAPDelete):
    __doc__ = _('Delete service delegation.')

    msg_summary = _('Deleted service delegation "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        if keys[0] in PROTECTED_CONSTRAINT_RULES:
            raise errors.ProtectedEntryError(
                label=_(u'service delegation rule'),
                key=keys[0],
                reason=_(u'privileged service delegation rule')
            )
        return dn


@register()
class servicedelegationrule_find(LDAPSearch):
    __doc__ = _('Search for service delegations rule.')

    msg_summary = ngettext(
        '%(count)d service delegation rule matched',
        '%(count)d service delegation rules matched', 0
    )


@register()
class servicedelegationrule_show(LDAPRetrieve):
    __doc__ = _('Display information about a named service delegation rule.')


@register()
class servicedelegationrule_add_member(servicedelegation_add_member):
    __doc__ = _('Add member to a named service delegation rule.')

    member_names = {
        'memberprincipal': 'principal',
    }


@register()
class servicedelegationrule_remove_member(servicedelegation_remove_member):
    __doc__ = _('Remove member from a named service delegation rule.')
    member_names = {
        'memberprincipal': 'principal',
    }


@register()
class servicedelegationrule_add_target(LDAPAddMember):
    __doc__ = _('Add target to a named service delegation rule.')

    member_attributes = ['ipaallowedtarget']
    attribute_members = {
        'ipaallowedtarget': ['servicedelegationtarget'],
    }


@register()
class servicedelegationrule_remove_target(LDAPRemoveMember):
    __doc__ = _('Remove target from a named service delegation rule.')
    member_attributes = ['ipaallowedtarget']
    attribute_members = {
        'ipaallowedtarget': ['servicedelegationtarget'],
    }


@register()
class servicedelegationtarget(servicedelegation):
    object_name = _('service delegation target')
    object_name_plural = _('service delegation targets')
    object_class = ['groupofprincipals', 'top']
    default_attributes = [
        'cn', 'memberprincipal',
    ]
    attribute_members = {}

    label = _('Service delegation targets')
    label_singular = _('Service delegation target')


@register()
class servicedelegationtarget_add(LDAPCreate):
    __doc__ = _('Create a new service delegation target.')

    msg_summary = _('Added service delegation target "%(value)s"')


@register()
class servicedelegationtarget_del(LDAPDelete):
    __doc__ = _('Delete service delegation target.')

    msg_summary = _('Deleted service delegation target "%(value)s"')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        if keys[0] in PROTECTED_CONSTRAINT_TARGETS:
            raise errors.ProtectedEntryError(
                label=_(u'service delegation target'),
                key=keys[0],
                reason=_(u'privileged service delegation target')
            )
        return dn


@register()
class servicedelegationtarget_find(LDAPSearch):
    __doc__ = _('Search for service delegation target.')

    msg_summary = ngettext(
        '%(count)d service delegation target matched',
        '%(count)d service delegation targets matched', 0
    )

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope,
                     term=None, **options):
        """
        Exclude rules from the search output. A target contains a subset
        of a rule objectclass.
        """
        search_kw = self.args_options_2_entry(**options)
        search_kw['objectclass'] = self.obj.object_class
        attr_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        rule_kw = {'objectclass': 'ipakrb5delegationacl'}
        target_filter = ldap.make_filter(rule_kw, rules=ldap.MATCH_NONE)
        attr_filter = ldap.combine_filters(
            (target_filter, attr_filter), rules=ldap.MATCH_ALL
        )

        search_kw = {}
        for a in self.obj.default_attributes:
            search_kw[a] = term

        term_filter = ldap.make_filter(search_kw, exact=False)

        sfilter = ldap.combine_filters(
            (term_filter, attr_filter), rules=ldap.MATCH_ALL
        )
        return sfilter, base_dn, ldap.SCOPE_ONELEVEL


@register()
class servicedelegationtarget_show(LDAPRetrieve):
    __doc__ = _('Display information about a named service delegation target.')


@register()
class servicedelegationtarget_add_member(servicedelegation_add_member):
    __doc__ = _('Add member to a named service delegation target.')

    member_names = {
        'memberprincipal': 'principal',
    }


@register()
class servicedelegationtarget_remove_member(servicedelegation_remove_member):
    __doc__ = _('Remove member from a named service delegation target.')
    member_names = {
        'memberprincipal': 'principal',
    }
