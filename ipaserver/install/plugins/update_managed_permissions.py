# Authors:
#   Petr Viktorin <pviktori@redhat.com>
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

"""
Plugin for updating managed permissions.

The permissions are declared in Object plugins in the "managed_permissions"
attribute, which is a dictionary mapping permission names to a "template"
for the updater.
For example, an entry could look like this:

    managed_permissions = {
        'System: Read Object A': {
            'ipapermbindruletype': 'all',
            'ipapermright': {'read', 'search', 'compare'},
            'ipapermdefaultattr': {'cn', 'description'},
            'replaces_global_anonymous_aci': True,
        },
    }

For permissions not tied to an object plugin, a NONOBJECT_PERMISSIONS
dict of the same format is defined in this module.

The permission name must start with the "System:" prefix.

The template dictionary can have the following keys:
* ipapermtarget, ipapermtargetfilter, ipapermlocation, ipapermright, ,ipapermtargetto, ipapermtargetfrom, objectclass
  - Directly used as attributes on the permission.
  - Replaced when upgrading an existing permission
  - If not specified, these default to the defaults of a permission of the
    corresponding --type, or, if non_object is specified, or if not on an
    object, to general permission defaults .
  - ipapermlocation, ipatargetto, ipapermtargetfrom, ipapermtarget must be DNs
  - ipapermtargetfilter and objectclass must be iterables of strings
* ipapermbindruletype
  - Directly used as attribute on the permission.
  - Not replaced when upgrading an existing permission.
* ipapermdefaultattr
  - Used as attribute of the permission.
  - When upgrading, only new values are added; all old values are kept.
* default_privileges
  - Names of privileges to add the permission to
  - Only applied on newly created permissions
* replaces_global_anonymous_aci
  - If true, any attributes specified (denied) in the legacy global anonymous
    read ACI will be added to excluded_attributes of the new permission.
  - Has no effect when existing permissions are updated.
* non_object
  - If true, no object-specific defaults are used (e.g. for
    ipapermtargetfilter, ipapermlocation).
* replaces
  - A list of ACIs corresponding to legacy default permissions replaced
    by this permission.
* replaces_system
  - A list of names of old SYSTEM permissions this replaces.
* fixup_function
  - A callable that may modify the template in-place before it is applied.
  - Called with the permission name, template dict, and keyword arguments:
    - is_new: true if the permission was previously existing
    - anonymous_read_aci: the legacy 'Enable Anonymous access' ACI as
      an ipalib.aci.ACI object, or None if it does not exist
    Extra keyword arguments must be ignored, since this list may grow
    in the future.

No other keys are allowed in the template

The plugin also deletes permissions specified in OBSOLETE_PERMISSIONS.
"""

import logging

import six

from ipalib import api, errors
from ipapython.dn import DN
from ipalib.plugable import Registry
from ipalib.aci import ACI
from ipalib import Updater
from ipapython import ipautil
from ipaserver.plugins import aci
from ipaserver.plugins.permission import permission, permission_del

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

register = Registry()

OBSOLETE_PERMISSIONS = {
    # These permissions will be removed on upgrade, if they exist.
    # Any modifications the user might have made to them are not taken
    # into account. This should be used sparingly.
    'System: Read Timestamp and USN Operational Attributes',
    'System: Read Creator and Modifier Operational Attributes',
}

NONOBJECT_PERMISSIONS = {
    'System: Read IPA Masters': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation': DN('cn=masters,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=nscontainer)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'ipaconfigstring',
        },
        'default_privileges': {'IPA Masters Readers'},
    },
    'System: Compat Tree ID View targets': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation':  api.env.basedn,
        'ipapermtarget': DN('cn=*,cn=compat', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipaOverrideTarget)'},
        'ipapermbindruletype': 'anonymous',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'ipaAnchorUUID',
        },
    },
    'System: Read DNA Configuration': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation': DN('cn=dna,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=dnasharedconfig)'},
        'ipapermbindruletype': 'all',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'dnaHostname', 'dnaPortNum',
            'dnaSecurePortNum', 'dnaRemoteBindMethod', 'dnaRemoteConnProtocol',
            'dnaRemainingValues',
        },
    },
    'System: Read CA Renewal Information': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation': DN('cn=ca_renewal,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=pkiuser)'},
        'ipapermbindruletype': 'all',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'usercertificate',
        },
    },
    'System: Add CA Certificate For Renewal': {
        'ipapermlocation': DN('cn=ca_renewal,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtarget': DN(
            'cn=caSigningCert cert-pki-ca,cn=ca_renewal,cn=ipa,cn=etc',
            api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=pkiuser)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'add'},
        'default_privileges': {'Certificate Administrators'},
    },
    'System: Modify CA Certificate For Renewal': {
        'ipapermlocation': DN('cn=ca_renewal,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtarget': DN(
            'cn=caSigningCert cert-pki-ca,cn=ca_renewal,cn=ipa,cn=etc',
            api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=pkiuser)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'write'},
        'ipapermdefaultattr': {
            'usercertificate',
        },
        'default_privileges': {'Certificate Administrators'},
    },
    'System: Read CA Certificate': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation': DN('cn=CAcert,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=pkica)'},
        'ipapermbindruletype': 'anonymous',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'cacertificate', 'certificaterevocationlist',
            'authorityrevocationlist', 'crosscertificatepair',
        },
    },
    'System: Modify CA Certificate': {
        'ipapermlocation': DN('cn=CAcert,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=pkica)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'write'},
        'ipapermdefaultattr': {
            'cacertificate',
        },
        'default_privileges': {'Certificate Administrators'},
    },
    'System: Read Certificate Store Entries': {
        'ipapermlocation': DN('cn=certificates,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipacertificate)'},
        'ipapermbindruletype': 'anonymous',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'ipacertsubject', 'ipacertissuerserial',
            'ipapublickey', 'ipaconfigstring', 'cacertificate', 'ipakeytrust',
            'ipakeyusage', 'ipakeyextusage',
        },
    },
    'System: Add Certificate Store Entry': {
        'ipapermlocation': DN('cn=certificates,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipacertificate)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'add'},
        'default_privileges': {'Certificate Administrators'},
    },
    'System: Modify Certificate Store Entry': {
        'ipapermlocation': DN('cn=certificates,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipacertificate)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'write'},
        'ipapermdefaultattr': {
            'ipacertissuerserial', 'ipaconfigstring', 'cacertificate',
            'ipakeytrust', 'ipakeyusage', 'ipakeyextusage',
        },
        'default_privileges': {'Certificate Administrators'},
    },
    'System: Remove Certificate Store Entry': {
        'ipapermlocation': DN('cn=certificates,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipacertificate)'},
        'ipapermbindruletype': 'permission',
        'ipapermright': {'delete'},
        'default_privileges': {'Certificate Administrators'},
    },
    'System: Read Replication Information': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation': DN('cn=replication,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=nsds5replica)'},
        'ipapermbindruletype': 'all',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'nsds5replicaroot', 'nsds5replicaid',
            'nsds5replicacleanruv', 'nsds5replicaabortcleanruv',
            'nsds5replicatype', 'nsds5replicabinddn', 'nsstate',
            'nsds5replicaname', 'nsds5flags', 'nsds5task',
            'nsds5replicareferral', 'nsds5replicaautoreferral',
            'nsds5replicapurgedelay', 'nsds5replicatombstonepurgeinterval',
            'nsds5replicachangecount', 'nsds5replicalegacyconsumer',
            'nsds5replicaprotocoltimeout', 'nsds5replicabackoffmin',
            'nsds5replicabackoffmax',
        },
    },
    'System: Read AD Domains': {
        'replaces_global_anonymous_aci': True,
        'ipapermlocation': DN('cn=etc', api.env.basedn),
        'ipapermtarget': DN('cn=ad,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipantdomainattrs)'},
        'ipapermbindruletype': 'all',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass', 'ipantsecurityidentifier', 'ipantflatname',
            'ipantdomainguid', 'ipantfallbackprimarygroup',
        },
    },
    'System: Read DUA Profile': {
        'ipapermlocation': DN('ou=profile', api.env.basedn),
        'ipapermtargetfilter': {
            '(|'
                '(objectclass=organizationalUnit)'
                '(objectclass=DUAConfigProfile)'
            ')'
        },
        'ipapermbindruletype': 'anonymous',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'objectclass', 'ou', 'cn', 'defaultServerList',
            'preferredServerList', 'defaultSearchBase', 'defaultSearchScope',
            'searchTimeLimit', 'bindTimeLimit', 'credentialLevel',
            'authenticationMethod', 'followReferrals', 'dereferenceAliases',
            'serviceSearchDescriptor', 'serviceCredentialLevel',
            'serviceAuthenticationMethod', 'objectclassMap', 'attributeMap',
            'profileTTL'
        },
    },
    'System: Read Domain Level': {
        'ipapermlocation': DN('cn=Domain Level,cn=ipa,cn=etc', api.env.basedn),
        'ipapermtargetfilter': {'(objectclass=ipadomainlevelconfig)'},
        'ipapermbindruletype': 'all',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'ipadomainlevel', 'objectclass',
        },
    },
}


class IncompatibleACIModification(Exception):
    """User has made a legacy default perm modification we can't handle"""


@register()
class update_managed_permissions(Updater):
    """Update managed permissions after an update.

    Update managed permissions according to templates specified in plugins.
    For read permissions, puts any attributes specified in the legacy
    Anonymous access ACI in the exclude list when creating the permission.
    """

    def get_anonymous_read_aci(self, ldap):
        aciname = u'Enable Anonymous access'
        aciprefix = u'none'

        base_entry = ldap.get_entry(self.api.env.basedn, ['aci'])

        acistrs = base_entry.get('aci', [])
        acilist = aci._convert_strings_to_acis(acistrs)
        try:
            return aci._find_aci_by_name(acilist, aciprefix, aciname)
        except errors.NotFound:
            return None

    def remove_anonymous_read_aci(self, ldap, anonymous_read_aci):
        base_entry = ldap.get_entry(self.api.env.basedn, ['aci'])

        acistrs = base_entry.get('aci', [])

        for acistr in acistrs:
            if ACI(acistr).isequal(anonymous_read_aci):
                logger.debug('Removing anonymous ACI: %s', acistr)
                acistrs.remove(acistr)
                break
        else:
            return

        ldap.update_entry(base_entry)

    def get_templates(self):
        """Return (name, template, obj) triples for all managed permissions

        If the permission is not defined in an object plugin, obj is None.
        Entries with the same obj are returned consecutively.
        """
        for obj in sorted(self.api.Object(), key=lambda o: o.name):
            managed_permissions = getattr(obj, 'managed_permissions', {})
            for name, template in sorted(managed_permissions.items()):
                yield name, template, obj

        for name, template in sorted(NONOBJECT_PERMISSIONS.items()):
            yield name, template, None


    def execute(self, **options):
        ldap = self.api.Backend.ldap2

        anonymous_read_aci = self.get_anonymous_read_aci(ldap)

        if anonymous_read_aci:
            logger.debug('Anonymous read ACI: %s', anonymous_read_aci)
        else:
            logger.debug('Anonymous ACI not found')

        current_obj = ()  # initially distinct from any obj value, even None
        for name, template, obj in self.get_templates():
            if current_obj != obj:
                if obj:
                    logger.debug('Updating managed permissions for %s',
                                 obj.name)
                else:
                    logger.debug('Updating non-object managed permissions')
                current_obj = obj

            self.update_permission(ldap,
                                    obj,
                                    unicode(name),
                                    template,
                                    anonymous_read_aci)

        if anonymous_read_aci:
            self.remove_anonymous_read_aci(ldap, anonymous_read_aci)

        for obsolete_name in OBSOLETE_PERMISSIONS:
            logger.debug('Deleting obsolete permission %s', obsolete_name)
            try:
                self.api.Command[permission_del](unicode(obsolete_name),
                                                 force=True,
                                                 version=u'2.101')
            except errors.NotFound:
                logger.debug('Obsolete permission not found')
            else:
                logger.debug('Obsolete permission deleted: %s', obsolete_name)

        return False, ()

    def update_permission(self, ldap, obj, name, template, anonymous_read_aci):
        """Update the given permission and the corresponding ACI"""
        assert name.startswith('System:')

        dn = self.api.Object[permission].get_dn(name)
        permission_plugin = self.api.Object[permission]

        try:
            attrs_list = list(permission_plugin.default_attributes)
            attrs_list.remove('memberindirect')
            entry = ldap.get_entry(dn, attrs_list)
            is_new = False
        except errors.NotFound:
            entry = ldap.make_entry(dn)
            is_new = True

        self.update_entry(obj, entry, template,
                          anonymous_read_aci, is_new=is_new)

        remove_legacy = False
        if 'replaces' in template:
            sub_dict = {
                'SUFFIX': str(self.api.env.basedn),
                'REALM': str(self.api.env.realm),
            }
            legacy_acistrs = [ipautil.template_str(r, sub_dict)
                              for r in template['replaces']]

            legacy_aci = ACI(legacy_acistrs[0])
            prefix, sep, legacy_name = legacy_aci.name.partition(':')
            assert prefix == 'permission' and sep

            legacy_dn = permission_plugin.get_dn(legacy_name)
            try:
                legacy_entry = ldap.get_entry(legacy_dn,
                                              ['ipapermissiontype', 'cn'])
            except errors.NotFound:
                logger.debug("Legacy permission %s not found", legacy_name)
            else:
                if 'ipapermissiontype' not in legacy_entry:
                    if is_new:
                        _acientry, acistr = (
                            permission_plugin._get_aci_entry_and_string(
                                legacy_entry, notfound_ok=True))
                        try:
                            included, excluded = self.get_upgrade_attr_lists(
                                acistr, legacy_acistrs)
                        except IncompatibleACIModification:
                            logger.error(
                                "Permission '%s' has been modified from its "
                                "default; not updating it to '%s'.",
                                legacy_name, name)
                            return
                        else:
                            logger.debug("Merging attributes from legacy "
                                         "permission '%s'", legacy_name)
                            logger.debug("Included attrs: %s",
                                         ', '.join(sorted(included)))
                            logger.debug("Excluded attrs: %s",
                                         ', '.join(sorted(excluded)))
                            entry['ipapermincludedattr'] = list(included)
                            entry['ipapermexcludedattr'] = list(excluded)
                            remove_legacy = True
                    else:
                        logger.debug("Ignoring attributes in legacy "
                                     "permission '%s' because '%s' exists",
                                     legacy_name, name)
                        remove_legacy = True
                else:
                    logger.debug("Ignoring V2 permission named '%s'",
                                 legacy_name)

        update_aci = True
        logger.debug('Updating managed permission: %s', name)
        if is_new:
            ldap.add_entry(entry)
        else:
            try:
                ldap.update_entry(entry)
            except errors.EmptyModlist:
                logger.debug('No changes to permission: %s', name)
                update_aci = False

        if update_aci:
            logger.debug('Updating ACI for managed permission: %s', name)
            permission_plugin.update_aci(entry)

        if remove_legacy:
            logger.debug("Removing legacy permission '%s'", legacy_name)
            self.api.Command[permission_del](unicode(legacy_name))

        for name in template.get('replaces_system', ()):
            name = unicode(name)
            try:
                entry = ldap.get_entry(permission_plugin.get_dn(name),
                                       ['ipapermissiontype'])
            except errors.NotFound:
                logger.debug("Legacy permission '%s' not found", name)
            else:
                flags = entry.get('ipapermissiontype', [])
                if list(flags) == ['SYSTEM']:
                    logger.debug("Removing legacy permission '%s'", name)
                    self.api.Command[permission_del](name, force=True)
                else:
                    logger.debug("Ignoring V2 permission '%s'", name)

    def get_upgrade_attr_lists(self, current_acistring, default_acistrings):
        """Compute included and excluded attributes for a new permission

        :param current_acistring: ACI is in LDAP currently
        :param default_acistrings:
            List of all default ACIs IPA historically used for this permission
        :return:
            (ipapermincludedattr, ipapermexcludedattr) for the upgraded
            permission

        An attribute will be included if the user has it in LDAP but it does
        not appear in *any* historic ACI.
        It will be excluded if it is in *all* historic ACIs but not in LDAP.
        Rationale: When we don't know which version of an ACI the user is
        upgrading from, we only consider attributes where all the versions
        agree. For other attrs we'll use the default from the new managed perm.

        If the ACIs differ in something else than the list of attributes,
        raise IncompatibleACIModification. This means manual action is needed
        (either delete the old permission or change it to resemble the default
        again, then re-run ipa-ldap-updater).

        In case there are multiple historic default ACIs, and some of them
        are compatible with the current but other ones aren't, we deduce that
        the user is upgrading from one of the compatible ones.
        The incompatible ones are removed from consideration, both for
        compatibility and attribute lists.
        """
        assert default_acistrings

        def _pop_targetattr(aci):
            """Return the attr list it as a set, clear it in the ACI object
            """
            targetattr = aci.target.get('targetattr')
            if targetattr:
                attrs = targetattr['expression']
                targetattr['expression'] = []
                return set(t.lower() for t in attrs)
            else:
                return set()

        current_aci = ACI(current_acistring)
        current_attrs = _pop_targetattr(current_aci)
        logger.debug("Current ACI for '%s': %s",
                     current_aci.name, current_acistring)

        attrs_in_all_defaults = None
        attrs_in_any_defaults = set()
        all_incompatible = True
        for default_acistring in default_acistrings:
            default_aci = ACI(default_acistring)
            default_attrs = _pop_targetattr(default_aci)
            logger.debug("Default ACI for '%s': %s",
                         default_aci.name, default_acistring)

            if current_aci != default_aci:
                logger.debug('ACIs not compatible')
                continue
            all_incompatible = False

            if attrs_in_all_defaults is None:
                attrs_in_all_defaults = set(default_attrs)
            else:
                attrs_in_all_defaults &= attrs_in_all_defaults
            attrs_in_any_defaults |= default_attrs

        if all_incompatible:
            logger.debug('All old default ACIs are incompatible')
            raise(IncompatibleACIModification())

        included = current_attrs - attrs_in_any_defaults
        excluded = attrs_in_all_defaults - current_attrs

        return included, excluded

    def update_entry(self, obj, entry, template,
                     anonymous_read_aci, is_new):
        """Update the given permission Entry (without contacting LDAP)"""

        [name_ava] = entry.dn[0]
        assert name_ava.attr == 'cn'
        name = name_ava.value
        entry.single_value['cn'] = name

        template = dict(template)
        template.pop('replaces', None)
        template.pop('replaces_system', None)
        template.pop('replaces_permissions', None)
        template.pop('replaces_acis', None)

        fixup_function = template.pop('fixup_function', None)
        if fixup_function:
            fixup_function(name, template,
                           is_new=is_new,
                           anonymous_read_aci=anonymous_read_aci)

        if template.pop('non_object', False):
            obj = None

        entry['ipapermissiontype'] = [u'SYSTEM', u'V2', u'MANAGED']

        # Attributes with defaults
        objectclass = template.pop('objectclass', None)
        if objectclass is None:
            objectclass = self.api.Object[permission].object_class
        entry['objectclass'] = list(objectclass)

        ldap_filter = template.pop('ipapermtargetfilter', None)
        if obj and ldap_filter is None:
            ldap_filter = [self.api.Object[permission].make_type_filter(obj)]
        entry['ipapermtargetfilter'] = list(ldap_filter or [])

        ipapermlocation = template.pop('ipapermlocation', None)
        if ipapermlocation is None:
            assert obj
            ipapermlocation = DN(obj.container_dn, self.api.env.basedn)
        entry.single_value['ipapermlocation'] = ipapermlocation

        # Optional attributes
        ipapermtarget = template.pop('ipapermtarget', None)
        if ipapermtarget is not None:
            entry['ipapermtarget'] = ipapermtarget

        ipapermtargetto = template.pop('ipapermtargetto', None)
        if ipapermtargetto is not None:
            entry['ipapermtargetto'] = ipapermtargetto

        ipapermtargetfrom = template.pop('ipapermtargetfrom', None)
        if ipapermtargetfrom is not None:
            entry['ipapermtargetfrom'] = ipapermtargetfrom

        # Attributes from template
        bindruletype = template.pop('ipapermbindruletype', 'permission')
        if is_new:
            entry.single_value['ipapermbindruletype'] = bindruletype

        entry['ipapermright'] = list(template.pop('ipapermright'))

        default_privileges = template.pop('default_privileges', None)
        if is_new and default_privileges:
            entry['member'] = list(
                DN(('cn', privilege_name),
                   self.api.env.container_privilege,
                   self.api.env.basedn)
                for privilege_name in default_privileges)

        # Add to the set of default attributes
        attributes = set(template.pop('ipapermdefaultattr', ()))
        attributes.update(entry.get('ipapermdefaultattr', ()))
        attributes = set(a.lower() for a in attributes)
        entry['ipapermdefaultattr'] = list(attributes)

        # Exclude attributes filtered from the global read ACI
        replaces_ga_aci = template.pop('replaces_global_anonymous_aci', False)
        if replaces_ga_aci and is_new and anonymous_read_aci:
            read_blacklist = set(
                a.lower() for a in
                anonymous_read_aci.target['targetattr']['expression'])
            read_blacklist &= attributes
            if read_blacklist:
                logger.debug('Excluded attributes for %s: %s',
                             name, ', '.join(read_blacklist))
                entry['ipapermexcludedattr'] = list(read_blacklist)

        # Sanity check
        if template:
            raise ValueError(
                'Unknown key(s) in managed permission template %s: %s' % (
                    name, ', '.join(template.keys())))


@register()
class update_read_replication_agreements_permission(Updater):
    """'Read replication agreements' permission must not be managed permission

    https://fedorahosted.org/freeipa/ticket/5631

    Existing permission "cn=System: Read Replication Agreements" must be moved
    to non-managed permission "cn=Read Replication Agreements" using modrdn
    ldap operation to keep current membership of the permission set by user.

    ACI is updated via update files
    """

    def execute(self, **options):
        ldap = self.api.Backend.ldap2
        old_perm_dn = DN(
            ('cn', 'System: Read Replication Agreements'),
            self.api.env.container_permission,
            self.api.env.basedn
        )

        new_perm_dn = DN(
            ('cn', 'Read Replication Agreements'),
            self.api.env.container_permission,
            self.api.env.basedn
        )

        try:
            perm_entry = ldap.get_entry(old_perm_dn)
        except errors.NotFound:
            logger.debug("Old permission not found")
            return False, ()

        try:
            ldap.get_entry(new_perm_dn)
        except errors.NotFound:
            # we can happily upgrade
            pass
        else:
            logger.error("Permission '%s' cannot be upgraded. "
                         "Permission with target name '%s' already "
                         "exists", old_perm_dn, new_perm_dn)
            return False, ()

        # values are case insensitive
        for t in list(perm_entry['ipapermissiontype']):
            if t.lower() in ['managed', 'v2']:
                perm_entry['ipapermissiontype'].remove(t)

        for o in list(perm_entry['objectclass']):
            if o.lower() == 'ipapermissionv2':
                # remove permission V2 objectclass and related attributes
                perm_entry['objectclass'].remove(o)
                perm_entry['ipapermdefaultattr'] = []
                perm_entry['ipapermright'] = []
                perm_entry['ipapermbindruletype'] = []
                perm_entry['ipapermlocation'] = []
                perm_entry['ipapermtargetfilter'] = []

        logger.debug("Removing MANAGED attributes from permission %s",
                     old_perm_dn)
        try:
            ldap.update_entry(perm_entry)
        except errors.EmptyModlist:
            pass

        # do modrdn on permission
        logger.debug("modrdn: %s -> %s", old_perm_dn, new_perm_dn)
        ldap.move_entry(old_perm_dn, new_perm_dn)
        return False, ()
