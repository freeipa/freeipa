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
* ipapermtarget, ipapermtargetfilter, ipapermlocation, ipapermright, objectclass
  - Directly used as attributes on the permission.
  - Replaced when upgrading an existing permission
  - If not specified, these default to the defaults of a permission of the
    corresponding --type, or, if non_object is specified, or if not on an
    object, to general permission defaults .
  - ipapermlocation and ipapermtarget must be DNs
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
* fixup_function
  - A callable that may modify the template in-place before it is applied.
  - Called with the permission name, template dict, and keyword arguments:
    - is_new: true if the permission was previously existing
    - anonymous_read_aci: the legacy 'Enable Anonymous access' ACI as
      an ipalib.aci.ACI object, or None if it does not exist
    Extra keyword arguments must be ignored, since this list may grow
    in the future.

No other keys are allowed in the template
"""

from ipalib import api, errors
from ipapython.dn import DN
from ipalib.plugable import Registry
from ipalib.plugins import aci
from ipalib.plugins.permission import permission
from ipaserver.plugins.ldap2 import ldap2
from ipaserver.install.plugins import LAST
from ipaserver.install.plugins.baseupdate import PostUpdate


register = Registry()

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
    'System: Read Replication Agreements': {
        'ipapermlocation': DN('cn=config'),
        'ipapermtargetfilter': {
            '(|'
                '(objectclass=nsds5Replica)'
                '(objectclass=nsds5replicationagreement)'
                '(objectclass=nsDSWindowsReplicationAgreement)'
                '(objectClass=nsMappingTree)'
            ')'
        },
        'ipapermbindruletype': 'permission',
        'ipapermright': {'read', 'search', 'compare'},
        'ipapermdefaultattr': {
            'cn', 'objectclass',
            # nsds5Replica
            'nsds5replicaroot', 'nsds5replicaid', 'nsds5replicacleanruv',
            'nsds5replicaabortcleanruv', 'nsds5replicatype',
            'nsds5replicabinddn', 'nsstate', 'nsds5replicaname',
            'nsds5flags', 'nsds5task', 'nsds5replicareferral',
            'nsds5replicaautoreferral', 'nsds5replicapurgedelay',
            'nsds5replicatombstonepurgeinterval', 'nsds5replicachangecount',
            'nsds5replicalegacyconsumer', 'nsds5replicaprotocoltimeout',
            'nsds5replicabackoffmin', 'nsds5replicabackoffmax',
            # nsds5replicationagreement
            'nsds5replicacleanruvnotified', 'nsds5replicahost',
            'nsds5replicaport', 'nsds5replicatransportinfo',
            'nsds5replicabinddn', 'nsds5replicacredentials',
            'nsds5replicabindmethod', 'nsds5replicaroot',
            'nsds5replicatedattributelist',
            'nsds5replicatedattributelisttotal', 'nsds5replicaupdateschedule',
            'nsds5beginreplicarefresh', 'description', 'nsds50ruv',
            'nsruvreplicalastmodified', 'nsds5replicatimeout',
            'nsds5replicachangessentsincestartup', 'nsds5replicalastupdateend',
            'nsds5replicalastupdatestart', 'nsds5replicalastupdatestatus',
            'nsds5replicaupdateinprogress', 'nsds5replicalastinitend',
            'nsds5replicaenabled', 'nsds5replicalastinitstart',
            'nsds5replicalastinitstatus', 'nsds5debugreplicatimeout',
            'nsds5replicabusywaittime', 'nsds5replicastripattrs',
            'nsds5replicasessionpausetime', 'nsds5replicaprotocoltimeout',
            # nsDSWindowsReplicationAgreement
            'nsds5replicahost', 'nsds5replicaport',
            'nsds5replicatransportinfo', 'nsds5replicabinddn',
            'nsds5replicacredentials', 'nsds5replicabindmethod',
            'nsds5replicaroot', 'nsds5replicatedattributelist',
            'nsds5replicaupdateschedule', 'nsds5beginreplicarefresh',
            'description', 'nsds50ruv', 'nsruvreplicalastmodified',
            'nsds5replicatimeout', 'nsds5replicachangessentsincestartup',
            'nsds5replicalastupdateend', 'nsds5replicalastupdatestart',
            'nsds5replicalastupdatestatus', 'nsds5replicaupdateinprogress',
            'nsds5replicalastinitend', 'nsds5replicalastinitstart',
            'nsds5replicalastinitstatus', 'nsds5debugreplicatimeout',
            'nsds5replicabusywaittime', 'nsds5replicasessionpausetime',
            'nsds7windowsreplicasubtree', 'nsds7directoryreplicasubtree',
            'nsds7newwinusersyncenabled', 'nsds7newwingroupsyncenabled',
            'nsds7windowsdomain', 'nsds7dirsynccookie', 'winsyncinterval',
            'onewaysync', 'winsyncmoveaction', 'nsds5replicaenabled',
            'winsyncdirectoryfilter', 'winsyncwindowsfilter',
            'winsyncsubtreepair',
        },
        'default_privileges': {'Replication Administrators'},
    }
}


@register()
class update_managed_permissions(PostUpdate):
    """Update managed permissions after an update.

    Update managed permissions according to templates specified in plugins.
    For read permissions, puts any attributes specified in the legacy
    Anonymous access ACI in the exclude list when creating the permission.
    """
    order = LAST

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

    def execute(self, **options):
        ldap = self.api.Backend[ldap2]

        anonymous_read_aci = self.get_anonymous_read_aci(ldap)

        if anonymous_read_aci:
            self.log.info('Anonymous read ACI: %s', anonymous_read_aci)
        else:
            self.log.info('Anonymous ACI not found')

        for obj in self.api.Object():
            managed_permissions = getattr(obj, 'managed_permissions', {})
            if managed_permissions:
                self.log.info('Updating managed permissions for %s', obj.name)
            for name, template in managed_permissions.items():
                self.update_permission(ldap,
                                       obj,
                                       unicode(name),
                                       template,
                                       anonymous_read_aci)

        self.log.info('Updating non-object managed permissions')
        for name, template in NONOBJECT_PERMISSIONS.iteritems():
            self.update_permission(ldap, None, unicode(name), template,
                                   anonymous_read_aci)

        return False, False, ()

    def update_permission(self, ldap, obj, name, template, anonymous_read_aci):
        """Update the given permission and the corresponding ACI"""
        assert name.startswith('System:')

        dn = self.api.Object[permission].get_dn(name)

        try:
            attrs_list = list(self.api.Object[permission].default_attributes)
            attrs_list.remove('memberindirect')
            entry = ldap.get_entry(dn, attrs_list)
            is_new = False
        except errors.NotFound:
            entry = ldap.make_entry(dn)
            is_new = True

        self.log.debug('Updating managed permission: %s', name)
        self.update_entry(obj, entry, template,
                          anonymous_read_aci, is_new=is_new)

        if is_new:
            ldap.add_entry(entry)
        else:
            try:
                ldap.update_entry(entry)
            except errors.EmptyModlist:
                self.log.debug('No changes to permission: %s', name)
                return

        self.log.debug('Updating ACI for managed permission: %s', name)

        self.api.Object[permission].update_aci(entry)

    def update_entry(self, obj, entry, template,
                     anonymous_read_aci, is_new):
        """Update the given permission Entry (without contacting LDAP)"""

        [name_ava] = entry.dn[0]
        assert name_ava.attr == 'cn'
        name = name_ava.value
        entry.single_value['cn'] = name

        template = dict(template)

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
            ldap_filter = ['(objectclass=%s)' % oc
                           for oc in obj.permission_filter_objectclasses]
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

        # Attributes from template
        bindruletype = template.pop('ipapermbindruletype')
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
                self.log.info('Excluded attributes for %s: %s',
                              name, ', '.join(read_blacklist))
                entry['ipapermexcludedattr'] = list(read_blacklist)

        # Sanity check
        if template:
            raise ValueError(
                'Unknown key(s) in managed permission template %s: %s' % (
                    name, ', '.join(template.keys())))
