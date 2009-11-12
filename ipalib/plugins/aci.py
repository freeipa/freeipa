# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
"""
Directory Server Access Control Instructions (ACIs)

ACI's are used to allow or deny access to information. This module is
currently designed to allow, not deny, access, primarily write access.

The primary use of this plugin is to create low-level permission sets
to allow a group to write or update entries or a set of attributes. This
may include adding or removing entries as well. These groups are called
taskgroups. These low-level permissions can be combined into roles
that grant broader access. These roles are another type of group, rolegroups.

For example, if you have taskgroups that allow adding and modifying users you
could create a rolegroup, useradmin. You would assign users to the useradmin
rolegroup to allow them to do the operations defined by the taskgroups.

You can create ACIs that delegate permission so users in
group A can write attributes on group B.

The type option is a map that applies to all entries in the users, groups or
host location. It is primarily designed to be used when granting add
permissions (to write new entries).

For a more thorough description of access controls see
http://www.redhat.com/docs/manuals/dir-server/ag/8.0/Managing_Access_Control.html

EXAMPLES:

 Add an ACI so the group 'secretaries' can update the address on any user:
   ipa aci-add --attrs=streetAddress --memberof=ipausers --group=secretaries --permissions=write "Secretaries write addresses"

 Show the new ACI:
   ipa aci-show "Secretaries write addresses"

 Add an ACI that allows members of the 'addusers' taskgroup to add new users:
   ipa aci-add --type=user --taskgroup=addusers --permissions=add "Add new users"

The show command will show the raw DS ACI.

"""

from ipalib import api, crud, errors
from ipalib import Object, Command
from ipalib import Flag, Int, List, Str, StrEnum
from ipalib.aci import ACI
import logging

_type_map = {
    'user': 'ldap:///uid=*,%s,%s' % (api.env.container_user, api.env.basedn),
    'group': 'ldap:///cn=*,%s,%s' % (api.env.container_group, api.env.basedn),
    'host': 'ldap:///fqdn=*,%s,%s' % (api.env.container_host, api.env.basedn)
}

_valid_permissions_values = [
    u'read', u'write', u'add', u'delete', u'selfwrite', u'all'
]


def _make_aci(current, aciname, kw):
    # Do some quick and dirty validation
    t1 = 'type' in kw
    t2 = 'filter' in kw
    t3 = 'subtree' in kw
    t4 = 'targetgroup' in kw
    t5 = 'attrs' in kw
    t6 = 'memberof' in kw
    if t1 + t2 + t3 + t4 > 1:
        raise errors.ValidationError(name='target', error='type, filter, subtree and targetgroup are mutually exclusive')

    if t1 + t2 + t3 + t4 + t5 + t6 == 0:
        raise errors.ValidationError(name='target', error='at least one of: type, filter, subtree, targetgroup, attrs or memberof are required')

    group = 'group' in kw
    taskgroup = 'taskgroup' in kw
    if group + taskgroup > 1:
        raise errors.ValidationError(name='target', error='group and taskgroup are mutually exclusive')
    elif group + taskgroup == 0:
        raise errors.ValidationError(name='target', error='One of group or taskgroup is required')

    # Grab the dn of the group we're granting access to. This group may be a
    # taskgroup or a user group.
    if taskgroup:
        try:
            (dn, entry_attrs) = api.Command['taskgroup_show'](kw['taskgroup'])
        except errors.NotFound:
            # The task group doesn't exist, let's be helpful and add it
            tgkw = {'description': aciname}
            (dn, entry_attrs) = api.Command['taskgroup_add'](
                kw['taskgroup'], **tgkw
            )
    elif group:
        # Not so friendly with groups. This will raise
        try:
            (dn, entry_attrs) = api.Command['group_show'](kw['group'])
        except errors.NotFound:
            raise errors.NotFound(reason="Group '%s' does not exist" % kw['group'])

    a = ACI(current)
    a.name = aciname
    a.permissions = kw['permissions']
    a.set_bindrule('groupdn = "ldap:///%s"' % dn)
    if 'attrs' in kw:
        a.set_target_attr(kw['attrs'])
    if 'memberof' in kw:
        (dn, entry_attrs) = api.Command['group_show'](kw['memberof'])
        a.set_target_filter('memberOf=%s' % dn)
    if 'filter' in kw:
        a.set_target_filter(kw['filter'])
    if 'type' in kw:
        target = _type_map[kw['type']]
        a.set_target(target)
    if 'targetgroup' in kw:
        # Purposely no try here so we'll raise a NotFound
        (dn, entry_attrs) = api.Command['group_show'](kw['targetgroup'])
        target = 'ldap:///%s' % dn
        a.set_target(target)
    if 'subtree' in kw:
        # See if the subtree is a full URI
        target = kw['subtree']
        if not target.startswith('ldap:///'):
            target = 'ldap:///%s' % target
        a.set_target(target)

    return a

def _convert_strings_to_acis(acistrs):
    acis = []
    for a in acistrs:
        try:
            acis.append(ACI(a))
        except SyntaxError, e:
            logging.warn("Failed to parse: %s" % a)
    return acis

def _find_aci_by_name(acis, aciname):
    for a in acis:
        if a.name.lower() == aciname.lower():
            return a
    raise errors.NotFound(reason='ACI with name "%s" not found' % aciname)

def _normalize_permissions(permissions):
    valid_permissions = []
    permissions = permissions.split(',')
    for p in permissions:
        p = p.strip().lower()
        if p in _valid_permissions_values and p not in valid_permissions:
            valid_permissions.append(p)
    return ','.join(valid_permissions)


class aci(Object):
    """
    ACI object.
    """
    takes_params = (
        Str('aciname',
            cli_name='name',
            doc='name',
            primary_key=True,
        ),
        Str('taskgroup?',
            cli_name='taskgroup',
            doc='taskgroup ACI grants access to',
        ),
        Str('group?',
            cli_name='group',
            doc='user group ACI grants access to',
        ),
        List('permissions',
            cli_name='permissions',
            doc='comma-separated list of permissions to grant' \
                '(read, write, add, delete, selfwrite, all)',
            normalizer=_normalize_permissions,
        ),
        List('attrs?',
            cli_name='attrs',
            doc='comma-separated list of attributes',
        ),
        StrEnum('type?',
            cli_name='type',
            doc='type of IPA object (user, group, host)',
            values=(u'user', u'group', u'host'),
        ),
        Str('memberof?',
            cli_name='memberof',
            doc='member of a group',
        ),
        Str('filter?',
            cli_name='filter',
            doc='legal LDAP filter (e.g. ou=Engineering)',
        ),
        Str('subtree?',
            cli_name='subtree',
            doc='subtree to apply ACI to',
        ),
        Str('targetgroup?',
            cli_name='targetgroup',
            doc='group to apply ACI to',
        ),
    )

api.register(aci)


class aci_add(crud.Create):
    """
    Create new ACI.
    """
    def execute(self, aciname, **kw):
        """
        Execute the aci-create operation.

        Returns the entry as it will be created in LDAP.

        :param aciname: The name of the ACI being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'aciname' not in kw
        ldap = self.api.Backend.ldap2

        newaci = _make_aci(None, aciname, kw)

        (dn, entry_attrs) = ldap.get_entry(self.api.env.basedn, ['aci'])

        acis = _convert_strings_to_acis(entry_attrs.get('aci', []))
        for a in acis:
            if a.isequal(newaci):
                raise errors.DuplicateEntry()

        newaci_str = str(newaci)
        entry_attrs['aci'].append(newaci_str)

        ldap.update_entry(dn, entry_attrs)

        return newaci_str

    def output_for_cli(self, textui, result, aciname, **options):
        """
        Display the newly created ACI and a success message.
        """
        textui.print_name(self.name)
        textui.print_plain(result)
        textui.print_dashed('Created ACI "%s".' % aciname)

api.register(aci_add)


class aci_del(crud.Delete):
    """
    Delete ACI.
    """
    def execute(self, aciname, **kw):
        """
        Execute the aci-delete operation.

        :param aciname: The name of the ACI being added.
        :param kw: unused
        """
        assert 'aciname' not in kw
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.get_entry(self.api.env.basedn, ['aci'])

        acistrs = entry_attrs.get('aci', [])
        acis = _convert_strings_to_acis(acistrs)
        aci = _find_aci_by_name(acis, aciname)
        for a in acistrs:
            candidate = ACI(a)
            if aci.isequal(candidate):
                acistrs.remove(a)
                break

        entry_attrs['aci'] = acistrs

        ldap.update_entry(dn, entry_attrs)

        return True

    def output_for_cli(self, textui, result, aciname, **options):
        """
        Output result of this command to command line interface.
        """
        textui.print_name(self.name)
        textui.print_plain('Deleted ACI "%s".' % aciname)

api.register(aci_del)


class aci_mod(crud.Update):
    """
    Modify ACI.
    """
    def execute(self, aciname, **kw):
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.get_entry(self.api.env.basedn, ['aci'])

        acis = _convert_strings_to_acis(entry_attrs.get('aci', []))
        aci = _find_aci_by_name(acis, aciname)

        kw.setdefault('aciname', aci.name)
        kw.setdefault('taskgroup', aci.bindrule['expression'])
        kw.setdefault('permissions', aci.permissions)
        kw.setdefault('attrs', aci.target['targetattr']['expression'])
        if 'type' not in kw and 'targetgroup' not in kw and 'subtree' not in kw:
            kw['subtree'] = aci.target['target']['expression']
        if 'memberof' not in kw and 'filter' not in kw:
            kw['filter'] = aci.target['targetfilter']['expression']

        self.api.Command['aci_del'](aciname)

        return self.api.Command['aci_add'](aciname, **kw)

    def output_for_cli(self, textui, result, aciname, **options):
        """
        Display the updated ACI and a success message.
        """
        textui.print_name(self.name)
        textui.print_plain(result)
        textui.print_dashed('Modified ACI "%s".' % aciname)

api.register(aci_mod)


class aci_find(crud.Search):
    """
    Search for ACIs.

    Returns a list of ACIs

    EXAMPLES:

     To find all ACIs that apply directly to members of the group ipausers:
       ipa aci-find --memberof=ipausers

     To find all ACIs that grant add access:
       ipa aci-find --permissions=add

    Note that the find command only looks for the given text in the set of
    ACIs, it does not evaluate the ACIs to see if something would apply.
    For example, searching on memberof=ipausers will find all ACIs that
    have ipausers as a memberof. There may be other ACIs that apply to
    members of that group indirectly.
    """
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.get_entry(self.api.env.basedn, ['aci'])

        acis = _convert_strings_to_acis(entry_attrs.get('aci', []))
        results = []

        if term:
            term = term.lower()
            for a in acis:
                if a.name.lower().find(term) != -1 and a not in results:
                    results.append(a)
            acis = list(results)
        else:
            results = list(acis)

        if 'aciname' in kw:
            for a in acis:
                if a.name != kw['aciname']:
                    results.remove(a)
            acis = list(results)

        if 'attrs' in kw:
            for a in acis:
                alist1 = sorted(
                    [t.lower() for t in a.target['targetattr']['expression']]
                )
                alist2 = sorted([t.lower() for t in kw['attrs']])
                if alist1 != alist2:
                    results.remove(a)
            acis = list(results)

        if 'taskgroup' in kw:
            try:
                (dn, entry_attrs) = self.api.Command['taskgroup_show'](
                    kw['taskgroup']
                )
            except errors.NotFound:
                pass
            else:
                for a in acis:
                    if a.bindrule['expression'] != ('ldap:///%s' % dn):
                        results.remove(a)
                acis = list(results)

        if 'permissions' in kw:
            for a in acis:
                alist1 = sorted(a.permissions)
                alist2 = sorted(kw['permissions'])
                if alist1 != alist2:
                    results.remove(a)
                acis = list(results)

        if 'memberof' in kw:
            try:
                (dn, entry_attrs) = self.api.Command['group_show'](
                    kw['memberof']
                )
            except errors.NotFound:
                pass
            else:
                memberof_filter = '(memberOf=%s)' % dn
                for a in acis:
                    if 'targetfilter' in a.target:
                        targetfilter = a.target['targetfilter']['expression']
                        if targetfilter != memberof_filter:
                            results.remove(a)
                    else:
                        results.remove(a)
                # uncomment next line if you add more search criteria
                # acis = list(results)

        # TODO: searching by: type, filter, subtree

        return [str(aci) for aci in results]

    def output_for_cli(self, textui, result, term, **options):
        """
        Display the search results
        """
        textui.print_name(self.name)
        for aci in result:
            textui.print_plain(aci)
            textui.print_plain('')
        textui.print_count(
            len(result), '%i ACI matched.', '%i ACIs matched.'
        )

api.register(aci_find)


class aci_show(crud.Retrieve):
    """
    Display a single ACI given an ACI name.
    """
    def execute(self, aciname, **kw):
        """
        Execute the aci-show operation.

        Returns the entry

        :param uid: The login name of the user to retrieve.
        :param kw: unused
        """
        ldap = self.api.Backend.ldap2

        (dn, entry_attrs) = ldap.get_entry(self.api.env.basedn, ['aci'])

        acis = _convert_strings_to_acis(entry_attrs.get('aci', []))

        return str(_find_aci_by_name(acis, aciname))

    def output_for_cli(self, textui, result, aciname, **options):
        """
        Display the requested ACI
        """
        textui.print_name(self.name)
        textui.print_plain(result)

api.register(aci_show)
