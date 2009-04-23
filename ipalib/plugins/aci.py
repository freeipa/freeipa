# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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
Frontend plugins for managing DS ACIs
"""

from ipalib import api, crud, errors
from ipalib import Object, Command  # Plugin base classes
from ipalib import Str, Flag, Int, StrEnum  # Parameter types
from ipalib.aci import ACI

type_map = {
    'user': 'ldap:///uid=*,%s,%s' % (api.env.container_user, api.env.basedn),
    'group': 'ldap:///cn=*,%s,%s' % (api.env.container_group, api.env.basedn),
    'host': 'ldap:///cn=*,%s,%s' % (api.env.container_host, api.env.basedn)
}

def make_aci(current, aciname, kw):
    try:
        taskgroup = api.Command['taskgroup_show'](kw['taskgroup'])
    except errors.NotFound:
        # The task group doesn't exist, let's be helpful and add it
        tgkw = {'description':aciname}
        taskgroup = api.Command['taskgroup_add'](kw['taskgroup'], **tgkw)

    a = ACI(current)
    a.name = aciname
    a.permissions = kw['permissions'].replace(' ','').split(',')
    a.set_bindrule("groupdn = \"ldap:///%s\"" % taskgroup['dn'])
    if kw.get('attrs', None):
        a.set_target_attr(kw['attrs'].split(','))
    if kw.get('memberof', None):
        group = api.Command['group_show'](kw['memberof'])
        a.set_target_filter("memberOf=%s" % group['dn'].decode('UTF-8'))
    if kw.get('type', None):
        target = type_map[kw.get('type')]
        a.set_target(target)
    if kw.get('targetgroup', None):
        # Purposely no try here so we'll raise a NotFound
        group = api.Command['group_show'](kw.get('targetgroup'))
        target = "ldap:///%s" % group.get('dn')
        a.set_target(target)
    if kw.get('subtree',None):
        # See if the subtree is a full URI
        target = kw.get('subtree')
        if not target.startswith("ldap:///"):
            target = "ldap:///" + target
        a.set_target(target)

    return a

def search_by_name(acis, aciname):
    """
    Find an aci using the name field.

    Must be an exact match of the entire name.
    """
    for a in acis:
        try:
            t = ACI(a)
            if t.name == aciname:
                return str(t)
        except SyntaxError, e:
            # FIXME: need to log syntax errors, ignore for now
            pass

    raise errors.NotFound()

def search_by_attr(acis, attrlist):
    """
    Find an aci by targetattr.

    Returns an ACI list of all acis the attribute appears in.
    """
    results = []
    for a in acis:
        try:
            t = ACI(a)
            for attr in attrlist:
                attr = attr.lower()
                for v in t.target['targetattr'].get('expression'):
                    if attr == v.lower():
                        results.append(str(t))
        except SyntaxError, e:
            # FIXME: need to log syntax errors, ignore for now
            pass

    if results:
        return results

    raise errors.NotFound()

def search_by_taskgroup(acis, tgdn):
    """
    Find an aci by taskgroup. This searches the ACI bind rule.

    Returns an ACI list of all acis that match.
    """
    results = []
    for a in acis:
        try:
            t = ACI(a)
            if t.bindrule['expression'] == "ldap:///" + tgdn:
                results.append(str(t))
        except SyntaxError, e:
            # FIXME: need to log syntax errors, ignore for now
            pass

    if results:
        return results

    raise errors.NotFound()

def search_by_perm(acis, permlist):
    """
    Find an aci by permissions

    Returns an ACI list of all acis the permission appears in.
    """
    results = []
    for a in acis:
        try:
            t = ACI(a)
            for perm in permlist:
                if perm.lower() in t.permissions:
                    results.append(str(t))
        except SyntaxError, e:
            # FIXME: need to log syntax errors, ignore for now
            pass

    if results:
        return results

    raise errors.NotFound()

def search_by_memberof(acis, memberoffilter):
    """
    Find an aci by memberof

    Returns an ACI list of all acis that has a matching memberOf as a
    targetfilter.
    """
    results = []
    memberoffilter = memberoffilter.lower()
    for a in acis:
        try:
            t = ACI(a)
            try:
                if memberoffilter == t.target['targetfilter'].get('expression').lower():
                    results.append(str(t))
            except KeyError:
                pass
        except SyntaxError, e:
            # FIXME: need to log syntax errors, ignore for now
            pass

    if results:
        return results

    raise errors.NotFound()

class aci(Object):
    """
    ACI object.
    """
    takes_params = (
        Str('aciname',
            doc='Name of ACI',
            primary_key=True,
        ),
        Str('taskgroup',
            doc='Name of taskgroup this ACI grants access to',
        ),
        StrEnum('permissions',
            doc='Permissions to grant: read, write, add, delete, selfwrite, all',
            values=(u'read', u'write', u'add', u'delete', u'selfwrite', u'all')
        ),
        Str('attrs?',
            doc='Comma-separated list of attributes',
        ),
        StrEnum('type?',
            doc='type of IPA object: user, group, host',
            values=(u'user', u'group')
        ),
        Str('memberof?',
            doc='member of a group',
        ),
        Str('filter?',
            doc='A legal LDAP filter (ou=Engineering)',
        ),
        Str('subtree?',
            doc='A subtree to apply the ACI to',
        ),
        Str('targetgroup?',
            doc='Apply the ACI to a specific group',
        ),
    )
api.register(aci)


class aci_add(crud.Create):
    """
    Add a new aci.
    """

    def execute(self, aciname, **kw):
        """
        Execute the aci-add operation.

        Returns the entry as it will be created in LDAP.

        :param aciname: The name of the ACI being added.
        :param kw: Keyword arguments for the other LDAP attributes.
        """
        assert 'aciname' not in kw
        ldap = self.api.Backend.ldap

        newaci = make_aci(None, aciname, kw)

        currentaci = ldap.retrieve(self.api.env.basedn, ['aci'])

        acilist = currentaci.get('aci')
        for a in acilist:
            try:
                b = ACI(a)
                if newaci.isequal(b):
                    raise errors.DuplicateEntry()
            except SyntaxError:
                pass
        acilist.append(str(newaci))
        kwupdate = {'aci': acilist}

        return ldap.update(currentaci.get('dn'), **kwupdate)

api.register(aci_add)


class aci_del(crud.Delete):
    'Delete an existing aci.'
    """
    Remove an aci by name.
    """

    def execute(self, aciname, **kw):
        """
        Execute the aci-del operation.

        :param aciname: The name of the ACI being added.
        :param kw: unused
        """
        assert 'aciname' not in kw
        ldap = self.api.Backend.ldap

        currentaci = ldap.retrieve(self.api.env.basedn, ['aci'])
        acilist = currentaci.get('aci')
        a = search_by_name(acilist, aciname)
        i = acilist.index(a)
        del acilist[i]

        kwupdate = {'aci': acilist}

        return ldap.update(currentaci.get('dn'), **kwupdate)

    def output_for_cli(self, textui, result, aciname):
        """
        Output result of this command to command line interface.
        """
        textui.print_plain('Deleted aci "%s"' % aciname)

api.register(aci_del)


class aci_mod(crud.Update):
    'Edit an existing aci.'
    def execute(self, aciname, **kw):
        return "Not implemented"
    def output_for_cli(self, textui, result, aciname, **options):
        textui.print_plain(result)
api.register(aci_mod)


class aci_find(crud.Search):
    'Search for a aci.'
    takes_options = (
        Str('bindrule?',
            doc='The bindrule (e.g. ldap:///self)'
        ),
        Flag('and?',
             doc='Consider multiple options to be \"and\" so all are required.')
    )
    def execute(self, term, **kw):
        ldap = self.api.Backend.ldap
        currentaci = ldap.retrieve(self.api.env.basedn, ['aci'])
        currentaci = currentaci.get('aci')
        results = []

        # aciname
        if kw.get('aciname'):
            try:
                a = search_by_name(currentaci, kw.get('aciname'))
                results = [a]
                if kw.get('and'):
                    currentaci = results
            except errors.NotFound:
                if kw.get('and'):
                    results = []
                    currentaci = []
                pass

        # attributes
        if kw.get('attrs'):
            try:
                attrs = kw.get('attrs')
                attrs = attrs.replace(' ','').split(',')
                a=search_by_attr(currentaci, attrs)
                if kw.get('and'):
                    results = a
                    currentaci = results
                else:
                    results = results + a
            except errors.NotFound:
                if kw.get('and'):
                    results = []
                    currentaci = []
                pass

        # taskgroup
        if kw.get('taskgroup'):
            try:
                tg = api.Command['taskgroup_show'](kw.get('taskgroup'))
            except errors.NotFound:
                # FIXME, need more precise error
                raise
            try:
                a=search_by_taskgroup(currentaci, tg.get('dn'))
                if kw.get('and'):
                    results = a
                    currentaci = results
                else:
                    results = results + a
            except errors.NotFound:
                if kw.get('and'):
                    results = []
                    currentaci = []
                pass

        # permissions
        if kw.get('permissions'):
            try:
                permissions = kw.get('permissions')
                permissions = permissions.replace(' ','').split(',')
                a=search_by_perm(currentaci, permissions)
                if kw.get('and'):
                    results = a
                    currentaci = results
                else:
                    results = results + a
            except errors.NotFound:
                if kw.get('and'):
                    results = []
                    currentaci = []
                pass

        # memberOf
        if kw.get('memberof'):
            try:
                group = api.Command['group_show'](kw['memberof'])
                memberof = "(memberOf=%s)" % group['dn'].decode('UTF-8')
                a=search_by_memberof(currentaci, memberof)
                results = results + a
                if kw.get('and'):
                    currentaci = results
            except errors.NotFound:
                if kw.get('and'):
                    results = []
                    currentaci = []
                pass

# TODO
#  --type=STR         type of IPA object: user, group, host
#  --filter=STR       A legal LDAP filter (ou=Engineering)
#  --subtree=STR      A subtree to apply the ACI to
#  --bindrule=STR      A subtree to apply the ACI to

        # Make sure we have no dupes in the list
        results = list(set(results))

        # the first entry contains the count
        counter = len(results)
        return [counter] + results

    def output_for_cli(self, textui, result, term, **options):
        counter = result[0]
        acis = result[1:]
        if counter == 0 or len(acis) == 0:
            textui.print_plain("No entries found")
            return
        textui.print_name(self.name)
        for a in acis:
            textui.print_plain(a)
        textui.print_count(acis, '%d acis matched')

api.register(aci_find)


class aci_show(crud.Retrieve):
    'Examine an existing aci.'
    def execute(self, aciname, **kw):
        """
        Execute the aci-show operation.

        Returns the entry

        :param uid: The login name of the user to retrieve.
        :param kw: unused
        """
        ldap = self.api.Backend.ldap
        currentaci = ldap.retrieve(self.api.env.basedn, ['aci'])

        a = search_by_name(currentaci.get('aci'), aciname)
        return str(a)

    def output_for_cli(self, textui, result, aciname, **options):
        textui.print_plain(result)

api.register(aci_show)


class aci_showall(Command):
    'Examine all existing acis.'
    def execute(self):
        """
        Execute the aci-show operation.

        Returns the entry

        :param uid: The login name of the user to retrieve.
        :param kw: unused
        """
        ldap = self.api.Backend.ldap
        return ldap.retrieve(self.api.env.basedn, ['aci'])
    def output_for_cli(self, textui, result, **options):
        textui.print_entry(result)

api.register(aci_showall)
