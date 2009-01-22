# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

import shlex
import re
import ldap

# The Python re module doesn't do nested parenthesis

# Break the ACI into 3 pieces: target, name, permissions/bind_rules
ACIPat = re.compile(r'\s*(\(.*\)+)\s*\(version\s+3.0\s*;\s*acl\s+\"(.*)\"\s*;\s*(.*);\)')

# Break the permissions/bind_rules out
PermPat = re.compile(r'(\w+)\s*\((.*)\)\s+(.*)')


class ACI:
    """
    Holds the basic data for an ACI entry, as stored in the cn=accounts
    entry in LDAP.  Has methods to parse an ACI string and export to an
    ACI String.
    """

    # Don't allow arbitrary attributes to be set in our __setattr__ implementation.
    _objectattrs = ["name", "orig_acistr", "target", "action", "permissions",
                   "bindrule"]

    __actions = ["allow", "deny"]

    __permissions = ["read", "write", "add", "delete", "search", "compare",
                   "selfwrite", "proxy", "all"]

    def __init__(self,acistr=None):
        self.name = None
        self.orig_acistr = acistr
        self.target = {}
        self.action = "allow"
        self.permissions = ["write"]
        self.bindrule = None
        if acistr is not None:
            self._parse_acistr(acistr)

    def __getitem__(self,key):
        """Fake getting attributes by key for sorting"""
        if key == 0:
            return self.name
        if key == 1:
            return self.source_group
        if key == 2:
            return self.dest_group
        raise TypeError("Unknown key value %s" % key)

    def __repr__(self):
        """An alias for export_to_string()"""
        return self.export_to_string()

    def __getattr__(self, name):
        """
        Backward compatibility for the old ACI class.

        The following extra attributes are available:

            - source_group
            - dest_group
            - attrs
        """
        if name == 'source_group':
            group = ''
            dn = self.bindrule.split('=',1)
            if dn[0] == "groupdn":
                group = self._remove_quotes(dn[1])
                if group.startswith("ldap:///"):
                    group = group[8:]
            return group
        if name == 'dest_group':
            group = self.target.get('targetfilter', '')
            if group:
                g = group.split('=',1)[1]
                if g.endswith(')'):
                    g = g[:-1]
                return g
            return ''
        if name == 'attrs':
            return self.target.get('targetattr', None)
        raise AttributeError, "object has no attribute '%s'" % name

    def __setattr__(self, name, value):
        """
        Backward compatibility for the old ACI class.

        The following extra attributes are available:
            - source_group
            - dest_group
            - attrs
        """
        if name == 'source_group':
            self.__dict__['bindrule'] = 'groupdn="ldap:///%s"' % value
        elif name == 'dest_group':
            if value.startswith('('):
                self.__dict__['target']['targetfilter'] = 'memberOf=%s' % value
            else:
                self.__dict__['target']['targetfilter'] = '(memberOf=%s)' % value
        elif name == 'attrs':
            self.__dict__['target']['targetattr'] = value
        elif name in self._objectattrs:
            self.__dict__[name] = value
        else:
            raise AttributeError, "object has no attribute '%s'" % name

    def export_to_string(self):
        """Output a Directory Server-compatible ACI string"""
        self.validate()
        aci = ""
        for t in self.target:
            if isinstance(self.target[t], list):
                target = ""
                for l in self.target[t]:
                    target = target + l + " || "
                target = target[:-4]
                aci = aci + "(%s=\"%s\")" % (t, target)
            else:
                aci = aci + "(%s=\"%s\")" % (t, self.target[t])
        aci = aci + "(version 3.0;acl \"%s\";%s (%s) %s" % (self.name, self.action, ",".join(self.permissions), self.bindrule) + ";)"
        return aci

    def _remove_quotes(self, s):
        # Remove leading and trailing quotes
        if s.startswith('"'):
            s = s[1:]
        if s.endswith('"'):
            s = s[:-1]
        return s

    def _parse_target(self, aci):
        lexer = shlex.shlex(aci)
        lexer.wordchars = lexer.wordchars + "."

        l = []

        var = False
        for token in lexer:
            # We should have the form (a = b)(a = b)...
            if token == "(":
                var = lexer.next().strip()
                operator = lexer.next()
                if operator != "=" and operator != "!=":
                    raise SyntaxError('No operator in target, got %s' % operator)
                val = lexer.next().strip()
                val = self._remove_quotes(val)
                end = lexer.next()
                if end != ")":
                    raise SyntaxError('No end parenthesis in target, got %s' % end)

            if var == 'targetattr':
                # Make a string of the form attr || attr || ... into a list
                t = re.split('[\W]+', val)
                self.target[var] = t
            else:
                self.target[var] = val

    def _parse_acistr(self, acistr):
        acimatch = ACIPat.match(acistr)
        if not acimatch or len(acimatch.groups()) < 3:
            raise SyntaxError, "malformed ACI"
        self._parse_target(acimatch.group(1))
        self.name = acimatch.group(2)
        bindperms = PermPat.match(acimatch.group(3))
        if not bindperms or len(bindperms.groups()) < 3:
            raise SyntaxError, "malformed ACI"
        self.action = bindperms.group(1)
        self.permissions = bindperms.group(2).split(',')
        self.bindrule = bindperms.group(3)

    def validate(self):
        """Do some basic verification that this will produce a
           valid LDAP ACI.

           returns True if valid
        """
        if not isinstance(self.permissions, list):
            raise SyntaxError, "permissions must be a list"
        for p in self.permissions:
            if not p.lower() in self.__permissions:
                raise SyntaxError, "invalid permission: '%s'" % p
        if not self.name:
            raise SyntaxError, "name must be set"
        if not isinstance(self.name, basestring):
            raise SyntaxError, "name must be a string"
        if not isinstance(self.target, dict) or len(self.target) == 0:
            raise SyntaxError, "target must be a non-empty dictionary"
        return True

def extract_group_cns(aci_list, client):
    """Extracts all the cn's from a list of aci's and returns them as a hash
       from group_dn to group_cn.

       It first tries to cheat by looking at the first rdn for the
       group dn.  If that's not cn for some reason, it looks up the group."""
    group_dn_to_cn = {}
    for aci in aci_list:
        for dn in (aci.source_group, aci.dest_group):
            if not group_dn_to_cn.has_key(dn):
                rdn_list = ldap.explode_dn(dn, 0)
                first_rdn = rdn_list[0]
                (type,value) = first_rdn.split('=')
                if type == "cn":
                    group_dn_to_cn[dn] = value
                else:
                    try:
                        group = client.get_entry_by_dn(dn, ['cn'])
                        group_dn_to_cn[dn] = group.getValue('cn')
                    except ipaerror.IPAError, e:
                        group_dn_to_cn[dn] = 'unknown'

    return group_dn_to_cn

if __name__ == '__main__':
    # Pass in an ACI as a string
    a = ACI('(targetattr="title")(targetfilter="(memberOf=cn=bar,cn=groups,cn=accounts ,dc=example,dc=com)")(version 3.0;acl "foobar";allow (write) groupdn="ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com";)')
    print a

    # Create an ACI in pieces
    a = ACI()
    a.name ="foobar"
    a.source_group="cn=foo,cn=groups,dc=example,dc=org"
    a.dest_group="cn=bar,cn=groups,dc=example,dc=org"
    a.attrs = ['title']
    a.permissions = ['read','write','add']
    print a
