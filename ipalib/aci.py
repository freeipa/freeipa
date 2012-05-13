# Authors:
#   Rob Crittenden <rcritten@redhat.com>
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

import shlex
import re
import ldap

# The Python re module doesn't do nested parenthesis

# Break the ACI into 3 pieces: target, name, permissions/bind_rules
ACIPat = re.compile(r'\(version\s+3.0\s*;\s*acl\s+\"([^\"]*)\"\s*;\s*([^;]*);\s*\)', re.UNICODE)

# Break the permissions/bind_rules out
PermPat = re.compile(r'(\w+)\s*\((.*)\)\s+(.*)', re.UNICODE)

# Break the bind rule out
BindPat = re.compile(r'([a-zA-Z0-9;\.]+)\s*(\!?=)\s*(.*)', re.UNICODE)

ACTIONS = ["allow", "deny"]

PERMISSIONS = ["read", "write", "add", "delete", "search", "compare",
               "selfwrite", "proxy", "all"]

class ACI:
    """
    Holds the basic data for an ACI entry, as stored in the cn=accounts
    entry in LDAP.  Has methods to parse an ACI string and export to an
    ACI String.
    """
    def __init__(self,acistr=None):
        self.name = None
        self.source_group = None
        self.dest_group = None
        self.orig_acistr = acistr
        self.target = {}
        self.action = "allow"
        self.permissions = ["write"]
        self.bindrule = {}
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

    def export_to_string(self):
        """Output a Directory Server-compatible ACI string"""
        self.validate()
        aci = ""
        for t in self.target:
            op = self.target[t]['operator']
            if type(self.target[t]['expression']) in (tuple, list):
                target = ""
                for l in self.target[t]['expression']:
                    target = target + l + " || "
                target = target[:-4]
                aci = aci + "(%s %s \"%s\")" % (t, op, target)
            else:
                aci = aci + "(%s %s \"%s\")" % (t, op, self.target[t]['expression'])
        aci = aci + "(version 3.0;acl \"%s\";%s (%s) %s %s \"%s\"" % (self.name, self.action, ",".join(self.permissions), self.bindrule['keyword'], self.bindrule['operator'], self.bindrule['expression']) + ";)"
        return aci

    def _remove_quotes(self, s):
        # Remove leading and trailing quotes
        if s.startswith('"'):
            s = s[1:]
        if s.endswith('"'):
            s = s[:-1]
        return s

    def _parse_target(self, aci):
        lexer = shlex.shlex(aci.encode('utf-8'))
        lexer.wordchars = lexer.wordchars + "."

        l = []

        var = False
        op = "="
        for token in lexer:
            # We should have the form (a = b)(a = b)...
            if token == "(":
                var = lexer.next().strip()
                operator = lexer.next()
                if operator != "=" and operator != "!=":
                    # Peek at the next char before giving up
                    operator = operator + lexer.next()
                    if operator != "=" and operator != "!=":
                        raise SyntaxError("No operator in target, got '%s'" % operator)
                op = operator
                val = lexer.next().strip()
                val = self._remove_quotes(val)
                end = lexer.next()
                if end != ")":
                    raise SyntaxError('No end parenthesis in target, got %s' % end)

            if var == 'targetattr':
                # Make a string of the form attr || attr || ... into a list
                t = re.split('[^a-zA-Z0-9;\*]+', val)
                self.target[var] = {}
                self.target[var]['operator'] = op
                self.target[var]['expression'] = t
            else:
                self.target[var] = {}
                self.target[var]['operator'] = op
                self.target[var]['expression'] = val

    def _parse_acistr(self, acistr):
        vstart = acistr.find('version 3.0')
        if vstart < 0:
            raise SyntaxError, "malformed ACI, unable to find version %s" % acistr
        acimatch = ACIPat.match(acistr[vstart-1:])
        if not acimatch or len(acimatch.groups()) < 2:
            raise SyntaxError, "malformed ACI, match for version and bind rule failed %s" % acistr
        self._parse_target(acistr[:vstart-1])
        self.name = acimatch.group(1)
        bindperms = PermPat.match(acimatch.group(2))
        if not bindperms or len(bindperms.groups()) < 3:
            raise SyntaxError, "malformed ACI, permissions match failed %s" % acistr
        self.action = bindperms.group(1)
        self.permissions = bindperms.group(2).replace(' ','').split(',')
        self.set_bindrule(bindperms.group(3))

    def validate(self):
        """Do some basic verification that this will produce a
           valid LDAP ACI.

           returns True if valid
        """
        if not type(self.permissions) in (tuple, list):
            raise SyntaxError, "permissions must be a list"
        for p in self.permissions:
            if not p.lower() in PERMISSIONS:
                raise SyntaxError, "invalid permission: '%s'" % p
        if not self.name:
            raise SyntaxError, "name must be set"
        if not isinstance(self.name, basestring):
            raise SyntaxError, "name must be a string"
        if not isinstance(self.target, dict) or len(self.target) == 0:
            raise SyntaxError, "target must be a non-empty dictionary"
        if not isinstance(self.bindrule, dict):
            raise SyntaxError, "bindrule must be a dictionary"
        if not self.bindrule.get('operator') or not self.bindrule.get('keyword') or not self.bindrule.get('expression'):
            raise SyntaxError, "bindrule is missing a component"
        return True

    def set_target_filter(self, filter, operator="="):
        self.target['targetfilter'] = {}
        if not filter.startswith("("):
            filter = "(" + filter + ")"
        self.target['targetfilter']['expression'] = filter
        self.target['targetfilter']['operator'] = operator

    def set_target_attr(self, attr, operator="="):
        if not attr:
            if 'targetattr' in self.target:
                del self.target['targetattr']
            return
        if not type(attr) in (tuple, list):
            attr = [attr]
        self.target['targetattr'] = {}
        self.target['targetattr']['expression'] = attr
        self.target['targetattr']['operator'] = operator

    def set_target(self, target, operator="="):
        assert target.startswith("ldap:///")
        self.target['target'] = {}
        self.target['target']['expression'] = target
        self.target['target']['operator'] = operator

    def set_bindrule(self, bindrule):
        match = BindPat.match(bindrule)
        if not match or len(match.groups()) < 3:
            raise SyntaxError, "malformed bind rule"
        self.set_bindrule_keyword(match.group(1))
        self.set_bindrule_operator(match.group(2))
        self.set_bindrule_expression(match.group(3).replace('"',''))

    def set_bindrule_keyword(self, keyword):
        self.bindrule['keyword'] = keyword

    def set_bindrule_operator(self, operator):
        self.bindrule['operator'] = operator

    def set_bindrule_expression(self, expression):
        self.bindrule['expression'] = expression

    def isequal(self, b):
        """
        Compare the current ACI to another one to see if they are
        the same.

        returns True if equal, False if not.
        """
        assert isinstance(b, ACI)
        try:
            if self.name.lower() != b.name.lower():
                return False

            if set(self.permissions) != set(b.permissions):
                return False

            if self.bindrule.get('keyword') != b.bindrule.get('keyword'):
                return False
            if self.bindrule.get('operator') != b.bindrule.get('operator'):
                return False
            if self.bindrule.get('expression') != b.bindrule.get('expression'):
                return False

            if self.target.get('targetfilter',{}).get('expression') != b.target.get('targetfilter',{}).get('expression'):
                return False
            if self.target.get('targetfilter',{}).get('operator') != b.target.get('targetfilter',{}).get('operator'):
                return False

            if set(self.target.get('targetattr', {}).get('expression', ())) != set(b.target.get('targetattr',{}).get('expression', ())):
                return False
                if self.target.get('targetattr',{}).get('operator') != b.target.get('targetattr',{}).get('operator'):
                    return False

            if self.target.get('target',{}).get('expression') != b.target.get('target',{}).get('expression'):
                return False
            if self.target.get('target',{}).get('operator') != b.target.get('target',{}).get('operator'):
                return False

        except Exception:
            # If anything throws up then they are not equal
            return False

        # We got this far so lets declare them the same
        return True

if __name__ == '__main__':
#    a = ACI('(targetattr="title")(targetfilter="(memberOf=cn=bar,cn=groups,cn=accounts ,dc=example,dc=com)")(version 3.0;acl "foobar";allow (write) groupdn="ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com";)')
#    print a
#    a = ACI('(target="ldap:///uid=bjensen,dc=example,dc=com")(targetattr=*) (version 3.0;acl "aci1";allow (write) userdn="ldap:///self";)')
#    print a
#    a = ACI(' (targetattr = "givenName || sn || cn || displayName || title || initials || loginShell || gecos || homePhone || mobile || pager || facsimileTelephoneNumber || telephoneNumber || street || roomNumber || l || st || postalCode || manager || secretary || description || carLicense || labeledURI || inetUserHTTPURL || seeAlso || employeeType  || businessCategory || ou")(version 3.0;acl "Self service";allow (write) userdn = "ldap:///self";)')
#    print a

    a = ACI('(target="ldap:///uid=*,cn=users,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user";allow (add) groupdn="ldap:///cn=add_user,cn=taskgroups,dc=example,dc=com";)')
    print a
    print "---"

    a = ACI('(targetattr=member)(target="ldap:///cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user_to_default_group";allow (write) groupdn="ldap:///cn=add_user_to_default_group,cn=taskgroups,dc=example,dc=com";)')
    print a
    print "---"

    a = ACI('(targetattr!=member)(target="ldap:///cn=ipausers,cn=groups,cn=accounts,dc=example,dc=com")(version 3.0;acl "add_user_to_default_group";allow (write) groupdn="ldap:///cn=add_user_to_default_group,cn=taskgroups,dc=example,dc=com";)')
    print a
    print "---"

    a = ACI('(targetattr = "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0; acl "change_password"; allow (write) groupdn = "ldap:///cn=change_password,cn=taskgroups,dc=example,dc=com";)')
    print a
    print "---"

    a = ACI()
    a.name ="foo"
    a.set_target_attr(['title','givenname'], "!=")
#    a.set_bindrule("groupdn = \"ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com\"")
    a.set_bindrule_keyword("groupdn")
    a.set_bindrule_operator("=")
    a.set_bindrule_expression ("\"ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com\"")
    a.permissions = ['read','write','add']
    print a

    b = ACI()
    b.name ="foo"
    b.set_target_attr(['givenname','title'], "!=")
    b.set_bindrule_keyword("groupdn")
    b.set_bindrule_operator("=")
    b.set_bindrule_expression ("\"ldap:///cn=foo,cn=groups,cn=accounts,dc=example,dc=com\"")
    b.permissions = ['add','read','write']
    print b

    print a.isequal(b)

    a = ACI('(targetattr != "userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory || krbMKey")(version 3.0; acl "Enable Anonymous access"; allow (read, search, compare) userdn = "ldap:///anyone";)')
    print a

    a = ACI('(targetfilter = "(|(objectClass=person)(objectClass=krbPrincipalAux)(objectClass=posixAccount)(objectClass=groupOfNames)(objectClass=posixGroup))")(targetattr != "aci || userPassword || krbPrincipalKey || sambaLMPassword || sambaNTPassword || passwordHistory")(version 3.0; acl "Account Admins can manage Users and Groups"; allow (add, delete, read, write) groupdn = "ldap:///cn=admins,cn=groups,cn=accounts,dc=greyoak,dc=com";)')
    print a
