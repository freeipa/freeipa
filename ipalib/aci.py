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

import six

# The Python re module doesn't do nested parenthesis

# Break the ACI into 3 pieces: target, name, permissions/bind_rules
ACIPat = re.compile(r'\(version\s+3.0\s*;\s*ac[li]\s+\"([^\"]*)\"\s*;'
                    r'\s*(.*);\s*\)', re.UNICODE)

# Break the permissions/bind_rules out.
#
# The action may carry the 389-ds "absolute" keyword
# (e.g. "deny absolute (add,delete,write) ..."); such a rule is final: when
# its bind rule matches, its decision is returned without consulting the
# other rules. It is captured so it round-trips through export.
PermPat = re.compile(r'(\w+)\s*(absolute\s+)?\(([^()]*)\)\s*(.*)',
                     re.UNICODE)

# Break the bind rule out.
#
# The primary term is "keyword op "value"" (optionally wrapped in parentheses).
# The value is matched non-greedily (it never contains a double quote), and
# anything that follows - an "and"/"or"/"not" continuation such as a second
# userattr/groupdn clause (the RBCD and OTP rules use them) - is captured as a
# trailing group and preserved verbatim (see set_bindrule / bindrule_suffix).
# This lets compound bind rules round-trip while keeping bindrule['expression']
# the plain primary grantee (e.g. "ldap:///self") that the rest of the code
# inspects. A single-term rule matches exactly as before with an empty trailer.
# A compound rule wrapped in its own outer parentheses (the self-service
# "(userdn = \"ldap:///self\" and userdn = \"ldap:///all\")" rules) is unwrapped
# by set_bindrule before matching, and the wrapping is restored on export.
BindPat = re.compile(r'\(?([a-zA-Z0-9;\.]+)\s*(\!?=)\s*\"([^\"]*)\"\)?(.*)',
                     re.UNICODE)

ACTIONS = ["allow", "deny"]

PERMISSIONS = ["read", "write", "add", "delete", "search", "compare",
               "selfwrite", "proxy", "all"]


class ACI:
    """
    Holds the basic data for an ACI entry, as stored in the cn=accounts
    entry in LDAP.  Has methods to parse an ACI string and export to an
    ACI String.
    """
    __hash__ = None

    def __init__(self,acistr=None):
        self.name = None
        self.source_group = None
        self.dest_group = None
        self.orig_acistr = acistr
        self.target = {}
        self.action = "allow"
        self.absolute = False
        self.permissions = ["write"]
        self.bindrule = {}
        self.bindrule_suffix = None
        self.bindrule_parenthesized = False
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
        for t, v in sorted(self.target.items()):
            op = v['operator']
            if type(v['expression']) in (tuple, list):
                target = ""
                for l in self._unique_list(v['expression']):
                    target = target + l + " || "
                target = target[:-4]
                aci = aci + "(%s %s \"%s\")" % (t, op, target)
            else:
                aci = aci + "(%s %s \"%s\")" % (t, op, v['expression'])
        aci = aci + "(version 3.0;acl \"%s\";%s%s (%s) %s" % (
            self.name,
            self.action,
            " absolute" if self.absolute else "",
            ",".join(self.permissions),
            self.export_bindrule(),
        )
        aci = aci + ";)"
        return aci

    def export_bindrule(self):
        """The bind rule in Directory Server syntax: the primary term plus
        any continuation clause, re-wrapped if the rule was fully
        parenthesized."""
        bindrule = '%s %s "%s"' % (
            self.bindrule['keyword'],
            self.bindrule['operator'],
            self.bindrule['expression'],
        )
        if self.bindrule_suffix:
            bindrule = bindrule + " " + self.bindrule_suffix
        if self.bindrule_parenthesized:
            bindrule = "(%s)" % bindrule
        return bindrule

    def _unique_list(self, l):
        """
        A set() doesn't maintain order so make a list unique ourselves.

        The number of entries in our lists are always going to be
        relatively low and this code will be called infrequently
        anyway so the overhead will be small.
        """
        unique = []
        for item in l:
            if item not in unique:
                unique.append(item)
        return unique

    def _remove_quotes(self, s):
        # Remove leading and trailing quotes
        if s.startswith('"'):
            s = s[1:]
        if s.endswith('"'):
            s = s[:-1]
        return s

    def _parse_target(self, aci):
        if six.PY2:
            aci = aci.encode('utf-8')
        lexer = shlex.shlex(aci)
        lexer.wordchars = lexer.wordchars + "."

        var = False
        op = "="
        for token in lexer:
            # We should have the form (a = b)(a = b)...
            if token == "(":
                var = next(lexer).strip()
                operator = next(lexer)
                if operator not in ("=", "!="):
                    # Peek at the next char before giving up
                    operator = operator + next(lexer)
                    if operator not in ("=", "!="):
                        raise SyntaxError("No operator in target, got '%s'" % operator)
                op = operator
                val = next(lexer).strip()
                val = self._remove_quotes(val)
                end = next(lexer)
                if end != ")":
                    raise SyntaxError('No end parenthesis in target, got %s' % end)

            if var == 'targetattr':
                # Make a string of the form attr || attr || ... into a list
                t = re.split(r'[^a-zA-Z0-9;\*]+', val)
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
            raise SyntaxError("malformed ACI, unable to find version %s" % acistr)
        acimatch = ACIPat.match(acistr[vstart-1:])
        if not acimatch or len(acimatch.groups()) < 2:
            raise SyntaxError("malformed ACI, match for version and bind rule failed %s" % acistr)
        self._parse_target(acistr[:vstart-1])
        self.name = acimatch.group(1)
        bindperms = PermPat.match(acimatch.group(2))
        if not bindperms or len(bindperms.groups()) < 4:
            raise SyntaxError("malformed ACI, permissions match failed %s" % acistr)
        self.action = bindperms.group(1)
        self.absolute = bool(bindperms.group(2))
        self.permissions = self._unique_list(
            bindperms.group(3).replace(' ','').split(',')
        )
        self.set_bindrule(bindperms.group(4))

    def validate(self):
        """Do some basic verification that this will produce a
           valid LDAP ACI.

           returns True if valid
        """
        if type(self.permissions) not in (tuple, list):
            raise SyntaxError("permissions must be a list")
        for p in self.permissions:
            if p.lower() not in PERMISSIONS:
                raise SyntaxError("invalid permission: '%s'" % p)
        if not self.name:
            raise SyntaxError("name must be set")
        if not isinstance(self.name, str):
            raise SyntaxError("name must be a string")
        if not isinstance(self.target, dict) or len(self.target) == 0:
            raise SyntaxError("target must be a non-empty dictionary")
        if not isinstance(self.bindrule, dict):
            raise SyntaxError("bindrule must be a dictionary")
        if not self.bindrule.get('operator') or not self.bindrule.get('keyword') or not self.bindrule.get('expression'):
            raise SyntaxError("bindrule is missing a component")
        return True

    def set_permissions(self, permissions):
        if type(permissions) not in (tuple, list):
            permissions = [permissions]
        self.permissions = self._unique_list(permissions)

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
        if type(attr) not in (tuple, list):
            attr = [attr]
        self.target['targetattr'] = {}
        self.target['targetattr']['expression'] = self._unique_list(attr)
        self.target['targetattr']['operator'] = operator

    def set_target(self, target, operator="="):
        assert target.startswith("ldap:///")
        self.target['target'] = {}
        self.target['target']['expression'] = target
        self.target['target']['operator'] = operator

    @staticmethod
    def _outer_parens_wrap(s):
        """True if the whole rule is wrapped in one outer pair of
        parentheses: s starts with '(' and that first '(' closes exactly at
        the last character ('(a = "x" and b = "y")' is, '(a = "x") or
        (b = "y")' and 'a = "x" or (b = "y")' are not)."""
        if not s.startswith('('):
            return False
        depth = 0
        for i, ch in enumerate(s):
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    return i == len(s) - 1
        return False

    def set_bindrule(self, bindrule):
        bindrule = bindrule.strip()
        # Parenthesis balance is a cheap sanity check that also accepts
        # compound rules (e.g. two or/and-combined userattr clauses, or the
        # fully parenthesized self-service rule), which the previous
        # startswith('(') != endswith(')') test rejected.
        if bindrule.count('(') != bindrule.count(')'):
            raise SyntaxError("non-matching parentheses in bindrule")
        # A compound rule may be wrapped in its own outer parentheses; parse
        # the content and remember the wrapping so the rule round-trips
        # verbatim through export.
        self.bindrule_parenthesized = self._outer_parens_wrap(bindrule)
        if self.bindrule_parenthesized:
            bindrule = bindrule[1:-1]

        match = BindPat.match(bindrule)
        if not match or len(match.groups()) < 3:
            raise SyntaxError("malformed bind rule")
        self.set_bindrule_keyword(match.group(1))
        self.set_bindrule_operator(match.group(2))
        self.set_bindrule_expression(match.group(3).replace('"',''))
        # Everything after the primary term (an and/or/not continuation) is
        # kept verbatim so the bind rule round-trips through export.
        suffix = match.group(4).strip()
        self.set_bindrule_suffix(suffix or None)

    def set_bindrule_keyword(self, keyword):
        self.bindrule['keyword'] = keyword

    def set_bindrule_operator(self, operator):
        self.bindrule['operator'] = operator

    def set_bindrule_expression(self, expression):
        self.bindrule['expression'] = expression

    def set_bindrule_suffix(self, suffix):
        """Set an optional extra bind-rule clause (an "and"/"or" continuation
        such as a second userattr/groupdn clause) appended after the primary
        term. None clears it."""
        self.bindrule_suffix = suffix

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
            if self.bindrule_suffix != b.bindrule_suffix:
                return False
            if self.absolute != b.absolute:
                return False
            if self.bindrule_parenthesized != b.bindrule_parenthesized:
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

    __eq__ = isequal

    def __ne__(self, b):
        return not self == b
