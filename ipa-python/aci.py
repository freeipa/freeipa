# Copyright (C) 2007    Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 or later
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import re
import urllib
import ldap

import ipa.ipautil

class ACI:
    """
    Holds the basic data for an ACI entry, as stored in the cn=accounts
    entry in LDAP.  Has methods to parse an ACI string and export to an
    ACI String.
    """

    def __init__(self,acistr=None):
        self.name = ''
        self.source_group = ''
        self.dest_group = ''
        self.attrs = []
        self.orig_acistr = acistr
        if acistr is not None:
            self.parse_acistr(acistr)

    def __getitem__(self,key):
        """Fake getting attributes by key for sorting"""
        if key == 0:
            return self.name
        if key == 1:
            return self.source_group
        if key == 2:
            return self.dest_group
        raise TypeError("Unknown key value %s" % key)

    def export_to_string(self):
        """Converts the ACI to a string suitable for an LDAP aci attribute."""
        attrs_str = ' || '.join(self.attrs)

        # dest_group and source_group are assumed to be pre-escaped.
        # dn's aren't typed in, but searched for, and the search results
        # will return escaped dns

        acistr = ('(targetattr="%s")' +
                  '(targetfilter="(memberOf=%s)")' +
                  '(version 3.0;' +
                  'acl "%s";' +
                  'allow (write) ' +
                  'groupdn="ldap:///%s";)') % (attrs_str,
                                       self.dest_group,
                                       self.name,
                                       urllib.quote(self.source_group, "/=, "))
        return acistr

    def to_dict(self):
        result = ipa.ipautil.CIDict()
        result['name'] = self.name
        result['source_group'] = self.source_group
        result['dest_group'] = self.dest_group
        result['attrs'] = self.attrs
        result['orig_acistr'] = self.orig_acistr

        return result

    def _match(self, prefix, inputstr):
        """Returns inputstr with prefix removed, or else raises a
           SyntaxError."""
        if inputstr.startswith(prefix):
            return inputstr[len(prefix):]
        else:
            raise SyntaxError, "'%s' not found at '%s'" % (prefix, inputstr)

    def _match_str(self, inputstr):
        """Tries to extract a " delimited string from the front of inputstr.
           Returns (string, inputstr) where:
             - string is the extracted string (minus the enclosing " chars)
             - inputstr is the parameter with the string removed.
           Raises SyntaxError is a string is not found."""
        if not inputstr.startswith('"'):
            raise SyntaxError, "string not found at '%s'" % inputstr

        found = False
        start_index = 1
        final_index = 1
        while not found and (final_index < len(inputstr)):
            if inputstr[final_index] == '\\':
                final_index += 2
            elif inputstr[final_index] == '"':
                found = True
            else:
                final_index += 1
        if not found:
            raise SyntaxError, "string not found at '%s'" % inputstr

        match = inputstr[start_index:final_index]
        inputstr = inputstr[final_index + 1:]

        return(match, inputstr)

    def parse_acistr(self, acistr):
        """Parses the acistr.  If the string isn't recognized, a SyntaxError
           is raised."""
        self.orig_acistr = acistr

        acistr = self._match('(targetattr=', acistr)
        (attrstr, acistr) = self._match_str(acistr)
        self.attrs = attrstr.split(' || ')

        acistr = self._match(')(targetfilter=', acistr)
        (target_dn_str, acistr) = self._match_str(acistr)
        target_dn_str = self._match('(memberOf=', target_dn_str)
        if target_dn_str.endswith(')'):
            self.dest_group = target_dn_str[:-1]
        else:
            raise SyntaxError, "illegal dest_group at '%s'" % target_dn_str

        acistr = self._match(')(version 3.0;acl ', acistr)
        (name_str, acistr) = self._match_str(acistr)
        self.name = name_str

        acistr = self._match(';allow (write) groupdn=', acistr)
        (src_dn_str, acistr) = self._match_str(acistr)
        src_dn_str = self._match('ldap:///', src_dn_str)
        self.source_group = urllib.unquote(src_dn_str)

        acistr = self._match(';)', acistr)
        if len(acistr) > 0:
            raise SyntaxError, "unexpected aci suffix at '%s'" % acistr

def extract_group_cns(aci_list, client):
    """Extracts all the cn's from a list of aci's and returns them as a hash
       from group_dn to group_cn.

       It first tries to cheat by looking at the first rdn for the
       group dn.  If that's not cn for some reason, it looks up the group."""
    group_dn_to_cn = {}
    for aci in aci_list:
        for dn in (aci.source_group, aci.dest_group):
            if not group_dn_to_cn.has_key(dn):
                rdn_list = ldap.dn.str2dn(dn)
                first_rdn = rdn_list[0]
                for (type,value,junk) in first_rdn:
                    if type == "cn":
                        group_dn_to_cn[dn] = value
                        break;
                else:
                    try:
                        group = client.get_entry_by_dn(dn, ['cn'])
                        group_dn_to_cn[dn] = group.getValue('cn')
                    except ipaerror.IPAError, e:
                        group_dn_to_cn[dn] = 'unknown'

    return group_dn_to_cn
