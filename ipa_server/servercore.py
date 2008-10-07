# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2007  Red Hat
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
#

import ldap
from ipa_server.context import context
import ipautil

# temporary
import krbV

krbctx = krbV.default_context()
realm = krbctx.default_realm
basedn = ipautil.realm_to_suffix(realm)

DefaultUserContainer = "cn=users,cn=accounts"
DefaultGroupContainer = "cn=groups,cn=accounts"
DefaultServiceContainer = "cn=services,cn=accounts"

def convert_entry(ent):
    entry = dict(ent.data)
    entry['dn'] = ent.dn
    # For now convert single entry lists to a string for the ui.
    # TODO: we need to deal with multi-values better
    for key,value in entry.iteritems():
        if isinstance(value,list) or isinstance(value,tuple):
            if len(value) == 0:
                entry[key] = ''
            elif len(value) == 1:
                entry[key] = value[0]
    return entry

def convert_scalar_values(orig_dict):
    """LDAP update dicts expect all values to be a list (except for dn).
       This method converts single entries to a list."""
    new_dict={}
    for (k,v) in orig_dict.iteritems():
        if not isinstance(v, list) and k != 'dn':
            v = [v]
        new_dict[k] = v

    return new_dict


# TODO: rethink the get_entry vs get_list API calls.
#       they currently restrict the data coming back without
#       restricting scope.  For now adding a get_base/sub_entry()
#       calls, but the API isn't great.
def get_entry (base, scope, searchfilter, sattrs=None):
    """Get a specific entry (with a parametized scope).
       Return as a dict of values.
       Multi-valued fields are represented as lists.
    """
    ent=""

    ent = context.conn.getConn().getEntry(base, scope, searchfilter, sattrs)

    return convert_entry(ent)

def get_base_entry (base, searchfilter, sattrs=None):
    """Get a specific entry (with a scope of BASE).
       Return as a dict of values.
       Multi-valued fields are represented as lists.
    """
    return get_entry(base, ldap.SCOPE_BASE, searchfilter, sattrs)

def get_sub_entry (base, searchfilter, sattrs=None):
    """Get a specific entry (with a scope of SUB).
       Return as a dict of values.
       Multi-valued fields are represented as lists.
    """
    return get_entry(base, ldap.SCOPE_SUBTREE, searchfilter, sattrs)

def get_list (base, searchfilter, sattrs=None):
    """Gets a list of entries. Each is converted to a dict of values.
       Multi-valued fields are represented as lists.
    """
    entries = []

    entries = context.conn.getConn().getList(base, ldap.SCOPE_SUBTREE, searchfilter, sattrs)

    return map(convert_entry, entries)

# General searches

def get_entry_by_dn (dn, sattrs=None):
    """Get a specific entry. Return as a dict of values.
       Multi-valued fields are represented as lists.
    """
    searchfilter = "(objectClass=*)"
#    logging.info("IPA: get_entry_by_dn '%s'" % dn)
    return get_base_entry(dn, searchfilter, sattrs)

# User support

def is_user_unique(uid):
    """Return True if the uid is unique in the tree, False otherwise."""
    # FIXME
#    uid = self.__safe_filter(uid)
    searchfilter = "(&(uid=%s)(objectclass=posixAccount))" % uid

    try:
        entry = get_sub_entry("cn=accounts," + basedn, searchfilter, ['dn','uid'])
        return False
#    except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
    except Exception:
        return True

def uid_too_long(uid):
    """Verify that the new uid is within the limits we set. This is a
       very narrow test.

       Returns True if it is longer than allowed
               False otherwise
    """
    if not isinstance(uid,basestring) or len(uid) == 0:
        # It is bad, but not too long
        return False
#    logging.debug("IPA: __uid_too_long(%s)" % uid)
    try:
        config = get_ipa_config()
        maxlen = int(config.get('ipamaxusernamelength', 0))
        if maxlen > 0 and len(uid) > maxlen:
            return True
    except Exception, e:
#        logging.debug("There was a problem " + str(e))
        pass

    return False

def update_entry (oldentry, newentry):
    """Update an LDAP entry

       oldentry is a dict
       newentry is a dict
    """
    oldentry = convert_scalar_values(oldentry)
    newentry = convert_scalar_values(newentry)

    # Should be able to get this from either the old or new entry
    # but just in case someone has decided to try changing it, use the
    # original
    try:
        moddn = oldentry['dn']
    except KeyError, e:
        # FIXME: return a missing DN error message
        raise e

    res = context.conn.getConn().updateEntry(moddn, oldentry, newentry)
    return res

def add_entry(entry):
    """Add a new entry"""
    return context.conn.getConn().addEntry(entry)

def uniq_list(x):
    """Return a unique list, preserving order and ignoring case"""
    myset = {}
    return [myset.setdefault(e.lower(),e) for e in x if e.lower() not in myset]

def get_schema():
    """Retrieves the current LDAP schema from the LDAP server."""

    schema_entry = get_base_entry("", "objectclass=*", ['dn','subschemasubentry'])
    schema_cn = schema_entry.get('subschemasubentry')
    schema = get_base_entry(schema_cn, "objectclass=*", ['*'])

    return schema

def get_objectclasses():
    """Returns a list of available objectclasses that the LDAP
       server supports. This parses out the syntax, attributes, etc
       and JUST returns a lower-case list of the names."""

    schema = get_schema()

    objectclasses = schema.get('objectclasses')

    # Convert this list into something more readable
    result = []
    for i in range(len(objectclasses)):
        oc = objectclasses[i].lower().split(" ")
        result.append(oc[3].replace("'",""))

    return result

def get_ipa_config():
    """Retrieve the IPA configuration"""
    searchfilter = "cn=ipaconfig"
    try:
        config = get_sub_entry("cn=etc," + basedn, searchfilter)
    except ldap.NO_SUCH_OBJECT, e:
        # FIXME
        raise e

    return config
