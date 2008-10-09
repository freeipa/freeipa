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
import string
import re
from ipa_server.context import context
import ipautil
from ipalib import errors

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

def generate_match_filters(search_fields, criteria_words):
    """Generates a search filter based on a list of words and a list
       of fields to search against.

       Returns a tuple of two filters: (exact_match, partial_match)"""

    # construct search pattern for a single word
    # (|(f1=word)(f2=word)...)
    search_pattern = "(|"
    for field in search_fields:
        search_pattern += "(" + field + "=%(match)s)"
    search_pattern += ")"
    gen_search_pattern = lambda word: search_pattern % {'match':word}

    # construct the giant match for all words
    exact_match_filter = "(&"
    partial_match_filter = "(|"
    for word in criteria_words:
        exact_match_filter += gen_search_pattern(word)
        partial_match_filter += gen_search_pattern("*%s*" % word)
    exact_match_filter += ")"
    partial_match_filter += ")"

    return (exact_match_filter, partial_match_filter)

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

def user_exists(uid):
    """Return True if the exists, False otherwise."""
    # FIXME: fix the filter
    # FIXME: should accept a container to look in
#    uid = self.__safe_filter(uid)
    searchfilter = "(&(uid=%s)(objectclass=posixAccount))" % uid

    try:
        entry = get_sub_entry("cn=accounts," + basedn, searchfilter, ['dn','uid'])
        return False
#    except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
    except Exception:
        return True

def get_user_by_uid (uid, sattrs):
    """Get a specific user's entry. Return as a dict of values.
       Multi-valued fields are represented as lists.
    """

    if not isinstance(uid,basestring) or len(uid) == 0:
        raise SyntaxError("uid is not a string")
#        raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
    if sattrs is not None and not isinstance(sattrs,list):
        raise SyntaxError("sattrs is not a list")
#        raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
#    logging.info("IPA: get_user_by_uid '%s'" % uid)
#    uid = self.__safe_filter(uid)
    searchfilter = "(uid=" + uid + ")"
    return get_sub_entry("cn=accounts," + basedn, searchfilter, sattrs)

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

def find_users (criteria, sattrs, sizelimit=-1, timelimit=-1):
    """Returns a list: counter followed by the results.
       If the results are truncated, counter will be set to -1."""

    """
    if not isinstance(criteria,basestring) or len(criteria) == 0:
        raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
    if sattrs is not None and not isinstance(sattrs, list):
        raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
    if not isinstance(sizelimit,int):
        raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
    if not isinstance(timelimit,int):
        raise ipaerror.gen_exception(ipaerror.INPUT_INVALID_PARAMETER)
    """

#    logging.info("IPA: find_users '%s'" % criteria)
    config = get_ipa_config()
    if timelimit < 0:
        timelimit = float(config.get('ipasearchtimelimit'))
    if sizelimit < 0:
        sizelimit = int(config.get('ipasearchrecordslimit'))

    # Assume the list of fields to search will come from a central
    # configuration repository.  A good format for that would be
    # a comma-separated list of fields
    search_fields_conf_str = config.get('ipausersearchfields')
    search_fields = string.split(search_fields_conf_str, ",")

#    criteria = self.__safe_filter(criteria)
    criteria_words = re.split(r'\s+', criteria)
    criteria_words = filter(lambda value:value!="", criteria_words)
    if len(criteria_words) == 0:
        return [0]

    (exact_match_filter, partial_match_filter) = generate_match_filters(
            search_fields, criteria_words)

    #
    # further constrain search to just the objectClass
    # TODO - need to parameterize this into generate_match_filters,
    #        and work it into the field-specification search feature
    #
    exact_match_filter = "(&(objectClass=person)%s)" % exact_match_filter
    partial_match_filter = "(&(objectClass=person)%s)" % partial_match_filter

    try:
        exact_results = context.conn.getConn().getListAsync("cn=accounts," + basedn, ldap.SCOPE_SUBTREE, exact_match_filter, sattrs, 0, None, None, timelimit, sizelimit)
#    except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
    except Exception:
        exact_results = [0]

    try:
        partial_results = context.conn.getConn().getListAsync("cn=accounts," + basedn, ldap.SCOPE_SUBTREE, partial_match_filter, sattrs, 0, None, None, timelimit, sizelimit)
#    except ipaerror.exception_for(ipaerror.LDAP_NOT_FOUND):
    except Exception:
        partial_results = [0]

    exact_counter = exact_results[0]
    partial_counter = partial_results[0]

    exact_results = exact_results[1:]
    partial_results = partial_results[1:]

    # Remove exact matches from the partial_match list
    exact_dns = set(map(lambda e: e.dn, exact_results))
    partial_results = filter(lambda e: e.dn not in exact_dns,
                             partial_results)

    if (exact_counter == -1) or (partial_counter == -1):
        counter = -1
    else:
        counter = len(exact_results) + len(partial_results)

    users = [counter]
    for u in exact_results + partial_results:
        users.append(convert_entry(u))

    return users

def update_entry (entry):
    """Update an LDAP entry

       entry is a dict

       This refreshes the record from LDAP in order to obtain the list of
       attributes that has changed.
    """
    attrs = entry.keys()
    o = get_base_entry(entry['dn'], "objectclass=*", attrs)
    oldentry = convert_scalar_values(o)
    newentry = convert_scalar_values(entry)

    # Should be able to get this from either the old or new entry
    # but just in case someone has decided to try changing it, use the
    # original
    try:
        moddn = oldentry['dn']
    except KeyError, e:
        # FIXME: return a missing DN error message
        raise e

    return context.conn.getConn().updateEntry(moddn, oldentry, newentry)

def add_entry(entry):
    """Add a new entry"""
    return context.conn.getConn().addEntry(entry)

def delete_entry(dn):
    """Remove an entry"""
    return context.conn.getConn().deleteEntry(dn)

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
        raise errors.NotFound

    return config
