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
from ipa_server import ipaldap
import ipautil
from ipalib import errors
from ipalib import api

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

def has_nsaccountlock(dn):
    """Check to see if an entry has the nsaccountlock attribute.
       This attribute is provided by the Class of Service plugin so
       doing a search isn't enough. It is provided by the two
       entries cn=inactivated and cn=activated. So if the entry has
       the attribute and isn't in either cn=activated or cn=inactivated
       then the attribute must be in the entry itself.

       Returns True or False
    """
    # First get the entry. If it doesn't have nsaccountlock at all we
    # can exit early.
    entry = get_entry_by_dn(dn, ['dn', 'nsaccountlock', 'memberof'])
    if not entry.get('nsaccountlock'):
        return False

    # Now look to see if they are in activated or inactivated
    # entry is a member
    memberof = entry.get('memberof')
    if isinstance(memberof, basestring):
        memberof = [memberof]
    for m in memberof:
        inactivated = m.find("cn=inactivated")
        activated = m.find("cn=activated")
        # if they are in either group that means that the nsaccountlock
        # value comes from there, otherwise it must be in this entry.
        if inactivated >= 0 or activated >= 0:
            return False

    return True

# General searches

def get_entry_by_dn (dn, sattrs=None):
    """Get a specific entry. Return as a dict of values.
       Multi-valued fields are represented as lists.
    """
    searchfilter = "(objectClass=*)"
#    logging.info("IPA: get_entry_by_dn '%s'" % dn)
    return get_base_entry(dn, searchfilter, sattrs)

def get_entry_by_cn (cn, sattrs):
    """Get a specific entry by cn. Return as a dict of values.
       Multi-valued fields are represented as lists.
    """
#    logging.info("IPA: get_entry_by_cn '%s'" % cn)
#    cn = self.__safe_filter(cn)
    searchfilter = "(cn=%s)" % cn 
    return get_sub_entry("cn=accounts," + api.env.basedn, searchfilter, sattrs)

def get_user_by_uid(uid, sattrs):
    """Get a specific user's entry."""
    # FIXME: should accept a container to look in
#    uid = self.__safe_filter(uid)
    searchfilter = "(&(uid=%s)(objectclass=person))" % uid

    return get_sub_entry("cn=accounts," + api.env.basedn, searchfilter, sattrs)

# User support

def entry_exists(dn):
    """Return True if the entry exists, False otherwise."""
    try:
        get_base_entry(dn, "objectclass=*", ['dn','objectclass'])
        return True
    except errors.NotFound:
        return False

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
    return get_sub_entry("cn=accounts," + api.env.basedn, searchfilter, sattrs)

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

# FIXME, get time and search limit from cn=ipaconfig
def search(base, filter, attributes, timelimit=1, sizelimit=3000):
    """Perform an LDAP query"""
    try:
        timelimit = float(timelimit)
        results = context.conn.getConn().getListAsync(base, ldap.SCOPE_SUBTREE,
            filter, attributes, 0, None, None, timelimit, sizelimit)
    except ldap.NO_SUCH_OBJECT:
        raise errors.NotFound

    counter = results[0]
    entries = [counter]
    for r in results[1:]:
        entries.append(convert_entry(r))

    return entries

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
        config = get_sub_entry("cn=etc," + api.env.basedn, searchfilter)
    except ldap.NO_SUCH_OBJECT, e:
        # FIXME
        raise errors.NotFound

    return config

def mark_entry_active (dn):
    """Mark an entry as active in LDAP."""

    # This can be tricky. The entry itself can be marked inactive
    # by being in the inactivated group. It can also be inactivated by
    # being the member of an inactive group.
    #
    # First we try to remove the entry from the inactivated group. Then
    # if it is still inactive we have to add it to the activated group
    # which will override the group membership.

    res = ""
    # First, check the entry status
    entry = get_entry_by_dn(dn, ['dn', 'nsAccountlock'])

    if entry.get('nsaccountlock', 'false').lower() == "false":
#        logging.debug("IPA: already active")
        raise errors.AlreadyActiveError

    if has_nsaccountlock(dn):
#        logging.debug("IPA: appears to have the nsaccountlock attribute")
        raise errors.HasNSAccountLock

    group = get_entry_by_cn("inactivated", None)
    try:
        remove_member_from_group(entry.get('dn'), group.get('dn'))
    except errors.NotGroupMember:
        # Perhaps the user is there as a result of group membership
        pass

    # Now they aren't a member of inactivated directly, what is the status
    # now?
    entry = get_entry_by_dn(dn, ['dn', 'nsAccountlock'])

    if entry.get('nsaccountlock', 'false').lower() == "false":
        # great, we're done
#        logging.debug("IPA: removing from inactivated did it.")
        return res

    # So still inactive, add them to activated
    group = get_entry_by_cn("activated", None)
    res = add_member_to_group(dn, group.get('dn'))
#    logging.debug("IPA: added to activated.")

    return res

def mark_entry_inactive (dn):
    """Mark an entry as inactive in LDAP."""

    entry = get_entry_by_dn(dn, ['dn', 'nsAccountlock', 'memberOf'])

    if entry.get('nsaccountlock', 'false').lower() == "true":
#        logging.debug("IPA: already marked as inactive")
        raise errors.AlreadyInactiveError

    if has_nsaccountlock(dn):
#        logging.debug("IPA: appears to have the nsaccountlock attribute")
        raise errors.HasNSAccountLock

    # First see if they are in the activated group as this will override
    # the our inactivation.
    group = get_entry_by_cn("activated", None)
    try:
        remove_member_from_group(dn, group.get('dn'))
    except errors.NotGroupMember:
        # this is fine, they may not be explicitly in this group
        pass

    # Now add them to inactivated
    group = get_entry_by_cn("inactivated", None)
    res = add_member_to_group(dn, group.get('dn'))

    return res

def add_member_to_group(member_dn, group_dn):
    """Add a member to an existing group."""
#    logging.info("IPA: add_member_to_group '%s' to '%s'" % (member_dn, group_dn))
    if member_dn.lower() == group_dn.lower():
        # You can't add a group to itself
        raise errors.SameGroupError

    group = get_entry_by_dn(group_dn, None)
    if group is None:
        raise errors.NotFound

    # check to make sure member_dn exists
    member_entry = get_base_entry(member_dn, "(objectClass=*)", ['dn','objectclass'])
    if not member_entry:
        raise errors.NotFound

    if group.get('member') is not None:
        if isinstance(group.get('member'),basestring):
            group['member'] = [group['member']]
        group['member'].append(member_dn)
    else:
        group['member'] = member_dn

    try:
        return update_entry(group)
    except errors.EmptyModlist:
        raise

def remove_member_from_group(member_dn, group_dn=None):
    """Remove a member_dn from an existing group."""

    group = get_entry_by_dn(group_dn, None)
    if group is None:
        raise errors.NotFound
    """
    if group.get('cn') == "admins":
        member = get_entry_by_dn(member_dn, ['dn','uid'])
        if member.get('uid') == "admin":
            raise ipaerror.gen_exception(ipaerror.INPUT_ADMIN_REQUIRED_IN_ADMINS)
    """
#    logging.info("IPA: remove_member_from_group '%s' from '%s'" % (member_dn, group_dn))

    if group.get('member') is not None:
        if isinstance(group.get('member'),basestring):
            group['member'] = [group['member']]
        for i in range(len(group['member'])):
            group['member'][i] = ipaldap.IPAdmin.normalizeDN(group['member'][i])
        try:
            group['member'].remove(member_dn)
        except ValueError:
            # member is not in the group
            # FIXME: raise more specific error?
            raise errors.NotGroupMember
    else:
        # Nothing to do if the group has no members
        raise errors.NotGroupMember

    try:
        return update_entry(group)
    except errors.EmptyModlist:
        raise
