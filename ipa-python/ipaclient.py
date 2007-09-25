#! /usr/bin/python -E
# Authors: Rob Crittenden <rcritten@redhat.com>
#
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

#!/usr/bin/python

import sys
sys.path.append("/usr/share/ipa")

from ipaserver import funcs
import ipa.rpcclient as rpcclient
import user
import group
import ipa
import config

class IPAClient:

    def __init__(self,local=None):
        self.local = local
        ipa.config.init_config()
        if local:
            self.transport = funcs.IPAServer()
            # client needs to call set_principal(user@REALM)
        else:
            self.transport = rpcclient.RPCClient()

    def set_principal(self,princ):
        """Set the name of the principal that will be used for
           LDAP proxy authentication"""
        if self.local:
            self.transport.set_principal(princ)

    def set_krbccache(self,krbccache):
        """Set the file location of the Kerberos credentials cache to be used
           for LDAP authentication"""
        if self.local:
            self.transport.set_krbccache(krbccache)

# User support
    def get_user_by_uid(self,uid,sattrs=None):
        """Get a specific user by uid. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_user_by_uid(uid,sattrs)
        return user.User(result)

    def get_user_by_dn(self,dn,sattrs=None):
        """Get a specific user by dn. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_user_by_dn(dn,sattrs)
        return user.User(result)

    def get_users_by_manager(self,manager_dn,sattrs=None):
        """Gets the users the report to a particular manager.
           If sattrs is not None then only those
           attributes will be returned, otherwise all available
           attributes are returned. The result is a list of groups."""
        results = self.transport.get_users_by_manager(manager_dn, sattrs)

        return map(lambda result: user.User(result), results)

    def add_user(self,user,user_container=None):
        """Add a user. user is a ipa.user.User object"""

        realm = config.config.get_realm()

        user_dict = user.toDict()

        # dn is set on the server-side
        del user_dict['dn']

        # convert to a regular dict before sending
        result = self.transport.add_user(user_dict, user_container)
        return result

    def get_all_users(self):
        """Get as a list of User objects all users in the directory"""
        result = self.transport.get_all_users()

        all_users = []
        for attrs in result:
            if attrs is not None:
                all_users.append(user.User(attrs))

        return all_users

    def get_add_schema(self):
        """Prototype for the GUI. Specify in the directory fields to
           be displayed and what data to get for new users."""
        result = self.transport.get_add_schema()
        return result

    def find_users(self, criteria, sattrs=None, searchlimit=0):
        """Return a list: counter followed by a User object for each user that
           matches the criteria. If the results are truncated, counter will
           be set to -1"""
        result = self.transport.find_users(criteria, sattrs, searchlimit)
        counter = result[0]

        users = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                users.append(user.User(attrs))

        return users

    def update_user(self,user):
        """Update a user entry."""

        realm = config.config.get_realm()

        result = self.transport.update_user(user.origDataDict(), user.toDict())
        return result

    def delete_user(self,uid):
        """Delete a user entry."""

        realm = config.config.get_realm()

        result = self.transport.delete_user(uid)
        return result

    def modifyPassword(self,uid,oldpass,newpass):
        """Modify a user's password"""

        result = self.transport.modifyPassword(uid,oldpass,newpass)

        return result

    def mark_user_deleted(self,uid):
        """Set a user as inactive by uid."""

        realm = config.config.get_realm()

        result = self.transport.mark_user_deleted(uid)
        return result

# Groups support

    def get_group_by_cn(self,cn,sattrs=None):
        """Get a specific group by cn. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_group_by_cn(cn,sattrs)
        return group.Group(result)

    def get_group_by_dn(self,dn,sattrs=None):
        """Get a specific group by cn. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_group_by_dn(dn,sattrs)
        return group.Group(result)

    def get_groups_by_member(self,member_dn,sattrs=None):
        """Gets the groups that member_dn belongs to.
           If sattrs is not None then only those
           attributes will be returned, otherwise all available
           attributes are returned. The result is a list of groups."""
        results = self.transport.get_groups_by_member(member_dn,sattrs)

        return map(lambda result: group.Group(result), results)

    def add_group(self,group,group_container=None):
        """Add a group. group is a ipa.group.Group object"""

        realm = config.config.get_realm()

        group_dict = group.toDict()

        # dn is set on the server-side
        del group_dict['dn']

        # convert to a regular dict before sending
        result = self.transport.add_group(group_dict, group_container)
        return result

    def find_groups(self, criteria, sattrs=None, searchlimit=0):
        """Find groups whose cn matches the criteria. Wildcards are 
           acceptable. Returns a list of Group objects."""
        result = self.transport.find_groups(criteria, sattrs, searchlimit)
        counter = result[0]

        groups = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                groups.append(group.Group(attrs))

        return groups

    def add_user_to_group(self, user, group):
        """Add a user to an existing group.
           user is a uid of the user to add
           group is the cn of the group to be added to
        """

        return self.transport.add_user_to_group(user, group)

    def add_users_to_group(self, users, group):
        """Add several users to an existing group.
           user is a list of uids of the users to add
           group is the cn of the group to be added to

           Returns a list of the users that were not added.
        """

        return self.transport.add_users_to_group(users, group)

    def remove_user_from_group(self, user, group):
        """Remove a user from an existing group.
           user is a uid of the user to remove
           group is the cn of the group to be removed from
        """

        return self.transport.remove_user_from_group(user, group)

    def remove_users_from_group(self, users, group):
        """Remove several users from an existing group.
           user is a list of uids of the users to remove
           group is the cn of the group to be removed from

           Returns a list of the users that were not removed.
        """

        return self.transport.remove_users_from_group(users, group)

    def update_group(self,group):
        """Update a group entry."""

        return self.transport.update_group(group.origDataDict(), group.toDict())

    def delete_group(self,group_cn):
        """Delete a group entry."""

        return self.transport.delete_group(group_cn)

    def add_group_to_group(self, group_cn, tgroup_cn):
        """Add a group to an existing group.
           group_cn is a cn of the group to add
           tgroup_cn is the cn of the group to be added to
        """

        return self.transport.add_group_to_group(group_cn, tgroup_cn)
