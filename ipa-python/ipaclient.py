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

import ipa.rpcclient as rpcclient
import entity
import user
import group
import radius_util

class IPAClient:

    def __init__(self,transport=None):
        if transport:
            self.local = True
            self.transport = transport
        else:
            self.local = False
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

# Higher-level API

    def get_aci_entry(self, sattrs=None):
        """Returns the entry containing access control ACIs."""

        result = self.transport.get_aci_entry(sattrs)
        return entity.Entity(result)

# General searches

    def get_entry_by_dn(self,dn,sattrs=None):
        """Get a specific entry by dn. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_entry_by_dn(dn,sattrs)
        return entity.Entity(result)

    def get_entry_by_cn(self,cn,sattrs=None):
        """Get a specific entry by cn. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_entry_by_cn(cn,sattrs)
        return entity.Entity(result)

    def update_entry(self,entry):
        """Update a entry."""

        result = self.transport.update_entry(entry.origDataDict(), entry.toDict())
        return result

# User support
    def get_user_by_uid(self,uid,sattrs=None):
        """Get a specific user by uid. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_user_by_uid(uid,sattrs)
        return user.User(result)

    def get_user_by_principal(self,principal,sattrs=None):
        """Get a specific user by uid. If sattrs is set then only those
           attributes will be returned, otherwise all available attributes
           are returned."""
        result = self.transport.get_user_by_principal(principal,sattrs)
        return user.User(result)

    def get_user_by_email(self,email,sattrs=None):
        """Get a specific user's entry. Return as a dict of values.
           Multi-valued fields are represented as lists.
        """
        result = self.transport.get_user_by_email(email,sattrs)
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

        user_dict = user.toDict()

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

    def get_custom_fields(self):
        """Get custom user fields"""
        result = self.transport.get_custom_fields()
        return result

    def set_custom_fields(self, schema):
        """Set custom user fields"""
        result = self.transport.set_custom_fields(schema)
        return result

    def find_users(self, criteria, sattrs=None, searchlimit=0, timelimit=-1):
        """Return a list: counter followed by a User object for each user that
           matches the criteria. If the results are truncated, counter will
           be set to -1"""
        result = self.transport.find_users(criteria, sattrs, searchlimit, timelimit)
        counter = result[0]

        users = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                users.append(user.User(attrs))

        return users

    def update_user(self,user):
        """Update a user entry."""

        result = self.transport.update_user(user.origDataDict(), user.toDict())
        return result

    def delete_user(self,uid):
        """Delete a user entry."""

        result = self.transport.delete_user(uid)
        return result

    def modifyPassword(self,principal,oldpass,newpass):
        """Modify a user's password"""

        result = self.transport.modifyPassword(principal,oldpass,newpass)

        return result

    def mark_user_active(self,uid):
        """Set a user as active by uid."""

        result = self.transport.mark_user_active(uid)
        return result

    def mark_user_inactive(self,uid):
        """Set a user as inactive by uid."""

        result = self.transport.mark_user_inactive(uid)
        return result

# Groups support

    def get_groups_by_member(self,member_dn,sattrs=None):
        """Gets the groups that member_dn belongs to.
           If sattrs is not None then only those
           attributes will be returned, otherwise all available
           attributes are returned. The result is a list of groups."""
        results = self.transport.get_groups_by_member(member_dn,sattrs)

        return map(lambda result: group.Group(result), results)

    def add_group(self,group,group_container=None):
        """Add a group. group is a ipa.group.Group object"""

        group_dict = group.toDict()

        # dn is set on the server-side
        del group_dict['dn']

        # convert to a regular dict before sending
        result = self.transport.add_group(group_dict, group_container)
        return result

    def find_groups(self, criteria, sattrs=None, searchlimit=0, timelimit=-1):
        """Find groups whose cn matches the criteria. Wildcards are 
           acceptable. Returns a list of Group objects."""
        result = self.transport.find_groups(criteria, sattrs, searchlimit, timelimit)
        counter = result[0]

        groups = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                groups.append(group.Group(attrs))

        return groups

    def add_member_to_group(self, member_dn, group_dn):
        """Add a member to an existing group.
        """

        return self.transport.add_member_to_group(member_dn, group_dn)

    def add_members_to_group(self, member_dns, group_dn):
        """Add several members to an existing group.
           member_dns is a list of dns to add

           Returns a list of the dns that were not added.
        """

        return self.transport.add_members_to_group(member_dns, group_dn)

    def remove_member_from_group(self, member_dn, group_dn):
        """Remove a member from an existing group.
        """

        return self.transport.remove_member_from_group(member_dn, group_dn)

    def remove_members_from_group(self, member_dns, group_dn):
        """Remove several members from an existing group.
           member_dns is a list of dns to remove

           Returns a list of the dns that were not removed.
        """

        return self.transport.remove_members_from_group(member_dns, group_dn)

    def add_user_to_group(self, user_uid, group_dn):
        """Add a user to an existing group.
           user is a uid of the user to add
           group is the cn of the group to be added to
        """

        return self.transport.add_user_to_group(user_uid, group_dn)

    def add_users_to_group(self, user_uids, group_dn):
        """Add several users to an existing group.
           user_uids is a list of uids of the users to add

           Returns a list of the user uids that were not added.
        """

        return self.transport.add_users_to_group(user_uids, group_dn)

    def remove_user_from_group(self, user_uid, group_dn):
        """Remove a user from an existing group.
           user is a uid of the user to remove
           group is the cn of the group to be removed from
        """

        return self.transport.remove_user_from_group(user_uid, group_dn)

    def remove_users_from_group(self, user_uids, group_dn):
        """Remove several users from an existing group.
           user_uids is a list of uids of the users to remove

           Returns a list of the user uids that were not removed.
        """

        return self.transport.remove_users_from_group(user_uids, group_dn)

    def add_groups_to_user(self, group_dns, user_dn):
        """Given a list of group dn's add them to the user.

           Returns a list of the group dns that were not added.
        """
        return self.transport.add_groups_to_user(group_dns, user_dn)

    def remove_groups_from_user(self, group_dns, user_dn):
        """Given a list of group dn's remove them from the user.

           Returns a list of the group dns that were not removed.
        """

        return self.transport.remove_groups_from_user(group_dns, user_dn)

    def update_group(self,group):
        """Update a group entry."""

        return self.transport.update_group(group.origDataDict(), group.toDict())

    def delete_group(self,group_dn):
        """Delete a group entry."""

        return self.transport.delete_group(group_dn)

    def add_group_to_group(self, group_cn, tgroup_cn):
        """Add a group to an existing group.
           group_cn is a cn of the group to add
           tgroup_cn is the cn of the group to be added to
        """

        return self.transport.add_group_to_group(group_cn, tgroup_cn)

    def attrs_to_labels(self,attrs):
        """Convert a list of LDAP attributes into a more readable form."""

        return self.transport.attrs_to_labels(attrs)

    def get_all_attrs(self):
        """We have a list of hardcoded attributes -> readable labels. Return
           that complete list if someone wants it.
        """

        return self.transport.get_all_attrs()

    def group_members(self, groupdn, attr_list):
        """Do a memberOf search of groupdn and return the attributes in
           attr_list (an empty list returns everything)."""

        results = self.transport.group_members(groupdn, attr_list)

        counter = results[0]

        entries = [counter]
        for e in results[1:]:
            if e is not None:
                entries.append(user.User(e))

        return entries
 
    def mark_group_active(self,cn):
        """Set a group as active by cn."""

        result = self.transport.mark_group_active(cn)
        return result

    def mark_group_inactive(self,cn):
        """Set a group as inactive by cn."""

        result = self.transport.mark_group_inactive(cn)
        return result

# Configuration

    def get_ipa_config(self):
        """Get the IPA configuration"""
        result = self.transport.get_ipa_config()
        return entity.Entity(result)

    def update_ipa_config(self, config):
        """Updates the IPA configuration.

           config is an Entity object.
        """
        result = self.transport.update_ipa_config(config.origDataDict(), config.toDict())
        return result

    def get_password_policy(self):
        """Get the IPA password policy"""
        result = self.transport.get_password_policy()
        return entity.Entity(result)

    def update_password_policy(self, policy):
        """Updates the IPA password policy.

           policy is an Entity object.
        """
        result = self.transport.update_password_policy(policy.origDataDict(), policy.toDict())
        return result

    def add_service_principal(self, princ_name):
        return self.transport.add_service_principal(princ_name)

    def delete_service_principal(self, principal_dn):
        return self.transport.delete_service_principal(principal_dn)

    def find_service_principal(self, criteria, sattrs=None, searchlimit=0, timelimit=-1):
        """Return a list: counter followed by a Entity object for each host that
           matches the criteria. If the results are truncated, counter will
           be set to -1"""
        result = self.transport.find_service_principal(criteria, sattrs, searchlimit, timelimit)
        counter = result[0]

        hosts = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                hosts.append(entity.Entity(attrs))

        return hosts

    def get_keytab(self, princ_name):
        return self.transport.get_keytab(princ_name)

# radius support
    def get_radius_client_by_ip_addr(self, ip_addr, container=None, sattrs=None):
        result = self.transport.get_radius_client_by_ip_addr(ip_addr, container, sattrs)
        return radius_util.RadiusClient(result)

    def add_radius_client(self, client, container=None):
        client_dict = client.toDict()

        # dn is set on the server-side
        del client_dict['dn']

        # convert to a regular dict before sending
        result = self.transport.add_radius_client(client_dict, container)
        return result

    def update_radius_client(self, client):
        result = self.transport.update_radius_client(client.origDataDict(), client.toDict())
        return result

    def delete_radius_client(self, ip_addr, container=None):
        return self.transport.delete_radius_client(ip_addr, container)

    def find_radius_clients(self, criteria, container=None, sattrs=None, searchlimit=0, timelimit=-1):
        result = self.transport.find_radius_clients(criteria, container, sattrs, searchlimit, timelimit)
        counter = result[0]

        users = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                users.append(user.User(attrs))

        return users

    def get_radius_profile_by_uid(self, uid, user_profile=None, sattrs=None):
        result = self.transport.get_radius_profile_by_uid(uid, user_profile, sattrs)
        return radius_util.RadiusClient(result)

    def add_radius_profile(self, profile, user_profile=None):
        profile_dict = profile.toDict()

        # dn is set on the server-side
        del profile_dict['dn']

        # convert to a regular dict before sending
        result = self.transport.add_radius_profile(profile_dict, user_profile)
        return result

    def update_radius_profile(self, profile):
        result = self.transport.update_radius_profile(profile.origDataDict(), profile.toDict())
        return result

    def delete_radius_profile(self, ip_addr, user_profile=None):
        return self.transport.delete_radius_profile(ip_addr, user_profile)

    def find_radius_profiles(self, criteria, user_profile=None, sattrs=None, searchlimit=0, timelimit=-1):
        result = self.transport.find_radius_profiles(criteria, user_profile, sattrs, searchlimit, timelimit)
        counter = result[0]

        users = [counter]
        for attrs in result[1:]:
            if attrs is not None:
                users.append(user.User(attrs))

        return users

