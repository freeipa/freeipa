#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#


"""
serverroles backend
=======================================

The `serverroles` backend has access to all roles and attributes stored in
module-level lists exposed in `ipaserver/servroles.py` module. It uses these
lists to populate populate its internal stores with instances of the
roles/attributes. The information contained in them can be accessed by
the following methods:

    *api.Backend.serverroles.server_role_search(
            server_server=None, role_servrole=None status=None)
        search for roles matching the given substrings and return the status of
        the matched roles. Optionally filter the result by role status. If
        `server_erver` is not None, the search is limited to a single master.
        Otherwise, the status is computed for all masters in the topology. If
        `role_servrole` is None, the all configured roled are queried

    *api.Backend.serverroles.server_role_retrieve(server_server, role_servrole)
        retrieve the status of a single role on a given master

    *api.Backend.serverroles.config_retrieve(role_servrole)
        return a configuration object given role name. This object is a
        dictionary containing a list of enabled masters and all attributes
        associated with the role along with master(s) on which they are set.

    *api.Backend.serverroles.config_update(**attrs_values)
        update configuration object. Since server roles are currently
        immutable, only attributes can be set

Note that attribute/role names are searched/matched case-insensitively. Also
note that the `serverroles` backend does not create/destroy any LDAP connection
by itself, so make sure `ldap2` backend connections are taken care of
in the calling code
"""


import six

from ipalib import errors, _
from ipalib.backend import Backend
from ipalib.plugable import Registry
from ipaserver.servroles import (
    attribute_instances, ENABLED, HIDDEN, role_instances
)
from ipaserver.servroles import SingleValuedServerAttribute


if six.PY3:
    unicode = str


register = Registry()


@register()
class serverroles(Backend):
    """
    This Backend can be used to query various information about server roles
    and attributes configured in the topology.
    """

    def __init__(self, api_instance):
        super(serverroles, self).__init__(api_instance)

        self.role_names = {
            obj.name.lower(): obj for obj in role_instances}

        self.attributes = {
            attr.attr_name: attr for attr in attribute_instances}

    def _get_role(self, role_name):
        key = role_name.lower()

        try:
            return self.role_names[key]
        except KeyError:
            raise errors.NotFound(
                reason=_("{role}: role not found".format(role=role_name)))

    def _get_masters(self, role_name, include_hidden):
        result = {}
        role = self._get_role(role_name)
        role_states = role.status(self.api, server=None)

        enabled_masters = [
            r[u'server_server'] for r in role_states if
            r[u'status'] == ENABLED
        ]
        if enabled_masters:
            result.update({role.attr_name: enabled_masters})

        if include_hidden and role.attr_name_hidden is not None:
            hidden_masters = [
                r[u'server_server'] for r in role_states if
                r[u'status'] == HIDDEN
            ]
            if hidden_masters:
                result.update({role.attr_name_hidden: hidden_masters})

        return result

    def _get_assoc_attributes(self, role_name):
        role = self._get_role(role_name)
        assoc_attributes = {
            name: attr for name, attr in self.attributes.items() if
            attr.associated_role is role}

        if not assoc_attributes:
            raise NotImplementedError(
                "Role {} has no associated attribute to set".format(role.name))

        return assoc_attributes

    def server_role_search(self, server_server=None, role_servrole=None,
                           status=None):
        if role_servrole is None:
            found_roles = self.role_names.values()
        else:
            try:
                found_roles = [self._get_role(role_servrole)]
            except errors.NotFound:
                found_roles = []

        result = []
        for found_role in found_roles:
            role_status = found_role.status(self.api, server=server_server)

            result.extend(role_status)

        if status is not None:
            return [r for r in result if r[u'status'] == status]

        return result

    def server_role_retrieve(self, server_server, role_servrole):
        return self._get_role(role_servrole).status(
            self.api, server=server_server)

    def config_retrieve(self, servrole, include_hidden=True):
        result = self._get_masters(servrole, include_hidden=include_hidden)

        try:
            assoc_attributes = self._get_assoc_attributes(servrole)
        except NotImplementedError:
            return result

        for name, attr in assoc_attributes.items():
            attr_value = attr.get(self.api)

            if attr_value:
                # attr can be a SingleValuedServerAttribute
                # in this case, the API expects a value, not a list of values
                if isinstance(attr, SingleValuedServerAttribute):
                    attr_value = attr_value[0]
                result.update({name: attr_value})

        return result

    def config_update(self, **attrs_values):
        for attr, value in attrs_values.items():
            try:
                # when the attribute is single valued, it will be stored
                # in a SingleValuedServerAttribute. The set method expects
                # a list containing a single value.
                # We need to convert value to a list containing value
                if isinstance(self.attributes[attr],
                              SingleValuedServerAttribute):
                    value = [value]
                self.attributes[attr].set(self.api, value)
            except KeyError:
                raise errors.NotFound(
                    reason=_('{attr}: no such attribute'.format(attr=attr)))
