#
# Copyright (C) 2016 FreeIPA Contributors see COPYING for license
#


"""
This module contains the set of classes which abstract various bits and pieces
of information present in the LDAP tree about functionalities such as DNS
server, Active Directory trust controller etc. These properties come in two
distinct groups:

    server roles
        this group represents a genral functionality provided by one or more
        IPA servers, such as DNS server, certificate authority and such. In
        this case there is a many-to-many mapping between the roles and the
        masters which provide them.

    server attributes
        these represent a functionality associated with the whole topology,
        such as CA renewal master or DNSSec key master.

See the corresponding design page (http://www.freeipa.org/page/V4/Server_Roles)
for more info.

Both of these groups use `LDAPBasedProperty` class as a base.

Server Roles
============

Server role objects are usually consuming information from the master's service
container (cn=FQDN,cn=masters,cn=ipa,cn=etc,$SUFFIX) are represented by
`ServiceBasedRole`class. To create an instance of such role, you only need to
specify role name and individual services comprising the role (more systemd
services may be enabled to provide some function):

>>> example_role = ServiceBasedRole(
...     "Example Role",
...     component_services = ['SERVICE1', 'SERVICE2'])
>>> example_role.name
'Example Role'

The role object can then be queried for the status of the role in the whole
topology or on a single master by using its `status` method. This method
returns a list of dictionaries akin to LDAP entries comprised from server name,
role name and role status (enabled if role is enabled, configured if the
service entries are present but not marked as enabled by 'enabledService'
config string, absent if the service entries are not present).

Note that 'AD trust agent' role is based on membership of the master in the
'adtrust agents' sysaccount group and is thus an instance of different class
(`ADTrustBasedRole`). This role also does not have 'configured' status, since
the master is either member of the group ('enabled') or not ('absent')

Server Attributes
=================

Server attributes are implemented as instances of `ServerAttribute` class. The
attribute is defined by some flag set on 'ipaConfigString' attribute of some
service entry. To create your own server attribute, see the following example:

>>> example_attribute = ServerAttribute("Example Attribute", example_role,
...                                     "SERVICE1", "roleMaster")
>>> example_attribute.name
'Example Attribute'

The FQDN of master with the attribute set can be requested using `get()`
method. The attribute master can be changed by the `set()` method
which accepts FQDN of a new master hosting the attribute.

The available role/attribute instances are stored in
`role_instances`/`attribute_instances` tuples.
"""

import abc
from collections import namedtuple, defaultdict

from ldap import SCOPE_ONELEVEL
import six

from ipalib import _, errors
from ipapython.dn import DN
from ipaserver.masters import ENABLED_SERVICE, HIDDEN_SERVICE

if six.PY3:
    unicode = str


ENABLED = u'enabled'
CONFIGURED = u'configured'
HIDDEN = u'hidden'
ABSENT = u'absent'


@six.add_metaclass(abc.ABCMeta)
class LDAPBasedProperty(object):
    """
    base class for all master properties defined by LDAP content
    :param attr_name: attribute name
    :param name: user-friendly name of the property
    :param attrs_list: list of attributes to retrieve during search, defaults
        to all
    """

    def __init__(self, attr_name, name):
        self.attr_name = attr_name
        self.name = name
        # for hidden services, insert hidden before '_server' suffix
        if attr_name.endswith(u'_server'):
            parts = attr_name.rsplit(u'_', 1)
            self.attr_name_hidden = u'{}_hidden_server'.format(parts[0])
        else:
            self.attr_name_hidden = None


@six.add_metaclass(abc.ABCMeta)
class BaseServerRole(LDAPBasedProperty):
    """
    Server role hierarchy apex. All other server role definition should either
    inherit from it or at least provide the 'status' method for querying role
    status
    property
    """

    def create_role_status_dict(self, server, status):
        """
        the output of `status()` method should be a list of dictionaries having
        the following keys:
            * role_servrole: name of role
            * server_server: server FQDN
            * status: role status on server

        this methods returns such a dict given server and role status
        """
        return {
            u'role_servrole': self.name,
            u'server_server': server,
            u'status': status}

    @abc.abstractmethod
    def create_search_params(self, ldap, api_instance, server=None):
        """
        create search base and filter
        :param ldap: ldap connection
        :param api_instance: API instance
        :param server: server FQDN. if given, the method should generate
        filter and search base matching only the status on this server
        :returns: tuple of search base (a DN) and search filter
        """

    @abc.abstractmethod
    def get_result_from_entries(self, entries):
        """
        Get role status from returned LDAP entries

        :param entries: LDAPEntry objects returned by `search()`
        :returns: list of dicts generated by `create_role_status_dict()`
                  method
        """

    def _fill_in_absent_masters(self, ldap2, api_instance, result):
        """
        get all masters on which the role is absent

        :param ldap2: LDAP connection
        :param api_instance: API instance
        :param result: output of `get_result_from_entries` method

        :returns: list of masters on which the role is absent
        """
        search_base = DN(api_instance.env.container_masters,
                         api_instance.env.basedn)
        search_filter = '(objectclass=ipaConfigObject)'
        attrs_list = ['cn']

        all_masters = ldap2.get_entries(
            search_base,
            filter=search_filter,
            scope=SCOPE_ONELEVEL,
            attrs_list=attrs_list)

        all_master_cns = set(m['cn'][0] for m in all_masters)
        enabled_configured_masters = set(r[u'server_server'] for r in result)

        absent_masters = all_master_cns.difference(enabled_configured_masters)

        return [self.create_role_status_dict(m, ABSENT) for m in
                absent_masters]

    def status(self, api_instance, server=None, attrs_list=("*",)):
        """
        probe and return status of the role either on single server or on the
        whole topology

        :param api_instance: API instance
        :param server: server FQDN. If given, only the status of the role on
                       this master will be returned
        :returns: * 'enabled' if the role is enabled on the master
                  * 'configured' if it is not enabled but has
                    been configured by installer
                  * 'hidden' if the role is not advertised
                  * 'absent' otherwise
        """
        ldap2 = api_instance.Backend.ldap2
        search_base, search_filter = self.create_search_params(
            ldap2, api_instance, server=server)

        try:
            entries = ldap2.get_entries(
                search_base,
                filter=search_filter,
                attrs_list=attrs_list)
        except errors.EmptyResult:
            entries = []

        if not entries and server is not None:
            return [self.create_role_status_dict(server, ABSENT)]

        result = self.get_result_from_entries(entries)

        if server is None:
            result.extend(
                self._fill_in_absent_masters(ldap2, api_instance, result))

        return sorted(result, key=lambda x: x[u'server_server'])


class ServerAttribute(LDAPBasedProperty):
    """
    Class from which server attributes should be instantiated

    :param associated_role_name: name of a role which must be enabled
        on the provider
    :param associated_service_name: name of LDAP service on which the
        attribute is set. Does not need to belong to the service entries
        of associate role
    :param ipa_config_string_value: value of `ipaConfigString` attribute
        associated with the presence of server attribute
    """

    def __init__(self, attr_name, name, associated_role_name,
                 associated_service_name,
                 ipa_config_string_value):
        super(ServerAttribute, self).__init__(attr_name, name)

        self.associated_role_name = associated_role_name
        self.associated_service_name = associated_service_name
        self.ipa_config_string_value = ipa_config_string_value

    @property
    def associated_role(self):
        for inst in role_instances:
            if self.associated_role_name == inst.attr_name:
                return inst

        raise NotImplementedError(
            "{}: no valid associated role found".format(self.attr_name))

    def create_search_filter(self, ldap):
        """
        Create search filter which matches LDAP data corresponding to the
        attribute
        """
        svc_filter = ldap.make_filter_from_attr(
            'cn', self.associated_service_name)

        configstring_filter = ldap.make_filter_from_attr(
            'ipaConfigString', self.ipa_config_string_value)
        return ldap.combine_filters(
            [svc_filter, configstring_filter], rules=ldap.MATCH_ALL)

    def get(self, api_instance):
        """
        get the master which has the attribute set
        :param api_instance: API instance
        :returns: master FQDN
        """
        ldap2 = api_instance.Backend.ldap2
        search_base = DN(api_instance.env.container_masters,
                         api_instance.env.basedn)

        search_filter = self.create_search_filter(ldap2)

        try:
            entries = ldap2.get_entries(search_base, filter=search_filter)
        except errors.EmptyResult:
            return []

        master_cns = {e.dn[1]['cn'] for e in entries}

        associated_role_providers = set(
            self._get_assoc_role_providers(api_instance))

        if not master_cns.issubset(associated_role_providers):
            raise errors.ValidationError(
                name=self.name,
                error=_("all masters must have %(role)s role enabled" %
                        {'role': self.associated_role.name})
            )

        return sorted(master_cns)

    def _get_master_dns(self, api_instance, servers):
        return [
            DN(('cn', server), api_instance.env.container_masters,
               api_instance.env.basedn) for server in servers]

    def _get_masters_service_entries(self, ldap, master_dns):
        service_dns = [
            DN(('cn', self.associated_service_name), master_dn) for master_dn
            in master_dns]

        return [ldap.get_entry(service_dn) for service_dn in service_dns]

    def _add_attribute_to_svc_entry(self, ldap, service_entry):
        """
        add the server attribute to the entry of associated service

        :param ldap: LDAP connection object
        :param service_entry: associated service entry
        """
        ipa_config_string = service_entry.get('ipaConfigString', [])

        ipa_config_string.append(self.ipa_config_string_value)

        service_entry['ipaConfigString'] = ipa_config_string
        ldap.update_entry(service_entry)

    def _remove_attribute_from_svc_entry(self, ldap, service_entry):
        """
        remove the server attribute to the entry of associated service

        single ipaConfigString attribute is case-insensitive, we must handle
        arbitrary case of target value

        :param ldap: LDAP connection object
        :param service_entry: associated service entry
        """
        ipa_config_string = service_entry.get('ipaConfigString', [])

        for value in ipa_config_string:
            if value.lower() == self.ipa_config_string_value.lower():
                service_entry['ipaConfigString'].remove(value)

        ldap.update_entry(service_entry)

    def _get_assoc_role_providers(self, api_instance):
        """get list of all servers on which the associated role is enabled

        Consider a hidden server as a valid provider for a role.
        """
        return [
            r[u'server_server'] for r in self.associated_role.status(
                api_instance) if r[u'status'] in {ENABLED, HIDDEN}]

    def _remove(self, api_instance, masters):
        """
        remove attribute from one or more masters

        :param api_instance: API instance
        :param master: list or iterable containing master FQDNs
        """

        ldap = api_instance.Backend.ldap2

        master_dns = self._get_master_dns(api_instance, masters)
        service_entries = self._get_masters_service_entries(ldap, master_dns)

        for service_entry in service_entries:
            self._remove_attribute_from_svc_entry(ldap, service_entry)

    def _add(self, api_instance, masters):
        """
        add attribute to the master
        :param api_instance: API instance
        :param master: iterable containing master FQDNs

        :raises: * errors.ValidationError if the associated role is not enabled
                   on the master
        """

        ldap = api_instance.Backend.ldap2

        master_dns = self._get_master_dns(api_instance, masters)
        service_entries = self._get_masters_service_entries(ldap, master_dns)
        for service_entry in service_entries:
            self._add_attribute_to_svc_entry(ldap, service_entry)

    def _check_receiving_masters_having_associated_role(self, api_instance,
                                                      masters):
        assoc_role_providers = set(
            self._get_assoc_role_providers(api_instance))
        masters_set = set(masters)
        masters_without_role = masters_set - assoc_role_providers

        if masters_without_role:
            raise errors.ValidationError(
                name=', '.join(sorted(masters_without_role)),
                error=_("must have %(role)s role enabled" %
                        {'role': self.associated_role.name})
            )

    def set(self, api_instance, masters):
        """
        set the attribute on masters

        :param api_instance: API instance
        :param masters: an interable with FQDNs of the new masters

        the attribute is automatically unset from previous masters if present

        :raises: errors.EmptyModlist if the new masters is the same as
                 the original ones
        """
        old_masters = self.get(api_instance)

        if sorted(old_masters) == sorted(masters):
            raise errors.EmptyModlist

        self._check_receiving_masters_having_associated_role(
            api_instance, masters)

        if old_masters:
            self._remove(api_instance, old_masters)

        self._add(api_instance, masters)


class SingleValuedServerAttribute(ServerAttribute):
    """
    Base class for server attributes that are forced to be single valued

    this means that `get` method will return a one-element list, and `set`
    method will accept only one-element list
    """

    def set(self, api_instance, masters):
        if len(masters) > 1:
            raise errors.ValidationError(
                name=self.attr_name,
                error=_("must be enabled only on a single master"))

        super(SingleValuedServerAttribute, self).set(api_instance, masters)

    def get(self, api_instance):
        masters = super(SingleValuedServerAttribute, self).get(api_instance)
        num_masters = len(masters)

        if num_masters > 1:
            raise errors.SingleMatchExpected(found=num_masters)

        return masters


_Service = namedtuple('Service', ['name', 'enabled', 'hidden'])


class ServiceBasedRole(BaseServerRole):
    """
    class for all role instances whose status is defined by presence of one or
    more entries in LDAP and/or their attributes
    """

    def __init__(self, attr_name, name, component_services):
        super(ServiceBasedRole, self).__init__(attr_name, name)

        self.component_services = component_services

    def _validate_component_services(self, services):
        svc_set = {s.name for s in services}
        if svc_set != set(self.component_services):
            raise ValueError(
                "{}: Mismatch between component services and search result "
                "(expected: {}, got: {})".format(
                    self.__class__.__name__,
                    ', '.join(sorted(self.component_services)),
                    ', '.join(sorted(s.name for s in services))))

    def _get_service(self, entry):
        entry_cn = entry['cn'][0]

        enabled = self._is_service_enabled(entry)
        hidden = self._is_service_hidden(entry)

        return _Service(name=entry_cn, enabled=enabled, hidden=hidden)

    def _is_service_enabled(self, entry):
        """
        determine whether the service is enabled based on the presence of
        enabledService attribute in ipaConfigString attribute.
        Since the attribute is case-insensitive, we must first lowercase its
        values and do the comparison afterwards.

        :param entry: LDAPEntry of the service
        :returns: True if the service entry is enabled, False otherwise
        """
        ipaconfigstring_values = set(entry.get('ipaConfigString', []))
        return ENABLED_SERVICE in ipaconfigstring_values

    def _is_service_hidden(self, entry):
        """Determine if service is hidden

        :param entry: LDAPEntry of the service
        :returns: True if the service entry is enabled, False otherwise
        """
        ipaconfigstring_values = set(entry.get('ipaConfigString', []))
        return HIDDEN_SERVICE in ipaconfigstring_values

    def _get_services_by_masters(self, entries):
        """
        given list of entries, return a dictionary keyed by master FQDNs which
        contains list of service entries belonging to the master
        """
        services_by_master = defaultdict(list)
        for e in entries:
            service = self._get_service(e)
            master_cn = e.dn[1]['cn']

            services_by_master[master_cn].append(service)

        return services_by_master

    def get_result_from_entries(self, entries):
        result = []
        services_by_master = self._get_services_by_masters(entries)
        for master, services in services_by_master.items():
            try:
                self._validate_component_services(services)
            except ValueError:
                continue

            if all(s.enabled for s in services):
                status = ENABLED
            elif all(s.hidden for s in services):
                status = HIDDEN
            else:
                status = CONFIGURED

            result.append(self.create_role_status_dict(master, status))

        return result

    def create_search_params(self, ldap, api_instance, server=None):
        search_base = DN(api_instance.env.container_masters,
                         api_instance.env.basedn)

        search_filter = ldap.make_filter_from_attr(
            'cn',
            self.component_services,
            rules=ldap.MATCH_ANY,
            exact=True
        )

        if server is not None:
            search_base = DN(('cn', server), search_base)

        return search_base, search_filter

    def status(self, api_instance, server=None):
        return super(ServiceBasedRole, self).status(
            api_instance, server=server, attrs_list=('ipaConfigString', 'cn'))


class ADtrustBasedRole(BaseServerRole):
    """
    Class which should instantiate roles besed on membership in 'adtrust agent'
    sysaccount group.
    """

    def get_result_from_entries(self, entries):
        result = []

        for e in entries:
            result.append(
                self.create_role_status_dict(e['fqdn'][0], ENABLED)
            )
        return result

    def create_search_params(self, ldap, api_instance, server=None):
        search_base = DN(
            api_instance.env.container_host, api_instance.env.basedn)

        search_filter = ldap.make_filter_from_attr(
            "memberof",
            DN(('cn', 'adtrust agents'), ('cn', 'sysaccounts'),
               ('cn', 'etc'), api_instance.env.basedn)
        )
        if server is not None:
            server_filter = ldap.make_filter_from_attr(
                'fqdn',
                server,
                exact=True
            )
            search_filter = ldap.combine_filters(
                [search_filter, server_filter],
                rules=ldap.MATCH_ALL
            )

        return search_base, search_filter


role_instances = (
    ADtrustBasedRole(u"ad_trust_agent_server", u"AD trust agent"),
    ServiceBasedRole(
        u"ad_trust_controller_server",
        u"AD trust controller",
        component_services=['ADTRUST']
    ),
    ServiceBasedRole(
        u"ca_server_server",
        u"CA server",
        component_services=['CA']
    ),
    ServiceBasedRole(
        u"dns_server_server",
        u"DNS server",
        component_services=['DNS', 'DNSKeySync']
    ),
    ServiceBasedRole(
        u"ipa_master_server",
        u"IPA master",
        component_services=['HTTP', 'KDC', 'KPASSWD']
    ),
    ServiceBasedRole(
        u"kra_server_server",
        u"KRA server",
        component_services=['KRA']
    ),
    ServiceBasedRole(
        u"ntp_server_server",
        u"NTP server",
        component_services=['NTP']
    )
)

attribute_instances = (
    SingleValuedServerAttribute(
        u"ca_renewal_master_server",
        u"CA renewal master",
        u"ca_server_server",
        u"CA",
        u"caRenewalMaster",
    ),
    SingleValuedServerAttribute(
        u"dnssec_key_master_server",
        u"DNSSec key master",
        u"dns_server_server",
        u"DNSSEC",
        u"dnssecKeyMaster",
    ),
    ServerAttribute(
        u"pkinit_server_server",
        u"PKINIT enabled server",
        u"ipa_master_server",
        u"KDC",
        u"pkinitEnabled"
    )
)
