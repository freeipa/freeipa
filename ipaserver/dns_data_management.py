#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import logging

import six

from collections import defaultdict
from dns import (
    rdata,
    rdataclass,
    rdatatype,
    zone,
)
from dns.exception import DNSException

from time import sleep, time

from ipalib import errors
from ipalib.dns import record_name_format
from ipapython.dnsutil import DNSName, resolve_rrsets

if six.PY3:
    unicode=str

logger = logging.getLogger(__name__)


IPA_DEFAULT_MASTER_SRV_REC = (
    # srv record name, port
    (DNSName(u'_ldap._tcp'), 389),
    (DNSName(u'_kerberos._tcp'), 88),
    (DNSName(u'_kerberos._udp'), 88),
    (DNSName(u'_kerberos-master._tcp'), 88),
    (DNSName(u'_kerberos-master._udp'), 88),
    (DNSName(u'_kpasswd._tcp'), 464),
    (DNSName(u'_kpasswd._udp'), 464),
)

IPA_DEFAULT_ADTRUST_SRV_REC = (
    # srv record name, port
    (DNSName(u'_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs'), 389),
    (DNSName(u'_ldap._tcp.dc._msdcs'), 389),
    (DNSName(u'_kerberos._tcp.Default-First-Site-Name._sites.dc._msdcs'), 88),
    (DNSName(u'_kerberos._udp.Default-First-Site-Name._sites.dc._msdcs'), 88),
    (DNSName(u'_kerberos._tcp.dc._msdcs'), 88),
    (DNSName(u'_kerberos._udp.dc._msdcs'), 88),
)

IPA_DEFAULT_NTP_SRV_REC = (
    # srv record name, port
    (DNSName("_ntp._udp"), 123),
)

CA_RECORDS_DNS_TIMEOUT = 30  # timeout in seconds


class IPADomainIsNotManagedByIPAError(Exception):
    pass


class IPASystemRecords(object):

    # fixme do it configurable
    PRIORITY_HIGH = 0
    PRIORITY_LOW = 50

    def __init__(self, api_instance):
        self.api_instance = api_instance
        self.domain_abs = DNSName(self.api_instance.env.domain).make_absolute()
        self.servers_data = {}
        self.__init_data()

    def reload_data(self):
        """
        After any change made to IPA servers, this method must be called to
        update data in the object, otherwise invalid records may be
        created/updated
        """
        self.__init_data()

    def __get_server_attrs(self, server_result):
        weight = int(server_result.get('ipaserviceweight', [u'100'])[0])
        location = server_result.get('ipalocation_location', [None])[0]
        roles = set(server_result.get('enabled_role_servrole', ()))

        return weight, location, roles

    def __get_location_suffix(self, location):
        return location + DNSName('_locations') + self.domain_abs

    def __init_data(self):
        self.servers_data = {}

        servers_result = self.api_instance.Command.server_find(
            no_members=False,
            servrole=u"IPA master",  # only active, fully installed masters
        )['result']
        for s in servers_result:
            weight, location, roles = self.__get_server_attrs(s)
            self.servers_data[s['cn'][0]] = {
                'weight': weight,
                'location': location,
                'roles': roles,
            }

    def __add_srv_records(
        self, zone_obj, hostname, rname_port_map,
        weight=100, priority=0, location=None
    ):
        assert isinstance(hostname, DNSName)
        assert isinstance(priority, int)
        assert isinstance(weight, int)

        if location:
            suffix = self.__get_location_suffix(location)
        else:
            suffix = self.domain_abs

        for name, port in rname_port_map:
            rd = rdata.from_text(
                rdataclass.IN, rdatatype.SRV,
                '{0} {1} {2} {3}'.format(
                    priority, weight, port, hostname.make_absolute()
                )
            )

            r_name = name.derelativize(suffix)

            rdataset = zone_obj.get_rdataset(
                r_name, rdatatype.SRV, create=True)
            rdataset.add(rd, ttl=86400)  # FIXME: use TTL from config

    def __add_ca_records_from_hostname(self, zone_obj, hostname):
        assert isinstance(hostname, DNSName) and hostname.is_absolute()
        r_name = DNSName('ipa-ca') + self.domain_abs
        rrsets = []
        end_time = time() + CA_RECORDS_DNS_TIMEOUT
        while time() < end_time:
            try:
                rrsets = resolve_rrsets(hostname, (rdatatype.A, rdatatype.AAAA))
            except DNSException:  # logging is done inside resolve_rrsets
                pass
            if rrsets:
                break
            sleep(5)

        if not rrsets:
            logger.error('unable to resolve host name %s to IP address, '
                         'ipa-ca DNS record will be incomplete', hostname)
            return

        for rrset in rrsets:
            for rd in rrset:
                rdataset = zone_obj.get_rdataset(
                    r_name, rd.rdtype, create=True)
                rdataset.add(rd, ttl=86400)  # FIXME: use TTL from config

    def __add_kerberos_txt_rec(self, zone_obj):
        # FIXME: with external DNS, this should generate records for all
        # realmdomains
        r_name = DNSName('_kerberos') + self.domain_abs
        rd = rdata.from_text(rdataclass.IN, rdatatype.TXT,
                             self.api_instance.env.realm)
        rdataset = zone_obj.get_rdataset(
            r_name, rdatatype.TXT, create=True
        )
        rdataset.add(rd, ttl=86400)  # FIXME: use TTL from config

    def _add_base_dns_records_for_server(
            self, zone_obj, hostname, roles=None, include_master_role=True,
            include_kerberos_realm=True,
    ):
        server = self.servers_data[hostname]
        if roles:
            eff_roles = server['roles'] & set(roles)
        else:
            eff_roles = server['roles']
        hostname_abs = DNSName(hostname).make_absolute()

        if include_kerberos_realm:
            self.__add_kerberos_txt_rec(zone_obj)

        # get master records
        if include_master_role:
            self.__add_srv_records(
                zone_obj,
                hostname_abs,
                IPA_DEFAULT_MASTER_SRV_REC,
                weight=server['weight']
            )

        if 'CA server' in eff_roles:
            self.__add_ca_records_from_hostname(zone_obj, hostname_abs)

        if 'AD trust controller' in eff_roles:
            self.__add_srv_records(
                zone_obj,
                hostname_abs,
                IPA_DEFAULT_ADTRUST_SRV_REC,
                weight=server['weight']
            )

        if 'NTP server' in eff_roles:
            self.__add_srv_records(
                zone_obj,
                hostname_abs,
                IPA_DEFAULT_NTP_SRV_REC,
                weight=server['weight']
            )

    def _get_location_dns_records_for_server(
            self, zone_obj, hostname, locations,
            roles=None, include_master_role=True):
        server = self.servers_data[hostname]
        if roles:
            eff_roles = server['roles'] & roles
        else:
            eff_roles = server['roles']
        hostname_abs = DNSName(hostname).make_absolute()

        # generate locations specific records
        for location in locations:
            if location == self.servers_data[hostname]['location']:
                priority = self.PRIORITY_HIGH
            else:
                priority = self.PRIORITY_LOW

            if include_master_role:
                self.__add_srv_records(
                    zone_obj,
                    hostname_abs,
                    IPA_DEFAULT_MASTER_SRV_REC,
                    weight=server['weight'],
                    priority=priority,
                    location=location
                )

            if 'AD trust controller' in eff_roles:
                self.__add_srv_records(
                    zone_obj,
                    hostname_abs,
                    IPA_DEFAULT_ADTRUST_SRV_REC,
                    weight=server['weight'],
                    priority=priority,
                    location=location
                )

            if 'NTP server' in eff_roles:
                self.__add_srv_records(
                    zone_obj,
                    hostname_abs,
                    IPA_DEFAULT_NTP_SRV_REC,
                    weight=server['weight'],
                    priority=priority,
                    location=location
                )

        return zone_obj

    def __prepare_records_update_dict(self, node):
        update_dict = defaultdict(list)
        for rdataset in node:
            for rdata in rdataset:
                option_name = (record_name_format % rdatatype.to_text(
                    rdata.rdtype).lower())
                update_dict[option_name].append(unicode(rdata.to_text()))
        return update_dict

    def __update_dns_records(
            self, record_name, nodes, set_cname_template=True
    ):
        update_dict = self.__prepare_records_update_dict(nodes)
        cname_template = {
            'addattr': [u'objectclass=idnsTemplateObject'],
            'setattr': [
                u'idnsTemplateAttribute;cnamerecord=%s'
                u'.\{substitutionvariable_ipalocation\}._locations' %
                record_name.relativize(self.domain_abs)
            ]
        }
        try:
            if set_cname_template:
                # only srv records should have configured cname templates
                update_dict.update(cname_template)
            self.api_instance.Command.dnsrecord_mod(
                self.domain_abs, record_name,
                **update_dict
            )
        except errors.NotFound:
            # because internal API magic, addattr and setattr doesn't work with
            # dnsrecord-add well, use dnsrecord-mod instead later
            update_dict.pop('addattr', None)
            update_dict.pop('setattr', None)

            self.api_instance.Command.dnsrecord_add(
                self.domain_abs, record_name, **update_dict)

            if set_cname_template:
                try:
                    self.api_instance.Command.dnsrecord_mod(
                        self.domain_abs,
                        record_name, **cname_template)
                except errors.EmptyModlist:
                    pass
        except errors.EmptyModlist:
            pass

    def get_base_records(
            self, servers=None, roles=None, include_master_role=True,
            include_kerberos_realm=True
    ):
        """
        Generate IPA service records for specific servers and roles
        :param servers: list of server which will be used in records,
        if None all IPA servers will be used
        :param roles: roles for which DNS records will be generated,
        if None all roles will be used
        :param include_master_role: generate records required by IPA master
        role
        :return: dns.zone.Zone object that contains base DNS records
        """

        zone_obj = zone.Zone(self.domain_abs, relativize=False)
        if servers is None:
            servers = self.servers_data.keys()

        for server in servers:
            self._add_base_dns_records_for_server(zone_obj, server,
                roles=roles, include_master_role=include_master_role,
                include_kerberos_realm=include_kerberos_realm
            )
        return zone_obj

    def get_locations_records(
            self, servers=None, roles=None, include_master_role=True):
        """
        Generate IPA location records for specific servers and roles.
        :param servers: list of server which will be used in records,
        if None all IPA servers will be used
        :param roles: roles for which DNS records will be generated,
        if None all roles will be used
        :param include_master_role: generate records required by IPA master
        role
        :return: dns.zone.Zone object that contains location DNS records
        """
        zone_obj = zone.Zone(self.domain_abs, relativize=False)
        if servers is None:
            servers_result = self.api_instance.Command.server_find(
                pkey_only=True,
                servrole=u"IPA master",  # only fully installed masters
            )['result']
            servers = [s['cn'][0] for s in servers_result]

        locations_result = self.api_instance.Command.location_find()['result']
        locations = [l['idnsname'][0] for l in locations_result]

        for server in servers:
            self._get_location_dns_records_for_server(
                zone_obj, server,
                locations, roles=roles,
                include_master_role=include_master_role)
        return zone_obj

    def update_base_records(self):
        """
        Update base DNS records for IPA services
        :return: [(record_name, node), ...], [(record_name, node, error), ...]
        where the first list contains successfully updated records, and the
        second list contains failed updates with particular exceptions
        """
        fail = []
        success = []
        names_requiring_cname_templates = set(
            rec[0].derelativize(self.domain_abs) for rec in (
                IPA_DEFAULT_MASTER_SRV_REC +
                IPA_DEFAULT_ADTRUST_SRV_REC +
                IPA_DEFAULT_NTP_SRV_REC
            )
        )

        base_zone = self.get_base_records()
        for record_name, node in base_zone.items():
            set_cname_template = record_name in names_requiring_cname_templates
            try:
                self.__update_dns_records(
                    record_name, node, set_cname_template)
            except errors.PublicError as e:
                fail.append((record_name, node, e))
            else:
                success.append((record_name, node))
        return success, fail

    def update_locations_records(self):
        """
        Update locations DNS records for IPA services
        :return: [(record_name, node), ...], [(record_name, node, error), ...]
        where the first list contains successfully updated records, and the
        second list contains failed updates with particular exceptions
        """
        fail = []
        success = []

        location_zone = self.get_locations_records()
        for record_name, nodes in location_zone.items():
            try:
                self.__update_dns_records(
                    record_name, nodes,
                    set_cname_template=False)
            except errors.PublicError as e:
                fail.append((record_name, nodes, e))
            else:
                success.append((record_name, nodes))
        return success, fail

    def update_dns_records(self):
        """
        Update all IPA DNS records
        :return: (sucessfully_updated_base_records, failed_base_records,
        sucessfully_updated_locations_records, failed_locations_records)
        For format see update_base_records or update_locations_method
        :raise IPADomainIsNotManagedByIPAError: if IPA domain is not managed by
        IPA DNS
        """
        try:
            self.api_instance.Command.dnszone_show(self.domain_abs)
        except errors.NotFound:
            raise IPADomainIsNotManagedByIPAError()

        return (
            self.update_base_records(),
            self.update_locations_records()
        )

    def remove_location_records(self, location):
        """
        Remove all location records
        :param location: DNSName object
        :return: list of successfuly removed record names, list of record
        names that cannot be removed and returned exception in tuples
        [rname1, ...], [(rname2, exc), ...]
        """
        success = []
        failed = []

        location = DNSName(location)
        loc_records = []
        for records in (
                IPA_DEFAULT_MASTER_SRV_REC,
                IPA_DEFAULT_ADTRUST_SRV_REC,
                IPA_DEFAULT_NTP_SRV_REC
        ):
            for name, _port in records:
                loc_records.append(
                    name + self.__get_location_suffix(location))

        for rname in loc_records:
            try:
                self.api_instance.Command.dnsrecord_del(
                    self.domain_abs, rname, del_all=True)
            except errors.NotFound:
                pass
            except errors.PublicError as e:
                failed.append((rname, e))
            else:
                success.append(rname)
        return success, failed


    @classmethod
    def records_list_from_node(cls, name, node):
        records = []
        for rdataset in node:
            for rd in rdataset:
                records.append(
                    u'{name} {ttl} {rdclass} {rdtype} {rdata}'.format(
                        name=name.ToASCII(),
                        ttl=rdataset.ttl,
                        rdclass=rdataclass.to_text(rd.rdclass),
                        rdtype=rdatatype.to_text(rd.rdtype),
                        rdata=rd.to_text()
                    )
                )
        return records

    @classmethod
    def records_list_from_zone(cls, zone_obj, sort=True):
        records = []
        for name, node in zone_obj.items():
            records.extend(IPASystemRecords.records_list_from_node(name, node))
        if sort:
            records.sort()
        return records
