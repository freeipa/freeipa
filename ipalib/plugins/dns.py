# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Domain Name System (DNS) plugin

Implements a set of commands useful for manipulating DNS records used by
the BIND LDAP plugin.

EXAMPLES:

 Add new zone;
   ipa dns-add example.com nameserver.example.com admin@example.com

 Add second nameserver for example.com:
   ipa dns-add-rr example.com @ NS nameserver2.example.com

 Delete previously added nameserver from example.com:
   ipa dns-del-rr example.com @ NS nameserver2.example.com

 Add new A record for www.example.com: (random IP)
   ipa dns-add-rr example.com www A 80.142.15.2

 Show zone example.com:
   ipa dns-show example.com

 Find zone with 'example' in it's domain name:
   ipa dns-find example

 Find records for resources with 'www' in their name in zone example.com:
   ipa dns-find-rr example.com www

 Find A records for resource www in zone example.com
   ipa dns-find-rr example.com --resource www --type A

 Show records for resource www in zone example.com
   ipa dns-show-rr example.com www

 Delete zone example.com with all resource records:
   ipa dns-delete example.com
"""

# A few notes about the LDAP schema to make this plugin more understandable:
#  - idnsRecord object is a HOSTNAME with one or more resource records
#  - idnsZone object is a idnsRecord object with mandatory SOA record
#    it basically makes the assumption that ZONE == DOMAINNAME + SOA record
#    resource records can be stored in both idnsZone and idnsRecord objects

import time

from ipalib import api, crud, errors, output
from ipalib import Object, Command
from ipalib import Flag, Int, Str, StrEnum
from ipalib import _, ngettext
from ipalib.output import Output, standard_entry, standard_list_of_entries

# parent DN
_zone_container_dn = api.env.container_dns

# supported resource record types
_record_types = (
    u'A', u'AAAA', u'A6', u'AFSDB', u'CERT', u'CNAME', u'DNAME',
    u'DS', u'HINFO', u'KEY', u'KX', u'LOC', u'MD', u'MINFO', u'MX',
    u'NAPTR', u'NS', u'NSEC', u'NXT', u'PTR', u'RRSIG', u'SSHFP',
    u'SRV', u'TXT',
)

# supported DNS classes, IN = internet, rest is almost never used
_record_classes = (u'IN', u'CS', u'CH', u'HS')

# attributes displayed by default for resource records
_record_default_attributes = ['%srecord' % r for r in _record_types]
_record_default_attributes.append('idnsname')

# attributes displayed by default for zones
_zone_default_attributes = [
    'idnsname', 'idnszoneactive', 'idnssoamname', 'idnssoarname',
    'idnssoaserial', 'idnssoarefresh', 'idnssoaretry', 'idnssoaexpire',
    'idnssoaminimum'
]


# build zone dn
def _get_zone_dn(ldap, idnsname):
    rdn = ldap.make_rdn_from_attr('idnsname', idnsname)
    return ldap.make_dn_from_rdn(rdn, _zone_container_dn)

# build dn for entry with record
def _get_record_dn(ldap, zone, idnsname):
    parent_dn = _get_zone_dn(ldap, zone)
    if idnsname == '@' or idnsname == zone:
        return parent_dn
    rdn = ldap.make_rdn_from_attr('idnsname', idnsname)
    return ldap.make_dn_from_rdn(rdn, parent_dn)


class dns(Object):
    """DNS zone/SOA record object."""
    label = _('DNS')

    takes_params = (
        Str('idnsname',
            cli_name='name',
            label=_('Zone'),
            doc=_('Zone name (FQDN)'),
            normalizer=lambda value: value.lower(),
            primary_key=True,
        ),
        Str('idnssoamname',
            cli_name='name_server',
            label=_('Authoritative name server'),
        ),
        Str('idnssoarname',
            cli_name='admin_email',
            label=_('administrator e-mail address'),
            default_from=lambda idnsname: 'root.%s' % idnsname,
            normalizer=lambda value: value.replace('@', '.'),
        ),
        Int('idnssoaserial?',
            cli_name='serial',
            label=_('SOA serial'),
        ),
        Int('idnssoarefresh?',
            cli_name='refresh',
            label=_('SOA refresh'),
        ),
        Int('idnssoaretry?',
            cli_name='retry',
            label=_('SOA retry'),
        ),
        Int('idnssoaexpire?',
            cli_name='expire',
            label=_('SOA expire'),
        ),
        Int('idnssoaminimum?',
            cli_name='minimum',
            label=_('SOA minimum'),
        ),
        Int('dnsttl?',
            cli_name='ttl',
            label=_('SOA time to live'),
        ),
        StrEnum('dnsclass?',
            cli_name='class',
            label=_('SOA class'),
            values=_record_classes,
        ),
        Flag('idnsallowdynupdate',
            cli_name='allow_dynupdate',
            label=_('allow dynamic update?'),
        ),
        Str('idnsupdatepolicy?',
            cli_name='update_policy',
            label=_('BIND update policy'),
        ),
    )

api.register(dns)


class dns_add(crud.Create):
    """
    Create new DNS zone/SOA record.
    """
    def execute(self, *args, **options):
        ldap = self.Backend.ldap2
        idnsname = args[0]

        # build entry attributes
        entry_attrs = self.args_options_2_entry(*args, **options)

        # build entry DN
        dn = _get_zone_dn(ldap, idnsname)

        # fill in required attributes
        entry_attrs['objectclass'] = ['top', 'idnsrecord', 'idnszone']
        entry_attrs['idnszoneactive'] = 'TRUE'
        entry_attrs['idnsallowdynupdate'] = str(
            entry_attrs['idnsallowdynupdate']
        ).upper()

        # fill default values, build SOA serial from current date
        soa_serial = int('%s01' % time.strftime('%Y%d%m'))
        entry_attrs.setdefault('idnssoaserial', soa_serial)
        entry_attrs.setdefault('idnssoarefresh', 3600)
        entry_attrs.setdefault('idnssoaretry', 900)
        entry_attrs.setdefault('idnssoaexpire', 1209600)
        entry_attrs.setdefault('idnssoaminimum', 3600)

        # create zone entry
        ldap.add_entry(dn, entry_attrs)

        # get zone entry with created attributes for output
        (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=idnsname)

    def output_for_cli(self, textui, result, *args, **options):
        entry_attrs = result['result']
        idnsname = result['value']

        textui.print_name(self.name)
        textui.print_attribute('dn', entry_attrs['dn'])
        del entry_attrs['dn']
        textui.print_entry(entry_attrs)
        textui.print_dashed('Created DNS zone "%s".' % idnsname)

api.register(dns_add)


class dns_del(crud.Delete):
    """
    Delete existing DNS zone/SOA record.
    """
    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2
        idnsname = args[0]

        # build zone entry DN
        dn = _get_zone_dn(ldap, idnsname)
        # just check if zone exists for now
        ldap.get_entry(dn, [''])

        # retrieve all subentries of zone - records
        try:
            (entries, truncated) = ldap.find_entries(
                None, [''], dn, ldap.SCOPE_ONELEVEL
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        # kill'em all, records first
        for e in entries:
            ldap.delete_entry(e[0])
        ldap.delete_entry(dn)

        return dict(result=True, value=u'')

    def output_for_cli(self, textui, result, *args, **options):
        textui.print_name(self.name)
        textui.print_dashed('Deleted DNS zone "%s".' % args[0])

api.register(dns_del)


class dns_mod(crud.Update):
    """
    Modify DNS zone/SOA record.
    """
    def execute(self, *args, **options):
        ldap = self.api.Backend.ldap2
        idnsname = args[0]

        # build entry attributes, don't include idnsname!
        entry_attrs = self.args_options_2_entry(*tuple(), **options)
        entry_attrs['idnsallowdynupdate'] = str(
            entry_attrs['idnsallowdynupdate']
        ).upper()

        # build entry DN
        dn = _get_zone_dn(ldap, idnsname)

        # update zone entry
        ldap.update_entry(dn, entry_attrs)

        # get zone entry with modified + default attributes for output
        (dn, entry_attrs) = ldap.get_entry(
            dn, (entry_attrs.keys() + _zone_default_attributes)
        )
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=idnsname)

    def output_for_cli(self, textui, result, *args, **options):
        entry_attrs = result['result']
        idnsname = result['value']

        textui.print_name(self.name)
        textui.print_attribute('dn', entry_attrs['dn'])
        del entry_attrs['dn']
        textui.print_entry(entry_attrs)
        textui.print_dashed('Modified DNS zone "%s".' % idnsname)

api.register(dns_mod)


class dns_find(crud.Search):
    """
    Search for DNS zones/SOA records.
    """
    def execute(self, term, **options):
        ldap = self.api.Backend.ldap2

        # build search filter
        filter = ldap.make_filter_from_attr('idnsname', term, exact=False)

        # select attributes we want to retrieve
        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = _zone_default_attributes

        # get matching entries
        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, _zone_container_dn, ldap.SCOPE_ONELEVEL
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        for e in entries:
            e[1]['dn'] = e[0]
        entries = tuple(e for (dn, e) in entries)

        return dict(result=entries, count=len(entries), truncated=truncated)

    def output_for_cli(self, textui, result, term, **options):
        entries = result['result']
        truncated = result['truncated']

        textui.print_name(self.name)
        for entry_attrs in entries:
            textui.print_attribute('dn', entry_attrs['dn'])
            del entry_attrs['dn']
            textui.print_entry(entry_attrs)
            textui.print_plain('')
        textui.print_count(
            len(entries), '%i DNS zone matched.', '%i DNS zones matched.'
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )

api.register(dns_find)


class dns_show(crud.Retrieve):
    """
    Display DNS zone/SOA record.
    """
    def execute(self, idnsname, **options):
        ldap = self.api.Backend.ldap2

        # build entry DN
        dn = _get_zone_dn(ldap, idnsname)

        # select attributes we want to retrieve
        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = _zone_default_attributes

        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=idnsname)

    def output_for_cli(self, textui, result, *args, **options):
        entry_attrs = result['result']

        textui.print_name(self.name)
        textui.print_attribute('dn', entry_attrs['dn'])
        del entry_attrs['dn']
        textui.print_entry(entry_attrs)

api.register(dns_show)


class dns_enable(Command):
    """
    Activate DNS zone.
    """
    takes_args = (
        Str('zone',
            cli_name='zone',
            label=_('Zone name'),
            normalizer=lambda value: value.lower(),
        ),
    )

    has_output = output.standard_value

    def execute(self, zone):
        ldap = self.api.Backend.ldap2

        # build entry DN
        dn = _get_zone_dn(ldap, zone)

        # activate!
        try:
            ldap.update_entry(dn, {'idnszoneactive': 'TRUE'})
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=zone)

    def output_for_cli(self, textui, result, zone):
        textui.print_name(self.name)
        textui.print_dashed('Activated DNS zone "%s".' % zone)

api.register(dns_enable)


class dns_disable(Command):
    """
    Deactivate DNS zone.
    """
    takes_args = (
        Str('zone',
            label=_('Zone name'),
            normalizer=lambda value: value.lower(),
        ),
    )

    has_output = output.standard_value

    def execute(self, zone):
        ldap = self.api.Backend.ldap2

        # build entry DN
        dn = _get_zone_dn(ldap, zone)

        # deactivate!
        try:
            ldap.update_entry(dn, {'idnszoneactive': 'FALSE'})
        except errors.EmptyModlist:
            pass

        return dict(result=True, value=zone)

    def output_for_cli(self, textui, result, zone):
        textui.print_name(self.name)
        textui.print_dashed('Deactivated DNS zone "%s".' % zone)

api.register(dns_disable)


class dns_add_rr(Command):
    """
    Add new DNS resource record.
    """

    takes_args = (
        Str('zone',
            label=_('Zone name'),
            normalizer=lambda value: value.lower(),
        ),
        Str('idnsname',
            cli_name='resource',
            label=_('resource name'),
            default_from=lambda zone: zone.lower(),
            attribute=True,
        ),
        StrEnum('type',
            label=_('Record type'),
            values=_record_types,
        ),
        Str('data',
            label=_('Data'),
            doc=_('Type-specific data'),
        ),
    )

    takes_options = (
        Int('dnsttl?',
            cli_name='ttl',
            label=_('Time to live'),
            attribute=True,
        ),
        StrEnum('dnsclass?',
            cli_name='class',
            label=_('Class'),
            values=_record_classes,
            attribute=True,
        ),
    )

    has_output = standard_entry

    def execute(self, zone, idnsname, type, data, **options):
        ldap = self.api.Backend.ldap2
        attr = ('%srecord' % type).lower()

        # build entry DN
        dn = _get_record_dn(ldap, zone, idnsname)

        # get resource entry where to store the new record
        try:
            (dn, entry_attrs) = ldap.get_entry(dn, [attr])
        except errors.NotFound:
            if idnsname != '@' and idnsname != zone:
                # resource entry doesn't exist, check if zone exists
                zone_dn = _get_zone_dn(ldap, zone)
                ldap.get_entry(zone_dn, [''])
                # it does, create new resource entry

                # build entry attributes
                entry_attrs = self.args_options_2_entry(
                    (idnsname, ), **options
                )

                # fill in required attributes
                entry_attrs['objectclass'] = ['top', 'idnsrecord']

                # fill in the record
                entry_attrs[attr] = data

                # create the entry
                ldap.add_entry(dn, entry_attrs)

                # get entry with created attributes for output
                (dn, entry_attrs) = ldap.get_entry(dn, entry_attrs.keys())
                entry_attrs['dn'] = dn

                return dict(result=entry_attrs, value=idnsname)

            # zone doesn't exist
            raise
        # resource entry already exists, create a modlist for the new record

        # convert entry_attrs keys to lowercase
        #entry_attrs = dict(
        #    (k.lower(), v) for (k, v) in entry_attrs.iteritems()
        #)

        # get new value for record attribute
        attr_value = entry_attrs.get(attr, [])
        attr_value.append(data)

        ldap.update_entry(dn, {attr: attr_value})
        # get entry with updated attribute for output
        (dn, entry_attrs) = ldap.get_entry(dn, ['idnsname', attr])
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=idnsname)

    def output_for_cli(self, textui, result, zone, idnsname, type, data,
            **options):
        entry_attrs = result['result']
        output = '"%s %s %s" to zone "%s"' % (
            idnsname, type, data, zone,
        )

        textui.print_name(self.name)
        textui.print_attribute('dn', entry_attrs['dn'])
        del entry_attrs['dn']
        textui.print_entry(entry_attrs)
        textui.print_dashed('Added DNS resource record %s.' % output)

api.register(dns_add_rr)


class dns_del_rr(Command):
    """
    Delete DNS resource record.
    """

    takes_args = (
        Str('zone',
            label=_('Zone name'),
            normalizer=lambda value: value.lower(),
        ),
        Str('idnsname',
            cli_name='resource',
            label=_('Resource name'),
            default_from=lambda zone: zone.lower(),
            attribute=True,
        ),
        StrEnum('type',
            label=_('Record type'),
            values=_record_types,
        ),
        Str('data',
            label=_('Data'),
            doc=_('Type-specific data'),
        ),
    )

    has_output = standard_entry

    def execute(self, zone, idnsname, type, data, **options):
        ldap = self.api.Backend.ldap2
        attr = ('%srecord' % type).lower()

        # build entry DN
        dn = _get_record_dn(ldap, zone, idnsname)

        # get resource entry with the record we're trying to delete
        (dn, entry_attrs) = ldap.get_entry(dn)

        # convert entry_attrs keys to lowercase
        entry_attrs = dict(
            (k.lower(), v) for (k, v) in entry_attrs.iteritems()
        )

        # get new value for record attribute
        attr_value = entry_attrs.get(attr.lower(), [])
        try:
            attr_value.remove(data)
        except ValueError:
            raise errors.NotFound(reason=u'resource record not found')

        # check if it's worth to keep this entry in LDAP
        if 'idnszone' not in entry_attrs['objectclass']:
            # get a list of all meaningful record attributes
            record_attrs = []
            for (k, v) in entry_attrs.iteritems():
                if k.endswith('record') and v:
                    record_attrs.append(k)
            # check if the list is empty
            if not record_attrs:
                # it's not
                ldap.delete_entry(dn)
                return dict(result={}, value=idnsname)

        ldap.update_entry(dn, {attr: attr_value})
        # get entry with updated attribute for output
        (dn, entry_attrs) = ldap.get_entry(dn, ['idnsname', attr])
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=idnsname)

    def output_for_cli(self, textui, result, zone, idnsname, type, data, **options):
        output = '"%s %s %s" from zone "%s"' % (
            idnsname, type, data, zone,
        )
        entry_attrs = result['result']

        textui.print_name(self.name)
        if entry_attrs:
            textui.print_attribute('dn', entry_attrs['dn'])
            del entry_attrs['dn']
            textui.print_entry(entry_attrs)
        textui.print_dashed('Deleted DNS resource record %s' % output)

api.register(dns_del_rr)


class dns_find_rr(Command):
    """
    Search for DNS resource records.
    """
    takes_args = (
        Str('zone',
            label=_('Zone name'),
            normalizer=lambda value: value.lower(),
        ),
        Str('criteria?',
            cli_name='criteria',
            label=_('Search criteria'),
        ),
    )

    takes_options = (
        Str('idnsname?',
            cli_name='resource',
            label=_('Resource name'),
            default_from=lambda zone: zone.lower(),
        ),
        StrEnum('type?',
            label=_('Record type'),
            values=_record_types,
        ),
        Str('data?',
            label=_('type-specific data'),
        ),
    )

    has_output = standard_list_of_entries

    def execute(self, zone, term, **options):
        ldap = self.api.Backend.ldap2
        if 'type' in options:
            attr = ('%srecord' % options['type']).lower()
        else:
            attr = None

        # build base dn for search
        base_dn = _get_zone_dn(ldap, zone)

        # build search keywords
        search_kw = {}
        if 'data' in options:
            if attr is not None:
                # user is looking for a certain record type
                search_kw[attr] = options['data']
            else:
                # search in all record types
                for a in _record_default_attributes:
                    search_kw[a] = term
        if 'idnsname' in options:
            idnsname = options['idnsname']
            if idnsname == '@':
                search_kw['idnsname'] = zone
            else:
                search_kw['idnsname'] = idnsname

        # build search filter
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        if term:
            search_kw = {}
            for a in _record_default_attributes:
                search_kw[a] = term
            term_filter = ldap.make_filter(search_kw, exact=False)
            filter = ldap.combine_filters((filter, term_filter), ldap.MATCH_ALL)

        # select attributes we want to retrieve
        if options.get('all', False):
            attrs_list = ['*']
        elif attr is not None:
            attrs_list = [attr]
        else:
            attrs_list = _record_default_attributes

        # get matching entries
        try:
            (entries, truncated) = ldap.find_entries(
                filter, attrs_list, base_dn
            )
        except errors.NotFound:
            (entries, truncated) = (tuple(), False)

        # if the user is looking for a certain record type, don't display
        # entries that do not contain it
        if attr is not None:
            related_entries = []
            for e in entries:
                entry_attrs = e[1]
                if attr in entry_attrs:
                    related_entries.append(e)
            entries = related_entries

        for e in entries:
            e[1]['dn'] = e[0]
        entries = tuple(e for (dn, e) in entries)

        return dict(result=entries, count=len(entries), truncated=truncated)

    def output_for_cli(self, textui, result, zone, term, **options):
        entries = result['result']
        truncated = result['truncated']

        textui.print_name(self.name)
        for entry_attrs in entries:
            textui.print_attribute('dn', entry_attrs['dn'])
            del entry_attrs['dn']
            textui.print_entry(entry_attrs)
            textui.print_plain('')
        textui.print_count(
            len(entries), '%i DNS resource record matched.',
            '%i DNS resource records matched.'
        )
        if truncated:
            textui.print_dashed('These results are truncated.', below=False)
            textui.print_dashed(
                'Please refine your search and try again.', above=False
            )

api.register(dns_find_rr)


class dns_show_rr(Command):
    """
    Show existing DNS resource records.
    """

    takes_args = (
        Str('zone',
            label=_('Zone name'),
            normalizer=lambda value: value.lower(),
        ),
        Str('idnsname',
            cli_name='resource',
            label=_('Resource name'),
            normalizer=lambda value: value.lower(),
        ),
    )

    has_output = standard_entry

    def execute(self, zone, idnsname, **options):
        # shows all records associated with resource
        ldap = self.api.Backend.ldap2

        # build entry DN
        dn = _get_record_dn(ldap, zone, idnsname)

        # select attributes we want to retrieve
        if options.get('all', False):
            attrs_list = ['*']
        else:
            attrs_list = _record_default_attributes

        (dn, entry_attrs) = ldap.get_entry(dn, attrs_list)
        entry_attrs['dn'] = dn

        return dict(result=entry_attrs, value=idnsname)

    def output_for_cli(self, textui, result, zone, idnsname, **options):
        entry_attrs = result['result']

        textui.print_name(self.name)
        textui.print_attribute('dn', entry_attrs['dn'])
        del entry_attrs['dn']
        textui.print_entry(entry_attrs)

api.register(dns_show_rr)
